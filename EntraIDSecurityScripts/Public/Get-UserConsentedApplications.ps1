<#
.SYNOPSIS
    Identifies "Shadow IT" by auditing user-consented applications.

.DESCRIPTION
    Discovers applications where individual users have granted permissions (user consent),
    bypassing formal IT approval processes. This is a primary source of "Shadow IT" and
    security risks. The function analyzes delegated permissions, usage patterns, and flags
    high-risk applications.
    
    v2.2.0: Performance optimizations - parallel processing, batched user lookups, progress tracking.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party applications in the audit. Default is $false.

.PARAMETER DaysInactive
    Number of days without sign-ins to consider an app "dormant". Default is 90.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.PARAMETER ThrottleLimit
    Maximum parallel threads for service principal lookups. Default is 10.

.EXAMPLE
    Get-UserConsentedApplications

    Returns all user-consented third-party applications with risk assessment.

.EXAMPLE
    Get-UserConsentedApplications -IncludeMicrosoftApps $true

    Includes Microsoft apps in the audit.

.EXAMPLE
    Get-UserConsentedApplications | Where-Object { $_.HasHighRiskPermissions }

    Shows only apps with high-risk delegated permissions.

.EXAMPLE
    Get-UserConsentedApplications | Where-Object { $_.UsageStatus -eq 'Dormant' }

    Finds dormant apps that users consented to but aren't using.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Updated: 2026-03-12 (v2.2.0 performance optimizations)
    Requires: Microsoft.Graph PowerShell module, PowerShell 7.0+
    Permissions: Application.Read.All, Directory.Read.All, AuditLog.Read.All, 
                 DelegatedPermissionGrant.Read.All

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-UserConsentedApplications {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludeMicrosoftApps = $false,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysInactive = 90,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 50)]
        [int]$ThrottleLimit = 10
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'DelegatedPermissionGrant.Read.All'"
        }

        # Verify PowerShell 7+ for parallel processing
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            Write-Warning "PowerShell 7+ recommended for best performance. Current version: $($PSVersionTable.PSVersion)"
        }

        # High-risk delegated permissions
        $highRiskPermissions = @(
            'Mail.ReadWrite'
            'Mail.ReadWrite.All'
            'Mail.Send'
            'Files.ReadWrite.All'
            'Sites.ReadWrite.All'
            'User.ReadWrite.All'
            'Directory.ReadWrite.All'
            'RoleManagement.ReadWrite.Directory'
            'AppRoleAssignment.ReadWrite.All'
            'GroupMember.ReadWrite.All'
            'Application.ReadWrite.All'
            'Domain.ReadWrite.All'
            'IdentityRiskEvent.ReadWrite.All'
        )

        $results = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
        $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)
    }

    process {
        Write-Verbose "Retrieving delegated permission grants (user consents)..."

        try {
            # Get all OAuth2PermissionGrants (user consents) - only fetch needed properties
            $grants = Get-MgOauth2PermissionGrant -All -Property ClientId, PrincipalId, Scope -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve permission grants: $_"
        }

        Write-Verbose "Found $($grants.Count) permission grants"

        # Group by ClientId (application) and filter to only user consents
        $grantsByApp = $grants | Where-Object { $_.PrincipalId } | Group-Object -Property ClientId

        if ($grantsByApp.Count -eq 0) {
            Write-Warning "No user-consented applications found."
            return
        }

        Write-Host "Processing $($grantsByApp.Count) applications..." -ForegroundColor Cyan

        # Batch collect all unique user IDs for lookup
        Write-Verbose "Collecting unique user IDs for batch lookup..."
        $allUserIds = $grants | Where-Object { $_.PrincipalId } | Select-Object -ExpandProperty PrincipalId -Unique

        # Batch fetch users - Graph API supports filtering with 'in' operator (max 15 per filter)
        Write-Verbose "Batch fetching $($allUserIds.Count) users..."
        $userLookup = @{}
        $userBatchSize = 15
        $userBatchCount = [Math]::Ceiling($allUserIds.Count / $userBatchSize)

        for ($i = 0; $i -lt $allUserIds.Count; $i += $userBatchSize) {
            $batchNum = [Math]::Floor($i / $userBatchSize) + 1
            Write-Progress -Activity "Fetching user details" -Status "Batch $batchNum of $userBatchCount" -PercentComplete (($i / $allUserIds.Count) * 100)
            
            $batch = $allUserIds[$i..([Math]::Min($i + $userBatchSize - 1, $allUserIds.Count - 1))]
            $filter = "id in ('" + ($batch -join "','") + "')"
            
            try {
                $batchUsers = Get-MgUser -Filter $filter -Property Id, UserPrincipalName -ErrorAction SilentlyContinue
                foreach ($user in $batchUsers) {
                    $userLookup[$user.Id] = $user.UserPrincipalName
                }
            }
            catch {
                Write-Verbose "Batch user lookup failed: $_"
            }
        }
        Write-Progress -Activity "Fetching user details" -Completed

        Write-Verbose "User lookup table built with $($userLookup.Count) entries"

        # Process apps in parallel (PowerShell 7+)
        $appIndex = 0
        $totalApps = $grantsByApp.Count

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Verbose "Using parallel processing with throttle limit: $ThrottleLimit"
            
            $grantsByApp | ForEach-Object -Parallel {
                $appGrants = $_
                $clientId = $appGrants.Name
                $highRiskPermissions = $using:highRiskPermissions
                $IncludeMicrosoftApps = $using:IncludeMicrosoftApps
                $inactiveThreshold = $using:inactiveThreshold
                $userLookup = $using:userLookup
                $results = $using:results
                $appIndex = $using:appIndex
                $totalApps = $using:totalApps

                # Thread-safe progress (approximate)
                $currentIndex = [System.Threading.Interlocked]::Increment([ref]$appIndex)
                if ($currentIndex % 5 -eq 0) {
                    Write-Progress -Activity "Processing applications" -Status "$currentIndex of $totalApps" -PercentComplete (($currentIndex / $totalApps) * 100) -Id 1
                }

                # Get service principal details - only needed properties
                try {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $clientId -Property Id, DisplayName, AppId, PublisherName, Homepage, AppOwnerOrganizationId -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Skipping app $clientId - not found"
                    return
                }

                # Filter Microsoft apps if requested
                if (-not $IncludeMicrosoftApps -and $sp.AppOwnerOrganizationId -eq '72f988bf-86f1-41af-91ab-2d7cd011db47') {
                    Write-Verbose "Skipping Microsoft app: $($sp.DisplayName)"
                    return
                }

                # Count user consents
                $userConsents = $appGrants.Group | Where-Object { $_.PrincipalId }
                $userConsentCount = ($userConsents | Measure-Object).Count

                if ($userConsentCount -eq 0) {
                    return  # Skip app-only permissions
                }

                # Get consenting users from lookup table
                $consentingUsers = @()
                foreach ($consent in $userConsents) {
                    if ($consent.PrincipalId -and $userLookup.ContainsKey($consent.PrincipalId)) {
                        $consentingUsers += $userLookup[$consent.PrincipalId]
                    }
                    elseif ($consent.PrincipalId) {
                        $consentingUsers += $consent.PrincipalId
                    }
                }

                # Collect all delegated permissions
                $allPermissions = $userConsents.Scope | ForEach-Object { $_ -split ' ' } | Select-Object -Unique | Where-Object { $_ }

                # Check for high-risk permissions
                $hasHighRisk = $false
                $highRiskPerms = @()
                foreach ($perm in $allPermissions) {
                    if ($perm -in $highRiskPermissions) {
                        $hasHighRisk = $true
                        $highRiskPerms += $perm
                    }
                }

                # Get last sign-in (if available) - limit to 1 result
                $lastSignIn = $null
                $usageStatus = 'Unknown'
                
                try {
                    $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($sp.AppId)'" -Top 1 -Property CreatedDateTime -ErrorAction SilentlyContinue
                    
                    if ($signIns) {
                        $lastSignIn = $signIns[0].CreatedDateTime
                        if ($lastSignIn -lt $inactiveThreshold) {
                            $usageStatus = 'Dormant'
                        } else {
                            $usageStatus = 'Active'
                        }
                    }
                    else {
                        $usageStatus = 'No Recent Sign-ins'
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve sign-ins for $($sp.DisplayName): $_"
                }

                # Determine risk level
                $riskLevel = if ($hasHighRisk -and $usageStatus -eq 'Dormant') {
                    'CRITICAL'
                } elseif ($hasHighRisk) {
                    'HIGH'
                } elseif ($usageStatus -eq 'Dormant') {
                    'MEDIUM'
                } else {
                    'LOW'
                }

                $recommendation = switch ($riskLevel) {
                    'CRITICAL' { 'High-risk dormant app - Review and revoke consents immediately' }
                    'HIGH' { 'Active app with high-risk permissions - Verify business justification' }
                    'MEDIUM' { 'Dormant app - Consider revoking unused consents' }
                    'LOW' { 'Monitor for unusual activity' }
                }

                $results.Add([PSCustomObject]@{
                    DisplayName           = $sp.DisplayName
                    AppId                 = $sp.AppId
                    ServicePrincipalId    = $sp.Id
                    UserConsentsCount     = $userConsentCount
                    ConsentingUsers       = ($consentingUsers -join '; ')
                    HasHighRiskPermissions = $hasHighRisk
                    HighRiskPermissions   = ($highRiskPerms -join ', ')
                    AllDelegatedPermissions = ($allPermissions -join ', ')
                    LastSignInUTC         = $lastSignIn
                    UsageStatus           = $usageStatus
                    RiskLevel             = $riskLevel
                    Recommendation        = $recommendation
                    Publisher             = $sp.PublisherName
                    Homepage              = $sp.Homepage
                })
            } -ThrottleLimit $ThrottleLimit

            Write-Progress -Activity "Processing applications" -Completed -Id 1
        }
        else {
            # Fallback to sequential processing for PowerShell 5.1
            Write-Verbose "Using sequential processing (PowerShell 7+ recommended for parallel processing)"
            
            foreach ($appGrants in $grantsByApp) {
                $appIndex++
                Write-Progress -Activity "Processing applications" -Status "$appIndex of $totalApps" -PercentComplete (($appIndex / $totalApps) * 100)
                
                $clientId = $appGrants.Name

                try {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $clientId -Property Id, DisplayName, AppId, PublisherName, Homepage, AppOwnerOrganizationId -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Skipping app $clientId - not found"
                    continue
                }

                if (-not $IncludeMicrosoftApps -and $sp.AppOwnerOrganizationId -eq '72f988bf-86f1-41af-91ab-2d7cd011db47') {
                    Write-Verbose "Skipping Microsoft app: $($sp.DisplayName)"
                    continue
                }

                $userConsents = $appGrants.Group | Where-Object { $_.PrincipalId }
                $userConsentCount = ($userConsents | Measure-Object).Count

                if ($userConsentCount -eq 0) {
                    continue
                }

                $consentingUsers = @()
                foreach ($consent in $userConsents) {
                    if ($consent.PrincipalId -and $userLookup.ContainsKey($consent.PrincipalId)) {
                        $consentingUsers += $userLookup[$consent.PrincipalId]
                    }
                    elseif ($consent.PrincipalId) {
                        $consentingUsers += $consent.PrincipalId
                    }
                }

                $allPermissions = $userConsents.Scope | ForEach-Object { $_ -split ' ' } | Select-Object -Unique | Where-Object { $_ }

                $hasHighRisk = $false
                $highRiskPerms = @()
                foreach ($perm in $allPermissions) {
                    if ($perm -in $highRiskPermissions) {
                        $hasHighRisk = $true
                        $highRiskPerms += $perm
                    }
                }

                $lastSignIn = $null
                $usageStatus = 'Unknown'
                
                try {
                    $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($sp.AppId)'" -Top 1 -Property CreatedDateTime -ErrorAction SilentlyContinue
                    
                    if ($signIns) {
                        $lastSignIn = $signIns[0].CreatedDateTime
                        if ($lastSignIn -lt $inactiveThreshold) {
                            $usageStatus = 'Dormant'
                        } else {
                            $usageStatus = 'Active'
                        }
                    }
                    else {
                        $usageStatus = 'No Recent Sign-ins'
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve sign-ins for $($sp.DisplayName): $_"
                }

                $riskLevel = if ($hasHighRisk -and $usageStatus -eq 'Dormant') {
                    'CRITICAL'
                } elseif ($hasHighRisk) {
                    'HIGH'
                } elseif ($usageStatus -eq 'Dormant') {
                    'MEDIUM'
                } else {
                    'LOW'
                }

                $recommendation = switch ($riskLevel) {
                    'CRITICAL' { 'High-risk dormant app - Review and revoke consents immediately' }
                    'HIGH' { 'Active app with high-risk permissions - Verify business justification' }
                    'MEDIUM' { 'Dormant app - Consider revoking unused consents' }
                    'LOW' { 'Monitor for unusual activity' }
                }

                $results.Add([PSCustomObject]@{
                    DisplayName           = $sp.DisplayName
                    AppId                 = $sp.AppId
                    ServicePrincipalId    = $sp.Id
                    UserConsentsCount     = $userConsentCount
                    ConsentingUsers       = ($consentingUsers -join '; ')
                    HasHighRiskPermissions = $hasHighRisk
                    HighRiskPermissions   = ($highRiskPerms -join ', ')
                    AllDelegatedPermissions = ($allPermissions -join ', ')
                    LastSignInUTC         = $lastSignIn
                    UsageStatus           = $usageStatus
                    RiskLevel             = $riskLevel
                    Recommendation        = $recommendation
                    Publisher             = $sp.PublisherName
                    Homepage              = $sp.Homepage
                })
            }

            Write-Progress -Activity "Processing applications" -Completed
        }
    }

    end {
        # Convert ConcurrentBag to array for output
        $resultArray = @($results)
        
        Write-Verbose "Found $($resultArray.Count) user-consented applications"

        # Summary
        $critical = ($resultArray | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
        $high = ($resultArray | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
        $dormant = ($resultArray | Where-Object { $_.UsageStatus -eq 'Dormant' }).Count

        Write-Host "`n=== User-Consented Applications (Shadow IT) ===" -ForegroundColor Yellow
        Write-Host "Total user-consented apps: $($resultArray.Count)" -ForegroundColor White
        Write-Host "CRITICAL risk: $critical" -ForegroundColor $(if ($critical -gt 0) { 'Red' } else { 'Green' })
        Write-Host "HIGH risk: $high" -ForegroundColor $(if ($high -gt 0) { 'Red' } else { 'Yellow' })
        Write-Host "Dormant apps: $dormant" -ForegroundColor $(if ($dormant -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "================================================" -ForegroundColor Yellow

        # Export if requested
        if ($ExportPath) {
            try {
                $resultArray | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to export results: $_"
            }
        }

        return $resultArray
    }
}

Export-ModuleMember -Function Get-UserConsentedApplications -ErrorAction SilentlyContinue
