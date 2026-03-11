<#
.SYNOPSIS
    Identifies "Shadow IT" by auditing user-consented applications.

.DESCRIPTION
    Discovers applications where individual users have granted permissions (user consent),
    bypassing formal IT approval processes. This is a primary source of "Shadow IT" and
    security risks. The function analyzes delegated permissions, usage patterns, and flags
    high-risk applications.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party applications in the audit. Default is $false.

.PARAMETER DaysInactive
    Number of days without sign-ins to consider an app "dormant". Default is 90.

.PARAMETER ExportPath
    Optional path to export results to CSV.

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
    Requires: Microsoft.Graph PowerShell module
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
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'DelegatedPermissionGrant.Read.All'"
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

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)
    }

    process {
        Write-Verbose "Retrieving delegated permission grants (user consents)..."

        try {
            # Get all OAuth2PermissionGrants (user consents)
            $grants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve permission grants: $_"
        }

        Write-Verbose "Found $($grants.Count) permission grants"

        # Group by ClientId (application)
        $grantsByApp = $grants | Group-Object -Property ClientId

        foreach ($appGrants in $grantsByApp) {
            $clientId = $appGrants.Name
            
            # Get service principal details
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $clientId -ErrorAction Stop
            }
            catch {
                Write-Verbose "Skipping app $clientId - not found"
                continue
            }

            # Filter Microsoft apps if requested
            if (-not $IncludeMicrosoftApps -and $sp.AppOwnerOrganizationId -eq '72f988bf-86f1-41af-91ab-2d7cd011db47') {
                Write-Verbose "Skipping Microsoft app: $($sp.DisplayName)"
                continue
            }

            # Count user consents (PrincipalId not null = user consent)
            $userConsents = $appGrants.Group | Where-Object { $_.PrincipalId }
            $userConsentCount = ($userConsents | Measure-Object).Count

            if ($userConsentCount -eq 0) {
                continue  # Skip app-only permissions
            }

            # Get consenting users
            $consentingUsers = @()
            foreach ($consent in $userConsents) {
                if ($consent.PrincipalId) {
                    try {
                        $user = Get-MgUser -UserId $consent.PrincipalId -Property DisplayName, UserPrincipalName -ErrorAction SilentlyContinue
                        if ($user) {
                            $consentingUsers += $user.UserPrincipalName
                        }
                    }
                    catch {
                        $consentingUsers += $consent.PrincipalId
                    }
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

            # Get last sign-in (if available)
            $lastSignIn = $null
            $usageStatus = 'Unknown'
            
            try {
                # Query sign-ins for this app (limited to last 30 days due to API limits)
                $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($sp.AppId)'" -Top 1 -OrderBy "createdDateTime DESC" -ErrorAction SilentlyContinue
                
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
        }
    }

    end {
        Write-Verbose "Found $($results.Count) user-consented applications"

        # Summary
        $critical = ($results | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
        $high = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
        $dormant = ($results | Where-Object { $_.UsageStatus -eq 'Dormant' }).Count

        Write-Host "`n=== User-Consented Applications (Shadow IT) ===" -ForegroundColor Yellow
        Write-Host "Total user-consented apps: $($results.Count)" -ForegroundColor White
        Write-Host "CRITICAL risk: $critical" -ForegroundColor $(if ($critical -gt 0) { 'Red' } else { 'Green' })
        Write-Host "HIGH risk: $high" -ForegroundColor $(if ($high -gt 0) { 'Red' } else { 'Yellow' })
        Write-Host "Dormant apps: $dormant" -ForegroundColor $(if ($dormant -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "================================================`n" -ForegroundColor Yellow

        # Export if requested
        if ($ExportPath) {
            try {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to export results: $_"
            }
        }

        return $results
    }
}

Export-ModuleMember -Function Get-UserConsentedApplications -ErrorAction SilentlyContinue
