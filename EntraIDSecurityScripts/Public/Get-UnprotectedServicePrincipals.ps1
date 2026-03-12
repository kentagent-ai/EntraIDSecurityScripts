<#
.SYNOPSIS
    Finds service principals with unprotected, expired, or excessive credentials.

.DESCRIPTION
    Audits service principal credentials (certificates and secrets) to identify security risks:
    - Expired credentials that should be removed
    - Credentials without expiration dates (never expire)
    - Excessive credential accumulation
    
    Automatically excludes Microsoft first-party applications and Microsoft-managed 
    platform certificates where credentials are managed by Microsoft.

    Can optionally remove expired credentials with -RemoveExpiredCredentials.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party applications in the audit. Default is $false.

.PARAMETER IncludeMicrosoftCerts
    Include Microsoft platform certificates (*.microsoft.com, *.azure.com, etc.). Default is $false.

.PARAMETER RemoveExpiredCredentials
    Remove expired credentials. Use with -WhatIf to preview changes.
    Requires Application.ReadWrite.All permission.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-UnprotectedServicePrincipals

    Returns all third-party service principals with credential issues.

.EXAMPLE
    Get-UnprotectedServicePrincipals -RemoveExpiredCredentials -WhatIf

    Shows what expired credentials WOULD be removed without actually removing them.

.EXAMPLE
    Get-UnprotectedServicePrincipals -RemoveExpiredCredentials

    Actually removes expired credentials (prompts for confirmation).

.EXAMPLE
    Get-UnprotectedServicePrincipals | Where-Object { $_.RiskLevel -eq 'HIGH' }

    Shows only high-risk credential issues.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Updated: 2026-03-12 (Added -RemoveExpiredCredentials with WhatIf support)
    Requires: Microsoft.Graph PowerShell module
    Permissions: Application.Read.All (read), Application.ReadWrite.All (remove)

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-UnprotectedServicePrincipals {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludeMicrosoftApps = $false,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeMicrosoftCerts = $false,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveExpiredCredentials,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Application.Read.All'"
        }

        # Check for write permissions if removing credentials
        if ($RemoveExpiredCredentials) {
            if ('Application.ReadWrite.All' -notin $context.Scopes) {
                Write-Warning "Missing Application.ReadWrite.All scope. Reconnect with: Connect-MgGraph -Scopes 'Application.ReadWrite.All'"
            }
        }

        # Microsoft's tenant ID (for first-party apps)
        $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'
        
        # Microsoft-managed certificate patterns (CN= or display names)
        # These are platform certificates managed by Microsoft services
        $microsoftCertPatterns = @(
            '\.microsoft\.com$'
            '\.azure\.com$'
            '\.azure-api\.net$'
            '\.windows\.net$'
            '\.windowsazure\.com$'
            '\.dynamics\.com$'
            '\.office\.com$'
            '\.office365\.com$'
            '\.sharepoint\.com$'
            '\.onmicrosoft\.com$'
            '\.microsoftonline\.com$'
            '\.powerapps\.com$'
            '\.powerva\.microsoft\.com$'
            '^CN=Microsoft '
            '^CN=Azure '
            '^MS-Organization-'
        )
        $microsoftCertRegex = $microsoftCertPatterns -join '|'

        $results = New-Object System.Collections.ArrayList
        $removedCount = 0
        $skippedCount = 0
    }

    process {
        Write-Verbose "Retrieving service principals..."
        
        try {
            $servicePrincipals = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, AppOwnerOrganizationId, KeyCredentials, PasswordCredentials -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve service principals: $_"
        }

        Write-Host "Processing $($servicePrincipals.Count) service principals..." -ForegroundColor Cyan
        $skippedMicrosoftCerts = 0

        foreach ($sp in $servicePrincipals) {
            # Check if Microsoft first-party app
            $isMicrosoftApp = $sp.AppOwnerOrganizationId -eq $microsoftTenantId

            # Skip Microsoft apps unless explicitly requested
            if ($isMicrosoftApp -and -not $IncludeMicrosoftApps) {
                continue
            }

            $allCredentials = @()
            $allCredentials += $sp.KeyCredentials
            $allCredentials += $sp.PasswordCredentials

            if ($allCredentials.Count -eq 0) {
                continue  # Skip service principals with no credentials
            }

            # Track issues per service principal
            $expiredCount = 0
            $neverExpireCount = 0
            $activeCount = 0

            foreach ($cred in $allCredentials) {
                $now = Get-Date
                $credentialType = if ($cred.Type) { 'Certificate' } else { 'Secret' }
                $credentialName = $cred.DisplayName
                
                # Check if this is a Microsoft-managed certificate
                $isMicrosoftCert = $false
                if ($credentialName -and $credentialName -match $microsoftCertRegex) {
                    $isMicrosoftCert = $true
                }
                
                # Skip Microsoft-managed certificates unless explicitly requested
                if ($isMicrosoftCert -and -not $IncludeMicrosoftCerts) {
                    $skippedMicrosoftCerts++
                    Write-Verbose "Skipping Microsoft-managed cert: $credentialName on $($sp.DisplayName)"
                    continue
                }

                $isExpired = $cred.EndDateTime -and ($cred.EndDateTime -lt $now)
                $neverExpires = $null -eq $cred.EndDateTime -or $cred.EndDateTime -gt $now.AddYears(10)

                # Categorize the credential
                if ($isExpired) {
                    $expiredCount++
                    
                    # Calculate how long it's been expired
                    $daysExpired = ($now - $cred.EndDateTime).Days
                    
                    $riskLevel = if ($daysExpired -gt 365) {
                        'HIGH'  # Expired over a year ago
                    } elseif ($daysExpired -gt 90) {
                        'MEDIUM'  # Expired over 90 days ago
                    } else {
                        'LOW'  # Recently expired (might be in rotation)
                    }

                    $resultObj = [PSCustomObject]@{
                        DisplayName        = $sp.DisplayName
                        AppId              = $sp.AppId
                        ServicePrincipalId = $sp.Id
                        IsMicrosoftApp     = $isMicrosoftApp
                        IsMicrosoftCert    = $isMicrosoftCert
                        CredentialType     = $credentialType
                        CredentialName     = $credentialName
                        StartDate          = $cred.StartDateTime
                        ExpiryDate         = $cred.EndDateTime
                        DaysExpired        = $daysExpired
                        KeyId              = $cred.KeyId
                        Issue              = 'Expired Credential'
                        RiskLevel          = $riskLevel
                        Recommendation     = if ($isMicrosoftApp -or $isMicrosoftCert) {
                            'Microsoft-managed credential - likely auto-renewed, verify before removal'
                        } else {
                            "Remove expired $credentialType (expired $daysExpired days ago)"
                        }
                        Removed            = $false
                    }

                    # Remove expired credential if requested
                    if ($RemoveExpiredCredentials -and -not $isMicrosoftApp -and -not $isMicrosoftCert) {
                        $target = "$credentialType '$credentialName' from $($sp.DisplayName)"
                        
                        if ($PSCmdlet.ShouldProcess($target, "Remove expired credential")) {
                            try {
                                # Need to get the Application object to remove credentials
                                $app = Get-MgApplication -Filter "appId eq '$($sp.AppId)'" -ErrorAction SilentlyContinue
                                
                                if ($app) {
                                    if ($credentialType -eq 'Secret') {
                                        Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $cred.KeyId -ErrorAction Stop
                                    } else {
                                        Remove-MgApplicationKey -ApplicationId $app.Id -KeyId $cred.KeyId -ErrorAction Stop
                                    }
                                    $resultObj.Removed = $true
                                    $removedCount++
                                    Write-Host "  [REMOVED] $target" -ForegroundColor Green
                                } else {
                                    Write-Warning "Cannot find application for $($sp.DisplayName) - may be external/enterprise app only"
                                    $skippedCount++
                                }
                            }
                            catch {
                                Write-Warning "Failed to remove $target : $_"
                                $skippedCount++
                            }
                        }
                    }

                    [void]$results.Add($resultObj)
                }
                elseif ($neverExpires) {
                    $neverExpireCount++
                    
                    [void]$results.Add([PSCustomObject]@{
                        DisplayName        = $sp.DisplayName
                        AppId              = $sp.AppId
                        ServicePrincipalId = $sp.Id
                        IsMicrosoftApp     = $isMicrosoftApp
                        IsMicrosoftCert    = $isMicrosoftCert
                        CredentialType     = $credentialType
                        CredentialName     = $credentialName
                        StartDate          = $cred.StartDateTime
                        ExpiryDate         = $cred.EndDateTime
                        DaysExpired        = $null
                        KeyId              = $cred.KeyId
                        Issue              = 'No Expiration'
                        RiskLevel          = 'HIGH'
                        Recommendation     = "Set expiration policy for $credentialType (recommended: 1-2 years for certificates, 6-12 months for secrets)"
                        Removed            = $false
                    })
                }
                else {
                    $activeCount++
                }
            }

            # Flag service principals with excessive credential accumulation
            $totalCredentials = $allCredentials.Count
            if ($totalCredentials -gt 5) {
                [void]$results.Add([PSCustomObject]@{
                    DisplayName        = $sp.DisplayName
                    AppId              = $sp.AppId
                    ServicePrincipalId = $sp.Id
                    IsMicrosoftApp     = $isMicrosoftApp
                    IsMicrosoftCert    = $false
                    CredentialType     = 'Multiple'
                    CredentialName     = $null
                    StartDate          = $null
                    ExpiryDate         = $null
                    DaysExpired        = $null
                    KeyId              = $null
                    Issue              = 'Excessive Credentials'
                    RiskLevel          = 'MEDIUM'
                    Recommendation     = "Review and consolidate credentials (found $totalCredentials credentials, $expiredCount expired)"
                    Removed            = $false
                })
            }
        }
    }

    end {
        Write-Host ""
        
        if ($skippedMicrosoftCerts -gt 0) {
            Write-Host "Skipped $skippedMicrosoftCerts Microsoft-managed certificates (use -IncludeMicrosoftCerts `$true to include)" -ForegroundColor Gray
        }

        if ($results.Count -gt 0) {
            $expiredCreds = ($results | Where-Object { $_.Issue -eq 'Expired Credential' }).Count
            $noExpiryCreds = ($results | Where-Object { $_.Issue -eq 'No Expiration' }).Count
            $excessiveCreds = ($results | Where-Object { $_.Issue -eq 'Excessive Credentials' }).Count
            $highRisk = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count

            Write-Host "=== Credential Issues Summary ===" -ForegroundColor Yellow
            Write-Host "Total issues: $($results.Count)" -ForegroundColor White
            Write-Host "Expired credentials: $expiredCreds" -ForegroundColor $(if ($expiredCreds -gt 0) { 'Red' } else { 'Green' })
            Write-Host "No expiration set: $noExpiryCreds" -ForegroundColor $(if ($noExpiryCreds -gt 0) { 'Yellow' } else { 'Green' })
            Write-Host "Excessive credentials: $excessiveCreds" -ForegroundColor $(if ($excessiveCreds -gt 0) { 'Yellow' } else { 'Green' })
            Write-Host "High risk items: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { 'Red' } else { 'Green' })
            
            if ($RemoveExpiredCredentials) {
                Write-Host ""
                Write-Host "Removed: $removedCount | Skipped: $skippedCount" -ForegroundColor Cyan
            }
            
            Write-Host "=================================" -ForegroundColor Yellow

            # Export if requested
            if ($ExportPath) {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation
                Write-Host ""
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            }
        }
        else {
            Write-Host "[OK] No credential issues found!" -ForegroundColor Green
        }

        Write-Host ""
        return $results
    }
}

Export-ModuleMember -Function Get-UnprotectedServicePrincipals -ErrorAction SilentlyContinue
