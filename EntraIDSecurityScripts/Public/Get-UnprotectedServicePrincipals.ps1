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

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party applications in the audit. Default is $false.

.PARAMETER IncludeMicrosoftCerts
    Include Microsoft platform certificates (*.microsoft.com, *.azure.com, etc.). Default is $false.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-UnprotectedServicePrincipals

    Returns all third-party service principals with credential issues.

.EXAMPLE
    Get-UnprotectedServicePrincipals -IncludeMicrosoftApps $true -IncludeMicrosoftCerts $true

    Includes all Microsoft-managed apps and certificates (for troubleshooting).

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Updated: 2026-03-12 (v2.2.3 - improved Microsoft platform certificate detection)
    Requires: Microsoft.Graph PowerShell module
    Permissions: Application.Read.All

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-UnprotectedServicePrincipals {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludeMicrosoftApps = $false,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeMicrosoftCerts = $false,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Application.Read.All'"
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
            '\.cloudapp\.azure\.com$'
            '\.trafficmanager\.net$'
            '\.servicebus\.windows\.net$'
            '\.blob\.core\.windows\.net$'
            '\.table\.core\.windows\.net$'
            '\.queue\.core\.windows\.net$'
            '\.azurewebsites\.net$'
            '\.azurecr\.io$'
            '\.cognitiveservices\.azure\.com$'
            '^CN=Microsoft'
            '^CN=Azure'
        )
        
        # Combine into single regex for efficiency
        $microsoftCertRegex = ($microsoftCertPatterns -join '|')
        
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        Write-Verbose "Retrieving service principals..."
        
        try {
            # Get all service principals with only needed properties
            $sps = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, AppOwnerOrganizationId, KeyCredentials, PasswordCredentials, ServicePrincipalType -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve service principals: $_"
        }

        Write-Verbose "Found $($sps.Count) service principals"
        Write-Host "Analyzing credentials for $($sps.Count) service principals..." -ForegroundColor Cyan

        $processedCount = 0
        $skippedMicrosoftApps = 0
        $skippedMicrosoftCerts = 0

        foreach ($sp in $sps) {
            $processedCount++
            if ($processedCount % 100 -eq 0) {
                Write-Progress -Activity "Analyzing service principals" -Status "$processedCount of $($sps.Count)" -PercentComplete (($processedCount / $sps.Count) * 100)
            }

            # Filter Microsoft first-party apps unless explicitly requested
            $isMicrosoftApp = $sp.AppOwnerOrganizationId -eq $microsoftTenantId
            if ($isMicrosoftApp -and -not $IncludeMicrosoftApps) {
                $skippedMicrosoftApps++
                Write-Verbose "Skipping Microsoft app: $($sp.DisplayName)"
                continue
            }

            # Skip managed identities (they don't have user-manageable credentials)
            if ($sp.ServicePrincipalType -eq 'ManagedIdentity') {
                Write-Verbose "Skipping managed identity: $($sp.DisplayName)"
                continue
            }

            # Combine all credentials
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

                    $results.Add([PSCustomObject]@{
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
                    })
                }
                elseif ($neverExpires) {
                    $neverExpireCount++
                    
                    $results.Add([PSCustomObject]@{
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
                    })
                }
                else {
                    $activeCount++
                }
            }

            # Flag service principals with excessive credential accumulation
            $totalCredentials = $allCredentials.Count
            if ($totalCredentials -gt 5) {
                $results.Add([PSCustomObject]@{
                    DisplayName        = $sp.DisplayName
                    AppId              = $sp.AppId
                    ServicePrincipalId = $sp.Id
                    IsMicrosoftApp     = $isMicrosoftApp
                    IsMicrosoftCert    = $false
                    CredentialType     = 'Multiple'
                    CredentialName     = "Total: $totalCredentials ($expiredCount expired, $activeCount active)"
                    StartDate          = $null
                    ExpiryDate         = $null
                    DaysExpired        = $null
                    KeyId              = $null
                    Issue              = 'Excessive Credentials'
                    RiskLevel          = 'MEDIUM'
                    Recommendation     = "Review and clean up unused credentials (has $totalCredentials total, $expiredCount expired)"
                })
            }
        }

        Write-Progress -Activity "Analyzing service principals" -Completed
    }

    end {
        Write-Verbose "Found $($results.Count) credential issues"

        # Summary
        $high = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
        $medium = ($results | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
        $low = ($results | Where-Object { $_.RiskLevel -eq 'LOW' }).Count
        $expired = ($results | Where-Object { $_.Issue -eq 'Expired Credential' }).Count
        $neverExpire = ($results | Where-Object { $_.Issue -eq 'No Expiration' }).Count

        Write-Host "`n=== Service Principal Credential Issues ===" -ForegroundColor Yellow
        Write-Host "Total issues found: $($results.Count)" -ForegroundColor White
        Write-Host "Skipped Microsoft apps: $skippedMicrosoftApps" -ForegroundColor Gray
        Write-Host "Skipped Microsoft certs: $skippedMicrosoftCerts" -ForegroundColor Gray
        Write-Host "HIGH risk: $high" -ForegroundColor $(if ($high -gt 0) { 'Red' } else { 'Green' })
        Write-Host "MEDIUM risk: $medium" -ForegroundColor $(if ($medium -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "LOW risk: $low" -ForegroundColor $(if ($low -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "`nBy Issue Type:" -ForegroundColor White
        Write-Host "  Expired credentials: $expired" -ForegroundColor Gray
        Write-Host "  No expiration set: $neverExpire" -ForegroundColor Gray
        Write-Host "==========================================" -ForegroundColor Yellow

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

Export-ModuleMember -Function Get-UnprotectedServicePrincipals -ErrorAction SilentlyContinue
