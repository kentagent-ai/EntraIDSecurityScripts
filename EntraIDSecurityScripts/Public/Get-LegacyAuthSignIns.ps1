<#
.SYNOPSIS
    Finds sign-ins using legacy authentication protocols.

.DESCRIPTION
    This function queries the Entra ID sign-in logs to find sign-ins that used
    legacy authentication protocols (IMAP, POP3, SMTP AUTH, etc.). These protocols
    bypass Conditional Access and MFA, making them a significant security risk.

    Use this to identify users and applications still using legacy auth before
    blocking it with Conditional Access.
    
    v2.4.0: Major performance improvement - queries each legacy protocol separately
    with server-side filtering instead of fetching all sign-ins.

.PARAMETER Days
    Number of days to look back in sign-in logs. Default is 7. Maximum is 30.

.PARAMETER IncludeSuccessful
    Include successful sign-ins. Default is $true.

.PARAMETER IncludeFailed
    Include failed sign-ins. Default is $false.

.PARAMETER UserPrincipalName
    Filter by specific user UPN.

.EXAMPLE
    Get-LegacyAuthSignIns

    Returns legacy auth sign-ins from the last 7 days.

.EXAMPLE
    Get-LegacyAuthSignIns -Days 30 -IncludeFailed $true

    Returns all legacy auth sign-ins (successful and failed) from the last 30 days.

.EXAMPLE
    Get-LegacyAuthSignIns | Group-Object ClientAppUsed | Sort-Object Count -Descending

    Shows which legacy protocols are most commonly used.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Updated: 2026-03-12 (v2.4.0 - server-side filtering per protocol)
    Requires: Microsoft.Graph PowerShell module
    Permissions: AuditLog.Read.All

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-LegacyAuthSignIns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 30)]
        [int]$Days = 7,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeSuccessful = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeFailed = $false,

        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'AuditLog.Read.All'"
        }

        # Legacy authentication client apps - query each separately for efficiency
        $legacyAuthClients = @(
            'Exchange ActiveSync'
            'IMAP4'
            'MAPI Over HTTP'
            'Offline Address Book'
            'Other clients'
            'Outlook Anywhere (RPC over HTTP)'
            'POP3'
            'Reporting Web Services'
            'SMTP'
            'Authenticated SMTP'
            'Exchange Web Services'
            'AutoDiscover'
        )

        $results = New-Object System.Collections.ArrayList
    }

    process {
        $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        
        Write-Host ""
        Write-Host "=== Legacy Authentication Sign-In Scan ===" -ForegroundColor Cyan
        Write-Host "Date range: Last $Days days (since $startDate)" -ForegroundColor Gray
        Write-Host ""

        # Build status filter
        $statusFilters = @()
        if ($IncludeSuccessful) { $statusFilters += "status/errorCode eq 0" }
        if ($IncludeFailed) { $statusFilters += "status/errorCode ne 0" }
        
        if ($statusFilters.Count -eq 0) {
            throw "At least one of -IncludeSuccessful or -IncludeFailed must be true"
        }
        
        $statusFilter = if ($statusFilters.Count -eq 2) {
            # Both - no status filter needed
            $null
        } else {
            $statusFilters[0]
        }

        # User filter
        $userFilter = $null
        if ($UserPrincipalName) {
            $userFilter = "userPrincipalName eq '$UserPrincipalName'"
        }

        # Properties to select
        $selectProperties = 'createdDateTime,userPrincipalName,userDisplayName,clientAppUsed,appDisplayName,ipAddress,location,status,deviceDetail,id'

        $totalSignIns = 0
        $protocolsFound = @{}

        # Query each legacy protocol separately (server-side filtering)
        foreach ($protocol in $legacyAuthClients) {
            # Build filter for this protocol
            $filterParts = @(
                "createdDateTime ge $startDate"
                "clientAppUsed eq '$protocol'"
            )
            
            if ($statusFilter) {
                $filterParts += $statusFilter
            }
            
            if ($userFilter) {
                $filterParts += $userFilter
            }
            
            $filter = $filterParts -join ' and '
            
            Write-Progress -Activity "Scanning legacy protocols" -Status "Checking: $protocol" -PercentComplete (([array]::IndexOf($legacyAuthClients, $protocol) / $legacyAuthClients.Count) * 100)

            # Paginated query for this protocol
            $protocolCount = 0
            $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=1000&`$select=$selectProperties"
            
            do {
                try {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                    $signIns = $response.value
                    
                    if ($null -ne $signIns -and $signIns.Count -gt 0) {
                        foreach ($signIn in $signIns) {
                            $protocolCount++
                            $totalSignIns++

                            $riskLevel = switch ($protocol) {
                                { $_ -in @('IMAP4', 'POP3', 'Authenticated SMTP', 'SMTP') } { 'HIGH' }
                                { $_ -eq 'Exchange ActiveSync' } { 'MEDIUM' }
                                default { 'MEDIUM' }
                            }

                            $recommendation = switch ($protocol) {
                                'IMAP4' { 'Migrate to modern mail client or Graph API' }
                                'POP3' { 'Migrate to modern mail client or Graph API' }
                                'SMTP' { 'Use authenticated relay or Graph API Send Mail' }
                                'Authenticated SMTP' { 'Use Graph API Send Mail for applications' }
                                'Exchange ActiveSync' { 'Migrate to Outlook mobile or modern client' }
                                default { 'Evaluate need and migrate to modern authentication' }
                            }

                            $locationString = ''
                            if ($null -ne $signIn.location) {
                                $city = $signIn.location.city
                                $country = $signIn.location.countryOrRegion
                                if ($city -or $country) {
                                    $locationString = "$city, $country"
                                }
                            }

                            $statusText = 'Success'
                            $errorCode = 0
                            $failureReason = ''
                            if ($null -ne $signIn.status) {
                                $errorCode = $signIn.status.errorCode
                                if ($errorCode -ne 0) {
                                    $statusText = 'Failed'
                                    $failureReason = $signIn.status.failureReason
                                }
                            }

                            $deviceOS = ''
                            if ($null -ne $signIn.deviceDetail) {
                                $deviceOS = $signIn.deviceDetail.operatingSystem
                            }

                            $obj = New-Object PSObject -Property @{
                                Timestamp         = $signIn.createdDateTime
                                UserPrincipalName = $signIn.userPrincipalName
                                UserDisplayName   = $signIn.userDisplayName
                                ClientAppUsed     = $signIn.clientAppUsed
                                AppDisplayName    = $signIn.appDisplayName
                                IPAddress         = $signIn.ipAddress
                                Location          = $locationString
                                Status            = $statusText
                                ErrorCode         = $errorCode
                                FailureReason     = $failureReason
                                DeviceDetail      = $deviceOS
                                RiskLevel         = $riskLevel
                                Recommendation    = $recommendation
                                SignInId          = $signIn.id
                            }
                            [void]$results.Add($obj)
                        }
                    }
                    
                    # Get next page
                    $uri = $response.'@odata.nextLink'
                }
                catch {
                    Write-Verbose "Error querying $protocol : $_"
                    $uri = $null
                }
            } while ($null -ne $uri)

            if ($protocolCount -gt 0) {
                $protocolsFound[$protocol] = $protocolCount
                Write-Host "  [!] $protocol : $protocolCount sign-ins" -ForegroundColor Yellow
            }
        }

        Write-Progress -Activity "Scanning legacy protocols" -Completed
    }

    end {
        Write-Host ""
        
        if ($results.Count -gt 0) {
            # Summary statistics
            $uniqueUsers = ($results | Select-Object -Property UserPrincipalName -Unique).Count
            $highRiskCount = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
            $successfulCount = ($results | Where-Object { $_.Status -eq 'Success' }).Count
            $failedCount = ($results | Where-Object { $_.Status -eq 'Failed' }).Count

            Write-Host "=== Legacy Authentication Summary ===" -ForegroundColor Yellow
            Write-Host "Total sign-ins: $($results.Count)" -ForegroundColor White
            Write-Host "Unique users: $uniqueUsers" -ForegroundColor White
            
            if ($IncludeSuccessful) {
                $color = if ($successfulCount -gt 0) { 'Yellow' } else { 'Green' }
                Write-Host "Successful: $successfulCount" -ForegroundColor $color
            }
            if ($IncludeFailed) {
                Write-Host "Failed: $failedCount" -ForegroundColor Gray
            }
            
            $color = if ($highRiskCount -gt 0) { 'Red' } else { 'Green' }
            Write-Host "High risk (IMAP/POP/SMTP): $highRiskCount" -ForegroundColor $color
            
            Write-Host ""
            Write-Host "By Protocol:" -ForegroundColor White
            foreach ($key in $protocolsFound.Keys | Sort-Object { $protocolsFound[$_] } -Descending) {
                Write-Host "  $key : $($protocolsFound[$key])" -ForegroundColor Gray
            }
            Write-Host "======================================" -ForegroundColor Yellow
        }
        else {
            Write-Host "[OK] No legacy authentication sign-ins found!" -ForegroundColor Green
            Write-Host "Your environment is clean - all users are using modern authentication." -ForegroundColor Green
        }
        
        Write-Host ""
        return $results
    }
}

Export-ModuleMember -Function Get-LegacyAuthSignIns -ErrorAction SilentlyContinue
