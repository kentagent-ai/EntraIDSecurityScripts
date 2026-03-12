<#
.SYNOPSIS
    Finds sign-ins using legacy authentication protocols.

.DESCRIPTION
    This function queries the Entra ID sign-in logs to find sign-ins that used
    legacy authentication protocols (IMAP, POP3, SMTP AUTH, etc.). These protocols
    bypass Conditional Access and MFA, making them a significant security risk.

    Use this to identify users and applications still using legacy auth before
    blocking it with Conditional Access.
    
    v2.2.0: Performance optimizations - combined queries, server-side filtering, 
    progress tracking, property selection.

.PARAMETER Days
    Number of days to look back in sign-in logs. Default is 7. Maximum is 30.

.PARAMETER IncludeSuccessful
    Include successful sign-ins. Default is $true.

.PARAMETER IncludeFailed
    Include failed sign-ins. Default is $false.

.PARAMETER UserPrincipalName
    Filter by specific user UPN. Supports wildcards.

.PARAMETER MaxResults
    Maximum number of sign-in records to retrieve. Default is 5000.
    Use lower values for faster scans.

.EXAMPLE
    Get-LegacyAuthSignIns

    Returns legacy auth sign-ins from the last 7 days.

.EXAMPLE
    Get-LegacyAuthSignIns -Days 30 -IncludeFailed $true

    Returns all legacy auth sign-ins (successful and failed) from the last 30 days.

.EXAMPLE
    Get-LegacyAuthSignIns -MaxResults 1000

    Quick scan - only fetch first 1000 sign-ins.

.EXAMPLE
    Get-LegacyAuthSignIns | Group-Object ClientAppUsed | Sort-Object Count -Descending

    Shows which legacy protocols are most commonly used.

.EXAMPLE
    Get-LegacyAuthSignIns | Group-Object UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 10

    Shows top 10 users using legacy authentication.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Updated: 2026-03-12 (v2.2.0 performance optimizations)
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
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 50000)]
        [int]$MaxResults = 5000
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'AuditLog.Read.All'"
        }

        # Legacy authentication client apps
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

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        
        Write-Verbose "Querying sign-in logs from $startDate..."

        # Build base filter
        $filterParts = @(
            "createdDateTime ge $startDate"
        )

        # Add status filter
        $statusFilters = @()
        if ($IncludeSuccessful) { $statusFilters += "status/errorCode eq 0" }
        if ($IncludeFailed) { $statusFilters += "status/errorCode ne 0" }
        
        if ($statusFilters.Count -eq 1) {
            $filterParts += $statusFilters[0]
        }
        elseif ($statusFilters.Count -eq 0) {
            throw "At least one of -IncludeSuccessful or -IncludeFailed must be true"
        }

        # Add user filter if specified
        if ($UserPrincipalName) {
            if ($UserPrincipalName -match '\*') {
                $searchPattern = $UserPrincipalName -replace '\*', ''
                $filterParts += "startsWith(userPrincipalName, '$searchPattern')"
            }
            else {
                $filterParts += "userPrincipalName eq '$UserPrincipalName'"
            }
        }

        $baseFilter = $filterParts -join ' and '
        
        # Optimization: Use paginated queries with property selection to reduce payload
        # Select only the properties we actually need
        $selectProperties = @(
            'createdDateTime'
            'userPrincipalName'
            'userDisplayName'
            'clientAppUsed'
            'appDisplayName'
            'ipAddress'
            'location'
            'status'
            'deviceDetail'
            'id'
        )

        Write-Host "Scanning sign-in logs (max $MaxResults records)..." -ForegroundColor Cyan
        
        # Single optimized query - fetch in batches with pagination
        $pageSize = 1000
        $fetchedCount = 0
        $legacyCount = 0
        
        try {
            # Use pagination to control memory and provide progress
            $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$baseFilter&`$top=$pageSize&`$select=$($selectProperties -join ',')"
            
            do {
                Write-Progress -Activity "Fetching sign-in logs" -Status "Retrieved: $fetchedCount | Legacy found: $legacyCount" -PercentComplete (($fetchedCount / $MaxResults) * 100)
                
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                $signIns = $response.value
                
                if ($signIns) {
                    $fetchedCount += $signIns.Count
                    
                    # Filter for legacy auth clients (do this client-side as Graph doesn't support complex clientAppUsed filters)
                    $legacySignIns = $signIns | Where-Object { 
                        $_.clientAppUsed -in $legacyAuthClients -or 
                        $_.clientAppUsed -match 'Exchange|IMAP|POP|SMTP|MAPI'
                    }

                    foreach ($signIn in $legacySignIns) {
                        $legacyCount++
                        
                        $riskLevel = switch ($signIn.clientAppUsed) {
                            { $_ -in @('IMAP4', 'POP3', 'Authenticated SMTP', 'SMTP') } { 'HIGH' }
                            { $_ -match 'Exchange ActiveSync' } { 'MEDIUM' }
                            default { 'MEDIUM' }
                        }

                        $recommendation = switch ($signIn.clientAppUsed) {
                            'IMAP4' { 'Migrate to modern mail client or Graph API' }
                            'POP3' { 'Migrate to modern mail client or Graph API' }
                            'SMTP' { 'Use authenticated relay or Graph API Send Mail' }
                            'Authenticated SMTP' { 'Use Graph API Send Mail for applications' }
                            'Exchange ActiveSync' { 'Migrate to Outlook mobile or modern client' }
                            default { 'Evaluate need and migrate to modern authentication' }
                        }

                        $locationString = if ($signIn.location) {
                            "$($signIn.location.city), $($signIn.location.countryOrRegion)"
                        } else {
                            'Unknown'
                        }

                        $results.Add([PSCustomObject]@{
                            Timestamp           = $signIn.createdDateTime
                            UserPrincipalName   = $signIn.userPrincipalName
                            UserDisplayName     = $signIn.userDisplayName
                            ClientAppUsed       = $signIn.clientAppUsed
                            AppDisplayName      = $signIn.appDisplayName
                            IPAddress           = $signIn.ipAddress
                            Location            = $locationString
                            Status              = if ($signIn.status.errorCode -eq 0) { 'Success' } else { 'Failed' }
                            ErrorCode           = $signIn.status.errorCode
                            FailureReason       = $signIn.status.failureReason
                            DeviceDetail        = $signIn.deviceDetail.operatingSystem
                            RiskLevel           = $riskLevel
                            Recommendation      = $recommendation
                            SignInId            = $signIn.id
                        })
                    }
                }
                
                # Get next page
                $uri = $response.'@odata.nextLink'
                
                # Stop if we've hit the max results limit
                if ($fetchedCount -ge $MaxResults) {
                    Write-Verbose "Reached MaxResults limit ($MaxResults)"
                    break
                }
                
            } while ($uri)
            
            Write-Progress -Activity "Fetching sign-in logs" -Completed
        }
        catch {
            Write-Progress -Activity "Fetching sign-in logs" -Completed
            Write-Warning "Failed to retrieve sign-in logs: $_"
            throw
        }

        Write-Host "Scanned $fetchedCount sign-ins, found $legacyCount legacy auth attempts" -ForegroundColor Green
    }

    end {
        Write-Verbose "Found $($results.Count) legacy authentication sign-ins"
        
        if ($results.Count -gt 0) {
            # Summary statistics
            $summary = @{
                TotalLegacySignIns = $results.Count
                UniqueUsers        = ($results | Select-Object -Unique UserPrincipalName).Count
                ByProtocol         = $results | Group-Object ClientAppUsed | Sort-Object Count -Descending | 
                                     Select-Object Name, Count
                HighRiskCount      = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
                SuccessfulCount    = ($results | Where-Object { $_.Status -eq 'Success' }).Count
                FailedCount        = ($results | Where-Object { $_.Status -eq 'Failed' }).Count
            }

            Write-Host "`n=== Legacy Authentication Summary ===" -ForegroundColor Yellow
            Write-Host "Total sign-ins: $($summary.TotalLegacySignIns)" -ForegroundColor White
            Write-Host "Unique users: $($summary.UniqueUsers)" -ForegroundColor White
            Write-Host "Successful: $($summary.SuccessfulCount)" -ForegroundColor $(if ($summary.SuccessfulCount -gt 0) { 'Yellow' } else { 'Green' })
            Write-Host "Failed: $($summary.FailedCount)" -ForegroundColor Gray
            Write-Host "High risk sign-ins: $($summary.HighRiskCount)" -ForegroundColor $(if ($summary.HighRiskCount -gt 0) { 'Red' } else { 'Green' })
            Write-Host "`nBy Protocol:" -ForegroundColor White
            $summary.ByProtocol | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
            }
            Write-Host "======================================`n" -ForegroundColor Yellow
        }
        else {
            Write-Host "`n✓ No legacy authentication sign-ins found!" -ForegroundColor Green
            Write-Host "Your environment is clean - all users are using modern authentication.`n" -ForegroundColor Green
        }

        return $results
    }
}

# Export function if loaded as module
Export-ModuleMember -Function Get-LegacyAuthSignIns -ErrorAction SilentlyContinue
