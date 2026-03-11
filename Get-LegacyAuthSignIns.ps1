<#
.SYNOPSIS
    Finds sign-ins using legacy authentication protocols.

.DESCRIPTION
    This function queries the Entra ID sign-in logs to find sign-ins that used
    legacy authentication protocols (IMAP, POP3, SMTP AUTH, etc.). These protocols
    bypass Conditional Access and MFA, making them a significant security risk.

    Use this to identify users and applications still using legacy auth before
    blocking it with Conditional Access.

.PARAMETER Days
    Number of days to look back in sign-in logs. Default is 7. Maximum is 30.

.PARAMETER IncludeSuccessful
    Include successful sign-ins. Default is $true.

.PARAMETER IncludeFailed
    Include failed sign-ins. Default is $false.

.PARAMETER UserPrincipalName
    Filter by specific user UPN. Supports wildcards.

.EXAMPLE
    Get-LegacyAuthSignIns

    Returns legacy auth sign-ins from the last 7 days.

.EXAMPLE
    Get-LegacyAuthSignIns -Days 30 -IncludeFailed $true

    Returns all legacy auth sign-ins (successful and failed) from the last 30 days.

.EXAMPLE
    Get-LegacyAuthSignIns | Group-Object ClientAppUsed | Sort-Object Count -Descending

    Shows which legacy protocols are most commonly used.

.EXAMPLE
    Get-LegacyAuthSignIns | Group-Object UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 10

    Shows top 10 users using legacy authentication.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Requires: Microsoft.Graph PowerShell module
    Permissions: AuditLog.Read.All

.LINK
    https://github.com/kentagent-ai/EntraID-Security-Scripts
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

        # Build filter
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

        $filter = $filterParts -join ' and '
        
        Write-Verbose "Filter: $filter"

        try {
            # Get sign-ins (may need to page through results)
            $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve sign-in logs: $_"
        }

        Write-Verbose "Retrieved $($signIns.Count) sign-ins, filtering for legacy auth..."

        # Filter for legacy auth clients
        $legacySignIns = $signIns | Where-Object { 
            $_.ClientAppUsed -in $legacyAuthClients -or 
            $_.ClientAppUsed -match 'Exchange|IMAP|POP|SMTP|MAPI'
        }

        foreach ($signIn in $legacySignIns) {
            $riskLevel = switch ($signIn.ClientAppUsed) {
                { $_ -in @('IMAP4', 'POP3', 'Authenticated SMTP', 'SMTP') } { 'HIGH' }
                { $_ -match 'Exchange ActiveSync' } { 'MEDIUM' }
                default { 'MEDIUM' }
            }

            $recommendation = switch ($signIn.ClientAppUsed) {
                'IMAP4' { 'Migrate to modern mail client or Graph API' }
                'POP3' { 'Migrate to modern mail client or Graph API' }
                'SMTP' { 'Use authenticated relay or Graph API Send Mail' }
                'Authenticated SMTP' { 'Use Graph API Send Mail for applications' }
                'Exchange ActiveSync' { 'Migrate to Outlook mobile or modern client' }
                default { 'Evaluate need and migrate to modern authentication' }
            }

            $results.Add([PSCustomObject]@{
                Timestamp           = $signIn.CreatedDateTime
                UserPrincipalName   = $signIn.UserPrincipalName
                UserDisplayName     = $signIn.UserDisplayName
                ClientAppUsed       = $signIn.ClientAppUsed
                AppDisplayName      = $signIn.AppDisplayName
                IPAddress           = $signIn.IpAddress
                Location            = "$($signIn.Location.City), $($signIn.Location.CountryOrRegion)"
                Status              = if ($signIn.Status.ErrorCode -eq 0) { 'Success' } else { 'Failed' }
                ErrorCode           = $signIn.Status.ErrorCode
                FailureReason       = $signIn.Status.FailureReason
                DeviceDetail        = $signIn.DeviceDetail.OperatingSystem
                RiskLevel           = $riskLevel
                Recommendation      = $recommendation
                SignInId            = $signIn.Id
            })
        }
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
            }

            Write-Host "`n=== Legacy Authentication Summary ===" -ForegroundColor Yellow
            Write-Host "Total sign-ins: $($summary.TotalLegacySignIns)" -ForegroundColor White
            Write-Host "Unique users: $($summary.UniqueUsers)" -ForegroundColor White
            Write-Host "High risk sign-ins: $($summary.HighRiskCount)" -ForegroundColor $(if ($summary.HighRiskCount -gt 0) { 'Red' } else { 'Green' })
            Write-Host "`nBy Protocol:" -ForegroundColor White
            $summary.ByProtocol | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
            }
            Write-Host "======================================`n" -ForegroundColor Yellow
        }

        return $results
    }
}

# Export function if loaded as module
Export-ModuleMember -Function Get-LegacyAuthSignIns -ErrorAction SilentlyContinue
