<#
.SYNOPSIS
    Tests the Graph API filters for legacy auth sign-ins.
.DESCRIPTION
    Run this to verify the clientAppUsed filters work before updating the module.
#>

# Ensure connected
$context = Get-MgContext
if (-not $context) {
    Write-Host "Connect first: Connect-MgGraph -Scopes 'AuditLog.Read.All'" -ForegroundColor Red
    return
}

$startDate = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')

# Legacy protocols to test
$legacyProtocols = @(
    'IMAP4'
    'POP3'
    'SMTP'
    'Authenticated SMTP'
    'Exchange ActiveSync'
    'MAPI Over HTTP'
    'Outlook Anywhere (RPC over HTTP)'
    'Exchange Web Services'
    'AutoDiscover'
    'Other clients'
)

Write-Host "`n=== Testing Legacy Auth Filters ===" -ForegroundColor Cyan
Write-Host "Date filter: createdDateTime ge $startDate" -ForegroundColor Gray
Write-Host ""

$totalFound = 0

foreach ($protocol in $legacyProtocols) {
    $filter = "createdDateTime ge $startDate and clientAppUsed eq '$protocol'"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=5&`$select=id,clientAppUsed,userPrincipalName"
    
    try {
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $count = $result.value.Count
        $hasMore = $null -ne $result.'@odata.nextLink'
        
        if ($count -gt 0 -or $hasMore) {
            Write-Host "[OK] $protocol : $count+ results" -ForegroundColor Green
            $totalFound += $count
        } else {
            Write-Host "[--] $protocol : 0 results" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[ERROR] $protocol : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Total legacy sign-ins found (sample): $totalFound" -ForegroundColor White
Write-Host ""
Write-Host "If filters work, the new implementation can proceed!" -ForegroundColor Green
