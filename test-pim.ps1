# Test script for Get-PIMRoleAssignments
# Run this to test the new PIM auditing function

# Import the module (force reload to pick up changes)
Import-Module ./EntraIDSecurityScripts/EntraIDSecurityScripts.psd1 -Force

# Connect to Microsoft Graph (if not already connected)
$context = Get-MgContext
if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes @(
        'RoleManagement.Read.Directory'
        'AuditLog.Read.All'
        'Directory.Read.All'
    )
}

# Test 1: Basic audit (all assignments)
Write-Host "`n=== Test 1: Basic PIM Audit ===" -ForegroundColor Cyan
$allAssignments = Get-PIMRoleAssignments -Verbose

Write-Host "`nFound $($allAssignments.Count) total assignments" -ForegroundColor Green
Write-Host "`nSample results (first 5):" -ForegroundColor Yellow
$allAssignments | Select-Object -First 5 | Format-Table PrincipalName, RoleName, AssignmentType, RiskLevel, Recommendation -AutoSize

# Test 2: Show only eligible (JIT) assignments
Write-Host "`n=== Test 2: Eligible (JIT) Assignments Only ===" -ForegroundColor Cyan
$eligibleOnly = Get-PIMRoleAssignments -ShowEligibleOnly $true
Write-Host "`nFound $($eligibleOnly.Count) eligible assignments" -ForegroundColor Green

# Test 3: Find permanent assignments (high risk)
Write-Host "`n=== Test 3: Permanent Assignments (High Risk) ===" -ForegroundColor Cyan
$permanent = $allAssignments | Where-Object { $_.AssignmentType -eq 'Active Permanent' }
if ($permanent.Count -gt 0) {
    Write-Host "`nWARNING: Found $($permanent.Count) permanent assignments (should be converted to eligible):" -ForegroundColor Red
    $permanent | Format-Table PrincipalName, RoleName, RiskLevel, Recommendation -AutoSize
} else {
    Write-Host "`nNo permanent assignments found - excellent!" -ForegroundColor Green
}

# Test 4: Find assignments without MFA/approval
Write-Host "`n=== Test 4: Policy Gaps (Missing MFA/Approval) ===" -ForegroundColor Cyan
$withoutMFA = $allAssignments | Where-Object { $_.RequiresMFA -eq $false -and $_.AssignmentType -eq 'Eligible (JIT)' }
$withoutApproval = $allAssignments | Where-Object { $_.RequiresApproval -eq $false -and $_.AssignmentType -eq 'Eligible (JIT)' }

Write-Host "`nEligible assignments without MFA: $($withoutMFA.Count)" -ForegroundColor $(if ($withoutMFA.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "Eligible assignments without approval: $($withoutApproval.Count)" -ForegroundColor $(if ($withoutApproval.Count -gt 0) { 'Yellow' } else { 'Green' })

# Test 5: Export results
Write-Host "`n=== Test 5: Export to CSV ===" -ForegroundColor Cyan
$exportPath = "./PIM_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
Get-PIMRoleAssignments -ExportPath $exportPath
Write-Host "Results exported to: $exportPath" -ForegroundColor Green

Write-Host "`n=== All Tests Complete ===" -ForegroundColor Cyan
