# Test script for ShowNonElevated switch
# This demonstrates the new -ShowNonElevated parameter

Write-Host "Testing Get-PIMRoleAssignments -ShowNonElevated" -ForegroundColor Cyan
Write-Host "This will show only users with eligible (JIT) roles who are NOT currently elevated`n" -ForegroundColor Yellow

# Import the module
Import-Module ./EntraIDSecurityScripts/EntraIDSecurityScripts.psd1 -Force

# Example usage (uncomment when connected to Microsoft Graph):
# Connect-MgGraph -Scopes 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'Directory.Read.All'

Write-Host "Usage examples:" -ForegroundColor Green
Write-Host "  Get-PIMRoleAssignments -ShowNonElevated" -ForegroundColor White
Write-Host "  Get-PIMRoleAssignments -ShowNonElevated -ExportPath ./non-elevated-users.csv" -ForegroundColor White
Write-Host "  Get-PIMRoleAssignments -ShowNonElevated -ShowActivationHistory `$true" -ForegroundColor White
Write-Host ""
Write-Host "This will filter to show:" -ForegroundColor Cyan
Write-Host "  ✓ Users with eligible admin roles" -ForegroundColor White
Write-Host "  ✓ Who are NOT currently elevated (not active)" -ForegroundColor White
Write-Host "  ✓ Helps identify dormant admin access" -ForegroundColor White
Write-Host ""
Write-Host "To run the actual query, connect to Graph and uncomment the test line." -ForegroundColor Yellow
