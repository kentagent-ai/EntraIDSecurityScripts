<#
.SYNOPSIS
    Identifies enterprise applications with excessive Microsoft Graph API permissions.
.DESCRIPTION
    Audits service principals for overprivileged Graph API permissions that could pose security risks.
.EXAMPLE
    Get-ExcessiveAppPermissions
.NOTES
    Author: Kent Agent (kentagent-ai)
    Permissions: Application.Read.All, Directory.Read.All
#>
function Get-ExcessiveAppPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludeMicrosoftApps = $false,
        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )
    
    $highRiskPerms = @(
        'Mail.ReadWrite.All', 'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
        'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'User.ReadWrite.All',
        'Group.ReadWrite.All', 'Domain.ReadWrite.All', 'IdentityRiskEvent.ReadWrite.All'
    )
    
    $results = @()
    
    # PERFORMANCE: Filter and select only needed properties
    $filter = if (-not $IncludeMicrosoftApps) {
        "appOwnerOrganizationId ne '72f988bf-86f1-41af-91ab-2d7cd011db47'"
    } else { $null }
    
    $sps = if ($filter) {
        Get-MgServicePrincipal -Filter $filter -Select Id,DisplayName,AppId,ServicePrincipalType,AppRoles -All
    } else {
        Get-MgServicePrincipal -Select Id,DisplayName,AppId,ServicePrincipalType,AppRoles -All
    }
    
    foreach ($sp in $sps) {
        
        $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
        $riskyPerms = @()
        
        foreach ($assignment in $appRoles) {
            $perm = ($sp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }).Value
            if ($perm -in $highRiskPerms) {
                $riskyPerms += $perm
            }
        }
        
        if ($riskyPerms) {
            $results += [PSCustomObject]@{
                DisplayName = $sp.DisplayName
                AppId = $sp.AppId
                ServicePrincipalType = $sp.ServicePrincipalType
                RiskyPermissions = ($riskyPerms -join ', ')
                PermissionCount = $riskyPerms.Count
                RiskLevel = if ($riskyPerms.Count -gt 3) { 'HIGH' } else { 'MEDIUM' }
            }
        }
    }
    
    if ($ExportPath) {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation
    }
    
    return $results | Sort-Object RiskLevel, PermissionCount -Descending
}
Export-ModuleMember -Function Get-ExcessiveAppPermissions -ErrorAction SilentlyContinue
