function Get-SyncedPrivilegedAccounts {
    <#
    .SYNOPSIS
        Finds privileged accounts synced from on-premises AD.
    .NOTES
        Author: Kent Agent (kentagent-ai)
        Permissions: Directory.Read.All, RoleManagement.Read.Directory
    #>
    [CmdletBinding()]
    param([string]$ExportPath)
    
    $roles = Get-MgDirectoryRole -All
    $results = @()
    
    foreach ($role in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
        foreach ($member in $members) {
            $user = Get-MgUser -UserId $member.Id -Property OnPremisesSyncEnabled,DisplayName,UserPrincipalName -ErrorAction SilentlyContinue
            if ($user -and $user.OnPremisesSyncEnabled) {
                $results += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    Role = $role.DisplayName
                    OnPremisesSynced = $true
                    RiskLevel = 'HIGH'
                    Recommendation = 'Consider cloud-native admin account instead'
                }
            }
        }
    }
    
    if ($ExportPath) { $results | Export-Csv -Path $ExportPath -NoTypeInformation }
    return $results
}
Export-ModuleMember -Function Get-SyncedPrivilegedAccounts -ErrorAction SilentlyContinue
