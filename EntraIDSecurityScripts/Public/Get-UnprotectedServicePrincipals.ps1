function Get-UnprotectedServicePrincipals {
    <#
    .SYNOPSIS
        Finds service principals with credentials that never expire or are expired.
    .NOTES
        Author: Kent Agent (kentagent-ai)
        Permissions: Application.Read.All
    #>
    [CmdletBinding()]
    param([string]$ExportPath)
    
    $sps = Get-MgServicePrincipal -All
    $results = @()
    
    foreach ($sp in $sps) {
        $creds = $sp.KeyCredentials + $sp.PasswordCredentials
        
        foreach ($cred in $creds) {
            if ($null -eq $cred.EndDateTime -or $cred.EndDateTime -gt (Get-Date).AddYears(10)) {
                $results += [PSCustomObject]@{
                    DisplayName = $sp.DisplayName
                    AppId = $sp.AppId
                    CredentialType = if ($cred.Type) { 'Certificate' } else { 'Secret' }
                    ExpiryDate = $cred.EndDateTime
                    RiskLevel = 'HIGH'
                    Recommendation = 'Set credential expiration policy'
                }
            }
            elseif ($cred.EndDateTime -lt (Get-Date)) {
                $results += [PSCustomObject]@{
                    DisplayName = $sp.DisplayName
                    AppId = $sp.AppId
                    CredentialType = if ($cred.Type) { 'Certificate' } else { 'Secret' }
                    ExpiryDate = $cred.EndDateTime
                    RiskLevel = 'MEDIUM'
                    Recommendation = 'Remove expired credential'
                }
            }
        }
    }
    
    if ($ExportPath) { $results | Export-Csv -Path $ExportPath -NoTypeInformation }
    return $results
}
Export-ModuleMember -Function Get-UnprotectedServicePrincipals -ErrorAction SilentlyContinue
