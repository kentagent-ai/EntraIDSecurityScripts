<#
.SYNOPSIS
    Resolves Microsoft Graph object GUIDs to display names.

.DESCRIPTION
    Helper function to resolve user, group, role, and application GUIDs
    to their display names. Uses caching to minimize API calls.
#>
function Resolve-GraphObjectName {
    param(
        [Parameter(Mandatory)]
        [string]$ObjectId,
        
        [Parameter(Mandatory)]
        [ValidateSet('User', 'Group', 'Role', 'Application', 'ServicePrincipal')]
        [string]$ObjectType
    )
    
    # Handle special values
    if ([string]::IsNullOrEmpty($ObjectId)) { return $null }
    if ($ObjectId -eq 'All') { return 'All' }
    if ($ObjectId -eq 'None') { return 'None' }
    if ($ObjectId -eq 'GuestsOrExternalUsers') { return 'Guests or External Users' }
    
    # Check cache
    $cacheKey = "$ObjectType-$ObjectId"
    if ($script:GraphNameCache -and $script:GraphNameCache.ContainsKey($cacheKey)) {
        return $script:GraphNameCache[$cacheKey]
    }

    # Initialize cache if needed
    if (-not $script:GraphNameCache) {
        $script:GraphNameCache = @{}
    }

    $name = $ObjectId
    try {
        switch ($ObjectType) {
            'User' {
                $obj = Get-MgUser -UserId $ObjectId -Property DisplayName -ErrorAction SilentlyContinue
                if ($obj) { $name = $obj.DisplayName }
            }
            'Group' {
                $obj = Get-MgGroup -GroupId $ObjectId -Property DisplayName -ErrorAction SilentlyContinue
                if ($obj) { $name = $obj.DisplayName }
            }
            'Role' {
                $obj = Get-MgDirectoryRole -DirectoryRoleId $ObjectId -ErrorAction SilentlyContinue
                if (-not $obj) {
                    $template = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $ObjectId -ErrorAction SilentlyContinue
                    if ($template) { $name = $template.DisplayName }
                } else {
                    $name = $obj.DisplayName
                }
            }
            'Application' {
                $obj = Get-MgServicePrincipal -Filter "appId eq '$ObjectId'" -ErrorAction SilentlyContinue
                if ($obj) { $name = $obj.DisplayName }
            }
            'ServicePrincipal' {
                $obj = Get-MgServicePrincipal -ServicePrincipalId $ObjectId -Property DisplayName -ErrorAction SilentlyContinue
                if ($obj) { $name = $obj.DisplayName }
            }
        }
    }
    catch {
        Write-Verbose "Could not resolve $ObjectType $ObjectId : $_"
    }

    $script:GraphNameCache[$cacheKey] = $name
    return $name
}
