<#
.SYNOPSIS
    Audits all exclusions in Conditional Access policies.

.DESCRIPTION
    This function retrieves all Conditional Access policies and identifies excluded
    users, groups, roles, and applications. It resolves GUIDs to display names and
    provides a comprehensive report of all exclusions that should be reviewed.

    Exclusions are often the weakest point in Conditional Access policies and should
    be regularly audited to ensure they are still justified.

.PARAMETER PolicyState
    Filter policies by state. Valid values: 'All', 'Enabled', 'Disabled', 'ReportOnly'.
    Default is 'All'.

.PARAMETER IncludeApplicationExclusions
    Include excluded applications in the output. Default is $true.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-ConditionalAccessExclusions

    Returns all exclusions from all Conditional Access policies.

.EXAMPLE
    Get-ConditionalAccessExclusions -PolicyState Enabled | Format-Table

    Returns exclusions only from enabled policies.

.EXAMPLE
    Get-ConditionalAccessExclusions -ExportPath "C:\Reports\CA-Exclusions.csv"

    Exports all exclusions to a CSV file.

.EXAMPLE
    Get-ConditionalAccessExclusions | Where-Object { $_.ExclusionType -eq 'User' }

    Returns only user exclusions.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Requires: Microsoft.Graph PowerShell module
    Permissions: Policy.Read.All, Directory.Read.All

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-ConditionalAccessExclusions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Enabled', 'Disabled', 'ReportOnly')]
        [string]$PolicyState = 'All',

        [Parameter(Mandatory = $false)]
        [bool]$IncludeApplicationExclusions = $true,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All'"
        }

        # Check required scopes
        $requiredScopes = @('Policy.Read.All', 'Directory.Read.All')
        $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
        if ($missingScopes) {
            Write-Warning "Missing scopes: $($missingScopes -join ', '). Some lookups may fail."
        }

        # Cache for resolved names (avoid repeated API calls)
        $script:nameCache = @{}

        function Resolve-ObjectName {
            param([string]$ObjectId, [string]$ObjectType)
            
            if ([string]::IsNullOrEmpty($ObjectId)) { return $null }
            if ($ObjectId -eq 'All') { return 'All' }
            if ($ObjectId -eq 'None') { return 'None' }
            if ($ObjectId -eq 'GuestsOrExternalUsers') { return 'Guests or External Users' }
            
            $cacheKey = "$ObjectType-$ObjectId"
            if ($script:nameCache.ContainsKey($cacheKey)) {
                return $script:nameCache[$cacheKey]
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
                            # Try role template
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
                }
            }
            catch {
                Write-Verbose "Could not resolve $ObjectType $ObjectId : $_"
            }

            $script:nameCache[$cacheKey] = $name
            return $name
        }

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        Write-Verbose "Retrieving Conditional Access policies..."
        
        try {
            $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve Conditional Access policies: $_"
        }

        # Filter by state if specified
        if ($PolicyState -ne 'All') {
            $stateMap = @{
                'Enabled'    = 'enabled'
                'Disabled'   = 'disabled'
                'ReportOnly' = 'enabledForReportingButNotEnforced'
            }
            $policies = $policies | Where-Object { $_.State -eq $stateMap[$PolicyState] }
        }

        Write-Verbose "Processing $($policies.Count) policies..."

        foreach ($policy in $policies) {
            $policyName = $policy.DisplayName
            $policyState = $policy.State
            $policyId = $policy.Id

            # Process excluded users
            if ($policy.Conditions.Users.ExcludeUsers) {
                foreach ($userId in $policy.Conditions.Users.ExcludeUsers) {
                    $displayName = Resolve-ObjectName -ObjectId $userId -ObjectType 'User'
                    $results.Add([PSCustomObject]@{
                        PolicyName      = $policyName
                        PolicyId        = $policyId
                        PolicyState     = $policyState
                        ExclusionType   = 'User'
                        ExcludedId      = $userId
                        ExcludedName    = $displayName
                        Recommendation  = 'Review if user exclusion is still justified'
                    })
                }
            }

            # Process excluded groups
            if ($policy.Conditions.Users.ExcludeGroups) {
                foreach ($groupId in $policy.Conditions.Users.ExcludeGroups) {
                    $displayName = Resolve-ObjectName -ObjectId $groupId -ObjectType 'Group'
                    
                    # Get group member count for risk assessment
                    $memberCount = $null
                    try {
                        $members = Get-MgGroupMember -GroupId $groupId -CountVariable count -Top 1 -ErrorAction SilentlyContinue
                        $memberCount = $count
                    } catch {}

                    $recommendation = if ($memberCount -gt 50) {
                        "HIGH RISK: Large group ($memberCount members) - Review membership"
                    } elseif ($memberCount -gt 10) {
                        "MEDIUM RISK: Group has $memberCount members - Verify all are justified"
                    } else {
                        "Review if group exclusion is still justified"
                    }

                    $results.Add([PSCustomObject]@{
                        PolicyName      = $policyName
                        PolicyId        = $policyId
                        PolicyState     = $policyState
                        ExclusionType   = 'Group'
                        ExcludedId      = $groupId
                        ExcludedName    = $displayName
                        MemberCount     = $memberCount
                        Recommendation  = $recommendation
                    })
                }
            }

            # Process excluded roles
            if ($policy.Conditions.Users.ExcludeRoles) {
                foreach ($roleId in $policy.Conditions.Users.ExcludeRoles) {
                    $displayName = Resolve-ObjectName -ObjectId $roleId -ObjectType 'Role'
                    $results.Add([PSCustomObject]@{
                        PolicyName      = $policyName
                        PolicyId        = $policyId
                        PolicyState     = $policyState
                        ExclusionType   = 'Role'
                        ExcludedId      = $roleId
                        ExcludedName    = $displayName
                        Recommendation  = 'CRITICAL: Excluding roles weakens security posture'
                    })
                }
            }

            # Process excluded guests/external users
            if ($policy.Conditions.Users.ExcludeGuestsOrExternalUsers) {
                $guestConfig = $policy.Conditions.Users.ExcludeGuestsOrExternalUsers
                $results.Add([PSCustomObject]@{
                    PolicyName      = $policyName
                    PolicyId        = $policyId
                    PolicyState     = $policyState
                    ExclusionType   = 'GuestsOrExternalUsers'
                    ExcludedId      = 'GuestsOrExternalUsers'
                    ExcludedName    = "Guest types: $($guestConfig.GuestOrExternalUserTypes -join ', ')"
                    Recommendation  = 'Review if guest exclusion aligns with Zero Trust principles'
                })
            }

            # Process excluded applications
            if ($IncludeApplicationExclusions -and $policy.Conditions.Applications.ExcludeApplications) {
                foreach ($appId in $policy.Conditions.Applications.ExcludeApplications) {
                    $displayName = Resolve-ObjectName -ObjectId $appId -ObjectType 'Application'
                    $results.Add([PSCustomObject]@{
                        PolicyName      = $policyName
                        PolicyId        = $policyId
                        PolicyState     = $policyState
                        ExclusionType   = 'Application'
                        ExcludedId      = $appId
                        ExcludedName    = $displayName
                        Recommendation  = 'Verify application exclusion is documented and necessary'
                    })
                }
            }
        }
    }

    end {
        Write-Verbose "Found $($results.Count) exclusions across $($policies.Count) policies"

        # Export if path specified
        if ($ExportPath) {
            try {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to export results: $_"
            }
        }

        # Return results
        return $results
    }
}

# Export function if loaded as module
Export-ModuleMember -Function Get-ConditionalAccessExclusions -ErrorAction SilentlyContinue
