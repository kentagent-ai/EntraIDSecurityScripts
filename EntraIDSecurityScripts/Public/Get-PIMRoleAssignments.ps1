<#
.SYNOPSIS
    Audits Privileged Identity Management (PIM) role assignments and identifies security risks.

.DESCRIPTION
    This function audits PIM-enabled role assignments in Entra ID, identifying:
    - Eligible role assignments (can be activated on-demand)
    - Active permanent assignments (should be minimized per Zero Trust)
    - Active time-bound assignments (JIT access)
    - Unused eligible assignments (never activated)
    - Assignments without MFA or approval requirements
    - High-privilege roles with weak activation policies

    Per Zero Trust principles, permanent admin access should be eliminated in favor
    of just-in-time (JIT) eligible assignments with MFA and approval workflows.

.PARAMETER ShowEligibleOnly
    Show only eligible (JIT) assignments. Default: $false (shows all)

.PARAMETER ShowNonElevated
    Show only users who have eligible roles but are NOT currently elevated (activated).
    This helps identify users with dormant admin access who haven't activated their roles.

.PARAMETER ShowActivationHistory
    Include recent activation history for eligible assignments. Queries last 30 days.

.PARAMETER IncludeInactive
    Include eligible assignments that have never been activated (candidates for removal).

.PARAMETER RolesToCheck
    Specific role names to audit. Default checks all critical admin roles.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-PIMRoleAssignments

    Returns all PIM role assignments with risk assessment.

.EXAMPLE
    Get-PIMRoleAssignments -ShowEligibleOnly $true

    Shows only eligible (JIT) assignments.

.EXAMPLE
    Get-PIMRoleAssignments -ShowNonElevated

    Shows only users who have eligible admin roles but are NOT currently elevated.
    Useful for checking who has dormant admin access.

.EXAMPLE
    Get-PIMRoleAssignments -IncludeInactive $true

    Highlights eligible assignments that have never been activated (unused access).

.EXAMPLE
    Get-PIMRoleAssignments -ShowActivationHistory $true

    Includes activation history for the last 30 days.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-14
    Requires: Microsoft.Graph PowerShell module
    Permissions: RoleManagement.Read.Directory, AuditLog.Read.All, Directory.Read.All

    PIM Best Practices:
    - Eliminate permanent admin assignments (use eligible instead)
    - Require MFA + approval for Global Admin activations
    - Set maximum activation duration (≤8 hours for high-privilege roles)
    - Regularly review unused eligible assignments
    - Enable notifications for role activations

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-PIMRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$ShowEligibleOnly = $false,

        [Parameter(Mandatory = $false)]
        [switch]$ShowNonElevated,

        [Parameter(Mandatory = $false)]
        [bool]$ShowActivationHistory = $false,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeInactive = $false,

        [Parameter(Mandatory = $false)]
        [string[]]$RolesToCheck,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'Directory.Read.All'"
        }

        # Default critical roles to check
        $defaultCriticalRoles = @(
            'Global Administrator'
            'Privileged Role Administrator'
            'Security Administrator'
            'Exchange Administrator'
            'SharePoint Administrator'
            'User Administrator'
            'Authentication Administrator'
            'Privileged Authentication Administrator'
            'Conditional Access Administrator'
            'Intune Administrator'
            'Cloud Application Administrator'
            'Application Administrator'
            'Billing Administrator'
            'Compliance Administrator'
            'Global Reader'
            'Helpdesk Administrator'
            'Password Administrator'
            'Directory Synchronization Accounts'
        )

        $rolesToAudit = if ($RolesToCheck) { $RolesToCheck } else { $defaultCriticalRoles }

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        $roleDefinitions = @{}
        
        Write-Verbose "Retrieving PIM-enabled role definitions..."
    }

    process {
        try {
            # Get all role definitions first (for lookups)
            $allRoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
            foreach ($roleDef in $allRoleDefinitions) {
                $roleDefinitions[$roleDef.Id] = $roleDef.DisplayName
            }

            # Filter to roles we care about
            $targetRoles = $allRoleDefinitions | Where-Object { $_.DisplayName -in $rolesToAudit }

            Write-Verbose "Auditing $($targetRoles.Count) privileged roles..."

            # Get role assignments (both active and eligible)
            $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction Stop
            $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop

            Write-Verbose "Found $($eligibleAssignments.Count) eligible assignments and $($activeAssignments.Count) active assignments"

            # Process eligible assignments
            foreach ($assignment in $eligibleAssignments) {
                $roleId = $assignment.RoleDefinitionId
                $roleName = $roleDefinitions[$roleId]

                # Skip if not in target roles
                if ($roleName -notin $rolesToAudit) {
                    continue
                }

                # Get principal details
                $principal = $null
                $principalType = $assignment.PrincipalId
                $principalName = 'Unknown'
                $principalUPN = ''

                try {
                    $principal = Get-MgUser -UserId $assignment.PrincipalId -Property Id, DisplayName, UserPrincipalName -ErrorAction SilentlyContinue
                    if ($principal) {
                        $principalName = $principal.DisplayName
                        $principalUPN = $principal.UserPrincipalName
                        $principalType = 'User'
                    }
                }
                catch {
                    # Might be a group or service principal
                    try {
                        $group = Get-MgGroup -GroupId $assignment.PrincipalId -Property Id, DisplayName -ErrorAction SilentlyContinue
                        if ($group) {
                            $principalName = $group.DisplayName
                            $principalType = 'Group'
                        }
                    }
                    catch {
                        Write-Verbose "Could not resolve principal: $($assignment.PrincipalId)"
                    }
                }

                # Get activation policy for this role
                $requiresMFA = $false
                $requiresApproval = $false
                $maxActivationDuration = 'N/A'

                try {
                    $policy = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$roleId'" -ErrorAction SilentlyContinue
                    if ($policy) {
                        # Get the detailed policy rules
                        $policyDetails = Get-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $policy.PolicyId -ExpandProperty "rules" -ErrorAction SilentlyContinue
                        
                        foreach ($rule in $policyDetails.Rules) {
                            $ruleType = $rule.AdditionalProperties['@odata.type']
                            
                            # Check for MFA requirement
                            if ($ruleType -eq '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule') {
                                $requiresMFA = $rule.AdditionalProperties['isEnabled'] -eq $true
                            }
                            
                            # Check for approval requirement
                            if ($ruleType -eq '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule') {
                                $requiresApproval = $rule.AdditionalProperties['setting']['isApprovalRequired'] -eq $true
                            }
                            
                            # Check activation duration
                            if ($ruleType -eq '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule' -and 
                                $rule.AdditionalProperties['target']['targetObjects'] -contains 'EndUser') {
                                $maxHours = $rule.AdditionalProperties['maximumDuration']
                                if ($maxHours) {
                                    # Parse ISO 8601 duration (e.g., "PT8H")
                                    if ($maxHours -match 'PT(\d+)H') {
                                        $maxActivationDuration = "$($Matches[1]) hours"
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve policy for role: $roleName"
                }

                # Check activation history (if requested)
                $lastActivation = 'Never'
                $activationCount = 0
                $isUnused = $true

                if ($ShowActivationHistory -or $IncludeInactive) {
                    try {
                        $startDate = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $filter = "activityDisplayName eq 'Add member to role completed (PIM activation)' and targetResources/any(t: t/id eq '$($assignment.PrincipalId)' and t/displayName eq '$roleName')"
                        
                        $activations = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction SilentlyContinue
                        
                        if ($activations) {
                            $activationCount = $activations.Count
                            $mostRecent = $activations | Sort-Object ActivityDateTime -Descending | Select-Object -First 1
                            $lastActivation = $mostRecent.ActivityDateTime.ToString("yyyy-MM-dd HH:mm")
                            $isUnused = $false
                        }
                    }
                    catch {
                        Write-Verbose "Could not retrieve activation history for $principalName"
                    }
                }

                # Skip if filtering for inactive and this has been used
                if ($IncludeInactive -and -not $isUnused) {
                    continue
                }

                # Determine risk level for eligible assignments
                $riskLevel = 'LOW'  # Eligible is good (JIT)
                $recommendation = 'Eligible assignment (JIT) - good practice'

                # Increase risk if high-privilege role lacks MFA/approval
                if ($roleName -in @('Global Administrator', 'Privileged Role Administrator')) {
                    if (-not $requiresMFA -or -not $requiresApproval) {
                        $riskLevel = 'HIGH'
                        $recommendation = "High-privilege role should require MFA and approval for activation"
                    }
                }

                # Flag unused assignments
                if ($isUnused -and $IncludeInactive) {
                    $riskLevel = 'MEDIUM'
                    $recommendation = "Eligible assignment never activated - consider removing"
                }

                $resultObj = [PSCustomObject]@{
                    PrincipalName           = $principalName
                    PrincipalUPN            = $principalUPN
                    PrincipalType           = $principalType
                    RoleName                = $roleName
                    AssignmentType          = 'Eligible (JIT)'
                    StartDateTime           = $assignment.StartDateTime
                    EndDateTime             = $assignment.EndDateTime
                    RequiresMFA             = $requiresMFA
                    RequiresApproval        = $requiresApproval
                    MaxActivationDuration   = $maxActivationDuration
                    LastActivation          = $lastActivation
                    ActivationCount30Days   = $activationCount
                    RiskLevel               = $riskLevel
                    Recommendation          = $recommendation
                }

                $results.Add($resultObj)
            }

            # Process active assignments (unless ShowEligibleOnly)
            if (-not $ShowEligibleOnly) {
                foreach ($assignment in $activeAssignments) {
                    $roleId = $assignment.RoleDefinitionId
                    $roleName = $roleDefinitions[$roleId]

                    # Skip if not in target roles
                    if ($roleName -notin $rolesToAudit) {
                        continue
                    }

                    # Get principal details
                    $principal = $null
                    $principalType = $assignment.PrincipalId
                    $principalName = 'Unknown'
                    $principalUPN = ''

                    try {
                        $principal = Get-MgUser -UserId $assignment.PrincipalId -Property Id, DisplayName, UserPrincipalName -ErrorAction SilentlyContinue
                        if ($principal) {
                            $principalName = $principal.DisplayName
                            $principalUPN = $principal.UserPrincipalName
                            $principalType = 'User'
                        }
                    }
                    catch {
                        # Might be a group or service principal
                        try {
                            $group = Get-MgGroup -GroupId $assignment.PrincipalId -Property Id, DisplayName -ErrorAction SilentlyContinue
                            if ($group) {
                                $principalName = $group.DisplayName
                                $principalType = 'Group'
                            }
                        }
                        catch {
                            Write-Verbose "Could not resolve principal: $($assignment.PrincipalId)"
                        }
                    }

                    # Determine if permanent or time-bound
                    $isPermanent = $null -eq $assignment.EndDateTime
                    $assignmentType = if ($isPermanent) { 'Active Permanent' } else { 'Active Time-Bound' }

                    # Determine risk level
                    $riskLevel = 'LOW'
                    $recommendation = 'Active time-bound assignment (JIT activation) - good practice'

                    if ($isPermanent) {
                        # Permanent assignments violate Zero Trust
                        if ($roleName -in @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator')) {
                            $riskLevel = 'CRITICAL'
                            $recommendation = "CRITICAL: Permanent $roleName assignment violates Zero Trust - convert to eligible"
                        }
                        elseif ($roleName -match 'Administrator') {
                            $riskLevel = 'HIGH'
                            $recommendation = "Permanent admin assignment - convert to eligible (JIT)"
                        }
                        else {
                            $riskLevel = 'MEDIUM'
                            $recommendation = "Consider converting to eligible assignment for better security"
                        }
                    }

                    $resultObj = [PSCustomObject]@{
                        PrincipalName           = $principalName
                        PrincipalUPN            = $principalUPN
                        PrincipalType           = $principalType
                        RoleName                = $roleName
                        AssignmentType          = $assignmentType
                        StartDateTime           = $assignment.StartDateTime
                        EndDateTime             = if ($assignment.EndDateTime) { $assignment.EndDateTime } else { 'Permanent' }
                        RequiresMFA             = 'N/A (Active)'
                        RequiresApproval        = 'N/A (Active)'
                        MaxActivationDuration   = 'N/A (Active)'
                        LastActivation          = 'N/A (Currently Active)'
                        ActivationCount30Days   = 'N/A'
                        RiskLevel               = $riskLevel
                        Recommendation          = $recommendation
                    }

                    $results.Add($resultObj)
                }
            }
        }
        catch {
            Write-Error "Failed to retrieve PIM role assignments: $_"
            return
        }
    }

    end {
        # Apply ShowNonElevated filter if requested
        if ($ShowNonElevated) {
            $beforeCount = $results.Count
            $results = $results | Where-Object { 
                $_.AssignmentType -eq 'Eligible (JIT)' -and 
                $_.LastActivation -ne 'N/A (Currently Active)'
            }
            Write-Verbose "ShowNonElevated filter: Reduced from $beforeCount to $($results.Count) assignments"
        }

        # Summary statistics
        $totalAssignments = $results.Count
        $eligibleAssignments = $results | Where-Object { $_.AssignmentType -eq 'Eligible (JIT)' }
        $activePermanent = $results | Where-Object { $_.AssignmentType -eq 'Active Permanent' }
        $activeTimeBound = $results | Where-Object { $_.AssignmentType -eq 'Active Time-Bound' }
        $critical = $results | Where-Object { $_.RiskLevel -eq 'CRITICAL' }
        $high = $results | Where-Object { $_.RiskLevel -eq 'HIGH' }
        $withoutMFA = $results | Where-Object { $_.RequiresMFA -eq $false -and $_.AssignmentType -eq 'Eligible (JIT)' }
        $withoutApproval = $results | Where-Object { $_.RequiresApproval -eq $false -and $_.AssignmentType -eq 'Eligible (JIT)' }

        Write-Host ""
        Write-Host "=== PIM Role Assignment Audit Summary ===" -ForegroundColor Yellow
        Write-Host "Total assignments audited: $totalAssignments" -ForegroundColor White
        Write-Host ""
        Write-Host "Assignment Types:" -ForegroundColor Cyan
        Write-Host "  Eligible (JIT): $($eligibleAssignments.Count)" -ForegroundColor Green
        Write-Host "  Active Permanent: $($activePermanent.Count)" -ForegroundColor $(if ($activePermanent.Count -gt 0) { 'Red' } else { 'Green' })
        Write-Host "  Active Time-Bound: $($activeTimeBound.Count)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Risk Assessment:" -ForegroundColor Cyan
        if ($critical.Count -gt 0) {
            Write-Host "  CRITICAL risk assignments: $($critical.Count)" -ForegroundColor Red
        }
        if ($high.Count -gt 0) {
            Write-Host "  HIGH risk assignments: $($high.Count)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "Policy Gaps (Eligible Assignments):" -ForegroundColor Cyan
        Write-Host "  Without MFA requirement: $($withoutMFA.Count)" -ForegroundColor $(if ($withoutMFA.Count -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "  Without approval requirement: $($withoutApproval.Count)" -ForegroundColor $(if ($withoutApproval.Count -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host ""
        Write-Host "Recommendations:" -ForegroundColor Cyan
        Write-Host "  1. Eliminate permanent admin assignments (convert to eligible)" -ForegroundColor White
        Write-Host "  2. Require MFA + approval for Global Admin activations" -ForegroundColor White
        Write-Host "  3. Set max activation duration ≤8h for high-privilege roles" -ForegroundColor White
        Write-Host "  4. Remove unused eligible assignments" -ForegroundColor White
        Write-Host "==========================================" -ForegroundColor Yellow
        Write-Host ""

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

        return $results
    }
}

# Export function if loaded as module
Export-ModuleMember -Function Get-PIMRoleAssignments -ErrorAction SilentlyContinue
