<#
.SYNOPSIS
    Identifies enterprise applications with excessive Microsoft Graph API permissions.

.DESCRIPTION
    Audits service principals for overprivileged Graph API permissions that could pose security risks.
    Checks for high-risk application permissions like Directory.ReadWrite.All, Mail.ReadWrite.All, etc.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party applications in the audit. Default is $false.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-ExcessiveAppPermissions

    Returns all third-party apps with excessive permissions.

.EXAMPLE
    Get-ExcessiveAppPermissions | Where-Object { $_.RiskLevel -eq 'HIGH' }

    Shows only high-risk apps (more than 3 risky permissions).

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Updated: 2026-03-12 (v2.2.5 - fixed Graph API filtering)
    Requires: Microsoft.Graph PowerShell module
    Permissions: Application.Read.All, Directory.Read.All

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-ExcessiveAppPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludeMicrosoftApps = $false,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Application.Read.All', 'Directory.Read.All'"
        }

        # Microsoft's tenant ID
        $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'

        # High-risk application (not delegated) permissions
        $highRiskPerms = @(
            'Mail.ReadWrite.All'
            'Mail.Read.All'
            'Mail.Send'
            'Directory.ReadWrite.All'
            'RoleManagement.ReadWrite.Directory'
            'Application.ReadWrite.All'
            'AppRoleAssignment.ReadWrite.All'
            'User.ReadWrite.All'
            'Group.ReadWrite.All'
            'Domain.ReadWrite.All'
            'IdentityRiskEvent.ReadWrite.All'
            'Policy.ReadWrite.ConditionalAccess'
            'UserAuthenticationMethod.ReadWrite.All'
            'Files.ReadWrite.All'
            'Sites.ReadWrite.All'
        )

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        Write-Verbose "Retrieving service principals..."

        try {
            # Get all service principals - filter client-side to avoid Graph API limitations
            $sps = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, AppOwnerOrganizationId, ServicePrincipalType -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve service principals: $_"
        }

        Write-Host "Analyzing permissions for $($sps.Count) service principals..." -ForegroundColor Cyan

        # Get Microsoft Graph service principal for permission lookups
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property Id, AppRoles -ErrorAction SilentlyContinue

        if (-not $graphSp) {
            Write-Warning "Could not find Microsoft Graph service principal for permission lookups"
        }

        $processedCount = 0
        $skippedMicrosoft = 0

        foreach ($sp in $sps) {
            $processedCount++
            if ($processedCount % 100 -eq 0) {
                Write-Progress -Activity "Analyzing app permissions" -Status "$processedCount of $($sps.Count)" -PercentComplete (($processedCount / $sps.Count) * 100)
            }

            # Filter Microsoft apps client-side
            $isMicrosoftApp = $sp.AppOwnerOrganizationId -eq $microsoftTenantId
            if ($isMicrosoftApp -and -not $IncludeMicrosoftApps) {
                $skippedMicrosoft++
                continue
            }

            # Skip managed identities
            if ($sp.ServicePrincipalType -eq 'ManagedIdentity') {
                continue
            }

            # Get app role assignments (application permissions granted to this SP)
            $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue

            if (-not $appRoles) {
                continue
            }

            $riskyPerms = @()

            foreach ($assignment in $appRoles) {
                # Look up the permission name from the resource's app roles
                $permName = $null

                if ($graphSp -and $assignment.ResourceId -eq $graphSp.Id) {
                    # This is a Graph API permission
                    $permName = ($graphSp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }).Value
                }
                else {
                    # For other resources, use the display name
                    $permName = $assignment.AppRoleId
                }

                if ($permName -and $permName -in $highRiskPerms) {
                    $riskyPerms += $permName
                }
            }

            if ($riskyPerms.Count -gt 0) {
                $riskLevel = if ($riskyPerms.Count -gt 3) { 'HIGH' } 
                             elseif ($riskyPerms.Count -gt 1) { 'MEDIUM' } 
                             else { 'LOW' }

                $results.Add([PSCustomObject]@{
                    DisplayName          = $sp.DisplayName
                    AppId                = $sp.AppId
                    ServicePrincipalId   = $sp.Id
                    ServicePrincipalType = $sp.ServicePrincipalType
                    IsMicrosoftApp       = $isMicrosoftApp
                    RiskyPermissions     = ($riskyPerms -join ', ')
                    PermissionCount      = $riskyPerms.Count
                    RiskLevel            = $riskLevel
                    Recommendation       = switch ($riskLevel) {
                        'HIGH'   { 'Review immediately - excessive high-risk permissions' }
                        'MEDIUM' { 'Review permissions and apply least privilege' }
                        'LOW'    { 'Monitor for unusual activity' }
                    }
                })
            }
        }

        Write-Progress -Activity "Analyzing app permissions" -Completed
    }

    end {
        Write-Verbose "Found $($results.Count) apps with excessive permissions"

        # Summary
        $high = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
        $medium = ($results | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
        $low = ($results | Where-Object { $_.RiskLevel -eq 'LOW' }).Count

        Write-Host "`n=== Excessive App Permissions ===" -ForegroundColor Yellow
        Write-Host "Apps with risky permissions: $($results.Count)" -ForegroundColor White
        Write-Host "Skipped Microsoft apps: $skippedMicrosoft" -ForegroundColor Gray
        Write-Host "HIGH risk (>3 perms): $high" -ForegroundColor $(if ($high -gt 0) { 'Red' } else { 'Green' })
        Write-Host "MEDIUM risk (2-3 perms): $medium" -ForegroundColor $(if ($medium -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "LOW risk (1 perm): $low" -ForegroundColor $(if ($low -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "=================================" -ForegroundColor Yellow

        # Export if requested
        if ($ExportPath) {
            try {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to export results: $_"
            }
        }

        return $results | Sort-Object RiskLevel, PermissionCount -Descending
    }
}

Export-ModuleMember -Function Get-ExcessiveAppPermissions -ErrorAction SilentlyContinue
