# Changelog - Version 2.5.1

**Release Date:** March 17, 2026

## Enhancement: Get-PIMRoleAssignments

### New Parameter: `-ShowNonElevated`

Added a switch parameter to filter PIM role assignments and show only users who have **eligible roles but have NEVER activated them** (not even once).

#### Use Cases
- **Identify unused eligible assignments:** Find users who were granted JIT access but never used it
- **Security cleanup:** Remove unnecessary eligible assignments (reduce attack surface)
- **Compliance reporting:** Report on unused privileged access grants
- **Access review:** Validate that eligible assignments are actually needed

#### Syntax
```powershell
Get-PIMRoleAssignments -ShowNonElevated
```

#### Examples

**Basic usage:**
```powershell
# Show all users with eligible roles who are not currently elevated
Get-PIMRoleAssignments -ShowNonElevated
```

**Export to CSV:**
```powershell
# Export non-elevated eligible users to CSV for reporting
Get-PIMRoleAssignments -ShowNonElevated -ExportPath ./dormant-admin-access.csv
```

**Combine with activation history:**
```powershell
# Show non-elevated users with their activation history
Get-PIMRoleAssignments -ShowNonElevated -ShowActivationHistory $true
```

**Check specific roles:**
```powershell
# Show non-elevated users for Global Admin role only
Get-PIMRoleAssignments -ShowNonElevated -RolesToCheck @('Global Administrator')
```

#### How It Works

The `-ShowNonElevated` switch filters the results to:
1. **Include:** Users with `AssignmentType = "Eligible (JIT)"`
2. **Include:** Users where `LastActivation = "Never"` (never activated, not even once)
3. **Automatically checks activation history** (queries audit logs for last 30 days)

This gives you a clean view of users who **were granted eligible access but never used it**.

#### Comparison with Other Parameters

| Parameter | What It Shows |
|-----------|---------------|
| *(none)* | All assignments (eligible + active permanent + active time-bound) |
| `-ShowEligibleOnly $true` | Only eligible assignments (includes both used and never-used) |
| `-ShowNonElevated` | Only eligible assignments that have NEVER been activated |
| `-IncludeInactive $true` | All assignments, but highlights never-activated eligible ones |

#### Example Output

```
PrincipalName           : Jane Smith
PrincipalUPN            : jane.smith@contoso.com
RoleName                : Security Administrator
AssignmentType          : Eligible (JIT)
RequiresMFA             : True
RequiresApproval        : True
LastActivation          : Never
ActivationCount30Days   : 0
```

This shows Jane has Security Admin eligible but has **never activated it** (0 activations in last 30 days). This assignment may be a candidate for removal.

## Module Version
- **Before:** 2.5.0
- **After:** 2.5.1

## Compatibility
- No breaking changes
- Fully backward compatible with 2.5.0
- Requires same permissions: `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `Directory.Read.All`

## Installation

```powershell
# Update the module
Update-Module -Name EntraIDSecurityScripts -Force

# Verify version
Get-Module -Name EntraIDSecurityScripts -ListAvailable | Select-Object Version
```

---

**Previous versions:** See [CHANGELOG.md](./CHANGELOG.md)
