# Changelog - Version 2.5.1

**Release Date:** March 17, 2026

## Enhancement: Get-PIMRoleAssignments

### New Parameter: `-ShowNonElevated`

Added a switch parameter to filter PIM role assignments and show only users who have **eligible roles but are NOT currently elevated** (activated).

#### Use Cases
- **Identify dormant admin access:** Find users who have admin privileges available but haven't elevated
- **Security auditing:** Check who has "sleeping" admin rights in your tenant
- **Compliance reporting:** Report on eligible-but-inactive privileged accounts
- **User training:** Identify users who may need reminders about when to elevate

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
2. **Exclude:** Users where `LastActivation = "N/A (Currently Active)"` (meaning they ARE elevated)

This gives you a clean view of users who **have the key but haven't unlocked the door yet**.

#### Comparison with Other Parameters

| Parameter | What It Shows |
|-----------|---------------|
| *(none)* | All assignments (eligible + active permanent + active time-bound) |
| `-ShowEligibleOnly $true` | Only eligible assignments (includes currently activated ones) |
| `-ShowNonElevated` | Only eligible assignments where user is NOT currently elevated |
| `-IncludeInactive $true` | Highlights eligible assignments never activated (with all other assignments) |

#### Example Output

```
PrincipalName           : John Doe
PrincipalUPN            : john.doe@contoso.com
RoleName                : Global Administrator
AssignmentType          : Eligible (JIT)
RequiresMFA             : True
RequiresApproval        : True
LastActivation          : 2026-03-10 14:23:00
ActivationCount30Days   : 3
```

This shows John has Global Admin eligible, is not currently elevated, but has activated it 3 times in the last 30 days.

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
