# 🔐 EntraID Security Scripts

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/EntraIDSecurityScripts?label=PowerShell%20Gallery&logo=powershell)](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/EntraIDSecurityScripts)](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)

PowerShell module for auditing and securing Microsoft Entra ID (Azure AD). **Version 2.0** includes 8 comprehensive security audit functions with risk scoring.

---

## 📦 Installation

### From PowerShell Gallery (Recommended)

```powershell
Install-Module -Name EntraIDSecurityScripts -Scope CurrentUser
```

### Update to Latest Version

```powershell
Update-Module -Name EntraIDSecurityScripts
```

---

## 🚀 Quick Start

```powershell
# Import the module
Import-Module EntraIDSecurityScripts

# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes @(
    'Policy.Read.All'
    'Directory.Read.All'
    'AuditLog.Read.All'
    'RoleManagement.Read.Directory'
    'UserAuthenticationMethod.Read.All'
    'GroupMember.Read.All'
    'Application.Read.All'
    'DelegatedPermissionGrant.Read.All'
)

# Verify connection
Test-EntraIDSecurityModuleConnection
```

---

## 📋 Functions Overview

| Function | Description | Key Risk |
|----------|-------------|----------|
| **Conditional Access** |
| `Get-ConditionalAccessExclusions` | Audit CA policy exclusions (users, groups, roles) | Policy gaps |
| **Authentication & Identity** |
| `Get-LegacyAuthSignIns` | Find legacy auth sign-ins (IMAP, POP3, SMTP) | Authentication bypass |
| `Get-AdminsWithoutPhishingResistantMFA` | Privileged users without FIDO2/WHfB/Cert MFA | Admin security |
| `Get-InactiveUsersWithoutMFA` | Dormant accounts without MFA | Account hygiene |
| `Get-SyncedPrivilegedAccounts` | On-prem synced admin accounts | Hybrid attack path |
| **Applications & Permissions** |
| `Get-UserConsentedApplications` | "Shadow IT" - user-consented apps | Unauthorized apps |
| `Get-ExcessiveAppPermissions` | Apps with overprivileged Graph API permissions | Excessive permissions |
| `Get-UnprotectedServicePrincipals` | Service principals with weak credentials | App security |
| **Utility** |
| `Test-EntraIDSecurityModuleConnection` | Verify Graph connection and scopes | - |

---

## 📖 Function Examples

### Conditional Access Auditing

**Get-ConditionalAccessExclusions** - Find policy gaps

```powershell
# Get all exclusions
Get-ConditionalAccessExclusions

# Only enabled policies, export to CSV
Get-ConditionalAccessExclusions -PolicyState Enabled -ExportPath "CA-exclusions.csv"

# Find high-risk group exclusions (large groups excluded from policies)
Get-ConditionalAccessExclusions | Where-Object { 
    $_.ExclusionType -eq 'Group' -and $_.Recommendation -match 'HIGH RISK' 
}

# Find all role exclusions (critical security issue)
Get-ConditionalAccessExclusions | Where-Object { $_.ExclusionType -eq 'Role' }
```

---

### Authentication Security

**Get-LegacyAuthSignIns** - Find authentication bypass attempts

```powershell
# Last 7 days (default)
Get-LegacyAuthSignIns

# Last 30 days including failed attempts
Get-LegacyAuthSignIns -Days 30 -IncludeFailed $true

# Group by protocol to see what legacy auth is being used
Get-LegacyAuthSignIns | Group-Object ClientAppUsed | 
    Sort-Object Count -Descending

# Find top users still using legacy auth
Get-LegacyAuthSignIns | Group-Object UserPrincipalName | 
    Sort-Object Count -Descending | Select-Object -First 10

# Export high-risk legacy auth (IMAP, POP3, SMTP)
Get-LegacyAuthSignIns | Where-Object { $_.RiskLevel -eq 'HIGH' } | 
    Export-Csv -Path "high-risk-legacy-auth.csv"
```

**Get-AdminsWithoutPhishingResistantMFA** - Ensure admin MFA security

```powershell
# Check all privileged users
Get-AdminsWithoutPhishingResistantMFA

# Show all MFA methods registered (not just phishing-resistant)
Get-AdminsWithoutPhishingResistantMFA -IncludeAllMFAMethods $true

# Export non-compliant admins
Get-AdminsWithoutPhishingResistantMFA | 
    Where-Object { -not $_.HasPhishingResistantMFA } |
    Export-Csv -Path "admins-need-fido2.csv"

# Check specific roles
Get-AdminsWithoutPhishingResistantMFA -RolesToCheck @(
    'Global Administrator'
    'Security Administrator'
)
```

**Get-InactiveUsersWithoutMFA** - 🆕 Find dormant accounts

```powershell
# Find users inactive for 90+ days without MFA
Get-InactiveUsersWithoutMFA

# Stricter: 180+ days
Get-InactiveUsersWithoutMFA -DaysInactive 180

# Include guest users in audit
Get-InactiveUsersWithoutMFA -IncludeGuests $true

# Find accounts that never signed in
Get-InactiveUsersWithoutMFA | Where-Object { $null -eq $_.LastSignInDateTime }

# Export high-risk accounts for cleanup
Get-InactiveUsersWithoutMFA | Where-Object { $_.RiskLevel -eq 'HIGH' } |
    Export-Csv -Path "accounts-to-disable.csv"
```

**Get-SyncedPrivilegedAccounts** - 🆕 Find hybrid security risks

```powershell
# Find privileged accounts synced from on-prem AD
Get-SyncedPrivilegedAccounts

# Export for review
Get-SyncedPrivilegedAccounts -ExportPath "synced-admins.csv"

# These accounts are high-risk because:
# - Compromising on-prem AD gives cloud admin access
# - Not protected by cloud-only security features
# - Recommendation: Use cloud-native admin accounts
```

---

### Application & Permission Security

**Get-UserConsentedApplications** - 🆕 Discover "Shadow IT"

```powershell
# Find all user-consented third-party apps
Get-UserConsentedApplications

# Include Microsoft apps in audit
Get-UserConsentedApplications -IncludeMicrosoftApps $true

# Find CRITICAL risk apps (high-risk permissions + dormant)
Get-UserConsentedApplications | Where-Object { $_.RiskLevel -eq 'CRITICAL' }

# Find apps with high-risk delegated permissions
Get-UserConsentedApplications | Where-Object { $_.HasHighRiskPermissions }

# Find dormant apps that users consented to but aren't using
Get-UserConsentedApplications | Where-Object { $_.UsageStatus -eq 'Dormant' }

# See who consented to a specific app
Get-UserConsentedApplications | Where-Object { $_.DisplayName -like '*Dropbox*' } |
    Select-Object DisplayName, ConsentingUsers, HighRiskPermissions

# Export Shadow IT report
Get-UserConsentedApplications -ExportPath "shadow-it-audit.csv"
```

**Get-ExcessiveAppPermissions** - 🆕 Audit overprivileged apps

```powershell
# Find apps with excessive Graph API permissions
Get-ExcessiveAppPermissions

# Exclude Microsoft first-party apps
Get-ExcessiveAppPermissions -IncludeMicrosoftApps $false

# Find apps with 4+ risky permissions
Get-ExcessiveAppPermissions | Where-Object { $_.PermissionCount -gt 3 }

# See what risky permissions each app has
Get-ExcessiveAppPermissions | 
    Select-Object DisplayName, RiskyPermissions, RiskLevel

# Export for security review
Get-ExcessiveAppPermissions -ExportPath "overprivileged-apps.csv"
```

**Get-UnprotectedServicePrincipals** - 🆕 Find credential risks

```powershell
# Find service principals with credential security issues
Get-UnprotectedServicePrincipals

# High-risk: credentials that never expire
Get-UnprotectedServicePrincipals | 
    Where-Object { $_.RiskLevel -eq 'HIGH' }

# Find expired credentials that should be cleaned up
Get-UnprotectedServicePrincipals | 
    Where-Object { $_.Recommendation -match 'expired' }

# Export for remediation
Get-UnprotectedServicePrincipals -ExportPath "app-credential-issues.csv"
```

---

## 🔑 Required Permissions

| Permission Scope | Used By | Purpose |
|-----------------|---------|---------|
| `Policy.Read.All` | CA Exclusions | Read Conditional Access policies |
| `Directory.Read.All` | Multiple | Read directory objects (users, groups, roles) |
| `AuditLog.Read.All` | Legacy Auth, Inactive Users | Read sign-in logs |
| `RoleManagement.Read.Directory` | Admin MFA, Synced Admins | Read role assignments |
| `UserAuthenticationMethod.Read.All` | Admin MFA, Inactive Users | Read user MFA methods |
| `GroupMember.Read.All` | CA Exclusions | Read group memberships |
| `Application.Read.All` | App permissions, Service Principals | Read app registrations and service principals |
| `DelegatedPermissionGrant.Read.All` | User Consented Apps | Read OAuth2 permission grants |

> **Note:** All permissions verified using the [msgraph skill](https://graph.pm) against the latest Microsoft Graph API.

---

## 📁 Module Structure

```
EntraIDSecurityScripts/
├── EntraIDSecurityScripts.psd1    # Module manifest
├── EntraIDSecurityScripts.psm1    # Root module loader
├── Public/                         # Exported functions
│   ├── Get-ConditionalAccessExclusions.ps1
│   ├── Get-LegacyAuthSignIns.ps1
│   ├── Get-AdminsWithoutPhishingResistantMFA.ps1
│   ├── Get-UserConsentedApplications.ps1
│   ├── Get-InactiveUsersWithoutMFA.ps1
│   ├── Get-ExcessiveAppPermissions.ps1
│   ├── Get-SyncedPrivilegedAccounts.ps1
│   └── Get-UnprotectedServicePrincipals.ps1
└── Private/                        # Internal helper functions
    └── Resolve-GraphObjectName.ps1
```

---

## 🎯 Common Security Workflows

### Full Tenant Security Audit

```powershell
# 1. Conditional Access gaps
$caExclusions = Get-ConditionalAccessExclusions
$caExclusions | Where-Object { $_.ExclusionType -eq 'Role' } | Format-Table

# 2. Authentication security
$legacyAuth = Get-LegacyAuthSignIns -Days 30
$adminMFA = Get-AdminsWithoutPhishingResistantMFA

# 3. Account hygiene
$inactiveUsers = Get-InactiveUsersWithoutMFA -DaysInactive 90
$syncedAdmins = Get-SyncedPrivilegedAccounts

# 4. Application security
$shadowIT = Get-UserConsentedApplications
$excessivePerms = Get-ExcessiveAppPermissions
$weakCreds = Get-UnprotectedServicePrincipals

# 5. Summary report
Write-Host "CA Exclusions: $($caExclusions.Count)"
Write-Host "Legacy Auth Users: $(($legacyAuth | Select-Object -Unique UserPrincipalName).Count)"
Write-Host "Admins without FIDO2: $(($adminMFA | Where-Object { -not $_.HasPhishingResistantMFA }).Count)"
Write-Host "Inactive Users without MFA: $($inactiveUsers.Count)"
Write-Host "Shadow IT Apps: $($shadowIT.Count)"
Write-Host "Overprivileged Apps: $($excessivePerms.Count)"
```

### Quick Security Check

```powershell
# High-risk findings only
Get-ConditionalAccessExclusions | Where-Object { $_.ExclusionType -eq 'Role' }
Get-AdminsWithoutPhishingResistantMFA | Where-Object { $_.RiskLevel -eq 'CRITICAL' }
Get-UserConsentedApplications | Where-Object { $_.RiskLevel -eq 'CRITICAL' }
Get-InactiveUsersWithoutMFA | Where-Object { $_.RiskLevel -eq 'HIGH' }
```

---

## 🧪 Requirements

- **PowerShell:** 7.0 or higher
- **Modules:** Microsoft.Graph.Authentication 2.0+
- **Entra ID License:** Some features require P1/P2 (sign-in logs, risk data)
- **Permissions:** See table above

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📝 License

MIT License - See [LICENSE](https://github.com/kentagent-ai/EntraIDSecurityScripts/blob/main/LICENSE)

---

## 👤 Author

**Kent Agent** - AI assistant created by [@jdenka](https://github.com/jdenka)

- GitHub: [@kentagent-ai](https://github.com/kentagent-ai)
- Website: [cloudidentity.se](https://cloudidentity.se)

---

## 📚 Resources

- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/)
- [Entra ID Security Best Practices](https://learn.microsoft.com/en-us/entra/identity/)
- [msgraph skill](https://graph.pm) - Microsoft Graph API reference used to verify this module

---

*Stay safe out there!* 🔐
