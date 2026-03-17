# 🔐 EntraID Security Scripts

[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/EntraIDSecurityScripts?label=PowerShell%20Gallery&logo=powershell)](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/EntraIDSecurityScripts)](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)

PowerShell module for auditing and securing Microsoft Entra ID (Azure AD). Includes **12 comprehensive security audit functions** with risk scoring, recommendations, and CSV export.

---

## 📦 Installation

```powershell
# Install from PowerShell Gallery
Install-Module -Name EntraIDSecurityScripts -Scope CurrentUser

# Update to latest version
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
    'Application.ReadWrite.All'  # For credential removal / app disabling
    'DelegatedPermissionGrant.Read.All'
)

# Verify connection
Test-EntraIDSecurityModuleConnection
```

---

## 📋 Functions Overview

| Function | Description | Risk Focus |
|----------|-------------|------------|
| **Conditional Access** | | |
| `Get-ConditionalAccessExclusions` | Audit CA policy exclusions (users, groups, roles) | Policy gaps |
| **Authentication & Identity** | | |
| `Get-LegacyAuthSignIns` | Find legacy auth sign-ins (IMAP, POP3, SMTP) | Auth bypass |
| `Get-AdminsWithoutPhishingResistantMFA` | Privileged users without FIDO2/WHfB MFA | Admin security |
| `Get-InactiveUsersWithoutMFA` | Dormant accounts without MFA | Account hygiene |
| `Get-SyncedPrivilegedAccounts` | On-prem synced admin accounts | Hybrid attack path |
| `Get-PIMRoleAssignments` | **NEW** Audit PIM role assignments & policies | Zero Trust / JIT |
| **Applications & Permissions** | | |
| `Get-UserConsentedApplications` | "Shadow IT" - user-consented apps | Unauthorized apps |
| `Get-ExcessiveAppPermissions` | Apps with overprivileged Graph permissions | Least privilege |
| `Get-UnprotectedServicePrincipals` | Service principals with credential issues | App security |
| `Get-MailSendAppAudit` | Apps with Mail.Send for scoping | Mail security |
| `Get-DormantEnterpriseApplications` | **NEW** Inactive apps with no recent sign-ins | App hygiene |
| **Utility** | | |
| `Test-EntraIDSecurityModuleConnection` | Verify Graph connection and scopes | - |

---

## 🆕 New Features

### Get-PIMRoleAssignments (v2.5.0 - NEW!)
Comprehensive Privileged Identity Management (PIM) auditing for Zero Trust compliance.

```powershell
# Audit all PIM assignments (eligible + active)
Get-PIMRoleAssignments

# Show only eligible (JIT) assignments
Get-PIMRoleAssignments -ShowEligibleOnly $true

# Show users with eligible roles who have NEVER activated them
Get-PIMRoleAssignments -ShowNonElevated

# Find unused eligible assignments (never activated) - includes all assignments
Get-PIMRoleAssignments -IncludeInactive $true

# Include activation history (last 30 days)
Get-PIMRoleAssignments -ShowActivationHistory $true

# Export to CSV for compliance reporting
Get-PIMRoleAssignments -ExportPath "PIM_Audit.csv"
```

**Key Findings:**
- ✅ Eligible (JIT) assignments = LOW risk (best practice)
- ⚠️ Permanent admin assignments = CRITICAL/HIGH risk
- 🔍 Unused eligible assignments = removal candidates
- 🚨 Assignments without MFA/approval = policy gaps

**Risk Scoring:**
- **CRITICAL**: Permanent Global Admin / Privileged Role Admin
- **HIGH**: Permanent admin roles without JIT
- **MEDIUM**: Unused eligible assignments
- **LOW**: Properly configured eligible assignments

**Zero Trust Alignment:**
- Identifies permanent vs eligible (JIT) assignments
- Audits activation policies (MFA, approval, max duration)
- Highlights policy gaps (missing MFA/approval requirements)
- Tracks activation history to find unused access

### Get-DormantEnterpriseApplications (NEW)
Find enterprise applications that haven't been used and may be candidates for cleanup.

```powershell
# Find apps inactive for 90+ days (default)
Get-DormantEnterpriseApplications

# Find apps inactive for 180+ days
Get-DormantEnterpriseApplications -DaysInactive 180

# Preview which apps would be disabled
Get-DormantEnterpriseApplications -DisableApps -WhatIf

# Actually disable dormant apps
Get-DormantEnterpriseApplications -DisableApps

# List all currently disabled apps
Get-DormantEnterpriseApplications -DisabledOnly

# Export dormant apps for review
Get-DormantEnterpriseApplications -ExportPath "dormant-apps.csv"
```

**Features:**
- Finds apps with no sign-ins in past X days
- Uses beta API for accurate lastSignInDateTime
- `-DisableApps` with `-WhatIf` support for safe cleanup
- `-DisabledOnly` to audit already-disabled apps
- Risk scoring based on inactivity duration
- Excludes Microsoft first-party and Managed Identities

### Get-UnprotectedServicePrincipals - Credential Removal
Now supports removing expired credentials directly!

```powershell
# Preview what would be removed (safe)
Get-UnprotectedServicePrincipals -RemoveExpiredCredentials -WhatIf

# Remove expired credentials (prompts for confirmation)
Get-UnprotectedServicePrincipals -RemoveExpiredCredentials

# Skip confirmation (use with caution)
Get-UnprotectedServicePrincipals -RemoveExpiredCredentials -Confirm:$false
```

### Get-MailSendAppAudit
Audit applications with Mail.Send permissions to determine if they can be scoped using Application Access Policies.

```powershell
# Connect to both services
Connect-MgGraph -Scopes "Application.Read.All"
Connect-IPPSSession  # For audit logs

# Find apps with Mail.Send and check their usage
Get-MailSendAppAudit -Days 30

# Export apps that can be scoped
Get-MailSendAppAudit | Where-Object { $_.CanScope } | Export-Csv apps-to-scope.csv
```

**Features:**
- Finds YOUR apps (excludes Microsoft first-party)
- Checks audit logs for actual send activity
- Shows which mailboxes each app sends from
- Identifies apps that can be scoped
- Generates `New-ApplicationAccessPolicy` commands
- Flags unused apps (have permission but no sends)

---

## 📖 Function Examples

### Conditional Access Auditing

```powershell
# Get all exclusions
Get-ConditionalAccessExclusions

# Only enabled policies, export to CSV
Get-ConditionalAccessExclusions -PolicyState Enabled -ExportPath "CA-exclusions.csv"

# Find high-risk role exclusions
Get-ConditionalAccessExclusions | Where-Object { $_.ExclusionType -eq 'Role' }
```

### Authentication Security

```powershell
# Find legacy auth sign-ins (last 30 days)
Get-LegacyAuthSignIns -Days 30 -IncludeFailed $true

# Check admin MFA compliance
Get-AdminsWithoutPhishingResistantMFA

# Find dormant accounts without MFA
Get-InactiveUsersWithoutMFA -DaysInactive 90

# Find synced admin accounts (hybrid risk)
Get-SyncedPrivilegedAccounts

# Audit PIM role assignments (Zero Trust compliance)
Get-PIMRoleAssignments

# Find permanent admin assignments (should be JIT)
Get-PIMRoleAssignments | Where-Object { $_.AssignmentType -eq 'Active Permanent' }

# Find users with eligible roles who have NEVER activated them
Get-PIMRoleAssignments -ShowNonElevated

# Find unused eligible assignments (highlights them among all assignments)
Get-PIMRoleAssignments -IncludeInactive $true
```

### Application Security

```powershell
# Discover Shadow IT (user-consented apps)
Get-UserConsentedApplications | Where-Object { $_.RiskLevel -eq 'CRITICAL' }

# Find overprivileged apps
Get-ExcessiveAppPermissions | Where-Object { $_.PermissionCount -gt 3 }

# Audit service principal credentials
Get-UnprotectedServicePrincipals

# Remove expired credentials (with preview)
Get-UnprotectedServicePrincipals -RemoveExpiredCredentials -WhatIf

# Find dormant enterprise apps
Get-DormantEnterpriseApplications -DaysInactive 180

# Audit Mail.Send permissions for scoping
Get-MailSendAppAudit -Days 30
```

---

## 🎯 Quick Security Audit

```powershell
# High-risk findings only
Get-ConditionalAccessExclusions | Where-Object { $_.ExclusionType -eq 'Role' }
Get-AdminsWithoutPhishingResistantMFA | Where-Object { $_.RiskLevel -eq 'CRITICAL' }
Get-PIMRoleAssignments | Where-Object { $_.RiskLevel -in @('CRITICAL', 'HIGH') }
Get-UserConsentedApplications | Where-Object { $_.RiskLevel -eq 'CRITICAL' }
Get-LegacyAuthSignIns | Where-Object { $_.RiskLevel -eq 'HIGH' }
Get-DormantEnterpriseApplications -DaysInactive 180 | Where-Object { $_.RiskLevel -eq 'HIGH' }
```

---

## 🔑 Required Permissions

| Permission Scope | Purpose |
|-----------------|---------|
| `Policy.Read.All` | Read Conditional Access policies |
| `Directory.Read.All` | Read directory objects |
| `AuditLog.Read.All` | Read sign-in and audit logs |
| `RoleManagement.Read.Directory` | Read role assignments |
| `UserAuthenticationMethod.Read.All` | Read user MFA methods |
| `GroupMember.Read.All` | Read group memberships |
| `Application.Read.All` | Read app registrations |
| `Application.ReadWrite.All` | Remove credentials / disable apps |
| `DelegatedPermissionGrant.Read.All` | Read OAuth2 grants |

**For Get-MailSendAppAudit:** Also requires `View-Only Audit Logs` role in Microsoft Purview (Connect-IPPSSession).

---

## 🧪 Requirements

- **PowerShell:** 5.1 or higher (7.x recommended for parallel processing)
- **Modules:** Microsoft.Graph.Authentication, ExchangeOnlineManagement (for audit logs)
- **Entra ID License:** P1/P2 for sign-in logs

---

## 📁 Module Structure

```
EntraIDSecurityScripts/
├── EntraIDSecurityScripts.psd1       # Module manifest
├── EntraIDSecurityScripts.psm1       # Root module loader
├── Public/                            # Exported functions (12)
│   ├── Get-ConditionalAccessExclusions.ps1
│   ├── Get-LegacyAuthSignIns.ps1
│   ├── Get-AdminsWithoutPhishingResistantMFA.ps1
│   ├── Get-PIMRoleAssignments.ps1    # NEW (v2.5.0)
│   ├── Get-UserConsentedApplications.ps1
│   ├── Get-InactiveUsersWithoutMFA.ps1
│   ├── Get-ExcessiveAppPermissions.ps1
│   ├── Get-SyncedPrivilegedAccounts.ps1
│   ├── Get-UnprotectedServicePrincipals.ps1
│   ├── Get-MailSendAppAudit.ps1
│   ├── Get-DormantEnterpriseApplications.ps1
│   └── Test-EntraIDSecurityModuleConnection.ps1
├── Private/                           # Internal helpers
│   └── Resolve-GraphObjectName.ps1
└── en-US/                             # Help documentation
    └── about_EntraIDSecurityScripts.help.txt
```

---

## 🤝 Contributing

Contributions welcome! Please fork and submit a pull request.

---

## 📝 License

MIT License - See [LICENSE](LICENSE)

---

## 👤 Author

**Kent Agent** - AI assistant by [@jdenka](https://github.com/jdenka)

- GitHub: [@kentagent-ai](https://github.com/kentagent-ai)
- Website: [cloudidentity.se](https://cloudidentity.se)

---

*Stay safe out there!* 🔐
