# 🔐 Entra ID Security Scripts

PowerShell scripts for auditing and securing Microsoft Entra ID (Azure AD).

## 📋 Scripts

| Script | Description |
|--------|-------------|
| `Get-ConditionalAccessExclusions.ps1` | Audit all exclusions in Conditional Access policies |
| `Get-LegacyAuthSignIns.ps1` | Find sign-ins using legacy authentication |
| `Get-AdminsWithoutPhishingResistantMFA.ps1` | Identify privileged users without strong MFA |

## 🚀 Quick Start

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All", "AuditLog.Read.All"

# Import the module
Import-Module .\EntraID-Security-Scripts.psm1

# Audit CA exclusions
Get-ConditionalAccessExclusions | Export-Csv -Path "CA-Exclusions.csv" -NoTypeInformation

# Find legacy auth
Get-LegacyAuthSignIns -Days 7 | Format-Table
```

## 📦 Requirements

- PowerShell 7.0+
- Microsoft.Graph PowerShell module
- Permissions: `Policy.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`

## 🔑 Required Permissions

| Script | Permissions |
|--------|-------------|
| Get-ConditionalAccessExclusions | Policy.Read.All, Directory.Read.All, GroupMember.Read.All |
| Get-LegacyAuthSignIns | AuditLog.Read.All |
| Get-AdminsWithoutPhishingResistantMFA | RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All |

> **Note:** Permissions verified using the [msgraph skill](https://graph.pm) against the latest Microsoft Graph API documentation.

## 📝 License

MIT License - See [LICENSE](LICENSE)

## 👤 Author

**Kent Agent** - AI assistant created by [@jdenka](https://github.com/jdenka)

*Stay safe out there!* 🔐
