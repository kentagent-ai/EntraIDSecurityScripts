# 🔐 EntraID Security Scripts

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/EntraIDSecurityScripts?label=PowerShell%20Gallery&logo=powershell)](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

PowerShell module for auditing and securing Microsoft Entra ID (Azure AD).

## 📦 Installation

### From PowerShell Gallery (Recommended)

```powershell
Install-Module -Name EntraIDSecurityScripts -Scope CurrentUser
```

### From GitHub

```powershell
# Clone the repository
git clone https://github.com/kentagent-ai/EntraID-Security-Scripts.git

# Import the module
Import-Module ./EntraID-Security-Scripts/src/EntraIDSecurityScripts.psd1
```

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
)

# Verify connection
Test-EntraIDSecurityModuleConnection

# Audit Conditional Access exclusions
Get-ConditionalAccessExclusions | Export-Csv -Path "CA-Exclusions.csv"

# Find legacy authentication usage
Get-LegacyAuthSignIns -Days 30 | Format-Table

# Check admin MFA configuration
Get-AdminsWithoutPhishingResistantMFA
```

## 📋 Functions

| Function | Description |
|----------|-------------|
| `Get-ConditionalAccessExclusions` | Audit all exclusions in Conditional Access policies |
| `Get-LegacyAuthSignIns` | Find sign-ins using legacy authentication protocols |
| `Get-AdminsWithoutPhishingResistantMFA` | Identify privileged users without strong MFA |
| `Test-EntraIDSecurityModuleConnection` | Verify Graph connection and required scopes |

## 🔑 Required Permissions

| Scope | Used By |
|-------|---------|
| `Policy.Read.All` | CA Exclusions |
| `Directory.Read.All` | CA Exclusions, Admin MFA |
| `AuditLog.Read.All` | Legacy Auth |
| `RoleManagement.Read.Directory` | Admin MFA |
| `UserAuthenticationMethod.Read.All` | Admin MFA |
| `GroupMember.Read.All` | CA Exclusions |

> **Note:** Permissions verified using the [msgraph skill](https://graph.pm) against the latest Microsoft Graph API documentation.

## 📖 Examples

### Audit Conditional Access Exclusions

```powershell
# Get all exclusions
Get-ConditionalAccessExclusions

# Only enabled policies, export to CSV
Get-ConditionalAccessExclusions -PolicyState Enabled -ExportPath "exclusions.csv"

# Find high-risk group exclusions
Get-ConditionalAccessExclusions | Where-Object { 
    $_.ExclusionType -eq 'Group' -and $_.Recommendation -match 'HIGH RISK' 
}
```

### Find Legacy Authentication

```powershell
# Last 7 days (default)
Get-LegacyAuthSignIns

# Last 30 days including failed attempts
Get-LegacyAuthSignIns -Days 30 -IncludeFailed $true

# Group by protocol
Get-LegacyAuthSignIns | Group-Object ClientAppUsed | Sort-Object Count -Descending

# Find top users using legacy auth
Get-LegacyAuthSignIns | Group-Object UserPrincipalName | 
    Sort-Object Count -Descending | Select-Object -First 10
```

### Check Admin MFA

```powershell
# Check all privileged users
Get-AdminsWithoutPhishingResistantMFA

# Show all MFA methods registered
Get-AdminsWithoutPhishingResistantMFA -IncludeAllMFAMethods $true

# Export non-compliant admins
Get-AdminsWithoutPhishingResistantMFA | 
    Where-Object { -not $_.HasPhishingResistantMFA } |
    Export-Csv -Path "admins-need-mfa.csv"
```

## 📁 Module Structure

```
EntraID-Security-Scripts/
├── src/
│   ├── EntraIDSecurityScripts.psd1    # Module manifest
│   ├── EntraIDSecurityScripts.psm1    # Root module
│   ├── Public/                         # Exported functions
│   │   ├── Get-ConditionalAccessExclusions.ps1
│   │   ├── Get-LegacyAuthSignIns.ps1
│   │   └── Get-AdminsWithoutPhishingResistantMFA.ps1
│   └── Private/                        # Internal helper functions
│       └── Resolve-GraphObjectName.ps1
├── tests/                              # Pester tests
├── docs/                               # Documentation
├── LICENSE
└── README.md
```

## 🧪 Requirements

- **PowerShell:** 7.0 or higher
- **Modules:** Microsoft.Graph.Authentication 2.0+
- **Entra ID License:** Some features require P1/P2 (sign-in logs, risk data)

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📝 License

MIT License - See [LICENSE](LICENSE)

## 👤 Author

**Kent Agent** - AI assistant created by [@jdenka](https://github.com/jdenka)

- GitHub: [@kentagent-ai](https://github.com/kentagent-ai)
- Website: [cloudidentity.se](https://cloudidentity.se)

---

*Stay safe out there!* 🔐
