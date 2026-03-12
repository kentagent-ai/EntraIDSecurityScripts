# EntraIDSecurityScripts

PowerShell module for auditing and securing Microsoft Entra ID (Azure AD). Built by security professionals for security professionals.

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/EntraIDSecurityScripts)](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)
[![Downloads](https://img.shields.io/powershellgallery/dt/EntraIDSecurityScripts)](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)
[![License](https://img.shields.io/github/license/kentagent-ai/EntraIDSecurityScripts)](LICENSE)

## 🚀 Installation

```powershell
# Install from PowerShell Gallery
Install-Module -Name EntraIDSecurityScripts -Scope CurrentUser

# Import the module
Import-Module EntraIDSecurityScripts

# Connect to Microsoft Graph (required)
Connect-MgGraph -Scopes 'Directory.Read.All', 'AuditLog.Read.All', 'Policy.Read.All'
```

## 📋 Features

### Conditional Access Auditing
- **Get-ConditionalAccessExclusions** - Find all exclusions in CA policies
- Identifies high-risk exclusions (large groups, privileged users)
- Resolves GUIDs to display names automatically

### Legacy Authentication Detection
- **Get-LegacyAuthSignIns** - Find sign-ins using legacy protocols (IMAP, POP3, SMTP)
- Supports both interactive and non-interactive sign-ins
- **v2.2.0: 3-5x faster** with smart pagination

### MFA & Authentication
- **Get-AdminsWithoutPhishingResistantMFA** - Find privileged users without FIDO2/WHfB
- **Get-InactiveUsersWithoutMFA** - Dormant accounts without MFA enabled

### Application Security
- **Get-UserConsentedApplications** - Discover "Shadow IT" via user app consents
- **v2.2.0: 5-10x faster** with parallel processing and batched lookups
- **Get-ExcessiveAppPermissions** - Audit overprivileged Graph API permissions
- **Get-MailSendAppAudit** - Audit apps with Mail.Send permissions for scoping

### Identity Hygiene
- **Get-SyncedPrivilegedAccounts** - Find on-prem synced admin accounts (cloud-only recommended)
- **Get-UnprotectedServicePrincipals** - Service principals with credential issues

### Utilities
- **Test-EntraIDSecurityModuleConnection** - Verify Graph connection and permissions

## 🎯 Quick Start Examples

### Check for legacy authentication
```powershell
# Last 7 days (default)
Get-LegacyAuthSignIns

# Last 30 days with failed attempts
Get-LegacyAuthSignIns -Days 30 -IncludeFailed $true

# Export to CSV
Get-LegacyAuthSignIns | Export-Csv -Path legacy-auth.csv -NoTypeInformation
```

### Audit Conditional Access exclusions
```powershell
# Get all exclusions
Get-ConditionalAccessExclusions

# Show only high-risk exclusions
Get-ConditionalAccessExclusions | Where-Object { $_.RiskLevel -eq 'HIGH' }

# Export to CSV
Get-ConditionalAccessExclusions -ExportPath ca-exclusions.csv
```

### Find Shadow IT (user-consented apps)
```powershell
# Scan for user consents
Get-UserConsentedApplications

# Show only critical/high risk apps
Get-UserConsentedApplications | Where-Object { $_.RiskLevel -in @('CRITICAL', 'HIGH') }

# Include Microsoft apps
Get-UserConsentedApplications -IncludeMicrosoftApps $true
```

### Check admin MFA status
```powershell
# Find admins without phishing-resistant MFA
Get-AdminsWithoutPhishingResistantMFA

# Show only Global Admins
Get-AdminsWithoutPhishingResistantMFA | Where-Object { $_.RoleName -eq 'Global Administrator' }
```

### Audit Mail.Send app permissions (v2.3.0)
```powershell
# Connect to both services
Connect-MgGraph -Scopes "Application.Read.All"
Connect-IPPSSession

# Find apps with Mail.Send and check their usage
Get-MailSendAppAudit -Days 30

# Export apps that can be scoped
Get-MailSendAppAudit | Where-Object { $_.CanScope } | Export-Csv apps-to-scope.csv
```

### Find inactive users without MFA
```powershell
# Default: 90+ days inactive
Get-InactiveUsersWithoutMFA

# Custom inactivity threshold
Get-InactiveUsersWithoutMFA -DaysInactive 180

# Quick scan (first 500 users)
Get-InactiveUsersWithoutMFA -MaxResults 500
```

## 📖 Getting Help

All functions have detailed help documentation:

```powershell
# List all available commands
Get-Command -Module EntraIDSecurityScripts

# Get detailed help for a function
Get-Help Get-LegacyAuthSignIns -Full

# See examples
Get-Help Get-UserConsentedApplications -Examples

# View online help
Get-Help Get-ConditionalAccessExclusions -Online
```

## 🔐 Required Permissions

Connect with the following Graph API permissions:

```powershell
Connect-MgGraph -Scopes @(
    'Directory.Read.All'              # Read users, groups, roles
    'AuditLog.Read.All'               # Read sign-in logs
    'Policy.Read.All'                 # Read Conditional Access policies
    'Application.Read.All'            # Read app registrations
    'DelegatedPermissionGrant.Read.All'  # Read OAuth consents
)
```

## ⚡ Performance (v2.2.0)

Major performance improvements in v2.2.0:

### Get-UserConsentedApplications
- **5-10x faster** on large tenants
- Parallel processing with `ForEach-Object -Parallel` (PowerShell 7+)
- Batched user lookups (15 users per API call vs 1 per user)
- Property selection reduces payload size
- Progress tracking for long operations

```powershell
# Control parallelism
Get-UserConsentedApplications -ThrottleLimit 20  # Default: 10
```

### Get-LegacyAuthSignIns
- **3-5x faster** with lower memory usage
- Combined queries with smart pagination
- Server-side property selection
- Progress tracking

```powershell
# Quick scan mode
Get-LegacyAuthSignIns -MaxResults 1000  # Default: 5000
```

## 📊 Risk Levels

All audit functions provide risk assessments:

- **CRITICAL** - Immediate action required (e.g., dormant app with high-risk permissions)
- **HIGH** - Review urgently (e.g., IMAP/POP3/SMTP usage, admin without MFA)
- **MEDIUM** - Schedule for review (e.g., dormant user accounts)
- **LOW** - Monitor (e.g., low-privilege apps, compliant configs)

## 🔄 Update & Changelog

```powershell
# Update to latest version
Update-Module -Name EntraIDSecurityScripts

# Check installed version
Get-Module -Name EntraIDSecurityScripts -ListAvailable
```

### Version History

**v2.2.0** (March 2026) - Performance Update
- 5-10x faster `Get-UserConsentedApplications` with parallel processing
- 3-5x faster `Get-LegacyAuthSignIns` with smart pagination
- New parameters: `-ThrottleLimit`, `-MaxResults`

**v2.1.0** (March 2026) - Optimization Update
- API-level filtering for faster queries
- Property selection to reduce payload sizes
- MFA check optimizations

**v2.0.0** (March 2026) - Major Feature Release
- 5 new security audit functions
- Risk scoring across all functions
- Enhanced documentation

**v1.0.x** (March 2026) - Initial Release
- Core auditing functions
- Conditional Access, legacy auth, MFA checks

## 🤝 Contributing

Contributions welcome! Please open issues or pull requests at:
https://github.com/kentagent-ai/EntraIDSecurityScripts

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Kent Agent** (kentagent-ai)  
Cloud Identity AB - Microsoft Identity & Security Consulting

## 🔗 Resources

- [PowerShell Gallery](https://www.powershellgallery.com/packages/EntraIDSecurityScripts)
- [GitHub Repository](https://github.com/kentagent-ai/EntraIDSecurityScripts)
- [Cloud Identity Blog](https://cloudidentity.se)

## ⚠️ Disclaimer

This module is provided as-is for auditing and security assessment purposes. Always test in a non-production environment first. The authors are not responsible for any unintended consequences of using this module.

---

**Found a security issue?** Please report responsibly via GitHub issues or email.
