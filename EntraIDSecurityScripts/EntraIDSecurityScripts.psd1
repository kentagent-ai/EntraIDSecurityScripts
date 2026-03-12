@{
    # Module identification
    RootModule        = 'EntraIDSecurityScripts.psm1'
    ModuleVersion     = '2.3.0'
    GUID              = 'a3b5c7d9-e1f2-4a6b-8c0d-2e4f6a8b0c2d'
    
    # Author information
    Author            = 'Kent Agent (kentagent-ai)'
    CompanyName       = 'Cloud Identity AB'
    Copyright         = '(c) 2026 Kent Agent. MIT License.'
    
    # Module description
    Description       = 'PowerShell module for auditing and securing Microsoft Entra ID (Azure AD). Includes functions for auditing Conditional Access exclusions, legacy authentication sign-ins, and privileged user MFA configuration.'
    
    # Minimum PowerShell version (5.1 compatible)
    PowerShellVersion = '5.1'
    
    # Required modules (commented out to allow installation without Graph pre-installed)
    # Users should install Microsoft.Graph.Authentication separately
    # RequiredModules   = @('Microsoft.Graph.Authentication')
    
    # Functions to export
    FunctionsToExport = @(
        'Get-ConditionalAccessExclusions'
        'Get-LegacyAuthSignIns'
        'Get-AdminsWithoutPhishingResistantMFA'
        'Get-UserConsentedApplications'
        'Get-InactiveUsersWithoutMFA'
        'Get-ExcessiveAppPermissions'
        'Get-SyncedPrivilegedAccounts'
        'Get-UnprotectedServicePrincipals'
        'Get-MailSendAppAudit'
        'Test-EntraIDSecurityModuleConnection'
    )
    
    # Cmdlets to export (none - this is a script module)
    CmdletsToExport   = @()
    
    # Variables to export (none)
    VariablesToExport = @()
    
    # Aliases to export
    AliasesToExport   = @()
    
    # Private data / PSData for PowerShell Gallery
    PrivateData       = @{
        PSData = @{
            # Tags for PowerShell Gallery discovery
            Tags         = @(
                'EntraID'
                'AzureAD'
                'Security'
                'Audit'
                'ConditionalAccess'
                'MFA'
                'Identity'
                'Microsoft365'
                'Graph'
                'Compliance'
                'ZeroTrust'
            )
            
            # License URI
            LicenseUri   = 'https://github.com/kentagent-ai/EntraIDSecurityScripts/blob/main/LICENSE'
            
            # Project URI
            ProjectUri   = 'https://github.com/kentagent-ai/EntraIDSecurityScripts'
            
            # Icon URI (optional)
            # IconUri = ''
            
            # Release notes
            ReleaseNotes = @'
## Version 2.3.0 - March 2026

NEW FEATURE - Mail.Send Application Audit

### New Function:
- Get-MailSendAppAudit: Audit apps with Mail.Send permissions
  * Finds YOUR app registrations with Mail.Send/Mail.Send.All
  * Excludes Microsoft first-party apps
  * Checks audit logs for actual send activity
  * Shows which mailboxes each app sends from
  * Identifies apps that can be scoped with Application Access Policies
  * Flags unused apps (have permission but no sends)
  * Generates New-ApplicationAccessPolicy commands

### Compatibility:
- Now compatible with PowerShell 5.1+
- Requires: Microsoft.Graph module, ExchangeOnlineManagement module
- Permissions: Application.Read.All (Graph), View-Only Audit Logs (Compliance)

### Usage:
```powershell
Connect-MgGraph -Scopes "Application.Read.All"
Connect-IPPSSession
Get-MailSendAppAudit -Days 30
```

## Version 2.2.5 - March 2026

BUG FIX - Get-ExcessiveAppPermissions complete rewrite

### Fixed:
- Removed OData filter entirely - Graph API doesn't support 'ne' on appOwnerOrganizationId
- Now filters Microsoft apps client-side (like other functions)
- Added proper Graph permission name lookups

### Improved:
- Better permission detection using Microsoft Graph service principal
- Added more high-risk permissions to check list
- Added progress tracking and summary output
- Skips managed identities
- Shows IsMicrosoftApp column
- Proper risk level recommendations

## Version 2.2.4 - March 2026

BUG FIX - OData GUID filter syntax

### Fixed:
- Get-ExcessiveAppPermissions: Fixed OData filter error "incompatible types Edm.Guid and Edm.String"
- GUIDs in OData filters must not be quoted (Graph API requirement)

## Version 2.2.3 - March 2026

BUG FIX - Microsoft platform certificate detection

### Fixed:
- Get-UnprotectedServicePrincipals now detects Microsoft platform certificates by name pattern
- Excludes certificates with CN=*.microsoft.com, *.azure.com, *.powerva.microsoft.com, etc.
- Fixes false positives for Power Platform, Azure services, and other Microsoft-managed certs

### New Detection Patterns:
- *.microsoft.com, *.azure.com, *.windows.net, *.dynamics.com
- *.office.com, *.sharepoint.com, *.powerapps.com
- *.servicebus.windows.net, *.blob.core.windows.net
- CN=Microsoft*, CN=Azure*

### New Parameters:
- -IncludeMicrosoftCerts $true to include Microsoft platform certs in audit

### Output Improvements:
- Shows count of skipped Microsoft apps and certs in summary
- New IsMicrosoftCert column for transparency

## Version 2.2.2 - March 2026

BUG FIX - Get-UnprotectedServicePrincipals false positives

### Fixed:
- Get-UnprotectedServicePrincipals no longer flags Microsoft-managed certificates
- Excludes Microsoft first-party apps by default (AppOwnerOrganizationId check)
- Excludes managed identities (system-managed credentials)

### Improved:
- Context-aware risk levels for expired credentials (based on days expired)
- Shows IsMicrosoftApp column for transparency
- Detects excessive credential accumulation (>5 credentials)
- Smarter recommendations based on app ownership

### New Parameters:
- -IncludeMicrosoftApps $true to include Microsoft apps in audit

## Version 2.2.1 - March 2026

DOCUMENTATION UPDATE - Complete help system!

### New Documentation:
- README.md with comprehensive examples and quick start guide
- about_EntraIDSecurityScripts.help.txt for PowerShell's help system
- All functions now fully discoverable via Get-Help
- Quick reference cards and workflow examples

### Help Commands:
```powershell
# Module overview
Get-Help about_EntraIDSecurityScripts

# Function help
Get-Help Get-LegacyAuthSignIns -Full
Get-Help Get-UserConsentedApplications -Examples

# List all commands
Get-Command -Module EntraIDSecurityScripts
```

## Version 2.2.0 - March 2026

MAJOR PERFORMANCE UPDATE - Parallel processing & smart batching!

### Performance Improvements:
- Get-UserConsentedApplications: 
  * Parallel processing with ForEach-Object -Parallel (PowerShell 7+)
  * Batched user lookups (15 users per API call vs 1 per user)
  * Property selection (-Select) reduces payload size
  * Progress tracking for long operations
  * **5-10x faster** on large tenants
  
- Get-LegacyAuthSignIns:
  * Combined interactive/non-interactive queries into single paginated fetch
  * Server-side property selection reduces bandwidth
  * Smart pagination with progress tracking
  * MaxResults parameter for quick scans
  * **3-5x faster** with lower memory usage

### New Parameters:
- Get-UserConsentedApplications: -ThrottleLimit (default 10, max 50)
- Get-LegacyAuthSignIns: -MaxResults (default 5000, controls scan depth)

### Breaking Changes:
None - fully backward compatible. PowerShell 7+ recommended for parallel processing.

## Version 2.1.0

PERFORMANCE UPDATE - Significant speed improvements!

### Performance Improvements:
- Get-InactiveUsersWithoutMFA: Filter at API level (5-10x faster)
- Get-ExcessiveAppPermissions: Filter Microsoft apps at API level
- All functions: Use -Select to only retrieve needed properties
- Added -MaxResults parameter for quick scans
- Optimized MFA checks (only check inactive users)

### Breaking Changes:
None - fully backward compatible

## Version 2.0.0

MAJOR UPDATE - 5 new security audit functions!

### New Functions:
- Get-UserConsentedApplications - Discover "Shadow IT" via user consents
- Get-InactiveUsersWithoutMFA - Find dormant accounts without MFA
- Get-ExcessiveAppPermissions - Audit overprivileged Graph API permissions
- Get-SyncedPrivilegedAccounts - Find on-prem synced admin accounts
- Get-UnprotectedServicePrincipals - Service principals with credential issues

### Improvements:
- Risk scoring across all functions (CRITICAL/HIGH/MEDIUM/LOW)
- Better summary output with color-coded warnings
- Enhanced documentation

## Version 1.0.0-1.0.2

Initial release with the following functions:

### Get-ConditionalAccessExclusions
- Audits all exclusions in Conditional Access policies
- Resolves GUIDs to display names
- Risk assessment for large group exclusions
- Export to CSV support

### Get-LegacyAuthSignIns
- Finds sign-ins using legacy authentication (IMAP, POP3, SMTP, etc.)
- Queries both interactive AND non-interactive sign-ins
- Risk level assessment per protocol
- Summary statistics and recommendations

### Get-AdminsWithoutPhishingResistantMFA
- Identifies privileged users without FIDO2/WHfB/Certificate MFA
- Checks all critical admin roles
- Risk level based on role criticality
- Compliance summary

### Test-EntraIDSecurityModuleConnection
- Verifies Microsoft Graph connection
- Checks for required permission scopes
'@
            
            # Prerelease tag (for beta versions)
            # Prerelease = 'beta'
            
            # Require license acceptance
            RequireLicenseAcceptance = $false
            
            # External module dependencies (not in PSGallery)
            # ExternalModuleDependencies = @()
        }
    }
    
    # Help info URI
    HelpInfoURI       = 'https://github.com/kentagent-ai/EntraIDSecurityScripts/blob/main/docs/'
}
