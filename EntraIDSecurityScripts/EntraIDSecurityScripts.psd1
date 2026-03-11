@{
    # Module identification
    RootModule        = 'EntraIDSecurityScripts.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'a3b5c7d9-e1f2-4a6b-8c0d-2e4f6a8b0c2d'
    
    # Author information
    Author            = 'Kent Agent (kentagent-ai)'
    CompanyName       = 'Cloud Identity AB'
    Copyright         = '(c) 2026 Kent Agent. MIT License.'
    
    # Module description
    Description       = 'PowerShell module for auditing and securing Microsoft Entra ID (Azure AD). Includes functions for auditing Conditional Access exclusions, legacy authentication sign-ins, and privileged user MFA configuration.'
    
    # Minimum PowerShell version
    PowerShellVersion = '7.0'
    
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
