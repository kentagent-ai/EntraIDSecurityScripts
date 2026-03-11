#Requires -Version 7.0
# Note: Microsoft.Graph.Authentication module is required for Graph API calls

<#
.SYNOPSIS
    Entra ID Security Scripts PowerShell Module

.DESCRIPTION
    A collection of PowerShell functions for auditing and securing Microsoft Entra ID.
    Includes tools for auditing Conditional Access exclusions, legacy authentication,
    and privileged user MFA configuration.

.NOTES
    Author: Kent Agent (kentagent-ai)
    GitHub: https://github.com/kentagent-ai/EntraID-Security-Scripts
    License: MIT
#>

# Module-level variables
$script:GraphNameCache = @{}
$script:ModuleRoot = $PSScriptRoot

# Get public and private function files
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($import in @($Private + $Public)) {
    try {
        Write-Verbose "Importing $($import.FullName)"
        . $import.FullName
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName

# Module initialization
$script:RequiredScopes = @(
    'Policy.Read.All'
    'Directory.Read.All'
    'AuditLog.Read.All'
    'RoleManagement.Read.Directory'
    'UserAuthenticationMethod.Read.All'
    'GroupMember.Read.All'
)

function Test-EntraIDSecurityModuleConnection {
    <#
    .SYNOPSIS
        Tests if connected to Microsoft Graph with required scopes.
    
    .DESCRIPTION
        Verifies the Microsoft Graph connection and checks for required permission scopes.
    
    .EXAMPLE
        Test-EntraIDSecurityModuleConnection
    #>
    [CmdletBinding()]
    param()
    
    $context = Get-MgContext
    if (-not $context) {
        Write-Warning "Not connected to Microsoft Graph."
        Write-Host "Run: Connect-MgGraph -Scopes '$($script:RequiredScopes -join "', '")'" -ForegroundColor Yellow
        return $false
    }
    
    $missingScopes = $script:RequiredScopes | Where-Object { $_ -notin $context.Scopes }
    if ($missingScopes) {
        Write-Warning "Missing recommended scopes: $($missingScopes -join ', ')"
        Write-Host "Some functions may fail. Reconnect with all required scopes for full functionality." -ForegroundColor Yellow
    }
    
    Write-Host "Connected to Microsoft Graph as: $($context.Account)" -ForegroundColor Green
    return $true
}

# Export the connection test function
Export-ModuleMember -Function Test-EntraIDSecurityModuleConnection
