<#
.SYNOPSIS
    Identifies privileged users without phishing-resistant MFA configured.

.DESCRIPTION
    This function checks all users with privileged directory roles and identifies
    those who do not have phishing-resistant MFA methods (FIDO2, Windows Hello for
    Business, or Certificate-based authentication) registered.

    Privileged accounts are prime targets for attackers, and SMS/Voice MFA can be
    bypassed through SIM swapping or social engineering. Phishing-resistant MFA
    provides significantly stronger protection.

.PARAMETER IncludeAllMFAMethods
    Include all MFA methods in output, not just phishing-resistant ones.

.PARAMETER RolesToCheck
    Specific role names to check. Default checks all critical admin roles.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-AdminsWithoutPhishingResistantMFA

    Returns all privileged users without phishing-resistant MFA.

.EXAMPLE
    Get-AdminsWithoutPhishingResistantMFA -IncludeAllMFAMethods $true

    Shows all MFA methods registered for each privileged user.

.EXAMPLE
    Get-AdminsWithoutPhishingResistantMFA | Where-Object { -not $_.HasPhishingResistantMFA }

    Returns only users who need to register stronger MFA.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Requires: Microsoft.Graph PowerShell module
    Permissions: Policy.Read.All, Directory.Read.All, RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All

.LINK
    https://github.com/kentagent-ai/EntraID-Security-Scripts
#>
function Get-AdminsWithoutPhishingResistantMFA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludeAllMFAMethods = $false,

        [Parameter(Mandatory = $false)]
        [string[]]$RolesToCheck,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Directory.Read.All', 'RoleManagement.Read.Directory', 'UserAuthenticationMethod.Read.All'"
        }

        # Default critical roles to check
        $defaultCriticalRoles = @(
            'Global Administrator'
            'Privileged Role Administrator'
            'Security Administrator'
            'Exchange Administrator'
            'SharePoint Administrator'
            'User Administrator'
            'Authentication Administrator'
            'Privileged Authentication Administrator'
            'Conditional Access Administrator'
            'Intune Administrator'
            'Cloud Application Administrator'
            'Application Administrator'
            'Azure AD Joined Device Local Administrator'
            'Billing Administrator'
            'Compliance Administrator'
            'Global Reader'
        )

        $rolesToAudit = if ($RolesToCheck) { $RolesToCheck } else { $defaultCriticalRoles }

        # Phishing-resistant MFA method types
        $phishingResistantMethods = @(
            '#microsoft.graph.fido2AuthenticationMethod'
            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
            '#microsoft.graph.platformCredentialAuthenticationMethod'
            '#microsoft.graph.x509CertificateAuthenticationMethod'
        )

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        Write-Verbose "Retrieving directory roles..."

        # Get all directory roles
        try {
            $directoryRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve directory roles: $_"
        }

        # Filter to roles we care about
        $targetRoles = $directoryRoles | Where-Object { $_.DisplayName -in $rolesToAudit }

        Write-Verbose "Checking $($targetRoles.Count) privileged roles..."

        # Track processed users to avoid duplicates
        $processedUsers = @{}

        foreach ($role in $targetRoles) {
            Write-Verbose "Processing role: $($role.DisplayName)"

            # Get role members
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to get members of $($role.DisplayName): $_"
                continue
            }

            foreach ($member in $members) {
                # Skip if already processed
                if ($processedUsers.ContainsKey($member.Id)) {
                    # Add this role to existing entry
                    $existingEntry = $results | Where-Object { $_.UserId -eq $member.Id }
                    if ($existingEntry -and $existingEntry.Roles -notcontains $role.DisplayName) {
                        $existingEntry.Roles += $role.DisplayName
                    }
                    continue
                }
                $processedUsers[$member.Id] = $true

                # Get user details
                try {
                    $user = Get-MgUser -UserId $member.Id -Property Id, DisplayName, UserPrincipalName, AccountEnabled -ErrorAction Stop
                }
                catch {
                    Write-Warning "Failed to get user details for $($member.Id): $_"
                    continue
                }

                # Skip disabled accounts
                if (-not $user.AccountEnabled) {
                    Write-Verbose "Skipping disabled account: $($user.UserPrincipalName)"
                    continue
                }

                # Get authentication methods
                $authMethods = @()
                $hasPhishingResistant = $false
                $phishingResistantMethodNames = @()
                $allMethodNames = @()

                try {
                    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
                    
                    foreach ($method in $methods) {
                        $methodType = $method.AdditionalProperties['@odata.type']
                        $methodName = switch ($methodType) {
                            '#microsoft.graph.fido2AuthenticationMethod' { 'FIDO2 Security Key' }
                            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { 'Windows Hello for Business' }
                            '#microsoft.graph.platformCredentialAuthenticationMethod' { 'Platform Credential' }
                            '#microsoft.graph.x509CertificateAuthenticationMethod' { 'Certificate (X.509)' }
                            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { 'Microsoft Authenticator' }
                            '#microsoft.graph.phoneAuthenticationMethod' { 'Phone (SMS/Voice)' }
                            '#microsoft.graph.emailAuthenticationMethod' { 'Email' }
                            '#microsoft.graph.passwordAuthenticationMethod' { 'Password' }
                            '#microsoft.graph.temporaryAccessPassAuthenticationMethod' { 'Temporary Access Pass' }
                            '#microsoft.graph.softwareOathAuthenticationMethod' { 'Software OATH Token' }
                            default { $methodType }
                        }

                        $allMethodNames += $methodName

                        if ($methodType -in $phishingResistantMethods) {
                            $hasPhishingResistant = $true
                            $phishingResistantMethodNames += $methodName
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to get auth methods for $($user.UserPrincipalName): $_"
                    $allMethodNames = @('Unable to retrieve')
                }

                # Determine risk level
                $riskLevel = if (-not $hasPhishingResistant) {
                    if ($role.DisplayName -eq 'Global Administrator') { 'CRITICAL' }
                    elseif ($role.DisplayName -match 'Privileged|Security|Authentication') { 'HIGH' }
                    else { 'MEDIUM' }
                } else { 'LOW' }

                # Build recommendation
                $recommendation = if (-not $hasPhishingResistant) {
                    "Register phishing-resistant MFA (FIDO2 key or Windows Hello)"
                } else {
                    "Compliant - has phishing-resistant MFA"
                }

                $resultObj = [PSCustomObject]@{
                    UserPrincipalName         = $user.UserPrincipalName
                    DisplayName               = $user.DisplayName
                    UserId                    = $user.Id
                    Roles                     = @($role.DisplayName)
                    HasPhishingResistantMFA   = $hasPhishingResistant
                    PhishingResistantMethods  = $phishingResistantMethodNames -join ', '
                    RiskLevel                 = $riskLevel
                    Recommendation            = $recommendation
                }

                if ($IncludeAllMFAMethods) {
                    $resultObj | Add-Member -NotePropertyName 'AllAuthMethods' -NotePropertyValue ($allMethodNames -join ', ')
                }

                $results.Add($resultObj)
            }
        }
    }

    end {
        # Convert Roles array to string for display/export
        foreach ($result in $results) {
            $result.Roles = $result.Roles -join ', '
        }

        # Summary
        $atRisk = $results | Where-Object { -not $_.HasPhishingResistantMFA }
        $critical = $atRisk | Where-Object { $_.RiskLevel -eq 'CRITICAL' }

        Write-Host "`n=== Privileged User MFA Audit Summary ===" -ForegroundColor Yellow
        Write-Host "Total privileged users: $($results.Count)" -ForegroundColor White
        Write-Host "With phishing-resistant MFA: $(($results | Where-Object { $_.HasPhishingResistantMFA }).Count)" -ForegroundColor Green
        Write-Host "Without phishing-resistant MFA: $($atRisk.Count)" -ForegroundColor $(if ($atRisk.Count -gt 0) { 'Red' } else { 'Green' })
        if ($critical.Count -gt 0) {
            Write-Host "CRITICAL (Global Admins at risk): $($critical.Count)" -ForegroundColor Red
        }
        Write-Host "==========================================`n" -ForegroundColor Yellow

        # Export if path specified
        if ($ExportPath) {
            try {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to export results: $_"
            }
        }

        return $results
    }
}

# Export function if loaded as module
Export-ModuleMember -Function Get-AdminsWithoutPhishingResistantMFA -ErrorAction SilentlyContinue
