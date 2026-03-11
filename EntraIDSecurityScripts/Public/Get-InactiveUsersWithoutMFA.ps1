<#
.SYNOPSIS
    Finds inactive user accounts without MFA capability.

.DESCRIPTION
    Identifies user accounts that have not signed in recently and lack MFA registration.
    These accounts represent a security risk as they may be forgotten, unmonitored, and
    lack basic security protections.

.PARAMETER DaysInactive
    Number of days without sign-ins to consider a user "inactive". Default is 90.

.PARAMETER IncludeGuests
    Include guest users in the audit. Default is $false.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-InactiveUsersWithoutMFA

    Returns all inactive users (90+ days) without MFA.

.EXAMPLE
    Get-InactiveUsersWithoutMFA -DaysInactive 180

    Finds users inactive for 180+ days without MFA.

.EXAMPLE
    Get-InactiveUsersWithoutMFA -IncludeGuests $true

    Includes guest users in the audit.

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-11
    Requires: Microsoft.Graph PowerShell module
    Permissions: User.Read.All, UserAuthenticationMethod.Read.All, AuditLog.Read.All

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-InactiveUsersWithoutMFA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysInactive = 90,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeGuests = $false,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'User.Read.All', 'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All'"
        }

        $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        Write-Verbose "Retrieving users with sign-in activity..."

        try {
            # Get users with sign-in activity
            $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime,SignInActivity -ErrorAction Stop
        }
        catch {
            throw "Failed to retrieve users: $_"
        }

        Write-Verbose "Processing $($users.Count) users..."

        foreach ($user in $users) {
            # Filter disabled accounts
            if (-not $user.AccountEnabled) {
                continue
            }

            # Filter guests if requested
            if (-not $IncludeGuests -and $user.UserType -eq 'Guest') {
                continue
            }

            # Check last sign-in
            $lastSignIn = $null
            $isInactive = $false

            if ($user.SignInActivity) {
                $lastSignIn = $user.SignInActivity.LastSignInDateTime
                
                if ($lastSignIn) {
                    if ($lastSignIn -lt $inactiveThreshold) {
                        $isInactive = $true
                    }
                }
                else {
                    # Never signed in
                    $isInactive = $true
                }
            }
            else {
                # No sign-in data
                $isInactive = $true
            }

            if (-not $isInactive) {
                continue  # User is active
            }

            # Check MFA registration
            $hasMFA = $false
            $mfaMethods = @()

            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
                
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties['@odata.type']
                    
                    # Count any MFA method except password and email
                    if ($methodType -notin @('#microsoft.graph.passwordAuthenticationMethod', '#microsoft.graph.emailAuthenticationMethod')) {
                        $hasMFA = $true
                        
                        $methodName = switch ($methodType) {
                            '#microsoft.graph.fido2AuthenticationMethod' { 'FIDO2' }
                            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { 'Windows Hello' }
                            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { 'Authenticator App' }
                            '#microsoft.graph.phoneAuthenticationMethod' { 'Phone (SMS/Voice)' }
                            '#microsoft.graph.softwareOathAuthenticationMethod' { 'OATH Token' }
                            default { $methodType }
                        }
                        
                        $mfaMethods += $methodName
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve auth methods for $($user.UserPrincipalName): $_"
            }

            if ($hasMFA) {
                continue  # User has MFA
            }

            # Calculate days inactive
            $daysInactiveCal = if ($lastSignIn) {
                [math]::Round(((Get-Date) - $lastSignIn).TotalDays)
            } else {
                $null
            }

            # Determine risk level
            $riskLevel = if ($daysInactiveCal -gt 180) {
                'HIGH'
            } elseif ($daysInactiveCal -gt 90 -or $null -eq $daysInactiveCal) {
                'MEDIUM'
            } else {
                'LOW'
            }

            $recommendation = if ($null -eq $lastSignIn) {
                'Never signed in - Consider disabling or deleting'
            } elseif ($daysInactiveCal -gt 180) {
                'Inactive >180 days without MFA - Disable and review'
            } else {
                'Inactive without MFA - Require MFA or disable'
            }

            $results.Add([PSCustomObject]@{
                DisplayName        = $user.DisplayName
                UserPrincipalName  = $user.UserPrincipalName
                UserId             = $user.Id
                UserType           = $user.UserType
                AccountEnabled     = $user.AccountEnabled
                CreatedDateTime    = $user.CreatedDateTime
                LastSignInDateTime = $lastSignIn
                DaysInactive       = $daysInactiveCal
                HasMFA             = $hasMFA
                RiskLevel          = $riskLevel
                Recommendation     = $recommendation
            })
        }
    }

    end {
        # Sort by risk and days inactive
        $results = $results | Sort-Object @{Expression={
            switch ($_.RiskLevel) {
                'HIGH' { 1 }
                'MEDIUM' { 2 }
                'LOW' { 3 }
            }
        }}, DaysInactive -Descending

        # Summary
        $high = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
        $neverSignedIn = ($results | Where-Object { $null -eq $_.LastSignInDateTime }).Count

        Write-Host "`n=== Inactive Users Without MFA ===" -ForegroundColor Yellow
        Write-Host "Total inactive users without MFA: $($results.Count)" -ForegroundColor White
        Write-Host "HIGH risk (>180 days): $high" -ForegroundColor $(if ($high -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Never signed in: $neverSignedIn" -ForegroundColor $(if ($neverSignedIn -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "==================================`n" -ForegroundColor Yellow

        # Export if requested
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

Export-ModuleMember -Function Get-InactiveUsersWithoutMFA -ErrorAction SilentlyContinue
