<#
.SYNOPSIS
    Finds enterprise applications with no recent sign-in activity.

.DESCRIPTION
    Identifies dormant enterprise applications that haven't been used in a specified
    number of days. These applications may be candidates for cleanup or disabling.
    
    Can optionally disable dormant applications or list already-disabled applications.

    Uses the Microsoft Graph beta API to access lastSignInDateTime for service principals.

.PARAMETER DaysInactive
    Number of days without sign-in activity to consider an app dormant. Default is 90.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party applications. Default is $false.

.PARAMETER IncludeDisabled
    Include already-disabled applications in the output. Default is $false.

.PARAMETER DisabledOnly
    Show only disabled applications (for audit/cleanup purposes).

.PARAMETER DisableApps
    Disable dormant applications. Use with -WhatIf to preview changes.
    Requires Application.ReadWrite.All permission.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    Get-DormantEnterpriseApplications

    Returns enterprise applications with no sign-ins in the last 90 days.

.EXAMPLE
    Get-DormantEnterpriseApplications -DaysInactive 180

    Returns apps inactive for 180+ days.

.EXAMPLE
    Get-DormantEnterpriseApplications -DisableApps -WhatIf

    Shows which apps WOULD be disabled without actually disabling them.

.EXAMPLE
    Get-DormantEnterpriseApplications -DisabledOnly

    Lists all currently disabled enterprise applications.

.EXAMPLE
    Get-DormantEnterpriseApplications -DisableApps -Confirm:$false

    Disables dormant apps without prompting (use with caution!).

.NOTES
    Author: Kent Agent (kentagent-ai)
    Created: 2026-03-12
    Requires: Microsoft.Graph PowerShell module
    Permissions: Application.Read.All (read), Application.ReadWrite.All (disable)
    
    Note: Uses beta API for lastSignInDateTime. This property may not be available
    for all apps, especially those that have never been used.

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-DormantEnterpriseApplications {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysInactive = 90,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeMicrosoftApps,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisabled,

        [Parameter(Mandatory = $false)]
        [switch]$DisabledOnly,

        [Parameter(Mandatory = $false)]
        [switch]$DisableApps,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Application.Read.All'"
        }

        # Check for write permissions if disabling apps
        if ($DisableApps) {
            if ('Application.ReadWrite.All' -notin $context.Scopes) {
                Write-Warning "Missing Application.ReadWrite.All scope. Reconnect with: Connect-MgGraph -Scopes 'Application.ReadWrite.All'"
            }
        }

        # Microsoft's tenant ID
        $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'
        
        $results = New-Object System.Collections.ArrayList
        $disabledCount = 0
        $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)
    }

    process {
        Write-Host ""
        
        if ($DisabledOnly) {
            Write-Host "=== Disabled Enterprise Applications ===" -ForegroundColor Cyan
        } else {
            Write-Host "=== Dormant Enterprise Applications (>$DaysInactive days inactive) ===" -ForegroundColor Cyan
        }
        
        Write-Host "Retrieving service principals..." -ForegroundColor Gray

        try {
            # Use beta API to get lastSignInDateTime
            $uri = "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,createdDateTime,signInAudience&`$top=999"
            
            $allServicePrincipals = New-Object System.Collections.ArrayList
            
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                
                if ($response.value) {
                    foreach ($sp in $response.value) {
                        [void]$allServicePrincipals.Add($sp)
                    }
                }
                
                $uri = $response.'@odata.nextLink'
            } while ($null -ne $uri)
            
            Write-Host "Found $($allServicePrincipals.Count) service principals" -ForegroundColor Gray
        }
        catch {
            throw "Failed to retrieve service principals: $_"
        }

        # Now get sign-in activity for each (this requires checking sign-in logs or beta signInActivity)
        Write-Host "Checking sign-in activity..." -ForegroundColor Gray
        
        $processedCount = 0
        $totalToProcess = $allServicePrincipals.Count

        foreach ($sp in $allServicePrincipals) {
            $processedCount++
            
            if ($processedCount % 50 -eq 0) {
                Write-Progress -Activity "Analyzing applications" -Status "$processedCount / $totalToProcess" -PercentComplete (($processedCount / $totalToProcess) * 100)
            }

            # Skip Microsoft apps unless requested
            $isMicrosoftApp = $sp.appOwnerOrganizationId -eq $microsoftTenantId
            if ($isMicrosoftApp -and -not $IncludeMicrosoftApps) {
                continue
            }

            # Skip managed identities
            if ($sp.servicePrincipalType -eq 'ManagedIdentity') {
                continue
            }

            $isDisabled = -not $sp.accountEnabled

            # Handle DisabledOnly mode
            if ($DisabledOnly) {
                if ($isDisabled) {
                    [void]$results.Add([PSCustomObject]@{
                        DisplayName        = $sp.displayName
                        AppId              = $sp.appId
                        ServicePrincipalId = $sp.id
                        AccountEnabled     = $false
                        IsMicrosoftApp     = $isMicrosoftApp
                        ServicePrincipalType = $sp.servicePrincipalType
                        CreatedDateTime    = $sp.createdDateTime
                        LastSignIn         = $null
                        DaysInactive       = $null
                        Status             = 'Disabled'
                        Recommendation     = 'Review if still needed, consider deletion'
                    })
                }
                continue
            }

            # Skip disabled apps unless requested
            if ($isDisabled -and -not $IncludeDisabled) {
                continue
            }

            # Get last sign-in activity from beta API
            $lastSignIn = $null
            $daysInactiveCalc = $null
            
            try {
                $activityUri = "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)?`$select=signInActivity"
                $activityResponse = Invoke-MgGraphRequest -Method GET -Uri $activityUri -ErrorAction SilentlyContinue
                
                if ($activityResponse.signInActivity) {
                    $lastSignIn = $activityResponse.signInActivity.lastSignInDateTime
                    if ($null -eq $lastSignIn) {
                        $lastSignIn = $activityResponse.signInActivity.lastNonInteractiveSignInDateTime
                    }
                }
            }
            catch {
                Write-Verbose "Could not get sign-in activity for $($sp.displayName): $_"
            }

            # Calculate days inactive
            if ($lastSignIn) {
                $lastSignInDate = [DateTime]$lastSignIn
                $daysInactiveCalc = ((Get-Date) - $lastSignInDate).Days
            } else {
                # No sign-in data - check if app is old enough
                if ($sp.createdDateTime) {
                    $createdDate = [DateTime]$sp.createdDateTime
                    $daysInactiveCalc = ((Get-Date) - $createdDate).Days
                }
            }

            # Check if dormant
            $isDormant = $false
            if ($null -ne $lastSignIn) {
                $isDormant = $lastSignIn -lt $inactiveThreshold
            } elseif ($null -ne $sp.createdDateTime) {
                # Never signed in - dormant if created before threshold
                $createdDate = [DateTime]$sp.createdDateTime
                $isDormant = $createdDate -lt $inactiveThreshold
            }

            if (-not $isDormant -and -not $isDisabled) {
                continue  # Skip active apps
            }

            $status = if ($isDisabled) {
                'Disabled'
            } elseif ($null -eq $lastSignIn) {
                'Never Used'
            } else {
                'Dormant'
            }

            $riskLevel = if ($null -eq $lastSignIn -and $daysInactiveCalc -gt 180) {
                'HIGH'
            } elseif ($daysInactiveCalc -gt 180) {
                'HIGH'
            } elseif ($daysInactiveCalc -gt 90) {
                'MEDIUM'
            } else {
                'LOW'
            }

            $recommendation = if ($isDisabled) {
                'Already disabled - review if deletion is appropriate'
            } elseif ($null -eq $lastSignIn) {
                'Never used - consider disabling or removing'
            } else {
                "Inactive for $daysInactiveCalc days - evaluate if still needed"
            }

            $resultObj = [PSCustomObject]@{
                DisplayName        = $sp.displayName
                AppId              = $sp.appId
                ServicePrincipalId = $sp.id
                AccountEnabled     = $sp.accountEnabled
                IsMicrosoftApp     = $isMicrosoftApp
                ServicePrincipalType = $sp.servicePrincipalType
                CreatedDateTime    = $sp.createdDateTime
                LastSignIn         = $lastSignIn
                DaysInactive       = $daysInactiveCalc
                Status             = $status
                RiskLevel          = $riskLevel
                Recommendation     = $recommendation
                WasDisabled        = $false
            }

            # Disable app if requested
            if ($DisableApps -and -not $isDisabled -and -not $isMicrosoftApp) {
                $target = "enterprise app '$($sp.displayName)'"
                
                if ($PSCmdlet.ShouldProcess($target, "Disable")) {
                    try {
                        Update-MgServicePrincipal -ServicePrincipalId $sp.id -AccountEnabled:$false -ErrorAction Stop
                        $resultObj.WasDisabled = $true
                        $resultObj.AccountEnabled = $false
                        $disabledCount++
                        Write-Host "  [DISABLED] $($sp.displayName)" -ForegroundColor Yellow
                    }
                    catch {
                        Write-Warning "Failed to disable $($sp.displayName): $_"
                    }
                }
            }

            [void]$results.Add($resultObj)
        }

        Write-Progress -Activity "Analyzing applications" -Completed
    }

    end {
        Write-Host ""
        
        if ($results.Count -gt 0) {
            if ($DisabledOnly) {
                Write-Host "=== Disabled Applications Summary ===" -ForegroundColor Yellow
                Write-Host "Total disabled apps: $($results.Count)" -ForegroundColor White
            } else {
                $dormantCount = ($results | Where-Object { $_.Status -eq 'Dormant' }).Count
                $neverUsedCount = ($results | Where-Object { $_.Status -eq 'Never Used' }).Count
                $alreadyDisabledCount = ($results | Where-Object { $_.Status -eq 'Disabled' }).Count
                $highRisk = ($results | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count

                Write-Host "=== Dormant Applications Summary ===" -ForegroundColor Yellow
                Write-Host "Total issues: $($results.Count)" -ForegroundColor White
                Write-Host "Dormant (no recent sign-ins): $dormantCount" -ForegroundColor $(if ($dormantCount -gt 0) { 'Yellow' } else { 'Green' })
                Write-Host "Never used: $neverUsedCount" -ForegroundColor $(if ($neverUsedCount -gt 0) { 'Red' } else { 'Green' })
                
                if ($IncludeDisabled) {
                    Write-Host "Already disabled: $alreadyDisabledCount" -ForegroundColor Gray
                }
                
                Write-Host "High risk (>180 days): $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { 'Red' } else { 'Green' })
                
                if ($DisableApps) {
                    Write-Host ""
                    Write-Host "Disabled in this run: $disabledCount" -ForegroundColor Cyan
                }
            }
            
            Write-Host "=====================================" -ForegroundColor Yellow

            # Export if requested
            if ($ExportPath) {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation
                Write-Host ""
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            }
        }
        else {
            if ($DisabledOnly) {
                Write-Host "[OK] No disabled enterprise applications found!" -ForegroundColor Green
            } else {
                Write-Host "[OK] No dormant enterprise applications found!" -ForegroundColor Green
            }
        }

        Write-Host ""
        return $results
    }
}

Export-ModuleMember -Function Get-DormantEnterpriseApplications -ErrorAction SilentlyContinue
