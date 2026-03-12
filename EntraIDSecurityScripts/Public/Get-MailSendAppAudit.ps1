<#
.SYNOPSIS
    Audits your apps with Mail.Send permissions and their usage patterns.

.DESCRIPTION
    Finds app registrations in your tenant with Mail.Send/Mail.Send.All permissions,
    then checks audit logs to see which mailboxes they're sending from.
    Excludes Microsoft first-party apps. Helps determine if apps can be scoped
    using Application Access Policies.

.PARAMETER Days
    Number of days to look back in audit logs. Default 30.

.EXAMPLE
    Get-MailSendAppAudit

    Finds all apps with Mail.Send and checks their send activity.

.EXAMPLE
    Get-MailSendAppAudit -Days 90

    Checks 90 days of audit history.

.EXAMPLE
    Get-MailSendAppAudit | Where-Object { $_.CanScope } | Export-Csv apps-to-scope.csv

    Exports apps that can be scoped to CSV.

.NOTES
    Author: Dennis Kämpe / Kent Agent
    Created: 2026-03-12
    Requires: Microsoft.Graph PowerShell module, ExchangeOnlineManagement module
    Permissions: Application.Read.All (Graph), View-Only Audit Logs (Compliance)
    
    Connect first:
    - Connect-MgGraph -Scopes "Application.Read.All"
    - Connect-IPPSSession

.LINK
    https://github.com/kentagent-ai/EntraIDSecurityScripts
#>
function Get-MailSendAppAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$Days = 30
    )

    begin {
        # Verify Graph connection
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Application.Read.All'"
        }

        # Microsoft tenant ID (to exclude their apps)
        $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'
    }

    process {
        Write-Host "`n=== Mail.Send Application Audit ===" -ForegroundColor Cyan
        Write-Host "Finding YOUR apps with Mail.Send permissions..." -ForegroundColor Yellow
        Write-Host ""

        # Get Microsoft Graph service principal
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property Id, AppRoles -ErrorAction Stop

        # Find Mail.Send role IDs (only Send permissions, not ReadWrite)
        # Mail.ReadWrite allows reading/modifying mail but NOT sending
        $mailSendRoleIds = New-Object System.Collections.ArrayList
        foreach ($role in $graphSp.AppRoles) {
            if ($role.Value -eq 'Mail.Send') {
                [void]$mailSendRoleIds.Add($role.Id)
                Write-Host "  Looking for: $($role.Value)" -ForegroundColor Gray
            }
        }

        Write-Host ""

        # Get all service principals
        $allSps = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, AppOwnerOrganizationId

        # Find apps with Mail.Send permissions (excluding Microsoft apps)
        $appsWithMailSend = New-Object System.Collections.ArrayList

        foreach ($sp in $allSps) {
            # Skip Microsoft first-party apps
            if ($sp.AppOwnerOrganizationId -eq $microsoftTenantId) {
                continue
            }

            # Check if this app has Mail.Send permissions
            $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
            
            if ($null -eq $assignments) { continue }

            $hasMailSend = $false
            $grantedPerms = New-Object System.Collections.ArrayList

            foreach ($assignment in $assignments) {
                if ($assignment.ResourceId -eq $graphSp.Id -and $mailSendRoleIds -contains $assignment.AppRoleId) {
                    $hasMailSend = $true
                    $permName = ($graphSp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }).Value
                    if ($permName -and $grantedPerms -notcontains $permName) {
                        [void]$grantedPerms.Add($permName)
                    }
                }
            }

            if ($hasMailSend) {
                $appInfo = New-Object PSObject -Property @{
                    DisplayName = $sp.DisplayName
                    AppId       = $sp.AppId
                    SpId        = $sp.Id
                    Permissions = ($grantedPerms -join ', ')
                }
                [void]$appsWithMailSend.Add($appInfo)
                Write-Host "  [FOUND] $($sp.DisplayName)" -ForegroundColor Green
                Write-Host "          Permissions: $($grantedPerms -join ', ')" -ForegroundColor Gray
            }
        }

        Write-Host ""
        Write-Host "Apps with Mail.Send: $($appsWithMailSend.Count)" -ForegroundColor Cyan

        if ($appsWithMailSend.Count -eq 0) {
            Write-Host "[OK] No custom apps have Mail.Send permissions!" -ForegroundColor Green
            return
        }

        # Check if audit log is available
        Write-Host ""
        Write-Host "Checking audit logs for send activity..." -ForegroundColor Yellow

        $cmdletExists = Get-Command -Name Search-UnifiedAuditLog -ErrorAction SilentlyContinue
        $auditAvailable = $null -ne $cmdletExists

        if (-not $auditAvailable) {
            Write-Host "[!] Audit log not available (run Connect-IPPSSession)" -ForegroundColor Yellow
            Write-Host "    Showing apps with permissions only - no usage data" -ForegroundColor Gray
        }

        $results = New-Object System.Collections.ArrayList
        $startDate = (Get-Date).AddDays(-$Days)
        $endDate = Get-Date

        foreach ($app in $appsWithMailSend) {
            Write-Host ""
            Write-Host "----------------------------------------" -ForegroundColor Gray
            Write-Host "App:         $($app.DisplayName)" -ForegroundColor Cyan
            Write-Host "AppId:       $($app.AppId)" -ForegroundColor Gray
            Write-Host "Permissions: $($app.Permissions)" -ForegroundColor White

            $sendCount = 0
            $mailboxes = New-Object System.Collections.ArrayList
            $lastUsed = $null

            if ($auditAvailable) {
                try {
                    # Search audit log for this specific app
                    $sends = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
                        -RecordType ExchangeItem -Operations Send, SendAs, SendOnBehalf `
                        -FreeText $app.AppId -ResultSize 5000 -ErrorAction SilentlyContinue

                    if ($null -ne $sends -and $sends.Count -gt 0) {
                        foreach ($record in $sends) {
                            try {
                                $data = $record.AuditData | ConvertFrom-Json
                                
                                # Verify it's actually this app
                                if ($data.ClientAppId -eq $app.AppId) {
                                    $sendCount++
                                    
                                    if ($null -ne $data.MailboxOwnerUPN -and $mailboxes -notcontains $data.MailboxOwnerUPN) {
                                        [void]$mailboxes.Add($data.MailboxOwnerUPN)
                                    }
                                    
                                    if ($null -eq $lastUsed -or $data.CreationTime -gt $lastUsed) {
                                        $lastUsed = $data.CreationTime
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch {
                    Write-Host "  [!] Audit search error: $_" -ForegroundColor Yellow
                }
            }

            # Display results
            if ($sendCount -gt 0) {
                Write-Host "Sends:       $sendCount (last $Days days)" -ForegroundColor White
                Write-Host "Mailboxes:   $($mailboxes.Count)" -ForegroundColor White
                Write-Host "Last used:   $lastUsed" -ForegroundColor Gray

                if ($mailboxes.Count -le 15) {
                    foreach ($mb in $mailboxes) {
                        Write-Host "             - $mb" -ForegroundColor Gray
                    }
                }

                # Recommendation
                if ($mailboxes.Count -le 5) {
                    Write-Host ">> SCOPE IT - only $($mailboxes.Count) mailbox(es)!" -ForegroundColor Green
                }
                elseif ($mailboxes.Count -le 20) {
                    Write-Host ">> SCOPE IT - create security group for $($mailboxes.Count) mailboxes" -ForegroundColor Yellow
                }
                else {
                    Write-Host ">> REVIEW - sends from $($mailboxes.Count) mailboxes" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Sends:       0 (no activity in last $Days days)" -ForegroundColor Yellow
                Write-Host ">> REVIEW - has permission but no recent usage" -ForegroundColor Yellow
            }

            $resultObj = New-Object PSObject -Property @{
                AppName      = $app.DisplayName
                AppId        = $app.AppId
                Permissions  = $app.Permissions
                SendCount    = $sendCount
                MailboxCount = $mailboxes.Count
                Mailboxes    = ($mailboxes -join '; ')
                LastUsed     = $lastUsed
                CanScope     = ($mailboxes.Count -gt 0 -and $mailboxes.Count -le 20)
            }
            [void]$results.Add($resultObj)
        }
    }

    end {
        # Summary
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "SUMMARY" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""

        $scopeable = @($results | Where-Object { $_.CanScope -eq $true })
        $unused = @($results | Where-Object { $_.SendCount -eq 0 })
        $needsReview = @($results | Where-Object { $_.MailboxCount -gt 20 })

        Write-Host "Total apps with Mail.Send: $($results.Count)" -ForegroundColor White
        Write-Host "Can be scoped:             $($scopeable.Count)" -ForegroundColor Green
        Write-Host "No recent activity:        $($unused.Count)" -ForegroundColor Yellow
        Write-Host "Needs review (>20 mbx):    $($needsReview.Count)" -ForegroundColor Red

        if ($scopeable.Count -gt 0) {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "APPLICATION ACCESS POLICY COMMANDS" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Yellow

            foreach ($r in $scopeable) {
                $groupName = $r.AppName -replace '\s', '' -replace '[^a-zA-Z0-9]', ''
                Write-Host ""
                Write-Host "# $($r.AppName) - $($r.MailboxCount) mailbox(es)" -ForegroundColor Gray
                Write-Host "New-ApplicationAccessPolicy ``" -ForegroundColor Cyan
                Write-Host "    -AppId '$($r.AppId)' ``" -ForegroundColor Cyan
                Write-Host "    -PolicyScopeGroupId 'MailSend-$groupName@yourdomain.com' ``" -ForegroundColor Cyan
                Write-Host "    -AccessRight RestrictAccess ``" -ForegroundColor Cyan
                Write-Host "    -Description 'Scope $($r.AppName) to specific mailboxes'" -ForegroundColor Cyan
            }
        }

        if ($unused.Count -gt 0) {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "UNUSED APPS - CONSIDER REMOVING PERMISSION" -ForegroundColor Red
            Write-Host "========================================" -ForegroundColor Yellow

            foreach ($r in $unused) {
                Write-Host ""
                Write-Host "# $($r.AppName) - no sends in $Days days" -ForegroundColor Gray
                Write-Host "# Review if Mail.Send is still needed" -ForegroundColor Yellow
                Write-Host "# Azure Portal > App Registrations > $($r.AppName) > API Permissions" -ForegroundColor Gray
            }
        }

        Write-Host ""
        return $results
    }
}

Export-ModuleMember -Function Get-MailSendAppAudit -ErrorAction SilentlyContinue
