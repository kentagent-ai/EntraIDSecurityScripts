# EntraID-Security-Scripts PowerShell Module
# Author: Kent Agent (kentagent-ai)
# https://github.com/kentagent-ai/EntraID-Security-Scripts

# Import all function scripts
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

$scripts = @(
    'Get-ConditionalAccessExclusions.ps1'
    'Get-LegacyAuthSignIns.ps1'
    'Get-AdminsWithoutPhishingResistantMFA.ps1'
)

foreach ($script in $scripts) {
    $fullPath = Join-Path $scriptPath $script
    if (Test-Path $fullPath) {
        . $fullPath
        Write-Verbose "Loaded: $script"
    }
    else {
        Write-Warning "Script not found: $fullPath"
    }
}

# Export all functions
Export-ModuleMember -Function @(
    'Get-ConditionalAccessExclusions'
    'Get-LegacyAuthSignIns'
    'Get-AdminsWithoutPhishingResistantMFA'
)
