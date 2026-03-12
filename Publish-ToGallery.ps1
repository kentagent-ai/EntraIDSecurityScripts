<#
.SYNOPSIS
    Publishes EntraIDSecurityScripts module to PowerShell Gallery.

.DESCRIPTION
    This script validates the module manifest and publishes to PowerShell Gallery.
    Requires a valid PowerShell Gallery API key.

.PARAMETER ApiKey
    PowerShell Gallery API key. If not provided, will check for PSGALLERY_API_KEY environment variable.

.PARAMETER SkipPublish
    Validates the module without actually publishing.

.EXAMPLE
    ./Publish-ToGallery.ps1 -ApiKey "your-api-key-here"

.EXAMPLE
    # Using environment variable
    $env:PSGALLERY_API_KEY = "your-api-key"
    ./Publish-ToGallery.ps1

.NOTES
    Get an API key from: https://www.powershellgallery.com/account/apikeys
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'
$ModulePath = Join-Path $PSScriptRoot 'EntraIDSecurityScripts'

Write-Host "`n=== Publishing EntraIDSecurityScripts to PowerShell Gallery ===" -ForegroundColor Cyan

# Check if module directory exists
if (-not (Test-Path $ModulePath)) {
    throw "Module directory not found: $ModulePath"
}

# Test module manifest
Write-Host "`n[1/4] Validating module manifest..." -ForegroundColor Yellow
try {
    $manifest = Test-ModuleManifest -Path (Join-Path $ModulePath 'EntraIDSecurityScripts.psd1')
    Write-Host "  ✓ Module: $($manifest.Name)" -ForegroundColor Green
    Write-Host "  ✓ Version: $($manifest.Version)" -ForegroundColor Green
    Write-Host "  ✓ Author: $($manifest.Author)" -ForegroundColor Green
    Write-Host "  ✓ Functions: $($manifest.ExportedFunctions.Count)" -ForegroundColor Green
}
catch {
    Write-Error "Module manifest validation failed: $_"
    exit 1
}

# Check for API key
Write-Host "`n[2/4] Checking for API key..." -ForegroundColor Yellow
if (-not $ApiKey) {
    $ApiKey = $env:PSGALLERY_API_KEY
}

if (-not $ApiKey) {
    Write-Host "  ⚠ No API key provided!" -ForegroundColor Red
    Write-Host "`nTo publish to PowerShell Gallery, you need an API key:" -ForegroundColor White
    Write-Host "  1. Go to: https://www.powershellgallery.com/account/apikeys" -ForegroundColor Cyan
    Write-Host "  2. Sign in with your Microsoft account" -ForegroundColor Cyan
    Write-Host "  3. Create a new API key (recommended scope: 'Push new packages and package versions')" -ForegroundColor Cyan
    Write-Host "  4. Run this script with: -ApiKey 'your-key-here'" -ForegroundColor Cyan
    Write-Host "`nOr set environment variable:" -ForegroundColor White
    Write-Host "  `$env:PSGALLERY_API_KEY = 'your-key-here'" -ForegroundColor Cyan
    exit 1
}

Write-Host "  ✓ API key found (${($ApiKey.Substring(0, 8))}...)" -ForegroundColor Green

# Check if this version already exists
Write-Host "`n[3/4] Checking if version $($manifest.Version) exists on Gallery..." -ForegroundColor Yellow
try {
    $existing = Find-Module -Name 'EntraIDSecurityScripts' -RequiredVersion $manifest.Version -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  ⚠ Version $($manifest.Version) already published!" -ForegroundColor Yellow
        Write-Host "  Please bump the version in EntraIDSecurityScripts.psd1" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  ✓ Version $($manifest.Version) is new" -ForegroundColor Green
}
catch {
    Write-Host "  ✓ Version check complete" -ForegroundColor Green
}

# Publish module
Write-Host "`n[4/4] Publishing to PowerShell Gallery..." -ForegroundColor Yellow

if ($SkipPublish) {
    Write-Host "  [DRY RUN] Would publish module to PSGallery" -ForegroundColor Cyan
    Write-Host "  Module: $($manifest.Name)" -ForegroundColor White
    Write-Host "  Version: $($manifest.Version)" -ForegroundColor White
    Write-Host "  Path: $ModulePath" -ForegroundColor White
}
else {
    try {
        Publish-Module -Path $ModulePath -NuGetApiKey $ApiKey -Verbose
        
        Write-Host "`n✓ Successfully published!" -ForegroundColor Green
        Write-Host "`nModule URL: https://www.powershellgallery.com/packages/EntraIDSecurityScripts/$($manifest.Version)" -ForegroundColor Cyan
        Write-Host "`nUsers can now install with:" -ForegroundColor White
        Write-Host "  Install-Module -Name EntraIDSecurityScripts" -ForegroundColor Cyan
        Write-Host "`nOr update existing installations:" -ForegroundColor White
        Write-Host "  Update-Module -Name EntraIDSecurityScripts" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Publishing failed: $_"
        exit 1
    }
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
