<#
  publish_update.ps1 - maintainer tool: after building the release zip, announce it for the self-update.
  It writes the "app" section of version.json: version, address of the zip, its SHA-256 and size, the oldest version that may update automatically,
  and an RSA-SHA256 signature made with YOUR private key (never commit the key). The program checks that signature with the public key built into it,
  then the SHA-256 and size of the download, before it unpacks anything.

    powershell -ExecutionPolicy Bypass -File tools\publish_update.ps1 -PrivateKey $env:USERPROFILE\Documents\MineHunterKeys\update_private.xml
    powershell -ExecutionPolicy Bypass -File tools\publish_update.ps1 -PrivateKey <key> -Zip dist\MineHunter-Portable-x64.zip -Notes "what is new"

  Run build_release.ps1 -Zip first, publish the GitHub release with that exact zip, then commit version.json.
  The text that is signed is:  MineHunter-app|<version>|<sha256>|<size>|<minVersion>|<url>
#>
param(
    [Parameter(Mandatory)][string]$PrivateKey,
    [string]$Zip,
    [string]$Version,
    [string]$MinVersion = '1.0.0',
    [string]$Notes,
    [string]$Repo = 'https://github.com/ilyasaffonovv-commits/MineHunter',
    [string]$Cli
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Cli) { $Cli = Join-Path $root 'MineHunter-cli.exe' }
if (-not $Zip) { $Zip = Join-Path $root 'dist\MineHunter-Portable-x64.zip' }
if (-not (Test-Path $Cli)) { throw "MineHunter-cli.exe not found ($Cli) - run build_release.ps1 first" }
if (-not (Test-Path $Zip)) { throw "zip not found ($Zip) - run build_release.ps1 -Zip first" }
if (-not $Version) { $Version = (Get-Item (Join-Path $root 'MineHunter.exe')).VersionInfo.ProductVersion }
$vf = Join-Path $root 'version.json'

$bytes = [System.IO.File]::ReadAllBytes($Zip)
$sha = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', '').ToLower()
$size = $bytes.Length
$url = "$Repo/releases/download/v$Version/MineHunter-Portable-x64.zip"
$canonical = "MineHunter-app|$Version|$sha|$size|$MinVersion|$url"
$tmp = Join-Path $env:TEMP ('mh-canonical-' + [Guid]::NewGuid().ToString('N') + '.txt')
[System.IO.File]::WriteAllBytes($tmp, (New-Object System.Text.UTF8Encoding($false)).GetBytes($canonical))
try { $sig = (& $Cli --sign $tmp $PrivateKey | Select-Object -Last 1).Trim() } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
if (-not $sig) { throw 'signing failed' }

$m = Get-Content $vf -Raw | ConvertFrom-Json
$app = [ordered]@{ version = $Version; url = $url; sha256 = $sha; size = $size; minVersion = $MinVersion; notes = $(if ($Notes) { $Notes } else { "MineHunter $Version" }); signature = $sig }
if ($m.PSObject.Properties.Name -contains 'app') { $m.app = [pscustomobject]$app } else { $m | Add-Member -NotePropertyName app -NotePropertyValue ([pscustomobject]$app) }
$m.latestVersion = $Version
if ($Notes) { $m.notes = $Notes }
$json = ($m | ConvertTo-Json -Depth 6)
[System.IO.File]::WriteAllText($vf, ($json -replace "`r`n", "`n") + "`n", (New-Object System.Text.UTF8Encoding($false)))
"version.json updated: app $Version  sha256 $sha  size $size"
