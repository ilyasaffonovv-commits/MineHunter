<#
  publish_rules.ps1 - maintainer tool: after editing rules\core.json (and bumping its "version"), run this to refresh version.json:
  SHA-256 of the rule pack, RSA-SHA256 signature made with YOUR private key (never commit it), optional new program version.

    powershell -ExecutionPolicy Bypass -File tools\publish_rules.ps1 -PrivateKey $env:USERPROFILE\Documents\MineHunterKeys\update_private.xml
    powershell -ExecutionPolicy Bypass -File tools\publish_rules.ps1 -PrivateKey <key> -LatestVersion 1.1.0      # also announces a new program release

  Then commit rules\core.json + version.json and push: every installed MineHunter picks the pack up on its next start
  (it verifies SHA-256 and the signature against the public key compiled into the program).
#>
param(
    [Parameter(Mandatory)][string]$PrivateKey,
    [string]$LatestVersion,
    [string]$Cli
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Cli) { $Cli = Join-Path $root 'MineHunter-cli.exe' }
if (-not (Test-Path $Cli)) { throw "MineHunter-cli.exe not found ($Cli) - run build_release.ps1 first" }
$rules = Join-Path $root 'rules\core.json'
$vf = Join-Path $root 'version.json'

$bytes = [System.IO.File]::ReadAllBytes($rules)
if ($bytes -contains 13) { throw 'rules\core.json contains CR characters: convert it to LF line endings, otherwise the hash differs after git normalisation' }
$rv = (Get-Content $rules -Raw | ConvertFrom-Json).version
$sha = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', '').ToLower()
$sig = (& $Cli --sign $rules $PrivateKey | Select-Object -Last 1).Trim()
if (-not $sig) { throw 'signing failed' }

$m = Get-Content $vf -Raw | ConvertFrom-Json
if ($LatestVersion) { $m.latestVersion = $LatestVersion }
$m.rules.version = $rv; $m.rules.sha256 = $sha; $m.rules.signature = $sig
$json = ($m | ConvertTo-Json -Depth 6)
[System.IO.File]::WriteAllText($vf, ($json -replace "`r`n", "`n") + "`n", (New-Object System.Text.UTF8Encoding($false)))
"version.json updated: rules $rv  sha256 $sha"
