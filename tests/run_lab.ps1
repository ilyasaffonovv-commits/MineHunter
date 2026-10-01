<#
  run_lab.ps1 - one complete MinerLab cycle in a single context (registry virtualization makes create + scan in different contexts unreliable):
  cleanup -> create static objects -> create the multi-signal object -> start the running processes -> scan the real release EXE -> evaluate -> cleanup.
  Everything the lab creates is harmless (see tests/MinerLab/README.md) and removed again.

    powershell -File tests\run_lab.ps1 [-Out <dir>] [-KeepLab] [-ExtraScanArgs '--no-browsers']

  Result files in <dir>: run.log, report.json/txt, entities.json, scan_console.txt, eval.txt (what was found for every lab object), cleanup.txt
#>
param(
    [string]$Out = (Join-Path $env:TEMP 'mh_lab_run'),
    [switch]$SkipStatic,
    [switch]$KeepLab,
    [string]$ExtraScanArgs = ''
)
$ErrorActionPreference = 'Continue'
# Windows PowerShell 5.1 started from PowerShell 7 inherits a PSModulePath that hides its own utility module (Get-FileHash would not be found)
$env:PSModulePath = (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules') + ';' + (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') + ';' + (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$lab = Join-Path $root 'tests\MinerLab'
Remove-Item $Out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Out | Out-Null
$log = Join-Path $Out 'run.log'
function Log($m) { Add-Content -Path $log -Value ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) -Encoding UTF8 }

Log 'cleanup of leftovers'
& powershell -NoProfile -File (Join-Path $lab 'MinerLabCleanup.ps1') -Quiet | Out-Null
if (-not $SkipStatic) {
    Log 'create static'; & powershell -NoProfile -File (Join-Path $lab 'lab.ps1') -Action Create-Static | ForEach-Object { Log $_ }
    Log 'create multi';  & powershell -NoProfile -File (Join-Path $lab 'lab.ps1') -Action Create-Multi | ForEach-Object { Log $_ }
}
Log 'start dynamic'; & powershell -NoProfile -File (Join-Path $lab 'lab.ps1') -Action Start-Dynamic | ForEach-Object { Log $_ }
Start-Sleep -Seconds 2
Log 'scan'
$scanArgs = @('scan', '--quick', '--report-dir', $Out, '--dump', (Join-Path $Out 'entities.json'), '--quiet')
if ($ExtraScanArgs) { $scanArgs += $ExtraScanArgs.Split(' ') }
& (Join-Path $root 'MineHunter-cli.exe') @scanArgs *> (Join-Path $Out 'scan_console.txt')
Log "scan exit $LASTEXITCODE"
& powershell -NoProfile -File (Join-Path $lab 'eval_lab.ps1') -ScanDir $Out *> (Join-Path $Out 'eval.txt')
Log 'eval written'
if (-not $KeepLab) {
    Log 'cleanup'; & powershell -NoProfile -File (Join-Path $lab 'MinerLabCleanup.ps1') *> (Join-Path $Out 'cleanup.txt'); Log "cleanup exit $LASTEXITCODE"
}
Log 'DONE'
