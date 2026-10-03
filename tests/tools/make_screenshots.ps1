<#
  make_screenshots.ps1 - documentation pictures of the main program, the two scan windows and the alert pop-up, in one language.

    powershell -File tests\tools\make_screenshots.ps1 -Lang en -OutDir docs\img\en [-WithLab] [-SkipScanWindows]

  The pages are drawn by the REAL program (MineHunter.exe --shots), so they show this computer: look at them before you publish them.
  With -WithLab the harmless MinerLab objects are created first, a quick scan stores its result, and the Scan page is captured with those findings
  (nothing private on that picture); the lab is removed again afterwards. Run no other scan meanwhile (one scan at a time).
  Output: NN_<page>_<lang>.png for the 13 pages, Quick_running/done_<lang>.png, Full_running_<lang>.png, alert_<lang>.png, scan_findings_<lang>.png
#>
param([string]$Lang = 'en', [Parameter(Mandatory)][string]$OutDir, [switch]$WithLab, [switch]$SkipScanWindows)
$ErrorActionPreference = 'Continue'
$env:PSModulePath = (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules') + ';' + (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') + ';' + (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$main = Join-Path $root 'MineHunter.exe'
$cli = Join-Path $root 'MineHunter-cli.exe'
$lab = Join-Path $root 'tests\MinerLab'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

function Run-Window([string]$exe, [string[]]$a, [int]$timeoutSec = 600) {
    $p = Start-Process -FilePath $exe -ArgumentList $a -PassThru
    if (-not $p.WaitForExit($timeoutSec * 1000)) { try { $p.Kill() } catch { }; Write-Host "timeout: $exe $a" }
}

if ($WithLab) {
    try {
        & powershell -NoProfile -File (Join-Path $lab 'MinerLabCleanup.ps1') -Quiet | Out-Null
        & powershell -NoProfile -File (Join-Path $lab 'lab.ps1') -Action Create-Static | Out-Null
        & powershell -NoProfile -File (Join-Path $lab 'lab.ps1') -Action Create-Multi | Out-Null
        & powershell -NoProfile -File (Join-Path $lab 'lab.ps1') -Action Start-Dynamic | Out-Null
        Start-Sleep -Seconds 2
        & $cli scan --quick --report-dir (Join-Path $env:TEMP 'mh_shots_report') --quiet | Out-Null      # stores the result for the window
        Run-Window $main @('--gui', '--page', 'scan', '--shot', (Join-Path $OutDir "scan_findings_$Lang.png"), '--lang', $Lang) 120
    }
    finally { & powershell -NoProfile -File (Join-Path $lab 'MinerLabCleanup.ps1') -Quiet | Out-Null }
    # the stored result now belongs to the lab: replace it by an honest scan of this computer before the other pictures
    & $cli scan --quick --report-dir (Join-Path $env:TEMP 'mh_shots_report') --quiet | Out-Null
}

Run-Window $main @('--gui', '--shots', $OutDir, '--lang', $Lang) 300
Run-Window $main @('--gui', '--page', 'alert', '--shot', (Join-Path $OutDir "alert_$Lang.png"), '--lang', $Lang) 120
if (-not $SkipScanWindows) {
    Run-Window (Join-Path $root 'MineHunter Quick Scan.exe') @('--shots', $OutDir, '--lang', $Lang) 900
    Run-Window (Join-Path $root 'MineHunter Full Scan.exe') @('--shots', $OutDir, '--lang', $Lang) 300
}
Get-ChildItem $OutDir -Filter "*_$Lang.png" | Select-Object Name, Length | Format-Table -AutoSize | Out-String
