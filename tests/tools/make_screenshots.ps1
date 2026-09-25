<#
  make_screenshots.ps1 - README screenshots from the benign MinerLab (no private results on the pictures).
  Prerequisite: lab objects exist (tests\MinerLab\lab.ps1 -Action Create-Static / Create-Multi). Starts the short-lived lab processes, then lets the GUI scan and
  render its tabs to PNG. The window shows only findings that involve "MinerLab" (--filter).
    powershell -File make_screenshots.ps1 -Lang en -OutDir ..\..\docs\img\en
    powershell -File make_screenshots.ps1 -Lang en -OutDir ..\..\docs\img\en -Neutralize    # also produces the "cleanup result" picture
#>
param([string]$Lang = 'en', [Parameter(Mandatory)][string]$OutDir, [switch]$Neutralize)
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'src\_bin\MineHunter.exe'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
& powershell.exe -NoProfile -File (Join-Path $root 'tests\MinerLab\lab.ps1') -Action Start-Dynamic | Select-Object -Last 1
if ($Neutralize) {
    Start-Process -FilePath $exe -ArgumentList @('--gui', '--neutralize', 'MinerLab', '--filter', 'MinerLab', '--shot', (Join-Path $OutDir 'cleanup.png'), '--lang', $Lang) -Wait
} else {
    Start-Process -FilePath $exe -ArgumentList @('--gui', '--filter', 'MinerLab', '--shots', $OutDir, '--lang', $Lang) -Wait
}
Get-ChildItem $OutDir | Select-Object Name, Length
