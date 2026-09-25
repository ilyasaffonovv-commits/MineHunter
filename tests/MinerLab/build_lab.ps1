<#
  build_lab.ps1 - builds the benign MinerLab harness (tests\MinerLab\bin\MinerSimulation.exe) that lab.ps1 copies around.
  The harness only simulates observable traits (CPU/RAM load, odd locations, persistence entries, loopback sockets); hard caps: 30/60 s, loopback only,
  kill-switch file MinerLab.STOP. See lab.ps1 for the scenarios and MinerLabCleanup.ps1 for the verified removal.
#>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
& dotnet build (Join-Path $here 'src\MinerLab.csproj') -c Release -o (Join-Path $here 'bin') -v q --nologo | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
Get-Item (Join-Path $here 'bin\MinerSimulation.exe') | Select-Object Name, Length
