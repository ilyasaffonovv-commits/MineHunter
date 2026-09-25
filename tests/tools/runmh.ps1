<#
  runmh.ps1 - runs MineHunter.exe with the given argument string, WAITS for it (it is a GUI-subsystem exe, so a plain call returns at once)
  and prints its console output. Test helper.
  Usage:  powershell -File runmh.ps1 -ArgString "scan --quick --no-files" [-Exe path]
#>
param([string]$Exe, [string]$ArgString = '')
if (-not $Exe) { $Exe = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\_bin\MineHunter.exe' }
$out = Join-Path $env:TEMP ('runmh_' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
$p = Start-Process -FilePath $Exe -ArgumentList $ArgString -Wait -PassThru -RedirectStandardOutput $out -WindowStyle Hidden
if (Test-Path $out) { Get-Content $out -Encoding UTF8; [System.IO.File]::Delete($out) }
exit $p.ExitCode
