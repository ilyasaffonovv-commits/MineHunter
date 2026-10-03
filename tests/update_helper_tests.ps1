<#
  update_helper_tests.ps1 - runs the real MineHunter.UpdateHelper.exe against fake install folders (in a temp folder only) and checks what the self-update promises:
    a good update replaces the files, keeps config.json, leaves a backup and a result file;
    a failure in the middle (a file that is locked) puts every old file back and removes what was added;
    the rollback command restores the saved version;
    the helper waits for the program to close, and refuses (changing nothing) when it is still open;
    a package path that tries to leave the folder is never produced by the helper itself (the program checks packages before the helper sees them).

    powershell -File tests\update_helper_tests.ps1 [-Helper <path to MineHunter.UpdateHelper.exe>]
#>
param([string]$Helper = (Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) 'components\MineHunter.UpdateHelper.exe'))
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Helper)) { throw "helper not found: $Helper (run build_release.ps1)" }
$root = Join-Path $env:TEMP ('mh_upd_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $root | Out-Null
$results = New-Object System.Collections.ArrayList
function Note($name, $ok, $detail) { [void]$results.Add([pscustomobject]@{ Check = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail }) }
function Write-Tree($dir, $map) { foreach ($k in $map.Keys) { $p = Join-Path $dir $k; New-Item -ItemType Directory -Force (Split-Path $p) | Out-Null; [IO.File]::WriteAllText($p, $map[$k]) } }
function Read-Text($p) { if (Test-Path $p) { [IO.File]::ReadAllText($p) } else { $null } }
function Run-Helper($argList) {
    $copy = Join-Path $root ('h_' + [Guid]::NewGuid().ToString('N').Substring(0, 6) + '.exe'); Copy-Item $Helper $copy
    $p = Start-Process -FilePath $copy -ArgumentList $argList -PassThru -WindowStyle Hidden; $p.WaitForExit(120000) | Out-Null
    if (-not $p.HasExited) { $p.Kill(); return -99 }; return $p.ExitCode
}
function Fresh($name) {
    $d = Join-Path $root $name; New-Item -ItemType Directory -Force $d | Out-Null
    Write-Tree (Join-Path $d 'install') @{ 'MineHunter.exe' = 'OLD-EXE'; 'components\core.dll' = 'OLD-CORE'; 'rules\core.json' = 'OLD-RULES'; 'config.json' = 'USER-CONFIG' }
    Write-Tree (Join-Path $d 'pkg') @{ 'MineHunter.exe' = 'NEW-EXE'; 'components\core.dll' = 'NEW-CORE'; 'components\extra.dll' = 'NEW-EXTRA'; 'rules\core.json' = 'NEW-RULES'; 'config.json' = 'PACKAGE-CONFIG' }
    return $d
}
try {
    # ---- 1. a good update
    $d = Fresh 't1'; $inst = Join-Path $d 'install'; $res = Join-Path $d 'res\result.json'
    $code = Run-Helper ('apply --src "' + (Join-Path $d 'pkg') + '" --dst "' + $inst + '" --backup "' + (Join-Path $d 'bk') + '" --result "' + $res + '" --from 1.0.0 --to 1.1.0')
    $r = Get-Content $res -Raw | ConvertFrom-Json
    Note 'a good update replaces the program, the libraries and the rules, adds new files' ($code -eq 0 -and (Read-Text (Join-Path $inst 'MineHunter.exe')) -eq 'NEW-EXE' -and (Read-Text (Join-Path $inst 'components\core.dll')) -eq 'NEW-CORE' -and (Read-Text (Join-Path $inst 'components\extra.dll')) -eq 'NEW-EXTRA' -and (Read-Text (Join-Path $inst 'rules\core.json')) -eq 'NEW-RULES') "exit $code"
    Note 'the user''s config.json is not overwritten by the package' ((Read-Text (Join-Path $inst 'config.json')) -eq 'USER-CONFIG') ''
    Note 'the old files are saved in the backup folder and the result says ok (from -> to)' ((Read-Text (Join-Path $d 'bk\MineHunter.exe')) -eq 'OLD-EXE' -and (Read-Text (Join-Path $d 'bk\components\core.dll')) -eq 'OLD-CORE' -and $r.ok -eq $true -and $r.from -eq '1.0.0' -and $r.to -eq '1.1.0') ($r | ConvertTo-Json -Compress)
    Note 'no temporary .mhnew files are left behind' (@(Get-ChildItem $inst -Recurse -Filter '*.mhnew' -ErrorAction SilentlyContinue).Count -eq 0) ''

    # ---- 2. rollback command restores the saved version
    $code2 = Run-Helper ('rollback --dst "' + $inst + '" --backup "' + (Join-Path $d 'bk') + '" --result "' + (Join-Path $d 'res\rb.json') + '"')
    Note 'the rollback command puts the previous version back and removes the files the update had added' ($code2 -eq 0 -and (Read-Text (Join-Path $inst 'MineHunter.exe')) -eq 'OLD-EXE' -and (Read-Text (Join-Path $inst 'components\core.dll')) -eq 'OLD-CORE' -and (Read-Text (Join-Path $inst 'rules\core.json')) -eq 'OLD-RULES' -and -not (Test-Path (Join-Path $inst 'components\extra.dll'))) "exit $code2"

    # ---- 3. a failure in the middle: one file is locked, everything is put back
    $d = Fresh 't3'; $inst = Join-Path $d 'install'; $res = Join-Path $d 'res\result.json'
    $lock = [IO.File]::Open((Join-Path $inst 'components\core.dll'), 'Open', 'Read', 'Read')     # readable (so it can be backed up) but not replaceable
    try { $code3 =Run-Helper ('apply --src "' + (Join-Path $d 'pkg') + '" --dst "' + $inst + '" --backup "' + (Join-Path $d 'bk') + '" --result "' + $res + '" --from 1.0.0 --to 1.1.0') } finally { $lock.Close() }
    $r3 = Get-Content $res -Raw | ConvertFrom-Json
    Note 'when one file cannot be replaced the update fails, reports it, and says it rolled back' ($code3 -eq 1 -and $r3.ok -eq $false -and $r3.rolledBack -eq $true -and $r3.error.Length -gt 10) ($r3 | ConvertTo-Json -Compress)
    Note 'after the failed update every old file is back, the added file is gone, nothing temporary is left' ((Read-Text (Join-Path $inst 'MineHunter.exe')) -eq 'OLD-EXE' -and (Read-Text (Join-Path $inst 'components\core.dll')) -eq 'OLD-CORE' -and (Read-Text (Join-Path $inst 'rules\core.json')) -eq 'OLD-RULES' -and -not (Test-Path (Join-Path $inst 'components\extra.dll')) -and @(Get-ChildItem $inst -Recurse -Filter '*.mhnew' -ErrorAction SilentlyContinue).Count -eq 0) ''

    # ---- 3b. a file that cannot even be read for the backup: the update stops before touching anything
    $d = Fresh 't3b'; $inst = Join-Path $d 'install'; $res = Join-Path $d 'res\result.json'
    $lock = [IO.File]::Open((Join-Path $inst 'components\core.dll'), 'Open', 'Read', 'None')
    try { $code3b = Run-Helper ('apply --src "' + (Join-Path $d 'pkg') + '" --dst "' + $inst + '" --backup "' + (Join-Path $d 'bk') + '" --result "' + $res + '" --from 1.0.0 --to 1.1.0') } finally { $lock.Close() }
    $r3b = Get-Content $res -Raw | ConvertFrom-Json
    Note 'when the current version cannot be backed up the update stops before changing anything' ($code3b -eq 1 -and $r3b.ok -eq $false -and $r3b.error -like '*Nothing was changed*' -and (Read-Text (Join-Path $inst 'MineHunter.exe')) -eq 'OLD-EXE' -and -not (Test-Path (Join-Path $inst 'components\extra.dll'))) ''

    # ---- 4. the helper waits for the program that started it
    $d = Fresh 't4'; $inst = Join-Path $d 'install'; $res = Join-Path $d 'res\result.json'
    $sleeper = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -Command Start-Sleep 5' -PassThru -WindowStyle Hidden
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $code4 = Run-Helper ('apply --src "' + (Join-Path $d 'pkg') + '" --dst "' + $inst + '" --backup "' + (Join-Path $d 'bk') + '" --result "' + $res + '" --from 1.0.0 --to 1.1.0 --pid ' + $sleeper.Id)
    Note 'the helper waits until the program that started it has closed, then installs' ($code4 -eq 0 -and $sw.Elapsed.TotalSeconds -ge 3.5 -and (Read-Text (Join-Path $inst 'MineHunter.exe')) -eq 'NEW-EXE') ("waited {0:N1} s" -f $sw.Elapsed.TotalSeconds)

    # ---- 5. a MineHunter program is still open in the folder: nothing is changed
    $d = Fresh 't5'; $inst = Join-Path $d 'install'; $res = Join-Path $d 'res\result.json'
    Copy-Item (Join-Path $env:SystemRoot 'System32\ping.exe') (Join-Path $inst 'MineHunter.exe') -Force
    $open = Start-Process -FilePath (Join-Path $inst 'MineHunter.exe') -ArgumentList '-n 40 127.0.0.1' -PassThru -WindowStyle Hidden
    Start-Sleep 2
    try { $code5 = Run-Helper ('apply --src "' + (Join-Path $d 'pkg') + '" --dst "' + $inst + '" --backup "' + (Join-Path $d 'bk') + '" --result "' + $res + '" --from 1.0.0 --to 1.1.0 --wait 3') } finally { try { $open.Kill() } catch { } }
    $r5 = Get-Content $res -Raw | ConvertFrom-Json
    Note 'while a MineHunter program is still open in the folder the helper changes nothing and says why' ($code5 -eq 1 -and $r5.ok -eq $false -and $r5.error -like '*still open*' -and (Read-Text (Join-Path $inst 'components\core.dll')) -eq 'OLD-CORE' -and -not (Test-Path (Join-Path $d 'bk'))) ($r5 | ConvertTo-Json -Compress)
}
finally {
    Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($root) } | ForEach-Object { try { $_.Kill() } catch { } }
    Start-Sleep -Milliseconds 400
    try { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
$results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Output
$bad = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
if ($bad) { "$bad CHECK(S) FAILED"; exit 1 } else { 'ALL UPDATE HELPER CHECKS PASSED'; exit 0 }
