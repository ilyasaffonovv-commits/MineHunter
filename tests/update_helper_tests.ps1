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
    Note 'the "update is being copied" marker is gone after a good update' (-not (Test-Path (Join-Path $d 'res\inprogress.json'))) ''

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
    Note 'the marker is gone after a failed update that was rolled back' (-not (Test-Path (Join-Path $d 'res\inprogress.json'))) ''

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
    # cmd.exe works as a stand-in anywhere (a copied ping.exe needs its .mui file and ends at once on some Windows Server builds); it stays alive while its ping child runs
    Copy-Item (Join-Path $env:SystemRoot 'System32\cmd.exe') (Join-Path $inst 'MineHunter.exe') -Force
    $open = Start-Process -FilePath (Join-Path $inst 'MineHunter.exe') -ArgumentList '/c ping -n 40 127.0.0.1 > nul' -PassThru -WindowStyle Hidden
    Start-Sleep 2
    if ($open.HasExited) { throw 'the stand-in program for test 5 ended at once: the test cannot say anything' }
    $seen5 = (Get-Process -Name MineHunter -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id): $($_.Path)" }) -join '; '
    try { $code5 = Run-Helper ('apply --src "' + (Join-Path $d 'pkg') + '" --dst "' + $inst + '" --backup "' + (Join-Path $d 'bk') + '" --result "' + $res + '" --from 1.0.0 --to 1.1.0 --wait 3') } finally { try { $open.Kill() } catch { } }
    $r5 = Get-Content $res -Raw | ConvertFrom-Json
    Note 'while a MineHunter program is still open in the folder the helper changes nothing and says why' ($code5 -eq 1 -and $r5.ok -eq $false -and $r5.error -like '*still open*' -and (Read-Text (Join-Path $inst 'components\core.dll')) -eq 'OLD-CORE' -and -not (Test-Path (Join-Path $d 'bk'))) (($r5 | ConvertTo-Json -Compress) + "  [dst: $inst; running: $seen5]")

    # ---- 6. an update cut short (power loss): the next start of a MineHunter program puts the saved files back by itself
    $repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
    $cliSrc = Join-Path $repo 'MineHunter-cli.exe'
    if (Test-Path $cliSrc) {
        function New-Install($d) {
            $inst = Join-Path $d 'install'; New-Item -ItemType Directory -Force $inst | Out-Null
            Copy-Item $cliSrc $inst; if (Test-Path "$cliSrc.config") { Copy-Item "$cliSrc.config" $inst }
            Copy-Item (Join-Path $repo 'components') (Join-Path $inst 'components') -Recurse
            Copy-Item (Join-Path $repo 'config.json') $inst -ErrorAction SilentlyContinue
            return $inst
        }
        function Esc($s) { $s.Replace('\', '\\') }
        $oldPD = $env:ProgramData
        try {
            $d = Join-Path $root 't6'; New-Item -ItemType Directory -Force $d | Out-Null
            $inst = New-Install $d; $bk = Join-Path $d 'bk'
            $pd = Join-Path $d 'pd'; $upd = Join-Path $pd 'MineHunter\updates'; New-Item -ItemType Directory -Force $upd | Out-Null
            Write-Tree $bk @{ 'docs\RESTORED.txt' = 'RESTORED'; '_created.txt' = "components\extra.dll" }
            [IO.File]::WriteAllText((Join-Path $inst 'components\extra.dll'), 'HALF-NEW')
            $marker = Join-Path $upd 'inprogress.json'
            [IO.File]::WriteAllText($marker, ('{"dst":"' + (Esc $inst) + '","backup":"' + (Esc $bk) + '","from":"1.1.0","to":"1.2.0","time":"2026-01-01T00:00:00"}'))
            $env:ProgramData = $pd
            $p = Start-Process -FilePath (Join-Path $inst 'MineHunter-cli.exe') -ArgumentList '--version' -PassThru -WindowStyle Hidden; $p.WaitForExit(60000) | Out-Null
            $res6 = Join-Path $upd 'result.json'
            for ($i = 0; $i -lt 40 -and -not (Test-Path $res6); $i++) { Start-Sleep -Milliseconds 500 }
            Start-Sleep -Seconds 2
            $r6 = if (Test-Path $res6) { Get-Content $res6 -Raw | ConvertFrom-Json } else { $null }
            Note 'a program started after a cut-short update puts the saved files back, removes what the update had added and removes the marker' ((Read-Text (Join-Path $inst 'docs\RESTORED.txt')) -eq 'RESTORED' -and -not (Test-Path (Join-Path $inst 'components\extra.dll')) -and -not (Test-Path $marker)) ("exit $($p.ExitCode)")
            Note 'the result says the update did not finish and the previous version was put back' ($r6 -ne $null -and $r6.ok -eq $false -and $r6.rolledBack -eq $true -and $r6.error -like '*interrupted*' -and $r6.to -eq '1.2.0') ($r6 | ConvertTo-Json -Compress)

            # a marker that belongs to some other installation is left alone and the program starts normally
            $d2 = Join-Path $root 't6b'; New-Item -ItemType Directory -Force $d2 | Out-Null
            $inst2 = New-Install $d2; $bk2 = Join-Path $d2 'bk'; Write-Tree $bk2 @{ 'docs\RESTORED.txt' = 'RESTORED' }
            $pd2 = Join-Path $d2 'pd'; $upd2 = Join-Path $pd2 'MineHunter\updates'; New-Item -ItemType Directory -Force $upd2 | Out-Null
            $other = Join-Path $d2 'some-other-folder'
            $marker2 = Join-Path $upd2 'inprogress.json'
            [IO.File]::WriteAllText($marker2, ('{"dst":"' + (Esc $other) + '","backup":"' + (Esc $bk2) + '","from":"1.1.0","to":"1.2.0","time":"2026-01-01T00:00:00"}'))
            $env:ProgramData = $pd2
            $out = & (Join-Path $inst2 'MineHunter-cli.exe') --version 2>&1 | Out-String
            Start-Sleep -Seconds 1
            Note 'a marker of another installation does not stop the program, and nothing is restored' ($out -like '*MineHunter*' -and (Test-Path $marker2) -and -not (Test-Path (Join-Path $inst2 'docs\RESTORED.txt'))) ($out.Trim())
        } finally { $env:ProgramData = $oldPD }
    }
}
finally {
    Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($root) } | ForEach-Object { try { $_.Kill() } catch { } }
    Start-Sleep -Milliseconds 400
    try { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
$results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Output
$bad = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
if ($bad) { "$bad CHECK(S) FAILED"; exit 1 } else { 'ALL UPDATE HELPER CHECKS PASSED'; exit 0 }
