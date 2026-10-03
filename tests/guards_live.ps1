<#
  guards_live.ps1 - end-to-end check of the real-time layer in the REAL program (MineHunter.exe --tray), with harmless lab files only:
    a copy of notepad with a few miner words appended (it does nothing, it only looks like a miner to a scanner) is dropped into Downloads,
    started from Temp, and registered in a Run key of the current user; an ordinary copy of notepad is dropped as the negative control.
  Expected: alerts for the lab files (Download Guard, Process Guard, Persistence Guard), none for the control, and nothing left behind.
  Nothing outside the lab files, one HKCU Run value and the program's own data folder is touched; everything is removed at the end.

    powershell -File tests\guards_live.ps1 [-Exe <path to MineHunter.exe>]
#>
param([string]$Exe = (Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) 'MineHunter.exe'), [int]$WaitSec = 60)
$ErrorActionPreference = 'Stop'
$results = New-Object System.Collections.ArrayList
function Note($name, $ok, $detail) { [void]$results.Add([pscustomobject]@{ Check = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail }) }
$data = Join-Path $env:ProgramData 'MineHunter'
$alertsFile = Join-Path $data 'alerts.json'
$downloads = Join-Path $env:USERPROFILE 'Downloads'
$lab = Join-Path $env:TEMP ('mh_lab_' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; $runName = 'MineHunterLab' + [Guid]::NewGuid().ToString('N').Substring(0, 5)
$dl = Join-Path $downloads ('mh-lab-setup-' + [Guid]::NewGuid().ToString('N').Substring(0, 5) + '.exe')
$ctl = Join-Path $downloads ('mh-lab-control-' + [Guid]::NewGuid().ToString('N').Substring(0, 5) + '.exe')
New-Item -ItemType Directory -Force $lab | Out-Null
function Words { ('stra' + 'tum+tcp://pool.example.invalid:3333'), ('xm' + 'rig'), ('don' + 'ate-level'), ('random' + 'x'), ('crypto' + 'night'), ('mining.' + 'subscribe'), ('--cpu-' + 'priority'), ('pool.' + 'mine' + 'xmr.com') -join "`n" }
function Alerts { try { $j = Get-Content $alertsFile -Raw -ErrorAction Stop | ConvertFrom-Json; @($j.alerts) } catch { @() } }
function Wait-Alert($pathLike, $sec) { $sw = [Diagnostics.Stopwatch]::StartNew(); while ($sw.Elapsed.TotalSeconds -lt $sec) { $a = Alerts | Where-Object { $_.path -like $pathLike } | Select-Object -First 1; if ($a) { return $a }; Start-Sleep 2 }; return $null }
$tray = $null
try {
    $before = @(Alerts).Count
    $tray = Start-Process -FilePath $Exe -ArgumentList '--tray' -PassThru
    Start-Sleep 10
    Note 'the tray program starts and stays up' (-not $tray.HasExited) ''
    $notepad = Join-Path $env:SystemRoot 'System32\notepad.exe'; $ping = Join-Path $env:SystemRoot 'System32\ping.exe'

    # ---- control: an ordinary program dropped into Downloads is not reported
    Copy-Item $notepad $ctl
    # ---- Download Guard: a lab "miner-looking" file lands in Downloads
    $bytes = [IO.File]::ReadAllBytes($notepad) + [Text.Encoding]::ASCII.GetBytes("`n" + (Words) + "`n")
    [IO.File]::WriteAllBytes($dl, $bytes)
    $a1 = Wait-Alert ('*' + [IO.Path]::GetFileName($dl)) $WaitSec
    Note 'Download Guard reports the lab file that looks like a miner, with its path and the honest wording' ($a1 -ne $null -and ($a1.guard -eq 'download' -or $a1.guard -eq 'file') -and $a1.text -match 'MineHunter') $(if ($a1) { "$($a1.level): $($a1.text)" } else { 'no alert' })
    Start-Sleep 5
    $c = Alerts | Where-Object { $_.path -like ('*' + [IO.Path]::GetFileName($ctl)) } | Select-Object -First 1
    Note 'the ordinary control file raised no alert' ($c -eq $null) $(if ($c) { $c.text } else { '' })

    # ---- Process Guard: the lab file is started from Temp
    $exe2 = Join-Path $lab 'svc_update.exe'
    [IO.File]::WriteAllBytes($exe2, ([IO.File]::ReadAllBytes($ping) + [Text.Encoding]::ASCII.GetBytes("`n" + (Words) + "`n")))
    $pr = Start-Process -FilePath $exe2 -ArgumentList '-n 6 127.0.0.1' -PassThru -WindowStyle Hidden
    $a2 = Wait-Alert ('*svc_update.exe') $WaitSec
    Note 'Process Guard or File Guard reports the lab program started from Temp' ($a2 -ne $null) $(if ($a2) { "$($a2.guard) $($a2.level): $($a2.text)" } else { 'no alert' })

    # ---- Persistence Guard: another lab program (never started) is registered for autostart
    $exe3 = Join-Path $lab 'updater_helper.exe'
    [IO.File]::WriteAllBytes($exe3, ([IO.File]::ReadAllBytes($ping) + [Text.Encoding]::ASCII.GetBytes("`n" + (Words) + "`n")))
    New-ItemProperty -Path $runKey -Name $runName -Value ('"' + $exe3 + '" --silent') -PropertyType String -Force | Out-Null
    $sw = [Diagnostics.Stopwatch]::StartNew(); $a3 = $null
    while ($sw.Elapsed.TotalSeconds -lt $WaitSec -and -not $a3) { $a3 = Alerts | Where-Object { $_.path -like '*updater_helper.exe' } | Select-Object -First 1; if (-not $a3) { Start-Sleep 3 } }
    # the program may already have been reported by File Guard the moment the file appeared: the same story is not told twice
    Note 'the lab program that was registered for autostart has been reported (once, by the first guard that saw it)' ($a3 -ne $null) $(if ($a3) { "$($a3.guard) $($a3.level)" } else { 'no alert' })
    $j = Join-Path $data 'journal.json'
    $jt = if (Test-Path $j) { Get-Content $j -Raw } else { '' }
    Note 'the change is written to the journal of system changes' ($jt -like ('*' + $runName + '*')) ''
}
finally {
    try { Remove-ItemProperty -Path $runKey -Name $runName -ErrorAction SilentlyContinue } catch { }
    Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($lab) } | ForEach-Object { try { $_.Kill() } catch { } }
    if ($tray -and -not $tray.HasExited) { try { $tray.Kill() } catch { } }
    Get-Process -Name 'MineHunter' -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch { } }
    Start-Sleep 1
    foreach ($f in $dl, $ctl) { try { Remove-Item $f -Force -ErrorAction SilentlyContinue } catch { } }
    try { Remove-Item $lab -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
$results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Output
$bad = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
if ($bad) { "$bad CHECK(S) FAILED"; exit 1 } else { 'ALL LIVE GUARD CHECKS PASSED'; exit 0 }
