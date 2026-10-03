<#
  ops_tests.ps1 - how the RELEASE programs behave when things around them are wrong: damaged rules / config / cache, no network, two instances, a scan that is
  cancelled or whose window is closed, folders nobody may read, a missing drive, no administrator rights, a second disk that goes away, a clean folder.
  Nothing outside a temp folder is changed for good: every file that a test damages is backed up first and put back in the end.
  What could not be run here says NOT TESTED.

    powershell -NoProfile -File tests\ops_tests.ps1 [-Out <dir>] [-Skip gui,vhd,noadmin]
#>
param(
    [string]$Out = (Join-Path $env:TEMP 'mh_ops'),
    [string[]]$Skip = @()
)
$ErrorActionPreference = 'Continue'
$env:PSModulePath = (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules') + ';' + (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') + ';' + (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')
$root = Split-Path -Parent $PSScriptRoot
$cli = Join-Path $root 'MineHunter-cli.exe'
$gui = Join-Path $root 'MineHunter.exe'
$data = Join-Path $env:ProgramData 'MineHunter'
Remove-Item $Out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Out | Out-Null
$results = New-Object System.Collections.ArrayList
function T([string]$Id, [string]$Name, [string]$State, [string]$Note = '') {
    [void]$results.Add([pscustomobject]@{ Id = $Id; Test = $Name; State = $State; Note = $Note })
    Write-Host ('{0,-4} {1,-10} {2}   {3}' -f $Id, $State, $Name, $Note)
}
function Backup-File([string]$p) { if (Test-Path -LiteralPath $p) { $b = Join-Path $Out ('backup_' + [guid]::NewGuid().ToString('N').Substring(0, 6)); Copy-Item -LiteralPath $p -Destination $b -Force; return $b }; $null }
function Restore-File([string]$p, [string]$b) { if ($b) { Copy-Item -LiteralPath $b -Destination $p -Force } elseif (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } }
function Run-Cli([string[]]$A, [int]$TimeoutSec = 300, [string]$Exe = $cli) {
    $psi = New-Object Diagnostics.ProcessStartInfo $Exe
    $psi.Arguments = ($A | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
    $timedOut = -not $p.WaitForExit($TimeoutSec * 1000)
    if ($timedOut) { try { $p.Kill() } catch { } }
    [pscustomobject]@{ Code = $(if ($timedOut) { -999 } else { $p.ExitCode }); Out = ($so.Result + $se.Result); Seconds = $sw.Elapsed.TotalSeconds; TimedOut = $timedOut }
}
function Small-Folder([string]$Name) {
    $d = Join-Path $Out $Name; New-Item -ItemType Directory -Force $d | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $d 'harmless.exe'), ([IO.File]::ReadAllBytes((Join-Path $env:SystemRoot 'System32\notepad.exe')))[0..4095])
    $d
}
function Valid-Report([string]$Dir) {
    $rj = Join-Path $Dir 'report.json'
    if (-not (Test-Path $rj)) { return $null }
    try { Get-Content $rj -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class CtrlC {
  [DllImport("kernel32.dll")] static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll")] static extern bool FreeConsole();
  [DllImport("kernel32.dll")] static extern bool SetConsoleCtrlHandler(IntPtr h, bool add);
  [DllImport("kernel32.dll")] static extern bool GenerateConsoleCtrlEvent(uint ev, uint grp);
  public static bool Send(uint pid) {
    FreeConsole();
    if (!AttachConsole(pid)) return false;
    SetConsoleCtrlHandler(IntPtr.Zero, true);
    bool ok = GenerateConsoleCtrlEvent(0, 0);
    System.Threading.Thread.Sleep(800);
    FreeConsole(); SetConsoleCtrlHandler(IntPtr.Zero, false);
    return ok;
  }
}
'@

# ------------------------------------------------------------------------------------------------------ O0 a clean folder, like an unzipped release
$clean = Join-Path $Out 'clean_unzip'
New-Item -ItemType Directory -Force $clean | Out-Null
foreach ($f in 'MineHunter.exe', 'MineHunter.exe.config', 'MineHunter Quick Scan.exe', 'MineHunter Quick Scan.exe.config', 'MineHunter Full Scan.exe', 'MineHunter Full Scan.exe.config', 'MineHunter-cli.exe', 'MineHunter-cli.exe.config', 'config.json', 'LICENSE', 'README.md', 'README.ru.md') { if (Test-Path (Join-Path $root $f)) { Copy-Item (Join-Path $root $f) $clean -Force } }
Copy-Item (Join-Path $root 'rules') (Join-Path $clean 'rules') -Recurse -Force
Copy-Item (Join-Path $root 'components') (Join-Path $clean 'components') -Recurse -Force
# an EXE copied alone (for example run from the preview of a zip) must say what is wrong in one sentence, not show a .NET crash
$alone = Join-Path $Out 'exe_alone'; New-Item -ItemType Directory -Force $alone | Out-Null
Copy-Item (Join-Path $root 'MineHunter-cli.exe') $alone -Force; Copy-Item (Join-Path $root 'MineHunter-cli.exe.config') $alone -Force
$ra = Run-Cli @('--version') 30 (Join-Path $alone 'MineHunter-cli.exe')
T 'O0z' 'the EXE alone, without its components folder: a clear message, not a crash trace' $(if ($ra.Code -eq 3 -and $ra.Out -match 'components' -and $ra.Out -notmatch 'System\.IO\.FileNotFound|Unhandled') { 'PASS' } else { 'FAIL' }) (($ra.Out -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1))
$cc = Join-Path $clean 'MineHunter-cli.exe'
$v = Run-Cli @('--version') 60 $cc
T 'O0a' 'clean folder: --version' $(if ($v.Code -eq 0 -and $v.Out -match 'MineHunter') { 'PASS' } else { 'FAIL' }) $v.Out.Trim()
$st = Run-Cli @('selftest') 600 $cc
T 'O0b' 'clean folder: the self test passes completely' $(if ($st.Code -eq 0 -and $st.Out -match 'ALL \d+ CHECKS PASSED') { 'PASS' } else { 'FAIL' }) (($st.Out -split "`r?`n" | Select-Object -Last 2) -join ' | ')
$sd = Small-Folder 'o0c'
$sc = Run-Cli @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o0c_report", '--quiet') 300 $cc
T 'O0c' 'clean folder: a scan of a small folder runs and writes a valid report' $(if ($sc.Code -in 0, 1, 2 -and (Valid-Report "$Out\o0c_report")) { 'PASS' } else { 'FAIL' }) "exit $($sc.Code), $([int]$sc.Seconds) s"

# ------------------------------------------------------------------------------------------------------ O1-O3 damaged cache / config / rules
$cache = Join-Path $data 'scancache.bin.gz'; $bc = Backup-File $cache
try {
    [IO.File]::WriteAllBytes($cache, [byte[]](1..200 | ForEach-Object { Get-Random -Maximum 256 }))
    $r = Run-Cli @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o1_report", '--quiet') 300
    T 'O1' 'damaged scan cache: the scan still runs (the cache is ignored)' $(if ($r.Code -in 0, 1, 2 -and (Valid-Report "$Out\o1_report")) { 'PASS' } else { 'FAIL' }) "exit $($r.Code)"
} finally { Restore-File $cache $bc }
$ucfg = Join-Path $data 'config.json'; $bu = Backup-File $ucfg
try {
    Set-Content -LiteralPath $ucfg -Value '{ this is not json ' -Encoding ASCII
    $r = Run-Cli @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o2_report", '--quiet') 300
    T 'O2a' 'damaged protected config.json: defaults are used, the scan runs' $(if ($r.Code -in 0, 1, 2 -and (Valid-Report "$Out\o2_report")) { 'PASS' } else { 'FAIL' }) "exit $($r.Code)"
} finally { Restore-File $ucfg $bu }
$bad = Join-Path $data 'rules\mh_ops_bad.json'
try {
    New-Item -ItemType Directory -Force (Split-Path $bad) | Out-Null
    Set-Content -LiteralPath $bad -Value '{"version": "2099.01.01.1", "cmdlinePatterns": [{"id": "X", "regex": "(((", "weight": 99}' -Encoding ASCII
    $r = Run-Cli @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o3_report", '--quiet') 300
    $ri = Run-Cli @('rules-info') 60
    T 'O3a' 'damaged rule file in the data folder: ignored, the scan runs and the version of the good pack is kept' $(if ($r.Code -in 0, 1, 2 -and $ri.Out -notmatch '2099') { 'PASS' } else { 'FAIL' }) "exit $($r.Code)"
} finally { Remove-Item -LiteralPath $bad -Force -ErrorAction SilentlyContinue }
# damaged files next to the EXE (in the temp copy, never in the real folder)
Set-Content -LiteralPath (Join-Path $clean 'config.json') -Value '{{{{' -Encoding ASCII
Set-Content -LiteralPath (Join-Path $clean 'rules\broken.json') -Value '[1,2,3' -Encoding ASCII
$r = Run-Cli @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o4_report", '--quiet') 300 $cc
T 'O3b' 'damaged config.json and a damaged rules file next to the EXE: ignored, the scan runs' $(if ($r.Code -in 0, 1, 2 -and (Valid-Report "$Out\o4_report")) { 'PASS' } else { 'FAIL' }) "exit $($r.Code)"

# ------------------------------------------------------------------------------------------------------ O5 no network
$bu2 = Backup-File $ucfg
try {
    Set-Content -LiteralPath $ucfg -Value '{"updateManifestUrl": "http://127.0.0.1:9/version.json"}' -Encoding ASCII
    $r = Run-Cli @('update-check') 90
    T 'O5' 'no network (update address unreachable): update-check answers within the time limit without a crash' $(if (-not $r.TimedOut -and $r.Code -in 0, 3 -and $r.Out -notmatch 'Unhandled|at MineHunter\.') { 'PASS' } else { 'FAIL' }) "exit $($r.Code), $([int]$r.Seconds) s: $(($r.Out -split "`r?`n" | Select-Object -First 1))"
    $r2 = Run-Cli @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o5_report", '--quiet') 300
    T 'O5b' 'no network: a scan does not need it' $(if ($r2.Code -in 0, 1, 2) { 'PASS' } else { 'FAIL' }) "exit $($r2.Code)"
} finally { Restore-File $ucfg $bu2 }

# ------------------------------------------------------------------------------------------------------ O6 two scans at once
$p1 = Start-Process -FilePath $cli -ArgumentList @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o6a", '--quiet') -PassThru -WindowStyle Hidden
$p2 = Start-Process -FilePath $cli -ArgumentList @('scan', '--path', $sd, '--no-browsers', '--no-memory', '--report-dir', "$Out\o6b", '--quiet') -PassThru -WindowStyle Hidden
[void]$p1.WaitForExit(300000); [void]$p2.WaitForExit(300000)
T 'O6' 'two scans started at the same time both finish with a valid report' $(if ($p1.HasExited -and $p2.HasExited -and $p1.ExitCode -in 0, 1, 2 -and $p2.ExitCode -in 0, 1, 2 -and (Valid-Report "$Out\o6a") -and (Valid-Report "$Out\o6b")) { 'PASS' } else { 'FAIL' }) "exits $($p1.ExitCode)/$($p2.ExitCode)"

# ------------------------------------------------------------------------------------------------------ O7 Ctrl+C in the middle of a scan
$p = Start-Process -FilePath $cli -ArgumentList @('scan', '--quick', '--no-browsers', '--report-dir', "$Out\o7", '--quiet') -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 12
$sent = [CtrlC]::Send([uint32]$p.Id)
$done = $p.WaitForExit(120000)
$rep = Valid-Report "$Out\o7"
if (-not $done) { try { $p.Kill() } catch { }; T 'O7' 'Ctrl+C during a scan ends it cleanly and the partial result is reported' 'FAIL' 'the scan did not stop within 2 minutes' }
elseif (-not $sent) { T 'O7' 'Ctrl+C during a scan ends it cleanly and the partial result is reported' 'NOT TESTED' 'a Ctrl+C could not be sent to the hidden console from this session' }
else { T 'O7' 'Ctrl+C during a scan ends it cleanly and the partial result is reported' $(if ($rep -and $rep.scan.aborted -eq $true) { 'PASS' } else { 'FAIL' }) "exit $($p.ExitCode), report aborted flag: $(if ($rep) { $rep.scan.aborted } else { 'no report' })" }
$lockFile = Join-Path $data 'scan.lock'
T 'O7b' 'after a cancelled scan no scan lock is left behind (the next scan does not report a crash)' $(if (-not (Test-Path $lockFile)) { 'PASS' } else { 'FAIL' }) ((Get-ChildItem $data -Filter '*.lock' -ErrorAction SilentlyContinue | ForEach-Object Name) -join ',')

# ------------------------------------------------------------------------------------------------------ O8 folders nobody may read, a drive that is not there
$denyRoot = Join-Path $Out 'o8'; $locked = Join-Path $denyRoot 'locked'; $open = Join-Path $denyRoot 'open'
New-Item -ItemType Directory -Force $locked, $open | Out-Null
Copy-Item (Join-Path $sd 'harmless.exe') (Join-Path $locked 'a.exe'); Copy-Item (Join-Path $sd 'harmless.exe') (Join-Path $open 'b.exe')
& icacls.exe $locked /inheritance:r /deny "$($env:USERNAME):(OI)(CI)(F)" /deny 'Administrators:(OI)(CI)(F)' 2>&1 | Out-Null
$r = Run-Cli @('scan', '--path', $denyRoot, '--no-browsers', '--no-memory', '--report-dir', "$Out\o8_report", '--quiet') 300
$rep = Valid-Report "$Out\o8_report"
# Run as administrator, MineHunter holds the backup privilege (it needs it to read other users' registry files), and a folder whose ACL denies everybody can then still be listed:
# the scanner reads it, which is what a scanner should do (a miner that locks its own folder with an ACL is not hidden from it). The gap is listed when it exists (see O10, no administrator rights).
$read = ($rep -and [int]$rep.scanned.accessDenied -eq 0 -and [int]$rep.scanned.filesInspected -ge 2)
$listed = ($rep -and ($rep.blindSpots -join ' ') -match 'locked|denied|access|Files')
T 'O8a' 'a folder nobody may read: no crash, the scan finishes; the folder is either read with the backup privilege or the gap is listed in the report' $(if ($r.Code -in 0, 1, 2 -and $rep -and ($listed -or $read)) { 'PASS' } else { 'FAIL' }) "exit $($r.Code); blind spots: $(@($rep.blindSpots).Count); folder read anyway: $read"
& icacls.exe $locked /reset /t 2>&1 | Out-Null
$r = Run-Cli @('scan', '--path', 'Z:\no\such\drive', '--no-browsers', '--no-memory', '--report-dir', "$Out\o8b_report", '--quiet') 120
T 'O8b' 'a path on a drive that does not exist: an answer, no hang, no crash' $(if (-not $r.TimedOut -and $r.Out -notmatch 'Unhandled|at MineHunter\.') { 'PASS' } else { 'FAIL' }) "exit $($r.Code): $(($r.Out -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1))"

# ------------------------------------------------------------------------------------------------------ O9 the window
if ($Skip -contains 'gui') { T 'O9' 'window tests' 'NOT TESTED' 'skipped' }
elseif (Get-Process MineHunter -ErrorAction SilentlyContinue) { T 'O9' 'window tests' 'NOT TESTED' 'a MineHunter window is already open on this computer; it was not touched' }
else {
    $crashLog = Join-Path $data 'crash.log'; $crashBefore = if (Test-Path $crashLog) { (Get-Item $crashLog).Length } else { 0 }
    $g1 = Start-Process -FilePath $gui -ArgumentList @('--gui', '--no-scan') -PassThru
    $t0 = Get-Date; while (((Get-Date) - $t0).TotalSeconds -lt 40 -and (-not $g1.HasExited)) { $g1.Refresh(); if ($g1.MainWindowHandle -ne [IntPtr]::Zero) { break }; Start-Sleep -Milliseconds 500 }
    $opened = (-not $g1.HasExited) -and $g1.MainWindowHandle -ne [IntPtr]::Zero
    T 'O9a' 'the window opens' $(if ($opened) { 'PASS' } else { 'FAIL' }) ''
    if ($opened) {
        $g2 = Start-Process -FilePath $gui -ArgumentList @('--gui', '--no-scan') -PassThru
        $second = $g2.WaitForExit(15000)
        $count = @(Get-Process MineHunter -ErrorAction SilentlyContinue).Count
        T 'O9b' 'a second start does not open a second window (and does not wait for a click)' $(if ($second -and $count -eq 1) { 'PASS' } else { 'FAIL' }) "second exited: $second, windows running: $count"
        if (-not $second) { try { $g2.Kill() } catch { } }
        [void]$g1.CloseMainWindow(); $closed = $g1.WaitForExit(15000)
        T 'O9c' 'closing the window ends the program' $(if ($closed) { 'PASS' } else { 'FAIL' }) ''
        if (-not $closed) { try { $g1.Kill() } catch { } }
    }
    # closing the window in the middle of a scan (Quick Scan.exe starts scanning at once; the window asks before it stops the scan, and the test answers with UI Automation like a person would)
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
    $quick = Join-Path $root 'MineHunter Quick Scan.exe'
    $g3 = Start-Process -FilePath $quick -ArgumentList @('--lang', 'en') -PassThru
    Start-Sleep -Seconds 15
    $g3.Refresh()
    if ($g3.HasExited) { T 'O9d' 'closing the window in the middle of a scan' 'FAIL' 'the program ended on its own' }
    else {
        [void]$g3.CloseMainWindow()
        $answered = $false
        for ($i = 0; $i -lt 20 -and -not $answered -and -not $g3.HasExited; $i++) {
            Start-Sleep -Milliseconds 500
            $cond = New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ProcessIdProperty), $g3.Id
            foreach ($w in [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children, $cond)) {
                $btn = $w.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::NameProperty), 'Stop and close'))
                if ($btn) { $btn.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke(); $answered = $true; break }
            }
        }
        $closed3 = $g3.WaitForExit(30000)
        if (-not $closed3) { try { $g3.Kill() } catch { } }
        $crashAfter = if (Test-Path $crashLog) { (Get-Item $crashLog).Length } else { 0 }
        T 'O9d' 'closing the window in the middle of a scan: it asks, stops the scan on "Stop and close", the program ends by itself, no crash record' $(if ($answered -and $closed3 -and $crashAfter -eq $crashBefore) { 'PASS' } else { 'FAIL' }) "asked: $answered, ended: $closed3, crash.log grew: $($crashAfter -ne $crashBefore)"
        $held = $false; try { $fs = [IO.File]::Open((Join-Path $data 'scan-running.lock'), 'Open', 'ReadWrite', 'None'); $fs.Close() } catch [IO.FileNotFoundException] { } catch { $held = $true }
        T 'O9e' 'closing the window in the middle of a scan leaves no scan lock (neither the engine lock nor the one-scan-at-a-time lock)' $(if (-not (Test-Path (Join-Path $data 'scan.lock')) -and -not $held) { 'PASS' } else { 'FAIL' }) "scan.lock present: $(Test-Path (Join-Path $data 'scan.lock')), lock held: $held"
    }
}

# ------------------------------------------------------------------------------------------------------ O10 no administrator rights
if ($Skip -contains 'noadmin') { T 'O10' 'run without administrator rights' 'NOT TESTED' 'skipped' }
else {
    $na = Join-Path $Out 'o10'
    New-Item -ItemType Directory -Force $na | Out-Null
    & runas.exe /trustlevel:0x20000 ('"' + $cli + '" scan --quick --no-browsers --no-memory --report-dir "' + $na + '" --quiet') 2>&1 | Out-Null
    $t0 = Get-Date; while (((Get-Date) - $t0).TotalSeconds -lt 360 -and -not (Test-Path (Join-Path $na 'report.json'))) { Start-Sleep -Seconds 3 }
    $rep = Valid-Report $na
    if ($rep) {
        T 'O10' 'started without administrator rights: the scan runs, the report says so, and what could not be read is listed' $(if ($rep.system.administrator -eq $false -and @($rep.blindSpots).Count -ge 1) { 'PASS' } else { 'FAIL' }) "administrator=$($rep.system.administrator), blind spots=$(@($rep.blindSpots).Count)"
    } else { T 'O10' 'started without administrator rights' 'NOT TESTED' 'runas /trustlevel did not produce a report from this session' }
}

# ------------------------------------------------------------------------------------------------------ O11 a second disk that appears and goes away (a virtual disk stands in for a real one)
if ($Skip -contains 'vhd') { T 'O11' 'second disk' 'NOT TESTED' 'skipped' }
else {
    $vhd = Join-Path $Out 'mh_ops.vhd'
    $letter = (68..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Test-Path ($_ + ':\')) } | Select-Object -Last 1)
    $ds = Join-Path $Out 'diskpart1.txt'
    @("create vdisk file=`"$vhd`" maximum=64 type=expandable", "select vdisk file=`"$vhd`"", 'attach vdisk', 'create partition primary', 'format fs=ntfs quick label=MHOPS', "assign letter=$letter") | Set-Content -LiteralPath $ds -Encoding ASCII
    $dpOut = & diskpart.exe /s $ds 2>&1 | Out-String
    if (Test-Path ($letter + ':\')) {
        try {
            Copy-Item (Join-Path $sd 'harmless.exe') ($letter + ':\harmless.exe')
            $r = Run-Cli @('scan', '--path', ($letter + ':\'), '--no-browsers', '--no-memory', '--report-dir', "$Out\o11a", '--quiet') 300
            T 'O11a' "a second (virtual) disk $($letter): can be scanned" $(if ($r.Code -in 0, 1, 2 -and (Valid-Report "$Out\o11a")) { 'PASS' } else { 'FAIL' }) "exit $($r.Code)"
        } finally {
            @("select vdisk file=`"$vhd`"", 'detach vdisk') | Set-Content -LiteralPath $ds -Encoding ASCII
            & diskpart.exe /s $ds 2>&1 | Out-Null
        }
        $r = Run-Cli @('scan', '--path', ($letter + ':\'), '--no-browsers', '--no-memory', '--report-dir', "$Out\o11b", '--quiet') 120
        T 'O11b' 'the same disk after it went offline: an answer, no hang, no crash' $(if (-not $r.TimedOut -and $r.Out -notmatch 'Unhandled|at MineHunter\.') { 'PASS' } else { 'FAIL' }) "exit $($r.Code)"
    } else { T 'O11' 'second disk that appears and goes away' 'NOT TESTED' 'a virtual disk could not be attached here' }
    Remove-Item -LiteralPath $vhd -Force -ErrorAction SilentlyContinue
}
T 'O12' 'removable drive (USB stick / card)' 'NOT TESTED' 'no removable media available; MineHunter scans fixed drives only in a full scan and any folder or drive with --path'

$fail = @($results | Where-Object { $_.State -eq 'FAIL' }).Count; $pass = @($results | Where-Object { $_.State -eq 'PASS' }).Count; $nt = @($results | Where-Object { $_.State -eq 'NOT TESTED' }).Count
$summary = "OPS TESTS: $pass passed, $fail FAILED, $nt not tested"
Write-Host $summary
($summary, ($results | ForEach-Object { '{0,-5} {1,-10} {2}   {3}' -f $_.Id, $_.State, $_.Test, $_.Note })) | ForEach-Object { $_ } | Set-Content -LiteralPath (Join-Path $Out 'results.txt') -Encoding UTF8
if ($fail) { exit 1 } else { exit 0 }
