<#
  robustness.ps1 - feeds the file scanner things that tend to hang or crash scanners, and checks that MineHunter finishes with a valid report.

  Creates (only inside its own temp folder):  a truncated and a zero-byte .exe, random bytes named .dll, a corrupt .zip, a 5 GB sparse .exe,
  an exe held open by another process (exclusive lock), a path longer than 260 characters, a folder with 15 000 files, a directory junction that
  points back at its own parent (endless recursion if followed) and a 2 MB binary named config.json.
  Then runs  MineHunter-cli.exe scan --path <folder>  and reports: exit code, duration, peak memory, whether report.json parses.
  Nothing outside the temp folder is touched; the folder is removed at the end.

    powershell -File tests\robustness.ps1 [-Exe <path to MineHunter-cli.exe>] [-TimeoutSec 180]
#>
param(
    [string]$Exe = (Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) 'MineHunter-cli.exe'),
    [int]$TimeoutSec = 180
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP ('mh_robust_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$out = Join-Path $root '_out'
$data = Join-Path $root 'data'
New-Item -ItemType Directory -Force $data, $out | Out-Null
$lockStream = $null
$results = New-Object System.Collections.ArrayList
function Note($name, $ok, $detail) { [void]$results.Add([pscustomobject]@{ Check = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail }) }

try {
    $notepad = Join-Path $env:SystemRoot 'System32\notepad.exe'
    # 1-4: malformed content
    [IO.File]::WriteAllBytes((Join-Path $data 'truncated.exe'), ([IO.File]::ReadAllBytes($notepad))[0..63])
    [IO.File]::WriteAllBytes((Join-Path $data 'zero.exe'), (New-Object byte[] 0))
    $rnd = New-Object byte[] 5120; (New-Object Random 7).NextBytes($rnd); $rnd[0] = 0x4D; $rnd[1] = 0x5A
    [IO.File]::WriteAllBytes((Join-Path $data 'garbage.dll'), $rnd)
    $rnd2 = New-Object byte[] 8192; (New-Object Random 9).NextBytes($rnd2)
    [IO.File]::WriteAllBytes((Join-Path $data 'corrupt.zip'), $rnd2)
    # PE whose section table claims far more than the file holds
    $pe = [IO.File]::ReadAllBytes($notepad); $pe = $pe[0..2047]
    [IO.File]::WriteAllBytes((Join-Path $data 'cut_pe.exe'), $pe)
    # 5: huge sparse file (logical size 3 GB, almost no disk space)
    $sparse = Join-Path $data 'huge_sparse.exe'
    [IO.File]::WriteAllBytes($sparse, [byte[]](0x4D, 0x5A, 0, 0))
    & fsutil sparse setflag $sparse | Out-Null
    $fs = [IO.File]::Open($sparse, 'Open', 'ReadWrite', 'ReadWrite'); $fs.SetLength(5GB); $fs.Close()      # more than 4 GB
    # 6: exclusive lock
    $locked = Join-Path $data 'locked.exe'; Copy-Item $notepad $locked
    $lockStream = [IO.File]::Open($locked, 'Open', 'Read', 'None')
    # 7: path longer than MAX_PATH
    $deep = $data; for ($i = 0; $i -lt 9; $i++) { $deep = $deep + '\' + ('d' * 40 + $i) }
    New-Item -ItemType Directory -Force ('\\?\' + $deep) | Out-Null
    [IO.File]::WriteAllBytes(('\\?\' + $deep + '\deep.exe'), ([IO.File]::ReadAllBytes($notepad))[0..4095])
    # 8: many files
    $many = Join-Path $data 'many'; New-Item -ItemType Directory $many | Out-Null
    1..15000 | ForEach-Object { [IO.File]::WriteAllBytes((Join-Path $many "f$_.txt"), [byte[]](65)) }
    # 9: junction pointing at the parent
    & cmd /c mklink /J (Join-Path $data 'loop') $data | Out-Null
    # 10: big binary candidate config
    $bigcfg = New-Object byte[] (2MB); (New-Object Random 3).NextBytes($bigcfg)
    [IO.File]::WriteAllBytes((Join-Path $data 'config.json'), $bigcfg)

    # 11: Unicode names: Cyrillic, Japanese, an emoji, a right-to-left override, and a name with a trailing dot (only possible with the extended prefix)
    $uni = (-join [char[]](0x0444, 0x0430, 0x0439, 0x043B)) + '-' + (-join [char[]](0x65E5, 0x672C, 0x8A9E)) + '-' + [char]::ConvertFromUtf32(0x1F600)
    $stub = ([IO.File]::ReadAllBytes($notepad))[0..4095]
    [IO.File]::WriteAllBytes((Join-Path $data ($uni + '.exe')), $stub)
    [IO.File]::WriteAllBytes((Join-Path $data ('invoice' + [char]0x202E + 'txt.exe')), $stub)
    [IO.File]::WriteAllBytes(('\\?\' + (Join-Path $data 'trailing.exe.')), $stub)
    # run the scan, sample its memory
    $args = @('scan', '--path', $data, '--no-memory', '--no-browsers', '--no-cache', '--report-dir', $out, '--quiet')
    $psi = New-Object Diagnostics.ProcessStartInfo $Exe
    $psi.Arguments = ($args | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
    $peak = 0
    while (-not $p.WaitForExit(500)) {
        try { $p.Refresh(); if ($p.PeakWorkingSet64 -gt $peak) { $peak = $p.PeakWorkingSet64 } } catch { }
        if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) { try { $p.Kill() } catch { }; break }
    }
    $hung = $sw.Elapsed.TotalSeconds -gt $TimeoutSec
    $sw.Stop()
    Note 'finishes within the time limit (no hang on junction loop / sparse file / lock / many files)' (-not $hung) ("{0:N0} s" -f $sw.Elapsed.TotalSeconds)
    if (-not $hung) {
        Note 'exit code is a scan result (0/1/2), not an error (3)' ($p.ExitCode -in 0, 1, 2) "exit $($p.ExitCode)"
        $rj = Join-Path $out 'report.json'
        $ok = $false; $detail = 'no report.json'
        if (Test-Path $rj) { try { $r = Get-Content $rj -Raw | ConvertFrom-Json; $ok = $null -ne $r.summary -or $null -ne $r.findings; $detail = "files inspected: $($r.stats.filesInspected)" } catch { $detail = 'report.json does not parse: ' + $_.Exception.Message } }
        Note 'report.json is written and valid' $ok $detail
        Note 'peak memory stays reasonable (< 700 MB)' ($peak -lt 700MB) ("{0:N0} MB" -f ($peak / 1MB))
        $txt = $so.Result + $se.Result
        $ru = -join [char[]](0x041D, 0x0435, 0x043E, 0x0431, 0x0440, 0x0430, 0x0431, 0x043E, 0x0442, 0x0430, 0x043D, 0x043D, 0x043E, 0x0435)       # the .NET message in a Russian Windows
        $bad = $txt -match ('Unhandled|' + $ru + '|StackOverflow|at MineHunter\.')
        Note 'no unhandled exception text in the output' (-not $bad) $(if ($bad) { 'exception printed' } else { '' })
    }
}
finally {
    if ($lockStream) { $lockStream.Close() }
    & cmd /c rmdir (Join-Path $data 'loop') 2>$null | Out-Null
    try { Remove-Item ('\\?\' + $root) -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
$results | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Output
$bad = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
if ($bad) { "$bad CHECK(S) FAILED"; exit 1 } else { 'ALL ROBUSTNESS CHECKS PASSED'; exit 0 }
