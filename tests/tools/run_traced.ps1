<#
  run_traced.ps1 - runs an executable while recording what it does to the system.

  Records (all read-only observation, nothing is injected into the target):
    * ETW kernel providers: process start, registry, file create/delete/rename, network, WMI-Activity
    * a 500 ms sampler: CPU time, working set, threads, handles, I/O counters, child processes, TCP connections
    * token privileges of the target (enabled/disabled) sampled twice
    * stdout / stderr of the target
  Output goes to -OutDir. Requires an elevated PowerShell (logman/ETW).
#>
param(
    [Parameter(Mandatory)][string]$Exe,
    [string[]]$ArgList = @(),
    [string]$ArgString = '',     # alternative to -ArgList when the script is started via 'powershell -File'
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$OutDir,
    [int]$TimeoutSec = 1200,
    [switch]$NoEtw,
    [switch]$ViaCmd,             # start through a hidden cmd.exe console (needed for tools that call Console.GetBufferInfo and crash when stdout is redirected)
    [string]$Priority = ''        # e.g. BelowNormal - applied from outside after start (recorded in the report)
)
$ErrorActionPreference = 'Stop'
if ($ArgString) { $ArgList = @($ArgString -split ' ' | Where-Object { $_ }) }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$etl = Join-Path $OutDir "$Label.etl"
$session = "MH_$Label"

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Collections.Generic; using System.Text;
public static class TokPriv {
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint acc, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeName(string sys, ref long luid, StringBuilder name, ref int cch);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public static string[] Get(int pid) {
    var res = new List<string>();
    IntPtr hp = OpenProcess(0x1000, false, pid); if (hp == IntPtr.Zero) return new[]{"<cannot open process>"};
    IntPtr tok; if (!OpenProcessToken(hp, 0x8, out tok)) { CloseHandle(hp); return new[]{"<cannot open token>"}; }
    int need; GetTokenInformation(tok, 3, IntPtr.Zero, 0, out need);
    IntPtr buf = Marshal.AllocHGlobal(need);
    try {
      if (GetTokenInformation(tok, 3, buf, need, out need)) {
        int cnt = Marshal.ReadInt32(buf);
        for (int i = 0; i < cnt; i++) {
          IntPtr e = IntPtr.Add(buf, 4 + i * 12);
          long luid = Marshal.ReadInt64(e); int attr = Marshal.ReadInt32(e, 8);
          var sb = new StringBuilder(128); int c = 128; LookupPrivilegeName(null, ref luid, sb, ref c);
          res.Add(sb.ToString() + ((attr & 2) != 0 ? " [ENABLED]" : (attr & 1) != 0 ? " [default-enabled]" : " [disabled]"));
        }
      }
    } finally { Marshal.FreeHGlobal(buf); CloseHandle(tok); CloseHandle(hp); }
    return res.ToArray();
  }
}
'@

function Start-Etw {
    logman stop $session -ets 2>$null | Out-Null
    logman create trace $session -ow -o $etl -ets -bs 1024 -nb 64 256 -max 2500 | Out-Null
    # Narrow profile: what the target CHANGES. (An all-keywords registry trace produced >2.5 GB in 2.5 minutes system-wide.)
    $providers = @(
        @('{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}', '0x10',   '5'),  # Kernel-Process: process start/stop
        @('{70EB4F03-C1DE-4F73-A051-33D13D5413BD}', '0x5344', '5'),  # Kernel-Registry: SetValue, DeleteValue, CreateKey, DeleteKey, Set(Security|Information)Key
        @('{EDD08927-9CC4-4E65-B970-C2560FB5C289}', '0x1C10', '5'),  # Kernel-File: filename map + delete + rename + create-new-file
        @('{7DD42A49-5329-4832-8DFD-43D979153A88}', '0x30',   '5'),  # Kernel-Network: IPv4 + IPv6
        @('{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}', '0x4000000000000000', '5')   # WMI-Activity/Operational
    )
    foreach ($p in $providers) { logman update trace $session -p $p[0] $p[1] $p[2] -ets | Out-Null }
}
function Stop-Etw { logman stop $session -ets 2>&1 | Out-Null }

$samples = New-Object System.Collections.Generic.List[object]
$childSeen = @{}
$netSeen = @{}
$privs = @{}

# stdin comes from a file holding a few newlines, so a trailing Console.ReadLine() in the target returns instead of hanging
$stdinFile = Join-Path $OutDir "$Label.stdin.txt"
[IO.File]::WriteAllText($stdinFile, "`r`n`r`n`r`n")
$startTime = Get-Date
if (-not $NoEtw) { Start-Etw }
if ($ViaCmd) {
    $q = '"'
    $inner = $q + $q + $Exe + $q + ' ' + ($ArgList -join ' ') + ' < ' + $q + $stdinFile + $q + $q
    $wrapper = Start-Process -FilePath cmd.exe -ArgumentList @('/c', $inner) -WindowStyle Hidden -PassThru -WorkingDirectory (Split-Path $Exe -Parent)
    $null = $wrapper.Handle
    $proc = $null
    for ($i = 0; $i -lt 40 -and -not $proc; $i++) {
        Start-Sleep -Milliseconds 100
        $kid = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($wrapper.Id)" | Where-Object { $_.Name -ne 'conhost.exe' } | Select-Object -First 1
        if ($kid) { $proc = Get-Process -Id $kid.ProcessId -ErrorAction SilentlyContinue }
    }
    if (-not $proc) { throw "could not find the child process of the cmd wrapper" }
    $null = $proc.Handle
} else {
    $psi = @{
        FilePath = $Exe; ArgumentList = $ArgList; PassThru = $true; WindowStyle = 'Hidden'
        RedirectStandardOutput = (Join-Path $OutDir "$Label.stdout.txt"); RedirectStandardError = (Join-Path $OutDir "$Label.stderr.txt")
        RedirectStandardInput = $stdinFile
        WorkingDirectory = (Split-Path $Exe -Parent)
    }
    $proc = Start-Process @psi
    $null = $proc.Handle
}
$pid0 = $proc.Id
if ($Priority) { try { $proc.PriorityClass = $Priority } catch {} }
"[$Label] started PID=$pid0 at $($startTime.ToString('HH:mm:ss'))  args: $($ArgList -join ' ')"

$sw = [Diagnostics.Stopwatch]::StartNew()
$tick = 0
while (-not $proc.HasExited -and $sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    Start-Sleep -Milliseconds 500
    $tick++
    try {
        $p = Get-Process -Id $pid0 -ErrorAction Stop
        $w = Get-CimInstance Win32_Process -Filter "ProcessId=$pid0" -ErrorAction SilentlyContinue
        $samples.Add([pscustomobject]@{ t = [math]::Round($sw.Elapsed.TotalSeconds,1); cpuSec = [math]::Round($p.TotalProcessorTime.TotalSeconds,2); wsMB = [math]::Round($p.WorkingSet64/1MB,1); privMB = [math]::Round($p.PrivateMemorySize64/1MB,1); threads = $p.Threads.Count; handles = $p.HandleCount; prio = "$($p.PriorityClass)"; readMB = [math]::Round($w.ReadTransferCount/1MB,1); writeMB = [math]::Round($w.WriteTransferCount/1MB,1) })
    } catch {}
    # descendants (children, grandchildren) created by the target
    if ($tick % 2 -eq 0) {
        $all = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        $ids = @($pid0); $grew = $true
        while ($grew) { $grew = $false; foreach ($c in $all) { if ($c.ParentProcessId -in $ids -and $c.ProcessId -notin $ids) { $ids += $c.ProcessId; $grew = $true; if (-not $childSeen.ContainsKey($c.ProcessId)) { $childSeen[$c.ProcessId] = "$($c.Name) | $($c.CommandLine) | ppid=$($c.ParentProcessId) | first seen t=$([math]::Round($sw.Elapsed.TotalSeconds,1))s" } } } }
        $conns = Get-NetTCPConnection -OwningProcess $ids -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Listen' -and $_.RemoteAddress -notin '0.0.0.0','::' }
        foreach ($c in $conns) { $k = "$($c.OwningProcess) $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) [$($c.State)]"; if (-not $netSeen.ContainsKey($k)) { $netSeen[$k] = [math]::Round($sw.Elapsed.TotalSeconds,1) } }
        $udp = Get-NetUDPEndpoint -OwningProcess $ids -ErrorAction SilentlyContinue
        foreach ($u in $udp) { $k = "UDP $($u.OwningProcess) $($u.LocalAddress):$($u.LocalPort)"; if (-not $netSeen.ContainsKey($k)) { $netSeen[$k] = [math]::Round($sw.Elapsed.TotalSeconds,1) } }
    }
    if ($tick -in 20, 160) { try { $privs["t=$($sw.Elapsed.TotalSeconds.ToString('N0'))s"] = [TokPriv]::Get($pid0) } catch {} }
}
$timedOut = -not $proc.HasExited
if ($timedOut) { "[$Label] TIMEOUT after $TimeoutSec s - stopping target"; Stop-Process -Id $pid0 -Force }
$proc.WaitForExit()
$endTime = Get-Date
$exit = $null; try { $proc.Refresh(); $exit = $proc.ExitCode } catch {}; if ($ViaCmd -and $wrapper) { try { $wrapper.WaitForExit(5000) | Out-Null; if ($null -eq $exit) { $exit = $wrapper.ExitCode } } catch {} }
if (-not $NoEtw) { Stop-Etw }
"[$Label] exited code=$exit after $([math]::Round($sw.Elapsed.TotalSeconds,1)) s"

$summary = [ordered]@{
    label = $Label; exe = $Exe; args = $ArgList; pid = $pid0; started = $startTime.ToString('o'); ended = $endTime.ToString('o')
    durationSec = [math]::Round($sw.Elapsed.TotalSeconds,1); exitCode = $exit; timedOut = $timedOut; externalPriority = $Priority
    peak = [ordered]@{
        cpuSec = ($samples | Measure-Object cpuSec -Maximum).Maximum; workingSetMB = ($samples | Measure-Object wsMB -Maximum).Maximum
        privateMB = ($samples | Measure-Object privMB -Maximum).Maximum; threads = ($samples | Measure-Object threads -Maximum).Maximum
        handles = ($samples | Measure-Object handles -Maximum).Maximum; readMB = ($samples | Measure-Object readMB -Maximum).Maximum; writeMB = ($samples | Measure-Object writeMB -Maximum).Maximum
    }
    priorityObserved = @($samples | Select-Object -ExpandProperty prio -Unique)
    descendants = @($childSeen.GetEnumerator() | Sort-Object Name | ForEach-Object { "PID $($_.Name): $($_.Value)" })
    network = @($netSeen.GetEnumerator() | Sort-Object Value | ForEach-Object { "t=$($_.Value)s $($_.Name)" })
    privileges = $privs
    etl = if ($NoEtw) { $null } else { $etl }
}
$summary | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir "$Label.summary.json") -Encoding UTF8
$samples | ConvertTo-Json | Set-Content (Join-Path $OutDir "$Label.samples.json") -Encoding UTF8
$summary | ConvertTo-Json -Depth 6
