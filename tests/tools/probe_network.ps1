<#
  probe_network.ps1 - runs a MineHunter scan and samples, about every 0.7 s, every TCP connection and UDP endpoint owned by the MineHunter process.
  Purpose: evidence for the privacy claim (with no update source configured, a scan opens no network connection at all).
#>
param([string]$ArgString = 'scan --quick --no-cache --quiet', [string]$Exe)
if (-not $Exe) { $Exe = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\_bin\MineHunter.exe' }
$out = Join-Path $env:TEMP ('probe_net_' + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Force $out | Out-Null
$p = Start-Process -FilePath $Exe -ArgumentList ($ArgString + " --report-dir `"$out`"") -PassThru -WindowStyle Hidden
$seen = @{}; $samples = 0
while (-not $p.HasExited) {
    $samples++
    foreach ($c in @(Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue)) { $seen["TCP $($c.State) $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort)"] = 1 }
    foreach ($u in @(Get-NetUDPEndpoint -OwningProcess $p.Id -ErrorAction SilentlyContinue)) { $seen["UDP $($u.LocalAddress):$($u.LocalPort)"] = 1 }
    Start-Sleep -Milliseconds 700
}
"samples: $samples   process exit code: $($p.ExitCode)"
if ($seen.Count -eq 0) { 'NETWORK ENDPOINTS OBSERVED FOR THE MINEHUNTER PROCESS: none' } else { 'observed:'; $seen.Keys | Sort-Object }
