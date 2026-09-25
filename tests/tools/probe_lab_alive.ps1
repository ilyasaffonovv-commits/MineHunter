<#
  probe_lab_alive.ps1 - starts the MinerLab dynamic processes and prints which of them are alive every 8 seconds (test-helper for timing questions).
#>
$lab = Join-Path (Split-Path -Parent $PSScriptRoot) 'MinerLab\lab.ps1'
& powershell.exe -NoProfile -File $lab -Action Start-Dynamic | Select-Object -Last 1
$dyn = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'MinerLab\lab_dynamic.json') -Raw | ConvertFrom-Json
$t0 = Get-Date
for ($i = 1; $i -le 9; $i++) {
    Start-Sleep -Seconds 7
    $alive = @($dyn | Where-Object { Get-Process -Id $_.pid -ErrorAction SilentlyContinue } | ForEach-Object { $_.id })
    "t+{0,3}s alive={1}: {2}" -f [int]((Get-Date) - $t0).TotalSeconds, $alive.Count, ($alive -join ',')
}
