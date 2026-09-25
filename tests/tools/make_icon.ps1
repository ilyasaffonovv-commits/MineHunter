<#
  make_icon.ps1 - draws the MineHunter icon (blue rounded square, white shield, check mark) and writes a multi-size .ico
  (PNG-compressed frames: 256/64/48/32/24/16). Pure System.Drawing, no downloads.
#>
param([string]$Out = "$PSScriptRoot\..\..\src\MineHunter\app.ico")
Add-Type -AssemblyName System.Drawing

function New-Frame([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 64.0
    # rounded square
    $r = 16 * $s; $rect = New-Object System.Drawing.RectangleF 0, 0, $size, $size
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $path.AddArc(0, 0, $d, $d, 180, 90); $path.AddArc($size - $d, 0, $d, $d, 270, 90)
    $path.AddArc($size - $d, $size - $d, $d, $d, 0, 90); $path.AddArc(0, $size - $d, $d, $d, 90, 90); $path.CloseFigure()
    $g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0x4C, 0x8D, 0xFF))), $path)
    # shield
    $pts = @(
        [System.Drawing.PointF]::new(32 * $s, 10 * $s), [System.Drawing.PointF]::new(50 * $s, 17 * $s), [System.Drawing.PointF]::new(50 * $s, 31 * $s),
        [System.Drawing.PointF]::new(44 * $s, 45 * $s), [System.Drawing.PointF]::new(32 * $s, 55 * $s),
        [System.Drawing.PointF]::new(20 * $s, 45 * $s), [System.Drawing.PointF]::new(14 * $s, 31 * $s), [System.Drawing.PointF]::new(14 * $s, 17 * $s))
    $g.FillPolygon([System.Drawing.Brushes]::White, [System.Drawing.PointF[]]$pts)
    # check mark
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 0x4C, 0x8D, 0xFF)), (5 * $s)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    [System.Drawing.PointF[]]$chk = @([System.Drawing.PointF]::new(23 * $s, 32 * $s), [System.Drawing.PointF]::new(30 * $s, 39 * $s), [System.Drawing.PointF]::new(42 * $s, 25 * $s))
    $g.DrawLines($pen, $chk)
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    , $ms.ToArray()
}

$sizes = 256, 64, 48, 32, 24, 16
$frames = foreach ($sz in $sizes) { , (New-Frame $sz) }
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter $ms
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]; $data = $frames[$i]
    $bw.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz }))); $bw.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz })))
    $bw.Write([byte]0); $bw.Write([byte]0); $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$data.Length); $bw.Write([uint32]$offset)
    $offset += $data.Length
}
foreach ($data in $frames) { $bw.Write($data) }
$bw.Flush()
[System.IO.File]::WriteAllBytes((Resolve-Path -LiteralPath (Split-Path $Out -Parent)).Path + '\' + (Split-Path $Out -Leaf), $ms.ToArray())
"icon written: $Out ($($ms.Length) bytes)"
