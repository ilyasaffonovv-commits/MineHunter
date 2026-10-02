using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SD = System.Drawing;

namespace MineHunter.Gui
{
    /// <summary>The program's mark (a blue rounded square with a white shield and a check) drawn in code, for the window, the tray and the taskbar.</summary>
    public static class Branding
    {
        public static ImageSource WpfIcon()
        {
            var dv = new DrawingVisual();
            using (var dc = dv.RenderOpen())
            {
                dc.DrawRoundedRectangle(new SolidColorBrush(Color.FromRgb(0x4C, 0x8D, 0xFF)), null, new Rect(0, 0, 64, 64), 16, 16);
                dc.DrawGeometry(Brushes.White, null, Geometry.Parse("M32,10 L50,17 L50,31 C50,43 42,51 32,55 C22,51 14,43 14,31 L14,17 Z"));
                dc.DrawGeometry(null, new Pen(new SolidColorBrush(Color.FromRgb(0x4C, 0x8D, 0xFF)), 5) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round }, Geometry.Parse("M23,32 L30,39 L42,25"));
            }
            var rtb = new RenderTargetBitmap(64, 64, 96, 96, PixelFormats.Pbgra32); rtb.Render(dv); rtb.Freeze(); return rtb;
        }

        /// <summary>The tray icon. state: 0 normal (blue), 1 needs attention (orange dot), 2 danger (red dot).</summary>
        public static SD.Icon TrayIcon(int state)
        {
            using (var bmp = new SD.Bitmap(32, 32))
            using (var g = SD.Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SD.Drawing2D.SmoothingMode.AntiAlias;
                using (var bg = new SD.Drawing2D.GraphicsPath())
                {
                    int r = 8; bg.AddArc(0, 0, r * 2, r * 2, 180, 90); bg.AddArc(32 - r * 2 - 1, 0, r * 2, r * 2, 270, 90); bg.AddArc(32 - r * 2 - 1, 32 - r * 2 - 1, r * 2, r * 2, 0, 90); bg.AddArc(0, 32 - r * 2 - 1, r * 2, r * 2, 90, 90); bg.CloseFigure();
                    using (var b = new SD.SolidBrush(SD.Color.FromArgb(0x4C, 0x8D, 0xFF))) g.FillPath(b, bg);
                }
                var shield = new SD.PointF[] { new SD.PointF(16, 5), new SD.PointF(25, 8.5f), new SD.PointF(25, 15.5f), new SD.PointF(23, 21), new SD.PointF(16, 27), new SD.PointF(9, 21), new SD.PointF(7, 15.5f), new SD.PointF(7, 8.5f) };
                using (var w = new SD.SolidBrush(SD.Color.White)) g.FillPolygon(w, shield);
                using (var p = new SD.Pen(SD.Color.FromArgb(0x4C, 0x8D, 0xFF), 2.6f) { StartCap = SD.Drawing2D.LineCap.Round, EndCap = SD.Drawing2D.LineCap.Round, LineJoin = SD.Drawing2D.LineJoin.Round }) g.DrawLines(p, new[] { new SD.PointF(11.5f, 16), new SD.PointF(15, 19.5f), new SD.PointF(21, 12.5f) });
                if (state > 0)
                {
                    var c = state == 2 ? SD.Color.FromArgb(0xFF, 0x4D, 0x5E) : SD.Color.FromArgb(0xFF, 0x8A, 0x3D);
                    using (var ring = new SD.SolidBrush(SD.Color.FromArgb(0x0B, 0x0F, 0x1A))) g.FillEllipse(ring, 17, 17, 15, 15);
                    using (var dot = new SD.SolidBrush(c)) g.FillEllipse(dot, 19, 19, 11, 11);
                }
                IntPtr h = bmp.GetHicon();
                var icon = SD.Icon.FromHandle(h);
                var clone = (SD.Icon)icon.Clone();
                NativeDestroy(h);
                return clone;
            }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr h);
        static void NativeDestroy(IntPtr h) { try { DestroyIcon(h); } catch { } }
    }
}
