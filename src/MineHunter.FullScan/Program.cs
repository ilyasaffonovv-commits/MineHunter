using System;
using MineHunter.Update;

namespace MineHunter
{
    /// <summary>MineHunter Full Scan.exe: the long, deep scan of all fixed drives with a live status.</summary>
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            AppConfig cfg = Bootstrap.Init();
            return Gui.GuiApp.RunScanWindow(cfg, MineHunter.Scanning.ScanMode.Full, args);
        }
    }
}
