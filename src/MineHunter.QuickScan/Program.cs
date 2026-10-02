using System;
using MineHunter.Update;

namespace MineHunter
{
    /// <summary>MineHunter Quick Scan.exe: double click, allow the Windows prompt, the quick scan starts at once.</summary>
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            AppConfig cfg = Bootstrap.Init();
            return Gui.GuiApp.RunScanWindow(cfg, MineHunter.Scanning.ScanMode.Quick, args);
        }
    }
}
