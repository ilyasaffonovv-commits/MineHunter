using System;
using System.Runtime.CompilerServices;

namespace MineHunter
{
    /// <summary>MineHunter Quick Scan.exe: double click, allow the Windows prompt, the quick scan starts at once.</summary>
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            try { return Run(args); }
            catch (Exception ex) when (LaunchGuard.IsMissingOwnFile(ex)) { return LaunchGuard.ShowGui(); }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static int Run(string[] args)
        {
            var cfg = Bootstrap.Init();
            return Gui.GuiApp.RunScanWindow(cfg, MineHunter.Scanning.ScanMode.Quick, args);
        }
    }
}
