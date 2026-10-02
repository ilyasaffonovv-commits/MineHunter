using System;
using System.IO;
using System.Threading;
using System.Windows;
using MineHunter.Rules;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Gui
{
    public static class GuiApp
    {
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);

        /// <summary>A second start brings the window that is already open to the front instead of opening a second one (no dialog that would wait for a click).</summary>
        static void ActivateRunningInstance()
        {
            try
            {
                var me = System.Diagnostics.Process.GetCurrentProcess();
                foreach (var p in System.Diagnostics.Process.GetProcessesByName(me.ProcessName))
                {
                    using (p)
                    {
                        if (p.Id == me.Id || p.MainWindowHandle == IntPtr.Zero) continue;
                        ShowWindow(p.MainWindowHandle, 9);          // SW_RESTORE
                        SetForegroundWindow(p.MainWindowHandle);
                        return;
                    }
                }
            }
            catch { }
        }

        public static bool IsGuiInvocation(string[] args) { return args.Length == 0 || args[0].Equals("--gui", StringComparison.OrdinalIgnoreCase); }

        public static int RunScanWindow(AppConfig cfg, MineHunter.Scanning.ScanMode mode, string[] args) { return Run(cfg, args); }

        public static int Run(AppConfig cfg, string[] args)
        {
            if (args.Length > 0 && args[0].Equals("--gui", StringComparison.OrdinalIgnoreCase)) args = System.Linq.Enumerable.ToArray(System.Linq.Enumerable.Skip(args, 1));
            bool created;
            using (var mutex = new Mutex(true, @"Local\MineHunter.Gui.SingleInstance", out created))
            {
                bool testMode = Array.IndexOf(args, "--shot") >= 0 || Array.IndexOf(args, "--shots") >= 0;
                if (!created && !testMode)
                {
                    ActivateRunningInstance();
                    return 0;
                }
                var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
                app.DispatcherUnhandledException += (s, e) =>
                {
                    try { Directory.CreateDirectory(RulePack.DataDir); File.AppendAllText(Path.Combine(RulePack.DataDir, "crash.log"), DateTime.Now.ToString("o") + "\n" + e.Exception + "\n\n"); } catch { }
                    Log.Error("UI error: " + e.Exception);
                    e.Handled = true;
                };
                MainWindow mw;
                try { mw = new MainWindow(cfg, args); }
                catch (Exception ex)
                {
                    try { Directory.CreateDirectory(RulePack.DataDir); File.AppendAllText(Path.Combine(RulePack.DataDir, "crash.log"), DateTime.Now.ToString("o") + "\nwindow: " + ex + "\n\n"); } catch { }
                    MessageBox.Show("MineHunter could not open its window:\n" + ex.Message + "\n\nThe command-line mode still works: MineHunter.exe scan --quick", "MineHunter", MessageBoxButton.OK, MessageBoxImage.Error);
                    return 1;
                }
                return app.Run(mw.W);
            }
        }
    }
}
