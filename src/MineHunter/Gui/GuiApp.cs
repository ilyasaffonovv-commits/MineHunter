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
        public static int Run(AppConfig cfg, string[] args)
        {
            bool created;
            using (var mutex = new Mutex(true, @"Local\MineHunter.Gui.SingleInstance", out created))
            {
                bool testMode = Array.IndexOf(args, "--shot") >= 0 || Array.IndexOf(args, "--shots") >= 0;
                if (!created && !testMode)
                {
                    MessageBox.Show(Loc.L("MineHunter is already running.", "MineHunter уже запущен."), "MineHunter", MessageBoxButton.OK, MessageBoxImage.Information);
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
