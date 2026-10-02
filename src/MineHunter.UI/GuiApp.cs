using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using MineHunter.Guards;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>The entry points of the windowed programs: the main program (window, tray, scheduled scans, Explorer commands) and the scan windows (Quick Scan.exe, Full Scan.exe).</summary>
    public static class GuiApp
    {
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);

        static readonly HashSet<string> Flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "--gui", "--tray", "--scheduled", "--after-update", "--open-last", "--check-file", "--analyze-file", "--scan-folder", "--page", "--shot", "--shots", "--tab", "--select", "--notes", "--neutralize", "--filter", "--no-scan", "--lang", "--shot-file" };

        public static bool IsGuiInvocation(string[] args) { return args.Length == 0 || Flags.Contains(args[0]); }

        sealed class Cmd
        {
            public bool Tray, AfterUpdate, OpenLast, NoScan; public string Scheduled, CheckFile, AnalyzeFile, ScanFolder, Page, Shots, Shot, ShotFile, Lang;
            public static Cmd Parse(string[] a)
            {
                var c = new Cmd();
                for (int i = 0; i < a.Length; i++)
                {
                    string k = a[i].ToLowerInvariant(); string v = i + 1 < a.Length && !a[i + 1].StartsWith("--") ? a[i + 1] : null;
                    switch (k)
                    {
                        case "--tray": c.Tray = true; break;
                        case "--after-update": c.AfterUpdate = true; break;
                        case "--open-last": c.OpenLast = true; break;
                        case "--no-scan": c.NoScan = true; break;
                        case "--scheduled": c.Scheduled = v ?? "quick"; if (v != null) i++; break;
                        case "--check-file": c.CheckFile = v; if (v != null) i++; break;
                        case "--analyze-file": c.AnalyzeFile = v; if (v != null) i++; break;
                        case "--scan-folder": c.ScanFolder = v; if (v != null) i++; break;
                        case "--page": c.Page = v; if (v != null) i++; break;
                        case "--shots": c.Shots = v; if (v != null) i++; break;
                        case "--shot": c.Shot = v; if (v != null) i++; break;
                        case "--shot-file": c.ShotFile = v; if (v != null) i++; break;
                        case "--lang": c.Lang = v; if (v != null) i++; break;
                    }
                }
                return c;
            }
            public string ToMessage()
            {
                if (CheckFile != null) return "check\t" + CheckFile; if (AnalyzeFile != null) return "analyze\t" + AnalyzeFile; if (ScanFolder != null) return "scan-folder\t" + ScanFolder;
                if (OpenLast) return "open-last\t"; if (Page != null) return "page\t" + Page; return "show\t";
            }
        }

        public static AppModel Model; static MainShell Main; static TrayHost Tray; static Application App; static bool replacing;

        // ============================================================================================ one window at a time
        static void ActivateRunningInstance()
        {
            try
            {
                var me = Process.GetCurrentProcess();
                foreach (var p in Process.GetProcessesByName(me.ProcessName))
                    using (p) { if (p.Id == me.Id || p.MainWindowHandle == IntPtr.Zero) continue; ShowWindow(p.MainWindowHandle, 9); SetForegroundWindow(p.MainWindowHandle); return; }
            }
            catch { }
        }

        const string PipeName = "MineHunter.Gui.Cmd";

        static bool Forward(string line)
        {
            try { using (var c = new NamedPipeClientStream(".", PipeName, PipeDirection.Out)) { c.Connect(2500); var w = new StreamWriter(c, new UTF8Encoding(false)) { AutoFlush = true }; w.WriteLine(line); return true; } }
            catch { return false; }
        }

        static void ServePipe(Action<string> onLine)
        {
            var t = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        var sec = new PipeSecurity();
                        sec.AddAccessRule(new PipeAccessRule(System.Security.Principal.WindowsIdentity.GetCurrent().User, PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));
                        using (var srv = new NamedPipeServerStream(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096, sec))
                        {
                            srv.WaitForConnection();
                            using (var r = new StreamReader(srv, Encoding.UTF8)) { string line = r.ReadLine(); if (!string.IsNullOrEmpty(line)) onLine(line); }
                        }
                    }
                    catch (Exception ex) { Log.Warn("pipe: " + ex.Message); Thread.Sleep(500); }
                }
            }) { IsBackground = true, Name = "MineHunter commands" };
            t.Start();
        }

        // ============================================================================================ the main program
        public static int Run(AppConfig cfg, string[] args)
        {
            if (args.Length > 0 && args[0].Equals("--gui", StringComparison.OrdinalIgnoreCase)) args = args.Skip(1).ToArray();
            var cmd = Cmd.Parse(args);
            if (!string.IsNullOrEmpty(cmd.Lang)) Loc.Init(cmd.Lang);
            bool testMode = cmd.Shots != null || cmd.Shot != null;
            bool scheduled = cmd.Scheduled != null;
            bool created;
            using (var mutex = new Mutex(true, scheduled ? @"Local\MineHunter.Gui.Scheduled" : @"Local\MineHunter.Gui.SingleInstance", out created))
            {
                if (!created && !testMode)
                {
                    if (!scheduled && !Forward(cmd.ToMessage())) ActivateRunningInstance();
                    return 0;
                }
                App = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                App.Resources.MergedDictionaries.Add(Ui.Theme);
                App.DispatcherUnhandledException += (s, e) => { Bootstrap.CrashLog("ui", e.Exception); Log.Error("UI error: " + e.Exception); e.Handled = true; };
                Model = new AppModel(cfg, App.Dispatcher);
                Model.Navigate = (p, a) => EnsureMain().Go(p, a);
                if (scheduled) return RunScheduled(cmd, cfg);

                Model.LastUpdateResult = AppUpdater.TakeResult();
                Tray = new TrayHost(Model, () => EnsureMain().Go(Main != null && Main.CurrentKey != null ? Main.CurrentKey : "home", null));
                Tray.ClickedBalloon(() => EnsureMain().Go("protection", null));
                Model.StartGuards();
                ServePipe(line => App.Dispatcher.BeginInvoke(new Action(() => HandleCommand(line))));
                // alerts from the real-time layer
                Model.Guards = Model.Guards ?? new GuardHost(Model.S);
                Model.Guards.AlertRaised += a => App.Dispatcher.BeginInvoke(new Action(() => OnAlert(a)));
                if (Model.S.AutoUpdateApp || cfg.CheckUpdatesOnStart) App.Dispatcher.BeginInvoke(new Action(() => Model.CheckUpdates(false)), DispatcherPriority.ApplicationIdle);
                App.Dispatcher.BeginInvoke(new Action(() => MissedScheduledScan()), DispatcherPriority.ApplicationIdle);

                if (!cmd.Tray || testMode || cmd.CheckFile != null || cmd.AnalyzeFile != null || cmd.ScanFolder != null || cmd.OpenLast || cmd.Page != null) App.Dispatcher.BeginInvoke(new Action(() => { var shell = EnsureMain(); HandleStartup(shell, cmd); }));
                Log.Info("MineHunter " + AppInfo.Version + (cmd.Tray ? " (tray)" : ""));
                return App.Run();
            }
        }

        static MainShell EnsureMain()
        {
            if (Main != null && Main.W.IsLoaded) { return Main; }
            if (Main != null) return Main;
            var shell = new MainShell(Model); Main = shell; WireMain(shell);
            shell.W.Show(); shell.Go("home", null);
            return shell;
        }

        static void WireMain(MainShell shell)
        {
            shell.W.Closing += (s, e) =>
            {
                if (replacing) return;
                var m = Model;
                if (m.S.CloseToTray && Tray != null) { e.Cancel = true; shell.W.Hide(); return; }
                if (m.Scanner.Running)
                {
                    if (!Dlg.Ask(shell.W, "MineHunter", Loc.L("A scan is running. Stop it and close MineHunter?", "Идёт проверка. Остановить её и закрыть MineHunter?"), Loc.L("Stop and close", "Остановить и закрыть"), Loc.L("Keep scanning", "Продолжить"))) { e.Cancel = true; return; }
                    m.Scanner.Cancel(); try { ScanEngine.ReleaseLock(); } catch { }
                }
                Quit();
            };
        }

        public static void Quit()
        {
            try { Model.StopGuards(); } catch { }
            try { if (Tray != null) Tray.Dispose(); } catch { }
            App.Shutdown();
        }

        public static void ReplaceMain(MainShell old, MainShell fresh, string key)
        {
            replacing = true; Main = fresh; WireMain(fresh);
            fresh.W.Show(); fresh.Go(key, null);
            old.W.Close(); replacing = false;
        }

        static void HandleStartup(MainShell shell, Cmd cmd)
        {
            if (cmd.Shots != null) { Shots(shell, cmd); return; }
            if (cmd.Shot != null) { ShotOne(shell, cmd); return; }
            if (cmd.CheckFile != null) { var p = Explorer(cmd.CheckFile); if (p != null) shell.Go("files", p); }
            else if (cmd.AnalyzeFile != null) { var p = Explorer(cmd.AnalyzeFile); if (p != null) { shell.Go("files", null); var fp = shell.Page("files") as FilesPage; if (fp != null) fp.OpenDeep(p); } }
            else if (cmd.ScanFolder != null) { var p = Explorer(cmd.ScanFolder); if (p != null) shell.Go("scan", new[] { p }); }
            else if (cmd.OpenLast) shell.Go("scan", null);
            else if (cmd.Page != null) shell.Go(cmd.Page, null);
        }

        static string Explorer(string arg) { string p = ShellIntegration.SafePath(arg); if (p == null) Log.Warn("a command from Explorer was refused: " + arg); return p; }

        static void HandleCommand(string line)
        {
            var parts = line.Split(new[] { '\t' }, 2); string verb = parts[0], arg = parts.Length > 1 ? parts[1] : "";
            var shell = EnsureMain();
            switch (verb)
            {
                case "check": { var p = Explorer(arg); if (p != null) shell.Go("files", p); break; }
                case "analyze": { var p = Explorer(arg); if (p != null) { shell.Go("files", null); var fp = shell.Page("files") as FilesPage; if (fp != null) fp.OpenDeep(p); } break; }
                case "scan-folder": { var p = Explorer(arg); if (p != null) shell.Go("scan", new[] { p }); break; }
                case "open-last": shell.Go("scan", null); break;
                case "page": shell.Go(arg, null); break;
                default: shell.W.Show(); if (shell.W.WindowState == WindowState.Minimized) shell.W.WindowState = WindowState.Normal; shell.W.Activate(); break;
            }
        }

        // ============================================================================================ alerts and scheduled work
        static void OnAlert(GuardAlert a)
        {
            try
            {
                if (Model.S.NotifySound) System.Media.SystemSounds.Exclamation.Play();
                if (a.Level >= AlertLevel.Suspicious) AlertWindow.Show(Model, a);
                else if (Tray != null) Tray.Balloon("MineHunter", a.Title + ": " + Text.Trunc(a.Text, 140));
            }
            catch (Exception ex) { Log.Warn("alert: " + ex.Message); }
        }

        /// <summary>A scheduled scan whose time passed while the PC was off is run when the program starts (if the user asked for it and Windows' own "run as soon as possible" did not).</summary>
        static void MissedScheduledScan()
        {
            try
            {
                var s = Model.S; if (!s.ScheduleEnabled || !s.ScheduleRunMissed || Model.Scanner.Running) return;
                string mode = s.ScheduleMode == "Full" ? "Full" : "Quick";
                var last = History.List().Where(h => !h.Aborted && h.Trigger == "scheduled").Select(h => (DateTime?)h.StartedTime).FirstOrDefault();
                if (last == null) { var any = History.Last(mode); last = any == null ? (DateTime?)null : any.StartedTime; }
                if (!ScheduleManager.IsOverdue(s, DateTime.Now, last)) return;
                if (s.GameMode && SystemState.FullScreenAppActive()) return;
                if (s.ScheduleNotOnBattery && SystemState.OnBattery()) return;
                Log.Info("A scheduled scan was missed: running it now");
                Model.StartScan(s.ScheduleMode == "Full" ? ScanMode.Full : s.ScheduleMode == "Custom" ? ScanMode.Custom : ScanMode.Quick, "scheduled", s.ScheduleMode == "Custom" ? s.ScheduleCustomPaths : null);
                Model.ScanFinishedHook = r => ReportScheduled(r);
            }
            catch (Exception ex) { Log.Warn("missed scan: " + ex.Message); }
        }

        static void ReportScheduled(ScanRun r)
        {
            if (r == null || r.Result == null || r.Result.Aborted) return;
            int mal = r.Result.Findings.Count(f => f.Verdict >= MineHunter.Model.Verdict.HighRisk), med = r.Result.Findings.Count(f => f.Verdict == MineHunter.Model.Verdict.Suspicious);
            if (mal + med == 0) { if (!Model.S.ScheduleNotifyOnlyIfFound && Tray != null) Tray.Balloon("MineHunter", Loc.L("The scheduled scan is finished: no threats found.", "Плановая проверка завершена: угроз не найдено.")); return; }
            AlertWindow.Show(Model, new GuardAlert { Guard = "scan", Level = mal > 0 ? AlertLevel.Dangerous : AlertLevel.Suspicious, Title = Loc.L("The scheduled scan found something", "Плановая проверка нашла угрозы"), Text = Loc.L("Dangerous: " + mal + ", suspicious: " + med + ". Open MineHunter to see what it is and what to do.", "Опасных: " + mal + ", подозрительных: " + med + ". Откройте MineHunter, чтобы увидеть, что это, и что делать.") });
            Model.Navigate("scan", null);
        }

        static int RunScheduled(Cmd cmd, AppConfig cfg)
        {
            var s = Model.S; var mode = cmd.Scheduled == "full" ? ScanMode.Full : cmd.Scheduled == "custom" ? ScanMode.Custom : ScanMode.Quick;
            Tray = new TrayHost(Model, () => EnsureMain().Go("scan", null));
            Task.Run(() =>
            {
                try
                {
                    // wait for a quiet moment (a full-screen game, work at the keyboard), but not forever
                    var until = DateTime.Now.AddMinutes(30);
                    while (DateTime.Now < until && ((s.GameMode && SystemState.FullScreenAppActive()) || (s.ScheduleOnlyIdle && SystemState.IdleSeconds() < 120))) Thread.Sleep(30000);
                    if (s.GameMode && SystemState.FullScreenAppActive()) { Log.Info("Scheduled scan skipped: a full-screen program stayed on the screen."); App.Dispatcher.BeginInvoke(new Action(() => Shutdown(0))); return; }
                    if (s.ScheduleNotOnBattery && SystemState.OnBattery()) { Log.Info("Scheduled scan skipped: the PC is on battery."); App.Dispatcher.BeginInvoke(new Action(() => Shutdown(0))); return; }
                    App.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        Model.ScanFinishedHook = r => { ReportScheduled(r); var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(75) }; t.Tick += (x, y) => { t.Stop(); Shutdown(0); }; t.Start(); };
                        string err = Model.StartScan(mode, "scheduled", mode == ScanMode.Custom ? s.ScheduleCustomPaths : null);
                        if (err != null) { Log.Warn("Scheduled scan not started: " + err); Shutdown(0); }
                    }));
                }
                catch (Exception ex) { Log.Error("scheduled scan: " + ex); App.Dispatcher.BeginInvoke(new Action(() => Shutdown(1))); }
            });
            return App.Run();
        }

        static void Shutdown(int code) { try { if (Tray != null) Tray.Dispose(); } catch { } App.Shutdown(code); }

        // ============================================================================================ Quick Scan.exe / Full Scan.exe
        public static int RunScanWindow(AppConfig cfg, ScanMode mode, string[] args)
        {
            var cmd = Cmd.Parse(args);
            if (!string.IsNullOrEmpty(cmd.Lang)) Loc.Init(cmd.Lang);
            bool created;
            using (var mutex = new Mutex(true, mode == ScanMode.Full ? @"Local\MineHunter.FullScan.SingleInstance" : @"Local\MineHunter.QuickScan.SingleInstance", out created))
            {
                if (!created) { ActivateRunningInstance(); return 0; }
                App = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
                App.Resources.MergedDictionaries.Add(Ui.Theme);
                App.DispatcherUnhandledException += (s, e) => { Bootstrap.CrashLog("ui", e.Exception); Log.Error("UI error: " + e.Exception); e.Handled = true; };
                Model = new AppModel(cfg, App.Dispatcher);
                ScanWindow w;
                try { w = new ScanWindow(Model, mode, !cmd.NoScan); if (cmd.Shots != null) w.CaptureSequence(cmd.Shots); }
                catch (Exception ex)
                {
                    Bootstrap.CrashLog("window", ex);
                    MessageBox.Show("MineHunter could not open its window:\n" + ex.Message + "\n\nThe command-line mode still works: MineHunter-cli.exe scan --quick", "MineHunter", MessageBoxButton.OK, MessageBoxImage.Error);
                    return 1;
                }
                return App.Run(w.W);
            }
        }

        // ============================================================================================ screenshots (documentation and automated checks)
        static void Shots(MainShell shell, Cmd cmd)
        {
            Directory.CreateDirectory(cmd.Shots);
            var keys = new[] { "home", "scan", "protection", "files", "processes", "startup", "network", "quarantine", "drivers", "health", "schedule", "history", "settings" };
            int i = 0; string lang = Loc.Lang;
            var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(2200) };
            bool prepared = false;
            t.Tick += (s, e) =>
            {
                try
                {
                    if (i >= keys.Length) { t.Stop(); Shutdown(0); return; }
                    if (!prepared)
                    {
                        shell.Go(keys[i], keys[i] == "files" ? (object)(cmd.ShotFile ?? Path.Combine(PathUtil.System32, "notepad.exe")) : null);
                        prepared = true; return;
                    }
                    Capture(shell.W, Path.Combine(cmd.Shots, (i + 1).ToString("00") + "_" + keys[i] + "_" + lang + ".png"));
                    i++; prepared = false;
                }
                catch (Exception ex) { Log.Error("shot: " + ex.Message); i++; prepared = false; }
            };
            t.Start();
        }

        static void ShotOne(MainShell shell, Cmd cmd)
        {
            string page = cmd.Page ?? "home";
            if (page == "alert")
            {
                var sample = new GuardAlert { Guard = "process", Level = AlertLevel.Dangerous, Title = Loc.L("Dangerous program started", "Запущена опасная программа"), Path = Path.Combine(PathUtil.System32, "notepad.exe"), Pid = 4242,
                    Text = Loc.L("Program \"svc_update.exe\" (from Temp): has the file name of a known miner program; carries several markers of a cryptominer; created an autostart task.", "Программа \"svc_update.exe\" (из Temp): носит имя известной программы-майнера; содержит несколько маркеров криптомайнера; создала задачу автозапуска.") };
                sample.Reasons.AddRange(new[] { Loc.L("has the file name of a known miner program", "носит имя известной программы-майнера"), Loc.L("carries several markers of a cryptominer", "содержит несколько маркеров криптомайнера"), Loc.L("created a scheduled task", "создала задачу автозапуска") });
                var aw = new AlertWindow(Model, sample); aw.W.Show();
                var ta = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1800) };
                ta.Tick += (s, e) => { ta.Stop(); try { Capture(aw.W, cmd.Shot); } catch (Exception ex) { Log.Error("shot: " + ex.Message); } Shutdown(0); };
                ta.Start(); return;
            }
            shell.Go(page, page == "files" ? (object)(cmd.ShotFile ?? Path.Combine(PathUtil.System32, "notepad.exe")) : null);
            var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(3500) };
            t.Tick += (s, e) => { t.Stop(); try { Capture(shell.W, cmd.Shot); } catch (Exception ex) { Log.Error("shot: " + ex.Message); } Shutdown(0); };
            t.Start();
        }

        internal static void Capture(Window w, string path)
        {
            w.UpdateLayout();
            var content = (FrameworkElement)VisualTreeHelper.GetChild(w, 0);
            var rtb = new RenderTargetBitmap((int)content.ActualWidth, (int)content.ActualHeight, 96, 96, PixelFormats.Pbgra32); rtb.Render(content);
            var enc = new PngBitmapEncoder(); enc.Frames.Add(BitmapFrame.Create(rtb));
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
            using (var fs = File.Create(path)) enc.Save(fs);
        }
    }
}
