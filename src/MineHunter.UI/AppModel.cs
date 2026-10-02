using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Gui
{
    public interface IPage
    {
        string Key { get; }
        string Title { get; }
        string Icon { get; }
        FrameworkElement View { get; }
        /// <summary>Called every time the page is shown (refresh what may have changed).</summary>
        void OnShow(object arg);
    }

    /// <summary>What the windows of one MineHunter program share: the settings, the one scan controller, the last result, the real-time layer, update state.</summary>
    public sealed class AppModel
    {
        public static AppModel I;

        public readonly AppConfig Cfg;
        public readonly ScanController Scanner = new ScanController();
        public GuardHost Guards;
        public ScanResult LastResult; public string LastReportTxt, LastReportHtml; public ScanOptions LastOptions;
        public AppUpdateStatus AppUpdate; public UpdateInfo RulesInfo;
        public UpdateResult LastUpdateResult;
        public string RulesVersion = "?";
        public readonly Dispatcher UiThread;
        public event Action StateChanged;
        public Action<string, object> Navigate = (p, a) => { };
        public Func<Window> OwnerWindow = () => null;
        public bool InTray;

        public Settings S { get { return Settings.Current; } }

        public AppModel(AppConfig cfg, Dispatcher d)
        {
            Cfg = cfg; UiThread = d; I = this;
            try { RulesVersion = RulePack.Load().Version; } catch { }
            LastResult = ResultSnapshot.Load();
            try { var last = History.List().FirstOrDefault(); if (last != null) LastReportTxt = last.ReportTxt; } catch { }
            Scanner.Finished += run => UiThread.BeginInvoke(new Action(() => OnScanFinished(run)));
        }

        public void Raise() { var h = StateChanged; if (h != null) { if (UiThread.CheckAccess()) h(); else UiThread.BeginInvoke(h); } }

        // ------------------------------------------------------------------------------------------------ scanning
        public ScanRun LastRun;
        public Action<ScanRun> ScanFinishedHook = r => { };

        /// <summary>Starts a scan (any kind, from anywhere in this program). Returns an error text, or null when it started.</summary>
        public string StartScan(ScanMode mode, string trigger, IEnumerable<string> paths = null)
        {
            if (!Scanner.Start(mode, trigger, Cfg, S, paths)) return Scanner.Error;
            Log.Info("Scan started: " + mode + " (" + trigger + ")");
            Raise();
            return null;
        }

        void OnScanFinished(ScanRun run)
        {
            if (run != null && run.Result != null)
            {
                LastRun = run; LastOptions = run.Options;
                if (!run.Result.Aborted) { LastResult = run.Result; LastReportTxt = run.ReportTxt; LastReportHtml = run.ReportHtml; }
                var r = run.Result;
                Log.Info("Scan finished in " + r.Stats.Seconds + " s: critical " + r.Findings.Count(f => f.Verdict == Verdict.Malware) + ", high " + r.Findings.Count(f => f.Verdict == Verdict.HighRisk) + ", medium " + r.Findings.Count(f => f.Verdict == Verdict.Suspicious) + ", notes " + r.Observations.Count);
            }
            Raise();
            try { ScanFinishedHook(run); } catch (Exception ex) { Log.Warn("scan hook: " + ex.Message); }
        }

        // ------------------------------------------------------------------------------------------------ protection
        public void StartGuards()
        {
            try
            {
                if (Guards == null) { Guards = new GuardHost(S); Guards.StatusChanged += () => Raise(); }
                Task.Run(() => { try { Guards.Apply(); } catch (Exception ex) { Log.Warn("guards: " + ex.Message); } UiThread.BeginInvoke(new Action(Raise)); });
            }
            catch (Exception ex) { Log.Warn("guards: " + ex.Message); }
        }

        public void StopGuards() { try { if (Guards != null) Guards.Stop(); } catch { } }

        public int GuardsOn { get { return Guards == null ? 0 : Guards.Statuses().Count(x => x.State == GuardState.On || x.State == GuardState.Limited); } }

        // ------------------------------------------------------------------------------------------------ updates
        public bool CheckingUpdates;

        /// <summary>Checks the rules and the program version; installs newer verified rules by itself and downloads (not installs) a newer program version when auto-update is on.</summary>
        public void CheckUpdates(bool userAsked, Action done = null)
        {
            if (CheckingUpdates) return;
            CheckingUpdates = true; Raise();
            Task.Run(() =>
            {
                UpdateInfo ri = null; AppUpdateStatus st = null;
                try
                {
                    var rules = RulePack.Load();
                    ri = Updater.Check(Cfg, rules.Version);
                    if (ri.RulesNewer && Cfg.AutoUpdateRules && !string.IsNullOrEmpty(ri.RulesUrl))
                    {
                        string err = Updater.UpdateRules(Cfg, ri);
                        if (err == null) { ri.LocalRulesVersion = ri.RulesVersion; ri.RulesNewer = false; Log.Info("Rules updated to " + ri.RulesVersion); try { RulesVersion = RulePack.Load().Version; } catch { } }
                        else Log.Warn("Rules not updated: " + err);
                    }
                    st = AppUpdater.Check(Cfg, S);
                    if (st.State == AppUpdateState.Available && S.AutoUpdateApp)
                    {
                        string staged; string err = AppUpdater.Download(st.Release, Cfg, null, CancellationToken.None, out staged);
                        if (err == null) { st.State = AppUpdateState.Ready; st.StagedDir = staged; st.StagedVersion = st.Release.Version; st.Message = "Version " + st.Release.Version + " is downloaded and verified."; }
                        else { Log.Warn("Update not downloaded: " + err); st.Message = err; }
                    }
                    S.LastUpdateCheck = DateTime.Now.ToString("o"); S.Save();
                }
                catch (Exception ex) { Log.Warn("update check: " + ex.Message); }
                UiThread.BeginInvoke(new Action(() => { CheckingUpdates = false; if (ri != null) RulesInfo = ri; if (st != null) AppUpdate = st; Raise(); if (done != null) done(); }));
            });
        }

        /// <summary>Hands over to the helper that installs the downloaded version. The program closes, the helper replaces the files and starts it again.</summary>
        public string InstallUpdate()
        {
            if (AppUpdate == null || AppUpdate.State != AppUpdateState.Ready) return "no verified update is waiting";
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MineHunter.exe");
            string err = AppUpdater.StartInstall(AppUpdate.StagedDir, AppUpdate.StagedVersion, AppDomain.CurrentDomain.BaseDirectory, File.Exists(exe) ? exe : null, true);
            if (err == null) { StopGuards(); try { ScanEngine.ReleaseLock(); } catch { } UiThread.BeginInvoke(new Action(() => Application.Current.Shutdown())); }
            return err;
        }

        // ------------------------------------------------------------------------------------------------ Windows health (read in the background, cached for a few minutes)
        public List<HealthItem> HealthCache; public DateTime HealthStamp; public bool HealthLoading;

        public void RefreshHealth(bool force, Action done = null)
        {
            if (HealthLoading) return;
            if (!force && HealthCache != null && (DateTime.Now - HealthStamp).TotalMinutes < 5) { if (done != null) done(); return; }
            HealthLoading = true; Raise();
            Task.Run(() =>
            {
                List<HealthItem> items = null;
                try { items = WindowsHealth.Run(); } catch (Exception ex) { Log.Warn("health: " + ex.Message); }
                UiThread.BeginInvoke(new Action(() => { HealthLoading = false; if (items != null) { HealthCache = items; HealthStamp = DateTime.Now; } Raise(); if (done != null) done(); }));
            });
        }

        // ------------------------------------------------------------------------------------------------ small things
        public string LastScanText(string mode)
        {
            var h = History.Last(mode);
            if (h == null) return Loc.L("never", "ещё не было");
            var t = h.StartedTime;
            string when = t.Date == DateTime.Today ? Loc.L("today ", "сегодня ") + t.ToString("HH:mm") : t.Date == DateTime.Today.AddDays(-1) ? Loc.L("yesterday ", "вчера ") + t.ToString("HH:mm") : t.ToString("dd.MM.yyyy HH:mm");
            return when;
        }

        public static void Open(string p)
        {
            if (string.IsNullOrEmpty(p)) return;
            try
            {
                if (p.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || p.StartsWith("ms-settings:", StringComparison.OrdinalIgnoreCase) || p.StartsWith("windowsdefender:", StringComparison.OrdinalIgnoreCase)) { Process.Start(new ProcessStartInfo(p) { UseShellExecute = true }); return; }
                if (File.Exists(p) || Directory.Exists(p)) Process.Start(new ProcessStartInfo(p) { UseShellExecute = true });
            }
            catch (Exception ex) { Log.Warn("open " + p + ": " + ex.Message); }
        }
    }
}
