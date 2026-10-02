using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Remediation;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Guards
{
    /// <summary>Owns the real-time components of the tray program: starts and stops each one according to the settings, keeps the list of recent alerts, and holds the actions the user
    /// can take on an alert (look at the file, quarantine it, allow it, freeze or stop the program).</summary>
    public sealed class GuardHost
    {
        public readonly GuardContext Ctx;
        readonly List<IGuard> guards = new List<IGuard>();
        readonly List<GuardAlert> recent = new List<GuardAlert>();
        public event Action<GuardAlert> AlertRaised;
        public event Action StatusChanged;
        readonly object lk = new object();
        FileGuard fileGuard, downloadGuard; ScriptGuard scriptGuard;

        public GuardHost(Settings s)
        {
            Ctx = new GuardContext { Settings = s, Rules = RulePack.Load(), Allow = Allowlist.Load() };
            foreach (var p in s.ExcludedPublishers) Ctx.Rules.UserTrustedPublishers.Add(p);
            Ctx.Raise = OnAlert;
        }

        public static string AlertsFile { get { return Path.Combine(RulePack.DataDir, "alerts.json"); } }

        public List<GuardAlert> Recent { get { lock (lk) return recent.ToList(); } }

        /// <summary>Starts the components that are switched on in the settings and stops the others.</summary>
        public void Apply()
        {
            var s = Ctx.Settings;
            Stop();
            Ctx.Rules = RulePack.Load(); foreach (var p in s.ExcludedPublishers) Ctx.Rules.UserTrustedPublishers.Add(p);
            Ctx.Allow = Allowlist.Load();
            Func<bool, IGuard, IGuard> on = (enabled, gd) => { if (enabled) { try { gd.Start(Ctx); } catch (Exception ex) { Log.Warn("guard " + gd.Name + ": " + ex.Message); } } guards.Add(gd); return gd; };
            on(s.FileGuard, fileGuard = new FileGuard(false));
            on(s.DownloadGuard, downloadGuard = new FileGuard(true));
            on(s.ProcessGuard, new ProcessGuard());
            on(s.ScriptGuard, scriptGuard = new ScriptGuard());
            on(s.PersistenceGuard, new PersistenceGuard());
            on(s.NetworkGuard, new NetworkGuard());
            on(s.UsbGuard, new UsbGuard());
            on(s.RansomwareGuard, new RansomwareGuard());
            var h = StatusChanged; if (h != null) h();
        }

        public void Stop()
        {
            foreach (var g in guards) { try { g.Stop(); } catch { } }
            guards.Clear();
            if (!Ctx.Settings.RansomwareGuard) RansomwareGuard.RemoveCanaries(RansomwareGuard.ProtectedFolders());
        }

        public List<GuardStatus> Statuses()
        {
            var l = new List<GuardStatus>();
            var s = Ctx.Settings;
            Func<string, bool> enabled = n => n == "file" ? s.FileGuard : n == "download" ? s.DownloadGuard : n == "process" ? s.ProcessGuard : n == "script" ? s.ScriptGuard : n == "persistence" ? s.PersistenceGuard : n == "network" ? s.NetworkGuard : n == "usb" ? s.UsbGuard : s.RansomwareGuard;
            foreach (var g in guards)
            {
                var st = g.Status;
                if (!enabled(g.Name)) st = new GuardStatus { Name = g.Name, Title = g.Title, State = GuardState.Off, Detail = Loc.L("switched off in the settings", "выключено в настройках") };
                l.Add(st);
            }
            return l;
        }

        // ------------------------------------------------------------------------------------------------ alerts
        void OnAlert(GuardAlert a)
        {
            // a full-screen game or presentation: only a dangerous alert is shown now; everything else waits in the list
            bool quiet = Ctx.Settings.GameMode && SystemState.FullScreenAppActive() && a.Level < AlertLevel.Dangerous;
            lock (lk) { recent.Insert(0, a); if (recent.Count > 200) recent.RemoveRange(200, recent.Count - 200); }
            Persist();
            Log.Info("[guard:" + a.Guard + "] " + a.Level + " - " + a.Title + ": " + a.Text);
            if (quiet) return;
            var h = AlertRaised; if (h != null) { try { h(a); } catch { } }
        }

        void Persist()
        {
            try
            {
                var arr = Recent.Take(100).Select(a => (object)new Dictionary<string, object> { { "id", a.Id }, { "time", a.Time.ToString("o") }, { "guard", a.Guard }, { "level", a.Level.ToString() }, { "title", a.Title }, { "text", a.Text }, { "path", a.Path }, { "sha256", a.Sha256 }, { "pid", a.Pid }, { "reasons", a.Reasons.ToArray() } }).ToArray();
                Directory.CreateDirectory(RulePack.DataDir);
                Fs.WriteDurable(AlertsFile, new System.Text.UTF8Encoding(false).GetBytes(Json.Pretty(Json.Serialize(new Dictionary<string, object> { { "alerts", arr } }))));
            }
            catch { }
        }

        public static List<GuardAlert> LoadAlerts()
        {
            var l = new List<GuardAlert>();
            try
            {
                if (!File.Exists(AlertsFile)) return l;
                var d = Json.Obj(Json.Parse(File.ReadAllText(AlertsFile)));
                foreach (var o in Json.Arr(d["alerts"]) ?? new object[0])
                {
                    var x = Json.Obj(o); if (x == null) continue;
                    DateTime t; DateTime.TryParse(Json.Str(x, "time"), null, System.Globalization.DateTimeStyles.RoundtripKind, out t);
                    AlertLevel lv; Enum.TryParse(Json.Str(x, "level"), out lv);
                    l.Add(new GuardAlert { Id = Json.Str(x, "id"), Time = t, Guard = Json.Str(x, "guard"), Level = lv, Title = Json.Str(x, "title"), Text = Json.Str(x, "text"), Path = Json.Str(x, "path"), Sha256 = Json.Str(x, "sha256"), Pid = Json.Int(x, "pid"), Reasons = Json.Strs(x, "reasons"), Seen = true });
                }
            }
            catch { }
            return l;
        }

        // ------------------------------------------------------------------------------------------------ what the user can do about an alert
        /// <summary>Moves the file into the quarantine (reversible) after stopping a program that runs from it. Returns null on success.</summary>
        public static string QuarantineFile(string path, string reason, int pid = 0)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return Loc.L("the file is gone", "файла уже нет");
                var ctx = new ScanContext(RulePack.Load(), Allowlist.Load(), new ScanOptions { Mode = ScanMode.Custom, UseCache = false, IncludeSelf = true }, CancellationToken.None);
                var e = ctx.Files.Inspect(path, FileRole.HotDir);
                if (e == null) return Loc.L("the file could not be read", "файл не удалось прочитать");
                var f = new Finding { Id = "G1", Title = Path.GetFileName(path), Verdict = Verdict.Suspicious, Entities = new List<Entity> { e } };
                var steps = new List<RemediationStep>();
                if (pid > 0) steps.Add(new RemediationStep { Type = ActionType.KillProcess, EntityId = e.Id, Target = pid.ToString(), Description = "Stop the program", Order = 1 });
                steps.Add(new RemediationStep { Type = ActionType.QuarantineFile, EntityId = e.Id, Target = path, Description = "Move the file to quarantine", Order = 2 });
                using (var lk = RemediationEngine.CleanupLock())
                {
                    if (lk == null) return Loc.L("another cleanup is running", "сейчас идёт другая очистка");
                    var oc = RemediationEngine.Execute(ctx, f, steps, null);
                    var bad = oc.Results.FirstOrDefault(r => !r.Success && r.Step.Type == ActionType.QuarantineFile);
                    return bad == null ? null : bad.Message;
                }
            }
            catch (Exception ex) { return ex.Message; }
        }

        /// <summary>"This one is fine": the file as it is now (its SHA-256) is not reported again.</summary>
        public static string Allow(string path)
        {
            try
            {
                var al = Allowlist.Load();
                if (al.Approve(path) == null) return Loc.L("the file could not be read, nothing was approved", "файл не удалось прочитать, ничего не одобрено");
                al.Save(); return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static bool Freeze(int pid) { return pid > 4 && SystemOps.Suspend(pid); }
        public static bool Unfreeze(int pid) { return pid > 4 && SystemOps.Resume(pid); }

        public static string Terminate(int pid)
        {
            try { if (pid <= 4) return "not allowed"; using (var p = System.Diagnostics.Process.GetProcessById(pid)) { p.Kill(); return null; } }
            catch (Exception ex) { return ex.Message; }
        }
    }
}
