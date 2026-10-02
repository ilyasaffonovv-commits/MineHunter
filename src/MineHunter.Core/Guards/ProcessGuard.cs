using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Guards
{
    public sealed class ProcStart { public int Pid, ParentPid; public string Name; public DateTime Time = DateTime.Now; }

    public interface IProcessSource : IDisposable
    {
        event Action<ProcStart> Started;
        string Mode { get; }
        void Start();
    }

    /// <summary>Windows tells us about every new process (Win32_ProcessStartTrace). Needs administrator rights.</summary>
    public sealed class WmiProcessSource : IProcessSource
    {
        ManagementEventWatcher w;
        public event Action<ProcStart> Started;
        public string Mode { get { return "WMI process events"; } }
        public void Start()
        {
            w = new ManagementEventWatcher(new WqlEventQuery("Win32_ProcessStartTrace"));
            w.EventArrived += (s, e) =>
            {
                try
                {
                    var h = Started; if (h == null) return;
                    h(new ProcStart { Pid = Convert.ToInt32(e.NewEvent["ProcessID"]), ParentPid = Convert.ToInt32(e.NewEvent["ParentProcessID"]), Name = Convert.ToString(e.NewEvent["ProcessName"]) });
                }
                catch { }
            };
            w.Start();
        }
        public void Dispose() { try { if (w != null) { w.Stop(); w.Dispose(); } } catch { } }
    }

    /// <summary>Fallback without WMI events: looks at the process list a couple of times a second. It can miss a program that lives for less than that.</summary>
    public sealed class PollingProcessSource : IProcessSource
    {
        Timer t; readonly HashSet<int> known = new HashSet<int>();
        public event Action<ProcStart> Started;
        public string Mode { get { return "process list polling"; } }
        public void Start()
        {
            foreach (var p in Process.GetProcesses()) using (p) known.Add(p.Id);
            t = new Timer(_ => Tick(), null, 600, 600);
        }
        void Tick()
        {
            try
            {
                var now = new HashSet<int>();
                foreach (var p in Process.GetProcesses())
                    using (p)
                    {
                        now.Add(p.Id);
                        if (known.Add(p.Id)) { var h = Started; if (h != null) h(new ProcStart { Pid = p.Id, Name = p.ProcessName + ".exe", ParentPid = SystemOps.ParentPid(p.Id) }); }
                    }
                known.IntersectWith(now);
            }
            catch { }
        }
        public void Dispose() { if (t != null) t.Dispose(); }
    }

    /// <summary>Process Guard: looks at every new program as it starts, with its parent chain and its command line. One odd thing is not enough: the signals about the same program
    /// are gathered by the correlator, and the user is told only when independent kinds agree.
    /// This is monitoring, not blocking: the program is already running when MineHunter hears about it.</summary>
    public sealed class ProcessGuard : IGuard
    {
        GuardContext g; IProcessSource src; GuardState state = GuardState.Off; string detail = "";
        LightCheck light; ScriptGuard scripts;
        public Func<IProcessSource> SourceFactory = () => new WmiProcessSource();
        /// <summary>What the last judgement was based on (for the log and the tests).</summary>
        public string LastDecision = "";

        public string Name { get { return "process"; } }
        public string Title { get { return Loc.L("Process Guard", "Контроль процессов"); } }
        public GuardStatus Status { get { return new GuardStatus { Name = Name, Title = Title, State = state, Detail = detail }; } }

        static readonly HashSet<string> Office = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "visio", "acrord32", "acrobat", "foxitreader", "foxitpdfreader", "sumatrapdf", "wordpad" };
        static readonly HashSet<string> Browsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "browser", "yandex", "iexplore" };
        static readonly HashSet<string> Archivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "7zfm", "7zg", "winrar", "winzip", "peazip", "bandizip", "7-zip", "winrar.exe" };
        static readonly HashSet<string> ScriptHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "wmic", "msiexec", "certutil", "bitsadmin", "installutil", "regasm", "regsvcs", "msbuild" };
        static readonly HashSet<string> SystemNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "svchost", "lsass", "csrss", "winlogon", "services", "smss", "wininit", "taskhostw", "dwm", "spoolsv", "lsm", "fontdrvhost", "searchindexer", "audiodg", "sihost", "ctfmon", "runtimebroker", "conhost" };

        public void Start(GuardContext ctx)
        {
            g = ctx; light = new LightCheck(g); scripts = new ScriptGuard(); scripts.Start(g);
            try { src = SourceFactory(); src.Started += OnStart; src.Start(); state = GuardState.On; detail = Loc.L("watching every new program (" + src.Mode + ")", "следит за каждой новой программой (" + src.Mode + ")"); }
            catch (Exception ex)
            {
                try { src = new PollingProcessSource(); src.Started += OnStart; src.Start(); state = GuardState.Limited; detail = Loc.L("limited: process events are not available (" + ex.Message + "), checking the process list instead", "ограничен: события процессов недоступны (" + ex.Message + "), проверяется список процессов"); }
                catch (Exception ex2) { state = GuardState.Error; detail = ex2.Message; }
            }
        }

        public void Stop() { state = GuardState.Off; try { if (src != null) src.Dispose(); } catch { } src = null; }

        void OnStart(ProcStart s)
        {
            // the work happens on a thread of its own: the event source must not wait
            ThreadPool.QueueUserWorkItem(_ => { try { Handle(Describe(s)); } catch (Exception ex) { Log.Warn("process guard: " + ex.Message); } });
        }

        /// <summary>Fills in the path and command line of a program that has just started.</summary>
        ProcRec Describe(ProcStart s)
        {
            var p = new ProcRec { Pid = s.Pid, ParentPid = s.ParentPid, Name = Path.GetFileNameWithoutExtension(s.Name ?? ""), Started = s.Time };
            try
            {
                using (var q = new ManagementObjectSearcher("SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = " + s.Pid))
                    foreach (ManagementObject o in q.Get()) { p.Path = Convert.ToString(o["ExecutablePath"]); p.Cmd = Convert.ToString(o["CommandLine"]); }
            }
            catch { }
            if (string.IsNullOrEmpty(p.Path)) { try { using (var pr = Process.GetProcessById(s.Pid)) p.Path = pr.MainModule.FileName; } catch { } }
            if (!string.IsNullOrEmpty(p.Path)) p.Name = Path.GetFileNameWithoutExtension(p.Path);
            return p;
        }

        bool IsTrusted(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            try
            {
                if (g.Allow != null) { string h = Hashing.Sha256(path); if (h != null && g.Allow.Sha256.Contains(h)) return true; }
                if (g.Settings != null && g.Settings.IsExcludedPath(path)) return true;
                var ti = Trust.Check(path);
                if (ti == null || !ti.IsValid) return false;
                if (ti.State == TrustState.ValidCatalog && PathUtil.Classify(path) == PathClass.WindowsSystem) return true;
                return g.Rules.IsTrustedPublisher(ti.Publisher) || (ti.Publisher ?? "").StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>The whole judgement for one new program. Public so tests can feed it a synthetic start.</summary>
        public void Handle(ProcRec p)
        {
            if (p == null || string.IsNullOrEmpty(p.Path)) { if (p != null) g.Processes.Add(p); return; }
            g.Processes.Add(p);
            var parent = g.Processes.Get(p.ParentPid);
            if (parent == null && p.ParentPid > 0)
            {
                try { using (var pp = Process.GetProcessById(p.ParentPid)) parent = new ProcRec { Pid = p.ParentPid, Name = pp.ProcessName, Path = SafeMain(pp), Started = DateTime.Now }; } catch { }
                if (parent != null) g.Processes.Add(parent);
            }
            bool selfProc = string.Equals(Path.GetDirectoryName(p.Path), AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
            if (selfProc) return;

            bool trusted = p.Trusted ?? (p.Trusted = IsTrusted(p.Path)).Value;
            // the program that is responsible: the first untrusted one up the chain (a script host is Microsoft's, but what it was told to run is somebody's)
            ProcRec actor = trusted ? null : p;
            ProcRec cur = parent; int depth = 0;
            while (actor == null && cur != null && depth++ < 4)
            {
                bool ct = cur.Trusted ?? (cur.Trusted = IsTrusted(cur.Path)).Value;
                if (!ct && !string.IsNullOrEmpty(cur.Path)) actor = cur;
                cur = g.Processes.Get(cur.ParentPid);
            }
            string pn = p.Name ?? "", parentName = parent != null ? parent.Name ?? "" : "";
            var signals = new List<Signal>();
            Action<EvidenceCategory, int, string, string, bool> add = (cat, w, rule, text, def) =>
                signals.Add(new Signal { Actor = PathUtil.Normalize((actor ?? p).Path), Category = cat, Weight = w, Rule = rule, Text = text, Definitive = def, Pid = (actor ?? p).Pid, Time = p.Started });

            // ---- parent chains. A document or a browser starting a shell is odd whoever signed them: the macro that does it runs inside a trusted program.
            bool anomalous = parent != null && ScriptHosts.Contains(pn) && (Office.Contains(parentName) || (Browsers.Contains(parentName) && pn != "rundll32" && pn != "msiexec"));
            if (parent != null && Office.Contains(parentName) && ScriptHosts.Contains(pn)) add(EvidenceCategory.Behavior, 40, "PROC.CHAIN.OFFICE_SHELL", Loc.L("started a command shell from \"" + parentName + "\" (documents do not normally do that)", "запустила командную оболочку из «" + parentName + "» (документы обычно так не делают)"), false);
            else if (parent != null && Browsers.Contains(parentName) && ScriptHosts.Contains(pn) && pn != "rundll32" && pn != "msiexec") add(EvidenceCategory.Behavior, 22, "PROC.CHAIN.BROWSER_SHELL", Loc.L("a browser started \"" + pn + "\"", "браузер запустил «" + pn + "»"), false);
            if (parent != null && Archivers.Contains(parentName) && !trusted && IsTempLike(p.Path)) add(EvidenceCategory.Behavior, 28, "PROC.CHAIN.ARCHIVE_TEMP", Loc.L("was started straight out of an archive (\"" + parentName + "\")", "запущена прямо из архива («" + parentName + "»)"), false);

            if (!trusted)
            {
                // ---- what the program is
                var lr = light.Check(p.Path);
                if (lr != null && !lr.MissingOrUnreadable && !lr.Trusted)
                {
                    foreach (var s in lr.Signals) signals.Add(new Signal { Actor = PathUtil.Normalize(p.Path), Category = s.Category, Weight = s.Weight, Rule = s.Rule, Text = s.Text, Definitive = s.Definitive, Pid = p.Pid, Time = p.Started });
                    if (lr.Tool) signals.RemoveAll(x => !x.Rule.StartsWith("PROC.CMD.MINER") && !x.Rule.StartsWith("NET."));      // a game cheat is not a miner
                }
                if (SystemNames.Contains(pn) && PathUtil.Classify(p.Path) != PathClass.WindowsSystem && PathUtil.Classify(p.Path) != PathClass.WindowsOther) add(EvidenceCategory.Masquerade, 55, "PROC.MASQ.SYSTEM_NAME", Loc.L("carries the name of a Windows program but lives in the wrong place", "носит имя программы Windows, но лежит не там, где положено"), false);
                if (g.Rules.MinerFileNames.Contains(pn + ".exe") || g.Rules.MinerFileNames.Contains(pn)) add(EvidenceCategory.Content, 40, "PROC.NAME.MINER", Loc.L("has the file name of a known miner program", "носит имя известной программы-майнера"), false);
                if (PathUtil.IsUserWritable(p.Path)) add(EvidenceCategory.Location, 8, "PROC.USERPATH", Loc.L("runs from a folder any program can write to", "запущена из папки, куда может писать любая программа"), false);
            }

            // ---- command line (the rule pack's rules: miners, Defender tampering, LOLBin download, persistence by command ...)
            if (!string.IsNullOrEmpty(p.Cmd))
            {
                foreach (var r in g.Rules.CmdRules)
                {
                    if (!r.Rx.IsMatch(p.Cmd)) continue;
                    // with a trusted chain only the miner rules count; a person typing into a trusted shell is not an alert
                    if (actor == null && !anomalous && !r.Id.StartsWith("CMD.MINER")) continue;
                    var cat = Scanning.FileIntel.ParseCat(r.Category);
                    signals.Add(new Signal { Actor = PathUtil.Normalize((actor ?? p).Path), Category = cat, Weight = r.Weight, Rule = "PROC." + r.Id, Text = r.Text, Definitive = r.Definitive, Pid = (actor ?? p).Pid, Time = p.Started });
                }
                if (ScriptHosts.Contains(pn))
                {
                    string sp = ScriptAnalyzer.ScriptPathOf(p.Cmd);
                    if (sp != null)
                    {
                        var sr = scripts.Check(sp, PathUtil.Normalize((actor ?? p).Path));
                        foreach (var s in sr.Signals) if (actor != null || anomalous || s.Definitive) { s.Pid = (actor ?? p).Pid; signals.Add(s); }
                    }
                }
            }
            LastDecision = "program=" + p.Path + " trusted=" + trusted + " actor=" + (actor == null ? "none (whole chain trusted)" : actor.Path) + " signals=" + string.Join(",", signals.Select(x => x.Rule + ":" + x.Weight));
            if (signals.Count == 0) return;

            // ---- the correlator decides whether this is worth the user's attention
            Assessment last = null;
            foreach (var s in signals) { var a = g.Correlator.Add(s); if (a != null) last = a; }
            if (last == null) return;
            Raise(last, (actor ?? p), p);
        }

        void Raise(Assessment a, ProcRec actor, ProcRec trigger)
        {
            string story = Correlator.Story(actor.Path, a.Signals);
            var alert = new GuardAlert
            {
                Guard = Name, Level = a.Level.Value, Path = actor.Path, Pid = actor.Pid, Actor = actor.Path,
                Title = a.Level == AlertLevel.Dangerous ? Loc.L("Dangerous program started", "Запущена опасная программа") : a.Level == AlertLevel.Suspicious ? Loc.L("Suspicious program started", "Запущена подозрительная программа") : Loc.L("A program worth a look", "Программа, на которую стоит взглянуть"),
                Text = story + " " + Loc.L("MineHunter watches and reports; it does not block programs before they start.", "MineHunter наблюдает и сообщает; он не блокирует программы до запуска.")
            };
            alert.Reasons = a.Signals.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Select(x => x.Text).Distinct().ToList();
            try { alert.Sha256 = Hashing.Sha256(actor.Path); } catch { }
            g.Alert(alert);
        }

        static bool IsTempLike(string path)
        {
            string p = (path ?? "").ToLowerInvariant();
            return p.Contains("\\temp\\") || p.Contains("\\rar$") || p.Contains("\\7z") || p.Contains("\\appdata\\local\\temp");
        }

        static string SafeMain(Process p) { try { return p.MainModule.FileName; } catch { return null; } }
    }
}
