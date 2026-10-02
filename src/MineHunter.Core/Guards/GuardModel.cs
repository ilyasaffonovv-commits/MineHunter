using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MineHunter.Model;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Guards
{
    public enum AlertLevel { Info = 0, Suspicious = 1, Dangerous = 2 }
    public enum GuardState { Off, On, Limited, Error, RestartRequired }

    /// <summary>One thing the real-time layer wants the user to know. The text says what concretely happened, not a score.</summary>
    public sealed class GuardAlert
    {
        public string Id = Guid.NewGuid().ToString("N").Substring(0, 10);
        public DateTime Time = DateTime.Now;
        public string Guard, Title, Text, Path, Sha256, Actor;
        public int Pid;
        public AlertLevel Level;
        public List<string> Reasons = new List<string>();
        public bool Seen;
        public string LevelText { get { return Level == AlertLevel.Dangerous ? Loc.L("Dangerous", "Опасно") : Level == AlertLevel.Suspicious ? Loc.L("Suspicious", "Подозрительно") : Loc.L("For your information", "К сведению"); } }
    }

    public sealed class GuardStatus
    {
        public string Name, Title, Detail; public GuardState State;
        public string StateText
        {
            get
            {
                switch (State)
                {
                    case GuardState.On: return Loc.L("On", "Включено");
                    case GuardState.Off: return Loc.L("Off", "Выключено");
                    case GuardState.Limited: return Loc.L("Limited mode", "Ограниченный режим");
                    case GuardState.RestartRequired: return Loc.L("Restart required", "Требуется перезапуск");
                    default: return Loc.L("Error", "Ошибка");
                }
            }
        }
    }

    public interface IGuard
    {
        string Name { get; }
        string Title { get; }
        GuardStatus Status { get; }
        void Start(GuardContext ctx);
        void Stop();
    }

    /// <summary>What every guard shares: the settings, the rule pack, the allow-list, one place to raise alerts and one correlator.</summary>
    public sealed class GuardContext
    {
        public Settings Settings; public RulePack Rules; public Allowlist Allow;
        public Action<GuardAlert> Raise = a => { };
        public Correlator Correlator = new Correlator();
        public SystemJournal Journal = new SystemJournal();
        public ProcessTable Processes = new ProcessTable();
        public Func<DateTime> Now = () => DateTime.Now;

        public void Alert(GuardAlert a)
        {
            if (a == null) return;
            // the level the user chose is the lowest one that is shown
            int min = Settings.NotifyLevel == "Info" ? 0 : Settings.NotifyLevel == "Dangerous" ? 2 : 1;
            if ((int)a.Level < min) { Log.Info("guard (below the notification level): " + a.Title + " - " + a.Text); return; }
            Raise(a);
        }
    }

    // ------------------------------------------------------------------------------------------------ correlation
    public sealed class Signal
    {
        public string Actor;                 // normalised path of the program the signal is about
        public EvidenceCategory Category;
        public int Weight; public string Rule, Text; public bool Definitive;
        public DateTime Time = DateTime.Now; public int Pid;
    }

    public sealed class Assessment
    {
        public AlertLevel? Level; public int Score, Categories; public bool Definitive; public List<Signal> Signals = new List<Signal>();
        public string Actor;
    }

    /// <summary>One signal is rarely a reason to bother anyone. The correlator collects the signals about the same program over a few minutes and says something only when
    /// independent kinds agree: a program from Temp that also created an autostart task and also connected to a new address is a story; any one of those alone is not.</summary>
    public sealed class Correlator
    {
        readonly Dictionary<string, List<Signal>> byActor = new Dictionary<string, List<Signal>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, AlertLevel> told = new Dictionary<string, AlertLevel>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, DateTime> toldAt = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        public TimeSpan Window = TimeSpan.FromMinutes(15);
        readonly object lk = new object();

        /// <summary>Records the signal; returns an assessment when this changes what the user should be told (a higher level than before), otherwise null.</summary>
        public Assessment Add(Signal s)
        {
            if (s == null || string.IsNullOrEmpty(s.Actor)) return null;
            lock (lk)
            {
                List<Signal> list;
                if (!byActor.TryGetValue(s.Actor, out list)) byActor[s.Actor] = list = new List<Signal>();
                list.RemoveAll(x => s.Time - x.Time > Window);
                if (!list.Any(x => x.Rule == s.Rule && x.Text == s.Text)) list.Add(s);
                if (byActor.Count > 4000) { var old = byActor.Where(kv => kv.Value.Count == 0 || (s.Time - kv.Value.Max(x => x.Time)) > Window).Select(kv => kv.Key).ToList(); foreach (var k in old) byActor.Remove(k); }
                var a = Evaluate(list); a.Actor = s.Actor;
                if (a.Level == null) return null;
                AlertLevel prev; DateTime when;
                if (told.TryGetValue(s.Actor, out prev) && toldAt.TryGetValue(s.Actor, out when) && prev >= a.Level.Value && s.Time - when < TimeSpan.FromMinutes(30)) return null;
                told[s.Actor] = a.Level.Value; toldAt[s.Actor] = s.Time;
                return a;
            }
        }

        public static Assessment Evaluate(IEnumerable<Signal> signals)
        {
            var list = signals.ToList();
            var a = new Assessment { Signals = list };
            double total = 0; int cats = 0;
            foreach (var g in list.Where(x => x.Weight > 0).GroupBy(x => x.Category))
            {
                var ws = g.Select(x => (double)x.Weight).OrderByDescending(x => x).ToList();
                double t = Math.Min(45, ws[0] + 0.5 * ws.Skip(1).Sum());
                double decisive = g.Where(x => x.Definitive).Select(x => (double)x.Weight).DefaultIfEmpty(0).Max();     // a decisive signal (known bad hash, a pool in the command line) is not capped
                if (decisive > t) t = Math.Min(100, decisive);
                total += t; if (t >= 12) cats++;
            }
            a.Score = (int)Math.Round(total); a.Categories = cats; a.Definitive = list.Any(x => x.Definitive);
            if ((a.Definitive && total >= 50) || (cats >= 3 && total >= 70) || (cats >= 2 && total >= 90)) a.Level = AlertLevel.Dangerous;
            else if ((cats >= 2 && total >= 40) || (a.Definitive && total >= 35) || list.Any(x => x.Weight >= 45)) a.Level = AlertLevel.Suspicious;
            else if (total >= 20) a.Level = AlertLevel.Info;
            return a;
        }

        public void Forget(string actor) { lock (lk) { byActor.Remove(actor); told.Remove(actor); toldAt.Remove(actor); } }

        /// <summary>"A program from Temp: did A; did B" - the story in one sentence.</summary>
        public static string Story(string actorPath, IEnumerable<Signal> signals)
        {
            string name = string.IsNullOrEmpty(actorPath) ? "?" : System.IO.Path.GetFileName(actorPath);
            string where = PlaceOf(actorPath);
            var parts = signals.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Select(x => x.Text).Distinct().Take(4).ToList();
            return Loc.L("Program ", "Программа ") + "\"" + name + "\"" + (where != null ? " (" + where + ")" : "") + ": " + string.Join("; ", parts) + ".";
        }

        public static string PlaceOf(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            string p = path.ToLowerInvariant();
            if (p.Contains("\\appdata\\local\\temp\\") || p.Contains("\\windows\\temp\\")) return Loc.L("from Temp", "из Temp");
            if (p.Contains("\\downloads\\")) return Loc.L("from Downloads", "из Загрузок");
            if (p.Contains("\\appdata\\")) return Loc.L("from AppData", "из AppData");
            if (p.Contains("\\programdata\\")) return Loc.L("from ProgramData", "из ProgramData");
            if (p.Contains("\\desktop\\")) return Loc.L("from the Desktop", "с Рабочего стола");
            if (p.StartsWith("\\\\") || p.Contains("\\users\\public\\")) return Loc.L("from a shared place", "из общего места");
            return null;
        }
    }

    // ------------------------------------------------------------------------------------------------ process table
    public sealed class ProcRec
    {
        public int Pid, ParentPid; public string Path, Name, Cmd; public DateTime Started;
        public bool? Trusted;           // cached: valid signature of a trusted publisher
    }

    /// <summary>The programs seen starting recently (the guards use it to say "started 5 seconds before" and to look up a parent).</summary>
    public sealed class ProcessTable
    {
        readonly Dictionary<int, ProcRec> byPid = new Dictionary<int, ProcRec>();
        readonly object lk = new object();

        public void Add(ProcRec p) { lock (lk) { byPid[p.Pid] = p; if (byPid.Count > 6000) foreach (var k in byPid.Where(kv => DateTime.Now - kv.Value.Started > TimeSpan.FromMinutes(30)).Select(kv => kv.Key).ToList()) byPid.Remove(k); } }
        public ProcRec Get(int pid) { lock (lk) { ProcRec p; return byPid.TryGetValue(pid, out p) ? p : null; } }
        public List<ProcRec> StartedWithin(TimeSpan span, DateTime now) { lock (lk) return byPid.Values.Where(p => now - p.Started <= span && now >= p.Started).ToList(); }
        public ProcRec ByPath(string path) { lock (lk) return byPid.Values.Where(p => string.Equals(p.Path, path, StringComparison.OrdinalIgnoreCase)).OrderByDescending(p => p.Started).FirstOrDefault(); }
    }

    // ------------------------------------------------------------------------------------------------ journal of system changes
    public sealed class JournalEntry
    {
        public DateTime Time; public string Kind, Text, Path, Actor;
    }

    /// <summary>"14:32 SomeSetup.exe added the service XYZ": what changed on the PC, in plain words, and by whom when that is known.</summary>
    public sealed class SystemJournal
    {
        public static string FilePath { get { return System.IO.Path.Combine(RulePack.DataDir, "journal.json"); } }
        readonly object lk = new object();
        public string FileOverride;
        string File_ { get { return FileOverride ?? FilePath; } }

        public void Add(string kind, string text, string path = null, string actor = null)
        {
            lock (lk)
            {
                var all = List();
                all.Insert(0, new JournalEntry { Time = DateTime.Now, Kind = kind, Text = text, Path = path, Actor = actor });
                Save(all.Take(2000).ToList());
            }
        }

        public List<JournalEntry> List()
        {
            var list = new List<JournalEntry>();
            try
            {
                if (!System.IO.File.Exists(File_)) return list;
                var d = Json.Obj(Json.Parse(System.IO.File.ReadAllText(File_)));
                foreach (var o in Json.Arr(d != null && d.ContainsKey("entries") ? d["entries"] : null) ?? new object[0])
                {
                    var x = Json.Obj(o); if (x == null) continue;
                    DateTime t; DateTime.TryParse(Json.Str(x, "time"), null, System.Globalization.DateTimeStyles.RoundtripKind, out t);
                    list.Add(new JournalEntry { Time = t, Kind = Json.Str(x, "kind"), Text = Json.Str(x, "text"), Path = Json.Str(x, "path"), Actor = Json.Str(x, "actor") });
                }
            }
            catch { }
            return list;
        }

        void Save(List<JournalEntry> list)
        {
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(File_));
                var arr = list.Select(e => (object)new Dictionary<string, object> { { "time", e.Time.ToString("o") }, { "kind", e.Kind }, { "text", e.Text }, { "path", e.Path }, { "actor", e.Actor } }).ToArray();
                Fs.WriteDurable(File_, new System.Text.UTF8Encoding(false).GetBytes(Json.Pretty(Json.Serialize(new Dictionary<string, object> { { "entries", arr } }))));
            }
            catch (Exception ex) { Log.Warn("journal: " + ex.Message); }
        }

        public void Clear() { lock (lk) Save(new List<JournalEntry>()); }
    }
}
