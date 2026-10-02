using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using MineHunter.Model;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    public enum ScanMode { Quick, Full, Custom }

    public sealed class ScanOptions
    {
        public ScanMode Mode = ScanMode.Quick;
        public string CustomPath;
        public int CpuSampleMs = 3000;          // process CPU/GPU sampling window
        public bool MemoryInspection = true;    // hollowing / unbacked executable memory checks
        public bool Browsers = true;
        public bool ScanHotDirs = true;
        public int MaxFileSizeMbForContentScan = 512;
        public long StringScanHeadBytes = 8L * 1024 * 1024;
        public long StringScanTailBytes = 1L * 1024 * 1024;
        public bool UseCache = true;
        public int Parallelism = Math.Max(2, Math.Min(8, Environment.ProcessorCount - 1));
        public int MaxFullScanMinutes = 45;     // hard budget: the full scan stops early rather than taking hours
        public bool IncludeSelf = false;
        public bool OtherUserHives = true;      // also read the registry of users who are not signed in (their NTUSER.DAT is mounted for a moment)
        public List<string> CustomPaths = new List<string>();   // Custom mode: every chosen folder / drive (CustomPath is the first one)
        public int Sensitivity = 0;             // 0 Normal, 1 Strict, 2 Paranoid: how many independent signals are needed before something is reported
        public bool DeveloperContext = false;   // build output, virtual environments and package folders do not raise "unsigned program in a user folder" notes
        public int CpuLimit = 0;                // 0 = automatic, else the share of the CPU (percent) the scan may use
        public bool ScanArchives = true;
        public bool IncludeRemovable = false;   // Full: also USB drives and memory cards
        public bool IncludeNetwork = false;     // Full: also mapped network drives
        public ScanProgress Live;               // optional: the window reads this while the scan runs
        public Settings UserSettings;           // exclusions come from here (null = none)

        public IEnumerable<string> AllCustomPaths()
        {
            var l = new List<string>();
            if (!string.IsNullOrEmpty(CustomPath)) l.Add(CustomPath);
            if (CustomPaths != null) foreach (var p in CustomPaths) if (!string.IsNullOrWhiteSpace(p) && !l.Contains(p, StringComparer.OrdinalIgnoreCase)) l.Add(p);
            return l;
        }
    }

    /// <summary>What a running scan is doing right now, readable from another thread (the Quick Scan / Full Scan windows poll it).</summary>
    public sealed class ScanProgress
    {
        public volatile string Status = "";      // the engine's own wording of the current step (see Loc.Progress)
        public volatile string Item = "";        // the file / program being looked at right now
        public int Percent;
        public readonly DateTime Started = DateTime.Now;
        public volatile ScanContext Ctx;
        public TimeSpan Elapsed { get { return DateTime.Now - Started; } }

        /// <summary>Everything looked at so far: programs, libraries, files, services, tasks, autostart entries, extensions.</summary>
        public long ObjectsChecked
        {
            get
            {
                var c = Ctx; if (c == null) return 0;
                var s = c.Stats;
                return (long)s.ProcessesScanned + s.ModulesChecked + s.FilesInspected + s.FilesSkippedByCache + s.ServicesScanned + s.TasksScanned + s.RunEntries + s.WmiObjects + s.BrowserExtensions + s.StreamFilesChecked;
            }
        }

        public int FilesChecked { get { var c = Ctx; return c == null ? 0 : c.Stats.FilesInspected + c.Stats.FilesSkippedByCache; } }

        /// <summary>Objects that already carry enough evidence to be worth a look (a first count, before the final verdict is made).</summary>
        public int Suspects
        {
            get
            {
                var c = Ctx; if (c == null) return 0;
                int n = 0;
                try
                {
                    foreach (var e in c.Entities.Values)
                    {
                        int w = 0;
                        lock (e.Evidence) foreach (var ev in e.Evidence) if (ev.Weight > 0) w += ev.Weight;
                        if (w >= 40 || e.Evidence.Any(x => x.Definitive && x.Weight > 0)) n++;
                    }
                }
                catch { }
                return n;
            }
        }
    }

    public sealed class ScanContext
    {
        public readonly RulePack Rules;
        public readonly Allowlist Allow;
        public readonly ScanOptions Options;
        public readonly ConcurrentDictionary<string, Entity> Entities = new ConcurrentDictionary<string, Entity>(StringComparer.OrdinalIgnoreCase);
        public readonly ConcurrentQueue<Link> Links = new ConcurrentQueue<Link>();
        public readonly ConcurrentQueue<BlindSpot> Blind = new ConcurrentQueue<BlindSpot>();
        public readonly ScanStats Stats = new ScanStats();
        public readonly CancellationToken Cancel;
        public Action<string, int> Progress = delegate { };
        public readonly string SelfPath;
        public readonly string SelfDir;
        public readonly FileIntel Files;
        public ScanCache Cache = new ScanCache();
        public ScanProgress Live;
        public readonly int CoreCount = Environment.ProcessorCount;
        public readonly List<string> PostureWarnings = new List<string>();
        public readonly List<string> PostureInfo = new List<string>();

        int _denied;
        public ScanContext(RulePack rules, Allowlist allow, ScanOptions opt, CancellationToken cancel)
        {
            Rules = rules; Allow = allow ?? new Allowlist(); Options = opt ?? new ScanOptions(); Cancel = cancel;
            Live = Options.Live; if (Live != null) Live.Ctx = this;
            try { SelfPath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName; SelfDir = System.IO.Path.GetDirectoryName(SelfPath); } catch { }
            Files = new FileIntel(this);
        }

        public Entity GetOrAdd(string id, EntityKind kind, Func<Entity> create)
        {
            return Entities.GetOrAdd(id, _ => { var e = create(); e.Id = id; e.Kind = kind; return e; });
        }

        public void Link(string from, string to, string relation)
        {
            if (string.IsNullOrEmpty(from) || string.IsNullOrEmpty(to) || from == to) return;
            Links.Enqueue(new Link(from, to, relation));
        }

        public void AddBlind(string area, string reason) { Blind.Enqueue(new BlindSpot(area, reason)); }

        public void Denied(string area, string what)
        {
            Interlocked.Increment(ref _denied);
            Stats.AccessDenied = _denied;
            if (_denied <= 60) AddBlind(area, "access denied: " + what);
        }

        public bool IsSelf(string path)
        {
            if (Options.IncludeSelf || string.IsNullOrEmpty(SelfDir) || string.IsNullOrEmpty(path)) return false;
            return PathUtil.IsUnder(path, SelfDir);
        }

        public void Report(string status, int percent)
        {
            var l = Live; if (l != null) { l.Status = status ?? ""; l.Percent = percent; }
            try { Progress(status, percent); } catch { }
        }

        /// <summary>Tells the window which file or program is being looked at (cheap: one write).</summary>
        public void Item(string what) { var l = Live; if (l != null) l.Item = what ?? ""; }

        /// <summary>True for a path the user excluded in the settings.</summary>
        public bool IsExcluded(string path) { var s = Options.UserSettings; return s != null && s.IsExcludedPath(path); }

        long _thrTick; TimeSpan _thrCpu; int _thrCalls;
        /// <summary>CPU limit: called from the loops that read files. When the scan used more than the allowed share of the CPU since the last look, it sleeps a little.</summary>
        public void Throttle()
        {
            int lim = Options.CpuLimit; if (lim <= 0) return;
            if ((Interlocked.Increment(ref _thrCalls) & 15) != 0) return;
            try
            {
                long now = Environment.TickCount; var cpu = System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime;
                long dt = now - _thrTick;
                if (dt >= 250)
                {
                    double used = (cpu - _thrCpu).TotalMilliseconds / (dt * (double)CoreCount) * 100.0;
                    _thrTick = now; _thrCpu = cpu;
                    if (used > lim) Thread.Sleep((int)Math.Min(400, dt * (used / lim - 1.0)));
                }
            }
            catch { }
        }
        public void ThrowIfCancelled() { Cancel.ThrowIfCancellationRequested(); }
    }
}
