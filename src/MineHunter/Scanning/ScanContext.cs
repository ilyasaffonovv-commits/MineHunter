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
        public readonly int CoreCount = Environment.ProcessorCount;
        public readonly List<string> PostureWarnings = new List<string>();
        public readonly List<string> PostureInfo = new List<string>();

        int _denied;
        public ScanContext(RulePack rules, Allowlist allow, ScanOptions opt, CancellationToken cancel)
        {
            Rules = rules; Allow = allow ?? new Allowlist(); Options = opt ?? new ScanOptions(); Cancel = cancel;
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

        public void Report(string status, int percent) { try { Progress(status, percent); } catch { } }
        public void ThrowIfCancelled() { Cancel.ThrowIfCancellationRequested(); }
    }
}
