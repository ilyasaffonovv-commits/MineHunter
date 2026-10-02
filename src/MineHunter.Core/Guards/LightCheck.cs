using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Guards
{
    public sealed class LightResult
    {
        public string Path, Sha256; public long Size;
        public bool Trusted, Unsigned, FromInternet, UserWritable, MissingOrUnreadable;
        public string Publisher, Origin;
        public int Score; public Verdict Verdict; public bool Definitive, Tool;
        public List<Evidence> Evidence = new List<Evidence>();
        public List<Signal> Signals = new List<Signal>();
        public string Cheat;
    }

    /// <summary>The quick look the guards give a file: hash, signature, Mark of the Web, PE layout, entropy, packer, imports, miner markers, script content, local reputation.
    /// It is the same engine as a scan, run on one file; the result is cached per path+size+date so a file is not looked at twice.</summary>
    public sealed class LightCheck
    {
        readonly GuardContext g;
        ScanContext ctx; int uses;
        readonly ConcurrentDictionary<string, LightResult> cache = new ConcurrentDictionary<string, LightResult>(StringComparer.OrdinalIgnoreCase);
        readonly object lk = new object();

        public LightCheck(GuardContext g) { this.g = g; }

        ScanContext Ctx()
        {
            lock (lk)
            {
                // a fresh context every few hundred files: the entity table inside it only grows
                if (ctx == null || ++uses > 300)
                {
                    var opt = new ScanOptions { Mode = ScanMode.Custom, UseCache = false, UserSettings = g.Settings, IncludeSelf = true, DeveloperContext = g.Settings != null && g.Settings.DeveloperContext };
                    ctx = new ScanContext(g.Rules, g.Allow, opt, CancellationToken.None); uses = 0;
                }
                return ctx;
            }
        }

        public LightResult Check(string path)
        {
            var r = new LightResult { Path = path };
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) { r.MissingOrUnreadable = true; return r; }
                string key = path + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks;
                LightResult cached; if (cache.TryGetValue(key, out cached)) return cached;
                r.Size = fi.Length; r.UserWritable = PathUtil.IsUserWritable(path);
                var c = Ctx();
                var e = c.Files.Inspect(path, FileRole.HotDir);
                if (e == null) { r.MissingOrUnreadable = true; return r; }
                r.Sha256 = e.Sha256 ?? Hashing.Sha256(path);
                r.Trusted = e.Trusted;
                r.Cheat = e.P("toolClass");
                Provenance.Fill(e);
                r.FromInternet = e.P("zoneId") == "3" || e.P("zoneId") == "4"; r.Origin = e.P("origin");
                lock (e.Evidence) r.Evidence = e.Evidence.Where(x => x.Weight != 0).ToList();
                var sc = RiskEngine.Compute(new[] { e });
                r.Score = (int)Math.Round(Math.Min(100, sc.Total));
                string why; r.Verdict = RiskEngine.Decide(sc, out why);
                r.Definitive = sc.Definitive;
                var ti = Trust.Check(path);
                if (ti != null) { r.Publisher = ti.Publisher; r.Unsigned = ti.State == TrustState.Unsigned; if (g.Rules != null && ti.IsValid && g.Rules.IsTrustedPublisher(ti.Publisher)) r.Trusted = true; }
                if (g.Allow != null && g.Allow.Sha256.Contains(r.Sha256 ?? "")) r.Trusted = true;
                if (g.Settings != null && g.Settings.IsExcludedPath(path)) r.Trusted = true;
                r.Tool = r.Cheat != null && !RiskEngine.HasThreatEvidence(new[] { e });
                string actor = PathUtil.Normalize(path);
                foreach (var ev in r.Evidence.Where(x => x.Weight > 0 && x.Category != EvidenceCategory.Trust))
                    r.Signals.Add(new Signal { Actor = actor, Category = ev.Category, Weight = ev.Weight, Rule = ev.RuleId, Text = Loc.Ev(ev), Definitive = ev.Definitive });
                // the entity table is not needed afterwards
                Entity rm; c.Entities.TryRemove(e.Id, out rm);
                if (cache.Count > 5000) cache.Clear();
                cache[key] = r;
            }
            catch (Exception ex) { Log.Warn("light check " + path + ": " + ex.Message); r.MissingOrUnreadable = true; }
            return r;
        }
    }
}
