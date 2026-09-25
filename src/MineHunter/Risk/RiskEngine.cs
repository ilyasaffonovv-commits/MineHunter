using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MineHunter.Model;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Risk
{
    public sealed class ScanResult
    {
        public List<Finding> Findings = new List<Finding>();
        public List<Entity> Observations = new List<Entity>();           // low-risk notes (score 12..29), not findings
        public SystemStatus Status = new SystemStatus();
        public ScanStats Stats = new ScanStats();
        public List<BlindSpot> BlindSpots = new List<BlindSpot>();
        public DateTime Started, Finished;
        public string Mode, RulesVersion, AppVersion;
        public int EntitiesTotal;
        public string SelfHash, SelfHashEnd;
        public bool Aborted; public string AbortReason;
        public List<string> PreviousScanIssues = new List<string>();
    }

    /// <summary>Transparent scoring. Every number in a verdict can be traced back to an Evidence line.</summary>
    public static class RiskEngine
    {
        public const int SuspiciousAt = 30, HighRiskAt = 60, MalwareAt = 85, ObservationAt = 12;

        static readonly Dictionary<EvidenceCategory, int> Cap = new Dictionary<EvidenceCategory, int>
        {
            { EvidenceCategory.Signature, 15 }, { EvidenceCategory.Location, 20 }, { EvidenceCategory.Masquerade, 50 }, { EvidenceCategory.Content, 75 },
            { EvidenceCategory.Behavior, 70 }, { EvidenceCategory.Network, 40 }, { EvidenceCategory.Persistence, 55 }, { EvidenceCategory.Tamper, 45 }, { EvidenceCategory.Reputation, 100 }
        };
        static readonly EvidenceCategory[] Strong = { EvidenceCategory.Content, EvidenceCategory.Behavior, EvidenceCategory.Persistence, EvidenceCategory.Network, EvidenceCategory.Masquerade, EvidenceCategory.Tamper, EvidenceCategory.Reputation };

        public sealed class Weighted { public Evidence Ev; public double W; public Entity Owner; }
        public sealed class Score
        {
            public double Total; public bool Definitive; public int StrongCategories; public Dictionary<EvidenceCategory, double> ByCategory = new Dictionary<EvidenceCategory, double>();
            public List<Weighted> Items = new List<Weighted>();
        }

        // ------------------------------------------------------------------------------------------------ scoring
        public static IEnumerable<Weighted> Effective(Entity e)
        {
            double pos = e.Evidence.Where(x => x.Weight > 0 && !x.Definitive).Sum(x => (double)x.Weight);
            double trust = -e.Evidence.Where(x => x.Weight < 0).Sum(x => (double)x.Weight);
            trust = Math.Min(trust, 100);
            double scale = pos > 0 ? Math.Max(0, Math.Min(1, (pos - trust) / pos)) : 1;
            if (e.Kind == EntityKind.Process) scale = 1;             // trust belongs to the FILE; behaviour of a process (hollowing, network) is never cancelled by its image's signature
            foreach (var ev in e.Evidence)
            {
                if (ev.Weight <= 0) continue;
                yield return new Weighted { Ev = ev, W = ev.Definitive ? ev.Weight : ev.Weight * scale, Owner = e };
            }
        }

        public static Score Compute(IEnumerable<Entity> members)
        {
            var s = new Score();
            var all = members.SelectMany(Effective).Where(x => x.W > 0.4).ToList();
            // collapse identical rules seen on many members: full weight once, +15 % for each further occurrence (max 3)
            var collapsed = new List<Weighted>();
            foreach (var g in all.GroupBy(x => x.Ev.RuleId))
            {
                var ordered = g.OrderByDescending(x => x.W).ToList();
                var first = ordered[0];
                double extra = Math.Min(3, ordered.Count - 1) * 0.15 * first.W;
                collapsed.Add(new Weighted { Ev = first.Ev, W = first.W + extra, Owner = first.Owner });
            }
            s.Items = collapsed.OrderByDescending(x => x.W).ToList();
            foreach (var cat in Enum.GetValues(typeof(EvidenceCategory)).Cast<EvidenceCategory>())
            {
                if (cat == EvidenceCategory.Trust) continue;
                var list = collapsed.Where(x => x.Ev.Category == cat).Select(x => x.W).OrderByDescending(x => x).ToList();
                if (list.Count == 0) continue;
                double t = list[0] + 0.5 * list.Skip(1).Sum();
                int cap; if (!Cap.TryGetValue(cat, out cap)) cap = 40;
                t = Math.Min(t, cap);
                s.ByCategory[cat] = t;
                s.Total += t;
            }
            s.Definitive = collapsed.Any(x => x.Ev.Definitive);
            s.StrongCategories = Strong.Count(c => s.ByCategory.ContainsKey(c) && s.ByCategory[c] >= 12);
            if (collapsed.Any(x => x.Ev.Definitive && x.Ev.Category == EvidenceCategory.Reputation && x.Ev.Weight >= 100)) s.Total = Math.Max(s.Total, 100);
            return s;
        }

        public static Verdict Decide(Score s, out string whyNotHigher)
        {
            whyNotHigher = null;
            double t = s.Total;
            if (t >= MalwareAt && ((s.Definitive && s.StrongCategories >= 2) || s.StrongCategories >= 3 || s.ByCategory.ContainsKey(EvidenceCategory.Reputation) && s.ByCategory[EvidenceCategory.Reputation] >= 100)) return Verdict.Malware;
            if ((t >= HighRiskAt && (s.Definitive || s.StrongCategories >= 2)) || (s.Definitive && t >= 50))
                return Verdict.HighRisk;
            if (t >= SuspiciousAt)
            {
                if (t >= HighRiskAt) whyNotHigher = "The score is high, but the evidence comes from a single kind of signal (" + (s.StrongCategories == 0 ? "only weak signals like path/signature" : "one category") + "). A program is only called High Risk when independent kinds of evidence agree, to avoid false alarms on normal software.";
                return Verdict.Suspicious;
            }
            return Verdict.Clean;
        }

        // ------------------------------------------------------------------------------------------------ graph + findings
        sealed class Uf
        {
            readonly Dictionary<string, string> p = new Dictionary<string, string>();
            public string Find(string x) { if (!p.ContainsKey(x)) p[x] = x; while (p[x] != x) { p[x] = p[p[x]]; x = p[x]; } return x; }
            public void Union(string a, string b) { string ra = Find(a), rb = Find(b); if (ra != rb) p[ra] = rb; }
        }

        public static List<Finding> Build(ScanContext ctx, out List<Entity> observations)
        {
            var ents = ctx.Entities.Values.ToList();
            var byId = ents.ToDictionary(e => e.Id, e => e, StringComparer.OrdinalIgnoreCase);
            var links = ctx.Links.ToList();

            AddDerivedLinksAndEvidence(ctx, ents, byId, links);

            // entity-level scores for display and node selection
            foreach (var e in ents)
            {
                var sc = Compute(new[] { e });
                e.Score = (int)Math.Round(sc.Total);
            }

            // candidate nodes
            Func<Entity, bool> isCandidate = e =>
                e.Evidence.Any(x => x.Weight > 0 && x.Definitive) || e.Score >= ObservationAt ||
                e.Evidence.Any(x => x.Weight > 0 && (x.Category == EvidenceCategory.Tamper || x.Category == EvidenceCategory.Persistence) && x.Weight >= 10);
            var cand = new HashSet<string>(ents.Where(isCandidate).Select(e => e.Id), StringComparer.OrdinalIgnoreCase);
            var uf = new Uf();
            foreach (var id in cand) uf.Find(id);
            foreach (var l in links)
            {
                if (!byId.ContainsKey(l.From) || !byId.ContainsKey(l.To)) continue;
                bool a = cand.Contains(l.From), b = cand.Contains(l.To);
                if (a && b) uf.Union(l.From, l.To);
                else if (a && !b && (l.Relation == "runs image" || l.Relation == "loads" || l.Relation == "launches")) { /* context node handled below */ }
            }
            var comps = cand.GroupBy(id => uf.Find(id)).Select(g => g.Select(i => byId[i]).ToList()).ToList();

            var findings = new List<Finding>();
            observations = new List<Entity>();
            int counter = 0;
            foreach (var members in comps)
            {
                // running instances of member files and children/parents give context and are needed for remediation
                var ctxMembers = new List<Entity>(members);
                var memberIds = new HashSet<string>(members.Select(m => m.Id), StringComparer.OrdinalIgnoreCase);
                foreach (var l in links)
                {
                    if (!byId.ContainsKey(l.From) || !byId.ContainsKey(l.To)) continue;
                    if (l.Relation == "runs image" && memberIds.Contains(l.To) && !memberIds.Contains(l.From)) { var p = byId[l.From]; if (!ctxMembers.Contains(p)) ctxMembers.Add(p); memberIds.Add(p.Id); }
                }
                var sc = Compute(members);
                string why; var verdict = Decide(sc, out why);
                if (verdict == Verdict.Clean)
                {
                    if (sc.Total >= ObservationAt) foreach (var m in members.Where(m => m.Score >= ObservationAt).OrderByDescending(m => m.Score).Take(1)) observations.Add(m);
                    continue;
                }
                var f = new Finding { Id = "F" + (++counter), Verdict = verdict, Score = (int)Math.Round(Math.Min(sc.Total, 100)), Entities = ctxMembers, WhyNotHigher = why };
                f.TopEvidence = sc.Items.Take(10).Select(x => x.Ev).ToList();
                foreach (var l in links) if (memberIds.Contains(l.From) && memberIds.Contains(l.To)) f.Links.Add(l);
                f.Title = TitleFor(f, sc);
                foreach (var m in ctxMembers) m.Verdict = verdict;
                findings.Add(f);
            }

            // aggregate many Defender exclusions into one reviewable finding (individually they are weak)
            findings = findings.OrderByDescending(f => (int)f.Verdict).ThenByDescending(f => f.Score).ToList();
            for (int i = 0; i < findings.Count; i++) findings[i].Id = "F" + (i + 1);
            foreach (var f in findings) { Decision.Plan(ctx, f); f.ChainLines = ThreatGraph.Render(f); }
            observations = observations.OrderByDescending(o => o.Score).Take(60).ToList();
            return findings;
        }

        static string TitleFor(Finding f, Score sc)
        {
            var ids = f.Entities.SelectMany(e => e.Evidence).Where(x => x.Weight > 0).Select(x => x.RuleId).ToList();
            Func<string, bool> has = p => ids.Any(i => i.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0);
            var main = f.Entities.OrderByDescending(e => e.Score).First();
            string name = main.Kind == EntityKind.File || main.Kind == EntityKind.Process ? main.Title : main.Title;
            if (has("REP.KNOWN_BAD_HASH")) return "Known malware: " + name;
            if (has("HOLLOW")) return "Hijacked (hollowed) process: " + name;
            if (has("MINER") ) return (f.Entities.Any(e => e.Kind == EntityKind.Process) ? "Cryptominer running: " : "Cryptominer files: ") + name;
            if (has("BROWSER.EXT_MINER_CODE")) return "Mining code in a browser/editor extension: " + name;
            if (has("MASQ.SYSTEM_NAME") || has("MASQ.HOMOGLYPH")) return "Fake system/vendor program: " + name;
            if (f.Entities.Any(e => e.Kind == EntityKind.Wmi)) return "WMI persistence: " + main.Title;
            if (has("TAMPER.DEF_EXCL") || has("TAMPER.DISALLOWRUN") || has("TAMPER.HOSTS")) return "Protection weakened: " + main.Title;
            if (f.Entities.Any(e => e.Kind == EntityKind.BrowserExtension || e.Kind == EntityKind.BrowserSetting)) return "Browser: " + main.Title;
            if (f.Entities.Any(e => e.Kind == EntityKind.Task || e.Kind == EntityKind.Service || e.Kind == EntityKind.RunKey || e.Kind == EntityKind.StartupItem)) return "Persistent program: " + name;
            return (f.Verdict == Verdict.Suspicious ? "Suspicious item: " : "Dangerous item: ") + name;
        }

        // ------------------------------------------------------------------------------------------------ derived links / evidence
        static void AddDerivedLinksAndEvidence(ScanContext ctx, List<Entity> ents, Dictionary<string, Entity> byId, List<Link> links)
        {
            // 1. several persistence mechanisms for the same untrusted file
            var perFile = new Dictionary<string, List<Entity>>(StringComparer.OrdinalIgnoreCase);
            foreach (var l in links.Where(l => l.Relation == "launches" || l.Relation == "hosts" || l.Relation == "loads"))
            {
                Entity src, dst;
                if (!byId.TryGetValue(l.From, out src) || !byId.TryGetValue(l.To, out dst)) continue;
                if (dst.Kind != EntityKind.File || dst.Trusted) continue;
                if (src.Kind == EntityKind.Process) continue;
                List<Entity> lst; if (!perFile.TryGetValue(dst.Id, out lst)) perFile[dst.Id] = lst = new List<Entity>();
                if (!lst.Contains(src)) lst.Add(src);
            }
            foreach (var kv in perFile)
            {
                var kinds = kv.Value.Select(e => e.Kind).Distinct().ToList();
                var f = byId[kv.Key];
                if (kv.Value.Count >= 2)
                {
                    int w = kv.Value.Count >= 3 ? 20 : 8;
                    string list = string.Join(", ", kv.Value.Select(e => e.Kind + ":" + e.Title).Take(6));
                    f.Add(new Evidence("PERSIST.MULTI", EvidenceCategory.Persistence, w, kv.Value.Count + " separate autostart mechanisms all start this same program (" + list + ") - infections do this to survive cleaning", list));
                }
            }

            // 1b. a background CPU hog whose program also starts itself automatically (miner-like combination)
            foreach (var p in ents.Where(e => e.Kind == EntityKind.Process && e.Evidence.Any(x => x.RuleId == "BEH.CPU_SUSTAINED")))
            {
                foreach (var l in links.Where(l => l.From == p.Id && l.Relation == "runs image"))
                {
                    List<Entity> owners;
                    if (perFile.TryGetValue(l.To, out owners) && owners.Count > 0)
                        p.Add(new Evidence("BEH.CPU_AND_AUTOSTART", EvidenceCategory.Behavior, 15, "A program that keeps the CPU busy in the background also starts itself automatically (" + owners.Count + " autostart entr" + (owners.Count == 1 ? "y" : "ies") + ")", string.Join(", ", owners.Select(o => o.Title).Take(4))));
                }
            }

            // 2. copies of the same untrusted file, and neighbours in the same folder (droppers place several files together)
            var cands = ents.Where(e => e.Kind == EntityKind.File && !e.Trusted && e.P("missing") == null && e.Evidence.Any(x => x.Weight > 0)).ToList();
            foreach (var g in cands.Where(e => !string.IsNullOrEmpty(e.Sha256)).GroupBy(e => e.Sha256).Where(g => g.Count() > 1))
            {
                var arr = g.ToList();
                for (int i = 1; i < arr.Count; i++) links.Add(new Link(arr[0].Id, arr[i].Id, "same content"));
                // copies are only meaningful when the file is already suspicious for a reason beyond "unsigned / odd folder"
                int real = arr[0].Evidence.Where(x => x.Weight > 0 && x.Category != EvidenceCategory.Signature && x.Category != EvidenceCategory.Location).Sum(x => x.Weight);
                if (real >= 30 && arr.Count >= 2)
                    arr[0].Add(new Evidence("REL.DUPLICATES", EvidenceCategory.Behavior, 6, "Identical copy exists in " + (arr.Count - 1) + " other place(s) (multi-drop pattern)", string.Join(" | ", arr.Skip(1).Take(4).Select(a => a.Location))));
            }
            foreach (var g in cands.GroupBy(e => Path.GetDirectoryName(e.Location) ?? "").Where(g => g.Key.Length > 0 && g.Count() >= 2 && PathUtil.IsUserWritable(g.Key)))
            {
                int strong = g.Count(e => e.Evidence.Where(x => x.Weight > 0 && x.Category != EvidenceCategory.Signature && x.Category != EvidenceCategory.Location).Sum(x => x.Weight) >= 6);
                var arr = g.ToList();
                for (int i = 1; i < arr.Count; i++) links.Add(new Link(arr[0].Id, arr[i].Id, "same folder"));
            }

            // 3. Defender exclusions that cover files of a finding
            var exclusions = ents.Where(e => e.Kind == EntityKind.DefenderExclusion && e.P("kind") == "Paths").ToList();
            foreach (var x in exclusions)
            {
                string p = PathUtil.Normalize(x.P("value"));
                foreach (var f in cands)
                    if (PathUtil.IsUnder(f.Location, p) || PathUtil.Same(f.Location, p)) links.Add(new Link(x.Id, f.Id, "excludes"));
            }
            foreach (var x in ents.Where(e => e.Kind == EntityKind.DefenderExclusion && e.P("kind") == "Processes"))
            {
                string n = Path.GetFileName(x.P("value"));
                foreach (var f in cands) if (string.Equals(f.Title, n, StringComparison.OrdinalIgnoreCase)) links.Add(new Link(x.Id, f.Id, "excludes"));
            }
            // many exclusions together form one reviewable group
            var excl = ents.Where(e => e.Kind == EntityKind.DefenderExclusion && e.Evidence.Any(v => v.Weight > 0)).ToList();
            if (excl.Count >= 4) for (int i = 1; i < excl.Count; i++) links.Add(new Link(excl[0].Id, excl[i].Id, "same list"));

            // 4. watchdog pattern: two or more different untrusted programs each kept alive by their own autostart, connected in one story
            var persistTargets = links.Where(l => l.Relation == "launches" && byId.ContainsKey(l.To) && !byId[l.To].Trusted && byId[l.To].Evidence.Any(x => x.Weight > 0)).Select(l => l.To).Distinct().ToList();
            if (persistTargets.Count >= 2)
            {
                // Only untrusted entities connect a group. A trusted process (conhost.exe, explorer.exe, a signed launcher) that happens to be the
                // parent of several unrelated programs must never glue them together into one "watchdog family".
                var adj = new Uf();
                foreach (var l in links)
                {
                    Entity a, b;
                    if (!byId.TryGetValue(l.From, out a) || !byId.TryGetValue(l.To, out b) || a.Trusted || b.Trusted) continue;
                    if (l.Relation == "allows" || l.Relation == "excludes") continue;
                    adj.Union(l.From, l.To);
                }
                foreach (var g in persistTargets.GroupBy(t => adj.Find(t)).Where(g => g.Count() >= 2))
                    foreach (var t in g) byId[t].Add(new Evidence("WATCHDOG.MULTI_PAYLOAD", EvidenceCategory.Behavior, 12, g.Count() + " different programs of one group are each set to auto-start (one can restart the other = watchdog)", string.Join(", ", g.Select(x => byId[x].Title).Take(6))));
            }
        }
    }

    // ==================================================================================================
    //   Rendering of the infection chain as text
    // ==================================================================================================
    public static class ThreatGraph
    {
        public static string Describe(Entity e)
        {
            switch (e.Kind)
            {
                case EntityKind.Process: return "Process " + e.Title + " (PID " + e.P("pid") + ")";
                case EntityKind.File: return "File " + e.Title + "  [" + Shorten(e.Location, 70) + "]";
                case EntityKind.Task: return "Scheduled task " + e.P("taskPath");
                case EntityKind.Service: return "Service " + e.Title;
                case EntityKind.Driver: return "Driver service " + e.Title;
                case EntityKind.RunKey: return "Autorun " + e.Location;
                case EntityKind.StartupItem: return "Startup item " + e.Title;
                case EntityKind.Wmi: return "WMI " + e.Title;
                case EntityKind.DefenderExclusion: return e.Title;
                case EntityKind.Registry: return "Registry " + e.Title;
                default: return e.Kind + " " + e.Title;
            }
        }
        static string Shorten(string s, int n) { if (string.IsNullOrEmpty(s) || s.Length <= n) return s; return s.Substring(0, 20) + "..." + s.Substring(s.Length - (n - 23)); }

        public static List<string> Render(Finding f, bool localized = false)
        {
            var lines = new List<string>();
            var byId = f.Entities.ToDictionary(e => e.Id, e => e, StringComparer.OrdinalIgnoreCase);
            var outgoing = new Dictionary<string, List<Link>>(StringComparer.OrdinalIgnoreCase);
            var hasIncoming = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var l in f.Links)
            {
                if (!byId.ContainsKey(l.From) || !byId.ContainsKey(l.To)) continue;
                string from = l.From, to = l.To, rel = l.Relation;
                // direction for display: persistence -> launches -> file -> (running) process
                if (rel == "runs image") { from = l.To; to = l.From; rel = "is running as"; }
                if (rel == "started by") { from = l.To; to = l.From; rel = "started"; }
                List<Link> lst; if (!outgoing.TryGetValue(from, out lst)) outgoing[from] = lst = new List<Link>();
                lst.Add(new Link(from, to, rel)); hasIncoming.Add(to);
            }
            var roots = f.Entities.Where(e => !hasIncoming.Contains(e.Id)).OrderBy(e => Order(e)).ToList();
            if (roots.Count == 0) roots = f.Entities.Take(1).ToList();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in roots) Walk(r, "", outgoing, byId, seen, lines, 0, localized);
            foreach (var e in f.Entities.Where(x => !seen.Contains(x.Id))) lines.Add(localized ? Loc.Describe(e) : Describe(e));
            return lines;
        }

        static int Order(Entity e) { switch (e.Kind) { case EntityKind.Task: case EntityKind.Service: case EntityKind.RunKey: case EntityKind.StartupItem: case EntityKind.Wmi: return 0; case EntityKind.DefenderExclusion: return 1; case EntityKind.Process: return 3; default: return 2; } }

        static void Walk(Entity e, string rel, Dictionary<string, List<Link>> outgoing, Dictionary<string, Entity> byId, HashSet<string> seen, List<string> lines, int depth, bool loc)
        {
            string prefix = new string(' ', depth * 3) + (depth > 0 ? "└─ " + (loc ? Loc.Relation(rel) : rel) + " → " : "");
            lines.Add(prefix + (loc ? Loc.Describe(e) : Describe(e)));
            if (!seen.Add(e.Id) || depth > 8) return;
            List<Link> outs;
            if (outgoing.TryGetValue(e.Id, out outs))
                foreach (var l in outs.OrderBy(x => Order(byId[x.To])))
                    if (!seen.Contains(l.To)) Walk(byId[l.To], l.Relation, outgoing, byId, seen, lines, depth + 1, loc);
            string conns = e.P("connections");
            if (e.Kind == EntityKind.Process && !string.IsNullOrEmpty(conns)) lines.Add(new string(' ', (depth + 1) * 3) + "└─ " + (loc ? Loc.Relation("connects to") : "connects to") + " → " + conns);
        }
    }

    // ==================================================================================================
    //   Decision engine: what to do about a finding (plan only - nothing is executed here)
    // ==================================================================================================
    public static class Decision
    {
        static readonly HashSet<string> CriticalProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe", "registry", "memory compression", "secure system" };

        public static bool IsProtectedProcess(Entity p)
        {
            string name = p.Title ?? "";
            if (CriticalProcesses.Contains(name)) return true;
            return false;
        }

        public static bool IsProtectedFile(ScanContext ctx, Entity f)
        {
            if (f.Kind != EntityKind.File) return false;
            if (f.Trusted) return true;
            var pc = PathUtil.Classify(f.Location);
            string tc = f.P("trustClass");
            if ((pc == PathClass.WindowsSystem) && (tc == "MicrosoftSigned")) return true;
            return false;
        }

        public static void Plan(ScanContext ctx, Finding f)
        {
            bool defaultOn = f.Verdict == Verdict.HighRisk || f.Verdict == Verdict.Malware;
            var steps = new List<RemediationStep>();
            var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Action<RemediationStep> add = s => { string k = s.Type + "|" + s.Target; if (seenTargets.Add(k)) steps.Add(s); };

            foreach (var e in f.Entities)
            {
                switch (e.Kind)
                {
                    case EntityKind.Task:
                        add(new RemediationStep { Type = ActionType.QuarantineTask, EntityId = e.Id, Target = e.P("taskPath") ?? e.Location, Order = 1, RecommendedByDefault = defaultOn, Description = "Remove scheduled task " + (e.P("taskPath") ?? e.Title) + " (a copy is kept so it can be restored)" });
                        break;
                    case EntityKind.Service: case EntityKind.Driver:
                        add(new RemediationStep { Type = ActionType.QuarantineService, EntityId = e.Id, Target = e.P("serviceKey") ?? e.Title, Order = 1, RecommendedByDefault = defaultOn && (e.Kind == EntityKind.Service), Description = "Stop and remove " + (e.Kind == EntityKind.Driver ? "driver service " : "service ") + e.Title + " (its registry settings are saved for restore)" });
                        break;
                    case EntityKind.RunKey:
                        add(new RemediationStep { Type = ActionType.RemoveRunValue, EntityId = e.Id, Target = e.Location, Order = 1, RecommendedByDefault = defaultOn, Description = "Remove autorun entry " + e.Title });
                        break;
                    case EntityKind.Registry:
                        if (e.P("hive") != null && e.P("value") != null)
                        {
                            bool restore = !string.IsNullOrEmpty(e.P("default"));
                            add(new RemediationStep { Type = restore ? ActionType.RestoreDefaultValue : ActionType.RemoveRegistryValue, EntityId = e.Id, Target = e.Location, Order = 1, RecommendedByDefault = defaultOn, Description = (restore ? "Restore the Windows default for " : "Remove registry value ") + e.Title });
                        }
                        break;
                    case EntityKind.StartupItem:
                        add(new RemediationStep { Type = ActionType.RemoveStartupItem, EntityId = e.Id, Target = e.P("file") ?? e.Location, Order = 1, RecommendedByDefault = defaultOn, Description = "Move startup item " + e.Title + " to quarantine" });
                        break;
                    case EntityKind.Wmi:
                        if (e.P("wmiClass") != null)
                            add(new RemediationStep { Type = ActionType.RemoveWmiSubscription, EntityId = e.Id, Target = e.P("wmiClass") + ":" + e.P("consumer"), Order = 1, RecommendedByDefault = defaultOn, Description = "Delete WMI subscription " + e.P("consumer") + " (binding, consumer and filter; saved for restore)" });
                        break;
                    case EntityKind.DefenderExclusion:
                        add(new RemediationStep { Type = ActionType.RemoveDefenderExclusion, EntityId = e.Id, Target = e.P("kind") + "|" + e.P("value") + "|" + e.P("policy"), Order = 1, RecommendedByDefault = defaultOn && f.Entities.Count > 0 && f.Entities.Any(x => x.Kind == EntityKind.File), Description = "Remove Defender exclusion: " + e.P("value") });
                        break;
                    case EntityKind.HostsEntry:
                        add(new RemediationStep { Type = ActionType.RemoveHostsLines, EntityId = e.Id, Target = e.Id, Order = 1, RecommendedByDefault = defaultOn, Description = "Remove the hosts-file lines that block security sites (backup saved)" });
                        break;
                    case EntityKind.PolicyValue:
                        if (e.P("hive") != null && e.P("key") != null && e.P("value") != null && e.Id.StartsWith("policy:"))
                            add(new RemediationStep { Type = ActionType.RemoveRegistryValue, EntityId = e.Id, Target = e.P("hive") + "\\" + e.P("key") + "\\" + e.P("value"), Order = 1, RecommendedByDefault = defaultOn, Description = "Remove policy value " + e.P("value") });
                        break;
                    case EntityKind.FirewallRule:
                        add(new RemediationStep { Type = ActionType.RemoveFirewallRule, EntityId = e.Id, Target = e.P("ruleName"), Order = 1, RecommendedByDefault = defaultOn, Description = "Remove firewall rule " + e.P("ruleName") });
                        break;
                    case EntityKind.BrowserExtension:
                        add(new RemediationStep { Type = ActionType.RemoveBrowserExtension, EntityId = e.Id, Target = e.P("dir") ?? e.Location, Order = 1, RecommendedByDefault = defaultOn, Description = "Remove extension \"" + (e.P("name") ?? e.Title) + "\" (files moved to quarantine; close the browser first)" });
                        break;
                    case EntityKind.BrowserSetting:
                        add(new RemediationStep { Type = ActionType.ReviewOnly, EntityId = e.Id, Target = e.Location, Order = 1, RecommendedByDefault = false, Description = "Review manually: " + e.Title + (e.P("value") != null ? " = " + e.P("value") : "") });
                        break;
                }
            }
            foreach (var e in f.Entities.Where(x => x.Kind == EntityKind.Process))
            {
                if (IsProtectedProcess(e)) continue;
                int pid; if (!int.TryParse(e.P("pid"), out pid)) continue;
                add(new RemediationStep { Type = ActionType.KillProcess, EntityId = e.Id, Target = pid + "|" + e.P("start"), Order = 2, RecommendedByDefault = defaultOn, Description = "Stop process " + e.Title + " (PID " + pid + ")" });
            }
            foreach (var e in f.Entities.Where(x => x.Kind == EntityKind.File && !IsProtectedFile(ctx, x) && x.P("missing") == null))
            {
                int pos = e.Evidence.Where(v => v.Weight > 0).Sum(v => v.Weight);
                if (pos < ObservationOrMore) continue;
                add(new RemediationStep { Type = ActionType.QuarantineFile, EntityId = e.Id, Target = e.Location, Order = 3, RecommendedByDefault = defaultOn, Description = "Quarantine file " + e.Location + " (a copy is kept, restorable)" });
            }
            f.Steps = steps.OrderBy(s => s.Order).ToList();
            if (!f.Steps.Any(s => s.Type != ActionType.ReviewOnly)) f.Recommendation = "Review only - nothing here can be undone automatically.";
            else if (f.Verdict == Verdict.Suspicious) f.Recommendation = "Review. If you do not recognise it, tick the actions and press Neutralize. Removed files and settings can be restored from Quarantine.";
            else f.Recommendation = "Neutralize: stop the processes, remove the autostart entries, then quarantine the files. Removed files and settings can be restored from Quarantine.";
        }
        const int ObservationOrMore = 8;
    }
}
