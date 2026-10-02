using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MineHunter.Model;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Report
{
    /// <summary>The result of the last scan, kept on disk in full (findings, the objects in them, the evidence, the links, the steps), so that another MineHunter program - the main window
    /// opened from Quick Scan.exe, for example - can show the same findings and neutralize them. It is written to the protected data folder.</summary>
    public static class ResultSnapshot
    {
        public static string FilePath { get { return Path.Combine(RulePack.DataDir, "last-scan.json"); } }

        static Dictionary<string, object> Ev(Evidence e) { return new Dictionary<string, object> { { "r", e.RuleId }, { "c", e.Category.ToString() }, { "w", e.Weight }, { "t", e.Text }, { "d", e.Detail }, { "f", e.Definitive } }; }
        static Evidence Ev(Dictionary<string, object> d) { EvidenceCategory c; Enum.TryParse(Json.Str(d, "c"), out c); return new Evidence(Json.Str(d, "r"), c, Json.Int(d, "w"), Json.Str(d, "t"), Json.Str(d, "d"), Json.Bool(d, "f")); }

        static Dictionary<string, object> En(Entity e)
        {
            return new Dictionary<string, object>
            {
                { "id", e.Id }, { "kind", e.Kind.ToString() }, { "title", e.Title }, { "loc", e.Location }, { "score", e.Score }, { "verdict", e.Verdict.ToString() }, { "trusted", e.Trusted }, { "sha", e.Sha256 },
                { "props", e.Props.Where(p => p.Key != "sections" && p.Key != "imports" && (p.Value ?? "").Length < 4000).ToDictionary(p => p.Key, p => (object)p.Value) },
                { "ev", e.Evidence.Select(x => (object)Ev(x)).ToArray() }
            };
        }

        static Entity En(Dictionary<string, object> d)
        {
            var e = new Entity { Id = Json.Str(d, "id"), Title = Json.Str(d, "title"), Location = Json.Str(d, "loc"), Score = Json.Int(d, "score"), Trusted = Json.Bool(d, "trusted"), Sha256 = Json.Str(d, "sha") };
            EntityKind k; Enum.TryParse(Json.Str(d, "kind"), out k); e.Kind = k;
            Verdict v; Enum.TryParse(Json.Str(d, "verdict"), out v); e.Verdict = v;
            var props = Json.Obj(d.ContainsKey("props") ? d["props"] : null); if (props != null) foreach (var kv in props) e.Props[kv.Key] = Convert.ToString(kv.Value);
            foreach (var x in Json.Arr(d.ContainsKey("ev") ? d["ev"] : null) ?? new object[0]) { var o = Json.Obj(x); if (o != null) e.Evidence.Add(Ev(o)); }
            return e;
        }

        public static void Save(ScanResult r)
        {
            try
            {
                var findings = r.Findings.Select(f => (object)new Dictionary<string, object>
                {
                    { "id", f.Id }, { "title", f.Title }, { "verdict", f.Verdict.ToString() }, { "score", f.Score }, { "tool", f.ToolClass }, { "why", f.WhyNotHigher }, { "rec", f.Recommendation },
                    { "entities", f.Entities.Select(x => (object)En(x)).ToArray() },
                    { "links", f.Links.Select(l => (object)new Dictionary<string, object> { { "from", l.From }, { "to", l.To }, { "rel", l.Relation } }).ToArray() },
                    { "top", f.TopEvidence.Select(x => (object)Ev(x)).ToArray() }, { "chain", f.ChainLines.ToArray() },
                    { "steps", f.Steps.Select(s => (object)new Dictionary<string, object> { { "type", s.Type.ToString() }, { "entity", s.EntityId }, { "desc", s.Description }, { "target", s.Target }, { "rev", s.Reversible }, { "def", s.RecommendedByDefault }, { "order", s.Order } }).ToArray() }
                }).ToArray();
                var root = new Dictionary<string, object>
                {
                    { "saved", DateTime.Now.ToString("o") }, { "version", r.AppVersion }, { "mode", r.Mode }, { "rules", r.RulesVersion }, { "started", r.Started.ToString("o") }, { "finished", r.Finished.ToString("o") }, { "aborted", r.Aborted },
                    { "seconds", r.Stats.Seconds.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                    { "stats", new Dictionary<string, object> { { "proc", r.Stats.ProcessesScanned }, { "mods", r.Stats.ModulesChecked }, { "files", r.Stats.FilesInspected }, { "cache", r.Stats.FilesSkippedByCache }, { "svc", r.Stats.ServicesScanned }, { "tasks", r.Stats.TasksScanned }, { "ext", r.Stats.BrowserExtensions } } },
                    { "status", new Dictionary<string, object> { { "defender", r.Status.DefenderState }, { "warnings", r.Status.PostureWarnings.ToArray() }, { "os", r.Status.OsVersion }, { "admin", r.Status.IsAdmin } } },
                    { "findings", findings }, { "notes", r.Observations.Select(x => (object)En(x)).ToArray() }, { "blind", r.BlindSpots.Select(b => b.Area + ": " + b.Reason).ToArray() }
                };
                Directory.CreateDirectory(RulePack.DataDir);
                Fs.WriteDurable(FilePath, new System.Text.UTF8Encoding(false).GetBytes(Json.Serialize(root)));
            }
            catch (Exception ex) { Log.Warn("last scan not saved: " + ex.Message); }
        }

        public static ScanResult Load()
        {
            try
            {
                if (!File.Exists(FilePath)) return null;
                var d = Json.Obj(Json.Parse(File.ReadAllText(FilePath)));
                var r = new ScanResult { AppVersion = Json.Str(d, "version"), Mode = Json.Str(d, "mode"), RulesVersion = Json.Str(d, "rules"), Aborted = Json.Bool(d, "aborted") };
                DateTime t; DateTime.TryParse(Json.Str(d, "started"), null, System.Globalization.DateTimeStyles.RoundtripKind, out t); r.Started = t;
                DateTime.TryParse(Json.Str(d, "finished"), null, System.Globalization.DateTimeStyles.RoundtripKind, out t); r.Finished = t;
                double sec; double.TryParse(Json.Str(d, "seconds", "0"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out sec); r.Stats.Seconds = sec;
                var st = Json.Obj(d["stats"]); r.Stats.ProcessesScanned = Json.Int(st, "proc"); r.Stats.ModulesChecked = Json.Int(st, "mods"); r.Stats.FilesInspected = Json.Int(st, "files"); r.Stats.FilesSkippedByCache = Json.Int(st, "cache"); r.Stats.ServicesScanned = Json.Int(st, "svc"); r.Stats.TasksScanned = Json.Int(st, "tasks"); r.Stats.BrowserExtensions = Json.Int(st, "ext");
                var ss = Json.Obj(d["status"]); r.Status.DefenderState = Json.Str(ss, "defender"); r.Status.PostureWarnings = Json.Strs(ss, "warnings"); r.Status.OsVersion = Json.Str(ss, "os"); r.Status.IsAdmin = Json.Bool(ss, "admin");
                foreach (var o in Json.Arr(d["findings"]) ?? new object[0])
                {
                    var fd = Json.Obj(o); if (fd == null) continue;
                    Verdict v; Enum.TryParse(Json.Str(fd, "verdict"), out v);
                    var f = new Finding { Id = Json.Str(fd, "id"), Title = Json.Str(fd, "title"), Verdict = v, Score = Json.Int(fd, "score"), ToolClass = Json.Str(fd, "tool"), WhyNotHigher = Json.Str(fd, "why"), Recommendation = Json.Str(fd, "rec"), ChainLines = Json.Strs(fd, "chain") };
                    foreach (var x in Json.Arr(fd["entities"]) ?? new object[0]) { var e = Json.Obj(x); if (e != null) f.Entities.Add(En(e)); }
                    foreach (var x in Json.Arr(fd["links"]) ?? new object[0]) { var l = Json.Obj(x); if (l != null) f.Links.Add(new Link(Json.Str(l, "from"), Json.Str(l, "to"), Json.Str(l, "rel"))); }
                    foreach (var x in Json.Arr(fd["top"]) ?? new object[0]) { var e = Json.Obj(x); if (e != null) f.TopEvidence.Add(Ev(e)); }
                    foreach (var x in Json.Arr(fd["steps"]) ?? new object[0])
                    {
                        var s = Json.Obj(x); if (s == null) continue;
                        ActionType at; if (!Enum.TryParse(Json.Str(s, "type"), out at)) continue;
                        f.Steps.Add(new RemediationStep { Type = at, EntityId = Json.Str(s, "entity"), Description = Json.Str(s, "desc"), Target = Json.Str(s, "target"), Reversible = Json.Bool(s, "rev", true), RecommendedByDefault = Json.Bool(s, "def", true), Order = Json.Int(s, "order") });
                    }
                    r.Findings.Add(f);
                }
                foreach (var x in Json.Arr(d["notes"]) ?? new object[0]) { var e = Json.Obj(x); if (e != null) r.Observations.Add(En(e)); }
                foreach (var b in Json.Strs(d, "blind")) { int i = b.IndexOf(": "); r.BlindSpots.Add(i > 0 ? new BlindSpot(b.Substring(0, i), b.Substring(i + 2)) : new BlindSpot("", b)); }
                return r;
            }
            catch (Exception ex) { Log.Warn("last scan not read: " + ex.Message); return null; }
        }
    }
}
