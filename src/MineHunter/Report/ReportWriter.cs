using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Report
{
    public sealed class FindingOutcome
    {
        public string FindingId;
        public RemediationOutcome Outcome;
        public string Verdict;        // Remediated / Partial / RebootRequired / Failed / NotAttempted
        public List<string> StillPresent = new List<string>();
        public string RescanNote;
    }

    public static class ReportWriter
    {
        public static string DefaultDir { get { return Path.Combine(RulePack.DataDir, "Reports"); } }

        static Dictionary<string, object> EvidenceJson(Evidence e)
        {
            return new Dictionary<string, object> { { "rule", e.RuleId }, { "category", e.Category.ToString() }, { "weight", e.Weight }, { "definitive", e.Definitive }, { "text", e.Text }, { "textLocalized", Loc.Ev(e) }, { "detail", e.Detail } };
        }

        public static Dictionary<string, object> ToJson(ScanResult r, IList<FindingOutcome> outcomes = null)
        {
            var findings = new List<object>();
            foreach (var f in r.Findings)
            {
                var oc = outcomes == null ? null : outcomes.FirstOrDefault(o => o.FindingId == f.Id);
                var d = new Dictionary<string, object>
                {
                    { "id", f.Id }, { "title", f.Title }, { "titleLocalized", Loc.Title(f.Title) }, { "verdict", f.Verdict.ToString() }, { "score", f.Score }, { "recommendation", f.Recommendation }, { "whyNotHigher", f.WhyNotHigher },
                    { "evidence", f.TopEvidence.Select(EvidenceJson).ToArray() },
                    { "chain", f.ChainLines.ToArray() },
                    { "entities", f.Entities.Select(e => new Dictionary<string, object> { { "id", e.Id }, { "kind", e.Kind.ToString() }, { "title", e.Title }, { "location", e.Location }, { "sha256", e.Sha256 }, { "score", e.Score }, { "trusted", e.Trusted }, { "props", e.Props.Where(p => p.Key != "sections" && p.Key != "imports").ToDictionary(p => p.Key, p => (object)p.Value) }, { "evidence", e.Evidence.Where(x => x.Weight != 0).Select(EvidenceJson).ToArray() } }).ToArray() },
                    { "recommendedSteps", f.Steps.Select(s => new Dictionary<string, object> { { "type", s.Type.ToString() }, { "description", s.Description }, { "target", s.Target }, { "reversible", s.Reversible }, { "recommended", s.RecommendedByDefault } }).ToArray() }
                };
                if (oc != null)
                    d["remediation"] = new Dictionary<string, object>
                    {
                        { "result", oc.Verdict }, { "rescan", oc.RescanNote }, { "stillPresent", oc.StillPresent.ToArray() },
                        { "rebootRequired", oc.Outcome != null && oc.Outcome.RebootRequired },
                        { "steps", oc.Outcome == null ? new object[0] : oc.Outcome.Results.Select(s => new Dictionary<string, object> { { "action", s.Step.Type.ToString() }, { "description", s.Step.Description }, { "success", s.Success }, { "message", s.Message }, { "rebootPending", s.RebootPending }, { "quarantineId", s.QuarantineId } }).ToArray() }
                    };
                findings.Add(d);
            }
            var root = new Dictionary<string, object>
            {
                { "app", "MineHunter" }, { "version", r.AppVersion }, { "generated", DateTime.Now.ToString("o") },
                { "privacy", "Generated locally. Nothing is uploaded anywhere." },
                { "system", new Dictionary<string, object> { { "os", r.Status.OsVersion }, { "machine", r.Status.Machine }, { "user", r.Status.User }, { "administrator", r.Status.IsAdmin }, { "protection", r.Status.DefenderState }, { "postureWarnings", r.Status.PostureWarnings.Select(x => x.Contains("|") ? x.Substring(x.IndexOf('|') + 1) : x).ToArray() } } },
                { "scan", new Dictionary<string, object> { { "mode", r.Mode }, { "started", r.Started.ToString("o") }, { "finished", r.Finished.ToString("o") }, { "seconds", r.Stats.Seconds }, { "rulesVersion", r.RulesVersion }, { "aborted", r.Aborted }, { "abortReason", r.AbortReason } } },
                { "scanned", new Dictionary<string, object> { { "processes", r.Stats.ProcessesScanned }, { "loadedLibraries", r.Stats.ModulesChecked }, { "filesInspected", r.Stats.FilesInspected }, { "filesSkippedByCache", r.Stats.FilesSkippedByCache }, { "filesHashed", r.Stats.FilesHashed }, { "megabytesRead", r.Stats.BytesRead / 1048576 }, { "services", r.Stats.ServicesScanned }, { "scheduledTasks", r.Stats.TasksScanned }, { "autorunEntries", r.Stats.RunEntries }, { "wmiObjects", r.Stats.WmiObjects }, { "browserExtensions", r.Stats.BrowserExtensions }, { "externalConnections", r.Stats.Connections }, { "accessDenied", r.Stats.AccessDenied }, { "entities", r.EntitiesTotal } } },
                { "summary", new Dictionary<string, object> { { "malware", r.Findings.Count(f => f.Verdict == Verdict.Malware) }, { "highRisk", r.Findings.Count(f => f.Verdict == Verdict.HighRisk) }, { "suspicious", r.Findings.Count(f => f.Verdict == Verdict.Suspicious) }, { "lowRiskNotes", r.Observations.Count } } },
                { "findings", findings.ToArray() },
                { "lowRiskNotes", r.Observations.Select(o => new Dictionary<string, object> { { "kind", o.Kind.ToString() }, { "title", o.Title }, { "location", o.Location }, { "score", o.Score }, { "evidence", o.Evidence.Where(x => x.Weight > 0).Select(EvidenceJson).ToArray() } }).ToArray() },
                { "blindSpots", r.BlindSpots.Select(b => b.Area + ": " + b.Reason).ToArray() },
                { "selfProtection", new Dictionary<string, object> { { "notes", r.PreviousScanIssues.ToArray() }, { "exeSha256AtStart", r.SelfHash }, { "exeSha256AtEnd", r.SelfHashEnd } } }
            };
            return root;
        }

        public static string ToText(ScanResult r, IList<FindingOutcome> outcomes = null)
        {
            var sb = new StringBuilder();
            string line = new string('=', 78);
            sb.AppendLine(line);
            sb.AppendLine(" MineHunter " + r.AppVersion + " - " + Loc.T("report.title"));
            sb.AppendLine(line);
            sb.AppendLine(" " + Loc.T("report.generated") + ": " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine(" " + Loc.T("report.os") + ": " + r.Status.OsVersion + "   " + r.Status.Machine + " \\ " + r.Status.User + (r.Status.IsAdmin ? "  (administrator)" : "  (NOT administrator)"));
            sb.AppendLine(" " + Loc.T("report.protection") + ": " + r.Status.DefenderState);
            foreach (var w in r.Status.PostureWarnings) sb.AppendLine("   ! " + Loc.Posture(w));
            sb.AppendLine(" " + Loc.T("report.scan") + ": " + r.Mode + ", " + r.Stats.Seconds + " s, rules " + r.RulesVersion + (r.Aborted ? "  [" + r.AbortReason + "]" : ""));
            sb.AppendLine(" " + Loc.T("report.scanned") + ": " + r.Stats.ProcessesScanned + " processes, " + r.Stats.ModulesChecked + " loaded libraries, " + r.Stats.FilesInspected + " files (+" + r.Stats.FilesSkippedByCache + " skipped by cache), " + r.Stats.ServicesScanned + " services, " + r.Stats.TasksScanned + " scheduled tasks, " + r.Stats.RunEntries + " autorun entries, " + r.Stats.WmiObjects + " WMI objects, " + r.Stats.BrowserExtensions + " browser extensions");
            sb.AppendLine(line);
            int m = r.Findings.Count(f => f.Verdict == Verdict.Malware), h = r.Findings.Count(f => f.Verdict == Verdict.HighRisk), s = r.Findings.Count(f => f.Verdict == Verdict.Suspicious);
            sb.AppendLine(" " + Loc.T("report.summary") + ":  MALWARE " + m + "   HIGH RISK " + h + "   SUSPICIOUS " + s + "   " + Loc.T("report.notes") + " " + r.Observations.Count);
            sb.AppendLine(line);
            if (r.Findings.Count == 0) sb.AppendLine("\n " + Loc.T("report.nothing") + "\n");
            foreach (var f in r.Findings)
            {
                sb.AppendLine();
                sb.AppendLine(" [" + f.Verdict.ToString().ToUpperInvariant() + "  score " + f.Score + "]  " + f.Id + "  " + Loc.Title(f.Title));
                sb.AppendLine(" " + new string('-', 74));
                sb.AppendLine("   " + Loc.T("report.why") + ":");
                foreach (var e in f.TopEvidence) sb.AppendLine("     " + (e.Weight >= 0 ? "+" : "") + e.Weight + "  [" + e.Category + "]  " + Loc.Ev(e) + (string.IsNullOrEmpty(e.Detail) ? "" : "   {" + Text.Trunc(e.Detail, 140) + "}") + (e.Definitive ? "  (definitive)" : ""));
                if (!string.IsNullOrEmpty(f.WhyNotHigher)) sb.AppendLine("   " + Loc.T("report.capped") + ": " + Loc.WhyNotHigher(f.WhyNotHigher));
                sb.AppendLine("   " + Loc.T("report.chain") + ":");
                foreach (var c in ThreatGraph.Render(f, true)) sb.AppendLine("     " + c);
                sb.AppendLine("   " + Loc.T("report.hashes") + ":");
                foreach (var e in f.Entities.Where(x => !string.IsNullOrEmpty(x.Sha256))) sb.AppendLine("     " + e.Sha256 + "  " + e.Location);
                sb.AppendLine("   " + Loc.T("report.action") + ": " + Loc.Recommendation(f));
                foreach (var st in f.Steps) sb.AppendLine("     - " + (st.RecommendedByDefault ? "[recommended] " : "[optional]    ") + st.Description);
                var oc = outcomes == null ? null : outcomes.FirstOrDefault(o => o.FindingId == f.Id);
                if (oc != null)
                {
                    sb.AppendLine("   " + Loc.T("report.result") + ": " + oc.Verdict + (oc.RescanNote != null ? " - " + oc.RescanNote : ""));
                    if (oc.Outcome != null) foreach (var st in oc.Outcome.Results) sb.AppendLine("     " + (st.Success ? "[OK]     " : "[FAILED] ") + st.Step.Description + (string.IsNullOrEmpty(st.Message) ? "" : " - " + st.Message));
                    foreach (var p in oc.StillPresent) sb.AppendLine("     still present: " + p);
                    if (oc.Outcome != null && oc.Outcome.RebootRequired) sb.AppendLine("     ** " + Loc.T("report.reboot") + " **");
                }
            }
            if (r.Observations.Count > 0)
            {
                sb.AppendLine(); sb.AppendLine(" " + Loc.T("report.notes.head")); sb.AppendLine(" " + new string('-', 74));
                foreach (var o in r.Observations.Take(40)) sb.AppendLine("   (" + o.Score + ") " + o.Kind + " " + o.Title + "  " + Text.Trunc(o.Location, 90));
            }
            sb.AppendLine(); sb.AppendLine(line);
            sb.AppendLine(" " + Loc.T("report.blind"));
            if (r.BlindSpots.Count == 0) sb.AppendLine("   -");
            foreach (var b in r.BlindSpots.Take(80)) sb.AppendLine("   * " + b.Area + ": " + b.Reason);
            if (r.BlindSpots.Count > 80) sb.AppendLine("   ... and " + (r.BlindSpots.Count - 80) + " more");
            if (r.PreviousScanIssues.Count > 0) { sb.AppendLine(" " + Loc.T("report.selfprot")); foreach (var i in r.PreviousScanIssues) sb.AppendLine("   ! " + i); }
            sb.AppendLine(line);
            sb.AppendLine(" " + Loc.T("report.privacy"));
            return sb.ToString();
        }

        public static string Write(ScanResult r, IList<FindingOutcome> outcomes, string dir)
        {
            if (string.IsNullOrEmpty(dir)) dir = DefaultDir;
            Directory.CreateDirectory(dir);
            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string j = Path.Combine(dir, "report-" + stamp + ".json");
            string t = Path.Combine(dir, "report-" + stamp + ".txt");
            File.WriteAllText(j, Json.Pretty(Json.Serialize(ToJson(r, outcomes))), new UTF8Encoding(false));
            File.WriteAllText(t, ToText(r, outcomes), new UTF8Encoding(true));
            // stable names for tools that want "the latest report"
            try { File.Copy(j, Path.Combine(dir, "report.json"), true); File.Copy(t, Path.Combine(dir, "report.txt"), true); } catch { }
            return t;
        }
    }
}
