using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter
{
    public static class Cli
    {
        static TextWriter O { get { return Console.Out; } }

        public static string Help()
        {
            return @"MineHunter " + AppInfo.Version + @" - local anti-miner / persistence hunter (no telemetry)

  MineHunter.exe                          open the window (auto-scan on start)
  MineHunter.exe scan [options]           scan from the command line
        --quick | --full | --path <dir>   scope (default: --quick)
        --fix                             neutralise findings (default: High Risk and Malware; asks nothing only with --yes)
        --yes                             do not ask for confirmation
        --min suspicious|high|malware     lowest verdict that --fix touches (default: high)
        --only <text>                     with --fix: touch only findings whose files/paths/names contain <text>
        --all-steps                       also run optional steps (default: recommended steps only)
        --report-dir <dir>                where report.json / report.txt go (default: %ProgramData%\MineHunter\Reports)
        --json <file>                     also copy the JSON report to <file>
        --dump <file>                     research: write every scanned entity with its evidence (JSON)
        --no-browsers  --no-memory  --no-files  --no-cache  --sample-ms <n>  --quiet
  MineHunter.exe quarantine list | restore <id> [--to <path>] | delete <id> | delete-all
  MineHunter.exe allow <path>             approve a file (allow-list by SHA-256 and path)
  MineHunter.exe update-check | update-rules
  MineHunter.exe rules-info               show the loaded rule packs
  MineHunter.exe markers <file>           list every miner marker (rule-pack string) found inside a file - explains 'Cryptominer files' findings
  MineHunter.exe selftest                 built-in self checks
  MineHunter.exe --gen-signing-keys <dir> | --sign <file> <private.xml>      (maintainers)
  MineHunter.exe --version | --help

Exit codes: 0 clean, 1 suspicious found, 2 high-risk/malware found, 3 error, 4 confirmation needed.";
        }

        public static int Run(string[] args, AppConfig cfg)
        {
            try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
            string cmd = args[0].ToLowerInvariant();
            try
            {
                switch (cmd)
                {
                    case "--help": case "-h": case "/?": case "help": O.WriteLine(Help()); return 0;
                    case "--version": case "-v": case "version": O.WriteLine("MineHunter " + AppInfo.Version); return 0;
                    case "scan": return Scan(args.Skip(1).ToArray(), cfg);
                    case "quarantine": return QuarantineCmd(args.Skip(1).ToArray());
                    case "allow": return Allow(args.Skip(1).ToArray());
                    case "update-check": return UpdateCheck(cfg, false);
                    case "update-rules": return UpdateCheck(cfg, true);
                    case "rules-info": return RulesInfo();
                    case "markers": return Markers(args.Skip(1).ToArray());
                    case "selftest": return SelfTest.Run(O);
                    case "--gen-signing-keys": Updater.GenerateKeys(args.Length > 1 ? args[1] : "."); O.WriteLine("keys written. KEEP update_private.xml SECRET; put the content of update_public.xml into config.json (updatePublicKeyXml)."); return 0;
                    case "--sign": O.WriteLine(Updater.Sign(args[1], args[2])); return 0;
                    default: O.WriteLine("Unknown command: " + args[0] + "\n" + Help()); return 3;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine("ERROR: " + ex.Message); Log.Error(ex.ToString()); return 3; }
        }

        static string Opt(string[] a, string name) { int i = Array.FindIndex(a, x => x.Equals(name, StringComparison.OrdinalIgnoreCase)); return i >= 0 && i + 1 < a.Length ? a[i + 1] : null; }
        static bool Has(string[] a, string name) { return a.Any(x => x.Equals(name, StringComparison.OrdinalIgnoreCase)); }

        static int Scan(string[] a, AppConfig cfg)
        {
            var opt = new ScanOptions();
            if (Has(a, "--full")) opt.Mode = ScanMode.Full;
            string path = Opt(a, "--path"); if (path != null) { opt.Mode = ScanMode.Custom; opt.CustomPath = path; }
            if (Has(a, "--no-browsers")) opt.Browsers = false;
            if (Has(a, "--no-memory")) opt.MemoryInspection = false;
            if (Has(a, "--no-files")) opt.ScanHotDirs = false;
            if (Has(a, "--no-cache")) opt.UseCache = false;
            string ms = Opt(a, "--sample-ms"); int msv; if (ms != null && int.TryParse(ms, out msv)) opt.CpuSampleMs = Math.Max(500, Math.Min(msv, 60000));
            bool quiet = Has(a, "--quiet");
            int lastPct = -1; string lastMsg = "";
            Action<string, int> prog = (s, p) => { if (quiet) return; if (p / 5 != lastPct / 5 || s != lastMsg && p == 100) { lastPct = p; lastMsg = s; Console.Error.WriteLine("  [" + p.ToString().PadLeft(3) + "%] " + s); } };
            O.WriteLine("MineHunter " + AppInfo.Version + "  " + opt.Mode + " scan" + (path != null ? " of " + path : "") + " ...");
            var res = ScanEngine.Run(opt, CancellationToken.None, prog);
            if (!quiet) Print(res);

            List<FindingOutcome> outcomes = null;
            if (Has(a, "--fix"))
            {
                var min = (Opt(a, "--min") ?? "high").ToLowerInvariant();
                Verdict minV = min.StartsWith("susp") ? Verdict.Suspicious : min.StartsWith("mal") ? Verdict.Malware : Verdict.HighRisk;
                var todo = res.Findings.Where(f => f.Verdict >= minV).ToList();
                string only = Opt(a, "--only");
                if (only != null) todo = todo.Where(f => f.Entities.Any(e => (e.Location ?? "").IndexOf(only, StringComparison.OrdinalIgnoreCase) >= 0 || (e.Title ?? "").IndexOf(only, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();
                bool all = Has(a, "--all-steps");
                if (todo.Count == 0) O.WriteLine("\nNothing to neutralise at level '" + min + "' or above.");
                else
                {
                    O.WriteLine("\nPlanned actions:");
                    foreach (var f in todo) { O.WriteLine("  " + f.Id + " [" + f.Verdict + "] " + Loc.Title(f.Title)); foreach (var s in f.Steps.Where(s => s.Type != ActionType.ReviewOnly && (all || s.RecommendedByDefault))) O.WriteLine("     - " + Loc.Step(s)); }
                    if (!Has(a, "--yes")) { O.WriteLine("\nNothing was changed. Add --yes to execute these actions (every action is reversible from quarantine)."); return 4; }
                    outcomes = new List<FindingOutcome>();
                    foreach (var f in todo)
                    {
                        O.WriteLine("\nNeutralising " + f.Id + " ...");
                        var steps = f.Steps.Where(s => s.Type != ActionType.ReviewOnly && (all || s.RecommendedByDefault)).ToList();
                        var oc = RemediationEngine.Execute(ScanEngine.LastContext, f, steps, m => O.WriteLine("   " + m));
                        outcomes.Add(new FindingOutcome { FindingId = f.Id, Outcome = oc });
                    }
                    O.WriteLine("\nRescanning to verify ...");
                    var re = Verifier.Rescan(opt, res.Findings, outcomes, CancellationToken.None, prog);
                    foreach (var oc in outcomes) O.WriteLine("  " + oc.FindingId + ": " + oc.Verdict + " - " + Loc.RescanNote(oc.RescanNote) + (oc.StillPresent.Count > 0 ? "\n       still present: " + string.Join("; ", oc.StillPresent) : ""));
                    O.WriteLine("  Rescan result: " + re.Findings.Count(f => f.Verdict >= Verdict.HighRisk) + " high-risk/malware finding(s) remain, " + re.Findings.Count(f => f.Verdict == Verdict.Suspicious) + " suspicious.");
                    if (outcomes.Any(o => o.Outcome != null && o.Outcome.RebootRequired)) O.WriteLine("  ** Restart Windows to finish the cleanup (locked files are scheduled for deletion). **");
                }
            }
            string rdir = Opt(a, "--report-dir");
            string txt = ReportWriter.Write(res, outcomes, rdir);
            O.WriteLine("\nReport: " + txt + "   (+ report.json in the same folder)");
            string dump = Opt(a, "--dump");
            if (dump != null)
            {
                // research aid: every entity the scan saw, with its evidence (also those that never became a finding)
                var all = ScanEngine.LastContext.Entities.Values.OrderByDescending(e => e.Score).Select(e => new Dictionary<string, object>
                {
                    { "id", e.Id }, { "kind", e.Kind.ToString() }, { "title", e.Title }, { "location", e.Location }, { "score", e.Score }, { "trusted", e.Trusted }, { "sha256", e.Sha256 },
                    { "props", e.Props.Where(p => p.Key != "sections" && p.Key != "imports").ToDictionary(p => p.Key, p => (object)p.Value) },
                    { "evidence", e.Evidence.Select(v => new Dictionary<string, object> { { "rule", v.RuleId }, { "category", v.Category.ToString() }, { "weight", v.Weight }, { "definitive", v.Definitive }, { "text", v.Text }, { "detail", v.Detail } }).ToArray() }
                }).ToArray();
                File.WriteAllText(dump, Json.Pretty(Json.Serialize(all)), new UTF8Encoding(false));
                File.WriteAllText(Path.ChangeExtension(dump, ".links.json"), Json.Pretty(Json.Serialize(ScanEngine.LastContext.Links.Select(l => new Dictionary<string, object> { { "from", l.From }, { "to", l.To }, { "rel", l.Relation } }).ToArray())), new UTF8Encoding(false));
                O.WriteLine("Entity dump: " + dump + " (" + all.Length + " entities)");
            }
            string jcopy = Opt(a, "--json");
            if (jcopy != null) { File.WriteAllText(jcopy, Json.Pretty(Json.Serialize(ReportWriter.ToJson(res, outcomes))), new UTF8Encoding(false)); O.WriteLine("JSON: " + jcopy); }
            return res.Findings.Any(f => f.Verdict >= Verdict.HighRisk) ? 2 : res.Findings.Any() ? 1 : 0;
        }

        public static void Print(ScanResult r)
        {
            O.WriteLine();
            O.WriteLine("Scanned in " + r.Stats.Seconds + " s: " + r.Stats.ProcessesScanned + " processes, " + r.Stats.ModulesChecked + " loaded libraries, " + r.Stats.FilesInspected + " files (+" + r.Stats.FilesSkippedByCache + " cached), " + r.Stats.ServicesScanned + " services, " + r.Stats.TasksScanned + " tasks, " + r.Stats.RunEntries + " autorun entries, " + r.Stats.WmiObjects + " WMI objects, " + r.Stats.BrowserExtensions + " browser extensions");
            foreach (var w in r.Status.PostureWarnings) O.WriteLine("  ! " + Loc.Posture(w));
            O.WriteLine("Result: MALWARE " + r.Findings.Count(f => f.Verdict == Verdict.Malware) + "   HIGH RISK " + r.Findings.Count(f => f.Verdict == Verdict.HighRisk) + "   SUSPICIOUS " + r.Findings.Count(f => f.Verdict == Verdict.Suspicious) + "   notes " + r.Observations.Count);
            foreach (var f in r.Findings)
            {
                O.WriteLine();
                O.WriteLine("[" + Loc.Verdict(f.Verdict) + " " + f.Score + "] " + f.Id + "  " + Loc.Title(f.Title));
                foreach (var e in f.TopEvidence.Take(6)) O.WriteLine("     " + (e.Weight >= 0 ? "+" : "") + e.Weight + "  " + Loc.Ev(e) + (string.IsNullOrEmpty(e.Detail) ? "" : "   {" + Text.Trunc(e.Detail, 100) + "}"));
                foreach (var c in ThreatGraph.Render(f, true).Take(12)) O.WriteLine("     " + c);
                if (f.WhyNotHigher != null) O.WriteLine("     (" + Loc.T("det.capped") + ": " + Loc.WhyNotHigher(f.WhyNotHigher) + ")");
                O.WriteLine("     => " + Loc.Recommendation(f));
            }
            if (r.Observations.Count > 0) { O.WriteLine("\nLow-risk notes (not findings): " + string.Join("; ", r.Observations.Take(8).Select(o => o.Title + " (" + o.Score + ")"))); }
            if (r.BlindSpots.Count > 0) O.WriteLine("\nCould not check (" + r.BlindSpots.Count + "): " + string.Join("; ", r.BlindSpots.Take(4).Select(b => b.Area + ": " + Text.Trunc(b.Reason, 60))) + (r.BlindSpots.Count > 4 ? " ..." : ""));
            foreach (var i in r.PreviousScanIssues) O.WriteLine("! " + i);
        }

        static int QuarantineCmd(string[] a)
        {
            string sub = a.Length > 0 ? a[0].ToLowerInvariant() : "list";
            var items = Quarantine.List();
            if (sub == "list")
            {
                if (items.Count == 0) { O.WriteLine("Quarantine is empty."); return 0; }
                foreach (var it in items) O.WriteLine(it.Id + "  " + it.Type.PadRight(16) + " " + Text.Trunc(it.OriginalPath, 70) + "  (" + it.Created.Substring(0, 19).Replace('T', ' ') + ")  " + Text.Trunc(it.FindingTitle, 40));
                return 0;
            }
            if (sub == "delete-all") { foreach (var it in items) Quarantine.Delete(it); O.WriteLine("Deleted " + items.Count + " item(s)."); return 0; }
            if (a.Length < 2) { O.WriteLine("item id required"); return 3; }
            var item = items.FirstOrDefault(i => i.Id == a[1]);
            if (item == null) { O.WriteLine("No such item."); return 3; }
            if (sub == "delete") { Quarantine.Delete(item); O.WriteLine("Deleted."); return 0; }
            if (sub == "restore") { string err = RemediationEngine.Restore(item, Opt(a, "--to")); if (err == null) { O.WriteLine("Restored " + item.OriginalPath); if (Has(a, "--keep")) { } else Quarantine.Delete(item); return 0; } O.WriteLine("Restore failed: " + err); return 3; }
            O.WriteLine("unknown quarantine command"); return 3;
        }

        static int Allow(string[] a)
        {
            if (a.Length == 0) { O.WriteLine("path required"); return 3; }
            var al = Allowlist.Load();
            string p = PathUtil.Normalize(a[0]);
            al.Paths.Add(p);
            string sha = Hashing.Sha256(p); if (sha != null) al.Sha256.Add(sha);
            al.Save();
            O.WriteLine("Approved: " + p + (sha != null ? "  (SHA-256 " + sha + ")" : ""));
            return 0;
        }

        static int UpdateCheck(AppConfig cfg, bool install)
        {
            var rules = RulePack.Load();
            var u = Updater.Check(cfg, rules.Version);
            O.WriteLine("Version " + AppInfo.Version + "  |  " + u.State + "  |  " + u.Message);
            if (!string.IsNullOrEmpty(u.Latest)) O.WriteLine("Latest: " + u.Latest + "  " + u.ReleaseUrl);
            if (!string.IsNullOrEmpty(u.RulesVersion)) O.WriteLine("Rules: local " + rules.Version + ", online " + u.RulesVersion + (u.RulesNewer ? "  (newer)" : ""));
            if (install && u.RulesNewer) { string err = Updater.UpdateRules(cfg, u); O.WriteLine(err == null ? "Rules updated." : "Rules NOT updated: " + err); return err == null ? 0 : 3; }
            return 0;
        }

        static int Markers(string[] a)
        {
            if (a.Length == 0 || !File.Exists(a[0])) { O.WriteLine("usage: markers <file>"); return 3; }
            var rules = RulePack.Load(); long read;
            var hits = rules.MinerScanner.ScanFile(a[0], 64L * 1024 * 1024, 0, out read);
            O.WriteLine(a[0] + ": " + hits.Count + " distinct marker(s), " + (read / 1024) + " KB read");
            foreach (var id in hits.Keys.OrderBy(x => x)) if (id < rules.ScanIndex.Count) O.WriteLine("  [" + rules.ScanIndex[id].Key + "] " + rules.ScanIndex[id].Value + "  x" + hits[id]);
            return 0;
        }

        static int RulesInfo()
        {
            var r = RulePack.Load();
            O.WriteLine("Rules version " + r.Version);
            foreach (var s in r.Sources) O.WriteLine("  source: " + s);
            O.WriteLine("  command-line rules: " + r.CmdRules.Count + ", miner strings: " + r.MinerStrings.Sum(kv => kv.Value.Count) + ", known-bad hashes: " + r.BadHashes.Count + ", trusted publishers: " + r.TrustedPublishers.Count);
            O.WriteLine("  data folder: " + RulePack.DataDir);
            return 0;
        }
    }
}
