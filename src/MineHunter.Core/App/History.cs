using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MineHunter.Model;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter
{
    public sealed class HistoryEntry
    {
        public string Id, Started, Mode, Trigger, ReportTxt, ReportJson, ReportHtml, RulesVersion, AppVersion;
        public double Seconds; public int Critical, High, Medium, Notes; public long Objects; public bool Aborted;
        public List<string> Titles = new List<string>();

        public DateTime StartedTime { get { DateTime d; return DateTime.TryParse(Started, null, System.Globalization.DateTimeStyles.RoundtripKind, out d) ? d : DateTime.MinValue; } }
        public int Threats { get { return Critical + High + Medium; } }
    }

    /// <summary>Scan history: one line per finished scan (when, which kind, how long, what was found, where the report is). Kept in the protected data folder.</summary>
    public static class History
    {
        public static string FilePath { get { return Path.Combine(RulePack.DataDir, "history.json"); } }
        const int Max = 400;
        static readonly object Lock = new object();

        public static HistoryEntry FromResult(ScanResult r, string trigger, string reportTxt)
        {
            var e = new HistoryEntry
            {
                Id = Guid.NewGuid().ToString("N").Substring(0, 12),
                Started = r.Started.ToString("o"),
                Mode = r.Mode, Trigger = trigger ?? "manual", Seconds = r.Stats.Seconds, RulesVersion = r.RulesVersion, AppVersion = r.AppVersion,
                Critical = r.Findings.Count(f => f.Verdict == Verdict.Malware), High = r.Findings.Count(f => f.Verdict == Verdict.HighRisk), Medium = r.Findings.Count(f => f.Verdict == Verdict.Suspicious),
                Notes = r.Observations.Count, Aborted = r.Aborted,
                Objects = (long)r.Stats.ProcessesScanned + r.Stats.ModulesChecked + r.Stats.FilesInspected + r.Stats.FilesSkippedByCache + r.Stats.ServicesScanned + r.Stats.TasksScanned + r.Stats.RunEntries + r.Stats.WmiObjects + r.Stats.BrowserExtensions,
                ReportTxt = reportTxt
            };
            if (!string.IsNullOrEmpty(reportTxt)) { e.ReportJson = Path.ChangeExtension(reportTxt, ".json"); e.ReportHtml = Path.ChangeExtension(reportTxt, ".html"); }
            e.Titles = r.Findings.Take(8).Select(f => Loc.Title(f.Title)).ToList();
            return e;
        }

        public static List<HistoryEntry> List()
        {
            lock (Lock)
            {
                var list = new List<HistoryEntry>();
                try
                {
                    if (!File.Exists(FilePath)) return list;
                    var d = Json.Obj(Json.Parse(File.ReadAllText(FilePath)));
                    foreach (var o in Json.Arr(d != null && d.ContainsKey("entries") ? d["entries"] : null) ?? new object[0])
                    {
                        var x = Json.Obj(o); if (x == null) continue;
                        list.Add(new HistoryEntry
                        {
                            Id = Json.Str(x, "id"), Started = Json.Str(x, "started"), Mode = Json.Str(x, "mode"), Trigger = Json.Str(x, "trigger"), ReportTxt = Json.Str(x, "reportTxt"), ReportJson = Json.Str(x, "reportJson"), ReportHtml = Json.Str(x, "reportHtml"),
                            RulesVersion = Json.Str(x, "rules"), AppVersion = Json.Str(x, "version"), Seconds = double.Parse(Json.Str(x, "seconds", "0"), System.Globalization.CultureInfo.InvariantCulture),
                            Critical = Json.Int(x, "critical"), High = Json.Int(x, "high"), Medium = Json.Int(x, "medium"), Notes = Json.Int(x, "notes"), Objects = Json.Int(x, "objects"), Aborted = Json.Bool(x, "aborted"), Titles = Json.Strs(x, "titles")
                        });
                    }
                }
                catch (Exception ex) { Log.Warn("history: " + ex.Message); }
                return list.OrderByDescending(e => e.StartedTime).ToList();
            }
        }

        public static void Add(HistoryEntry e)
        {
            lock (Lock)
            {
                var all = List();
                all.Insert(0, e);
                Save(all.Take(Max).ToList());
            }
        }

        public static void Clear() { lock (Lock) Save(new List<HistoryEntry>()); }

        static void Save(List<HistoryEntry> list)
        {
            try
            {
                var arr = list.Select(e => (object)new Dictionary<string, object>
                {
                    { "id", e.Id }, { "started", e.Started }, { "mode", e.Mode }, { "trigger", e.Trigger }, { "reportTxt", e.ReportTxt }, { "reportJson", e.ReportJson }, { "reportHtml", e.ReportHtml }, { "rules", e.RulesVersion }, { "version", e.AppVersion },
                    { "seconds", e.Seconds.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) }, { "critical", e.Critical }, { "high", e.High }, { "medium", e.Medium }, { "notes", e.Notes }, { "objects", e.Objects }, { "aborted", e.Aborted }, { "titles", e.Titles.ToArray() }
                }).ToArray();
                Directory.CreateDirectory(RulePack.DataDir);
                Fs.WriteDurable(FilePath, new System.Text.UTF8Encoding(false).GetBytes(Json.Pretty(Json.Serialize(new Dictionary<string, object> { { "entries", arr } }))));
            }
            catch (Exception ex) { Log.Warn("history not saved: " + ex.Message); }
        }

        /// <summary>The last finished (not cancelled) scan of a kind.</summary>
        public static HistoryEntry Last(string mode = null)
        {
            return List().FirstOrDefault(e => !e.Aborted && (mode == null || e.Mode == mode));
        }
    }
}
