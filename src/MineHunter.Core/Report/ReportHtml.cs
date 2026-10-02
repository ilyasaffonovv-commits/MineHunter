using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using MineHunter.Model;
using MineHunter.Risk;
using MineHunter.Util;

namespace MineHunter.Report
{
    /// <summary>A self-contained HTML copy of the report (one file, no scripts, no network): easy to read, to print and to send to someone who helps.</summary>
    public static class ReportHtml
    {
        static string E(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        static string Color(Verdict v) { switch (v) { case Verdict.Malware: return "#e5384b"; case Verdict.HighRisk: return "#ff8a3d"; case Verdict.Suspicious: return "#e0a526"; default: return "#8e99ba"; } }

        public static string Build(ScanResult r, IList<FindingOutcome> outcomes = null)
        {
            var sb = new StringBuilder();
            int m = r.Findings.Count(f => f.Verdict == Verdict.Malware), h = r.Findings.Count(f => f.Verdict == Verdict.HighRisk), s = r.Findings.Count(f => f.Verdict == Verdict.Suspicious);
            sb.Append("<!doctype html><html lang=\"" + (Loc.Ru ? "ru" : "en") + "\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>MineHunter - " + E(Loc.T("report.title")) + "</title><style>");
            sb.Append("body{margin:0;background:#0e1220;color:#e8ecf7;font:14px/1.5 Segoe UI,Arial,sans-serif}.w{max-width:960px;margin:0 auto;padding:28px 20px}h1{font-size:24px;margin:0 0 4px}h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:#8e99ba;margin:26px 0 8px}");
            sb.Append(".muted{color:#8e99ba}.cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}.card{background:#161b2e;border:1px solid #2a3253;border-radius:12px;padding:12px 16px;min-width:130px}.card b{display:block;font-size:26px}");
            sb.Append(".f{background:#161b2e;border:1px solid #2a3253;border-left:5px solid #4c8dff;border-radius:12px;padding:14px 18px;margin:12px 0}.tag{display:inline-block;border-radius:10px;padding:2px 10px;font-size:12px;font-weight:700;margin-right:6px}");
            sb.Append("code,.mono{font-family:Consolas,monospace;font-size:12.5px;color:#c9d2ee;word-break:break-all}li{margin:3px 0}table{border-collapse:collapse;width:100%}td{padding:3px 8px;border-bottom:1px solid #232b4a;vertical-align:top}</style></head><body><div class=\"w\">");
            sb.Append("<h1>MineHunter " + E(r.AppVersion) + " &mdash; " + E(Loc.T("report.title")) + "</h1>");
            sb.Append("<div class=\"muted\">" + E(r.Status.OsVersion) + " &middot; " + E(r.Status.Machine) + " &middot; " + E(r.Mode) + " &middot; " + r.Stats.Seconds.ToString("0") + " s &middot; " + E(r.Started.ToString("yyyy-MM-dd HH:mm")) + (r.Aborted ? " &middot; <b>" + E(Loc.L("cancelled", "отменена")) + "</b>" : "") + "</div>");
            sb.Append("<div class=\"cards\">");
            sb.Append("<div class=\"card\" style=\"border-color:#e5384b55\"><b style=\"color:#e5384b\">" + m + "</b>" + E(Loc.Severity(Verdict.Malware)) + "</div>");
            sb.Append("<div class=\"card\"><b style=\"color:#ff8a3d\">" + h + "</b>" + E(Loc.Severity(Verdict.HighRisk)) + "</div>");
            sb.Append("<div class=\"card\"><b style=\"color:#e0a526\">" + s + "</b>" + E(Loc.Severity(Verdict.Suspicious)) + "</div>");
            sb.Append("<div class=\"card\"><b style=\"color:#8e99ba\">" + r.Observations.Count + "</b>" + E(Loc.T("report.notes")) + "</div></div>");
            if (r.Findings.Count == 0) sb.Append("<p>" + E(Loc.T("report.nothing")) + "</p>");
            foreach (var f in r.Findings)
            {
                var oc = outcomes == null ? null : outcomes.FirstOrDefault(o => o.FindingId == f.Id);
                string c = Color(f.Verdict);
                string state = ReportWriter.StateTag(f, oc);
                sb.Append("<div class=\"f\" style=\"border-left-color:" + c + "\"><span class=\"tag\" style=\"background:" + c + "33;color:" + c + "\">" + E(Loc.Severity(f.Verdict).ToUpperInvariant()) + "</span>");
                if (state != null) sb.Append("<span class=\"tag\" style=\"background:#2ecc8f33;color:#2ecc8f\">" + E(state) + "</span>");
                sb.Append("<b>" + E(Loc.Title(f.Title)) + "</b> <span class=\"muted\">(" + E(Loc.L("score", "балл")) + " " + f.Score + ")</span>");
                sb.Append("<h2>" + E(Loc.T("report.why")) + "</h2><ul>");
                foreach (var e in f.TopEvidence) sb.Append("<li>" + (e.Weight >= 0 ? "+" : "") + e.Weight + " <span class=\"muted\">[" + E(Loc.CategoryName(e.Category)) + "]</span> " + E(Loc.Ev(e)) + (string.IsNullOrEmpty(e.Detail) ? "" : " <span class=\"mono\">" + E(Text.Trunc(e.Detail, 140)) + "</span>") + "</li>");
                sb.Append("</ul><h2>" + E(Loc.T("report.chain")) + "</h2><pre class=\"mono\">" + E(string.Join("\n", ThreatGraph.Render(f, true))) + "</pre>");
                var files = f.Entities.Where(x => !string.IsNullOrEmpty(x.Sha256)).ToList();
                if (files.Count > 0) { sb.Append("<h2>SHA-256</h2><table>"); foreach (var x in files) sb.Append("<tr><td class=\"mono\">" + E(x.Sha256) + "</td><td class=\"mono\">" + E(x.Location) + "</td></tr>"); sb.Append("</table>"); }
                sb.Append("<h2>" + E(Loc.T("report.action")) + "</h2><div>" + E(Loc.Recommendation(f)) + "</div>");
                if (oc != null) sb.Append("<div class=\"muted\" style=\"margin-top:8px\">" + E(Loc.T("report.result")) + ": " + E(oc.Verdict) + (oc.RescanNote != null ? " &mdash; " + E(Loc.RescanNote(oc.RescanNote)) : "") + "</div>");
                sb.Append("</div>");
            }
            if (r.Observations.Count > 0)
            {
                sb.Append("<h2>" + E(Loc.T("report.notes.head")) + "</h2><table>");
                foreach (var o in r.Observations.Take(60)) sb.Append("<tr><td>" + o.Score + "</td><td>" + E(Loc.KindName(o.Kind)) + "</td><td>" + E(o.Title) + "</td><td class=\"mono\">" + E(Text.Trunc(o.Location, 100)) + "</td></tr>");
                sb.Append("</table>");
            }
            sb.Append("<h2>" + E(Loc.T("report.blind")) + "</h2><ul>");
            foreach (var b in r.BlindSpots.Take(60)) sb.Append("<li>" + E(b.Area) + ": " + E(b.Reason) + "</li>");
            if (r.BlindSpots.Count == 0) sb.Append("<li>-</li>");
            sb.Append("</ul><p class=\"muted\">" + E(Loc.T("report.privacy")) + "</p></div></body></html>");
            return sb.ToString();
        }

        public static string Write(ScanResult r, IList<FindingOutcome> outcomes, string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
            File.WriteAllText(path, Build(r, outcomes), new UTF8Encoding(true));
            return path;
        }
    }
}
