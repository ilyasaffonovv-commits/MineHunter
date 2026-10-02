using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    public sealed class ScanRun
    {
        public ScanResult Result;
        public ScanOptions Options;
        public string ReportTxt, ReportHtml;
        public HistoryEntry Entry;
    }

    /// <summary>Runs one scan the way every front end needs it: the engine, then the report files (txt, json, html), the history entry and the "last scan" memory.
    /// Quick Scan.exe, Full Scan.exe, the main window, the scheduled scan and the command line all call exactly this.</summary>
    public static class ScanRunner
    {
        public static ScanRun Run(ScanMode mode, string trigger, AppConfig cfg, Settings settings, ScanProgress live, CancellationToken ct, Action<string, int> progress, IEnumerable<string> paths = null)
        {
            var opt = ScanProfiles.Build(mode, settings, cfg, paths, live);
            return Run(opt, trigger, settings, ct, progress);
        }

        public static ScanRun Run(ScanOptions opt, string trigger, Settings settings, CancellationToken ct, Action<string, int> progress)
        {
            var run = new ScanRun { Options = opt };
            var res = ScanEngine.Run(opt, ct, progress);
            run.Result = res;
            try
            {
                run.ReportTxt = ReportWriter.Write(res, null, ReportWriter.DefaultDir);
                run.ReportHtml = ReportHtml.Write(res, null, Path.ChangeExtension(run.ReportTxt, ".html"));
                if (!res.Aborted) ResultSnapshot.Save(res);
            }
            catch (Exception ex) { Log.Warn("report: " + ex.Message); }
            try
            {
                run.Entry = History.FromResult(res, trigger, run.ReportTxt);
                History.Add(run.Entry);
                if (!res.Aborted && settings != null)
                {
                    if (res.Mode == "Quick") settings.LastQuickScan = DateTime.Now.ToString("o");
                    else if (res.Mode == "Full") settings.LastFullScan = DateTime.Now.ToString("o");
                    settings.Save();
                }
            }
            catch (Exception ex) { Log.Warn("history: " + ex.Message); }
            return run;
        }
    }
}
