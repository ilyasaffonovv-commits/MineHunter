using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Runs one scan at a time for a program and tells it when it is over. The main window, Quick Scan.exe, Full Scan.exe and the scheduled scan all use this one class, so a
    /// scan started anywhere is the same scan. A second scan (even from another MineHunter program) is refused while one runs.</summary>
    public sealed class ScanController
    {
        public ScanProgress Live { get; private set; }
        public ScanRun LastRun { get; private set; }
        public ScanMode Mode { get; private set; }
        public string Trigger { get; private set; }
        public bool Running { get { return running; } }
        public string Error { get; private set; }
        public bool CancelRequested { get; private set; }
        public event Action<ScanRun> Finished;

        volatile bool running;
        CancellationTokenSource cts;
        FileStream global;      // an exclusive lock file: held while a scan runs, so no other MineHunter program starts one at the same time (released by the OS if the program dies)

        /// <summary>Starts a scan. Returns false (and sets Error) when one is already running here or in another MineHunter program.</summary>
        public bool Start(ScanMode mode, string trigger, AppConfig cfg, Settings settings, IEnumerable<string> paths = null)
        {
            Error = null;
            if (running) { Error = Loc.L("A scan is already running.", "Проверка уже идёт."); return false; }
            try
            {
                Directory.CreateDirectory(RulePack.DataDir);
                global = new FileStream(Path.Combine(RulePack.DataDir, "scan-running.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) { Error = Loc.L("Another MineHunter program is scanning right now. Wait until it finishes.", "Сейчас сканирует другая программа MineHunter. Дождитесь окончания."); return false; }
            catch (UnauthorizedAccessException) { Error = Loc.L("Another MineHunter program is scanning right now. Wait until it finishes.", "Сейчас сканирует другая программа MineHunter. Дождитесь окончания."); return false; }
            Mode = mode; Trigger = trigger; CancelRequested = false;
            Live = new ScanProgress();
            cts = new CancellationTokenSource(); var ct = cts.Token;
            running = true;
            var live = Live;
            Task.Run(() =>
            {
                ScanRun run = null; Exception err = null;
                try { run = ScanRunner.Run(mode, trigger, cfg, settings, live, ct, null, paths); }
                catch (Exception ex) { err = ex; Log.Error("scan failed: " + ex); }
                if (err != null) Error = err.GetBaseException().Message;
                LastRun = run; running = false;
                try { global.Dispose(); } catch { }
                var h = Finished; if (h != null) { try { h(run); } catch (Exception ex) { Log.Warn("scan finished handler: " + ex.Message); } }
            });
            return true;
        }

        public void Cancel() { if (running && cts != null) { CancelRequested = true; cts.Cancel(); } }
    }

    public sealed class NeutralizeResult
    {
        public List<FindingOutcome> Outcomes = new List<FindingOutcome>();
        public ScanResult Rescan;
        public string ReportTxt;
        public bool RebootRequired { get { return Outcomes.Any(o => o.Outcome != null && o.Outcome.RebootRequired); } }
        public bool AllOk { get { return Outcomes.All(o => o.Verdict == "Remediated" || o.Verdict == "RebootRequired"); } }
    }

    /// <summary>Neutralising findings: one cleanup at a time on the whole PC, a restore point first, the programs to stop frozen first, every step reversible through the quarantine, and a
    /// new scan afterwards that confirms the result.</summary>
    public static class Neutralizer
    {
        /// <summary>What "Neutralize all" does: every High Risk / Critical finding with the steps that are recommended by default (never a game cheat, never review-only steps).</summary>
        public static List<KeyValuePair<Finding, List<RemediationStep>>> DefaultPlan(ScanResult r)
        {
            return r.Findings.Where(f => f.Verdict >= Verdict.HighRisk).Select(f => new KeyValuePair<Finding, List<RemediationStep>>(f, f.Steps.Where(s => s.RecommendedByDefault && s.Type != ActionType.ReviewOnly).ToList())).Where(kv => kv.Value.Count > 0).ToList();
        }

        public static NeutralizeResult Run(ScanResult original, ScanOptions opt, List<KeyValuePair<Finding, List<RemediationStep>>> plan, AppConfig cfg, Action<string> status, Action<string, int> progress, CancellationToken ct)
        {
            var result = new NeutralizeResult();
            var ctx = ScanEngine.LastContext ?? new ScanContext(RulePack.Load(), Allowlist.Load(), opt ?? new ScanOptions(), ct);
            using (var cleanLock = RemediationEngine.CleanupLock())
            {
                if (cleanLock == null) throw new InvalidOperationException(Loc.L("Another MineHunter is cleaning this computer right now. Nothing was changed.", "Другой MineHunter сейчас лечит этот компьютер. Ничего не изменено."));
                if (cfg != null && cfg.CreateRestorePoint)
                {
                    if (status != null) status(Loc.L("Asking Windows for a restore point…", "Прошу Windows создать точку восстановления…"));
                    Log.Info("Restore point: " + SafetyNet.TryCreateRestorePoint("MineHunter: cleaning " + plan.Count + " finding(s)"));
                }
                // every process that is going to be stopped is frozen first, so that a second program of the same infection cannot put things back meanwhile
                var frozen = RemediationEngine.FreezeProcesses(plan.SelectMany(kv => kv.Value), m => Log.Info("   " + m));
                try
                {
                    foreach (var kv in plan)
                    {
                        if (status != null) status(Loc.Title(kv.Key.Title));
                        var oc = RemediationEngine.Execute(ctx, kv.Key, kv.Value, m => Log.Info("   " + m));
                        result.Outcomes.Add(new FindingOutcome { FindingId = kv.Key.Id, Outcome = oc });
                    }
                }
                finally { RemediationEngine.ResumeProcesses(frozen); }
                if (status != null) status(Loc.L("Checking the result with a new scan…", "Проверяю результат новой проверкой…"));
                result.Rescan = Verifier.Rescan(opt ?? new ScanOptions(), original.Findings, result.Outcomes, ct, progress ?? ((s, p) => { }));
                try { result.ReportTxt = ReportWriter.Write(original, result.Outcomes, ReportWriter.DefaultDir); } catch { }
            }
            return result;
        }
    }
}
