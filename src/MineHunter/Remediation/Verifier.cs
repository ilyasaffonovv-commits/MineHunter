using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using MineHunter.Model;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Remediation
{
    /// <summary>After neutralising: scan again and confirm the infection is really gone (process absent AND file neutralised AND persistence absent
    /// AND no watchdog respawn). A finding is only reported as remediated when the rescan agrees.</summary>
    public static class Verifier
    {
        public static ScanResult Rescan(ScanOptions original, IList<Finding> before, IList<FindingOutcome> outcomes, CancellationToken ct, Action<string, int> progress)
        {
            var opt = new ScanOptions { Mode = ScanMode.Quick, Browsers = original.Browsers, UseCache = true, CpuSampleMs = 2500, MemoryInspection = true };
            var res = ScanEngine.Run(opt, ct, progress);
            var ctx = ScanEngine.LastContext;
            var nowRunning = ctx.Entities.Values.Where(e => e.Kind == EntityKind.Process).ToList();
            var newFindingEntityIds = new HashSet<string>(res.Findings.SelectMany(f => f.Entities).Select(e => e.Id), StringComparer.OrdinalIgnoreCase);

            foreach (var oc in outcomes)
            {
                var f = before.First(x => x.Id == oc.FindingId);
                oc.StillPresent.Clear();
                var attempted = new HashSet<string>(oc.Outcome == null ? new string[0] : oc.Outcome.Results.Select(r => r.Step.EntityId), StringComparer.OrdinalIgnoreCase);
                foreach (var e in f.Entities)
                {
                    switch (e.Kind)
                    {
                        case EntityKind.Process:
                            {
                                if (!attempted.Contains(e.Id)) break;
                                string img = e.Location;
                                var again = nowRunning.FirstOrDefault(p => !string.IsNullOrEmpty(img) && string.Equals(p.Location, img, StringComparison.OrdinalIgnoreCase));
                                if (again != null) oc.StillPresent.Add("process is running again (respawn/watchdog): " + again.Title + " PID " + again.P("pid"));
                                break;
                            }
                        case EntityKind.File:
                        case EntityKind.StartupItem:
                            {
                                if (!attempted.Contains(e.Id)) break;
                                string p = e.P("file") ?? e.Location;
                                if (!string.IsNullOrEmpty(p) && File.Exists(p)) oc.StillPresent.Add("file still exists: " + p);
                                break;
                            }
                        default:
                            if (attempted.Contains(e.Id) && ctx.Entities.ContainsKey(e.Id) && newFindingEntityIds.Contains(e.Id)) oc.StillPresent.Add(e.Kind + " still present: " + e.Title);
                            break;
                    }
                }
                bool anyFailed = oc.Outcome != null && oc.Outcome.Results.Any(r => !r.Success);
                bool reboot = oc.Outcome != null && oc.Outcome.RebootRequired;
                if (oc.Outcome == null || oc.Outcome.Results.Count == 0) { oc.Verdict = "NotAttempted"; oc.RescanNote = "no action was selected"; }
                else if (oc.StillPresent.Count == 0 && !anyFailed) { oc.Verdict = reboot ? "RebootRequired" : "Remediated"; oc.RescanNote = reboot ? "Everything possible is done and verified by a rescan; finish the cleanup by restarting Windows." : "Verified by rescan: process gone, files neutralised, autostart entries removed."; }
                else if (oc.StillPresent.Count == 0 && anyFailed) { oc.Verdict = "Partial"; oc.RescanNote = "Some steps failed (see details); the rescan does not show the item any more."; }
                else { oc.Verdict = "Partial"; oc.RescanNote = "The rescan still sees parts of this infection."; }
            }
            return res;
        }
    }
}
