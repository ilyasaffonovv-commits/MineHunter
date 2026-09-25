using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    public static class AppInfo
    {
        public const string Version = "1.0.0";
        /// <summary>Bump when detection logic changes: cached "looked harmless" verdicts of older logic are then discarded.</summary>
        public const int EngineRevision = 5;
        public const string Name = "MineHunter";
    }

    public static class ScanEngine
    {
        static string LockFile { get { return Path.Combine(RulePack.DataDir, "scan.lock"); } }

        public static ScanResult Run(ScanOptions opt, CancellationToken ct, Action<string, int> progress)
        {
            var res = new ScanResult { Started = DateTime.Now, Mode = opt.Mode.ToString(), AppVersion = AppInfo.Version };
            var sw = Stopwatch.StartNew();
            // run below normal priority during the scan so the PC stays responsive
            ProcessPriorityClass? oldPriority = null;
            try { var me = Process.GetCurrentProcess(); oldPriority = me.PriorityClass; if (oldPriority == ProcessPriorityClass.Normal) me.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
            try { return RunCore(opt, ct, progress, res, sw); }
            finally { try { if (oldPriority.HasValue) Process.GetCurrentProcess().PriorityClass = oldPriority.Value; } catch { } }
        }

        static ScanResult RunCore(ScanOptions opt, CancellationToken ct, Action<string, int> progress, ScanResult res, Stopwatch sw)
        {
            RulePack rules = RulePack.Load();
            var allow = Allowlist.Load();
            res.RulesVersion = rules.Version;
            var ctx = new ScanContext(rules, allow, opt, ct);
            ctx.Progress = progress ?? ((s, p) => { });
            ctx.Report("Preparing...", 1);
            string cacheKey = rules.Version + "|" + AppInfo.Version + "|r" + AppInfo.EngineRevision;
            ctx.Cache = opt.UseCache ? ScanCache.Load(cacheKey) : new ScanCache { RulesVersion = cacheKey };

            // ---- self-integrity + interrupted-previous-scan detection (defence against tampering with the scanner)
            try
            {
                Directory.CreateDirectory(RulePack.DataDir);
                if (File.Exists(LockFile) && !LockOwnerAlive())
                    res.PreviousScanIssues.Add("The previous scan did not finish (crashed, was killed or the PC was switched off). If that was not you, something may be interfering with scanners.");
                File.WriteAllText(LockFile, DateTime.Now.ToString("o") + " pid=" + Process.GetCurrentProcess().Id);
                if (!string.IsNullOrEmpty(ctx.SelfPath)) res.SelfHash = Hashing.Sha256(ctx.SelfPath);
            }
            catch { }

            FillStatus(ctx, res);
            try
            {
                Stage(ctx, "processes and loaded libraries", () => ProcessScanner.Run(ctx));
                ctx.Report("Autostart locations...", 50);
                var persistenceTasks = new List<Task>
                {
                    Task.Run(() => Stage(ctx, "registry autostart", () => RegistryPersistenceScanner.Run(ctx))),
                    Task.Run(() => Stage(ctx, "startup folders", () => StartupScanner.Run(ctx))),
                    Task.Run(() => Stage(ctx, "services and drivers", () => ServiceScanner.Run(ctx))),
                    Task.Run(() => Stage(ctx, "scheduled tasks", () => TaskScanner.Run(ctx))),
                    Task.Run(() => Stage(ctx, "WMI subscriptions", () => WmiScanner.Run(ctx))),
                };
                Task.WaitAll(persistenceTasks.ToArray(), ct);
                ctx.Report("System tampering checks...", 60);
                Stage(ctx, "protection tampering", () => TamperScanner.Run(ctx));
                if (opt.Browsers) { ctx.Report("Browsers and extensions...", 66); Stage(ctx, "browsers", () => BrowserScanner.Run(ctx)); }
                if (opt.ScanHotDirs || opt.Mode != ScanMode.Quick) { ctx.Report("Files...", 70); Stage(ctx, "files", () => FileSystemScanner.Run(ctx)); }
                ctx.Report("Analysing evidence...", 96);
            }
            catch (OperationCanceledException) { res.Aborted = true; res.AbortReason = "cancelled by user"; }
            catch (AggregateException ae) when (ae.InnerExceptions.Any(x => x is OperationCanceledException)) { res.Aborted = true; res.AbortReason = "cancelled by user"; }

            List<Entity> observations;
            var findings = RiskEngine.Build(ctx, out observations);
            res.Findings = findings;
            res.Observations = observations;
            res.EntitiesTotal = ctx.Entities.Count;
            res.Stats = ctx.Stats;
            res.BlindSpots = ctx.Blind.ToList();
            res.Status.PostureWarnings = ctx.PostureWarnings.ToList();
            res.Status.PostureInfo = ctx.PostureInfo.ToList();
            ApplyPosture(res);
            if (!res.Aborted && opt.UseCache) ctx.Cache.Save();
            try { if (!string.IsNullOrEmpty(ctx.SelfPath)) { res.SelfHashEnd = Hashing.Sha256(ctx.SelfPath); if (res.SelfHash != null && res.SelfHashEnd != null && res.SelfHash != res.SelfHashEnd) res.PreviousScanIssues.Add("The scanner's own executable changed while the scan was running - something modified MineHunter.exe."); } } catch { }
            try { File.Delete(LockFile); } catch { }
            res.Finished = DateTime.Now;
            res.Stats.Seconds = Math.Round(sw.Elapsed.TotalSeconds, 1);
            res.Status.QuarantineCount = Quarantine.List().Count;
            ctx.Report("Done", 100);
            LastContext = ctx;
            return res;
        }

        /// <summary>The lock file holds "... pid=N": if that process is still running, another MineHunter is scanning right now (not a crash).</summary>
        static bool LockOwnerAlive()
        {
            try
            {
                var m = System.Text.RegularExpressions.Regex.Match(File.ReadAllText(LockFile), @"pid=(\d+)");
                if (!m.Success) return false;
                int pid = int.Parse(m.Groups[1].Value);
                if (pid == Process.GetCurrentProcess().Id) return false;
                using (var p = Process.GetProcessById(pid)) return !p.HasExited && p.ProcessName.StartsWith("MineHunter", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Kept for the rescan/verification step and the GUI (entity lookup by id).</summary>
        public static ScanContext LastContext;

        static void Stage(ScanContext ctx, string name, Action a)
        {
            try { ctx.ThrowIfCancelled(); a(); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Log.Error(name + ": " + ex.Message);
                ctx.AddBlind(name, "stage failed: " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        static void FillStatus(ScanContext ctx, ScanResult res)
        {
            var s = res.Status;
            try { s.OsVersion = Environment.OSVersion.VersionString + " (" + (Environment.Is64BitOperatingSystem ? "x64" : "x86") + ")"; s.Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86"; } catch { }
            try { using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")) if (k != null) s.OsVersion = Convert.ToString(k.GetValue("ProductName")) + " " + Convert.ToString(k.GetValue("DisplayVersion")) + " (build " + Convert.ToString(k.GetValue("CurrentBuildNumber")) + "." + Convert.ToString(k.GetValue("UBR")) + ", " + s.Architecture + ")"; } catch { }
            s.Machine = Environment.MachineName; s.User = Environment.UserName;
            try { s.IsAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { }
            if (!s.IsAdmin) ctx.AddBlind("Whole scan", "MineHunter is not running as administrator: services, tasks, WMI and other users' processes may be invisible.");
        }

        static void ApplyPosture(ScanResult res)
        {
            var s = res.Status;
            s.DefenderServiceRunning = s.PostureInfo.Contains("DEFENDER_RUNNING=True");
            s.RealtimeProtectionOn = s.DefenderServiceRunning;
            bool other = s.PostureInfo.Any(x => x.StartsWith("AV|"));
            s.ThirdPartyAv = string.Join(", ", s.PostureInfo.Where(x => x.StartsWith("AV|")).Select(x => x.Substring(3)));
            s.DefenderState = s.DefenderServiceRunning ? "Windows Defender is running" : (other ? "Windows Defender is off; other antivirus: " + s.ThirdPartyAv : "No active antivirus");
        }
    }
}
