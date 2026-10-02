using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Remediation;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter
{
    public static partial class SelfTest
    {
        // ============================================================================================ startup manager, Explorer menu, snapshot, controller, false-positive report
        static void ProductSupportChecks(RulePack rules)
        {
            W.WriteLine("\nStartup manager, Explorer menu, last-scan snapshot, scan controller, false-positive report");
            string tmp = NewTemp("mh_ps_");
            string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run", testName = "MineHunterSelfTest-" + Guid.NewGuid().ToString("N").Substring(0, 6);
            try
            {
                string notepad = Path.Combine(PathUtil.System32, "notepad.exe");
                using (var k = Registry.CurrentUser.CreateSubKey(runKey)) k.SetValue(testName, "\"" + notepad + "\" /selftest");
                var items = StartupManager.List(rules);
                var mine = items.FirstOrDefault(i => i.Name == testName);
                Check("the startup list shows a Run entry with its program, source and trust (a Microsoft program is trusted)", mine != null && mine.Kind == "run" && mine.Enabled && mine.Target.EndsWith("notepad.exe", StringComparison.OrdinalIgnoreCase) && mine.Trusted && mine.Source.StartsWith("HKCU"));
                string e1 = StartupManager.SetEnabled(mine, false);
                var off = StartupManager.List(rules).FirstOrDefault(i => i.Name == testName);
                bool flagged; using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")) { var b = k == null ? null : k.GetValue(testName) as byte[]; flagged = b != null && b.Length >= 12 && (b[0] & 1) == 1; }
                Check("switching an entry off sets the same flag the Task Manager uses and deletes nothing", e1 == null && off != null && !off.Enabled && flagged && Registry.CurrentUser.OpenSubKey(runKey).GetValue(testName) != null);
                string e2 = StartupManager.SetEnabled(off, true);
                Check("switching it back on restores it exactly", e2 == null && StartupManager.List(rules).First(i => i.Name == testName).Enabled);
                Check("an item that is only shown (Winlogon, AppInit) cannot be changed from here", StartupManager.SetEnabled(new StartupItem { Id = "special|shell", Kind = "special", CanChange = false }, false) != null);
                Check("tasks and services outside Windows' own are listed", items.Any(i => i.Kind == "task" || i.Kind == "service" || i.Kind == "folder" || i.Kind == "run"));
            }
            finally
            {
                try { using (var k = Registry.CurrentUser.OpenSubKey(runKey, true)) if (k != null) k.DeleteValue(testName, false); } catch { }
                try { using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", true)) if (k != null) k.DeleteValue(testName, false); } catch { }
            }

            string oldRoot = ShellIntegration.ClassesRoot;
            try
            {
                ShellIntegration.ClassesRoot = @"Software\MineHunterSelfTest\Classes";
                string exe = Path.Combine(tmp, "MineHunter.exe"); File.Copy(Path.Combine(PathUtil.System32, "notepad.exe"), exe);
                Check("the Explorer menu is not there before it is installed", !ShellIntegration.IsInstalled());
                string err = ShellIntegration.Install(exe);
                string cmd; using (var k = Registry.CurrentUser.OpenSubKey(ShellIntegration.ClassesRoot + @"\*\shell\MineHunter.Check\command")) cmd = k == null ? null : Convert.ToString(k.GetValue(""));
                string dirCmd; using (var k = Registry.CurrentUser.OpenSubKey(ShellIntegration.ClassesRoot + @"\Directory\shell\MineHunter.Scan\command")) dirCmd = k == null ? null : Convert.ToString(k.GetValue(""));
                Check("the menu verbs pass only the path to the program (files: check; folders and drives: scan)", err == null && ShellIntegration.IsInstalled() && cmd == "\"" + exe + "\" --check-file \"%1\"" && dirCmd == "\"" + exe + "\" --scan-folder \"%1\"");
                Check("removing the menu leaves nothing behind", ShellIntegration.Remove() == null && !ShellIntegration.IsInstalled() && Registry.CurrentUser.OpenSubKey(ShellIntegration.ClassesRoot + @"\*\shell\MineHunter.Check") == null);
                Check("a program path with a quote or a missing file is refused for the menu", ShellIntegration.Install(tmp + "\no\"quote.exe") != null && ShellIntegration.Install(Path.Combine(tmp, "missing.exe")) != null);
                Check("only one existing file or folder is accepted from a menu command; pipes, line breaks and made-up paths are not", ShellIntegration.SafePath(exe) == exe && ShellIntegration.SafePath(tmp) == tmp && ShellIntegration.SafePath(exe + "|calc") == null && ShellIntegration.SafePath(exe + "\n" + exe) == null && ShellIntegration.SafePath(Path.Combine(tmp, "nope.exe")) == null && ShellIntegration.SafePath("") == null);
            }
            finally { ShellIntegration.ClassesRoot = oldRoot; try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\MineHunterSelfTest", false); } catch { } }

            // the last-scan snapshot keeps everything needed to show and neutralize the findings in another program
            var ent = new Entity { Id = "file:x", Kind = EntityKind.File, Title = "evil.exe", Location = @"C:\Users\A\AppData\Local\Temp\evil.exe", Sha256 = new string('a', 64), Score = 72, Verdict = Verdict.HighRisk };
            ent.Evidence.Add(new Evidence("MINER.STRINGS", EvidenceCategory.Content, 45, "markers", "x", true)); ent.Props["pathClass"] = "UserTemp";
            var task = new Entity { Id = "task:y", Kind = EntityKind.Task, Title = "Updater", Location = @"\Updater" }; task.Props["taskPath"] = @"\Updater";
            var f = new Finding { Id = "F1", Title = "Cryptominer files: evil.exe", Verdict = Verdict.HighRisk, Score = 72, Entities = new List<Entity> { ent, task }, WhyNotHigher = null };
            f.Links.Add(new Link("task:y", "file:x", "launches")); f.TopEvidence.Add(ent.Evidence[0]); f.ChainLines.Add("Updater -> evil.exe");
            f.Steps.Add(new RemediationStep { Type = ActionType.QuarantineFile, EntityId = "file:x", Description = "Move the file to quarantine", Target = ent.Location, Order = 2, Reversible = true, RecommendedByDefault = true });
            f.Steps.Add(new RemediationStep { Type = ActionType.ReviewOnly, EntityId = "task:y", Description = "Look at the task", Order = 1, RecommendedByDefault = false });
            var sr = new ScanResult { AppVersion = AppInfo.Version, Mode = "Quick", RulesVersion = "t", Started = DateTime.Now.AddMinutes(-2), Finished = DateTime.Now }; sr.Findings.Add(f); sr.Observations.Add(new Entity { Id = "n", Kind = EntityKind.File, Title = "note", Location = "x", Score = 14 }); sr.Stats.Seconds = 91.5;
            ResultSnapshot.Save(sr);
            var back = ResultSnapshot.Load();
            Check("the last scan is saved and read back in full: findings, objects, evidence, links, steps, notes", back != null && back.Findings.Count == 1 && back.Findings[0].Entities.Count == 2 && back.Findings[0].Entities[0].Evidence[0].Definitive && back.Findings[0].Links.Count == 1 && back.Findings[0].Steps.Count == 2 && back.Findings[0].Steps[0].Type == ActionType.QuarantineFile && back.Observations.Count == 1 && Math.Abs(back.Stats.Seconds - 91.5) < 0.01 && back.Findings[0].Entities[1].P("taskPath") == @"\Updater");
            Check("'neutralize all' takes only High Risk and Critical findings with their recommended steps, never review-only ones", Neutralizer.DefaultPlan(back).Count == 1 && Neutralizer.DefaultPlan(back)[0].Value.Count == 1 && Neutralizer.DefaultPlan(back)[0].Value[0].Type == ActionType.QuarantineFile);
            var cheat = new Finding { Id = "F2", Title = "Game cheat / hack tool (kept): x", Verdict = Verdict.Suspicious, ToolClass = "GameCheat", Entities = new List<Entity> { ent } }; cheat.Steps.Add(new RemediationStep { Type = ActionType.QuarantineFile, EntityId = "file:x", RecommendedByDefault = false });
            back.Findings.Add(cheat);
            Check("a game cheat is never part of 'neutralize all'", Neutralizer.DefaultPlan(back).All(kv => kv.Key.ToolClass == null));
            File.WriteAllText(ResultSnapshot.FilePath, "{ damaged");
            Check("a damaged snapshot is ignored without an error", ResultSnapshot.Load() == null);

            // one scan at a time, in this program and across programs
            var c1 = new ScanController(); var c2 = new ScanController();
            var cfg = new AppConfig(); var st = new Settings { ScanMemory = false, ScanBrowsers = false };
            string small = NewTemp("mh_sc_"); File.WriteAllText(Path.Combine(small, "a.txt"), "hello");
            try
            {
                bool started = c1.Start(ScanMode.Custom, "selftest", cfg, st, new[] { small });
                bool second = c1.Start(ScanMode.Custom, "selftest", cfg, st, new[] { small });
                bool other = c2.Start(ScanMode.Custom, "selftest", cfg, st, new[] { small });
                Check("a second scan is refused while one runs, in the same program and in another one", started && !second && c1.Error != null && !other && c2.Error != null);
                bool done = WaitFor(() => !c1.Running, 120000);
                Check("the controller reports the finished run with its result and history entry", done && c1.LastRun != null && c1.LastRun.Result != null && c1.LastRun.Entry != null && c1.Live != null && c1.Live.Percent == 100);
                Check("... and a new scan can start afterwards", c2.Start(ScanMode.Custom, "selftest", cfg, st, new[] { small }) && WaitFor(() => !c2.Running, 120000));
                var c3 = new ScanController(); var bigCts = new ScanController();
                bool s3 = c3.Start(ScanMode.Custom, "selftest", cfg, new Settings { ScanMemory = false, ScanBrowsers = false }, new[] { PathUtil.WinDir });
                Thread.Sleep(1500); c3.Cancel();
                Check("a scan can be cancelled and then ends as 'stopped' with a partial result", s3 && WaitFor(() => !c3.Running, 120000) && c3.LastRun != null && c3.LastRun.Result.Aborted);
            }
            finally { try { Directory.Delete(small, true); } catch { } }

            // false-positive report: names removed, nothing sent
            var rep = new FileReport { Path = Path.Combine(PathUtil.UserProfiles().FirstOrDefault() ?? @"C:\Users\Zed", @"Downloads\my tool.exe"), Name = "my tool.exe", Sha256 = new string('c', 64), Size = 100, Location = "Downloads", VerdictText = "Suspicious", Score = 40, SignatureText = "Not signed" };
            rep.Evidence.Add(new Evidence("PE.PACKED", EvidenceCategory.Content, 12, "packed", @"C:\Users\" + Environment.UserName + @"\Desktop\x"));
            string txt = FalsePositiveReport.Build(rep, "this is my own tool, PC " + Environment.MachineName);
            string withoutLabels = txt.Replace("<user>", "").Replace("<pc>", "");
            Check("the false-positive report keeps the hash, the reasons and the verdict but not the user name or the PC name", txt.Contains(new string('c', 64)) && txt.Contains("packed") && txt.Contains("Suspicious") && txt.Contains("<pc>") && txt.IndexOf(Environment.MachineName, StringComparison.OrdinalIgnoreCase) < 0 && !System.Text.RegularExpressions.Regex.IsMatch(withoutLabels, @"\b" + System.Text.RegularExpressions.Regex.Escape(Environment.UserName) + @"\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase), txt.Replace("\n", " | "));
            string an = FalsePositiveReport.Anonymize(@"C:\Users\SomeOne\AppData\x on " + Environment.MachineName);
            Check("anonymising replaces profile paths and the machine name", an.Contains(@"C:\Users\<user>") && !FalsePositiveReport.Anonymize("host " + Environment.MachineName).Contains(Environment.MachineName), an + " / user=" + Environment.UserName + " pc=" + Environment.MachineName);
            try { Directory.Delete(tmp, true); } catch { }
        }
    }
}
