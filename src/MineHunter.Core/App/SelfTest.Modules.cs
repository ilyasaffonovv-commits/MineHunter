using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using MineHunter.Analysis;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter
{
    /// <summary>Checks of the product layer: settings, scan profiles, history, schedule, self-update, Windows health, drivers, reputation, the file report and the real-time guards.
    /// Everything runs in a temporary data folder and temporary files; nothing outside is changed (no setting of Windows is touched, no driver is installed).</summary>
    public static partial class SelfTest
    {
        static int FreePort() { var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0); l.Start(); int port = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return port; }

        static string NewTemp(string prefix) { string d = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N").Substring(0, 8)); Directory.CreateDirectory(d); return d; }

        static void ModuleChecks(RulePack rules)
        {
            string tmpData = NewTemp("mh_mod_data_");
            string oldData = RulePack.TestDataDirOverride;
            RulePack.TestDataDirOverride = tmpData;
            try
            {
                SettingsChecks();
                ProfileChecks(rules);
                HistoryScheduleChecks();
                AppUpdateChecks();
                HealthDriverChecks();
                ReputationReportChecks(rules);
                GuardLogicChecks(rules);
                GuardFileChecks(rules);
                GuardSystemChecks(rules);
                ProductSupportChecks(rules);
            }
            catch (Exception ex) { Check("module checks ran to the end", false, ex.ToString()); }
            finally
            {
                RulePack.TestDataDirOverride = oldData;
                try { Directory.Delete(tmpData, true); } catch { }
            }
        }

        // ============================================================================================ settings
        static void SettingsChecks()
        {
            W.WriteLine("\nSettings, presets, exclusions");
            string f = Path.Combine(RulePack.DataDir, "settings.json");
            var s = new Settings { CpuLimit = 5, Threads = 99, Sensitivity = "bogus", ScheduleTime = "25:99", MaxFileSizeMb = -4, NotifyLevel = "Dangerous", RansomwareGuard = true };
            s.ExcludedPaths.Add(@"C:\Games\Mine"); s.ExcludedPaths.Add(@"c:\games\mine");
            s.Save(f);
            var b = Settings.Load(f);
            Check("settings survive a save and a load", b.NotifyLevel == "Dangerous" && b.RansomwareGuard && b.ExcludedPaths.Count == 1);
            Check("out-of-range or unknown values are put back into range, never into 'less protection'", b.CpuLimit == 10 && b.Threads == 32 && b.Sensitivity == "Normal" && b.ScheduleTime == "13:00" && b.MaxFileSizeMb == 1);
            File.WriteAllText(f, "{ this is not json");
            var c = Settings.Load(f);
            Check("a damaged settings file falls back to the defaults without an error", c.FileGuard && c.Sensitivity == "Normal" && c.AutoUpdateApp);
            Check("defaults: protection is on, ransomware decoys are opt-in, nothing is uploaded", new Settings().ProcessGuard && !new Settings().RansomwareGuard && !new Settings().CloudLookup && !new Settings().VirusTotalLookup);
            var e = new Settings();
            Check("an exclusion for a whole drive, the Windows folder or the user profile is refused (it would switch the scan off)", !e.AddExclusion(@"C:\") && !e.AddExclusion(PathUtil.WinDir) && !e.AddExclusion(PathUtil.UserProfiles().FirstOrDefault() ?? @"C:\Users\Zed") && !e.AddExclusion(PathUtil.ProgramFiles));
            Check("a normal folder can be excluded, its children are excluded, a sibling is not", e.AddExclusion(@"C:\Games\Mine") && e.IsExcludedPath(@"C:\Games\Mine\bin\a.exe") && !e.IsExcludedPath(@"C:\Games\MineSweeper\a.exe"));
            var p = new Settings(); p.ApplyPreset("Strict");
            Check("Strict preset raises the sensitivity and shows every level", p.Sensitivity == "Strict" && p.NotifyLevel == "Info" && p.SensitivityLevel == 1);
            p.ApplyPreset("Developer");
            Check("Developer preset keeps protection and switches the developer context on", p.DeveloperContext && p.FileGuard && p.ProcessGuard);
            var k = new Settings(); k.SetVirusTotalKey("0123456789abcdef-test-key");
            Check("an API key is stored protected (not in plain text) and reads back", !string.IsNullOrEmpty(k.VirusTotalKeyProtected) && !k.VirusTotalKeyProtected.Contains("0123456789") && k.GetVirusTotalKey() == "0123456789abcdef-test-key");
        }

        // ============================================================================================ profiles, sensitivity, developer context, exclusions in scans
        static void ProfileChecks(RulePack rules)
        {
            W.WriteLine("\nScan profiles (one engine for Quick Scan, Full Scan, the window and the command line)");
            var cfg = new AppConfig();
            var s = new Settings { Sensitivity = "Strict", Threads = 3, ScanArchives = false, ScanRemovable = true, FullScanMaxMinutes = 90, CpuLimit = 50 };
            var q = ScanProfiles.Quick(s, cfg); var fu = ScanProfiles.Full(s, cfg); var cu = ScanProfiles.Custom(s, cfg, new[] { @"C:\a", @"D:\b" });
            Check("Quick, Full and Custom come from the same settings", q.Mode == ScanMode.Quick && fu.Mode == ScanMode.Full && cu.Mode == ScanMode.Custom && q.Sensitivity == 1 && fu.Sensitivity == 1 && q.Parallelism == 3 && fu.IncludeRemovable && !q.ScanArchives && fu.MaxFullScanMinutes == 90 && q.CpuLimit == 50);
            Check("Custom scan keeps every chosen folder", cu.AllCustomPaths().Count() == 2 && cu.CustomPath == @"C:\a");
            var a = ScanProfiles.Quick(s, cfg); var b = ScanProfiles.Quick(s, cfg);
            Check("the same settings always give the same options", a.Sensitivity == b.Sensitivity && a.Parallelism == b.Parallelism && a.MemoryInspection == b.MemoryInspection && a.Browsers == b.Browsers && a.MaxFileSizeMbForContentScan == b.MaxFileSizeMbForContentScan);

            // sensitivity: the same evidence is Clean, then Suspicious, then Suspicious earlier
            var e26 = Ent(EntityKind.File, "m", E("X.A", EvidenceCategory.Content, 18), E("X.B", EvidenceCategory.Location, 8));
            string why;
            Func<int, Verdict> at = lvl => { RiskEngine.Sensitivity = lvl; var v = RiskEngine.Decide(RiskEngine.Compute(new[] { e26 }), out why); RiskEngine.Sensitivity = 0; return v; };
            var e22 = Ent(EntityKind.File, "n", E("X.A", EvidenceCategory.Content, 22));
            Func<int, Verdict> at22 = lvl => { RiskEngine.Sensitivity = lvl; var v = RiskEngine.Decide(RiskEngine.Compute(new[] { e22 }), out why); RiskEngine.Sensitivity = 0; return v; };
            Check("sensitivity: 26 points is Clean at Normal, Suspicious at Strict; 22 points only at Paranoid", at(0) == Verdict.Clean && at(1) == Verdict.Suspicious && at22(1) == Verdict.Clean && at22(2) == Verdict.Suspicious);
            var big = Ent(EntityKind.File, "o", E("X.A", EvidenceCategory.Content, 40), E("X.B", EvidenceCategory.Location, 20));
            RiskEngine.Sensitivity = 2; var vb = RiskEngine.Decide(RiskEngine.Compute(new[] { big }), out why); RiskEngine.Sensitivity = 0;
            Check("sensitivity never lowers the bar for Malware or the number of independent kinds needed for High Risk", vb < Verdict.HighRisk);

            // developer context: weak signals set aside inside build output; a miner marker is not
            string tmp = NewTemp("mh_prof_");
            try
            {
                string nm = Path.Combine(tmp, "node_modules", "pkg"); Directory.CreateDirectory(nm);
                string tool = Path.Combine(nm, "native.exe");
                File.Copy(Path.Combine(PathUtil.System32, "notepad.exe"), tool);
                var ctx = TestCtx(rules); ctx.Options.DeveloperContext = true;
                var ent = new Entity { Id = "file:dev", Kind = EntityKind.File, Title = "native.exe", Location = tool };
                ent.Add(E("SIG.UNSIGNED", EvidenceCategory.Signature, 6)); ent.Add(E("LOC.USER", EvidenceCategory.Location, 12)); ent.Add(E("PE.HIGH_ENTROPY", EvidenceCategory.Content, 7)); ent.Add(E("MINER.STRINGS", EvidenceCategory.Content, 45));
                ctx.Entities["file:dev"] = ent;
                List<Entity> obs; RiskEngine.Build(ctx, out obs);
                Check("developer context: unsigned / user-folder / entropy signals are set aside in node_modules, a miner marker still counts", ent.Evidence.Where(x => x.Weight > 0).Select(x => x.RuleId).SequenceEqual(new[] { "MINER.STRINGS" }));
            }
            finally { try { Directory.Delete(tmp, true); } catch { } }

            // exclusions are honoured by the scanner
            string dir = NewTemp("mh_excl_");
            try
            {
                string cfgMiner = "{\"pools\":[{\"url\":\"127.0.0.1:3333\",\"user\":\"WalletNotReal0000000000\",\"pass\":\"x\"}],\"algo\":\"" + Obf.J("rx", "/0") + "\",\"" + Obf.J("donate", "-level") + "\":1}";
                string sub = Path.Combine(dir, "lab"); Directory.CreateDirectory(sub);
                File.WriteAllText(Path.Combine(sub, "config.json"), cfgMiner);
                var st = new Settings();
                var o1 = ScanProfiles.Custom(st, cfg, new[] { dir }); o1.UseCache = false; o1.MemoryInspection = false; o1.Browsers = false;
                Func<ScanResult, int> mine = res => res.Findings.Count(f => f.Entities.Any(en => (en.Location ?? "").StartsWith(dir, StringComparison.OrdinalIgnoreCase)));
                var r1 = ScanEngine.Run(o1, CancellationToken.None, null);
                st.ExcludedPaths.Add(sub);
                var o2 = ScanProfiles.Custom(st, cfg, new[] { dir }); o2.UseCache = false; o2.MemoryInspection = false; o2.Browsers = false;
                var r2 = ScanEngine.Run(o2, CancellationToken.None, null);
                Check("a scan reports a miner configuration in a folder, and nothing once the user has excluded that folder", mine(r1) > 0 && mine(r2) == 0, "before " + mine(r1) + ", after " + mine(r2));
                var o3 = ScanProfiles.Custom(new Settings(), cfg, new[] { dir }); o3.UseCache = false; o3.MemoryInspection = false; o3.Browsers = false;
                var r3 = ScanEngine.Run(o3, CancellationToken.None, null);
                var run = ScanRunner.Run(o3, "selftest", new Settings(), CancellationToken.None, null);
                Func<ScanResult, List<string>> titles = res => res.Findings.Where(f => f.Entities.Any(en => (en.Location ?? "").StartsWith(dir, StringComparison.OrdinalIgnoreCase))).Select(x => x.Title).OrderBy(x => x).ToList();
                Check("the engine and the shared runner give the same result for the same options (same findings in the scanned folder, same titles)", titles(r3).Count > 0 && titles(r3).SequenceEqual(titles(run.Result)));
                Check("the runner writes txt, json and html reports and a history entry", run.ReportTxt != null && File.Exists(run.ReportTxt) && File.Exists(Path.ChangeExtension(run.ReportTxt, ".json")) && File.Exists(run.ReportHtml) && History.List().Any(h => h.Id == run.Entry.Id));
                string html = File.ReadAllText(run.ReportHtml);
                Check("the HTML report is one self-contained page (no script, no external address)", html.Contains("<html") && !html.Contains("<script") && !html.Contains("src=\"http") && html.Contains("MineHunter"));
                var live = new ScanProgress(); var o4 = ScanProfiles.Custom(new Settings(), cfg, new[] { dir }, live); o4.UseCache = false; o4.MemoryInspection = false; o4.Browsers = false;
                var r4 = ScanEngine.Run(o4, CancellationToken.None, null);
                Check("the live progress object sees the scan: objects checked, status, elapsed", live.ObjectsChecked > 0 && !string.IsNullOrEmpty(live.Status) && live.Elapsed.TotalMilliseconds > 0 && live.Percent == 100, "objects " + live.ObjectsChecked + " status " + live.Status);
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ============================================================================================ history, schedule
        static void HistoryScheduleChecks()
        {
            W.WriteLine("\nHistory and schedule");
            History.Clear();
            for (int i = 0; i < 3; i++) History.Add(new HistoryEntry { Id = "h" + i, Started = DateTime.Now.AddMinutes(-i).ToString("o"), Mode = i == 1 ? "Full" : "Quick", Critical = i, Seconds = 12.5 + i, Titles = new List<string> { "t" + i } });
            var l = History.List();
            Check("history keeps entries newest first and reads them back", l.Count == 3 && l[0].Id == "h0" && l[2].Id == "h2" && Math.Abs(l[1].Seconds - 13.5) < 0.01 && l[1].Titles[0] == "t1");
            Check("last full scan is found by kind", History.Last("Full").Id == "h1" && History.Last("Quick").Id == "h0");
            File.WriteAllText(History.FilePath, "garbage");
            Check("a damaged history file reads as an empty list", History.List().Count == 0);

            var s = new Settings { ScheduleEnabled = true, ScheduleMode = "Full", ScheduleTime = "03:30", ScheduleNotOnBattery = true, ScheduleStopOnBattery = false, ScheduleRunMissed = true, ScheduleOnlyIdle = true };
            string exe = @"C:\Tools & Co\Mine Hunter\MineHunter.exe";
            DateTime now = new DateTime(2026, 10, 4, 14, 0, 0);
            foreach (var every in new[] { "Daily", "Every3Days", "Weekly", "Monthly", "CustomDays" })
            {
                s.ScheduleEvery = every; s.ScheduleCustomDays = 5;
                string xml = ScheduleManager.BuildScanXml(s, exe, "S-1-5-21-1-2-3-1001", now);
                var doc = System.Xml.Linq.XDocument.Parse(xml);
                var ns = doc.Root.Name.Namespace;
                bool shape = every == "Daily" ? xml.Contains("<DaysInterval>1</DaysInterval>") : every == "Every3Days" ? xml.Contains("<DaysInterval>3</DaysInterval>") : every == "CustomDays" ? xml.Contains("<DaysInterval>5</DaysInterval>") : every == "Weekly" ? xml.Contains("<Sunday />") && xml.Contains("<WeeksInterval>1</WeeksInterval>") : xml.Contains("<Day>1</Day>") && xml.Contains("<December />");
                Check("schedule XML (" + every + ") is valid and has the right trigger", shape && doc.Descendants(ns + "StartBoundary").First().Value == "2026-10-05T03:30:00");
            }
            string x2 = ScheduleManager.BuildScanXml(s, exe, "S-1-5-21-1-2-3-1001", now);
            Check("schedule XML carries the battery, idle and missed-run options and a quoted, escaped command", x2.Contains("<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>") && x2.Contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>") && x2.Contains("<StartWhenAvailable>true</StartWhenAvailable>") && x2.Contains("<RunOnlyIfIdle>true</RunOnlyIfIdle>") && x2.Contains("Tools &amp; Co") && x2.Contains("--scheduled full") && x2.Contains("<RunLevel>HighestAvailable</RunLevel>"));
            Check("the first start is today if the time has not passed, otherwise tomorrow", ScheduleManager.FirstStart(new Settings { ScheduleTime = "15:00" }, now) == new DateTime(2026, 10, 4, 15, 0, 0) && ScheduleManager.FirstStart(new Settings { ScheduleTime = "09:00" }, now) == new DateTime(2026, 10, 5, 9, 0, 0));
            Check("a missed scheduled scan is noticed (older than the interval + 2 h), a recent one is not, a switched-off schedule never", ScheduleManager.IsOverdue(new Settings { ScheduleEnabled = true, ScheduleEvery = "Daily" }, now, now.AddDays(-2)) && !ScheduleManager.IsOverdue(new Settings { ScheduleEnabled = true, ScheduleEvery = "Daily" }, now, now.AddHours(-20)) && !ScheduleManager.IsOverdue(new Settings { ScheduleEnabled = false }, now, null) && ScheduleManager.IsOverdue(new Settings { ScheduleEnabled = true, ScheduleEvery = "Weekly" }, now, null));
            string tray = ScheduleManager.BuildTrayXml(exe, "S-1-5-21-1-2-3-1001");
            Check("the tray task starts at the user's sign-in with the highest rights and no time limit", tray.Contains("<LogonTrigger>") && tray.Contains("--tray") && tray.Contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") && tray.Contains("HighestAvailable"));

            // a real task in the Task Scheduler (own name, removed at once)
            bool admin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            if (!admin) W.WriteLine("  [skip] creating a real scheduled task needs administrator rights");
            else
            {
                string name = "SelfTest-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                try
                {
                    string xml = ScheduleManager.BuildScanXml(new Settings { ScheduleEnabled = true, ScheduleTime = "04:00", ScheduleEvery = "Weekly" }, Path.Combine(PathUtil.System32, "cmd.exe"), ScheduleManager.CurrentUserSid(), DateTime.Now);
                    string err = ScheduleManager.Register(name, xml);
                    var st = ScheduleManager.Query(name);
                    Check("the Windows Task Scheduler accepts the task and reports its next run", err == null && st.Exists && st.NextRun.HasValue && st.NextRun.Value > DateTime.Now, err);
                    string d = ScheduleManager.Delete(name);
                    Check("the task is removed again", d == null && !ScheduleManager.Query(name).Exists, d);
                }
                finally { ScheduleManager.Delete(name); }
            }
        }

        // ============================================================================================ self-update
        static void AppUpdateChecks()
        {
            W.WriteLine("\nProgram self-update (signed announcement, SHA-256, size, safe unpacking, rollback inputs)");
            string kd = NewTemp("mh_upd_keys_");
            HttpListener srv = null; string oldVer = AppUpdater.CurrentVersion;
            try
            {
                Updater.GenerateKeys(kd);
                string priv = File.ReadAllText(Path.Combine(kd, "update_private.xml")), pub = File.ReadAllText(Path.Combine(kd, "update_public.xml"));
                // a package that looks like a release
                byte[] pkg = BuildPackage(false, true);
                string sha = Hashing.Sha256(pkg);
                Func<string, string> sign = text => { using (var rsa = new RSACryptoServiceProvider()) { rsa.FromXmlString(priv); return Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(text), CryptoConfig.MapNameToOID("SHA256"))); } };
                int port = FreePort();
                srv = new HttpListener(); srv.Prefixes.Add("http://127.0.0.1:" + port + "/"); srv.Start();
                string manifest = ""; byte[] served = pkg; int zipRequests = 0;
                var listener = srv;
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    while (true)
                    {
                        try
                        {
                            if (!listener.IsListening) break;
                            var ctx = listener.GetContext(); byte[] body;
                            if (ctx.Request.Url.AbsolutePath == "/pkg.zip") { zipRequests++; body = served; ctx.Response.ContentType = "application/zip"; }
                            else body = Encoding.UTF8.GetBytes(manifest);
                            ctx.Response.OutputStream.Write(body, 0, body.Length); ctx.Response.Close();
                        }
                        catch { }
                    }
                });
                Func<string, string, long, string, string, string> man = (ver, hash, size, minVer, sigOverride) =>
                {
                    var r = new AppRelease { Version = ver, Url = "http://127.0.0.1:" + port + "/pkg.zip", Sha256 = hash, Size = size, MinVersion = minVer };
                    string sg = sigOverride ?? sign(r.Canonical());
                    return "{\"latestVersion\":\"" + ver + "\",\"releaseUrl\":\"https://example.invalid/r\",\"app\":{\"version\":\"" + ver + "\",\"url\":\"" + r.Url + "\",\"sha256\":\"" + hash + "\",\"size\":" + size + ",\"minVersion\":\"" + minVer + "\",\"notes\":\"n\",\"signature\":\"" + sg + "\"}}";
                };
                var cfg = new AppConfig { UpdateManifestUrl = "http://127.0.0.1:" + port + "/version.json", CheckUpdatesOnStart = true, UpdatePublicKeyXml = pub };
                AppUpdater.CurrentVersion = "1.0.0";

                manifest = man("1.5.0", sha, pkg.Length, "1.0.0", null);
                var st = AppUpdater.Check(cfg, new Settings());
                Check("a newer, correctly signed program version is announced", st.State == AppUpdateState.Available && st.Release != null && st.Release.Version == "1.5.0", st.Message);
                string staged; string err = AppUpdater.Download(st.Release, cfg, null, CancellationToken.None, out staged);
                Check("the package downloads, matches the signed SHA-256 and size, unpacks safely and holds the required files", err == null && staged != null && File.Exists(Path.Combine(staged, "MineHunter.exe")) && File.Exists(Path.Combine(staged, "components", "MineHunter.UpdateHelper.exe")), err);
                var st2 = AppUpdater.Check(cfg, new Settings());
                Check("a verified package waits as 'ready to install'", st2.State == AppUpdateState.Ready && st2.StagedDir == staged, st2.Message);

                // a tampered package: same size, other content
                var evil = (byte[])pkg.Clone(); evil[evil.Length / 2] ^= 0xFF; served = evil;
                string e1 = AppUpdater.Download(st.Release, cfg, null, CancellationToken.None, out staged);
                Check("a package that differs from the signed SHA-256 is rejected and nothing is staged", e1 != null && e1.Contains("SHA-256") && staged == null, e1);
                served = pkg;
                // wrong signature (signed by another key)
                string kd2 = NewTemp("mh_upd_keys2_"); Updater.GenerateKeys(kd2);
                string otherSig; using (var rsa = new RSACryptoServiceProvider()) { rsa.FromXmlString(File.ReadAllText(Path.Combine(kd2, "update_private.xml"))); otherSig = Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(new AppRelease { Version = "1.5.0", Url = "http://127.0.0.1:" + port + "/pkg.zip", Sha256 = sha, Size = pkg.Length, MinVersion = "1.0.0" }.Canonical()), CryptoConfig.MapNameToOID("SHA256"))); }
                try { Directory.Delete(kd2, true); } catch { }
                manifest = man("1.5.0", sha, pkg.Length, "1.0.0", otherSig);
                var st3 = AppUpdater.Check(cfg, new Settings());
                Check("an announcement signed with a different key is ignored (no download offered)", st3.State == AppUpdateState.Error && st3.Message.Contains("signature") && st3.Release == null, st3.Message);
                // swapped values keep the old signature
                string good = man("1.5.0", sha, pkg.Length, "1.0.0", null);
                manifest = good.Replace("\"size\":" + pkg.Length, "\"size\":" + (pkg.Length + 1));
                Check("changing the announced size (or hash, or address) after signing breaks the signature", AppUpdater.Check(cfg, new Settings()).State == AppUpdateState.Error);
                manifest = good.Replace(sha, new string('0', 64));
                Check("... also for the hash", AppUpdater.Check(cfg, new Settings()).State == AppUpdateState.Error);
                manifest = good.Replace("\"signature\":\"", "\"x\":\"");
                Check("an unsigned announcement is ignored", AppUpdater.Check(cfg, new Settings()).State == AppUpdateState.Error);
                // package with a path leaving its folder
                byte[] slip = BuildPackage(true, true); served = slip;
                manifest = man("1.5.0", Hashing.Sha256(slip), slip.Length, "1.0.0", null);
                var st4 = AppUpdater.Check(cfg, new Settings());
                string e2 = AppUpdater.Download(st4.Release, cfg, null, CancellationToken.None, out staged);
                Check("a package that tries to write outside its folder (..\\) is rejected", e2 != null && e2.Contains("leaves its folder") && staged == null, e2);
                byte[] thin = BuildPackage(false, false); served = thin;
                manifest = man("1.5.0", Hashing.Sha256(thin), thin.Length, "1.0.0", null);
                var st5 = AppUpdater.Check(cfg, new Settings());
                string e3 = AppUpdater.Download(st5.Release, cfg, null, CancellationToken.None, out staged);
                Check("a package without the main program or the helper is rejected", e3 != null && e3.Contains("does not contain"), e3);
                // versions
                served = pkg;
                manifest = man("1.5.0", sha, pkg.Length, "1.2.0", null);
                Check("a program too old for an automatic update is told to download the full package", AppUpdater.Check(cfg, new Settings()).State == AppUpdateState.NeedsManualInstall);
                AppUpdater.CurrentVersion = "1.5.0"; manifest = man("1.5.0", sha, pkg.Length, "1.0.0", null);
                Check("the same version is up to date, an older announcement never offers a downgrade", AppUpdater.Check(cfg, new Settings()).State == AppUpdateState.UpToDate);
                AppUpdater.CurrentVersion = "1.0.0";
                var cfgRemote = new AppConfig { UpdateManifestUrl = "http://example.com/version.json", CheckUpdatesOnStart = true, UpdatePublicKeyXml = pub };
                Check("plain http to a host that is not this PC is refused", AppUpdater.Check(cfgRemote, new Settings()).State == AppUpdateState.Error);
                var cfgNoKey = new AppConfig { UpdateManifestUrl = cfg.UpdateManifestUrl, CheckUpdatesOnStart = true, UpdatePublicKeyXml = "" };
                manifest = man("1.5.0", sha, pkg.Length, "1.0.0", null);
                Check("without a signing key an update cannot be verified, so it is not accepted", AppUpdater.Check(cfgNoKey, new Settings()).State == AppUpdateState.Error);
                srv.Stop(); srv.Close(); srv = null;
                Check("an unreachable server is 'offline' (the program keeps working)", AppUpdater.Check(cfg, new Settings()).State == AppUpdateState.Offline);
            }
            catch (Exception ex) { Check("self-update flow", false, ex.ToString()); }
            finally
            {
                AppUpdater.CurrentVersion = oldVer;
                try { if (srv != null) { srv.Stop(); srv.Close(); } } catch { }
                try { Directory.Delete(kd, true); } catch { }
            }
            // the install result file written by the helper
            Directory.CreateDirectory(AppUpdater.UpdatesDir);
            File.WriteAllText(AppUpdater.ResultFile, "{\"ok\":false,\"rolledBack\":true,\"from\":\"1.0.0\",\"to\":\"1.5.0\",\"error\":\"disk full\",\"time\":\"2026-10-04T10:00:00\"}");
            var res = AppUpdater.TakeResult();
            Check("the result of a failed install (rolled back) is read once and then removed", res != null && !res.Ok && res.RolledBack && res.Error == "disk full" && AppUpdater.TakeResult() == null);
        }

        static byte[] BuildPackage(bool slip, bool complete)
        {
            using (var ms = new MemoryStream())
            {
                using (var za = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    Action<string, string> put = (n, t) => { var e = za.CreateEntry(n); using (var w = new StreamWriter(e.Open())) w.Write(t); };
                    put("MineHunter.exe", "MZ fake main program " + new string('x', 5000));
                    if (complete)
                    {
                        put("components/MineHunter.Core.dll", "MZ fake core " + new string('y', 5000));
                        put("components/MineHunter.UI.dll", "MZ fake ui " + new string('z', 5000));
                        put("components/MineHunter.UpdateHelper.exe", "MZ fake helper " + new string('h', 3000));
                    }
                    put("README.md", "release");
                    if (slip) put("../evil.txt", "should never be written");
                }
                return ms.ToArray();
            }
        }
    }
}
