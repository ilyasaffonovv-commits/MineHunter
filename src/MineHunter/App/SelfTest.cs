using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using MineHunter.Analysis;
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
    /// <summary>Built-in checks: `MineHunter.exe selftest`. They exercise parsing, rules, scoring calibration and the reversible quarantine
    /// without touching anything outside a temporary folder.</summary>
    public static class SelfTest
    {
        static int passed, failed;
        static TextWriter W;

        static void Check(string name, bool ok, string detail = null)
        {
            if (ok) passed++; else failed++;
            W.WriteLine((ok ? "  [PASS] " : "  [FAIL] ") + name + (ok || string.IsNullOrEmpty(detail) ? "" : "   -> " + detail));
        }

        static Entity Ent(EntityKind kind, string title, params Evidence[] ev)
        {
            var e = new Entity { Id = kind + ":" + title, Kind = kind, Title = title, Location = "x" };
            foreach (var x in ev) e.Evidence.Add(x);
            return e;
        }
        static Evidence E(string id, EvidenceCategory c, int w, bool def = false) { return new Evidence(id, c, w, id, null, def); }

        static Verdict V(params Entity[] es) { string why; return RiskEngine.Decide(RiskEngine.Compute(es), out why); }

        public static int Run(TextWriter w)
        {
            W = w; passed = failed = 0;
            w.WriteLine("MineHunter self-test\n");
            var rules = RulePack.Load();

            w.WriteLine("Paths and text helpers");
            Check("classify %TEMP%", PathUtil.Classify(Path.Combine(Path.GetTempPath(), "x.exe")) == PathClass.UserTemp);
            Check("classify System32", PathUtil.Classify(PathUtil.System32 + @"\cmd.exe") == PathClass.WindowsSystem);
            Check("classify Program Files", PathUtil.Classify(PathUtil.ProgramFiles + @"\App\a.exe") == PathClass.ProgramFiles);
            Check("classify ProgramData", PathUtil.Classify(PathUtil.ProgramData + @"\Vendor\a.exe") == PathClass.ProgramData);
            string up = PathUtil.UserProfiles().FirstOrDefault() ?? (PathUtil.SystemDrive + @"\Users\User");
            Check("classify AppData root", PathUtil.Classify(up + @"\AppData\Roaming\a.exe") == PathClass.UserAppDataRoamingRoot);
            Check("classify Local\\Programs is legit per-user install", PathUtil.Classify(up + @"\AppData\Local\Programs\App\a.exe") == PathClass.UserAppDataLocalPrograms);
            Check("homoglyph fold: ReaItekHD -> contains realtek", Text.FoldConfusables("ReaItekHD").Contains("realtek"));
            Check("extract exe from quoted command", PathUtil.ExtractExecutable("\"C:\\Program Files\\A B\\app.exe\" --x 1") == @"C:\Program Files\A B\app.exe");
            Check("extract exe: cmd via System32", (PathUtil.ExtractExecutable("cmd.exe /c echo") ?? "").EndsWith(@"\cmd.exe", StringComparison.OrdinalIgnoreCase));

            w.WriteLine("\nRules and scanners");
            Check("rule pack loaded", rules.CmdRules.Count >= 12 && rules.MinerScanner != null, "cmdRules=" + rules.CmdRules.Count);
            try
            {
                long selfRead; string selfExe = System.Reflection.Assembly.GetExecutingAssembly().Location;
                var selfHits = rules.MinerScanner.ScanFile(selfExe, 64L * 1024 * 1024, 0, out selfRead);
                Check("this program's own EXE contains no miner marker (it must not flag itself or be flagged by other anti-miner tools)", selfHits.Count == 0, selfHits.Count + " marker(s): " + string.Join(", ", selfHits.Keys.Take(6).Select(i => rules.ScanIndex[i].Value)));
            }
            catch (Exception ex) { Check("self scan for miner markers", false, ex.Message); }
            Check("publisher trust: real vendor names pass", rules.IsTrustedPublisher("Intel Corporation") && rules.IsTrustedPublisher("NVIDIA Corporation") && rules.IsTrustedPublisher("ASUSTeK COMPUTER INC.") && rules.IsTrustedPublisher("Valve Corp.") && rules.IsTrustedPublisher("Advanced Micro Devices, Inc."));
            Check("publisher trust: look-alike names are NOT trusted", !rules.IsTrustedPublisher("Intelligent Systems Ltd") && !rules.IsTrustedPublisher("Pineapple Corp") && !rules.IsTrustedPublisher("Valverde Media LLC") && !rules.IsTrustedPublisher("Free Intel Miner LLC") && !rules.IsTrustedPublisher(""));
            var sc = new StringScanner(new[] { Obf.J("stra", "tum+tcp://"), Obf.J("xm", "rig"), Obf.J("random", "x") });
            var bytesA = Encoding.ASCII.GetBytes("junk " + Obf.J("STRA", "TUM+TCP") + "://pool:3333 more " + Obf.J("XM", "Rig"));
            var bytesU = Encoding.Unicode.GetBytes(Obf.J("random", "x"));
            var hitsA = sc.ScanBytes(bytesA, bytesA.Length);
            var hitsU = sc.ScanBytes(bytesU, bytesU.Length);
            Check("string scanner finds ASCII case-insensitively", hitsA.ContainsKey(0) && hitsA.ContainsKey(1));
            Check("string scanner finds UTF-16", hitsU.ContainsKey(2));
            string minerCmd = Obf.J("xm", "rig") + ".exe -o " + Obf.J("stra", "tum+tcp") + "://pool.support" + Obf.J("x", "mr") + ".com:3333 -u 49abcdef -p x --" + Obf.J("don", "ate-level") + " 1 -a " + Obf.J("r", "x/0");
            Check("miner command line hits rules", rules.CmdRules.Count(r => r.Rx.IsMatch(minerCmd)) >= 3);
            foreach (var benign in new[] { "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --profile-directory=Default", "node.exe server.js --port 3333", "python.exe -m http.server 4444", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "\"C:\\Program Files\\Docker\\Docker Desktop.exe\"", "java -jar minecraft.jar --algo test" })
                Check("benign command line has no miner hit: " + Text.Trunc(benign, 45), !rules.CmdRules.Any(r => r.Id.StartsWith("CMD.MINER") && r.Definitive && r.Rx.IsMatch(benign)) && !rules.CmdRules.Any(r => r.Id == "CMD.MINER.STRATUM_URL" && r.Rx.IsMatch(benign)));
            Check("Defender exclusion command detected", rules.CmdRules.Any(r => r.Id == "CMD.DEFENDER.EXCLUSION" && r.Rx.IsMatch("powershell -c Add-MpPreference -ExclusionPath 'C:\\ProgramData'")));

            string notepad = Path.Combine(PathUtil.System32, "notepad.exe");
            if (File.Exists(notepad))
            {
                var pe = PeAnalyzer.Analyze(notepad, true);
                Check("PE parser reads notepad.exe", pe.IsPe && pe.Is64 && pe.Sections.Count >= 3 && pe.ImportDlls.Count > 0, "sections=" + pe.Sections.Count + " imports=" + pe.ImportDlls.Count);
                var ti = Trust.Check(notepad);
                Check("Authenticode/catalog verification: notepad.exe is Microsoft-signed", ti.IsValid && FileIntelClassify(ti, rules) == TrustClass.MicrosoftSigned, ti.ToString());
            }
            string self = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            Check("verification: this build is reported as unsigned (honest)", Trust.Check(self).State == TrustState.Unsigned || Trust.Check(self).IsValid == false);

            w.WriteLine("\nRisk engine calibration (false-positive safety)");
            Check("unsigned + temp + high CPU alone stays Clean/low", V(Ent(EntityKind.File, "a", E("SIG.UNSIGNED", EvidenceCategory.Signature, 6), E("LOC.TEMP", EvidenceCategory.Location, 6), E("BEH.CPU_SUSTAINED", EvidenceCategory.Behavior, 10))) == Verdict.Clean);
            Check("trusted heavy program stays Clean", V(Ent(EntityKind.File, "steam", E("TRUST.OS_SIGNED", EvidenceCategory.Trust, -70)), Ent(EntityKind.Process, "steam.exe")) == Verdict.Clean);
            Check("many weak path/signature hits never exceed Suspicious",
                  V(Ent(EntityKind.File, "b", E("SIG.UNSIGNED", EvidenceCategory.Signature, 6), E("LOC.APPDATA_ROOT", EvidenceCategory.Location, 12), E("ATTR.HIDDEN", EvidenceCategory.Location, 5), E("PE.PACKED", EvidenceCategory.Content, 5))) <= Verdict.Suspicious);
            Check("one loud category without confirmation is capped at Suspicious", V(Ent(EntityKind.Process, "c", E("X1", EvidenceCategory.Behavior, 40), E("X2", EvidenceCategory.Behavior, 40), E("X3", EvidenceCategory.Behavior, 30))) == Verdict.Suspicious);
            Check("complete miner command line (definitive) = High Risk", V(Ent(EntityKind.Process, "d", E("CMD.MINER.STRATUM_URL", EvidenceCategory.Content, 40, true), E("CMD.MINER.POOL_USER", EvidenceCategory.Content, 35))) >= Verdict.HighRisk);
            Check("miner + persistence + masquerade = Malware", V(Ent(EntityKind.Process, "e", E("CMD.MINER.STRATUM_URL", EvidenceCategory.Content, 40, true), E("CMD.MINER.POOL_USER", EvidenceCategory.Content, 35)), Ent(EntityKind.Task, "t", E("PERSIST.TARGET_USER_PATH", EvidenceCategory.Persistence, 16), E("TASK.MS_NAMESPACE_UNTRUSTED", EvidenceCategory.Masquerade, 25)), Ent(EntityKind.File, "f", E("SIG.UNSIGNED", EvidenceCategory.Signature, 6), E("MASQ.SYSTEM_NAME_WRONG_PATH", EvidenceCategory.Masquerade, 32))) == Verdict.Malware);
            Check("fake svchost (masquerade + wrong parent) = High Risk", V(Ent(EntityKind.File, "svchost.exe", E("MASQ.SYSTEM_NAME_WRONG_PATH", EvidenceCategory.Masquerade, 32), E("SIG.UNSIGNED", EvidenceCategory.Signature, 6), E("LOC.TEMP", EvidenceCategory.Location, 6)), Ent(EntityKind.Process, "svchost.exe", E("PROC.PARENT_ANOMALY", EvidenceCategory.Behavior, 25))) == Verdict.HighRisk);
            Check("multi-signal harmless-looking program (unsigned + appdata + CPU + 3 autostarts) = High Risk",
                  V(Ent(EntityKind.File, "m", E("SIG.UNSIGNED", EvidenceCategory.Signature, 6), E("LOC.APPDATA", EvidenceCategory.Location, 4), E("PERSIST.MULTI", EvidenceCategory.Persistence, 24)),
                    Ent(EntityKind.RunKey, "r", E("PERSIST.TARGET_USER_PATH", EvidenceCategory.Persistence, 16)), Ent(EntityKind.Task, "t", E("PERSIST.TARGET_USER_PATH", EvidenceCategory.Persistence, 16), E("TASK.REPEAT_SHORT", EvidenceCategory.Persistence, 8)),
                    Ent(EntityKind.Process, "p", E("BEH.CPU_SUSTAINED", EvidenceCategory.Behavior, 10), E("PROC.PARENT_ANOMALY", EvidenceCategory.Behavior, 12))) >= Verdict.HighRisk);
            Check("known-bad hash alone = Malware", V(Ent(EntityKind.File, "h", E("REP.KNOWN_BAD_HASH", EvidenceCategory.Reputation, 100, true))) == Verdict.Malware);
            Check("Trust evidence lowers the file's own evidence but never a process's behaviour",
                  RiskEngine.Compute(new[] { Ent(EntityKind.Process, "hollow", E("PROC.HOLLOW.IMAGE_MISMATCH", EvidenceCategory.Behavior, 62, true)) }).Total >= 60);

            w.WriteLine("\nDecision safety");
            Check("critical Windows processes are never killed", Decision.IsProtectedProcess(Ent(EntityKind.Process, "csrss.exe")) && Decision.IsProtectedProcess(Ent(EntityKind.Process, "lsass.exe")));
            var trustedFile = Ent(EntityKind.File, "notepad.exe"); trustedFile.Trusted = true; trustedFile.Location = notepad;
            Check("trusted files are never quarantined", Decision.IsProtectedFile(null, trustedFile));

            w.WriteLine("\nReversible quarantine (temp folder only)");
            string dir = Path.Combine(Path.GetTempPath(), "mh_selftest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            try
            {
                string f1 = Path.Combine(dir, "a.bin"), f2 = Path.Combine(dir, "b.bin");
                var data = new byte[3 * 1024 * 1024 + 123]; new Random(5).NextBytes(data);
                File.WriteAllBytes(f1, data); File.WriteAllBytes(f2, data);
                string e1, e2;
                var i1 = Quarantine.StoreFile("File", f1, "selftest", "test", out e1);
                var i2 = Quarantine.StoreFile("File", f2, "selftest", "test", out e2);
                Check("identical files get separate quarantine ids (no collision)", i1 != null && i2 != null && i1.Id != i2.Id && i1.Sha256 == i2.Sha256, e1 + e2);
                if (i1 != null && i2 != null)
                {
                    Check("stored payload is not the plain file", !File.ReadAllBytes(Path.Combine(i1.Dir, i1.PayloadFile)).Take(4096).SequenceEqual(data.Take(4096)));
                    File.Delete(f1); File.Delete(f2);
                    string r1 = Quarantine.RestoreFileTo(i1, f1, false), r2 = Quarantine.RestoreFileTo(i2, f2, false);
                    Check("both files restore with identical SHA-256", r1 == null && r2 == null && Hashing.Sha256(f1) == i1.Sha256 && Hashing.Sha256(f2) == i2.Sha256, r1 + r2);
                    var damaged = Path.Combine(i1.Dir, i1.PayloadFile); var bytes = File.ReadAllBytes(damaged); bytes[100] ^= 0xFF; File.WriteAllBytes(damaged, bytes);
                    File.Delete(f1);
                    Check("damaged quarantine copy is refused on restore", Quarantine.RestoreFileTo(i1, f1, false) != null && !File.Exists(f1));
                    Quarantine.Delete(i1); Quarantine.Delete(i2);
                    Check("quarantine delete removes the item", !Directory.Exists(i1.Dir) && !Directory.Exists(i2.Dir));
                }
            }
            finally { try { Directory.Delete(dir, true); } catch { } }

            w.WriteLine("\nRegistry export/import round trip");
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\MineHunterSelfTest\A"))
                {
                    k.SetValue("s", "text"); k.SetValue("d", 42, Microsoft.Win32.RegistryValueKind.DWord); k.SetValue("m", new[] { "x", "y" }, Microsoft.Win32.RegistryValueKind.MultiString); k.SetValue("b", new byte[] { 1, 2, 3 }, Microsoft.Win32.RegistryValueKind.Binary);
                    using (var s = k.CreateSubKey("Sub")) s.SetValue("q", 7L, Microsoft.Win32.RegistryValueKind.QWord);
                }
                Dictionary<string, object> exp;
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\MineHunterSelfTest\A")) exp = RegExport.Export(k);
                var text = Json.Serialize(exp); var back = Json.Obj(Json.Parse(text));
                Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\MineHunterSelfTest\A");
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\MineHunterSelfTest\B")) RegExport.Import(k, back);
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\MineHunterSelfTest\B"))
                    Check("registry values and sub-keys survive export -> JSON -> import", (string)k.GetValue("s") == "text" && (int)k.GetValue("d") == 42 && ((string[])k.GetValue("m")).Length == 2 && ((byte[])k.GetValue("b")).Length == 3 && (long)k.OpenSubKey("Sub").GetValue("q") == 7L);
            }
            catch (Exception ex) { Check("registry round trip", false, ex.Message); }
            finally { try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\MineHunterSelfTest", false); } catch { } }

            w.WriteLine("\nUpdates and signatures");
            Check("version compare", Updater.CompareVersions("1.2.0", "1.10.0") < 0 && Updater.CompareVersions("v2.0", "1.9.9") > 0 && Updater.CompareVersions("1.0.0", "1.0.0") == 0);
            try
            {
                string kd = Path.Combine(Path.GetTempPath(), "mh_keys_" + Guid.NewGuid().ToString("N").Substring(0, 6)); Directory.CreateDirectory(kd);
                Updater.GenerateKeys(kd);
                string pack = Path.Combine(kd, "pack.json"); File.WriteAllText(pack, "{\"pack\":\"x\",\"version\":\"9\"}");
                string sig = Updater.Sign(pack, Path.Combine(kd, "update_private.xml"));
                bool ok = Updater.VerifySignature(File.ReadAllBytes(pack), sig, File.ReadAllText(Path.Combine(kd, "update_public.xml")));
                File.WriteAllText(pack, "{\"pack\":\"x\",\"version\":\"9\",\"evil\":1}");
                bool tampered = Updater.VerifySignature(File.ReadAllBytes(pack), sig, File.ReadAllText(Path.Combine(kd, "update_public.xml")));
                Check("rule-pack signature verifies, and rejects a modified pack", ok && !tampered);
                try { Directory.Delete(kd, true); } catch { }
            }
            catch (Exception ex) { Check("signature round trip", false, ex.Message); }

            w.WriteLine("\nUpdate flow end-to-end (loopback server + temporary data folder)");
            string oldData = Environment.GetEnvironmentVariable("MINEHUNTER_DATA_DIR");
            string tmpData = Path.Combine(Path.GetTempPath(), "mh_upd_" + Guid.NewGuid().ToString("N").Substring(0, 6));
            System.Net.HttpListener srv = null;
            try
            {
                Environment.SetEnvironmentVariable("MINEHUNTER_DATA_DIR", tmpData);
                string kd = Path.Combine(tmpData, "keys"); Directory.CreateDirectory(kd);
                Updater.GenerateKeys(kd); string pub = File.ReadAllText(Path.Combine(kd, "update_public.xml")), priv = Path.Combine(kd, "update_private.xml");
                string otherDir = Path.Combine(tmpData, "keys2"); Directory.CreateDirectory(otherDir); Updater.GenerateKeys(otherDir);
                var tcp = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); tcp.Start(); int port = ((System.Net.IPEndPoint)tcp.LocalEndpoint).Port; tcp.Stop();
                byte[] pack = Encoding.UTF8.GetBytes("{\"version\":\"2099.01.01.1\",\"minerStrings\":{\"selftest\":[\"mh-selftest-marker\"]}}");
                string packFile = Path.Combine(tmpData, "pack.json"); File.WriteAllBytes(packFile, pack);
                string goodSig = Updater.Sign(packFile, priv), badSig = Updater.Sign(packFile, Path.Combine(otherDir, "update_private.xml")), sha = Hashing.Sha256(pack);
                string manifest = "";
                srv = new System.Net.HttpListener(); srv.Prefixes.Add("http://127.0.0.1:" + port + "/"); srv.Start();
                var listener = srv;
                System.Threading.Tasks.Task.Run(() =>
                {
                    while (listener.IsListening)
                    {
                        try
                        {
                            var ctx = listener.GetContext(); byte[] body = ctx.Request.Url.AbsolutePath == "/rules.json" ? pack : Encoding.UTF8.GetBytes(manifest);
                            ctx.Response.OutputStream.Write(body, 0, body.Length); ctx.Response.Close();
                        }
                        catch { }
                    }
                });
                Func<string, string, string, string> man = (latest, sh, sg) => "{\"latestVersion\":\"" + latest + "\",\"releaseUrl\":\"https://example.invalid/release\",\"rules\":{\"version\":\"2099.01.01.1\",\"url\":\"http://127.0.0.1:" + port + "/rules.json\",\"sha256\":\"" + sh + "\"" + (sg != null ? ",\"signature\":\"" + sg + "\"" : "") + "}}";
                var cfg = new AppConfig { UpdateManifestUrl = "http://127.0.0.1:" + port + "/version.json", CheckUpdatesOnStart = true, UpdatePublicKeyXml = pub };

                manifest = man("99.0.0", sha, goodSig);
                var u1 = Updater.Check(cfg, "2026.01.01.1");
                Check("newer app version is announced (UpdateAvailable)", u1.State == UpdateState.UpdateAvailable && u1.Latest == "99.0.0" && u1.RulesNewer, u1.Message);
                string err = Updater.UpdateRules(cfg, u1);
                var loaded = RulePack.Load();
                Check("signed rule pack downloads, verifies and installs", err == null && loaded.Version == "2099.01.01.1" && loaded.MinerStrings.ContainsKey("selftest"), err);
                manifest = man(AppInfo.Version, sha, goodSig);
                Check("same version = UpToDate", Updater.Check(cfg, "2099.01.01.1").State == UpdateState.UpToDate);
                manifest = man("99.0.0", "0000000000000000000000000000000000000000000000000000000000000000", goodSig);
                string e2 = Updater.UpdateRules(cfg, Updater.Check(cfg, "2026.01.01.1"));
                Check("rule pack with wrong SHA-256 is rejected", e2 != null && e2.Contains("SHA-256"), e2);
                manifest = man("99.0.0", sha, badSig);
                string e3 = Updater.UpdateRules(cfg, Updater.Check(cfg, "2026.01.01.1"));
                Check("rule pack signed with a different key is rejected", e3 != null && e3.Contains("signature"), e3);
                manifest = man("99.0.0", sha, null);
                string e4 = Updater.UpdateRules(cfg, Updater.Check(cfg, "2026.01.01.1"));
                Check("unsigned rule pack is rejected when a signing key is configured", e4 != null && e4.Contains("not signed"), e4);
                var cfgRemote = new AppConfig { UpdateManifestUrl = "http://example.com/version.json", CheckUpdatesOnStart = true };
                Check("plain http to a non-local host is refused", Updater.Check(cfgRemote, "1").State == UpdateState.Error);
                srv.Stop(); srv.Close(); srv = null;
                Check("unreachable update server = Offline (scan still works)", Updater.Check(cfg, "1").State == UpdateState.Offline);
            }
            catch (Exception ex) { Check("update flow", false, ex.Message); }
            finally
            {
                try { if (srv != null) { srv.Stop(); srv.Close(); } } catch { }
                Environment.SetEnvironmentVariable("MINEHUNTER_DATA_DIR", oldData);
                try { Directory.Delete(tmpData, true); } catch { }
            }

            w.WriteLine("\nReports");
            var empty = new ScanResult { AppVersion = AppInfo.Version, Started = DateTime.Now, Finished = DateTime.Now, Mode = "Quick", RulesVersion = rules.Version };
            Check("empty report serialises to JSON and text", Json.Serialize(ReportWriter.ToJson(empty)).Length > 50 && ReportWriter.ToText(empty).Contains("MineHunter"));

            w.WriteLine("\n" + (failed == 0 ? "ALL " + passed + " CHECKS PASSED" : failed + " CHECK(S) FAILED, " + passed + " passed"));
            return failed == 0 ? 0 : 1;
        }

        static TrustClass FileIntelClassify(TrustInfo ti, RulePack rules)
        {
            var tc = FileIntel.Classify(ti);
            if (tc == TrustClass.SignedOther && ti.IsValid && rules.IsTrustedPublisher(ti.Publisher)) return TrustClass.TrustedPublisher;
            return tc;
        }
    }
}
