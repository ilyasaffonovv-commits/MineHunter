using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using Microsoft.Win32;
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

        /// <summary>An attacker running as the current user can write next to the EXE, set environment variables and edit user-level files. None of that may be
        /// enough to switch MineHunter off, redirect its data, or make it trust the attacker's own file.</summary>
        static void SelfProtectionChecks()
        {
            W.WriteLine("\nSelf-protection (ordinary-user tampering must not weaken the scanner)");
            string tmp = Path.Combine(Path.GetTempPath(), "mh_sp_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tmp);
            try
            {
                string f = Path.Combine(tmp, "approved.bin");
                File.WriteAllBytes(f, new byte[] { 1, 2, 3, 4, 5 });
                var al = new Allowlist();
                string sha = al.Approve(f);
                Check("allow-list: an approved file is trusted by its SHA-256", sha != null && al.Contains(f, sha));
                File.WriteAllBytes(f, new byte[] { 9, 9, 9, 9 });
                string sha2 = Hashing.Sha256(f);
                Check("allow-list: the same path with different content is NOT trusted (a replaced file loses its approval)", !al.Contains(f, sha2) && !al.Contains(f, null));
                Check("allow-list: a file that cannot be hashed is not approved at all", new Allowlist().Approve(Path.Combine(tmp, "missing.bin")) == null);

                string baseRule = "{\"version\":\"2026.01.01.1\",\"cmdlinePatterns\":[{\"id\":\"CMD.SP.X\",\"regex\":\"spx\",\"weight\":30,\"category\":\"Content\",\"text\":\"t\"}]}";
                string evil = "{\"version\":\"2099.01.01.1\",\"cmdlinePatterns\":[{\"id\":\"CMD.SP.X\",\"regex\":\"zzz\",\"weight\":0,\"category\":\"Content\",\"text\":\"t\"},"
                            + "{\"id\":\"CMD.SP.NEW\",\"regex\":\"newrule\",\"weight\":20,\"category\":\"Content\",\"text\":\"t\"},{\"id\":\"CMD.SP.NEG\",\"regex\":\"negrule\",\"weight\":-50,\"category\":\"Content\",\"text\":\"t\"}],"
                            + "\"disabledRules\":[\"CMD.SP.X\"],\"trustedPublishers\":[\"Evil Miner Inc\"],\"heavyAppNames\":[\"evilminer\"],\"knownGoodHashes\":{\"" + new string('b', 64) + "\":\"x\"}}";
                var pk = new RulePack(); pk.Merge(baseRule, "base"); pk.Merge(evil, "next-to-exe", true); pk.Build();
                var x = pk.CmdRules.SingleOrDefault(r => r.Id == "CMD.SP.X");
                Check("a pack next to the EXE cannot replace, weaken or disable a built-in rule", x != null && x.Weight == 30 && x.Rx.IsMatch("spx") && !x.Rx.IsMatch("zzz"));
                Check("a pack next to the EXE cannot vouch for a publisher, an app or a file", !pk.IsTrustedPublisher("Evil Miner Inc") && !pk.HeavyApps.Contains("evilminer") && pk.GoodHashes.Count == 0);
                var nw = pk.CmdRules.SingleOrDefault(r => r.Id == "CMD.SP.NEW"); var ng = pk.CmdRules.SingleOrDefault(r => r.Id == "CMD.SP.NEG");
                Check("a pack next to the EXE can still ADD a detection; a negative (trust) weight is clamped to 0", nw != null && nw.Weight == 20 && ng != null && ng.Weight == 0);

                string inst = Path.Combine(tmp, "install.json"), usr = Path.Combine(tmp, "user.json");
                File.WriteAllText(inst, "{\"updateManifestUrl\":\"https://evil.invalid/v.json\",\"updatePublicKeyXml\":\"<RSAKeyValue>evil</RSAKeyValue>\",\"scanMemory\":false,\"scanBrowsers\":false,\"autoUpdateRules\":false,\"language\":\"ru\"}");
                var c = AppConfig.Load(inst, usr);
                Check("config.json next to the EXE cannot change the update address, the signing key or the scan switches", c.UpdateManifestUrl == AppConfig.DefaultManifestUrl && c.UpdatePublicKeyXml == AppConfig.DefaultPublicKeyXml && c.ScanMemory && c.ScanBrowsers && c.AutoUpdateRules);
                Check("... while a harmless interface preference still works", c.Language == "ru");
                File.WriteAllText(usr, "{\"scanMemory\":false}");
                Check("the protected user config in the data folder may change them", !AppConfig.Load(inst, usr).ScanMemory);

                string oldEnv = Environment.GetEnvironmentVariable("MINEHUNTER_DATA_DIR");
                try
                {
                    Environment.SetEnvironmentVariable("MINEHUNTER_DATA_DIR", tmp);
                    Check("the data folder cannot be redirected with an environment variable", RulePack.TestDataDirOverride == null && !string.Equals(RulePack.DataDir.TrimEnd('\\'), tmp.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
                }
                finally { Environment.SetEnvironmentVariable("MINEHUNTER_DATA_DIR", oldEnv); }
            }
            catch (Exception ex) { Check("self-protection checks", false, ex.Message); }
            finally { try { Directory.Delete(tmp, true); } catch { } }
        }

        static ScanContext TestCtx(RulePack rules) { return new ScanContext(rules, new Allowlist(), new ScanOptions(), CancellationToken.None); }
        static string DumpEntities(ScanContext c) { return string.Join(" | ", c.Entities.Values.Select(e => e.Id + "=[" + string.Join(",", e.Evidence.Select(x => x.RuleId)) + "]")); }
        static bool HasRule(Entity e, string id) { return e != null && e.Evidence.Any(x => x.RuleId == id); }
        static Entity Find(ScanContext c, Func<Entity, bool> pred) { return c.Entities.Values.FirstOrDefault(pred); }

        /// <summary>The mechanisms added to find miners that do not announce themselves (packed, renamed, hidden in streams or archives), the kernel-integrity
        /// checks, the less common autostart points and the "came back after cleaning" memory. Each one is exercised on harmless synthetic input.</summary>
        static void DetectionChecks(RulePack rules)
        {
            W.WriteLine("\nMiner profile, memory, config files, streams, archives, kernel integrity, autostart points, relapse");
            string tmp = Path.Combine(Path.GetTempPath(), "mh_dt_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tmp);
            string oldData = RulePack.TestDataDirOverride;
            try
            {
                var ctx = TestCtx(rules);
                string user = PathUtil.UserProfiles().FirstOrDefault() ?? @"C:\Users\Test";
                string appPath = user + @"\AppData\Roaming\vendor\tool.exe";

                // ---- miner profile: the classic fingerprint, and every way of NOT matching it
                Func<bool, string, double, double, bool, bool, Entity> prof = (trusted, path, cpu, gpu, window, net) =>
                {
                    var img = new Entity { Id = "file:x", Kind = EntityKind.File, Title = "x.exe", Location = path, Trusted = trusted };
                    var ent = new Entity { Id = "proc:1:1", Kind = EntityKind.Process, Title = "x.exe" };
                    if (net) ent.Add(new Evidence("NET.PERSISTENT_UNTRUSTED", EvidenceCategory.Network, 4, "t"));
                    MinerProfile.Triad(ctx, new ProcInfo { Pid = 1, Name = "x.exe", Path = path, Image = img, Entity = ent, CpuPercent = cpu, GpuPercent = gpu, HasWindow = window });
                    return ent;
                };
                Check("miner profile: unsigned, windowless program in a user folder with heavy CPU and a public connection is flagged", HasRule(prof(false, appPath, 60, 0, false, true), "BEH.MINER_PROFILE"));
                Check("miner profile: heavy GPU use counts the same as CPU", HasRule(prof(false, appPath, 1, 80, false, true), "BEH.MINER_PROFILE"));
                Check("miner profile: a signed program is not flagged", !HasRule(prof(true, appPath, 60, 0, false, true), "BEH.MINER_PROFILE"));
                Check("miner profile: a program with a window is not flagged", !HasRule(prof(false, appPath, 60, 0, true, true), "BEH.MINER_PROFILE"));
                Check("miner profile: no network connection, no flag", !HasRule(prof(false, appPath, 60, 0, false, false), "BEH.MINER_PROFILE"));
                Check("miner profile: low load, no flag", !HasRule(prof(false, appPath, 3, 2, false, true), "BEH.MINER_PROFILE"));
                Check("miner profile: an installed program (Program Files) is not flagged", !HasRule(prof(false, PathUtil.ProgramFiles + @"\App\x.exe", 60, 0, false, true), "BEH.MINER_PROFILE"));

                Func<string, bool, string, bool, string[], Entity> cheap = (owner, trusted, path, window, mods) =>
                {
                    var img = new Entity { Id = "file:y", Kind = EntityKind.File, Title = "y.exe", Location = path, Trusted = trusted };
                    var ent = new Entity { Id = "proc:2:2", Kind = EntityKind.Process, Title = "y.exe" };
                    MinerProfile.Cheap(ctx, new ProcInfo { Pid = 2, Name = "y.exe", Path = path, Image = img, Entity = ent, Owner = owner, HasWindow = window, Modules = mods == null ? new List<string>() : mods.ToList() });
                    return ent;
                };
                Check("SYSTEM rights + unsigned file in a user-writable folder is flagged", HasRule(cheap(@"NT AUTHORITY\SYSTEM", false, appPath, true, null), "PROC.SYSTEM_FROM_USERPATH"));
                Check("... an ordinary user account is not", !HasRule(cheap(@"PC\User", false, appPath, true, null), "PROC.SYSTEM_FROM_USERPATH"));
                Check("... nor a signed program running as SYSTEM", !HasRule(cheap(@"NT AUTHORITY\SYSTEM", true, appPath, true, null), "PROC.SYSTEM_FROM_USERPATH"));
                Check("GPU compute libraries in an unsigned windowless user-folder program are noted", HasRule(cheap(@"PC\User", false, appPath, false, new[] { @"C:\Windows\System32\nvcuda.dll" }), "PROC.GPU_COMPUTE_LIBS"));
                Check("... but not when the program has a window", !HasRule(cheap(@"PC\User", false, appPath, true, new[] { @"C:\Windows\System32\nvcuda.dll" }), "PROC.GPU_COMPUTE_LIBS"));

                // ---- memory: a live process is read and the miner words found in it; an ordinary Windows tool has none
                var me = new ProcInfo { Pid = System.Diagnostics.Process.GetCurrentProcess().Id, Name = "selftest.exe", Entity = new Entity { Id = "proc:me", Kind = EntityKind.Process, Title = "selftest" } };
                long readMe; MinerProfile.ScanMemory(ctx, me, out readMe);
                Check("memory scan reads a live process and finds miner markers in its memory (this process holds the rule pack)", readMe > 1000000 && HasRule(me.Entity, "PROC.MEM.MINER_STRONG"), "read " + readMe + " bytes");
                var ping = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(PathUtil.System32, "ping.exe"), "-n 6 127.0.0.1") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
                try
                {
                    System.Threading.Thread.Sleep(300);
                    var pp = new ProcInfo { Pid = ping.Id, Name = "ping.exe", Entity = new Entity { Id = "proc:ping", Kind = EntityKind.Process, Title = "ping" } };
                    long readPing; MinerProfile.ScanMemory(ctx, pp, out readPing);
                    Check("memory scan: an ordinary Windows tool holds no miner markers", readPing > 100000 && !pp.Entity.Evidence.Any(x => x.Weight > 0), "read " + readPing + " bytes");
                }
                finally { try { ping.Kill(); } catch { } try { ping.Dispose(); } catch { } }

                // ---- miner configuration files
                string cfgMiner = "{\"autosave\":true,\"pools\":[{\"url\":\"127.0.0.1:3333\",\"user\":\"WalletNotReal0000000000\",\"pass\":\"x\"}],\"algo\":\"" + Obf.J("rx", "/0") + "\",\"" + Obf.J("donate", "-level") + "\":1}";
                string cfgDb = "{\"pools\":[{\"url\":\"db.example.com:5432\",\"user\":\"service_account\",\"pass\":\"x\"}],\"timeout\":30}";
                string fMiner = Path.Combine(tmp, "config.json"), fDb = Path.Combine(tmp, "dbconfig.json"), fBin = Path.Combine(tmp, "config.txt");
                File.WriteAllText(fMiner, cfgMiner); File.WriteAllText(fDb, cfgDb); File.WriteAllBytes(fBin, new byte[] { 0, 1, 2, 3, 0, 0, 7, 8, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 });
                var rm = MinerConfigAnalyzer.Analyze(ctx, fMiner);
                Check("config file: pool + wallet + mining options is a miner configuration (definitive)", rm != null && rm.Definitive && rm.RuleId == "MINER.CONFIG_FILE");
                Check("config file: a database connection-pool configuration is NOT one", MinerConfigAnalyzer.Analyze(ctx, fDb) == null);
                Check("config file: a binary file is ignored", MinerConfigAnalyzer.Analyze(ctx, fBin) == null);
                Check("config file names: config.json is looked at, an unrelated name is not", MinerConfigAnalyzer.IsCandidateName(@"C:\x\config.json") && MinerConfigAnalyzer.IsCandidateName(@"C:\x\pools.txt") && !MinerConfigAnalyzer.IsCandidateName(@"C:\x\readme.txt"));

                // ---- NTFS alternate data streams
                string host = Path.Combine(tmp, "host.txt");
                File.WriteAllText(host, "hello");
                byte[] payload = new byte[200]; payload[0] = (byte)'M'; payload[1] = (byte)'Z';
                Check("a stream can be written through the Win32 wrapper (plain File.* rejects file:stream paths on .NET Framework)", AdsScanner.Write(host, "payload", payload));
                AdsScanner.Write(host, "Zone.Identifier", Encoding.ASCII.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/a.exe\r\n"));
                var streams = AdsScanner.Streams(host);
                Check("alternate streams are listed (a hidden payload and Zone.Identifier)", streams.Any(s => s.Name == "payload") && streams.Any(s => s.Name == "Zone.Identifier"));
                Check("Zone.Identifier is treated as normal, a custom stream is not", AdsScanner.IsBenignStream("Zone.Identifier") && !AdsScanner.IsBenignStream("payload"));
                string rule, text, kind; int wt; bool def;
                Check("a stream that starts with MZ is an executable hidden in a stream (definitive)", AdsScanner.Classify(AdsScanner.Head(host, "payload"), 200, out rule, out wt, out def, out text, out kind) && rule == "ADS.PE_STREAM" && def);
                Check("a PowerShell script in a stream is recognised", AdsScanner.Classify(Encoding.ASCII.GetBytes("powershell -enc AAAA"), 20, out rule, out wt, out def, out text, out kind) && rule == "ADS.SCRIPT_STREAM");
                Check("a short harmless text stream is ignored", !AdsScanner.Classify(Encoding.ASCII.GetBytes("note"), 4, out rule, out wt, out def, out text, out kind));
                {
                    // the whole chain on a real file: finding -> plan -> remove only the stream -> restore it
                    RulePack.TestDataDirOverride = Path.Combine(tmp, "data1");
                    var he = ctx.Files.Inspect(host, FileRole.Referenced);
                    he.Add(new Evidence("ADS.PE_STREAM", EvidenceCategory.Content, 55, "hidden program", host + ":payload", true));
                    he.Set("adsStreams", "payload");
                    var fnd = new Finding { Id = "T1", Title = "ads test", Verdict = Verdict.HighRisk, Score = 60, Entities = new List<Entity> { he } };
                    Decision.Plan(ctx, fnd);
                    Check("stream plan: removes the stream and does NOT quarantine the harmless host file", fnd.Steps.Any(s => s.Type == ActionType.RemoveStream) && !fnd.Steps.Any(s => s.Type == ActionType.QuarantineFile));
                    var oc = RemediationEngine.Execute(ctx, fnd, fnd.Steps, null);
                    Check("stream removal: the stream is gone, the file stays", oc.Results.All(r => r.Success) && File.Exists(host) && !AdsScanner.Streams(host).Any(s => s.Name == "payload") && File.ReadAllText(host) == "hello");
                    var qi = Quarantine.List().FirstOrDefault(i => i.Type == "Stream");
                    Check("stream removal: a copy was kept and can be restored byte for byte", qi != null && RemediationEngine.Restore(qi) == null && AdsScanner.Head(host, "payload").SequenceEqual(payload.Take(200)));
                }

                // ---- archives: names only, no extraction
                string zip1 = Path.Combine(tmp, "tools.zip"), zip2 = Path.Combine(tmp, "docs.zip");
                string mn = Obf.J("xm", "rig");
                using (var za = ZipFile.Open(zip1, ZipArchiveMode.Create)) { za.CreateEntry(mn + "-6.21.0/" + mn + ".exe"); za.CreateEntry("readme.txt"); }
                using (var za = ZipFile.Open(zip2, ZipArchiveMode.Create)) { za.CreateEntry("setup.exe"); za.CreateEntry("lib/helper.dll"); }
                int aw;
                Check("archive: a miner-named executable inside a zip is noticed without unpacking it", ArchiveNames.Find(ctx, zip1, out aw) != null && aw >= 15);
                Check("archive: an ordinary zip is not", ArchiveNames.Find(ctx, zip2, out aw) == null);

                // ---- provenance: Mark of the Web and owner
                var pe = new Entity { Id = "file:host", Kind = EntityKind.File, Title = "host.txt", Location = host };
                Provenance.Fill(pe);
                Check("provenance: the Mark of the Web (zone 3, download address) is read from Zone.Identifier", pe.P("zoneId") == "3" && (pe.P("hostUrl") ?? "").Contains("example.invalid") && (pe.P("origin") ?? "").StartsWith("Downloaded from the Internet"));
                Check("provenance: the NTFS owner of the file is read", !string.IsNullOrEmpty(pe.P("fileOwner")));

                // ---- kernel integrity
                uint ci; int cist = IntegrityScanner.ReadCodeIntegrity(out ci);
                Check("kernel code-integrity state can be read", cist == 0, "status 0x" + cist.ToString("X"));
                var c1 = TestCtx(rules); IntegrityScanner.CodeIntegrityEvidence(c1, 0x3);
                var c2 = TestCtx(rules); IntegrityScanner.CodeIntegrityEvidence(c2, 0x0);
                var c3 = TestCtx(rules); IntegrityScanner.CodeIntegrityEvidence(c3, 0x1);
                Check("test-signing mode is reported, integrity checks off are reported, a normal system is quiet",
                      Find(c1, e => HasRule(e, "TAMPER.TESTSIGNING")) != null && Find(c2, e => HasRule(e, "TAMPER.CI_DISABLED")) != null && !c3.Entities.Values.Any(e => e.Evidence.Count > 0));
                var drv = IntegrityScanner.LoadedDriverPaths();
                Check("the list of loaded kernel drivers can be read (and contains the kernel)", drv != null && drv.Count > 20 && drv.Any(x => x.EndsWith("ntoskrnl.exe", StringComparison.OrdinalIgnoreCase)), drv == null ? "null" : drv.Count + " drivers");
                Check("driver paths are normalised (\\SystemRoot\\ and \\??\\ prefixes)", (IntegrityScanner.DriverPath(@"\SystemRoot\System32\drivers\x.sys") ?? "").StartsWith(PathUtil.WinDir, StringComparison.OrdinalIgnoreCase) && string.Equals(IntegrityScanner.DriverPath(@"\??\C:\a\b.sys"), PathUtil.Normalize(@"C:\a\b.sys"), StringComparison.OrdinalIgnoreCase));
                Check("DNS: router/local addresses are not 'unknown'", IntegrityScanner.IsPrivateOrLocal("192.168.0.1") && IntegrityScanner.IsPrivateOrLocal("10.1.2.3") && IntegrityScanner.IsPrivateOrLocal("::1") && !IntegrityScanner.IsPrivateOrLocal("203.0.113.7"));

                // protection switches, read from a fake hive in the self-test's own registry namespace
                using (var fakeM = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\MineHunterSelfTest\FakeHKLM"))
                using (var fakeU = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\MineHunterSelfTest\FakeHKCU"))
                {
                    fakeM.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config").SetValue("VulnerableDriverBlocklistEnable", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    fakeM.CreateSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection").SetValue("DisableRealtimeMonitoring", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    fakeU.CreateSubKey(@"Software\Microsoft\Windows Script\Settings").SetValue("AmsiEnable", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    var pol = fakeM.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"); pol.SetValue("EnableLUA", 1, Microsoft.Win32.RegistryValueKind.DWord); pol.SetValue("ConsentPromptBehaviorAdmin", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    fakeM.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{11111111-1111-1111-1111-111111111111}").SetValue("NameServer", "203.0.113.7,8.8.8.8,192.168.1.1");
                    var cb = TestCtx(rules);
                    IntegrityScanner.DriverBlocklist(cb, fakeM); IntegrityScanner.ProtectionSettings(cb, fakeM, fakeU); IntegrityScanner.DnsSettings(cb, fakeM);
                    Check("vulnerable-driver block list switched off is reported", Find(cb, e => HasRule(e, "TAMPER.DRIVER_BLOCKLIST_OFF")) != null);
                    Check("Defender real-time monitoring switched off in the registry is reported", Find(cb, e => HasRule(e, "TAMPER.DEFENDER_RTP_OFF")) != null);
                    Check("AMSI switched off for Windows Script Host is reported", Find(cb, e => HasRule(e, "TAMPER.AMSI_OFF")) != null);
                    Check("UAC set to elevate without asking is reported", Find(cb, e => HasRule(e, "TAMPER.UAC_NO_PROMPT")) != null);
                    var dns = Find(cb, e => HasRule(e, "TAMPER.DNS_UNKNOWN"));
                    Check("DNS: only the unknown public server is reported, not a known resolver or a router", dns != null && dns.Title.Contains("203.0.113.7") && !dns.Title.Contains("8.8.8.8") && !dns.Title.Contains("192.168.1.1"));
                    // the same switches in their normal positions: silence
                    fakeM.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config").SetValue("VulnerableDriverBlocklistEnable", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    fakeM.CreateSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection").SetValue("DisableRealtimeMonitoring", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    fakeU.CreateSubKey(@"Software\Microsoft\Windows Script\Settings").SetValue("AmsiEnable", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    pol.SetValue("ConsentPromptBehaviorAdmin", 5, Microsoft.Win32.RegistryValueKind.DWord);
                    fakeM.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{11111111-1111-1111-1111-111111111111}").SetValue("NameServer", "8.8.8.8");
                    var cq = TestCtx(rules);
                    IntegrityScanner.DriverBlocklist(cq, fakeM); IntegrityScanner.ProtectionSettings(cq, fakeM, fakeU); IntegrityScanner.DnsSettings(cq, fakeM);
                    Check("the same switches in their normal positions raise nothing", !cq.Entities.Values.Any(e => e.Evidence.Count > 0));

                    // ---- autostart points that are easy to forget, on the same fake hive
                    string exe = Path.Combine(tmp, "payload.exe"); File.WriteAllBytes(exe, new byte[] { 1, 2, 3 });
                    var gp = fakeU.CreateSubKey(@"GP\Startup\0\0"); gp.SetValue("Script", exe); gp.SetValue("Parameters", "/x");
                    var cg = TestCtx(rules);
                    using (var gk = fakeU.OpenSubKey("GP")) ExtraPersistenceScanner.WalkScripts(cg, gk, "HKCU", "GP", 0);
                    Check("Group Policy script that starts an unsigned program from a user folder is found", Find(cg, e => e.Id.StartsWith("gpscript:") && HasRule(e, "REG.GP_SCRIPT")) != null);
                    fakeM.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\FakeSvc").SetValue("FailureCommand", "\"" + exe + "\" /restart");
                    fakeM.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\VendorSvc").SetValue("FailureCommand", "\"" + Path.Combine(PathUtil.System32, "notepad.exe") + "\"");
                    var cs = TestCtx(rules);
                    ExtraPersistenceScanner.ServiceFailureCommands(cs, fakeM);
                    Check("service recovery command that runs an unsigned program is found, a signed Windows one is not", Find(cs, e => e.Id == "svcfail:FakeSvc" && HasRule(e, "SVC.FAILURE_COMMAND")) != null && Find(cs, e => e.Id == "svcfail:VendorSvc") == null);
                }

                // ---- scheduled-task triggers that wait for nobody to be watching
                Func<string, string, ScanContext> taskCtx = (name, trigger) =>
                {
                    string xml = "<?xml version=\"1.0\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers>" + trigger + "</Triggers><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Command>" + Path.Combine(tmp, "payload.exe") + "</Command></Exec></Actions></Task>";
                    string tf = Path.Combine(tmp, name); File.WriteAllText(tf, xml);
                    var c = TestCtx(rules); TaskScanner.One(c, tf, "\\" + name); return c;
                };
                var ci1 = taskCtx("TIdle", "<IdleTrigger/>");
                Check("scheduled task that starts when the PC is idle is flagged", Find(ci1, e => HasRule(e, "TASK.IDLE_TRIGGER")) != null, DumpEntities(ci1));
                Check("scheduled task that starts when the screen is locked is flagged", Find(taskCtx("TLock", "<SessionStateChangeTrigger><StateChange>SessionLock</StateChange></SessionStateChangeTrigger>"), e => HasRule(e, "TASK.LOCK_TRIGGER")) != null);
                var tplain = taskCtx("TLogon", "<LogonTrigger/>");
                Check("a plain logon task gets neither", Find(tplain, e => HasRule(e, "TASK.IDLE_TRIGGER") || HasRule(e, "TASK.LOCK_TRIGGER")) == null);

                // ---- PATH: a Windows-named program in a folder that is searched first
                string shadowDir = Path.Combine(tmp, "bin"); Directory.CreateDirectory(shadowDir);
                File.WriteAllBytes(Path.Combine(shadowDir, "ping.exe"), new byte[] { 9, 9, 9 }); File.WriteAllBytes(Path.Combine(shadowDir, "mytool.exe"), new byte[] { 9, 9, 9 });
                var cp1 = TestCtx(rules); ExtraPersistenceScanner.Shadowing(cp1, new List<string> { shadowDir, PathUtil.System32 });
                var cp2 = TestCtx(rules); ExtraPersistenceScanner.Shadowing(cp2, new List<string> { PathUtil.System32, shadowDir });
                var sh1 = Find(cp1, e => HasRule(e, "PATH.SHADOWS_SYSTEM_BINARY")); var sh2 = Find(cp2, e => HasRule(e, "PATH.SHADOWS_SYSTEM_BINARY"));
                Check("PATH: a program named like a Windows tool ahead of System32 in a user-writable folder is flagged strongly, after it more weakly, an ordinary name not",
                      sh1 != null && sh1.Evidence.First(x => x.RuleId == "PATH.SHADOWS_SYSTEM_BINARY").Weight == 35 && sh2 != null && sh2.Evidence.First(x => x.RuleId == "PATH.SHADOWS_SYSTEM_BINARY").Weight == 20
                      && !cp1.Entities.Values.Any(e => e.Title == "mytool.exe" && HasRule(e, "PATH.SHADOWS_SYSTEM_BINARY")));

                // ---- "it came back": the quarantine remembers what was removed
                RulePack.TestDataDirOverride = Path.Combine(tmp, "data2");
                string dropped = Path.Combine(tmp, "dropped.exe"); byte[] bytes = new byte[] { 7, 7, 7, 7, 7, 7, 7, 7 };
                File.WriteAllBytes(dropped, bytes);
                string qerr; var item = Quarantine.StoreFile("File", dropped, "relapse test", "test", out qerr);
                File.Delete(dropped);
                var r0 = new ScanResult(); var cr0 = TestCtx(rules); Reappearance.Check(cr0, r0);
                Check("relapse: nothing is reported while the removed file is gone", !cr0.Entities.Values.Any(e => HasRule(e, "REL.REAPPEARED")));
                File.WriteAllBytes(dropped, bytes);
                var r1 = new ScanResult(); var cr1 = TestCtx(rules); Reappearance.Check(cr1, r1);
                Check("relapse: a file that reappears minutes after cleaning is not judged too early (a rescan covers that)", !cr1.Entities.Values.Any(e => HasRule(e, "REL.REAPPEARED")));
                item.Created = DateTime.Now.AddMinutes(-10).ToString("o"); Quarantine.Save(item);
                var r2 = new ScanResult(); var cr2 = TestCtx(rules); Reappearance.Check(cr2, r2);
                var back = Find(cr2, e => HasRule(e, "REL.REAPPEARED"));
                Check("relapse: the same file back after cleaning is flagged as definitive and reported in the self-protection notes", back != null && back.Evidence.First(x => x.RuleId == "REL.REAPPEARED").Definitive && r2.PreviousScanIssues.Count == 1);
                File.Delete(dropped);
                Check("restore on purpose works (no relapse from that)", RemediationEngine.Restore(item) == null && File.Exists(dropped));
                var r3 = new ScanResult(); var cr3 = TestCtx(rules); Reappearance.Check(cr3, r3);
                Check("relapse: a file the user restored himself is never reported as 'came back'", !cr3.Entities.Values.Any(e => HasRule(e, "REL.REAPPEARED")));

                // ---- severity grading
                Check("severity: Malware = Critical, High Risk = High, Suspicious = Medium, a note = Low", Loc.SeverityEn(Verdict.Malware) == "Critical" && Loc.SeverityEn(Verdict.HighRisk) == "High" && Loc.SeverityEn(Verdict.Suspicious) == "Medium" && Loc.SeverityEn(Verdict.Clean) == "Low");
            }
            catch (Exception ex) { Check("detection mechanism checks", false, ex.ToString().Split('\n')[0] + " @ " + (ex.StackTrace ?? "").Split('\n')[0].Trim()); }
            finally
            {
                RulePack.TestDataDirOverride = oldData;
                try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\MineHunterSelfTest", false); } catch { }
                try { Directory.Delete(tmp, true); } catch { }
            }
        }

        static string ShortPath(string p)
        {
            var sb = new StringBuilder(520);
            return GetShortPathNameW(p, sb, 520) > 0 ? sb.ToString() : null;
        }
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)] static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, uint len);

        /// <summary>The second round of the audit: autostart points that were missing, ways around the path checks, the safety of the cleaning itself (quarantine records,
        /// changed files, folder links, interrupted cleanups, two cleanups at once) and the grading of game cheats.</summary>
        static void AuditChecks(RulePack rules)
        {
            W.WriteLine("\nAudit round: more autostart points, path tricks, safe cleaning, game cheats");
            string tmp = Path.Combine(Path.GetTempPath(), "mh_au_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tmp);
            string oldData = RulePack.TestDataDirOverride;
            const string fakeRoot = @"Software\MineHunterSelfTest\Audit";
            try
            {
                string payload = Path.Combine(tmp, "payload.exe"); File.WriteAllBytes(payload, new byte[] { 1, 2, 3 });
                string dll = Path.Combine(tmp, "evil.dll"); File.WriteAllBytes(dll, new byte[] { 1, 2, 3 });
                Registry.CurrentUser.DeleteSubKeyTree(fakeRoot, false);
                using (var fm = Registry.CurrentUser.CreateSubKey(fakeRoot + @"\M"))
                using (var fu = Registry.CurrentUser.CreateSubKey(fakeRoot + @"\U"))
                {
                    // ---- table-driven autostart points: every one must be found, with the data needed to remove it
                    fu.CreateSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows").SetValue("Load", payload);
                    fu.CreateSubKey(@"SOFTWARE\Microsoft\Command Processor").SetValue("AutoRun", "\"" + payload + "\" /q");
                    fu.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\001").SetValue("1", payload);
                    fm.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager").SetValue("SetupExecute", new[] { "autocheck autochk *", payload }, RegistryValueKind.MultiString);
                    fm.CreateSubKey(@"SYSTEM\Setup").SetValue("CmdLine", payload);
                    fm.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").SetValue("InitialProgram", payload);
                    fm.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd").SetValue("StartupPrograms", "rdpclip");
                    fm.CreateSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{AAAAAAAA-0000-0000-0000-000000000001}").SetValue("DatabasePath", payload);
                    fm.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs").SetValue("evil", dll);
                    fm.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs").SetValue("DllDirectory", tmp);
                    fm.CreateSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe").SetValue("VerifierDlls", dll);
                    fu.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command").SetValue(null, "\"" + payload + "\"");
                    fu.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command").SetValue("DelegateExecute", "");
                    fu.CreateSubKey(@"Software\Classes\.mlabx\shell\open\command").SetValue(null, "\"" + payload + "\" \"%1\"");
                    fu.CreateSubKey(@"Software\Classes\Vendor.Document\shell\open\command").SetValue(null, "\"" + payload + "\" \"%1\"");              // an ordinary per-user program association: not looked at
                    fu.CreateSubKey(@"Software\Classes\exefile\shell\open\command").SetValue(null, "\"" + Path.Combine(PathUtil.System32, "notepad.exe") + "\" \"%1\"");   // overridden, but with a signed program
                    fu.CreateSubKey(@"Software\Classes\CLSID\{BBBBBBBB-0000-0000-0000-000000000002}\ScriptletURL").SetValue(null, "script:file:///" + tmp.Replace('\\', '/') + "/x.sct");
                    fu.CreateSubKey(@"Software\Classes\CLSID\{CCCCCCCC-0000-0000-0000-000000000003}\InprocHandler32").SetValue(null, dll);

                    var cx = TestCtx(rules);
                    var users = new List<KeyValuePair<string, RegistryKey>> { new KeyValuePair<string, RegistryKey>("HKCU", fu) };
                    MorePersistenceScanner.RunOn(cx, fm, users);
                    Func<string, Entity> byKey = frag => cx.Entities.Values.FirstOrDefault(e => e.Id.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0);
                    Func<Entity, string, bool> removable = (e, v) => e != null && e.P("hive") != null && e.P("key") != null && e.P("value") == v;
                    Check("autostart: the Load value of the Windows key", HasRule(byKey(@"Windows\Load"), "REG.WINDOWS_LOAD_RUN") && removable(byKey(@"Windows\Load"), "Load"));
                    Check("autostart: cmd.exe AutoRun", HasRule(byKey(@"Command Processor\AutoRun"), "REG.CMD_AUTORUN"));
                    Check("autostart: RunOnceEx", byKey(@"RunOnceEx\001") != null);
                    var se = byKey("SetupExecute#1");
                    Check("autostart: only the foreign entry of the SetupExecute list is reported, not the Windows one (and it can be removed alone)", se != null && byKey("SetupExecute#0") == null && se.P("data") == payload && HasRule(se, "REG.BOOT_EXECUTE"));
                    Check("autostart: the Setup command line", HasRule(byKey(@"SYSTEM\Setup\CmdLine"), "REG.SETUP_CMDLINE"));
                    Check("autostart: the Remote Desktop initial program", HasRule(byKey("InitialProgram"), "REG.RDP_INITIAL_PROGRAM"));
                    Check("autostart: the standard rdpclip start-up program is not reported", byKey("StartupPrograms") == null);
                    Check("autostart: an installed compatibility database", HasRule(byKey("InstalledSDB"), "REG.APPCOMPAT_SDB"));
                    Check("autostart: a KnownDLLs entry that is not signed, and a KnownDLLs folder that is not System32", HasRule(byKey(@"KnownDLLs\evil"), "REG.KNOWNDLLS_UNTRUSTED") && HasRule(byKey(@"KnownDLLs\DllDirectory"), "REG.KNOWNDLLS_DIR"));
                    Check("autostart: an IFEO verifier DLL", HasRule(byKey("VerifierDlls"), "REG.IFEO_VERIFIER"));
                    var ms = byKey(@"ms-settings\shell\open\command");
                    Check("autostart: a per-user ms-settings override (the UAC bypass) is reported strongly and carries what is needed to remove it", HasRule(ms, "REG.HANDLER_HIJACK") && ms.Evidence.First(x => x.RuleId == "REG.HANDLER_HIJACK").Weight == 35 && removable(ms, ""));
                    Check("autostart: a per-user override for a file extension", HasRule(byKey(@".mlabx\shell"), "REG.HANDLER_HIJACK"));
                    Check("autostart: an ordinary program association (a program's own ProgID) is not looked at", byKey("Vendor.Document") == null);
                    Check("autostart: an override that starts a signed Windows program is not reported", byKey(@"exefile\shell") == null);
                    Check("autostart: a per-user COM class that runs a scriptlet, and a per-user COM handler DLL", HasRule(byKey("ScriptletURL"), "REG.COM_SCRIPTLET") && byKey("InprocHandler32") != null);
                }

                // ---- a program started out of a hidden NTFS stream, and files that need an interpreter
                var ca = TestCtx(rules);
                string host = Path.Combine(tmp, "notes.txt"); File.WriteAllText(host, "x");
                var ea = Persist.Evaluate(ca, "t:ads", EntityKind.RunKey, "t", "t", "\"" + host + ":payload.exe\"", "Autorun entry");
                Check("a command that starts something inside a hidden data stream is flagged (File.Exists cannot even see such a path)", HasRule(ea, "PERSIST.ADS_TARGET"));
                var eb = Persist.Evaluate(TestCtx(rules), "t:zone", EntityKind.RunKey, "t", "t", "\"" + host + ":Zone.Identifier\"", "Autorun entry");
                Check("... but the Mark of the Web stream is not", !HasRule(eb, "PERSIST.ADS_TARGET"));
                string py = Path.Combine(tmp, "run.py");
                File.WriteAllText(py, Obf.J("xm", "rig") + " -o " + Obf.J("stra", "tum+tcp://") + "pool.example.invalid:3333 -u WALLETNOTREAL000000 -p x " + Obf.J("--don", "ate-level") + " 1 --algo " + Obf.J("rand", "omx"));
                var cpy = TestCtx(rules);
                Persist.Evaluate(cpy, "t:py", EntityKind.RunKey, "t", "t", "python.exe \"" + py + "\"", "Autorun entry");
                Check("a Python script started by autostart is read and its miner command line is found", cpy.Entities.Values.Any(e => e.Kind == EntityKind.File && e.Evidence.Any(x => x.RuleId.StartsWith("SCRIPT.") || x.RuleId.StartsWith("CONTENT.MINER"))));
                string longDir = Path.Combine(tmp, "A_Rather_Long_Folder_Name"); Directory.CreateDirectory(longDir);
                string longFile = Path.Combine(longDir, "payload_with_long_name.exe"); File.WriteAllBytes(longFile, new byte[] { 1 });
                string sp = ShortPath(longFile);
                if (sp != null && sp.IndexOf('~') >= 0) Check("an 8.3 short name is resolved before the location is judged", string.Equals(PathUtil.Normalize(sp), PathUtil.Normalize(longFile), StringComparison.OrdinalIgnoreCase), PathUtil.Normalize(sp));
                else W.WriteLine("  [skip] 8.3 short names are switched off on this volume");

                // ---- scheduled task whose XML is damaged: what it runs is still read
                string tf = Path.Combine(tmp, "Broken"); File.WriteAllText(tf, "<?xml version=\"1.0\"?><Task><Actions><Exec><Command>" + payload + "</Command><Arguments>--x</Arguments></Exec></Actions><Triggers><LogonTrigger>");
                var cbk = TestCtx(rules); TaskScanner.One(cbk, tf, "\\Broken");
                var tb = Find(cbk, e => e.Kind == EntityKind.Task);
                Check("a damaged task definition is not skipped: what it runs is read as text, and the damage is reported", tb != null && HasRule(tb, "TASK.XML_UNPARSABLE") && HasRule(tb, "PERSIST.TARGET_USER_PATH"));

                // ---- a service that is only a wrapper (NSSM): the program it keeps running is what counts
                using (var fs = Registry.CurrentUser.CreateSubKey(fakeRoot + @"\Services"))
                {
                    var sk = fs.CreateSubKey("FakeNssm");
                    sk.SetValue("ImagePath", "\"" + Path.Combine(PathUtil.System32, "notepad.exe") + "\"", RegistryValueKind.ExpandString);
                    sk.SetValue("Type", 16); sk.SetValue("Start", 2);
                    sk.CreateSubKey("Parameters").SetValue("Application", payload);
                    var csv = TestCtx(rules); ServiceScanner.One(csv, fs, "FakeNssm", new Dictionary<string, string>());
                    Check("a service that wraps a program from a user folder (NSSM style) is flagged", Find(csv, e => e.Id == "svc:FakeNssm" && HasRule(e, "SVC.WRAPPED_USER_PATH")) != null);
                }

                // ---- cleaning: one list entry only, identical files, a file that changed, folder links
                RulePack.TestDataDirOverride = Path.Combine(tmp, "data");
                using (var tk = Registry.CurrentUser.CreateSubKey(fakeRoot + @"\Multi"))
                {
                    tk.SetValue("List", new[] { "autocheck autochk *", payload }, RegistryValueKind.MultiString);
                    var re = new Entity { Id = "reg:multi", Kind = EntityKind.Registry, Title = "multi", Location = "HKCU\\x" };
                    re.Set("hive", "HKCU"); re.Set("key", fakeRoot + @"\Multi"); re.Set("value", "List"); re.Set("data", payload);
                    var fnd = new Finding { Id = "T2", Title = "t", Verdict = Verdict.HighRisk, Entities = new List<Entity> { re } };
                    var stp = new List<RemediationStep> { new RemediationStep { Type = ActionType.RemoveRegistryValue, EntityId = re.Id, Target = "x", Order = 1, Description = "d" } };
                    var o2 = RemediationEngine.Execute(TestCtx(rules), fnd, stp, null);
                    var left = tk.GetValue("List") as string[];
                    Check("cleaning a list value removes only the foreign entry and keeps the Windows one", o2.Results.All(r => r.Success) && left != null && left.Length == 1 && left[0] == "autocheck autochk *");
                    var qi2 = Quarantine.List().FirstOrDefault(i => i.Type == "RegistryValue");
                    Check("... and the whole list can be put back from the quarantine record", qi2 != null && RemediationEngine.Restore(qi2) == null && ((tk.GetValue("List") as string[]) ?? new string[0]).Length == 2);
                }
                byte[] same = Encoding.ASCII.GetBytes("identical content for two files");
                string f1 = Path.Combine(tmp, "one.bin"), f2 = Path.Combine(tmp, "two.bin"); File.WriteAllBytes(f1, same); File.WriteAllBytes(f2, same);
                string q1e, q2e; var i1 = Quarantine.StoreFile("File", f1, "t", "r", out q1e); var i2 = Quarantine.StoreFile("File", f2, "t", "r", out q2e);
                Check("two files with identical content get two separate quarantine records (a record is never overwritten by a copy)", i1 != null && i2 != null && i1.Id != i2.Id && i1.Sha256 == i2.Sha256 && i1.Dir != i2.Dir);
                File.Delete(f1); File.Delete(f2);
                Check("... and both are restored byte for byte to their own places", RemediationEngine.Restore(i1) == null && RemediationEngine.Restore(i2) == null && Hashing.Sha256(f1) == Hashing.Sha256(same) && Hashing.Sha256(f2) == Hashing.Sha256(same));
                // damaged manifest
                string mf = Path.Combine(i1.Dir, "manifest.json"); File.WriteAllText(mf + ".bak", File.ReadAllText(mf)); File.WriteAllText(mf, "{ not json");
                var rl = Quarantine.Load(i1.Dir);
                Check("a damaged quarantine record falls back to the previous copy instead of becoming invisible", rl != null && rl.Id == i1.Id && rl.Sha256 == i1.Sha256);
                Quarantine.Save(i2);
                Check("a record is written atomically (no half-written temp file is left behind)", !File.Exists(Path.Combine(i2.Dir, "manifest.json.tmp")) && File.Exists(Path.Combine(i2.Dir, "manifest.json")));
                // a file that changed after the scan is left alone
                string chg = Path.Combine(tmp, "changed.exe"); File.WriteAllBytes(chg, new byte[] { 9, 9, 9, 9 });
                string chgSha = Hashing.Sha256(chg);
                File.WriteAllBytes(chg, new byte[] { 7, 7, 7, 7, 7 });
                string chgErr; var ci = Quarantine.StoreFile("File", chg, "t", "r", out chgErr, chgSha);
                Check("a file that changed since the scan is NOT quarantined (the file that was judged is the file that is removed)", ci == null && File.Exists(chg) && chgErr != null && chgErr.Contains("changed"));
                var ce = new Entity { Id = "file:chg", Kind = EntityKind.File, Title = "changed.exe", Location = chg, Sha256 = chgSha };
                ce.Set("size", "4");
                var cf = new Finding { Id = "T3", Title = "t", Verdict = Verdict.HighRisk, Entities = new List<Entity> { ce } };
                var oc3 = RemediationEngine.Execute(TestCtx(rules), cf, new List<RemediationStep> { new RemediationStep { Type = ActionType.QuarantineFile, EntityId = ce.Id, Target = chg, Order = 3, Description = "q" } }, null);
                Check("... also through the cleaning engine: the step fails with a clear message and the file stays", oc3.Results.Count == 1 && !oc3.Results[0].Success && File.Exists(chg));
                // folder links
                string realDir = Path.Combine(tmp, "real"); Directory.CreateDirectory(realDir);
                string junc = Path.Combine(tmp, "link");
                string o; int mk = RemediationEngine.RunTool(Path.Combine(PathUtil.System32, "cmd.exe"), "/c mklink /J \"" + junc + "\" \"" + realDir + "\"", 10000, out o);
                if (mk == 0 && Directory.Exists(junc))
                {
                    string viaLink = Path.Combine(junc, "restored.bin");
                    Check("a path that goes through a junction is recognised", Fs.HasLinkedFolder(viaLink) && !Fs.HasLinkedFolder(Path.Combine(realDir, "x.bin")) && string.Equals(PathUtil.Normalize(Fs.FinalPath(junc)), PathUtil.Normalize(realDir), StringComparison.OrdinalIgnoreCase), Fs.FinalPath(junc));
                    string qe2; var qj = Quarantine.StoreFile("File", f2, "t", "r", out qe2); File.Delete(f2);
                    string err = Quarantine.RestoreFileTo(qj, viaLink, false);
                    Check("restoring through a junction is refused (an administrator write must not be steered into a system folder)", err != null && err.Contains("junction") && !File.Exists(Path.Combine(realDir, "restored.bin")), err);
                    try { Directory.Delete(junc); } catch { }
                }
                else W.WriteLine("  [skip] could not create a junction here");

                // ---- an interrupted cleanup does not leave programs frozen; two cleanups do not run at once
                var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(PathUtil.System32, "ping.exe"), "-n 40 127.0.0.1") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
                try
                {
                    System.Threading.Thread.Sleep(300);
                    var ks = new RemediationStep { Type = ActionType.KillProcess, EntityId = "p", Target = child.Id + "|" + child.StartTime.ToUniversalTime().ToString("o"), Order = 2, Description = "k" };
                    var frozen = RemediationEngine.FreezeProcesses(new[] { ks });
                    System.Threading.Thread.Sleep(300);
                    Func<bool> suspended = () => { try { child.Refresh(); return child.Threads.Cast<System.Diagnostics.ProcessThread>().All(t => t.ThreadState == System.Diagnostics.ThreadState.Wait && t.WaitReason == System.Diagnostics.ThreadWaitReason.Suspended); } catch { return false; } };
                    bool wasFrozen = suspended();
                    Check("a process that is about to be stopped is frozen first", frozen.Count == 1 && wasFrozen);
                    int rec = RemediationEngine.RecoverInterrupted();       // as if MineHunter had died here and was started again
                    System.Threading.Thread.Sleep(300);
                    Check("a cleanup that died while processes were frozen is made good at the next start: they run again", rec == 1 && !suspended());
                }
                finally { try { child.Kill(); } catch { } child.Dispose(); }
                var lk1 = RemediationEngine.CleanupLock(500);
                bool otherGotIt = true;
                var th = new System.Threading.Thread(() => { var x = RemediationEngine.CleanupLock(300); otherGotIt = x != null; if (x != null) x.Dispose(); });
                th.Start(); th.Join();
                lk1.Dispose();
                var lk3 = RemediationEngine.CleanupLock(500);
                Check("only one cleanup runs at a time: a second one is told to wait, and gets the lock when the first is done", lk1 != null && !otherGotIt && lk3 != null);
                if (lk3 != null) lk3.Dispose();

                // ---- a signed program in a user folder with a Windows-named unsigned DLL beside it
                string appDir = Path.Combine(tmp, "app"); Directory.CreateDirectory(appDir);
                string signedExe = Path.Combine(appDir, "notepad.exe"); File.Copy(Path.Combine(PathUtil.System32, "notepad.exe"), signedExe, true);
                var csl0 = TestCtx(rules);
                Check("a signed program alone, started from a user folder, is not reported", Persist.Evaluate(csl0, "t:s0", EntityKind.RunKey, "t", "t", "\"" + signedExe + "\"", "Autorun entry") == null);
                File.WriteAllBytes(Path.Combine(appDir, "helper.dll"), new byte[] { 1, 2, 3 });
                Check("... nor with an ordinary library beside it", Persist.Evaluate(TestCtx(rules), "t:s1", EntityKind.RunKey, "t", "t", "\"" + signedExe + "\"", "Autorun entry") == null);
                File.WriteAllBytes(Path.Combine(appDir, "version.dll"), new byte[] { 1, 2, 3 });
                var csl = TestCtx(rules);
                var esl = Persist.Evaluate(csl, "t:s2", EntityKind.RunKey, "t", "t", "\"" + signedExe + "\"", "Autorun entry");
                Check("with an unsigned version.dll beside it, the pair is flagged as DLL side-loading and the library is linked into the finding", HasRule(esl, "PERSIST.SIDELOAD_PAIR") && csl.Links.Any(l => l.Relation == "loads"));

                // ---- the registry file of a user who is not signed in (a saved hive stands in for NTUSER.DAT)
                // the registry opens the file itself, so it must be in a place that is the same for every process: a redirected %TEMP% (packaged-app processes) is not
                string offDir = Path.Combine(PathUtil.WinDir, "Temp", "mh_off_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                try { Directory.CreateDirectory(offDir); } catch { offDir = tmp; }
                string dat = Path.Combine(offDir, "NTUSER.DAT");
                string offLabel = @"HKUOFF\S-1-5-21-111-222-333-1001";
                using (var src = Registry.CurrentUser.CreateSubKey(fakeRoot + @"\OffUser"))
                {
                    src.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run").SetValue("OffRun", "\"" + payload + "\"");
                    src.CreateSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows").SetValue("Load", payload);
                }
                string regOut; int rsave = RemediationEngine.RunTool(Path.Combine(PathUtil.System32, "reg.exe"), "save \"HKCU\\" + fakeRoot + "\\OffUser\" \"" + dat + "\" /y", 20000, out regOut);
                string mErr = null; RegistryKey offKey = null;
                if (rsave == 0) { UserHives.TestDat[offLabel] = dat; offKey = UserHives.Mount(offLabel, dat, out mErr); }
                if (offKey == null) W.WriteLine("  [skip] registry file of another user cannot be mounted here (" + (rsave != 0 ? "reg save: " + regOut : mErr) + "; file " + dat + " exists=" + File.Exists(dat) + " size=" + (File.Exists(dat) ? new FileInfo(dat).Length : -1) + ")");
                else
                {
                    var co = TestCtx(rules);
                    RegistryPersistenceScanner.ScanRunKey(co, offKey, offLabel, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                    using (var emptyM = Registry.CurrentUser.CreateSubKey(fakeRoot + @"\EmptyM"))
                        MorePersistenceScanner.RunOn(co, emptyM, new List<KeyValuePair<string, RegistryKey>> { new KeyValuePair<string, RegistryKey>(offLabel, offKey) });
                    var eRun = Find(co, e => e.Kind == EntityKind.RunKey && e.Id.Contains("HKUOFF"));
                    var eLoad = Find(co, e => e.Id.Contains("HKUOFF") && e.Id.Contains(@"Windows\Load"));
                    Check("a user who is not signed in: the Run key and the Windows Load value in their registry file are found", eRun != null && eLoad != null);
                    var offFnd = new Finding { Id = "T7", Title = "t", Verdict = Verdict.HighRisk, Entities = new List<Entity> { eRun, eLoad } };
                    var offSteps = new List<RemediationStep>
                    {
                        new RemediationStep { Type = ActionType.RemoveRunValue, EntityId = eRun.Id, Target = eRun.Location, Order = 1, Description = "r" },
                        new RemediationStep { Type = ActionType.RemoveRegistryValue, EntityId = eLoad.Id, Target = eLoad.Location, Order = 1, Description = "l" }
                    };
                    var oOff = RemediationEngine.Execute(co, offFnd, offSteps, null);        // mounts the file again, removes both values, unmounts
                    Check("... both are removed from that user's registry file (reached again through the stored label)", oOff.Results.All(r => r.Success));
                    Check("... and nothing stays mounted afterwards", !Registry.Users.GetSubKeyNames().Any(n => n.StartsWith("MineHunter_")));
                    string mErr2; var mk2 = UserHives.Mount(offLabel, dat, out mErr2);
                    bool gone = false;
                    using (var rk = mk2 == null ? null : mk2.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) gone = rk != null && rk.GetValue("OffRun") == null;
                    using (var wk = mk2 == null ? null : mk2.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")) gone = gone && wk != null && wk.GetValue("Load") == null;
                    UserHives.ReleaseAll();
                    Check("... the file on disk really changed (read back after a fresh mount)", gone);
                    foreach (var qi in Quarantine.List().Where(i => i.Type == "RegistryValue" && (i.OriginalPath ?? "").Contains("HKUOFF")).ToList()) RemediationEngine.Restore(qi);
                    string mErr3; var mk3 = UserHives.Mount(offLabel, dat, out mErr3);
                    bool back = false;
                    using (var rk = mk3 == null ? null : mk3.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) back = rk != null && Convert.ToString(rk.GetValue("OffRun")) == "\"" + payload + "\"";
                    UserHives.ReleaseAll();
                    Check("... and restoring from the quarantine puts the value back into that user's registry file", back);
                    UserHives.TestDat.Remove(offLabel);
                }

                // ---- game cheats: graded as Suspicious at most, never removed by default - unless something specific to miners is there as well
                Check("the rule pack knows the game-cheat class", rules.ToolClasses.Any(t => t.Id == "TOOL.GAME_CHEAT"));
                string cheatDir = Path.Combine(tmp, "CheatEngine"); Directory.CreateDirectory(cheatDir);
                string cheatExe = Path.Combine(cheatDir, "cheatengine-x86_64.exe");
                string selfExe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                File.Copy(selfExe, cheatExe, true);
                Entity lastFe = null; List<Finding> lastBuilt = null;
                Func<bool, Finding> graded = withMiner =>
                {
                    var c = TestCtx(rules);
                    var fe = c.Files.Inspect(cheatExe, FileRole.PersistenceTarget);
                    fe.Add(new Evidence("PE.HIGH_ENTROPY", EvidenceCategory.Content, 35, "packed", "x"));
                    fe.Add(new Evidence("PERSIST.TARGET_USER_PATH", EvidenceCategory.Persistence, 30, "starts from a user folder", "x"));
                    fe.Add(new Evidence("TAMPER.DEF_EXCL_USERPATH", EvidenceCategory.Tamper, 20, "excluded from Defender", "x"));
                    if (withMiner) fe.Add(new Evidence("CONTENT.MINER.STRINGS_STRONG", EvidenceCategory.Content, 48, "miner strings", "x"));
                    List<Entity> obs; var fl = RiskEngine.Build(c, out obs);
                    lastFe = fe; lastBuilt = fl;
                    return fl.FirstOrDefault(x => x.Entities.Contains(fe));
                };
                var gf = graded(false);
                Check("the file name classes it as a game cheat", gf != null && gf.ToolClass == "GameCheat", lastFe == null ? "no entity" : "toolClass=" + lastFe.P("toolClass") + " score=" + lastFe.Score + " trusted=" + lastFe.Trusted + " props=" + string.Join(",", lastFe.Props.Keys) + " ev=" + string.Join(",", lastFe.Evidence.Select(x => x.RuleId)) + " findings=" + (lastBuilt == null ? -1 : lastBuilt.Count));
                Check("a cheat with loud generic signals is graded Suspicious (Medium), not High or Critical", gf != null && gf.Verdict == Verdict.Suspicious && Loc.SeverityEn(gf.Verdict) == "Medium");
                Check("... none of its steps is selected by default, and the recommendation says it is kept", gf != null && gf.Steps.All(s => !s.RecommendedByDefault) && gf.Recommendation.StartsWith("Kept:") && ReportWriter.StateTag(gf, null) != null);
                var gm = graded(true);
                Check("a cheat that also carries miner strings is a miner: the cheat class no longer protects it", gm != null && gm.ToolClass == null && gm.Verdict >= Verdict.HighRisk && gm.Steps.Any(s => s.RecommendedByDefault));
                var pkt = new RulePack(); pkt.Merge("{\"version\":\"2026.01.01.1\"}", "base");
                pkt.Merge("{\"version\":\"2099.01.01.1\",\"toolClasses\":[{\"id\":\"TOOL.EVIL\",\"class\":\"GameCheat\",\"regex\":\"miner\",\"text\":\"t\"}]}", "next-to-exe", true); pkt.Build();
                Check("a rule pack next to the EXE cannot add a tool class (a miner could name itself into the list)", pkt.ToolClasses.Count == 0);
                var fo = new Finding { Id = "T9", Title = "x", Verdict = Verdict.Malware, Score = 90 };
                var fok = new FindingOutcome { FindingId = "T9", Verdict = "Remediated" }; var fpart = new FindingOutcome { FindingId = "T9", Verdict = "Partial" };
                Check("the report shows the severity and what happened: \"[CRITICAL] [REMOVED]\"", ReportWriter.Badge(fo, fok).ToUpperInvariant() == "[" + Loc.Severity(Verdict.Malware).ToUpperInvariant() + "] [" + ReportWriter.StateTag(fo, fok).ToUpperInvariant() + "]" && ReportWriter.StateTag(fo, fok) == Loc.L("REMOVED", "УДАЛЕНО") && ReportWriter.StateTag(fo, fpart) == Loc.L("PARTLY REMOVED", "УДАЛЕНО ЧАСТИЧНО"));
            }
            catch (Exception ex) { Check("audit round checks", false, ex.ToString().Split('\n')[0] + " @ " + (ex.StackTrace ?? "").Split('\n')[0].Trim()); }
            finally
            {
                RulePack.TestDataDirOverride = oldData;
                try { UserHives.ReleaseAll(); foreach (var d in Directory.GetDirectories(Path.Combine(PathUtil.WinDir, "Temp"), "mh_off_*")) { try { Directory.Delete(d, true); } catch { } } } catch { }
                try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\MineHunterSelfTest", false); } catch { }
                try { foreach (var d in Directory.GetDirectories(tmp)) { try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) Directory.Delete(d); } catch { } } Directory.Delete(tmp, true); } catch { }
            }
        }

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
            Check("verification: this build is reported as unsigned", Trust.Check(self).State == TrustState.Unsigned || Trust.Check(self).IsValid == false);

            w.WriteLine("\nRule-pack semantics (what a rule update can do)");
            try
            {
                string R(string ver, int weight, string extra) { return "{\"version\":\"" + ver + "\",\"cmdlinePatterns\":[{\"id\":\"CMD.TEST.X\",\"regex\":\"zzz-test-token\",\"weight\":" + weight + ",\"category\":\"Persistence\",\"text\":\"t\",\"textRu\":\"тест-ру\"}]" + extra + "}"; }
                var older = R("2026.01.01.1", 10, ""); var newer = R("2026.02.01.1", 30, ",\"disabledRules\":[\"CMD.TEST.GONE\"],\"knownGoodHashes\":{\"" + new string('a', 64) + "\":\"Example App 1.0\"}");
                var pk = new RulePack(); pk.Merge(older, "old"); pk.Merge(newer, "new"); pk.Build();
                var pk2 = new RulePack(); pk2.Merge(newer, "new"); pk2.Merge(older, "old"); pk2.Build();
                Check("a newer rule pack overrides the same rule id (either load order); an older pack never does", pk.CmdRules.Single(r => r.Id == "CMD.TEST.X").Weight == 30 && pk2.CmdRules.Single(r => r.Id == "CMD.TEST.X").Weight == 30 && pk.Version == "2026.02.01.1");
                var pk3 = new RulePack(); pk3.Merge(older, "old"); pk3.Merge("{\"version\":\"2026.03.01.1\",\"disabledRules\":[\"CMD.TEST.X\"]}", "kill"); pk3.Build();
                Check("'disabledRules' switches a noisy rule off without a new EXE", pk3.CmdRules.All(r => r.Id != "CMD.TEST.X"));
                Check("'knownGoodHashes' are loaded (false-positive fix by data)", pk.GoodHashes.ContainsKey(new string('a', 64)));
                Check("'textRu' travels with the rule pack (bilingual updates)", Loc.PackText("CMD.TEST.X") == "тест-ру");
            }
            catch (Exception ex) { Check("rule-pack semantics", false, ex.Message); }

            {
                int sampleRules = 0, sampleLines = 0; var bad = new List<string>();
                foreach (var r in rules.CmdRules) { if (r.Match.Length + r.NoMatch.Length == 0) continue; sampleRules++; foreach (var t in r.Match) { sampleLines++; if (!r.Rx.IsMatch(t)) bad.Add(r.Id + " must match: " + Text.Trunc(t, 50)); } foreach (var t in r.NoMatch) { sampleLines++; if (r.Rx.IsMatch(t)) bad.Add(r.Id + " must NOT match: " + Text.Trunc(t, 50)); } }
                foreach (var r in rules.IocPaths.Concat(rules.NameRules)) { if (r.Match.Length + r.NoMatch.Length == 0) continue; sampleRules++; foreach (var t in r.Match) { sampleLines++; if (!r.Rx.IsMatch(t.ToLowerInvariant())) bad.Add(r.Id + " must match: " + Text.Trunc(t, 50)); } foreach (var t in r.NoMatch) { sampleLines++; if (r.Rx.IsMatch(t.ToLowerInvariant())) bad.Add(r.Id + " must NOT match: " + Text.Trunc(t, 50)); } }
                Check("every rule's own samples hold (" + sampleRules + " rules, " + sampleLines + " sample lines: malicious ones match, benign ones do not)", bad.Count == 0 && sampleRules > 0, string.Join("; ", bad.Take(3)));
            }

            SelfProtectionChecks();

            DetectionChecks(rules);
            AuditChecks(rules);

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
            string oldData = RulePack.TestDataDirOverride;
            string tmpData = Path.Combine(Path.GetTempPath(), "mh_upd_" + Guid.NewGuid().ToString("N").Substring(0, 6));
            System.Net.HttpListener srv = null;
            try
            {
                RulePack.TestDataDirOverride = tmpData;
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
                RulePack.TestDataDirOverride = oldData;
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
