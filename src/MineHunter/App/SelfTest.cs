using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
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
