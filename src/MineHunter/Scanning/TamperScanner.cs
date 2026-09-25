using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Attempts to weaken defences: Defender exclusions, hosts blocking security sites, DisallowRun, disabled tools, RDP Wrapper,
    /// plus the informational "security posture" of the machine.</summary>
    public static class TamperScanner
    {
        public static void Run(ScanContext ctx)
        {
            DefenderExclusions(ctx);
            Hosts(ctx);
            Policies(ctx);
            TermService(ctx);
            PowerShellHistory(ctx);
            Firewall(ctx);
            Posture(ctx);
        }

        // -------------------------------------------------------------------------------------------------
        static void DefenderExclusions(ScanContext ctx)
        {
            foreach (var basePath in new[] { @"SOFTWARE\Microsoft\Windows Defender\Exclusions", @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" })
            {
                bool policy = basePath.Contains("Policies");
                foreach (var kind in new[] { "Paths", "Processes", "Extensions" })
                {
                    try
                    {
                        using (var k = Registry.LocalMachine.OpenSubKey(basePath + "\\" + kind))
                        {
                            if (k == null) continue;
                            foreach (var vn in k.GetValueNames())
                            {
                                if (string.IsNullOrWhiteSpace(vn)) continue;
                                string id = "defexcl:" + (policy ? "policy:" : "local:") + kind + ":" + vn.ToLowerInvariant();
                                var e = ctx.GetOrAdd(id, EntityKind.DefenderExclusion, () => new Entity { Title = "Defender exclusion (" + kind.TrimEnd('s').ToLowerInvariant() + "): " + vn, Location = "HKLM\\" + basePath + "\\" + kind });
                                e.Set("kind", kind); e.Set("value", vn); e.Set("policy", policy.ToString()); e.Set("hive", "HKLM"); e.Set("key", basePath + "\\" + kind);
                                string lv = vn.Trim().Trim('"');
                                if (kind == "Extensions")
                                {
                                    string ext = lv.StartsWith(".") ? lv.ToLowerInvariant() : "." + lv.ToLowerInvariant();
                                    if (ctx.Rules.DefenderExt.Contains(ext, StringComparer.OrdinalIgnoreCase))
                                        e.Add(new Evidence("TAMPER.DEF_EXCL_EXT", EvidenceCategory.Tamper, 30, "Defender is told to ignore every " + ext + " file", vn));
                                }
                                else if (kind == "Processes")
                                {
                                    string stem = Path.GetFileNameWithoutExtension(lv).ToLowerInvariant();
                                    if (ctx.Rules.MinerFileNames.Contains(stem)) e.Add(new Evidence("TAMPER.DEF_EXCL_MINER", EvidenceCategory.Tamper, 40, "Defender is told to ignore a known miner program (" + stem + ")", vn));
                                    else if (PathUtil.IsUserWritable(lv)) e.Add(new Evidence("TAMPER.DEF_EXCL_USERPATH", EvidenceCategory.Tamper, 8, "Defender ignores a process running from a user-writable folder", vn));
                                }
                                else
                                {
                                    string np = PathUtil.Normalize(lv);
                                    if (ctx.Rules.DefenderPathDanger.Any(r => r.IsMatch(lv) || r.IsMatch(np)))
                                        e.Add(new Evidence("TAMPER.DEF_EXCL_BROAD", EvidenceCategory.Tamper, 28, "Defender is told to ignore a very broad location (drive / ProgramData / Temp / AppData / user profile)", vn));
                                    else if (PathUtil.IsUserWritable(np) || PathUtil.Classify(np) == PathClass.ProgramData)
                                        e.Add(new Evidence("TAMPER.DEF_EXCL_USERPATH", EvidenceCategory.Tamper, 8, "Defender is told to ignore a folder in a user-writable location", vn));
                                    string lastPart = Path.GetFileName(np.TrimEnd((char)92)) ?? ""; bool minerName = lastPart.StartsWith("miner", StringComparison.OrdinalIgnoreCase) || ctx.Rules.MinerFileNames.Any(n => lastPart.StartsWith(n, StringComparison.OrdinalIgnoreCase));
                                    if (minerName) e.Add(new Evidence("TAMPER.DEF_EXCL_MINER", EvidenceCategory.Tamper, 40, "Defender is told to ignore a path with a miner-like name", vn));
                                }
                                if (!e.Evidence.Any(x => x.Weight > 0)) ctx.Entities.TryRemove(id, out e);     // benign exclusion: not a finding
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { ctx.Denied("Defender exclusions", basePath); }
                    catch { }
                }
            }
        }

        // -------------------------------------------------------------------------------------------------
        static void Hosts(ScanContext ctx)
        {
            string hosts = Path.Combine(PathUtil.System32, @"drivers\etc\hosts");
            try
            {
                if (!File.Exists(hosts)) return;
                var blocked = new List<string>(); var winUpd = new List<string>();
                foreach (var raw in File.ReadAllLines(hosts))
                {
                    string line = raw; int h = line.IndexOf('#'); if (h >= 0) line = line.Substring(0, h);
                    var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;
                    for (int i = 1; i < parts.Length; i++)
                    {
                        string host = parts[i].ToLowerInvariant();
                        if (host.StartsWith("www.")) host = host.Substring(4);
                        foreach (var av in ctx.Rules.AvDomains)
                            if (host == av || host.EndsWith("." + av))
                            {
                                if (av.Contains("windowsupdate") || av.StartsWith("update.microsoft") || av.StartsWith("defender.microsoft")) winUpd.Add(raw.Trim());
                                else blocked.Add(raw.Trim());
                                break;
                            }
                    }
                }
                if (blocked.Count > 0)
                {
                    var e = ctx.GetOrAdd("hosts:av-block", EntityKind.HostsEntry, () => new Entity { Title = "hosts file blocks security websites", Location = hosts });
                    e.Add(new Evidence("TAMPER.HOSTS_BLOCKS_AV", EvidenceCategory.Tamper, Math.Min(35 + blocked.Count, 45), "The hosts file redirects/blocks " + blocked.Count + " antivirus/security websites", string.Join(" | ", blocked.Distinct().Take(8))));
                    e.Set("lines", string.Join("\n", blocked.Distinct()));
                }
                if (winUpd.Count > 0)
                {
                    var e = ctx.GetOrAdd("hosts:update-block", EntityKind.HostsEntry, () => new Entity { Title = "hosts file blocks Windows Update / Defender servers", Location = hosts });
                    e.Add(new Evidence("TAMPER.HOSTS_BLOCKS_UPDATE", EvidenceCategory.Tamper, 10, "The hosts file blocks Windows Update / Defender servers", string.Join(" | ", winUpd.Distinct().Take(6))));
                    e.Set("lines", string.Join("\n", winUpd.Distinct()));
                }
            }
            catch (Exception ex) { ctx.AddBlind("hosts file", ex.Message); }
        }

        // -------------------------------------------------------------------------------------------------
        static void Policies(ScanContext ctx)
        {
            // DisallowRun: Explorer refuses to start the listed programs
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                string hn = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                try
                {
                    using (var ex = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
                    {
                        if (ex == null) continue;
                        int dr = 0; try { dr = Convert.ToInt32(ex.GetValue("DisallowRun", 0)); } catch { }
                        using (var k = ex.OpenSubKey("DisallowRun"))
                        {
                            if (k == null) continue;
                            var names = k.GetValueNames().Select(v => Convert.ToString(k.GetValue(v))).Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
                            var sec = names.Where(n => ctx.Rules.SecurityTools.Contains(Path.GetFileName(n)) && !ctx.Rules.SecurityToolsBenign.Contains(Path.GetFileName(n))).ToList();
                            if (names.Count == 0) continue;
                            var e = ctx.GetOrAdd("policy:" + hn + ":DisallowRun", EntityKind.PolicyValue, () => new Entity { Title = "Explorer DisallowRun list", Location = hn + @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" });
                            e.Set("hive", hn); e.Set("key", @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"); e.Set("names", string.Join(", ", names));
                            if (sec.Count > 0 && dr == 1) e.Add(new Evidence("TAMPER.DISALLOWRUN_SECURITY", EvidenceCategory.Tamper, 35, "Windows is set to refuse starting security/analysis tools: " + string.Join(", ", sec.Take(8)), string.Join(", ", names.Take(12))));
                            else if (names.Count > 0 && dr == 1 && names.Any(n => !ctx.Rules.SecurityToolsBenign.Contains(Path.GetFileName(n)))) e.Add(new Evidence("TAMPER.DISALLOWRUN_OTHER", EvidenceCategory.Tamper, 3, "Explorer refuses to start some programs (DisallowRun)", string.Join(", ", names.Take(12))));
                            if (!e.Evidence.Any(x => x.Weight > 0)) { Entity rm; ctx.Entities.TryRemove(e.Id, out rm); }
                        }
                    }
                }
                catch { }
                try
                {
                    using (var k = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System"))
                    {
                        if (k == null) continue;
                        foreach (var vn in new[] { "DisableTaskMgr", "DisableRegistryTools", "DisableCMD" })
                        {
                            int v = 0; try { v = Convert.ToInt32(k.GetValue(vn, 0)); } catch { }
                            if (v != 0)
                            {
                                var e = ctx.GetOrAdd("policy:" + hn + ":" + vn, EntityKind.PolicyValue, () => new Entity { Title = "Policy " + vn + " = " + v, Location = hn + @"\Software\Microsoft\Windows\CurrentVersion\Policies\System\" + vn });
                                e.Set("hive", hn); e.Set("key", @"Software\Microsoft\Windows\CurrentVersion\Policies\System"); e.Set("value", vn); e.Set("data", v.ToString());
                                e.Add(new Evidence("TAMPER.TOOL_DISABLED", EvidenceCategory.Tamper, 20, vn + " is switched on: " + (vn == "DisableTaskMgr" ? "Task Manager" : vn == "DisableRegistryTools" ? "Registry Editor" : "Command Prompt") + " is blocked", vn));
                            }
                        }
                    }
                }
                catch { }
            }
            // proxy hijack
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    if (k != null)
                    {
                        int pe = 0; try { pe = Convert.ToInt32(k.GetValue("ProxyEnable", 0)); } catch { }
                        string ps = Convert.ToString(k.GetValue("ProxyServer")); string pac = Convert.ToString(k.GetValue("AutoConfigURL"));
                        if ((pe == 1 && !string.IsNullOrWhiteSpace(ps)) || !string.IsNullOrWhiteSpace(pac))
                        {
                            var e = ctx.GetOrAdd("policy:HKCU:Proxy", EntityKind.PolicyValue, () => new Entity { Title = "System proxy is configured", Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" });
                            e.Set("hive", "HKCU"); e.Set("key", @"Software\Microsoft\Windows\CurrentVersion\Internet Settings"); e.Set("proxy", ps ?? ""); e.Set("pac", pac ?? "");
                            bool local = (ps ?? "").Contains("127.0.0.1") || (ps ?? "").Contains("localhost");
                            e.Add(new Evidence("TAMPER.PROXY_SET", EvidenceCategory.Tamper, string.IsNullOrWhiteSpace(pac) ? 5 : 8, "A system-wide proxy" + (string.IsNullOrWhiteSpace(pac) ? "" : "/auto-config script") + " is set" + (local ? " (local proxy - typical of VPN/filter software)" : " (all browser traffic goes through it)"), (ps ?? "") + " " + (pac ?? "")));
                        }
                    }
                }
            }
            catch { }
        }

        // -------------------------------------------------------------------------------------------------
        static void TermService(ScanContext ctx)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TermService\Parameters"))
                {
                    string dll = k == null ? null : Convert.ToString(k.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                    if (string.IsNullOrWhiteSpace(dll)) return;
                    string norm = PathUtil.Normalize(dll);
                    if (string.Equals(norm, Path.Combine(PathUtil.System32, "termsrv.dll"), StringComparison.OrdinalIgnoreCase)) return;
                    var e = ctx.GetOrAdd("reg:HKLM\\TermService\\ServiceDll", EntityKind.Registry, () => new Entity { Title = "Remote Desktop service DLL replaced", Location = @"HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll" });
                    e.Set("hive", "HKLM"); e.Set("key", @"SYSTEM\CurrentControlSet\Services\TermService\Parameters"); e.Set("value", "ServiceDll"); e.Set("data", dll); e.Set("default", @"%SystemRoot%\System32\termsrv.dll");
                    e.Add(new Evidence("TAMPER.TERMSERVICE_DLL", EvidenceCategory.Tamper, 25, "The Remote Desktop service loads a non-standard DLL (RDP Wrapper style; used by many miner/RAT bundles)", dll));
                    if (File.Exists(norm)) { var f = ctx.Files.Inspect(norm, FileRole.PersistenceTarget); if (f != null) ctx.Link(e.Id, f.Id, "loads"); }
                }
            }
            catch { }
        }

        // -------------------------------------------------------------------------------------------------
        static readonly Regex PsTamper = new Regex(@"(add|set)-mppreference\s+[^\r\n]*-(exclusion(path|process|extension)|disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning))", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static void PowerShellHistory(ScanContext ctx)
        {
            foreach (var up in PathUtil.UserProfiles())
            {
                string f = Path.Combine(up, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
                try
                {
                    if (!File.Exists(f)) continue;
                    var fi = new FileInfo(f); if (fi.Length > 4 * 1024 * 1024) continue;
                    var hits = File.ReadLines(f).Where(l => PsTamper.IsMatch(l)).Select(l => Text.Trunc(l.Trim(), 160)).Distinct().Take(6).ToList();
                    if (hits.Count == 0) continue;
                    var e = ctx.GetOrAdd("tamper:pshistory:" + up.ToLowerInvariant(), EntityKind.PolicyValue, () => new Entity { Title = "PowerShell history shows Defender changes", Location = f });
                    e.Set("file", f);
                    e.Add(new Evidence("TAMPER.PSHISTORY_DEFENDER", EvidenceCategory.Tamper, 10, "The PowerShell command history contains commands that add Defender exclusions / turn protection off (installers of miners do this; you may have run them yourself)", string.Join(" || ", hits)));
                }
                catch { }
            }
        }

        // -------------------------------------------------------------------------------------------------
        static void Firewall(ScanContext ctx)
        {
            try
            {
                Type t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (t == null) return;
                dynamic pol = Activator.CreateInstance(t);
                int n = 0;
                foreach (dynamic r in pol.Rules)
                {
                    if (n++ > 6000) break;
                    string app = null;
                    try { app = (string)r.ApplicationName; } catch { }
                    if (string.IsNullOrWhiteSpace(app) || app.Equals("System", StringComparison.OrdinalIgnoreCase)) continue;
                    string np = PathUtil.Normalize(app);
                    if (!PathUtil.IsUserWritable(np) && PathUtil.Classify(np) != PathClass.ProgramData) continue;
                    if (!File.Exists(np)) continue;
                    var f = ctx.Files.Inspect(np, FileRole.Referenced);
                    if (f == null || f.Trusted) continue;
                    string rname = null; try { rname = (string)r.Name; } catch { }
                    bool enabled = true; try { enabled = (bool)r.Enabled; } catch { }
                    if (!enabled) continue;
                    var e = ctx.GetOrAdd("fw:" + rname + ":" + PathUtil.Key(np), EntityKind.FirewallRule, () => new Entity { Title = "Firewall rule: " + rname, Location = np });
                    e.Set("ruleName", rname); e.Set("app", np);
                    e.Add(new Evidence("FW.RULE_UNTRUSTED_APP", EvidenceCategory.Tamper, 5, "A firewall rule allows an untrusted program from a user-writable folder", np));
                    ctx.Link(e.Id, f.Id, "allows");
                }
            }
            catch (Exception ex) { ctx.AddBlind("Firewall", ex.Message); }
        }

        // -------------------------------------------------------------------------------------------------
        static void Posture(ScanContext ctx)
        {
            var warn = ctx.PostureWarnings; var info = ctx.PostureInfo;
            try
            {
                bool defRunning = false, defDisabled = false;
                try
                {
                    using (var s = new System.ServiceProcess.ServiceController("WinDefend")) { defRunning = s.Status == System.ServiceProcess.ServiceControllerStatus.Running; }
                }
                catch { }
                int dis = 0;
                try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender")) if (k != null) dis = Convert.ToInt32(k.GetValue("DisableAntiSpyware", 0)); } catch { }
                defDisabled = dis == 1;
                var others = new List<string>();
                try
                {
                    using (var s = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName FROM AntiVirusProduct"))
                        foreach (ManagementObject o in s.Get()) { string n = Convert.ToString(o["displayName"]); if (!string.IsNullOrEmpty(n) && n.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) < 0) others.Add(n); }
                }
                catch { }
                ctx.PostureInfo.Add("DEFENDER_RUNNING=" + defRunning);
                if (!defRunning && others.Count == 0)
                    warn.Add("NO_AV|Windows Defender is not running" + (defDisabled ? " (switched off by the policy DisableAntiSpyware=1)" : "") + " and no other antivirus is registered - this computer has no active real-time protection.");
                else if (!defRunning && others.Count > 0) info.Add("OTHER_AV|Windows Defender is off, third-party antivirus registered: " + string.Join(", ", others));
                foreach (var o in others) info.Add("AV|" + o);

                int lua = 1; try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) if (k != null) lua = Convert.ToInt32(k.GetValue("EnableLUA", 1)); } catch { }
                if (lua == 0) warn.Add("UAC_OFF|User Account Control (UAC) is turned off - programs can get administrator rights without any prompt.");

                foreach (var svc in new[] { "wuauserv", "UsoSvc" })
                {
                    try
                    {
                        using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + svc))
                            if (k != null && Convert.ToInt32(k.GetValue("Start", 3)) == 4) { warn.Add("WU_OFF|Windows Update service (" + svc + ") is disabled."); break; }
                    }
                    catch { }
                }
                int noAuto = 0; try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) if (k != null) noAuto = Convert.ToInt32(k.GetValue("NoAutoUpdate", 0)); } catch { }
                if (noAuto == 1) warn.Add("WU_POLICY|Automatic Windows Updates are switched off by policy.");
                foreach (var prof in new[] { "StandardProfile", "PublicProfile", "DomainProfile" })
                {
                    try
                    {
                        using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + prof))
                            if (k != null && Convert.ToInt32(k.GetValue("EnableFirewall", 1)) == 0) { warn.Add("FW_OFF|Windows Firewall is turned off for the " + prof.Replace("Profile", "").ToLowerInvariant() + " network profile."); }
                    }
                    catch { }
                }
                int sm = 0; try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) { var v = k == null ? null : Convert.ToString(k.GetValue("SmartScreenEnabled")); if (v != null && v.Equals("Off", StringComparison.OrdinalIgnoreCase)) sm = 1; } } catch { }
                if (sm == 1) warn.Add("SMARTSCREEN_OFF|Windows SmartScreen is switched off.");
            }
            catch (Exception ex) { ctx.AddBlind("Security posture", ex.Message); }
        }
    }
}
