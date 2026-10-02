using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Shared logic: a persistence item (run value, task action, service image, WMI command...) launches a command line;
    /// this evaluates what it launches and registers the item only when it is worth looking at.</summary>
    internal static class Persist
    {
        // "C:\Users\x\notes.txt:payload.exe": a program started out of a hidden NTFS stream. File.Exists() cannot even see such a path, so it is matched by its shape.
        static readonly Regex AdsTargetRx = new Regex(@"(?<![A-Za-z])[A-Za-z]:\\(?:[^""'<>|?*:\r\n]+\\)*[^""'<>|?*:\\\r\n]+\.[A-Za-z0-9]{1,5}:(?!\\)(?<s>[^\\/:""'<>|?*\s,;]+)", RegexOptions.Compiled);
        static readonly HashSet<string> Lolbins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "cmstp.exe", "bitsadmin.exe", "certutil.exe", "msiexec.exe", "schtasks.exe", "wmic.exe", "forfiles.exe", "pcalua.exe", "conhost.exe", "explorer.exe", "start.exe" };

        public static bool IsLolbin(string exePath) { return exePath != null && Lolbins.Contains(Path.GetFileName(exePath)); }

        /// <summary>Returns the registered entity or null when the item is unremarkable (trusted target, nothing suspicious).</summary>
        public static Entity Evaluate(ScanContext ctx, string id, EntityKind kind, string title, string location, string command, string mechanism, Action<Entity> extra = null)
        {
            var e = new Entity { Id = id, Kind = kind, Title = title, Location = location };
            e.Set("command", command); e.Set("mechanism", mechanism);
            var targets = new List<Entity>();
            string exe = PathUtil.ExtractExecutable(command);
            var paths = PathUtil.ExtractPaths(command);
            bool lolbin = IsLolbin(exe);
            bool userPathArg = false;

            foreach (var p in paths.Take(5))
            {
                if (string.IsNullOrEmpty(p) || ctx.IsSelf(p)) continue;
                bool isExe = PathUtil.IsExecutableExt(p) || PathUtil.IsScriptExt(p) || PathUtil.IsInterpretedExt(p) || p.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
                if (!isExe) continue;
                bool exists = false; try { exists = File.Exists(p); } catch { }
                if (!exists)
                {
                    if (p == exe && !lolbin && Path.IsPathRooted(p)) e.Add(new Evidence("PERSIST.TARGET_MISSING", EvidenceCategory.Persistence, 3, "The program this item starts does not exist any more", p));
                    continue;
                }
                var f = ctx.Files.Inspect(p, FileRole.PersistenceTarget);
                if (f == null) continue;
                if (lolbin && p == exe) continue;                        // the shell itself is not the payload
                targets.Add(f);
                if (lolbin && PathUtil.IsUserWritable(p)) userPathArg = true;
            }

            // a signed program started from a user folder is trusted itself, but an unsigned library with the name of a Windows DLL next to it is what it will load: DLL side-loading
            var sideDlls = new List<Entity>();
            foreach (var t in targets.Where(x => x.Trusted && PathUtil.IsUserWritable(x.Location) && string.Equals(Path.GetExtension(x.Location), ".exe", StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    string dir = Path.GetDirectoryName(t.Location);
                    foreach (var f in Directory.EnumerateFiles(dir, "*.dll").Take(400))
                    {
                        if (!ctx.Rules.SideloadNames.Contains(Path.GetFileName(f))) continue;
                        var d = ctx.Files.Inspect(f, FileRole.PersistenceTarget);
                        if (d == null || d.Trusted) continue;
                        sideDlls.Add(d);
                        e.Add(new Evidence("PERSIST.SIDELOAD_PAIR", EvidenceCategory.Persistence, 30, mechanism + " starts a signed program from a user folder, and an unsigned library named like a Windows DLL lies next to it: the program loads that file instead of the real one (DLL side-loading)", f));
                    }
                }
                catch { }
            }

            string expandedCmd = command ?? "";
            if (expandedCmd.IndexOf('%') >= 0) { try { expandedCmd = Environment.ExpandEnvironmentVariables(expandedCmd); } catch { } }
            var adsHit = AdsTargetRx.Match(expandedCmd);
            if (adsHit.Success && !adsHit.Groups["s"].Value.StartsWith("Zone", StringComparison.OrdinalIgnoreCase))
                e.Add(new Evidence("PERSIST.ADS_TARGET", EvidenceCategory.Persistence, 40, mechanism + " starts something that lives inside a hidden NTFS data stream of another file (\"" + adsHit.Groups["s"].Value + "\"). Normal software does not do this", Text.Trunc(adsHit.Value, 200)));

            var untrusted = targets.Where(t => !t.Trusted).ToList();
            foreach (var t in untrusted)
            {
                bool uw = PathUtil.IsUserWritable(t.Location);
                if (uw)
                    e.Add(new Evidence("PERSIST.TARGET_USER_PATH", EvidenceCategory.Persistence, 10, mechanism + " starts a program from a user-writable folder that is not signed by a trusted publisher", t.Location));
                else if (t.P("sig") == "Unsigned")
                    e.Add(new Evidence("PERSIST.TARGET_UNSIGNED", EvidenceCategory.Persistence, 3, mechanism + " starts an unsigned program", t.Location));
            }
            if (userPathArg && untrusted.Count > 0)
                e.Add(new Evidence("PERSIST.LOLBIN_USERPATH", EvidenceCategory.Persistence, 14, mechanism + " uses a system shell/interpreter to run a file from a user folder", Text.Trunc(command, 200)));

            if (!string.IsNullOrEmpty(command))
                foreach (var r in ctx.Rules.CmdRules)
                    if (r.Rx.IsMatch(command))
                        e.Add(new Evidence("PERSIST." + r.Id, FileIntel.ParseCat(r.Category), r.Weight, r.Text + " (in " + mechanism + ")", Text.Trunc(command, 200), r.Definitive));

            if (!string.IsNullOrEmpty(title))
                foreach (var nr in ctx.Rules.NameRules)
                    if (nr.Rx.IsMatch(title.Trim()))
                        e.Add(new Evidence(nr.Id, EvidenceCategory.Masquerade, nr.Weight, nr.Text, title));

            if (extra != null) extra(e);

            bool interesting = e.Evidence.Any(x => x.Weight > 0) || untrusted.Any(t => t.Evidence.Where(x => x.Weight > 0).Sum(x => x.Weight) >= 12);
            if (!interesting) return null;
            var reg = ctx.GetOrAdd(id, kind, () => e);
            if (!object.ReferenceEquals(reg, e)) { foreach (var ev in e.Evidence) reg.Add(ev); }
            foreach (var t in targets) ctx.Link(reg.Id, t.Id, "launches");
            foreach (var d in sideDlls) ctx.Link(reg.Id, d.Id, "loads");
            return reg;
        }
    }

    // ==========================================================================================================
    //   Registry autoruns and other registry-based persistence points
    // ==========================================================================================================
    public static class RegistryPersistenceScanner
    {
        static readonly string[] RunKeys =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
        };

        public static void Run(ScanContext ctx)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                string hn = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                foreach (var k in RunKeys) ScanRunKey(ctx, hive, hn, k);
            }
            // other users' Run keys: signed-in users (loaded under HKEY_USERS) and users who are not signed in (their NTUSER.DAT is mounted for a moment)
            try
            {
                var hives = UserHives.Enumerate(ctx, ctx.Options.OtherUserHives);
                foreach (var h in hives)
                {
                    if (h.Label == "HKCU") continue;                               // done above
                    foreach (var k in RunKeys.Take(5)) ScanRunKey(ctx, h.Root, h.Label, k);
                    if (!h.Label.StartsWith("HKUOFF\\")) h.Root.Dispose();           // offline mounts are released by the engine when the stage is over
                }
            }
            catch (Exception ex) { ctx.AddBlind("Registry", "other users' registry: " + ex.Message); }

            Winlogon(ctx);
            AppInit(ctx);
            Ifeo(ctx);
            Lsa(ctx);
            DllListKeys(ctx);
            ActiveSetup(ctx);
            ComHijack(ctx);
            Screensaver(ctx);
            EnvironmentProfilers(ctx);
            SessionManager(ctx);
        }

        internal static void ScanRunKey(ScanContext ctx, RegistryKey hive, string hiveName, string sub)
        {
            try
            {
                using (var k = hive.OpenSubKey(sub))
                {
                    if (k == null) return;
                    foreach (var vn in k.GetValueNames())
                    {
                        string data = null;
                        try { data = Convert.ToString(k.GetValue(vn, null, RegistryValueOptions.DoNotExpandEnvironmentNames)); } catch { }
                        if (string.IsNullOrWhiteSpace(data)) continue;
                        ctx.Stats.RunEntries++;
                        string id = "run:" + hiveName + "\\" + sub + "\\" + vn;
                        var e = Persist.Evaluate(ctx, id, EntityKind.RunKey, vn, hiveName + "\\" + sub + "\\" + vn, data, sub.Contains("RunOnce") ? "RunOnce entry" : "Autorun entry");
                        if (e != null) { e.Set("hive", hiveName); e.Set("key", sub); e.Set("value", vn); e.Set("data", data); }
                    }
                }
            }
            catch (UnauthorizedAccessException) { ctx.Denied("Registry", hiveName + "\\" + sub); }
            catch { }
        }

        static void Winlogon(ScanContext ctx)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                string hn = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                try
                {
                    using (var k = hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                    {
                        if (k == null) continue;
                        foreach (var vn in new[] { "Shell", "Userinit", "Taskman", "AppSetup", "VmApplet", "System", "UIHost", "GinaDLL" })
                        {
                            string v = Convert.ToString(k.GetValue(vn));
                            if (string.IsNullOrWhiteSpace(v)) continue;
                            bool ok = false;
                            string vl = v.Trim().ToLowerInvariant();
                            if (vn == "Shell") ok = vl == "explorer.exe" || vl == PathUtil.WinDir.ToLowerInvariant() + @"\explorer.exe";
                            else if (vn == "Userinit") ok = vl.TrimEnd(',') == (PathUtil.System32 + @"\userinit.exe").ToLowerInvariant();
                            else if (vn == "UIHost") ok = vl == "logonui.exe";
                            else if (vn == "VmApplet") ok = vl.Contains("systempropertiesperformance") || vl.Contains("systemproperties");
                            if (ok) continue;
                            string id = "reg:" + hn + "\\Winlogon\\" + vn;
                            var e = Persist.Evaluate(ctx, id, EntityKind.Registry, "Winlogon\\" + vn, hn + "\\...\\Winlogon\\" + vn, v, "Winlogon " + vn, ev =>
                                ev.Add(new Evidence("REG.WINLOGON_NONDEFAULT", EvidenceCategory.Persistence, 40, "Winlogon " + vn + " is not the Windows default (runs at every logon)", v)));
                            if (e != null) { e.Set("hive", hn); e.Set("value", vn); e.Set("data", v); e.Set("default", vn == "Shell" ? "explorer.exe" : (vn == "Userinit" ? PathUtil.System32 + @"\userinit.exe," : "")); }
                        }
                    }
                }
                catch { }
            }
        }

        static void AppInit(ScanContext ctx)
        {
            foreach (var sub in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(sub))
                    {
                        if (k == null) continue;
                        string v = Convert.ToString(k.GetValue("AppInit_DLLs"));
                        if (string.IsNullOrWhiteSpace(v)) continue;
                        int load = 0; try { load = Convert.ToInt32(k.GetValue("LoadAppInit_DLLs", 0)); } catch { }
                        string id = "reg:HKLM\\" + sub + "\\AppInit_DLLs";
                        var e = Persist.Evaluate(ctx, id, EntityKind.Registry, "AppInit_DLLs", "HKLM\\" + sub, v.Replace(',', ' '), "AppInit_DLLs", ev =>
                            ev.Add(new Evidence("REG.APPINIT_DLLS", EvidenceCategory.Persistence, load == 1 ? 32 : 14, "AppInit_DLLs injects a DLL into every program that loads user32" + (load == 1 ? " (enabled)" : " (LoadAppInit_DLLs is off)"), v)));
                        if (e != null) { e.Set("hive", "HKLM"); e.Set("key", sub); e.Set("value", "AppInit_DLLs"); e.Set("data", v); }
                    }
                }
                catch { }
            }
        }

        static void Ifeo(ScanContext ctx)
        {
            foreach (var root in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" })
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(root))
                    {
                        if (k == null) continue;
                        foreach (var name in k.GetSubKeyNames())
                        {
                            using (var s = k.OpenSubKey(name))
                            {
                                if (s == null) continue;
                                string dbg = Convert.ToString(s.GetValue("Debugger"));
                                if (string.IsNullOrWhiteSpace(dbg)) continue;
                                string id = "reg:HKLM\\IFEO\\" + name;
                                string dl = dbg.ToLowerInvariant();
                                bool blockTrick = Regex.IsMatch(dl, @"^(""?[a-z]:\\windows\\system32\\)?cmd(\.exe)?""?\s+/d\s+/c\s+exit\s*$") || dl.Contains("systray.exe");
                                var e = Persist.Evaluate(ctx, id, EntityKind.Registry, "IFEO debugger: " + name, "HKLM\\...\\Image File Execution Options\\" + name, dbg, "IFEO debugger", ev =>
                                {
                                    if (blockTrick) ev.Add(new Evidence("REG.IFEO_BLOCK", EvidenceCategory.Tamper, 2, "The program \"" + name + "\" is prevented from running via IFEO (a common tweak; harmless unless you did not do it)", dbg));
                                    else ev.Add(new Evidence("REG.IFEO_DEBUGGER", EvidenceCategory.Persistence, 26, "IFEO debugger hijack: every start of \"" + name + "\" runs another program first", dbg));
                                });
                                if (e != null) { e.Set("hive", "HKLM"); e.Set("key", root + "\\" + name); e.Set("value", "Debugger"); e.Set("data", dbg); }
                            }
                        }
                    }
                }
                catch { }
            }
            // SilentProcessExit: MonitorProcess runs a program when another exits (used for stealthy persistence)
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"))
                {
                    if (k != null)
                        foreach (var name in k.GetSubKeyNames())
                            using (var s = k.OpenSubKey(name))
                            {
                                string mon = s == null ? null : Convert.ToString(s.GetValue("MonitorProcess"));
                                if (string.IsNullOrWhiteSpace(mon)) continue;
                                var e = Persist.Evaluate(ctx, "reg:HKLM\\SilentProcessExit\\" + name, EntityKind.Registry, "SilentProcessExit: " + name, "HKLM\\...\\SilentProcessExit\\" + name, mon, "SilentProcessExit monitor", ev =>
                                    ev.Add(new Evidence("REG.SILENT_PROCESS_EXIT", EvidenceCategory.Persistence, 26, "A program is launched whenever \"" + name + "\" exits (SilentProcessExit persistence)", mon)));
                                if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" + name); e.Set("value", "MonitorProcess"); e.Set("data", mon); }
                            }
                }
            }
            catch { }
        }

        static readonly HashSet<string> DefaultLsaAuth = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "msv1_0" };
        static readonly HashSet<string> DefaultLsaNotify = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "scecli", "rassfm", "cngkeyx", "pkcs11" };
        static readonly HashSet<string> DefaultLsaSecurity = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "livessp", "" , "\"\"" };

        static void Lsa(ScanContext ctx)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa"))
                {
                    if (k == null) return;
                    foreach (var pair in new[] { new[] { "Authentication Packages", "auth" }, new[] { "Notification Packages", "notify" }, new[] { "Security Packages", "sec" } })
                    {
                        var vals = k.GetValue(pair[0]) as string[]; if (vals == null) { var s = k.GetValue(pair[0]) as string; if (s != null) vals = new[] { s }; }
                        if (vals == null) continue;
                        var def = pair[1] == "auth" ? DefaultLsaAuth : pair[1] == "notify" ? DefaultLsaNotify : DefaultLsaSecurity;
                        foreach (var raw in vals)
                        {
                            string n = (raw ?? "").Trim().Trim('"');
                            if (n.Length == 0 || def.Contains(n)) continue;
                            string dll = Path.Combine(PathUtil.System32, n.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? n : n + ".dll");
                            var e = Persist.Evaluate(ctx, "reg:HKLM\\Lsa\\" + pair[0] + "\\" + n, EntityKind.Registry, "LSA " + pair[0] + ": " + n, @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" + pair[0], dll, "LSA package", ev =>
                                ev.Add(new Evidence("REG.LSA_PACKAGE", EvidenceCategory.Persistence, 22, "Non-default LSA package is loaded into the security subsystem (credential-theft / persistence technique)", n)));
                            if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SYSTEM\CurrentControlSet\Control\Lsa"); e.Set("value", pair[0]); e.Set("data", n); }
                        }
                    }
                    var appCert = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls");
                    if (appCert != null)
                        foreach (var vn in appCert.GetValueNames())
                        {
                            string v = Convert.ToString(appCert.GetValue(vn));
                            var e = Persist.Evaluate(ctx, "reg:HKLM\\AppCertDlls\\" + vn, EntityKind.Registry, "AppCertDLLs: " + vn, @"HKLM\...\Session Manager\AppCertDlls\" + vn, v, "AppCertDLLs", ev =>
                                ev.Add(new Evidence("REG.APPCERT_DLLS", EvidenceCategory.Persistence, 30, "AppCertDLLs loads a DLL into every process that calls CreateProcess", v)));
                            if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"); e.Set("value", vn); e.Set("data", v); }
                        }
                }
            }
            catch { }
        }

        static void DllListKeys(ScanContext ctx)
        {
            // netsh helper DLLs, print monitors, time providers
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NetSh"))
                    if (k != null)
                        foreach (var vn in k.GetValueNames())
                        {
                            string v = Convert.ToString(k.GetValue(vn));
                            if (string.IsNullOrWhiteSpace(v)) continue;
                            string dll = Path.IsPathRooted(v) ? v : Path.Combine(PathUtil.System32, v);
                            var e = Persist.Evaluate(ctx, "reg:HKLM\\NetSh\\" + vn, EntityKind.Registry, "Netsh helper: " + vn, @"HKLM\SOFTWARE\Microsoft\NetSh\" + vn, dll, "netsh helper DLL");
                            if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SOFTWARE\Microsoft\NetSh"); e.Set("value", vn); e.Set("data", v); }
                        }
            }
            catch { }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Print\Monitors"))
                    if (k != null)
                        foreach (var name in k.GetSubKeyNames())
                            using (var s = k.OpenSubKey(name))
                            {
                                string v = s == null ? null : Convert.ToString(s.GetValue("Driver"));
                                if (string.IsNullOrWhiteSpace(v)) continue;
                                string dll = Path.IsPathRooted(v) ? v : Path.Combine(PathUtil.System32, v);
                                var e = Persist.Evaluate(ctx, "reg:HKLM\\PrintMonitor\\" + name, EntityKind.Registry, "Print monitor: " + name, @"HKLM\...\Print\Monitors\" + name, dll, "print monitor DLL");
                                if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SYSTEM\CurrentControlSet\Control\Print\Monitors\" + name); e.Set("value", "Driver"); e.Set("data", v); }
                            }
            }
            catch { }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"))
                    if (k != null)
                        foreach (var name in k.GetSubKeyNames())
                            using (var s = k.OpenSubKey(name))
                            {
                                string v = s == null ? null : Convert.ToString(s.GetValue("DllName"));
                                if (string.IsNullOrWhiteSpace(v)) continue;
                                string dll = Path.IsPathRooted(Environment.ExpandEnvironmentVariables(v)) ? Environment.ExpandEnvironmentVariables(v) : Path.Combine(PathUtil.System32, v);
                                var e = Persist.Evaluate(ctx, "reg:HKLM\\TimeProvider\\" + name, EntityKind.Registry, "Time provider: " + name, @"HKLM\...\W32Time\TimeProviders\" + name, dll, "time provider DLL");
                                if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\" + name); e.Set("value", "DllName"); e.Set("data", v); }
                            }
            }
            catch { }
        }

        static void ActiveSetup(ScanContext ctx)
        {
            foreach (var root in new[] { @"SOFTWARE\Microsoft\Active Setup\Installed Components", @"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" })
            {
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(root))
                        if (k != null)
                            foreach (var name in k.GetSubKeyNames())
                                using (var s = k.OpenSubKey(name))
                                {
                                    string v = s == null ? null : Convert.ToString(s.GetValue("StubPath"));
                                    if (string.IsNullOrWhiteSpace(v)) continue;
                                    var e = Persist.Evaluate(ctx, "reg:HKLM\\ActiveSetup\\" + name, EntityKind.Registry, "Active Setup: " + name, @"HKLM\...\Active Setup\Installed Components\" + name, v, "Active Setup StubPath");
                                    if (e != null) { e.Set("hive", "HKLM"); e.Set("key", root + "\\" + name); e.Set("value", "StubPath"); e.Set("data", v); }
                                }
                }
                catch { }
            }
        }

        static void ComHijack(ScanContext ctx)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID"))
                {
                    if (k == null) return;
                    foreach (var clsid in k.GetSubKeyNames().Take(3000))
                        foreach (var srv in new[] { "InprocServer32", "LocalServer32" })
                            using (var s = k.OpenSubKey(clsid + "\\" + srv))
                            {
                                string v = s == null ? null : Convert.ToString(s.GetValue(null));
                                if (string.IsNullOrWhiteSpace(v)) continue;
                                var e = Persist.Evaluate(ctx, "reg:HKCU\\CLSID\\" + clsid + "\\" + srv, EntityKind.Registry, "COM " + srv + " " + clsid, @"HKCU\Software\Classes\CLSID\" + clsid + "\\" + srv, v, "per-user COM registration");
                                if (e != null) { e.Set("hive", "HKCU"); e.Set("key", @"Software\Classes\CLSID\" + clsid + "\\" + srv); e.Set("value", ""); e.Set("data", v); }
                            }
                }
            }
            catch { }
        }

        static void Screensaver(ScanContext ctx)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop"))
                {
                    string v = k == null ? null : Convert.ToString(k.GetValue("SCRNSAVE.EXE"));
                    if (string.IsNullOrWhiteSpace(v)) return;
                    var e = Persist.Evaluate(ctx, "reg:HKCU\\Screensaver", EntityKind.Registry, "Screensaver", @"HKCU\Control Panel\Desktop\SCRNSAVE.EXE", v, "screensaver");
                    if (e != null) { e.Set("hive", "HKCU"); e.Set("key", @"Control Panel\Desktop"); e.Set("value", "SCRNSAVE.EXE"); e.Set("data", v); }
                }
            }
            catch { }
        }

        static void EnvironmentProfilers(ScanContext ctx)
        {
            foreach (var pair in new[] { new object[] { Registry.CurrentUser, "HKCU", "Environment" }, new object[] { Registry.LocalMachine, "HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment" } })
            {
                try
                {
                    using (var k = ((RegistryKey)pair[0]).OpenSubKey((string)pair[2]))
                    {
                        if (k == null) continue;
                        foreach (var vn in new[] { "COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH", "CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH", "DOTNET_STARTUP_HOOKS", "_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS" })
                        {
                            string v = Convert.ToString(k.GetValue(vn));
                            if (string.IsNullOrWhiteSpace(v)) continue;
                            if ((vn == "_JAVA_OPTIONS" || vn == "JAVA_TOOL_OPTIONS") && !v.Contains("javaagent")) continue;
                            var e = Persist.Evaluate(ctx, "reg:" + pair[1] + "\\Env\\" + vn, EntityKind.Registry, "Environment " + vn, pair[1] + "\\" + pair[2] + "\\" + vn, v, "environment profiler", ev =>
                                ev.Add(new Evidence("REG.ENV_PROFILER", EvidenceCategory.Persistence, 28, "A profiler/startup hook variable makes every .NET/Java program load extra code", vn + "=" + v)));
                            if (e != null) { e.Set("hive", (string)pair[1]); e.Set("key", (string)pair[2]); e.Set("value", vn); e.Set("data", v); }
                        }
                    }
                }
                catch { }
            }
        }

        static void SessionManager(ScanContext ctx)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
                {
                    if (k == null) return;
                    var be = k.GetValue("BootExecute") as string[];
                    if (be != null)
                        foreach (var v in be)
                        {
                            string t = (v ?? "").Trim();
                            if (t.Length == 0 || Regex.IsMatch(t, @"^autocheck\s+autochk\s+\*$", RegexOptions.IgnoreCase)) continue;
                            var e = Persist.Evaluate(ctx, "reg:HKLM\\BootExecute\\" + t, EntityKind.Registry, "BootExecute: " + t, @"HKLM\...\Session Manager\BootExecute", t, "BootExecute", ev =>
                                ev.Add(new Evidence("REG.BOOT_EXECUTE", EvidenceCategory.Persistence, 35, "Non-default BootExecute entry runs before Windows fully starts", t)));
                            if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SYSTEM\CurrentControlSet\Control\Session Manager"); e.Set("value", "BootExecute"); e.Set("data", t); }
                        }
                }
            }
            catch { }
        }
    }

    // ==========================================================================================================
    //   Startup folders (files and shortcuts)
    // ==========================================================================================================
    public static class StartupScanner
    {
        public static void Run(ScanContext ctx)
        {
            var dirs = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) };
            foreach (var up in PathUtil.UserProfiles())
                dirs.Add(Path.Combine(up, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
            foreach (var d in dirs.Where(x => !string.IsNullOrEmpty(x)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(d)) continue;
                string[] files;
                try { files = Directory.GetFiles(d); } catch { ctx.Denied("Startup folder", d); continue; }
                foreach (var f in files)
                {
                    string name = Path.GetFileName(f);
                    if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.Stats.PersistenceItems++;
                    string command = f;
                    if (f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        string target, args;
                        if (ResolveShortcut(f, out target, out args)) command = (target ?? "") + (string.IsNullOrEmpty(args) ? "" : " " + args);
                    }
                    var e = Persist.Evaluate(ctx, "startup:" + PathUtil.Key(f), EntityKind.StartupItem, name, f, command, "Startup-folder item", ev =>
                    {
                        bool hidden = Fs.IsHidden(f);
                        if (hidden) ev.Add(new Evidence("STARTUP.HIDDEN", EvidenceCategory.Persistence, 12, "Hidden file in a Startup folder", f));
                        if (name.IndexOf('\u200b') >= 0 || name.Trim().Length == 0 || name.StartsWith(" ") || Regex.IsMatch(Path.GetFileNameWithoutExtension(name), @"^[\u200b\u00a0\s]+$"))
                            ev.Add(new Evidence("STARTUP.INVISIBLE_NAME", EvidenceCategory.Masquerade, 25, "Startup item with an invisible/blank name", f));
                        if (Regex.IsMatch(command, @"cmd(\.exe)?""?\s+/c\s", RegexOptions.IgnoreCase) && f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                            ev.Add(new Evidence("STARTUP.LNK_CMD", EvidenceCategory.Persistence, 22, "Shortcut runs cmd.exe /c (typical of dropped malware shortcuts)", command));
                    });
                    if (e != null) { e.Set("file", f); e.Set("resolved", command); }
                }
            }
        }

        public static bool ResolveShortcut(string lnk, out string target, out string args)
        {
            target = null; args = null;
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell");
                dynamic sh = Activator.CreateInstance(t);
                dynamic s = sh.CreateShortcut(lnk);
                target = (string)s.TargetPath; args = (string)s.Arguments;
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(s);
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(sh);
                return true;
            }
            catch { return false; }
        }
    }

    // ==========================================================================================================
    //   Services and drivers
    // ==========================================================================================================
    public static class ServiceScanner
    {
        static readonly Regex RandomNameRx = new Regex(@"^[A-Za-z]{8,14}$", RegexOptions.Compiled);
        static readonly Regex WinDescRx = new Regex(@"\b(windows|microsoft)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static void Run(ScanContext ctx)
        {
            var wmi = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Name,State FROM Win32_Service"))
                    foreach (ManagementObject o in s.Get()) wmi[Convert.ToString(o["Name"])] = Convert.ToString(o["State"]);
            }
            catch { }

            try
            {
                using (var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (root == null) return;
                    foreach (var name in root.GetSubKeyNames())
                    {
                        ctx.ThrowIfCancelled();
                        try { One(ctx, root, name, wmi); }
                        catch (UnauthorizedAccessException) { ctx.Denied("Services", name); }
                        catch (Exception ex) { Log.Warn("service " + name + ": " + ex.Message); }
                    }
                }
            }
            catch (Exception ex) { ctx.AddBlind("Services", ex.Message); }
        }

        static string ResolveImage(string imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return null;
            string p = PathUtil.Normalize(imagePath);
            if (p.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase)) p = PathUtil.WinDir + "\\" + p;
            return p;
        }

        internal static void One(ScanContext ctx, RegistryKey root, string name, Dictionary<string, string> states)
        {
            using (var k = root.OpenSubKey(name))
            {
                if (k == null) return;
                string image = Convert.ToString(k.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                int type = 0, start = 3;
                try { type = Convert.ToInt32(k.GetValue("Type", 0)); } catch { }
                try { start = Convert.ToInt32(k.GetValue("Start", 3)); } catch { }
                string dllParam = null, wrapped = null;
                using (var p = k.OpenSubKey("Parameters"))
                    if (p != null)
                    {
                        dllParam = Convert.ToString(p.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                        // NSSM / srvany style wrappers: the service image is a harmless wrapper, the program that really runs is a parameter
                        string app = Convert.ToString(p.GetValue("Application", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                        if (!string.IsNullOrWhiteSpace(app))
                        {
                            string aargs = Convert.ToString(p.GetValue("AppParameters", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                            wrapped = (app.Contains(" ") && !app.StartsWith("\"") ? "\"" + app + "\"" : app) + (string.IsNullOrWhiteSpace(aargs) ? "" : " " + aargs);
                        }
                    }
                if (string.IsNullOrWhiteSpace(image) && string.IsNullOrWhiteSpace(dllParam)) return;
                ctx.Stats.ServicesScanned++;

                bool isDriver = type == 1 || type == 2 || type == 8;
                string cmd = image;
                if (isDriver && !string.IsNullOrEmpty(image) && !image.Contains(":") && !image.StartsWith("\\"))
                    cmd = PathUtil.WinDir + "\\" + image.TrimStart('\\');
                else if (isDriver && !string.IsNullOrEmpty(image) && image.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                    cmd = image;
                if (wrapped != null) cmd = (cmd ?? "") + " " + wrapped;
                string display = Convert.ToString(k.GetValue("DisplayName"));
                string desc = Convert.ToString(k.GetValue("Description"));
                string account = Convert.ToString(k.GetValue("ObjectName"));
                string state; states.TryGetValue(name, out state);

                string mechanism = isDriver ? "Driver service" : "Service";
                var e = Persist.Evaluate(ctx, "svc:" + name, isDriver ? EntityKind.Driver : EntityKind.Service, name, "Service " + name, cmd, mechanism, ev =>
                {
                    string exe = ResolveImage(PathUtil.ExtractExecutable(cmd));
                    bool uw = exe != null && PathUtil.IsUserWritable(exe);
                    var target = exe != null && File.Exists(exe) ? ctx.Files.Inspect(exe, FileRole.PersistenceTarget) : null;
                    bool untrusted = target != null && !target.Trusted;

                    if (untrusted && uw) ev.Add(new Evidence("SVC.IMAGE_USER_PATH", EvidenceCategory.Persistence, isDriver ? 28 : 22, (isDriver ? "Driver" : "Service") + " image is stored in a user-writable folder", exe));
                    if (wrapped != null)
                    {
                        string wexe = PathUtil.ExtractExecutable(wrapped);
                        var wt = wexe != null && File.Exists(wexe) ? ctx.Files.Inspect(wexe, FileRole.PersistenceTarget) : null;
                        if (wt != null && !wt.Trusted && PathUtil.IsUserWritable(wexe))
                        {
                            ev.Add(new Evidence("SVC.WRAPPED_USER_PATH", EvidenceCategory.Persistence, 22, "The service is only a wrapper (NSSM or similar); the program it keeps running is unsigned and lies in a user-writable folder", wexe));
                            ctx.Link("svc:" + name, wt.Id, "wraps");
                        }
                    }
                    if (untrusted && !uw && !isDriver && exe != null && (PathUtil.Classify(exe) == PathClass.WindowsSystem || PathUtil.Classify(exe) == PathClass.WindowsOther) && target.P("sig") == "Unsigned")
                        ev.Add(new Evidence("SVC.UNSIGNED_IN_WINDOWS", EvidenceCategory.Persistence, 10, "The service runs an unsigned program from inside the Windows folder (system folders only hold signed Microsoft programs)", exe));
                    if (untrusted && !isDriver)
                    {
                        string stem = Path.GetFileNameWithoutExtension(exe);
                        if (string.Equals(stem, name, StringComparison.OrdinalIgnoreCase) && (PathUtil.Classify(exe) == PathClass.UserTemp || PathUtil.Classify(exe) == PathClass.WindowsTemp))
                            ev.Add(new Evidence("SVC.NAME_EQUALS_TEMP_IMAGE", EvidenceCategory.Persistence, 12, "Service name equals its executable name and the image sits in a temp folder", exe));
                        if (RandomNameRx.IsMatch(name) && uw && start <= 2)
                            ev.Add(new Evidence("SVC.RANDOM_NAME", EvidenceCategory.Masquerade, 8, "Auto-start service with a random-looking name running from a user folder", name));
                        if ((WinDescRx.IsMatch(desc ?? "") || WinDescRx.IsMatch(display ?? "")) && (target.P("sig") == "Unsigned" || target.P("sig") == "Tampered"))
                            ev.Add(new Evidence("SVC.FAKE_DESCRIPTION", EvidenceCategory.Masquerade, 15, "Service claims to be a Windows/Microsoft component but its file is unsigned", display));
                        if (start <= 2 && HasRestartFailureActions(k) && uw)
                            ev.Add(new Evidence("SVC.AUTO_RESTART_UNTRUSTED", EvidenceCategory.Persistence, 8, "Auto-start service restarts itself when killed (watchdog behaviour) and runs from a user folder"));
                    }
                    if (!string.IsNullOrEmpty(dllParam))
                    {
                        string dll = PathUtil.Normalize(dllParam);
                        if (File.Exists(dll))
                        {
                            var df = ctx.Files.Inspect(dll, FileRole.PersistenceTarget);
                            if (df != null && !df.Trusted)
                            {
                                bool dw = PathUtil.IsUserWritable(dll) || PathUtil.Classify(dll) == PathClass.ProgramData;
                                ev.Add(new Evidence("SVC.SERVICEDLL_UNTRUSTED", EvidenceCategory.Persistence, dw ? 30 : 8, "svchost-hosted service DLL is not signed by a trusted publisher", dll));
                                ctx.Link("svc:" + name, df.Id, "hosts");
                            }
                        }
                    }
                    if (isDriver)
                    {
                        string stem2 = exe == null ? "" : Path.GetFileNameWithoutExtension(exe);
                        foreach (var v in ctx.Rules.VulnerableDrivers)
                            if (stem2.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0 || name.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0)
                            { ev.Add(new Evidence("DRV.VULNERABLE_KNOWN", EvidenceCategory.Content, 14, "Signed but vulnerable kernel driver that miners abuse for CPU tuning (also used by hardware-monitor tools)", exe ?? name)); break; }
                        if (target != null && !target.Trusted && target.P("sig") == "Unsigned" && !uw)
                            ev.Add(new Evidence("DRV.UNSIGNED", EvidenceCategory.Content, 18, "Kernel driver without a valid signature", exe));
                    }
                });
                if (e != null)
                {
                    e.Set("state", state); e.Set("startType", start.ToString()); e.Set("account", account); e.Set("description", desc); e.Set("display", display);
                    e.Set("serviceKey", name);
                }
            }
        }

        static bool HasRestartFailureActions(RegistryKey k)
        {
            try
            {
                var b = k.GetValue("FailureActions") as byte[];
                if (b == null || b.Length < 20) return false;
                int count = BitConverter.ToInt32(b, 12);
                for (int i = 0; i < Math.Min(count, 3); i++) { int off = 20 + i * 8; if (off + 4 <= b.Length && BitConverter.ToInt32(b, off) == 1) return true; }
            }
            catch { }
            return false;
        }
    }

    // ==========================================================================================================
    //   Scheduled tasks (XML store + TaskCache consistency)
    // ==========================================================================================================
    public static class TaskScanner
    {
        static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        public static void Run(ScanContext ctx)
        {
            string tasksRoot = Path.Combine(PathUtil.System32, "Tasks");
            var xmlFiles = new List<string>();
            try { xmlFiles = Fs.EnumerateFiles(tasksRoot, null, f => true, 10, d => ctx.Denied("Scheduled tasks", d)).ToList(); }
            catch (Exception ex) { ctx.AddBlind("Scheduled tasks", ex.Message); }
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in xmlFiles)
            {
                ctx.ThrowIfCancelled();
                string rel = f.Substring(tasksRoot.Length);
                known.Add(rel.TrimStart('\\'));
                try { One(ctx, f, "\\" + rel.TrimStart('\\')); }
                catch (Exception ex) { Log.Warn("task " + rel + ": " + ex.Message); }
                ctx.Stats.TasksScanned++;
            }
            HiddenFromStore(ctx, known);
        }

        static string Txt(XElement e, string name) { var x = e == null ? null : e.Element(Ns + name); return x == null ? null : x.Value; }

        internal static void One(ScanContext ctx, string file, string taskPath)
        {
            XDocument doc;
            try { doc = XDocument.Load(file); } catch { DamagedXml(ctx, file, taskPath); return; }
            var root = doc.Root; if (root == null) { DamagedXml(ctx, file, taskPath); return; }
            var reg = root.Element(Ns + "RegistrationInfo");
            var principals = root.Element(Ns + "Principals");
            var principal = principals == null ? null : principals.Element(Ns + "Principal");
            var settings = root.Element(Ns + "Settings");
            var triggers = root.Element(Ns + "Triggers");
            var actions = root.Element(Ns + "Actions");
            if (actions == null) return;
            bool enabled = !string.Equals(Txt(settings, "Enabled"), "false", StringComparison.OrdinalIgnoreCase);
            bool hidden = string.Equals(Txt(settings, "Hidden"), "true", StringComparison.OrdinalIgnoreCase);
            string runLevel = Txt(principal, "RunLevel");
            string author = Txt(reg, "Author");
            string name = Path.GetFileName(taskPath);
            string folder = taskPath.Substring(0, Math.Max(1, taskPath.LastIndexOf('\\')));

            var repeat = new List<TimeSpan>();
            var trigTypes = new List<string>();
            var sessionStates = new List<string>();
            bool idleOnly = string.Equals(Txt(settings, "RunOnlyIfIdle"), "true", StringComparison.OrdinalIgnoreCase);
            if (triggers != null)
                foreach (var t in triggers.Elements())
                {
                    trigTypes.Add(t.Name.LocalName);
                    if (t.Name.LocalName == "SessionStateChangeTrigger") { string sc = Txt(t, "StateChange"); if (!string.IsNullOrEmpty(sc)) sessionStates.Add(sc); }
                    var rep = t.Element(Ns + "Repetition");
                    string iv = Txt(rep, "Interval");
                    if (!string.IsNullOrEmpty(iv)) { try { repeat.Add(System.Xml.XmlConvert.ToTimeSpan(iv)); } catch { } }
                }

            bool nsMs = taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);

            // shared by every action kind: name-based IOC, hidden/highest/repeat/namespace signals once we know what the task runs
            Action<Entity, string> addCommonSignals = (ev, exe) =>
            {
                foreach (var r in ctx.Rules.TaskFolderRules)
                    if (folder.Equals(r.Folder, StringComparison.OrdinalIgnoreCase) && !r.Allowed.Contains(name))
                        ev.Add(new Evidence(r.Id, EvidenceCategory.Reputation, r.Weight, r.Text, taskPath));

                Entity target = null;
                try { if (exe != null && File.Exists(exe)) target = ctx.Files.Inspect(exe, FileRole.PersistenceTarget); } catch { }
                bool untrustedTarget = target != null && !target.Trusted;
                if (nsMs && untrustedTarget)
                    ev.Add(new Evidence("TASK.MS_NAMESPACE_UNTRUSTED", EvidenceCategory.Masquerade, 25, "Task hides inside \\Microsoft\\... but runs a program that is not signed by Microsoft", taskPath));
                if (untrustedTarget && PathUtil.IsUserWritable(exe))
                {
                    if (hidden) ev.Add(new Evidence("TASK.HIDDEN", EvidenceCategory.Persistence, 8, "Hidden task (not shown in Task Scheduler by default)", taskPath));
                    if (string.Equals(runLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase)) ev.Add(new Evidence("TASK.HIGHEST", EvidenceCategory.Persistence, 8, "Runs with the highest privileges from a user-writable folder", taskPath));
                    if (repeat.Any(r => r > TimeSpan.Zero && r <= TimeSpan.FromMinutes(10))) ev.Add(new Evidence("TASK.REPEAT_SHORT", EvidenceCategory.Persistence, 8, "Re-runs every few minutes (respawn / watchdog pattern)", string.Join(",", repeat.Select(r => r.TotalMinutes + "min"))));
                    if (trigTypes.Contains("IdleTrigger") || idleOnly)
                        ev.Add(new Evidence("TASK.IDLE_TRIGGER", EvidenceCategory.Persistence, 10, "Starts only when the computer is idle - the moment a miner can use all of it without the owner noticing", taskPath));
                    if (sessionStates.Any(s => s.IndexOf("Lock", StringComparison.OrdinalIgnoreCase) >= 0 || s.IndexOf("Disconnect", StringComparison.OrdinalIgnoreCase) >= 0))
                        ev.Add(new Evidence("TASK.LOCK_TRIGGER", EvidenceCategory.Persistence, 8, "Starts when the screen is locked or the session is disconnected (nobody is watching)", string.Join(",", sessionStates)));
                    if (trigTypes.Distinct().Count() >= 2) ev.Add(new Evidence("TASK.MULTI_TRIGGER", EvidenceCategory.Persistence, 3, "Several different triggers (boot + logon + timer)", string.Join(",", trigTypes)));
                }
            };

            foreach (var ex in actions.Elements(Ns + "Exec"))
            {
                string cmd = Txt(ex, "Command"); string args = Txt(ex, "Arguments");
                if (string.IsNullOrWhiteSpace(cmd)) continue;
                string full = cmd.Trim() + (string.IsNullOrWhiteSpace(args) ? "" : " " + args.Trim());
                if (!cmd.Trim().StartsWith("\"") && cmd.Contains(" ") && !string.IsNullOrWhiteSpace(args)) full = "\"" + cmd.Trim() + "\" " + args.Trim();
                string id = "task:" + taskPath.ToLowerInvariant();
                var e = Persist.Evaluate(ctx, id, EntityKind.Task, name, taskPath, full, "Scheduled task", ev => addCommonSignals(ev, PathUtil.ResolveCommand(cmd)));
                if (e != null)
                {
                    e.Set("taskPath", taskPath); e.Set("enabled", enabled.ToString()); e.Set("hidden", hidden.ToString()); e.Set("runLevel", runLevel); e.Set("author", author);
                    e.Set("triggers", string.Join(",", trigTypes)); e.Set("xmlFile", file);
                }
            }

            // COM handler actions run a registered COM class instead of a command line (fileless persistence: no Exec entry to look for).
            // The class is usually registered machine-wide by an installer; a class that resolves only per-user (HKCU) is how COM hijacking is done without admin rights.
            foreach (var ch in actions.Elements(Ns + "ComHandler"))
            {
                string clsid = (Txt(ch, "ClassId") ?? "").Trim();
                string data = Txt(ch, "Data");
                if (clsid.Length == 0) continue;
                string hive, srv, impl = ResolveComClass(clsid, out hive, out srv);
                string full = (impl ?? clsid) + (string.IsNullOrWhiteSpace(data) ? "" : " " + data.Trim());
                string id = "task:" + taskPath.ToLowerInvariant() + ":com";
                var e = Persist.Evaluate(ctx, id, EntityKind.Task, name, taskPath, full, "Scheduled task (COM handler)", ev =>
                {
                    addCommonSignals(ev, impl != null ? PathUtil.ExtractExecutable(impl) ?? impl : null);
                    if (impl == null)
                    {
                        if (hidden || nsMs) ev.Add(new Evidence("TASK.COMHANDLER_UNRESOLVED", EvidenceCategory.Masquerade, 6, "COM handler task action points to a class id with no registered implementation", clsid));
                    }
                    else if (hive == "HKCU")
                        ev.Add(new Evidence("TASK.COMHANDLER_HKCU", EvidenceCategory.Masquerade, 20, "The COM class this task runs is registered per-user (HKCU) rather than machine-wide - a common way to hijack a COM handler without administrator rights", clsid));
                });
                if (e != null)
                {
                    e.Set("taskPath", taskPath); e.Set("enabled", enabled.ToString()); e.Set("hidden", hidden.ToString()); e.Set("runLevel", runLevel); e.Set("author", author);
                    e.Set("triggers", string.Join(",", trigTypes)); e.Set("xmlFile", file); e.Set("comClassId", clsid); e.Set("comImpl", impl);
                    // linked to its HKCU COM registration (if any) once every scanner has finished: see RiskEngine.AddDerivedLinksAndEvidence
                    if (hive == "HKCU") e.Set("comRegId", "reg:HKCU\\CLSID\\" + clsid + "\\" + srv);
                }
            }
        }

        /// <summary>A task definition that a normal XML reader refuses. The Task Scheduler may still accept it, so what it runs is pulled out with a text search instead of
        /// being ignored. A broken definition is also reported by itself.</summary>
        internal static void DamagedXml(ScanContext ctx, string file, string taskPath)
        {
            string text;
            try
            {
                var raw = File.ReadAllBytes(file);
                if (raw.Length == 0) return;
                Encoding enc = Encoding.UTF8;
                if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) enc = Encoding.Unicode;
                else if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF) enc = Encoding.BigEndianUnicode;
                else if (raw.Length >= 4 && raw[1] == 0 && raw[3] == 0) enc = Encoding.Unicode;
                text = enc.GetString(raw);
            }
            catch { return; }
            string name = Path.GetFileName(taskPath);
            var cmds = Regex.Matches(text, @"<(?:\w+:)?Command>\s*(?<c>.*?)\s*</(?:\w+:)?Command>", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            var argm = Regex.Matches(text, @"<(?:\w+:)?Arguments>\s*(?<a>.*?)\s*</(?:\w+:)?Arguments>", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            string args = argm.Count > 0 ? System.Net.WebUtility.HtmlDecode(argm[0].Groups["a"].Value) : "";
            string id = "task:" + taskPath.ToLowerInvariant();
            if (cmds.Count == 0)
            {
                var ne = ctx.GetOrAdd(id, EntityKind.Task, () => new Entity { Title = name, Location = taskPath });
                ne.Add(new Evidence("TASK.XML_UNPARSABLE", EvidenceCategory.Tamper, 6, "The task's definition is damaged and cannot be read as XML, so what it runs is unknown", taskPath));
                ne.Set("taskPath", taskPath); ne.Set("xmlFile", file);
                return;
            }
            string cmd = System.Net.WebUtility.HtmlDecode(cmds[0].Groups["c"].Value).Trim();
            string full = cmd + (string.IsNullOrWhiteSpace(args) ? "" : " " + args.Trim());
            if (!cmd.StartsWith("\"") && cmd.Contains(" ") && !string.IsNullOrWhiteSpace(args)) full = "\"" + cmd + "\" " + args.Trim();
            var e = Persist.Evaluate(ctx, id, EntityKind.Task, name, taskPath, full, "Scheduled task (damaged definition)", ev =>
                ev.Add(new Evidence("TASK.XML_UNPARSABLE", EvidenceCategory.Tamper, 12, "The task's definition is damaged: a normal XML reader cannot parse it, yet the Task Scheduler store holds it (what it runs was read as plain text)", taskPath)));
            if (e != null) { e.Set("taskPath", taskPath); e.Set("xmlFile", file); }
        }

        /// <summary>Resolves a COM class id to its implementation path, the way COM itself does: per-user registration (HKCU) first, then the
        /// machine-wide one (HKLM, including the 32-bit view) - the exact precedence a real process would use, which is also what makes an
        /// HKCU-only registration able to silently replace a machine-wide COM handler.</summary>
        internal static string ResolveComClass(string clsid, out string hive, out string srv)
        {
            hive = null; srv = null;
            foreach (var s in new[] { "InprocServer32", "LocalServer32" })
            {
                string v = ReadDefaultValue(Registry.CurrentUser, @"Software\Classes\CLSID\" + clsid + "\\" + s);
                if (!string.IsNullOrWhiteSpace(v)) { hive = "HKCU"; srv = s; return v; }
            }
            foreach (var baseKey in new[] { @"SOFTWARE\Classes\CLSID\", @"SOFTWARE\Classes\Wow6432Node\CLSID\" })
                foreach (var s in new[] { "InprocServer32", "LocalServer32" })
                {
                    string v = ReadDefaultValue(Registry.LocalMachine, baseKey + clsid + "\\" + s);
                    if (!string.IsNullOrWhiteSpace(v)) { hive = "HKLM"; srv = s; return v; }
                }
            return null;
        }

        static string ReadDefaultValue(RegistryKey root, string key)
        {
            try { using (var k = root.OpenSubKey(key)) return k == null ? null : Convert.ToString(k.GetValue(null)); }
            catch { return null; }
        }

        static void HiddenFromStore(ScanContext ctx, HashSet<string> knownXml)
        {
            // TaskCache\Tree lists every task; a Tree entry without an XML file is a technique to hide a task from schtasks / Task Scheduler
            try
            {
                using (var tree = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"))
                {
                    if (tree == null) return;
                    Walk(ctx, tree, "", knownXml);
                }
            }
            catch (Exception ex) { ctx.AddBlind("Scheduled tasks", "TaskCache: " + ex.Message); }
        }

        static void Walk(ScanContext ctx, RegistryKey key, string rel, HashSet<string> knownXml)
        {
            foreach (var sub in key.GetSubKeyNames())
            {
                using (var s = key.OpenSubKey(sub))
                {
                    if (s == null) continue;
                    string r = rel.Length == 0 ? sub : rel + "\\" + sub;
                    object id = s.GetValue("Id");
                    if (id != null)
                    {
                        string tp = "\\" + r;
                        // The documented way to hide a task from schtasks / Task Scheduler (HAFNIUM "Tarrask") is deleting the Security Descriptor value of its Tree key: the task still runs.
                        if (s.GetValue("SD") == null)
                        {
                            var e = ctx.GetOrAdd("task:" + tp.ToLowerInvariant(), EntityKind.Task, () => new Entity { Title = sub, Location = tp });
                            e.Add(new Evidence("TASK.SD_MISSING", EvidenceCategory.Tamper, 40, "The task's security descriptor was deleted from the Task Scheduler cache, so it is invisible in Task Scheduler while it can still run (technique used by real malware)", tp));
                            e.Set("taskPath", tp);
                        }
                        // A Tree entry whose XML file is gone is only a ghost left behind by clean-up / debloat tools; it cannot run, so it is not a threat by itself.
                        else if (!knownXml.Contains(r))
                        {
                            var e = ctx.GetOrAdd("task:" + tp.ToLowerInvariant(), EntityKind.Task, () => new Entity { Title = sub, Location = tp });
                            e.Add(new Evidence("TASK.XML_MISSING", EvidenceCategory.Tamper, 2, "Leftover entry in the Task Scheduler cache: the task's XML file no longer exists", tp));
                            e.Set("taskPath", tp);
                        }
                    }
                    else Walk(ctx, s, r, knownXml);
                }
            }
        }
    }

    // ==========================================================================================================
    //   WMI permanent event subscriptions (all consumer classes, filters and bindings)
    // ==========================================================================================================
    public static class WmiScanner
    {
        // Permanent event subscriptions are normally kept in root\subscription, but any namespace can hold them (root\default and root\cimv2 are used to stay out of sight)
        public static readonly string[] Namespaces = { @"root\subscription", @"root\default", @"root\cimv2" };

        public static void Run(ScanContext ctx)
        {
            foreach (var ns in Namespaces) RunNamespace(ctx, ns);
            try { Providers(ctx); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { ctx.AddBlind("WMI", "providers: " + ex.Message); }
        }

        static void RunNamespace(ScanContext ctx, string ns)
        {
            bool main = ns == Namespaces[0];
            string nsTag = main ? "" : ns + ":";
            try
            {
                var scope = new ManagementScope(@"\\.\" + ns);
                scope.Connect();
                var filters = new Dictionary<string, ManagementBaseObject>(StringComparer.OrdinalIgnoreCase);
                var consumers = new Dictionary<string, ManagementBaseObject>(StringComparer.OrdinalIgnoreCase);
                var boundConsumers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var boundFilters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var bindings = new List<KeyValuePair<string, string>>();

                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter")))
                    foreach (ManagementObject o in s.Get()) filters[Convert.ToString(o["Name"])] = o;
                var knownClasses = new[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer", "LogFileEventConsumer", "NTEventLogEventConsumer", "SMTPEventConsumer" };
                foreach (var cls in knownClasses)
                {
                    try
                    {
                        using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + cls)))
                            foreach (ManagementObject o in s.Get()) consumers[cls + ":" + Convert.ToString(o["Name"])] = o;
                    }
                    catch { }
                }
                // consumers of any other class (a provider of the attacker's own)
                try
                {
                    using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventConsumer")))
                        foreach (ManagementObject o in s.Get())
                        {
                            string c = Convert.ToString(o["__CLASS"]);
                            if (Array.IndexOf(knownClasses, c) >= 0) continue;
                            consumers[c + ":" + Convert.ToString(o["Name"])] = o;
                        }
                }
                catch { }
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
                    foreach (ManagementObject o in s.Get())
                    {
                        string f = RefName(Convert.ToString(o["Filter"])); string c = RefName(Convert.ToString(o["Consumer"])); string ccls = RefClass(Convert.ToString(o["Consumer"]));
                        bindings.Add(new KeyValuePair<string, string>(f, ccls + ":" + c));
                        boundFilters.Add(f); boundConsumers.Add(ccls + ":" + c);
                    }
                ctx.Stats.WmiObjects += filters.Count + consumers.Count + bindings.Count;

                foreach (var kv in consumers)
                {
                    string cls = kv.Key.Substring(0, kv.Key.IndexOf(':')); string cname = kv.Key.Substring(cls.Length + 1);
                    var o = kv.Value;
                    string filterName = bindings.Where(b => b.Value.Equals(kv.Key, StringComparison.OrdinalIgnoreCase)).Select(b => b.Key).FirstOrDefault();
                    string query = null; if (filterName != null && filters.ContainsKey(filterName)) query = Convert.ToString(filters[filterName]["Query"]);
                    // the default Windows subscription (Service Control Manager event log) is not a finding
                    if (cls == "NTEventLogEventConsumer" && cname == "SCM Event Log Consumer" && filterName == "SCM Event Log Filter") continue;

                    string id = "wmi:" + nsTag + cls + ":" + cname;
                    string cmd = null, script = null, exePath = null;
                    if (cls == "CommandLineEventConsumer") { cmd = Convert.ToString(o["CommandLineTemplate"]); exePath = Convert.ToString(o["ExecutablePath"]); }
                    if (cls == "ActiveScriptEventConsumer") script = Convert.ToString(o["ScriptText"]) ?? Convert.ToString(o["ScriptFileName"]);
                    string commandForEval = cmd ?? (cls == "ActiveScriptEventConsumer" ? Convert.ToString(o["ScriptFileName"]) : null) ?? "";
                    // ExecutablePath is what actually starts; the template then only holds the arguments
                    if (!string.IsNullOrWhiteSpace(exePath)) commandForEval = (exePath.Contains(" ") && !exePath.StartsWith("\"") ? "\"" + exePath + "\"" : exePath) + " " + commandForEval;
                    var e = Persist.Evaluate(ctx, id, EntityKind.Wmi, cname, "WMI " + cls + ": " + cname, commandForEval, "WMI permanent subscription", ev =>
                    {
                        bool bound = boundConsumers.Contains(kv.Key);
                        if (cls == "CommandLineEventConsumer")
                            ev.Add(new Evidence("WMI.CMDLINE_CONSUMER", EvidenceCategory.Persistence, bound ? 14 : 6, "Custom WMI event subscription that starts a command (fileless persistence mechanism)", Text.Trunc(cmd, 200)));
                        else if (cls == "ActiveScriptEventConsumer")
                        {
                            ev.Add(new Evidence("WMI.SCRIPT_CONSUMER", EvidenceCategory.Persistence, bound ? 30 : 12, "WMI event subscription that executes a script (classic fileless malware persistence)", Text.Trunc(script, 300)));
                            if (!string.IsNullOrEmpty(script))
                                foreach (var r in ctx.Rules.CmdRules)
                                    if (r.Rx.IsMatch(script)) ev.Add(new Evidence("WMI.SCRIPT." + r.Id.Substring(4), FileIntel.ParseCat(r.Category), r.Weight, "WMI script contains: " + r.Text, Text.Trunc(script, 200), r.Definitive));
                        }
                        else if (cls == "LogFileEventConsumer" || cls == "SMTPEventConsumer")
                            ev.Add(new Evidence("WMI.OTHER_CONSUMER", EvidenceCategory.Persistence, 8, "Unusual WMI consumer (" + cls + ")", cname));
                        else if (cls == "NTEventLogEventConsumer")
                            ev.Add(new Evidence("WMI.EVENTLOG_CONSUMER", EvidenceCategory.Persistence, 2, "Additional WMI event-log consumer", cname));
                        else
                            ev.Add(new Evidence("WMI.OTHER_CONSUMER", EvidenceCategory.Persistence, 14, "A WMI consumer of a non-standard class (" + cls + ") is registered: a provider that is not part of Windows is doing something on WMI events", cname));
                        if (!main) ev.Add(new Evidence("WMI.HIDDEN_NAMESPACE", EvidenceCategory.Persistence, 12, "The subscription is kept in " + ns + " instead of root\\subscription, where tools look for it", ns));
                        if (!bound) ev.Add(new Evidence("WMI.UNBOUND", EvidenceCategory.Persistence, 2, "Consumer exists without a binding (left-over)", cname));
                    });
                    if (e != null) { e.Set("wmiClass", cls); e.Set("consumer", cname); e.Set("filter", filterName); e.Set("query", query); e.Set("command", cmd); e.Set("script", Text.Trunc(script, 2000)); e.Set("wmiNamespace", ns); }
                }
                // filters bound to consumers we could not read, or orphan bindings
                foreach (var b in bindings)
                    if (!consumers.ContainsKey(b.Value) && !b.Value.StartsWith("NTEventLogEventConsumer:SCM"))
                    {
                        var e = ctx.GetOrAdd("wmi:binding:" + nsTag + b.Key + ":" + b.Value, EntityKind.Wmi, () => new Entity { Title = "binding " + b.Key, Location = "WMI binding " + b.Key + " -> " + b.Value });
                        e.Add(new Evidence("WMI.ORPHAN_BINDING", EvidenceCategory.Persistence, 5, "WMI binding points to a consumer that cannot be read", b.Value));
                    }
            }
            catch (UnauthorizedAccessException) { ctx.Denied("WMI", ns); }
            catch (Exception ex) { if (main) ctx.AddBlind("WMI", ns + ": " + ex.Message); }       // the other namespaces may simply not be reachable: only the main one is worth a blind-spot note
        }

        /// <summary>WMI providers are DLLs that WMI loads on demand; a provider that is not a signed Windows component is either third-party software or a way to run code.</summary>
        static void Providers(ScanContext ctx)
        {
            foreach (var ns in Namespaces)
            {
                ctx.ThrowIfCancelled();
                try
                {
                    var scope = new ManagementScope(@"\\.\" + ns); scope.Connect();
                    using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name, CLSID FROM __Win32Provider")))
                        foreach (ManagementObject o in s.Get())
                        {
                            string clsid = Convert.ToString(o["CLSID"]), pname = Convert.ToString(o["Name"]);
                            if (string.IsNullOrWhiteSpace(clsid)) continue;
                            string hive, srv, impl = TaskScanner.ResolveComClass(clsid.Trim(), out hive, out srv);
                            if (string.IsNullOrWhiteSpace(impl)) continue;
                            string exe = PathUtil.ExtractExecutable(impl);
                            if (exe == null || !File.Exists(exe)) continue;
                            var f = ctx.Files.Inspect(exe, FileRole.PersistenceTarget);
                            if (f == null || f.Trusted) continue;
                            var e = Persist.Evaluate(ctx, "wmiprov:" + ns + ":" + pname, EntityKind.Wmi, "WMI provider " + pname, "WMI provider " + pname + " (" + ns + ")", impl, "WMI provider", ev =>
                                ev.Add(new Evidence("WMI.PROVIDER_UNTRUSTED", EvidenceCategory.Persistence, 18, "A WMI provider DLL (" + pname + ") is loaded by WMI but is not signed by a trusted publisher", exe)));
                            if (e != null) e.Set("wmiProvider", pname);
                        }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }

        static string RefName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int i = path.IndexOf("Name=\"", StringComparison.OrdinalIgnoreCase);
            if (i < 0) return path;
            string r = path.Substring(i + 6); int q = r.IndexOf('"');
            return q >= 0 ? r.Substring(0, q).Replace("\\\\", "\\") : r;
        }
        static string RefClass(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int i = path.LastIndexOf(':'); int j = path.IndexOf('.', Math.Max(0, i));
            return j > i ? path.Substring(i + 1, j - i - 1) : path;
        }
    }
}
