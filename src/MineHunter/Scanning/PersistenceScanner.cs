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
                bool isExe = PathUtil.IsExecutableExt(p) || PathUtil.IsScriptExt(p) || p.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
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
            // other users' Run keys (needs the hives to be loaded; loaded ones appear under HKEY_USERS)
            try
            {
                string mySid = null; try { mySid = System.Security.Principal.WindowsIdentity.GetCurrent().User.Value; } catch { }
                foreach (var sid in Registry.Users.GetSubKeyNames())
                {
                    if (sid.EndsWith("_Classes") || sid == ".DEFAULT" || sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20") continue;
                    if (mySid != null && string.Equals(sid, mySid, StringComparison.OrdinalIgnoreCase)) continue;       // HKCU is this same hive: do not report every entry twice
                    using (var u = Registry.Users.OpenSubKey(sid))
                        if (u != null) foreach (var k in RunKeys.Take(5)) ScanRunKey(ctx, u, "HKU\\" + sid, k);
                }
            }
            catch (Exception ex) { ctx.AddBlind("Registry", "HKEY_USERS enumeration: " + ex.Message); }

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

        static void ScanRunKey(ScanContext ctx, RegistryKey hive, string hiveName, string sub)
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
                    string command = f; string extraNote = null;
                    if (f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        string target, args;
                        if (ResolveShortcut(f, out target, out args)) command = (target ?? "") + (string.IsNullOrEmpty(args) ? "" : " " + args);
                        else extraNote = "shortcut could not be read";
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

        static void One(ScanContext ctx, RegistryKey root, string name, Dictionary<string, string> states)
        {
            using (var k = root.OpenSubKey(name))
            {
                if (k == null) return;
                string image = Convert.ToString(k.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                int type = 0, start = 3;
                try { type = Convert.ToInt32(k.GetValue("Type", 0)); } catch { }
                try { start = Convert.ToInt32(k.GetValue("Start", 3)); } catch { }
                string dllParam = null;
                using (var p = k.OpenSubKey("Parameters")) if (p != null) dllParam = Convert.ToString(p.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                if (string.IsNullOrWhiteSpace(image) && string.IsNullOrWhiteSpace(dllParam)) return;
                ctx.Stats.ServicesScanned++;

                bool isDriver = type == 1 || type == 2 || type == 8;
                string cmd = image;
                if (isDriver && !string.IsNullOrEmpty(image) && !image.Contains(":") && !image.StartsWith("\\"))
                    cmd = PathUtil.WinDir + "\\" + image.TrimStart('\\');
                else if (isDriver && !string.IsNullOrEmpty(image) && image.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                    cmd = image;
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

        static void One(ScanContext ctx, string file, string taskPath)
        {
            XDocument doc;
            try { doc = XDocument.Load(file); } catch { return; }
            var root = doc.Root; if (root == null) return;
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
            if (triggers != null)
                foreach (var t in triggers.Elements())
                {
                    trigTypes.Add(t.Name.LocalName);
                    var rep = t.Element(Ns + "Repetition");
                    string iv = Txt(rep, "Interval");
                    if (!string.IsNullOrEmpty(iv)) { try { repeat.Add(System.Xml.XmlConvert.ToTimeSpan(iv)); } catch { } }
                }

            foreach (var ex in actions.Elements(Ns + "Exec"))
            {
                string cmd = Txt(ex, "Command"); string args = Txt(ex, "Arguments");
                if (string.IsNullOrWhiteSpace(cmd)) continue;
                string full = cmd.Trim() + (string.IsNullOrWhiteSpace(args) ? "" : " " + args.Trim());
                if (!cmd.Trim().StartsWith("\"") && cmd.Contains(" ") && !string.IsNullOrWhiteSpace(args)) full = "\"" + cmd.Trim() + "\" " + args.Trim();
                string id = "task:" + taskPath.ToLowerInvariant();
                var e = Persist.Evaluate(ctx, id, EntityKind.Task, name, taskPath, full, "Scheduled task", ev =>
                {
                    // name-based knowledge
                    foreach (var r in ctx.Rules.TaskFolderRules)
                        if (folder.Equals(r.Folder, StringComparison.OrdinalIgnoreCase) && !r.Allowed.Contains(name))
                            ev.Add(new Evidence(r.Id, EvidenceCategory.Reputation, r.Weight, r.Text, taskPath));

                    bool nsMs = taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
                    string exe = PathUtil.ResolveCommand(cmd);
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
                        if (trigTypes.Distinct().Count() >= 2) ev.Add(new Evidence("TASK.MULTI_TRIGGER", EvidenceCategory.Persistence, 3, "Several different triggers (boot + logon + timer)", string.Join(",", trigTypes)));
                    }
                });
                if (e != null)
                {
                    e.Set("taskPath", taskPath); e.Set("enabled", enabled.ToString()); e.Set("hidden", hidden.ToString()); e.Set("runLevel", runLevel); e.Set("author", author);
                    e.Set("triggers", string.Join(",", trigTypes)); e.Set("xmlFile", file);
                }
            }
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
        public static void Run(ScanContext ctx)
        {
            try
            {
                var scope = new ManagementScope(@"\\.\root\subscription");
                scope.Connect();
                var filters = new Dictionary<string, ManagementBaseObject>(StringComparer.OrdinalIgnoreCase);
                var consumers = new Dictionary<string, ManagementBaseObject>(StringComparer.OrdinalIgnoreCase);
                var boundConsumers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var boundFilters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var bindings = new List<KeyValuePair<string, string>>();

                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter")))
                    foreach (ManagementObject o in s.Get()) filters[Convert.ToString(o["Name"])] = o;
                foreach (var cls in new[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer", "LogFileEventConsumer", "NTEventLogEventConsumer", "SMTPEventConsumer" })
                {
                    try
                    {
                        using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + cls)))
                            foreach (ManagementObject o in s.Get()) consumers[cls + ":" + Convert.ToString(o["Name"])] = o;
                    }
                    catch { }
                }
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
                    foreach (ManagementObject o in s.Get())
                    {
                        string f = RefName(Convert.ToString(o["Filter"])); string c = RefName(Convert.ToString(o["Consumer"])); string ccls = RefClass(Convert.ToString(o["Consumer"]));
                        bindings.Add(new KeyValuePair<string, string>(f, ccls + ":" + c));
                        boundFilters.Add(f); boundConsumers.Add(ccls + ":" + c);
                    }
                ctx.Stats.WmiObjects = filters.Count + consumers.Count + bindings.Count;

                foreach (var kv in consumers)
                {
                    string cls = kv.Key.Substring(0, kv.Key.IndexOf(':')); string cname = kv.Key.Substring(cls.Length + 1);
                    var o = kv.Value;
                    string filterName = bindings.Where(b => b.Value.Equals(kv.Key, StringComparison.OrdinalIgnoreCase)).Select(b => b.Key).FirstOrDefault();
                    string query = null; if (filterName != null && filters.ContainsKey(filterName)) query = Convert.ToString(filters[filterName]["Query"]);
                    // the default Windows subscription (Service Control Manager event log) is not a finding
                    if (cls == "NTEventLogEventConsumer" && cname == "SCM Event Log Consumer" && filterName == "SCM Event Log Filter") continue;

                    string id = "wmi:" + cls + ":" + cname;
                    string cmd = null, script = null;
                    if (cls == "CommandLineEventConsumer") cmd = Convert.ToString(o["CommandLineTemplate"]);
                    if (cls == "ActiveScriptEventConsumer") script = Convert.ToString(o["ScriptText"]) ?? Convert.ToString(o["ScriptFileName"]);
                    string commandForEval = cmd ?? (cls == "ActiveScriptEventConsumer" ? Convert.ToString(o["ScriptFileName"]) : null) ?? "";
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
                        if (!bound) ev.Add(new Evidence("WMI.UNBOUND", EvidenceCategory.Persistence, 2, "Consumer exists without a binding (left-over)", cname));
                    });
                    if (e != null) { e.Set("wmiClass", cls); e.Set("consumer", cname); e.Set("filter", filterName); e.Set("query", query); e.Set("command", cmd); e.Set("script", Text.Trunc(script, 2000)); }
                }
                // filters bound to consumers we could not read, or orphan bindings
                foreach (var b in bindings)
                    if (!consumers.ContainsKey(b.Value) && !b.Value.StartsWith("NTEventLogEventConsumer:SCM"))
                    {
                        var e = ctx.GetOrAdd("wmi:binding:" + b.Key + ":" + b.Value, EntityKind.Wmi, () => new Entity { Title = "binding " + b.Key, Location = "WMI binding " + b.Key + " -> " + b.Value });
                        e.Add(new Evidence("WMI.ORPHAN_BINDING", EvidenceCategory.Persistence, 5, "WMI binding points to a consumer that cannot be read", b.Value));
                    }
            }
            catch (UnauthorizedAccessException) { ctx.Denied("WMI", "root\\subscription"); }
            catch (Exception ex) { ctx.AddBlind("WMI", "root\\subscription: " + ex.Message); }
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
