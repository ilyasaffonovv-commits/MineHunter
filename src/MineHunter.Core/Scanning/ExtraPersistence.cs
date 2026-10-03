using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Less common places a program can be made to start by itself: Group Policy and logon scripts, Explorer shell hooks, PowerShell profiles,
    /// service recovery commands, and executables that shadow system programs through the PATH.</summary>
    public static class ExtraPersistenceScanner
    {
        public static void Run(ScanContext ctx)
        {
            Safe(ctx, "Group Policy scripts", () => GroupPolicyScripts(ctx));
            Safe(ctx, "logon script", () => LogonScript(ctx));
            Safe(ctx, "Explorer shell hooks", () => ShellHooks(ctx));
            Safe(ctx, "PowerShell profiles", () => PowerShellProfiles(ctx));
            Safe(ctx, "service recovery commands", () => ServiceFailureCommands(ctx, Registry.LocalMachine));
            Safe(ctx, "PATH", () => PathShadowing(ctx));
        }

        static void Safe(ScanContext ctx, string what, Action a)
        {
            try { a(); }
            catch (OperationCanceledException) { throw; }
            catch (UnauthorizedAccessException) { ctx.Denied("Autostart", what); }
            catch (Exception ex) { ctx.AddBlind("Autostart", what + ": " + ex.Message); }
        }

        // ------------------------------------------------------------------------------------------------ Group Policy scripts (startup / shutdown / logon / logoff)
        static void GroupPolicyScripts(ScanContext ctx)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                string hn = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                foreach (var root in new[] { @"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts", @"Software\Policies\Microsoft\Windows\System\Scripts" })
                    using (var k = hive.OpenSubKey(root))
                        if (k != null) WalkScripts(ctx, k, hn, root, 0);
            }
        }

        internal static void WalkScripts(ScanContext ctx, RegistryKey key, string hn, string path, int depth)
        {
            if (depth > 4) return;
            object script = key.GetValue("Script");
            if (script != null && !string.IsNullOrWhiteSpace(Convert.ToString(script)))
            {
                string s = Convert.ToString(script), prm = Convert.ToString(key.GetValue("Parameters"));
                string cmd = s + (string.IsNullOrWhiteSpace(prm) ? "" : " " + prm);
                var e = Persist.Evaluate(ctx, "gpscript:" + hn + "\\" + path, EntityKind.Registry, "Group Policy script " + path.Substring(path.LastIndexOf('\\') + 1), hn + "\\" + path, cmd, "Group Policy script", ev =>
                    ev.Add(new Evidence("REG.GP_SCRIPT", EvidenceCategory.Persistence, 6, "A Group Policy startup/logon script runs this at every boot or logon (rare on a home PC)", Text.Trunc(cmd, 200))));
                if (e != null) { e.Set("hive", hn); e.Set("key", path); e.Set("value", "Script"); e.Set("data", s); }
            }
            foreach (var sub in key.GetSubKeyNames())
                using (var sk = key.OpenSubKey(sub))
                    if (sk != null) WalkScripts(ctx, sk, hn, path + "\\" + sub, depth + 1);
        }

        // ------------------------------------------------------------------------------------------------ HKCU\Environment\UserInitMprLogonScript
        static void LogonScript(ScanContext ctx)
        {
            using (var k = Registry.CurrentUser.OpenSubKey("Environment"))
            {
                string v = k == null ? null : Convert.ToString(k.GetValue("UserInitMprLogonScript"));
                if (string.IsNullOrWhiteSpace(v)) return;
                var e = Persist.Evaluate(ctx, "reg:HKCU\\Environment\\UserInitMprLogonScript", EntityKind.Registry, "Logon script (UserInitMprLogonScript)", @"HKCU\Environment\UserInitMprLogonScript", v, "logon script", ev =>
                    ev.Add(new Evidence("REG.LOGON_SCRIPT", EvidenceCategory.Persistence, 22, "A per-user logon script is set (UserInitMprLogonScript runs at every logon and is a known persistence trick)", v)));
                if (e != null) { e.Set("hive", "HKCU"); e.Set("key", "Environment"); e.Set("value", "UserInitMprLogonScript"); e.Set("data", v); }
            }
        }

        // ------------------------------------------------------------------------------------------------ Explorer shell hooks and browser helper objects (COM DLLs loaded into Explorer)
        static void ShellHooks(ScanContext ctx)
        {
            var lists = new[]
            {
                new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", "name" },
                new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "data" },
                new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler", "name" },
                new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "subkey" },
                new[] { @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", "name" },
                new[] { @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "subkey" },
            };
            foreach (var l in lists)
            {
                using (var k = Registry.LocalMachine.OpenSubKey(l[0]))
                {
                    if (k == null) continue;
                    var clsids = new List<KeyValuePair<string, string>>();       // clsid, value name (for removal)
                    if (l[1] == "subkey") foreach (var s in k.GetSubKeyNames()) clsids.Add(new KeyValuePair<string, string>(s, null));
                    else foreach (var vn in k.GetValueNames())
                        clsids.Add(new KeyValuePair<string, string>(l[1] == "name" ? vn : Convert.ToString(k.GetValue(vn)), vn));
                    foreach (var c in clsids)
                    {
                        string clsid = (c.Key ?? "").Trim();
                        if (!clsid.StartsWith("{")) continue;
                        string hive, srv, impl = TaskScanner.ResolveComClass(clsid, out hive, out srv);
                        if (string.IsNullOrWhiteSpace(impl)) continue;
                        string id = "shellhook:" + l[0] + "\\" + clsid;
                        var e = Persist.Evaluate(ctx, id, EntityKind.Registry, "Explorer hook " + clsid, @"HKLM\" + l[0] + "\\" + clsid, impl, "Explorer shell hook / helper object");
                        if (e != null && c.Value != null) { e.Set("hive", "HKLM"); e.Set("key", l[0]); e.Set("value", c.Value); e.Set("data", clsid); }
                    }
                }
            }
        }

        // ------------------------------------------------------------------------------------------------ PowerShell profile scripts (run each time PowerShell starts)
        static void PowerShellProfiles(ScanContext ctx)
        {
            var paths = new List<string>
            {
                Path.Combine(PathUtil.System32, @"WindowsPowerShell\v1.0\profile.ps1"), Path.Combine(PathUtil.System32, @"WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"),
                Path.Combine(PathUtil.ProgramFiles, @"PowerShell\7\profile.ps1"), Path.Combine(PathUtil.ProgramFiles, @"PowerShell\7\Microsoft.PowerShell_profile.ps1")
            };
            foreach (var up in PathUtil.UserProfiles())
                foreach (var docs in new[] { "Documents", @"OneDrive\Documents" })
                    foreach (var dir in new[] { @"WindowsPowerShell", "PowerShell" })
                        foreach (var file in new[] { "profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.VSCode_profile.ps1" })
                            paths.Add(Path.Combine(up, docs, dir, file));
            foreach (var p in paths.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                ctx.ThrowIfCancelled();
                if (!File.Exists(p)) continue;
                ctx.Stats.PersistenceItems++;
                var e = ctx.Files.Inspect(p, FileRole.PersistenceTarget);
                // a profile is perfectly normal on a developer's machine: it only matters when the script itself already looks bad
                if (e != null && e.Evidence.Any(x => x.Weight > 0))
                    e.Add(new Evidence("PERSIST.PS_PROFILE", EvidenceCategory.Persistence, 12, "This PowerShell profile runs automatically every time PowerShell starts", p));
            }
        }

        // ------------------------------------------------------------------------------------------------ service recovery: "run this program when the service fails"
        internal static void ServiceFailureCommands(ScanContext ctx, RegistryKey hklm)
        {
            using (var k = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            {
                if (k == null) return;
                foreach (var name in k.GetSubKeyNames())
                {
                    ctx.ThrowIfCancelled();
                    using (var s = k.OpenSubKey(name))
                    {
                        string fc = s == null ? null : Convert.ToString(s.GetValue("FailureCommand"));
                        if (string.IsNullOrWhiteSpace(fc)) continue;
                        // vendors (NVIDIA, Microsoft ...) use recovery commands for their own services: only a command that runs something untrusted matters
                        string fexe = PathUtil.ExtractExecutable(Environment.ExpandEnvironmentVariables(fc));
                        if (!string.IsNullOrEmpty(fexe) && File.Exists(fexe)) { var fe = ctx.Files.Inspect(fexe, FileRole.PersistenceTarget); if (fe != null && fe.Trusted) continue; }
                        var e = Persist.Evaluate(ctx, "svcfail:" + name, EntityKind.Registry, "Service recovery command: " + name, @"HKLM\SYSTEM\CurrentControlSet\Services\" + name + @"\FailureCommand", fc, "service recovery command", ev =>
                            ev.Add(new Evidence("SVC.FAILURE_COMMAND", EvidenceCategory.Persistence, !string.IsNullOrEmpty(fexe) && PathUtil.IsUserWritable(fexe) ? 26 : 14, "A service is set to run a program whenever it fails (a stealthy way to restart a payload that was killed)", Text.Trunc(fc, 200))));
                        if (e != null) { e.Set("hive", "HKLM"); e.Set("key", @"SYSTEM\CurrentControlSet\Services\" + name); e.Set("value", "FailureCommand"); e.Set("data", fc); }
                    }
                }
            }
        }

        // ------------------------------------------------------------------------------------------------ PATH: a user-writable folder holding a program named like a Windows one
        static readonly string[] CommonTools =
        {
            "cmd.exe", "powershell.exe", "net.exe", "net1.exe", "netsh.exe", "ping.exe", "curl.exe", "tasklist.exe", "taskkill.exe", "schtasks.exe", "reg.exe", "wmic.exe", "whoami.exe",
            "ipconfig.exe", "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "sc.exe", "bitsadmin.exe", "msiexec.exe", "conhost.exe"
        };

        static void PathShadowing(ScanContext ctx)
        {
            var entries = new List<string>();
            foreach (var pair in new object[][] { new object[] { Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment" }, new object[] { Registry.CurrentUser, "Environment" } })
                using (var k = ((RegistryKey)pair[0]).OpenSubKey((string)pair[1]))
                {
                    string v = k == null ? null : Convert.ToString(k.GetValue("Path", "", RegistryValueOptions.DoNotExpandEnvironmentNames));
                    if (!string.IsNullOrWhiteSpace(v)) entries.AddRange(v.Split(';'));
                }
            var dirs = entries.Select(x => Environment.ExpandEnvironmentVariables((x ?? "").Trim().Trim('"')).TrimEnd('\\')).Where(x => x.Length > 3).ToList();
            Shadowing(ctx, dirs);
        }

        /// <summary>The PATH check itself, on an explicit list of folders in search order.</summary>
        internal static void Shadowing(ScanContext ctx, List<string> dirs)
        {
            int sysIdx = dirs.FindIndex(d => string.Equals(d, PathUtil.System32, StringComparison.OrdinalIgnoreCase));
            var names = new HashSet<string>(ctx.Rules.SystemBinaries.Concat(CommonTools), StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < dirs.Count; i++)
            {
                ctx.ThrowIfCancelled();
                string d = dirs[i];
                if (!Directory.Exists(d) || PathUtil.IsUnder(d, PathUtil.WinDir) || !PathUtil.IsUserWritable(Path.Combine(d, "x"))) continue;
                string[] files;
                try { files = Directory.GetFiles(d); } catch { continue; }
                foreach (var f in files)
                {
                    string n = Path.GetFileName(f);
                    if (!names.Contains(n)) continue;
                    var e = ctx.Files.Inspect(f, FileRole.PersistenceTarget);
                    if (e == null || e.Trusted) continue;
                    bool beforeSystem = sysIdx >= 0 && i < sysIdx;
                    e.Add(new Evidence("PATH.SHADOWS_SYSTEM_BINARY", EvidenceCategory.Masquerade, beforeSystem ? 35 : 20,
                        beforeSystem ? "A program named like a Windows tool sits in a folder that is searched BEFORE System32 and that any user can write to: starting \"" + n + "\" runs this file instead of the real one"
                                     : "A program named like a Windows tool sits in a folder on the PATH that any user can write to", f));
                }
            }
        }
    }
}
