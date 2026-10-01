using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Registry autostart points that are less well known than the Run keys: the old Windows Load/Run values, the cmd.exe AutoRun command, RunOnceEx,
    /// Session Manager and Setup commands, RDP start-up programs, KnownDLLs, IFEO verifier DLLs, installed compatibility databases, per-user overrides of how
    /// Windows opens files (UAC-bypass and handler hijacks) and COM redirections. The same per-user places are read for every user whose registry is loaded.
    /// Everything goes through <see cref="Persist.Evaluate"/>, so an entry that starts a trusted program is not reported.</summary>
    public static class MorePersistenceScanner
    {
        enum Mode { Values, SubKeyValues }

        sealed class Spot
        {
            public string Hives, Key, Mech, Rule, Text; public Mode Mode; public string[] Names; public int Weight;
            public Func<string, string> Command; public Func<string, bool> Skip;
        }

        static Spot S(string hives, string key, Mode mode, string[] names, string mech, string rule = null, int weight = 0, string text = null, Func<string, string> cmd = null, Func<string, bool> skip = null)
        {
            return new Spot { Hives = hives, Key = key, Mode = mode, Names = names, Mech = mech, Rule = rule, Weight = weight, Text = text, Command = cmd, Skip = skip };
        }

        static readonly Spot[] Spots =
        {
            S("MU", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", Mode.Values, new[] { "Load", "Run" }, "Windows Load/Run value", "REG.WINDOWS_LOAD_RUN", 20,
              "The Load/Run value of the Windows key starts a program at every logon (an old trick that ordinary software hardly uses)"),
            S("M", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows", Mode.Values, new[] { "Load", "Run" }, "Windows Load/Run value (32-bit)", "REG.WINDOWS_LOAD_RUN", 20,
              "The Load/Run value of the Windows key starts a program at every logon (an old trick that ordinary software hardly uses)"),
            S("MU", @"SOFTWARE\Microsoft\Command Processor", Mode.Values, new[] { "AutoRun" }, "cmd.exe AutoRun", "REG.CMD_AUTORUN", 25,
              "This command runs every time any Command Prompt window or batch file starts (cmd.exe AutoRun)"),
            S("M", @"SOFTWARE\WOW6432Node\Microsoft\Command Processor", Mode.Values, new[] { "AutoRun" }, "cmd.exe AutoRun (32-bit)", "REG.CMD_AUTORUN", 25,
              "This command runs every time any Command Prompt window or batch file starts (cmd.exe AutoRun)"),
            S("MU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Run", Mode.Values, null, "Explorer Run policy value"),
            S("M", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", Mode.Values, null, "Explorer Run policy value (32-bit)"),
            S("MU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", Mode.SubKeyValues, null, "RunOnceEx entry"),
            S("M", @"SYSTEM\CurrentControlSet\Control\Session Manager", Mode.Values, new[] { "SetupExecute", "PlatformExecute", "S0InitialCommand" }, "Session Manager boot command", "REG.BOOT_EXECUTE", 30,
              "A Session Manager command runs before Windows fully starts", skip: d => System.Text.RegularExpressions.Regex.IsMatch(d, @"^autocheck\s+autochk\s+\*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)),
            S("M", @"SYSTEM\Setup", Mode.Values, new[] { "CmdLine" }, "Windows Setup command line", "REG.SETUP_CMDLINE", 30,
              "Windows Setup is told to run this command at the next start (a stealthy way to run a program with SYSTEM rights before logon)"),
            S("M", @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", Mode.Values, new[] { "InitialProgram" }, "RDP initial program", "REG.RDP_INITIAL_PROGRAM", 25,
              "Every Remote Desktop session starts this program instead of the normal desktop shell"),
            S("M", @"SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd", Mode.Values, new[] { "StartupPrograms" }, "RDP start-up programs", "REG.RDP_INITIAL_PROGRAM", 25,
              "A program is started with every Remote Desktop session", skip: d => d.Trim().Equals("rdpclip", StringComparison.OrdinalIgnoreCase)),
            S("MU", @"SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop", Mode.Values, new[] { "SCRNSAVE.EXE" }, "screensaver policy"),
            S("M", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB", Mode.SubKeyValues, new[] { "DatabasePath" }, "installed compatibility database", "REG.APPCOMPAT_SDB", 28,
              "A custom application-compatibility database (shim) is installed. Shims can put code into other programs"),
            S("M", @"SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors", Mode.SubKeyValues, new[] { "Driver" }, "print processor DLL",
              cmd: d => Path.IsPathRooted(d) ? d : Path.Combine(PathUtil.System32, @"spool\prtprocs\x64", d)),
        };

        // classes whose per-user override is how UAC is bypassed or how every file of a kind is hijacked
        static readonly HashSet<string> SensitiveClasses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "ms-settings", "mscfile", "exefile", "batfile", "cmdfile", "comfile", "Folder", "*", "AllFilesystemObjects", "Directory", "Drive", "CLSID_ShellLink", "lnkfile", "htmlfile", "txtfile", "ms-windows-store" };

        public static void Run(ScanContext ctx)
        {
            var hives = UserHives.Enumerate(ctx, ctx.Options.OtherUserHives);
            try { RunOn(ctx, Registry.LocalMachine, hives.Select(h => new KeyValuePair<string, RegistryKey>(h.Label, h.Root)).ToList()); }
            finally { foreach (var h in hives) if (h.Label.StartsWith("HKU\\")) { try { h.Root.Dispose(); } catch { } } }       // offline mounts are released by the engine
        }

        static void Safe(ScanContext ctx, string what, Action a)
        {
            try { a(); }
            catch (OperationCanceledException) { throw; }
            catch (UnauthorizedAccessException) { ctx.Denied("Autostart", what); }
            catch (Exception ex) { ctx.AddBlind("Autostart", what + ": " + ex.Message); }
        }

        /// <summary>The scan itself, on explicit registry roots (the self test points it at a scratch hive instead of the real one).</summary>
        internal static void RunOn(ScanContext ctx, RegistryKey hklm, IList<KeyValuePair<string, RegistryKey>> users)
        {
            foreach (var sp in Spots)
            {
                ctx.ThrowIfCancelled();
                var spot = sp;
                if (spot.Hives.IndexOf('M') >= 0) Safe(ctx, "HKLM\\" + spot.Key, () => ScanSpot(ctx, hklm, "HKLM", spot));
                if (spot.Hives.IndexOf('U') >= 0) foreach (var u in users) { var uu = u; Safe(ctx, uu.Key + "\\" + spot.Key, () => ScanSpot(ctx, uu.Value, uu.Key, spot)); }
            }
            Safe(ctx, "KnownDLLs", () => KnownDlls(ctx, hklm));
            Safe(ctx, "IFEO verifier DLLs", () => IfeoVerifier(ctx, hklm));
            foreach (var u in users)
            {
                var uu = u;
                Safe(ctx, uu.Key + " file-type handlers", () => HandlerOverrides(ctx, uu.Key, uu.Value));
                Safe(ctx, uu.Key + " COM redirections", () => ComExtras(ctx, uu.Key, uu.Value));
            }
        }

        // ------------------------------------------------------------------------------------------------ table-driven values
        static void ScanSpot(ScanContext ctx, RegistryKey root, string hn, Spot sp)
        {
            using (var k = root.OpenSubKey(sp.Key))
            {
                if (k == null) return;
                if (sp.Mode == Mode.Values) ReadValues(ctx, k, hn, sp.Key, sp);
                else
                    foreach (var sub in k.GetSubKeyNames())
                        using (var s = k.OpenSubKey(sub))
                            if (s != null) ReadValues(ctx, s, hn, sp.Key + "\\" + sub, sp);
            }
        }

        static void ReadValues(ScanContext ctx, RegistryKey k, string hn, string keyPath, Spot sp)
        {
            foreach (var vn in sp.Names ?? k.GetValueNames())
            {
                object raw;
                try { raw = k.GetValue(vn, null, RegistryValueOptions.DoNotExpandEnvironmentNames); } catch { continue; }
                var items = raw as string[] ?? (raw is string ? new[] { (string)raw } : null);
                if (items == null) continue;
                for (int i = 0; i < items.Length; i++)
                {
                    string data = (items[i] ?? "").Trim();
                    if (data.Length == 0 || (sp.Skip != null && sp.Skip(data))) continue;
                    string cmd = sp.Command != null ? sp.Command(data) : data;
                    bool plain = TrustedProgramOnly(ctx, cmd);
                    string id = "reg2:" + hn + "\\" + keyPath + "\\" + vn + (items.Length > 1 ? "#" + i : "");
                    var e = Persist.Evaluate(ctx, id, EntityKind.Registry, sp.Mech + (vn.Length > 0 && sp.Names == null ? ": " + vn : ""), hn + "\\" + keyPath + "\\" + vn, cmd, sp.Mech, ev =>
                    {
                        if (sp.Rule != null && sp.Weight > 0 && !plain) ev.Add(new Evidence(sp.Rule, EvidenceCategory.Persistence, sp.Weight, sp.Text, Text.Trunc(data, 200)));
                    });
                    if (e != null) { e.Set("hive", hn); e.Set("key", keyPath); e.Set("value", vn); e.Set("data", data); }
                }
            }
        }

        /// <summary>True when the command starts nothing but programs that exist and are trusted (a signed vendor tool). An interpreter such as cmd or PowerShell is never
        /// "plain": what matters is what it is told to run.</summary>
        static bool TrustedProgramOnly(ScanContext ctx, string cmd)
        {
            try
            {
                var paths = PathUtil.ExtractPaths(cmd).Take(5).ToList();
                if (paths.Count == 0) return false;
                string exe = PathUtil.ExtractExecutable(cmd);
                if (Persist.IsLolbin(exe)) return false;
                foreach (var p in paths)
                {
                    if (!File.Exists(p)) return false;
                    var f = ctx.Files.Inspect(p, FileRole.PersistenceTarget);
                    if (f == null || !f.Trusted) return false;
                }
                return true;
            }
            catch { return false; }
        }

        // ------------------------------------------------------------------------------------------------ KnownDLLs: names the loader maps from one fixed folder
        static void KnownDlls(ScanContext ctx, RegistryKey hklm)
        {
            const string key = @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs";
            using (var k = hklm.OpenSubKey(key))
            {
                if (k == null) return;
                foreach (var vn in k.GetValueNames())
                {
                    string data = Convert.ToString(k.GetValue(vn, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                    if (string.IsNullOrWhiteSpace(data)) continue;
                    if (vn.StartsWith("DllDirectory", StringComparison.OrdinalIgnoreCase))
                    {
                        string dir = PathUtil.Normalize(data);
                        if (string.Equals(dir, PathUtil.System32, StringComparison.OrdinalIgnoreCase) || string.Equals(dir, PathUtil.SysWow64, StringComparison.OrdinalIgnoreCase)) continue;
                        var de = ctx.GetOrAdd("reg2:HKLM\\KnownDLLs\\" + vn, EntityKind.Registry, () => new Entity { Title = "KnownDLLs folder " + vn, Location = @"HKLM\" + key + "\\" + vn });
                        de.Add(new Evidence("REG.KNOWNDLLS_DIR", EvidenceCategory.Persistence, 40, "The folder Windows loads its core DLLs from is not the Windows system folder (" + data + ")", data));
                        de.Set("hive", "HKLM"); de.Set("key", key); de.Set("value", vn); de.Set("data", data);
                        continue;
                    }
                    string dll = Path.IsPathRooted(data) ? data : Path.Combine(PathUtil.System32, data);
                    if (!File.Exists(dll)) continue;
                    var f = ctx.Files.Inspect(dll, FileRole.PersistenceTarget);
                    if (f == null || f.Trusted) continue;
                    var e = Persist.Evaluate(ctx, "reg2:HKLM\\KnownDLLs\\" + vn, EntityKind.Registry, "KnownDLLs: " + vn, @"HKLM\" + key + "\\" + vn, dll, "KnownDLLs entry", ev =>
                        ev.Add(new Evidence("REG.KNOWNDLLS_UNTRUSTED", EvidenceCategory.Persistence, 30, "A KnownDLLs entry (loaded into every program by name) is a file that is not signed by a trusted publisher", dll)));
                    if (e != null) { e.Set("hive", "HKLM"); e.Set("key", key); e.Set("value", vn); e.Set("data", data); }
                }
            }
        }

        // ------------------------------------------------------------------------------------------------ IFEO VerifierDlls: a DLL the loader puts into a program every time it starts
        static void IfeoVerifier(ScanContext ctx, RegistryKey hklm)
        {
            foreach (var root in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" })
                using (var k = hklm.OpenSubKey(root))
                {
                    if (k == null) continue;
                    foreach (var name in k.GetSubKeyNames())
                        using (var s = k.OpenSubKey(name))
                        {
                            string v = s == null ? null : Convert.ToString(s.GetValue("VerifierDlls", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                            if (string.IsNullOrWhiteSpace(v)) continue;
                            string dll = Path.IsPathRooted(v) ? v : Path.Combine(PathUtil.System32, v);
                            var e = Persist.Evaluate(ctx, "reg2:HKLM\\" + root + "\\" + name + "\\VerifierDlls", EntityKind.Registry, "IFEO verifier DLL: " + name, @"HKLM\" + root + "\\" + name + "\\VerifierDlls", dll, "IFEO verifier DLL", ev =>
                                ev.Add(new Evidence("REG.IFEO_VERIFIER", EvidenceCategory.Persistence, 28, "A DLL is forced into \"" + name + "\" every time it starts (Application Verifier hook, also used for injection)", v)));
                            if (e != null) { e.Set("hive", "HKLM"); e.Set("key", root + "\\" + name); e.Set("value", "VerifierDlls"); e.Set("data", v); }
                        }
                }
        }

        // ------------------------------------------------------------------------------------------------ per-user overrides of how Windows opens things
        static void HandlerOverrides(ScanContext ctx, string hn, RegistryKey root)
        {
            using (var cls = root.OpenSubKey(@"Software\Classes"))
            {
                if (cls == null) return;
                int seen = 0;
                foreach (var name in cls.GetSubKeyNames())
                {
                    if (++seen > 8000) { ctx.AddBlind("Autostart", hn + " file-type handlers: stopped after 8000 classes"); break; }
                    bool sensitive = SensitiveClasses.Contains(name);
                    if (!sensitive && !name.StartsWith(".")) continue;
                    using (var c = cls.OpenSubKey(name))
                    {
                        if (c == null) continue;
                        var scan = new List<string> { name };
                        string prog = Convert.ToString(c.GetValue(null));                        // .ext -> ProgID redirect
                        if (name.StartsWith(".") && !string.IsNullOrWhiteSpace(prog) && !prog.Contains("\\")) scan.Add(prog);
                        foreach (var cn in scan)
                            using (var shell = cls.OpenSubKey(cn + @"\shell"))
                            {
                                if (shell == null) continue;
                                foreach (var verb in shell.GetSubKeyNames())
                                    using (var cmdKey = shell.OpenSubKey(verb + @"\command"))
                                    {
                                        if (cmdKey == null) continue;
                                        string cmd = Convert.ToString(cmdKey.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                                        string deleg = Convert.ToString(cmdKey.GetValue("DelegateExecute"));
                                        string valName = "";
                                        if (string.IsNullOrWhiteSpace(cmd) && !string.IsNullOrWhiteSpace(deleg) && deleg.StartsWith("{"))
                                        { string h, srv; cmd = TaskScanner.ResolveComClass(deleg, out h, out srv); valName = "DelegateExecute"; }
                                        if (string.IsNullOrWhiteSpace(cmd)) continue;
                                        bool uac = cn.Equals("ms-settings", StringComparison.OrdinalIgnoreCase) || cn.Equals("mscfile", StringComparison.OrdinalIgnoreCase);
                                        bool plain = TrustedProgramOnly(ctx, cmd);
                                        string keyPath = @"Software\Classes\" + cn + @"\shell\" + verb + @"\command";
                                        var e = Persist.Evaluate(ctx, "reg2:" + hn + "\\" + keyPath, EntityKind.Registry, "Per-user handler: " + cn + " (" + verb + ")", hn + "\\" + keyPath, cmd, "per-user file-type handler", ev =>
                                        {
                                            if (!plain) ev.Add(new Evidence("REG.HANDLER_HIJACK", EvidenceCategory.Persistence, uac ? 35 : 25,
                                                uac ? "A per-user override of \"" + cn + "\" makes a program run elevated without a UAC prompt when Windows opens it (a classic UAC bypass)" : "A per-user override changes what Windows runs when \"" + cn + "\" is opened", Text.Trunc(cmd, 200)));
                                        });
                                        if (e != null) { e.Set("hive", hn); e.Set("key", keyPath); e.Set("value", valName); e.Set("data", cmd); }
                                    }
                            }
                    }
                }
            }
        }

        // ------------------------------------------------------------------------------------------------ COM redirections that ComHijack (server paths) does not cover
        static void ComExtras(ScanContext ctx, string hn, RegistryKey root)
        {
            using (var k = root.OpenSubKey(@"Software\Classes\CLSID"))
            {
                if (k == null) return;
                foreach (var clsid in k.GetSubKeyNames().Take(4000))
                {
                    using (var c = k.OpenSubKey(clsid))
                    {
                        if (c == null) continue;
                        string treat = null;
                        using (var t = c.OpenSubKey("TreatAs")) if (t != null) treat = Convert.ToString(t.GetValue(null));
                        string scriptlet = null;
                        using (var s = c.OpenSubKey("ScriptletURL")) if (s != null) scriptlet = Convert.ToString(s.GetValue(null));
                        string handler = null;
                        using (var h = c.OpenSubKey("InprocHandler32")) if (h != null) handler = Convert.ToString(h.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                        if (!string.IsNullOrWhiteSpace(scriptlet))
                        {
                            string kp = @"Software\Classes\CLSID\" + clsid + @"\ScriptletURL";
                            var e = Persist.Evaluate(ctx, "reg2:" + hn + "\\" + kp, EntityKind.Registry, "Scriptlet COM class " + clsid, hn + "\\" + kp, scriptlet.Replace("script:", "").Replace("file:///", ""), "per-user scriptlet COM class", ev =>
                                ev.Add(new Evidence("REG.COM_SCRIPTLET", EvidenceCategory.Persistence, 30, "A per-user COM class runs a script (.sct scriptlet) instead of a compiled server: a known way to start code without an executable", Text.Trunc(scriptlet, 200))));
                            if (e != null) { e.Set("hive", hn); e.Set("key", kp); e.Set("value", ""); e.Set("data", scriptlet); }
                        }
                        if (!string.IsNullOrWhiteSpace(handler) && !TrustedProgramOnly(ctx, handler))
                        {
                            string kp = @"Software\Classes\CLSID\" + clsid + @"\InprocHandler32";
                            var e = Persist.Evaluate(ctx, "reg2:" + hn + "\\" + kp, EntityKind.Registry, "COM handler " + clsid, hn + "\\" + kp, handler, "per-user COM handler");
                            if (e != null) { e.Set("hive", hn); e.Set("key", kp); e.Set("value", ""); e.Set("data", handler); }
                        }
                        if (!string.IsNullOrWhiteSpace(treat))
                        {
                            string kp = @"Software\Classes\CLSID\" + clsid + @"\TreatAs";
                            string h2, srv2, impl = TaskScanner.ResolveComClass(treat.Trim(), out h2, out srv2);
                            if (impl != null && !TrustedProgramOnly(ctx, impl))
                            {
                                var e = Persist.Evaluate(ctx, "reg2:" + hn + "\\" + kp, EntityKind.Registry, "COM redirection " + clsid, hn + "\\" + kp, impl, "per-user COM redirection", ev =>
                                    ev.Add(new Evidence("REG.COM_TREATAS", EvidenceCategory.Persistence, 15, "A per-user COM class is redirected to another class (TreatAs), a way to swap the code that programs load", treat)));
                                if (e != null) { e.Set("hive", hn); e.Set("key", kp); e.Set("value", ""); e.Set("data", treat); }
                            }
                        }
                    }
                }
            }
        }
    }
}
