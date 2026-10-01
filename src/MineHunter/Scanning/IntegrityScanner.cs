using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Kernel-level integrity and the switches that protect it: may unsigned drivers be loaded, which drivers are loaded right now, and has
    /// someone turned off the protections that would stop a vulnerable or unsigned driver (the way miners get MSR access or kill security software).</summary>
    public static class IntegrityScanner
    {
        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_CODEINTEGRITY_INFORMATION { public int Length; public uint CodeIntegrityOptions; }
        [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int infoClass, ref SYSTEM_CODEINTEGRITY_INFORMATION info, int length, out int returned);
        [DllImport("psapi.dll", SetLastError = true)] static extern bool EnumDeviceDrivers([Out] IntPtr[] bases, uint cb, out uint needed);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetDeviceDriverFileName(IntPtr imageBase, StringBuilder name, uint size);

        const uint CI_ENABLED = 0x01, CI_TESTSIGN = 0x02;

        public static void Run(ScanContext ctx)
        {
            Safe(ctx, "code integrity", () => CodeIntegrity(ctx));
            Safe(ctx, "driver block list", () => DriverBlocklist(ctx, Registry.LocalMachine));
            Safe(ctx, "loaded drivers", () => LoadedDrivers(ctx));
            Safe(ctx, "Defender / AMSI / UAC settings", () => ProtectionSettings(ctx, Registry.LocalMachine, Registry.CurrentUser));
            Safe(ctx, "DNS settings", () => DnsSettings(ctx, Registry.LocalMachine));
        }

        static void Safe(ScanContext ctx, string what, Action a)
        {
            try { a(); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { ctx.AddBlind("Kernel integrity", what + ": " + ex.Message); }
        }

        static Entity PolicyEntity(ScanContext ctx, string id, string title, string location, string hive, string key, string value, string data)
        {
            var e = ctx.GetOrAdd(id, EntityKind.PolicyValue, () => new Entity { Title = title, Location = location });
            if (hive != null) { e.Set("hive", hive); e.Set("key", key); e.Set("value", value); e.Set("data", data); }
            return e;
        }

        // ------------------------------------------------------------------------------------------------ code integrity (test signing, integrity checks off)
        /// <summary>SystemCodeIntegrityInformation: the kernel's own view of whether driver signing is enforced. Returns the NTSTATUS (0 = success).</summary>
        internal static int ReadCodeIntegrity(out uint options)
        {
            var info = new SYSTEM_CODEINTEGRITY_INFORMATION { Length = Marshal.SizeOf(typeof(SYSTEM_CODEINTEGRITY_INFORMATION)) };
            int ret;
            int st = NtQuerySystemInformation(103, ref info, info.Length, out ret);
            options = info.CodeIntegrityOptions;
            return st;
        }

        static void CodeIntegrity(ScanContext ctx)
        {
            uint options;
            int st = ReadCodeIntegrity(out options);
            if (st != 0) { ctx.AddBlind("Kernel integrity", "code-integrity state could not be read (status 0x" + st.ToString("X") + ")"); return; }
            CodeIntegrityEvidence(ctx, options);
        }

        internal static void CodeIntegrityEvidence(ScanContext ctx, uint options)
        {
            var info = new SYSTEM_CODEINTEGRITY_INFORMATION { CodeIntegrityOptions = options };
            bool enabled = (info.CodeIntegrityOptions & CI_ENABLED) != 0, testSign = (info.CodeIntegrityOptions & CI_TESTSIGN) != 0;
            ctx.PostureInfo.Add("CODE_INTEGRITY=0x" + info.CodeIntegrityOptions.ToString("X"));
            if (testSign)
            {
                var e = PolicyEntity(ctx, "policy:CodeIntegrity:testsigning", "Windows is in test-signing mode", "Boot configuration (bcdedit /set testsigning)", null, null, null, null);
                e.Add(new Evidence("TAMPER.TESTSIGNING", EvidenceCategory.Tamper, 25, "Windows is in test-signing mode: kernel drivers do not have to be signed (only driver developers need this; miners and rootkits use it to load their own driver)", "CodeIntegrityOptions=0x" + info.CodeIntegrityOptions.ToString("X")));
                ctx.PostureWarnings.Add("TESTSIGNING|Windows is in test-signing mode: unsigned kernel drivers can be loaded.");
            }
            if (!enabled)
            {
                var e = PolicyEntity(ctx, "policy:CodeIntegrity:disabled", "Kernel code-integrity checks are off", "Boot configuration (bcdedit /set nointegritychecks)", null, null, null, null);
                e.Add(new Evidence("TAMPER.CI_DISABLED", EvidenceCategory.Tamper, 30, "Kernel code-integrity checks are switched off: any driver can be loaded, signed or not", "CodeIntegrityOptions=0x" + info.CodeIntegrityOptions.ToString("X")));
                ctx.PostureWarnings.Add("CI_DISABLED|Kernel code-integrity checks are switched off.");
            }
        }

        // ------------------------------------------------------------------------------------------------ Microsoft's vulnerable-driver block list
        internal static void DriverBlocklist(ScanContext ctx, RegistryKey hklm)
        {
            const string key = @"SYSTEM\CurrentControlSet\Control\CI\Config";
            using (var k = hklm.OpenSubKey(key))
            {
                if (k == null) return;
                object v = k.GetValue("VulnerableDriverBlocklistEnable");
                if (v == null) return;
                int val; try { val = Convert.ToInt32(v); } catch { return; }
                if (val != 0) return;
                var e = PolicyEntity(ctx, "policy:HKLM:VulnerableDriverBlocklistEnable", "Microsoft vulnerable-driver block list is switched off", @"HKLM\" + key + @"\VulnerableDriverBlocklistEnable", "HKLM", key, "VulnerableDriverBlocklistEnable", "0");
                e.Add(new Evidence("TAMPER.DRIVER_BLOCKLIST_OFF", EvidenceCategory.Tamper, 20, "Windows is told not to block known-vulnerable drivers (some hardware-monitor tools ask for this; attackers need it to load a vulnerable driver)", "VulnerableDriverBlocklistEnable=0"));
            }
        }

        // ------------------------------------------------------------------------------------------------ drivers loaded right now
        internal static string DriverPath(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            string p = raw.Trim();
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = Path.Combine(PathUtil.WinDir, p.Substring(12));
            else if (p.StartsWith(@"\??\")) p = p.Substring(4);
            else if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)) p = Path.Combine(PathUtil.WinDir, p);
            return PathUtil.Normalize(p);
        }

        /// <summary>Full paths of the kernel modules loaded right now (null when the list cannot be read).</summary>
        internal static List<string> LoadedDriverPaths()
        {
            uint needed;
            var bases = new IntPtr[2048];
            if (!EnumDeviceDrivers(bases, (uint)(bases.Length * IntPtr.Size), out needed)) return null;
            int count = (int)Math.Min(bases.Length, needed / (uint)IntPtr.Size);
            var list = new List<string>();
            for (int i = 0; i < count; i++)
            {
                var sb = new StringBuilder(520);
                if (GetDeviceDriverFileName(bases[i], sb, (uint)sb.Capacity) == 0) continue;
                string p = DriverPath(sb.ToString());
                if (p != null) list.Add(p);
            }
            return list;
        }

        static void LoadedDrivers(ScanContext ctx)
        {
            var paths = LoadedDriverPaths();
            if (paths == null) { ctx.AddBlind("Kernel integrity", "loaded driver list unavailable"); return; }
            var serviceStems = RegisteredDriverFiles();
            int inspected = 0;
            foreach (var path in paths)
            {
                ctx.ThrowIfCancelled();
                string stem = Path.GetFileNameWithoutExtension(path);
                bool inWindows = PathUtil.IsUnder(path, PathUtil.WinDir);
                if (!File.Exists(path)) continue;
                inspected++;

                var f = ctx.Files.Inspect(path, FileRole.Module);
                bool vulnerable = ctx.Rules.VulnerableDrivers.Any(v => stem.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0);
                bool unsignedDriver = f != null && !f.Trusted && (f.P("sig") == "Unsigned" || f.P("sig") == "Tampered" || f.P("trustClass") == "Unsigned");
                bool userPath = !inWindows && PathUtil.IsUserWritable(path);
                bool noService = !inWindows && !serviceStems.Contains(Path.GetFileName(path));
                if (!vulnerable && !unsignedDriver && !userPath && !noService) continue;

                var e = ctx.GetOrAdd("kdrv:" + PathUtil.Key(path), EntityKind.KernelDriver, () => new Entity { Title = Path.GetFileName(path), Location = path });
                e.Set("path", path);
                if (vulnerable) e.Add(new Evidence("DRV.VULNERABLE_KNOWN", EvidenceCategory.Content, 14, "A signed but known-vulnerable kernel driver is loaded right now (abused by miners for CPU tuning and by attackers to kill security software; hardware-monitor tools use it too)", path));
                if (unsignedDriver) e.Add(new Evidence("DRV.LOADED_UNSIGNED", EvidenceCategory.Tamper, 25, "A kernel driver without a valid signature is loaded", path));
                if (userPath) e.Add(new Evidence("DRV.LOADED_USERPATH", EvidenceCategory.Persistence, 35, "A kernel driver is loaded from a folder ordinary users can write to", path));
                if (noService && (unsignedDriver || userPath || vulnerable)) e.Add(new Evidence("DRV.LOADED_NO_SERVICE", EvidenceCategory.Masquerade, 12, "The driver is loaded but no driver service points at its file (the service entry was removed after loading, or the driver was mapped some other way)", path));
                if (f != null && e.Evidence.Any(x => x.Weight > 0)) ctx.Link(e.Id, f.Id, "loads");
            }
            ctx.PostureInfo.Add("KERNEL_DRIVERS_CHECKED=" + inspected);
        }

        /// <summary>File names (e.g. "winring0x64.sys") of every driver that has a service entry.</summary>
        static HashSet<string> RegisteredDriverFiles()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (k == null) return set;
                    foreach (var name in k.GetSubKeyNames())
                        using (var s = k.OpenSubKey(name))
                        {
                            string img = s == null ? null : Convert.ToString(s.GetValue("ImagePath"));
                            if (string.IsNullOrWhiteSpace(img)) continue;
                            try { set.Add(Path.GetFileName(img.Trim().Trim('"').Split(' ')[0])); } catch { }
                        }
                }
            }
            catch { }
            return set;
        }

        // ------------------------------------------------------------------------------------------------ Defender real-time switch, AMSI, UAC prompt behaviour
        internal static void ProtectionSettings(ScanContext ctx, RegistryKey hklm, RegistryKey hkcu)
        {
            // Defender real-time monitoring switched off in the registry (Tamper Protection normally prevents this)
            foreach (var key in new[] { @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" })
            {
                using (var k = hklm.OpenSubKey(key))
                {
                    if (k == null) continue;
                    foreach (var vn in new[] { "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning" })
                    {
                        int v = 0; try { v = Convert.ToInt32(k.GetValue(vn, 0)); } catch { }
                        if (v != 1) continue;
                        var e = PolicyEntity(ctx, "policy:HKLM:" + key + ":" + vn, "Defender setting " + vn + " = 1", @"HKLM\" + key + "\\" + vn, "HKLM", key, vn, "1");
                        e.Add(new Evidence("TAMPER.DEFENDER_RTP_OFF", EvidenceCategory.Tamper, 22, "Windows Defender " + vn.Replace("Disable", "").ToLowerInvariant() + " is switched off in the registry", vn + "=1"));
                        ctx.PostureWarnings.Add("DEFENDER_RTP_OFF|Windows Defender real-time protection component is switched off (" + vn + ").");
                    }
                }
            }
            // AMSI switched off for Windows Script Host scripts
            using (var k = hkcu.OpenSubKey(@"Software\Microsoft\Windows Script\Settings"))
            {
                object v = k == null ? null : k.GetValue("AmsiEnable");
                int val = -1; try { if (v != null) val = Convert.ToInt32(v); } catch { }
                if (val == 0)
                {
                    var e = PolicyEntity(ctx, "policy:HKCU:AmsiEnable", "AMSI is switched off for Windows Script Host", @"HKCU\Software\Microsoft\Windows Script\Settings\AmsiEnable", "HKCU", @"Software\Microsoft\Windows Script\Settings", "AmsiEnable", "0");
                    e.Add(new Evidence("TAMPER.AMSI_OFF", EvidenceCategory.Tamper, 25, "The Antimalware Scan Interface is switched off for Windows Script Host: scripts are no longer shown to the antivirus before they run", "AmsiEnable=0"));
                    ctx.PostureWarnings.Add("AMSI_OFF|AMSI is switched off for Windows Script Host scripts.");
                }
            }
            // UAC set to "elevate without prompting" for administrators while it is formally still on
            using (var k = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
            {
                if (k == null) return;
                object lua = k.GetValue("EnableLUA"), cp = k.GetValue("ConsentPromptBehaviorAdmin");
                int l = 1, c = 5; try { if (lua != null) l = Convert.ToInt32(lua); if (cp != null) c = Convert.ToInt32(cp); } catch { }
                if (l == 1 && c == 0)
                {
                    var e = PolicyEntity(ctx, "policy:HKLM:ConsentPromptBehaviorAdmin", "UAC elevates administrators without asking", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin", "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", "0");
                    e.Add(new Evidence("TAMPER.UAC_NO_PROMPT", EvidenceCategory.Tamper, 15, "User Account Control is on, but set to elevate administrators without any prompt - in effect the same as off", "ConsentPromptBehaviorAdmin=0"));
                    ctx.PostureWarnings.Add("UAC_NOPROMPT|User Account Control is set to elevate administrators without asking.");
                }
            }
        }

        // ------------------------------------------------------------------------------------------------ DNS servers set by hand
        static readonly string[] KnownResolvers =
        {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "77.88.8.8", "77.88.8.1", "77.88.8.88", "77.88.8.2",
            "94.140.14.14", "94.140.15.15", "185.228.168.9", "185.228.169.9", "76.76.2.0", "76.76.10.0", "4.2.2.1", "4.2.2.2", "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001"
        };

        internal static void DnsSettings(ScanContext ctx, RegistryKey hklm)
        {
            var rogue = new List<string>();
            var all = new List<string>();
            using (var k = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"))
            {
                if (k == null) return;
                foreach (var guid in k.GetSubKeyNames())
                    using (var s = k.OpenSubKey(guid))
                    {
                        string ns = s == null ? null : Convert.ToString(s.GetValue("NameServer"));          // set by hand (DHCP-supplied servers live in DhcpNameServer)
                        if (string.IsNullOrWhiteSpace(ns)) continue;
                        foreach (var ip in ns.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            all.Add(ip);
                            if (IsPrivateOrLocal(ip) || KnownResolvers.Contains(ip)) continue;
                            if (!rogue.Contains(ip)) rogue.Add(ip);
                        }
                    }
            }
            if (all.Count > 0) ctx.PostureInfo.Add("DNS_STATIC=" + string.Join(",", all.Distinct()));
            if (rogue.Count == 0) return;
            var e = PolicyEntity(ctx, "policy:HKLM:DnsNameServer", "DNS server set by hand: " + string.Join(", ", rogue), @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\...\NameServer", null, null, null, null);
            e.Add(new Evidence("TAMPER.DNS_UNKNOWN", EvidenceCategory.Tamper, 14, "A network adapter uses a hand-set DNS server that is neither a router/local address nor a well-known public resolver (" + string.Join(", ", rogue.Take(4)) + "): some malware redirects name lookups this way. Ignore it if it is your provider's server", string.Join(", ", rogue)));
        }

        internal static bool IsPrivateOrLocal(string ip)
        {
            System.Net.IPAddress a;
            if (!System.Net.IPAddress.TryParse(ip, out a)) return true;          // not an address: do not guess
            var b = a.GetAddressBytes();
            if (b.Length == 4) return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || ip.StartsWith("fc", StringComparison.OrdinalIgnoreCase) || ip.StartsWith("fd", StringComparison.OrdinalIgnoreCase) || ip == "::1";
        }
    }
}
