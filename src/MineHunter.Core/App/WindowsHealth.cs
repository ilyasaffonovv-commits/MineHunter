using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using MineHunter.Util;

namespace MineHunter
{
    public enum HealthState { Good, Info, Warn, Bad, Unknown }

    public sealed class HealthItem
    {
        public string Id, Group, Title, Text, Details, FixId, FixText, OpenSettings;
        public HealthState State = HealthState.Unknown;
        public bool CanFix { get { return !string.IsNullOrEmpty(FixId); } }
    }

    /// <summary>The "Windows health" page: concrete statements about this PC's protection (is it on, what exactly is off), with no invented score. Every item says what was
    /// read; where a safe, real fix exists the item carries one (applied only on a click and a confirmation, never by a scan).</summary>
    public static class WindowsHealth
    {
        static string L(string en, string ru) { return Loc.L(en, ru); }

        static object RegVal(RegistryHive hive, string path, string name)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (var k = b.OpenSubKey(path)) return k == null ? null : k.GetValue(name);
            }
            catch { return null; }
        }

        static int? RegInt(RegistryHive h, string p, string n) { var v = RegVal(h, p, n); try { return v == null ? (int?)null : Convert.ToInt32(v); } catch { return null; } }

        public static List<HealthItem> Run()
        {
            var list = new System.Collections.Concurrent.ConcurrentBag<HealthItem>();
            var checks = new List<Action>
            {
                () => Defender(list), () => Firewall(list), () => SmartScreen(list), () => Uac(list), () => WindowsUpdate(list), () => SecureBoot(list), () => Tpm(list), () => MemoryIntegrity(list),
                () => HostsFile(list), () => Proxies(list), () => Dns(list), () => PowerShellPolicy(list), () => RemoteDesktop(list), () => RemoteTools(list), () => Shares(list)
            };
            Task.WaitAll(checks.Select(c => Task.Run(() => { try { c(); } catch (Exception ex) { Log.Warn("health: " + ex.Message); } })).ToArray(), 40000);
            string[] order = { "defender", "defender.exclusions", "firewall", "smartscreen", "uac", "update", "secureboot", "tpm", "hvci", "hosts", "proxy", "winhttp", "dns", "powershell", "rdp", "remote", "shares" };
            return list.OrderBy(i => { int ix = Array.IndexOf(order, i.Id); return ix < 0 ? 99 : ix; }).ToList();
        }

        // ------------------------------------------------------------------------------------------------ Defender
        static ManagementObject MpPreference()
        {
            try
            {
                using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpPreference"))
                    foreach (ManagementObject o in s.Get()) return o;
            }
            catch { }
            return null;
        }

        static ManagementObject MpStatus()
        {
            try
            {
                using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus"))
                    foreach (ManagementObject o in s.Get()) return o;
            }
            catch { }
            return null;
        }

        static void Defender(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "defender", Group = "Windows", Title = L("Microsoft Defender", "Защитник Windows (Microsoft Defender)"), OpenSettings = "windowsdefender:" };
            var st = MpStatus();
            string otherAv = null;
            try
            {
                using (var s = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
                    otherAv = string.Join(", ", s.Get().Cast<ManagementObject>().Select(o => Convert.ToString(o["displayName"])).Where(n => n != null && n.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) < 0).Distinct());
            }
            catch { }
            if (st == null)
            {
                bool svc = ServiceRunning("WinDefend");
                it.State = svc ? HealthState.Unknown : (string.IsNullOrEmpty(otherAv) ? HealthState.Bad : HealthState.Info);
                it.Text = svc ? L("Defender is running, but its detailed state could not be read (another antivirus may manage it).", "Защитник запущен, но подробное состояние прочитать не удалось (возможно, им управляет другой антивирус).")
                              : string.IsNullOrEmpty(otherAv) ? L("Defender is not running and no other antivirus was found.", "Защитник не запущен, другого антивируса не найдено.") : L("Defender is off; another antivirus is registered: ", "Защитник выключен; зарегистрирован другой антивирус: ") + otherAv;
                list.Add(it); return;
            }
            bool av = B(st, "AntivirusEnabled"), rt = B(st, "RealTimeProtectionEnabled"), beh = B(st, "BehaviorMonitorEnabled"), tamper = B(st, "IsTamperProtected");
            DateTime sigDate = DateTime.MinValue; try { sigDate = ManagementDateTimeConverter.ToDateTime(Convert.ToString(st["AntivirusSignatureLastUpdated"])); } catch { }
            var lines = new List<string>
            {
                L("Antivirus: ", "Антивирус: ") + (av ? L("on", "включён") : L("off", "выключен")),
                L("Real-time protection: ", "Защита в реальном времени: ") + (rt ? L("on", "включена") : L("OFF", "ВЫКЛЮЧЕНА")),
                L("Behaviour monitoring: ", "Поведенческий анализ: ") + (beh ? L("on", "включён") : L("off", "выключен")),
                L("Tamper Protection: ", "Защита от подделки (Tamper Protection): ") + (tamper ? L("on", "включена") : L("off", "выключена")),
                L("Virus definitions updated: ", "Базы обновлены: ") + (sigDate > DateTime.MinValue ? sigDate.ToString("dd.MM.yyyy") : "?")
            };
            var mp = MpPreference();
            if (mp != null)
            {
                int maps = 0; try { maps = Convert.ToInt32(mp["MAPSReporting"]); } catch { }
                lines.Add(L("Cloud-delivered protection: ", "Облачная защита: ") + (maps > 0 ? L("on", "включена") : L("off", "выключена")));
            }
            it.Details = string.Join("\n", lines);
            if (!av || !rt)
            {
                if (!string.IsNullOrEmpty(otherAv)) { it.State = HealthState.Info; it.Text = L("Defender's real-time protection is off, but another antivirus is registered: ", "Защита Защитника выключена, но зарегистрирован другой антивирус: ") + otherAv; }
                else { it.State = HealthState.Bad; it.Text = L("Real-time protection is OFF: files are not checked when they are opened or run.", "Защита в реальном времени ВЫКЛЮЧЕНА: файлы не проверяются при открытии и запуске."); it.FixId = "defender.rtp"; it.FixText = L("Turn real-time protection on (Set-MpPreference -DisableRealtimeMonitoring $false)", "Включить защиту в реальном времени (Set-MpPreference -DisableRealtimeMonitoring $false)"); }
            }
            else if (sigDate > DateTime.MinValue && (DateTime.Now - sigDate).TotalDays > 7) { it.State = HealthState.Warn; it.Text = L("Defender is on, but its virus definitions are older than a week.", "Защитник включён, но его базы старше недели."); }
            else { it.State = HealthState.Good; it.Text = L("Defender is on, real-time protection works, definitions are fresh.", "Защитник включён, защита в реальном времени работает, базы свежие."); }
            list.Add(it);

            // exclusions
            var ex = new HealthItem { Id = "defender.exclusions", Group = "Windows", Title = L("Defender exclusions", "Исключения Защитника"), OpenSettings = "windowsdefender:" };
            var paths = new List<string>(); var procs = new List<string>(); var exts = new List<string>();
            if (mp != null)
            {
                paths = Arr(mp["ExclusionPath"]); procs = Arr(mp["ExclusionProcess"]); exts = Arr(mp["ExclusionExtension"]);
            }
            else
            {
                try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths")) if (k != null) paths = k.GetValueNames().ToList(); } catch { }
            }
            var dangerous = new List<string>();
            foreach (var p in paths) if (DangerousExclusion(p)) dangerous.Add(p);
            foreach (var e in exts) if (new[] { ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".sys", ".msi" }.Contains(e.TrimStart('*').ToLowerInvariant())) dangerous.Add("*" + e.TrimStart('*'));
            ex.Details = string.Join("\n", paths.Concat(procs.Select(x => L("process: ", "процесс: ") + x)).Concat(exts.Select(x => L("type: ", "тип: ") + x)).Take(40));
            if (mp == null && paths.Count == 0) { ex.State = HealthState.Unknown; ex.Text = L("The list of exclusions could not be read.", "Список исключений прочитать не удалось."); }
            else if (dangerous.Count > 0)
            {
                ex.State = HealthState.Bad; ex.Text = L("Defender is told NOT to look in: ", "Защитнику запрещено проверять: ") + string.Join(", ", dangerous.Take(4)) + (dangerous.Count > 4 ? " ..." : "") + L(". Miners and droppers add exactly such exclusions.", ". Именно такие исключения добавляют майнеры и дропперы.");
                ex.FixId = "defender.exclusion:" + dangerous[0]; ex.FixText = L("Remove the exclusion " + dangerous[0], "Убрать исключение " + dangerous[0]);
            }
            else if (paths.Count + procs.Count + exts.Count > 0) { ex.State = HealthState.Info; ex.Text = L((paths.Count + procs.Count + exts.Count) + " exclusion(s), none of them in a place where programs from the internet usually land.", (paths.Count + procs.Count + exts.Count) + " исключений, ни одно не в месте, куда обычно попадают программы из интернета."); }
            else { ex.State = HealthState.Good; ex.Text = L("No exclusions.", "Исключений нет."); }
            list.Add(ex);
        }

        static bool B(ManagementObject o, string n) { try { return Convert.ToBoolean(o[n]); } catch { return false; } }
        static List<string> Arr(object o) { var a = o as string[]; return a == null ? new List<string>() : a.Where(x => !string.IsNullOrWhiteSpace(x)).ToList(); }

        /// <summary>An exclusion that switches Defender off for the places malware lands in: a whole drive, the user profile, Temp, Downloads, AppData, ProgramData, the Windows folders.</summary>
        public static bool DangerousExclusion(string p)
        {
            if (string.IsNullOrWhiteSpace(p)) return false;
            string n = Environment.ExpandEnvironmentVariables(p).Trim().TrimEnd('\\', '/').ToLowerInvariant();
            if (n.Length <= 3) return true;                                  // "C:" / "C:\"
            if (n == "*" || n == "c:\\*") return true;
            string[] bad = { "\\temp", "\\tmp", "\\downloads", "\\appdata", "\\appdata\\local", "\\appdata\\roaming", "\\desktop", "\\users", "\\programdata", "\\windows", "\\windows\\system32", "\\public", "\\documents" };
            foreach (var b in bad) if (n.EndsWith(b)) return true;
            if (n.Contains("\\appdata\\local\\temp") || n.Contains("\\windows\\temp")) return true;
            foreach (var up in PathUtil.UserProfiles()) if (n == up.ToLowerInvariant()) return true;
            return false;
        }

        static bool ServiceRunning(string name)
        {
            try { using (var s = new ServiceController(name)) return s.Status == ServiceControllerStatus.Running; } catch { return false; }
        }

        // ------------------------------------------------------------------------------------------------ firewall
        static void Firewall(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "firewall", Group = "Windows", Title = L("Windows Firewall", "Брандмауэр Windows"), OpenSettings = "windowsdefender:" };
            string baseKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
            var prof = new[] { Tuple.Create("DomainProfile", L("domain", "доменная")), Tuple.Create("StandardProfile", L("private", "частная")), Tuple.Create("PublicProfile", L("public", "общедоступная")) };
            var off = new List<string>(); var lines = new List<string>(); bool read = false;
            foreach (var p in prof)
            {
                int? v = RegInt(RegistryHive.LocalMachine, baseKey + p.Item1, "EnableFirewall");
                if (v == null) { lines.Add(p.Item2 + ": ?"); continue; }
                read = true; lines.Add(p.Item2 + ": " + (v == 1 ? L("on", "включён") : L("OFF", "ВЫКЛЮЧЕН")));
                if (v == 0) off.Add(p.Item2);
            }
            it.Details = string.Join("\n", lines);
            if (!read) { it.State = HealthState.Unknown; it.Text = L("The firewall state could not be read.", "Состояние брандмауэра прочитать не удалось."); }
            else if (off.Count > 0)
            {
                bool otherFw = false; try { using (var s = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName FROM FirewallProduct")) otherFw = s.Get().Cast<ManagementObject>().Any(o => Convert.ToString(o["displayName"]).IndexOf("Windows", StringComparison.OrdinalIgnoreCase) < 0); } catch { }
                it.State = otherFw ? HealthState.Info : HealthState.Bad;
                it.Text = L("Windows Firewall is off for the " + string.Join(", ", off) + " network profile.", "Брандмауэр Windows выключен для сетей: " + string.Join(", ", off) + ".") + (otherFw ? L(" Another firewall is registered.", " Зарегистрирован другой брандмауэр.") : "");
                if (!otherFw) { it.FixId = "firewall.on"; it.FixText = L("Turn the Windows Firewall on for all profiles (netsh advfirewall set allprofiles state on)", "Включить брандмауэр Windows для всех профилей (netsh advfirewall set allprofiles state on)"); }
            }
            else { it.State = HealthState.Good; it.Text = L("Windows Firewall is on for all three network profiles.", "Брандмауэр Windows включён для всех трёх типов сетей."); }
            list.Add(it);
        }

        // ------------------------------------------------------------------------------------------------ SmartScreen / UAC
        static void SmartScreen(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "smartscreen", Group = "Windows", Title = "SmartScreen", OpenSettings = "windowsdefender:" };
            string v = Convert.ToString(RegVal(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"));
            int? pol = RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");
            it.Details = L("Setting: ", "Параметр: ") + (string.IsNullOrEmpty(v) ? "-" : v) + (pol != null ? L("   Policy: ", "   Политика: ") + pol : "");
            if (pol == 0 || string.Equals(v, "Off", StringComparison.OrdinalIgnoreCase)) { it.State = HealthState.Bad; it.Text = L("SmartScreen is off: downloaded programs are not checked for a bad reputation.", "SmartScreen выключен: скачанные программы не проверяются на плохую репутацию."); it.FixId = "smartscreen.on"; it.FixText = L("Set SmartScreen to 'Warn'", "Включить SmartScreen в режиме «Предупреждать»"); }
            else if (string.IsNullOrEmpty(v) && pol == null) { it.State = HealthState.Unknown; it.Text = L("The SmartScreen setting could not be read.", "Параметр SmartScreen прочитать не удалось."); }
            else { it.State = HealthState.Good; it.Text = L("SmartScreen is on (" + v + ").", "SmartScreen включён (" + v + ")."); }
            list.Add(it);
        }

        static void Uac(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "uac", Group = "Windows", Title = L("User Account Control (UAC)", "Контроль учётных записей (UAC)"), OpenSettings = "useraccountcontrol" };
            string k = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            int? lua = RegInt(RegistryHive.LocalMachine, k, "EnableLUA"), consent = RegInt(RegistryHive.LocalMachine, k, "ConsentPromptBehaviorAdmin"), secure = RegInt(RegistryHive.LocalMachine, k, "PromptOnSecureDesktop");
            it.Details = "EnableLUA=" + lua + "  ConsentPromptBehaviorAdmin=" + consent + "  PromptOnSecureDesktop=" + secure;
            if (lua == 0) { it.State = HealthState.Bad; it.Text = L("UAC is OFF: every program runs with full rights without asking.", "UAC ВЫКЛЮЧЕН: любая программа получает полные права без вопросов."); }
            else if (consent == 0) { it.State = HealthState.Bad; it.Text = L("UAC never asks administrators for confirmation: programs get full rights silently.", "UAC не спрашивает подтверждения у администраторов: программы получают полные права молча."); }
            else if (secure == 0) { it.State = HealthState.Warn; it.Text = L("UAC asks, but not on the secure desktop (a program can draw over the question).", "UAC спрашивает, но не на защищённом рабочем столе (программа может нарисовать поверх вопроса)."); }
            else if (lua == null) { it.State = HealthState.Unknown; it.Text = L("The UAC setting could not be read.", "Настройку UAC прочитать не удалось."); }
            else { it.State = HealthState.Good; it.Text = L("UAC is on and asks on the secure desktop.", "UAC включён и спрашивает на защищённом рабочем столе."); }
            list.Add(it);
        }

        static void WindowsUpdate(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "update", Group = "Windows", Title = "Windows Update", OpenSettings = "windowsupdate" };
            int? noAuto = RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate");
            string startType = ""; try { using (var s = new ServiceController("wuauserv")) startType = s.StartType.ToString(); } catch { }
            DateTime last = DateTime.MinValue;
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT InstalledOn FROM Win32_QuickFixEngineering"))
                    foreach (ManagementObject o in s.Get()) { DateTime d; if (DateTime.TryParse(Convert.ToString(o["InstalledOn"]), out d) && d > last) last = d; }
            }
            catch { }
            it.Details = L("Update service: ", "Служба обновления: ") + startType + (noAuto == 1 ? L("   Automatic updates are switched off by policy", "   Автообновление выключено политикой") : "") + (last > DateTime.MinValue ? L("   Latest update installed: ", "   Последнее обновление установлено: ") + last.ToString("dd.MM.yyyy") : "");
            if (noAuto == 1 || startType == "Disabled") { it.State = HealthState.Warn; it.Text = L("Automatic Windows updates are switched off.", "Автоматические обновления Windows отключены."); }
            else if (last > DateTime.MinValue && (DateTime.Now - last).TotalDays > 90) { it.State = HealthState.Warn; it.Text = L("The latest update was installed more than 3 months ago (" + last.ToString("dd.MM.yyyy") + ").", "Последнее обновление установлено больше 3 месяцев назад (" + last.ToString("dd.MM.yyyy") + ")."); }
            else { it.State = HealthState.Good; it.Text = L("Updates are enabled" + (last > DateTime.MinValue ? ", the latest was installed " + last.ToString("dd.MM.yyyy") : "") + ".", "Обновления включены" + (last > DateTime.MinValue ? ", последнее установлено " + last.ToString("dd.MM.yyyy") : "") + "."); }
            list.Add(it);
        }

        // ------------------------------------------------------------------------------------------------ boot / hardware security
        static void SecureBoot(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "secureboot", Group = L("Hardware", "Оборудование"), Title = "Secure Boot" };
            int? v = RegInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            if (v == 1) { it.State = HealthState.Good; it.Text = L("Secure Boot is on: only signed boot code can start.", "Secure Boot включён: загрузиться может только подписанный код."); }
            else if (v == 0) { it.State = HealthState.Warn; it.Text = L("Secure Boot is off (a boot-level rootkit would not be stopped by it).", "Secure Boot выключен (загрузочный руткит им не остановится)."); }
            else { it.State = HealthState.Info; it.Text = L("Secure Boot is not available (legacy BIOS mode) or could not be read.", "Secure Boot недоступен (режим Legacy BIOS) или не прочитан."); }
            list.Add(it);
        }

        static void Tpm(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "tpm", Group = L("Hardware", "Оборудование"), Title = "TPM" };
            try
            {
                var scope = new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftTpm"); scope.Connect();
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_Tpm")))
                    foreach (ManagementObject o in s.Get())
                    {
                        bool en = Convert.ToBoolean(o["IsEnabled_InitialValue"]); string spec = Convert.ToString(o["SpecVersion"]);
                        it.State = en ? HealthState.Good : HealthState.Warn;
                        it.Text = en ? L("TPM is present and enabled (spec " + spec.Split(',')[0] + ").", "TPM есть и включён (спецификация " + spec.Split(',')[0] + ").") : L("A TPM is present but not enabled.", "TPM есть, но не включён.");
                        list.Add(it); return;
                    }
            }
            catch { }
            it.State = HealthState.Info; it.Text = L("No TPM found (or it could not be read).", "TPM не найден (или не прочитан).");
            list.Add(it);
        }

        static void MemoryIntegrity(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "hvci", Group = L("Hardware", "Оборудование"), Title = L("Memory integrity (core isolation)", "Целостность памяти (изоляция ядра)"), OpenSettings = "windowsdefender:" };
            int? v = RegInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled");
            int? blocklist = RegInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable");
            it.Details = L("Vulnerable driver blocklist: ", "Блок-лист уязвимых драйверов: ") + (blocklist == null ? "?" : blocklist == 1 ? L("on", "включён") : L("off", "выключен"));
            if (v == 1) { it.State = HealthState.Good; it.Text = L("Memory integrity is on: kernel code is protected from tampering.", "Целостность памяти включена: код ядра защищён от подмены."); }
            else { it.State = HealthState.Info; it.Text = L("Memory integrity is off. Turning it on blocks old vulnerable drivers; some old drivers may stop it from turning on.", "Целостность памяти выключена. Её включение блокирует старые уязвимые драйверы; часть старых драйверов может мешать включению."); }
            list.Add(it);
        }

        // ------------------------------------------------------------------------------------------------ hosts / proxy / DNS
        static readonly string[] SecurityDomains = { "microsoft.com", "windowsupdate", "defender", "kaspersky", "eset", "avast", "avg.com", "malwarebytes", "virustotal", "bitdefender", "norton", "mcafee", "sophos", "drweb", "avira", "trendmicro", "symantec", "github.com" };

        static void HostsFile(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "hosts", Group = L("Network", "Сеть"), Title = L("hosts file", "Файл hosts") };
            try
            {
                string path = Path.Combine(PathUtil.System32, @"drivers\etc\hosts");
                var entries = File.Exists(path) ? File.ReadAllLines(path).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("#")).ToList() : new List<string>();
                entries = entries.Where(l => !IsLocalhostLine(l)).ToList();
                var blocking = entries.Where(l => SecurityDomains.Any(d => l.IndexOf(d, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();
                it.Details = string.Join("\n", entries.Take(30));
                if (blocking.Count > 0) { it.State = HealthState.Bad; it.Text = L("hosts redirects security or update sites: ", "hosts перенаправляет сайты защиты или обновлений: ") + string.Join("; ", blocking.Take(3)); }
                else if (entries.Count > 0) { it.State = HealthState.Info; it.Text = L(entries.Count + " custom entr" + (entries.Count == 1 ? "y" : "ies") + " in hosts (none of them points a security or update site elsewhere).", entries.Count + " своих записей в hosts (ни одна не перенаправляет сайты защиты или обновлений)."); }
                else { it.State = HealthState.Good; it.Text = L("hosts has no custom entries.", "В hosts нет посторонних записей."); }
            }
            catch { it.State = HealthState.Unknown; it.Text = L("hosts could not be read.", "hosts прочитать не удалось."); }
            list.Add(it);
        }

        static bool IsLocalhostLine(string line)
        {
            // the lines Windows itself puts there (localhost) are not "custom"
            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length >= 2 && (parts[1].Equals("localhost", StringComparison.OrdinalIgnoreCase) || parts[1].Equals("ip6-localhost", StringComparison.OrdinalIgnoreCase));
        }

        static void Proxies(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "proxy", Group = L("Network", "Сеть"), Title = L("Proxy (browser / system)", "Прокси (браузер / система)") };
            var found = new List<string>();
            foreach (var hive in new[] { Tuple.Create(RegistryHive.CurrentUser, "HKCU"), Tuple.Create(RegistryHive.LocalMachine, "HKLM") })
            {
                int? en = RegInt(hive.Item1, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable");
                string srv = Convert.ToString(RegVal(hive.Item1, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer"));
                string pac = Convert.ToString(RegVal(hive.Item1, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "AutoConfigURL"));
                if (en == 1 && !string.IsNullOrEmpty(srv)) found.Add(hive.Item2 + ": " + srv);
                if (!string.IsNullOrEmpty(pac)) found.Add(hive.Item2 + " PAC: " + pac);
            }
            it.Details = string.Join("\n", found);
            if (found.Count > 0) { it.State = HealthState.Warn; it.Text = L("A proxy is set: ", "Задан прокси: ") + string.Join("; ", found.Take(2)) + L(". If you did not set it up (and it is not a company PC), traffic may be going through someone else's server.", ". Если вы его не настраивали (и это не рабочий ПК), трафик может идти через чужой сервер."); }
            else { it.State = HealthState.Good; it.Text = L("No proxy is set for the browser or the system.", "Прокси для браузера и системы не задан."); }
            list.Add(it);

            var w = new HealthItem { Id = "winhttp", Group = L("Network", "Сеть"), Title = L("WinHTTP proxy (services)", "WinHTTP-прокси (службы)") };
            try
            {
                var b = RegVal(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", "WinHttpSettings") as byte[];
                if (b == null || b.Length < 12 || b[8] == 1 || b[8] == 9) { w.State = HealthState.Good; w.Text = L("WinHTTP uses a direct connection.", "WinHTTP использует прямое подключение."); }
                else
                {
                    int len = BitConverter.ToInt32(b, 12); string proxy = len > 0 && 16 + len <= b.Length ? Encoding.ASCII.GetString(b, 16, len) : "?";
                    w.State = HealthState.Warn; w.Text = L("System services go through the proxy ", "Системные службы ходят через прокси ") + proxy + L(". Check that you set it.", ". Убедитесь, что его задали вы.");
                }
            }
            catch { w.State = HealthState.Unknown; w.Text = L("WinHTTP settings could not be read.", "Параметры WinHTTP прочитать не удалось."); }
            list.Add(w);
        }

        static readonly string[] KnownDns = { "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "77.88.8.8", "77.88.8.1", "94.140.14.14", "94.140.15.15", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844" };

        static void Dns(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "dns", Group = L("Network", "Сеть"), Title = "DNS" };
            var odd = new List<string>(); var all = new List<string>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                    foreach (var a in nic.GetIPProperties().DnsAddresses)
                    {
                        string s = a.ToString(); if (a.IsIPv6LinkLocal || a.IsIPv6SiteLocal) continue;
                        all.Add(nic.Name + ": " + s);
                        if (!IsPrivate(a) && !KnownDns.Contains(s)) odd.Add(s);
                    }
                }
            }
            catch { }
            it.Details = string.Join("\n", all);
            if (all.Count == 0) { it.State = HealthState.Unknown; it.Text = L("No active DNS servers were found.", "Активных DNS-серверов не найдено."); }
            else if (odd.Count > 0) { it.State = HealthState.Info; it.Text = L("DNS server " + string.Join(", ", odd.Distinct()) + " is not your router and not a well-known public resolver. Normal for a provider; if you did not set it, check it.", "DNS-сервер " + string.Join(", ", odd.Distinct()) + " — не ваш роутер и не известный публичный. Для провайдера это нормально; если вы его не задавали, проверьте."); }
            else { it.State = HealthState.Good; it.Text = L("DNS points to your router or a well-known public resolver.", "DNS указывает на ваш роутер или известный публичный сервер."); }
            list.Add(it);
        }

        static bool IsPrivate(System.Net.IPAddress a)
        {
            if (System.Net.IPAddress.IsLoopback(a)) return true;
            var b = a.GetAddressBytes();
            if (b.Length == 4) return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
            return b.Length == 16 && (b[0] == 0xFC || b[0] == 0xFD);
        }

        // ------------------------------------------------------------------------------------------------ PowerShell / RDP / remote tools / shares
        static void PowerShellPolicy(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "powershell", Group = "Windows", Title = L("PowerShell policy", "Политика PowerShell") };
            string ep = Convert.ToString(RegVal(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy"));
            string epu = Convert.ToString(RegVal(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy"));
            int? sbl = RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging");
            it.Details = L("Execution policy (machine): ", "Политика выполнения (машина): ") + (string.IsNullOrEmpty(ep) ? L("default", "по умолчанию") : ep) + L("   (user): ", "   (пользователь): ") + (string.IsNullOrEmpty(epu) ? L("default", "по умолчанию") : epu) + L("   Script block logging: ", "   Журнал блоков скриптов: ") + (sbl == 1 ? L("on", "включён") : L("off", "выключен"));
            var loose = new[] { ep, epu }.Where(x => string.Equals(x, "Bypass", StringComparison.OrdinalIgnoreCase) || string.Equals(x, "Unrestricted", StringComparison.OrdinalIgnoreCase)).ToList();
            if (loose.Count > 0) { it.State = HealthState.Warn; it.Text = L("PowerShell is set to run any script without a check (" + loose[0] + ").", "PowerShell настроен запускать любые скрипты без проверки (" + loose[0] + ")."); }
            else { it.State = HealthState.Good; it.Text = L("PowerShell's execution policy is the default or stricter.", "Политика выполнения PowerShell стандартная или строже."); }
            list.Add(it);
        }

        static void RemoteDesktop(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "rdp", Group = L("Network", "Сеть"), Title = L("Remote Desktop (RDP)", "Удалённый рабочий стол (RDP)"), OpenSettings = "remotedesktop" };
            int? deny = RegInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
            int? nla = RegInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
            if (deny == 0) { it.State = nla == 1 ? HealthState.Warn : HealthState.Bad; it.Text = L("Remote Desktop is ENABLED" + (nla == 1 ? " (with network-level authentication)" : " WITHOUT network-level authentication") + ". If you do not use it, turn it off.", "Удалённый рабочий стол ВКЛЮЧЁН" + (nla == 1 ? " (с проверкой подлинности на уровне сети)" : " БЕЗ проверки подлинности на уровне сети") + ". Если им не пользуетесь, выключите."); }
            else if (deny == 1) { it.State = HealthState.Good; it.Text = L("Remote Desktop connections are not allowed.", "Подключения по удалённому рабочему столу запрещены."); }
            else { it.State = HealthState.Unknown; it.Text = L("The Remote Desktop setting could not be read.", "Настройку удалённого рабочего стола прочитать не удалось."); }
            list.Add(it);
        }

        static readonly string[] RemoteToolNames = { "anydesk", "teamviewer", "rustdesk", "ultraviewer", "radmin", "winvnc", "tvnserver", "uvnc", "tightvnc", "realvnc", "vncserver", "litemanager", "ammyy", "splashtop", "screenconnect", "connectwise", "supremo", "aeroadmin", "remotepc", "dwservice", "meshagent", "chromoting", "remoting_host", "gotomypc", "logmein", "zohoassist", "dameware" };

        static void RemoteTools(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "remote", Group = L("Network", "Сеть"), Title = L("Remote-access programs", "Программы удалённого доступа") };
            var running = new List<string>(); var installed = new List<string>();
            try { foreach (var p in Process.GetProcesses()) using (p) { string n = p.ProcessName.ToLowerInvariant(); var hit = RemoteToolNames.FirstOrDefault(t => n.Contains(t)); if (hit != null) running.Add(p.ProcessName); } } catch { }
            try
            {
                foreach (var s in ServiceController.GetServices()) using (s) { string n = (s.ServiceName + " " + s.DisplayName).ToLowerInvariant(); var hit = RemoteToolNames.FirstOrDefault(t => n.Contains(t)); if (hit != null) installed.Add(s.DisplayName + " (" + s.Status + ")"); }
            }
            catch { }
            running = running.Distinct().ToList(); installed = installed.Distinct().ToList();
            it.Details = string.Join("\n", running.Select(x => L("running: ", "запущено: ") + x).Concat(installed.Select(x => L("service: ", "служба: ") + x)));
            if (running.Count + installed.Count == 0) { it.State = HealthState.Good; it.Text = L("No remote-access programs found.", "Программ удалённого доступа не найдено."); }
            else { it.State = HealthState.Info; it.Text = L("Found: ", "Найдено: ") + string.Join(", ", running.Concat(installed.Select(x => x.Split('(')[0].Trim())).Distinct().Take(5)) + L(". These are normal tools, but they are also what scammers ask people to install: remove what you do not use.", ". Это обычные программы, но именно их просят поставить мошенники: уберите то, чем не пользуетесь."); }
            list.Add(it);
        }

        static void Shares(System.Collections.Concurrent.ConcurrentBag<HealthItem> list)
        {
            var it = new HealthItem { Id = "shares", Group = L("Network", "Сеть"), Title = L("Shared folders and admin shares", "Общие папки и административные ресурсы") };
            var custom = new List<string>();
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Name, Path, Type FROM Win32_Share"))
                    foreach (ManagementObject o in s.Get())
                    {
                        string name = Convert.ToString(o["Name"]); uint type = Convert.ToUInt32(o["Type"]);
                        if (type == 2147483648u || type == 2147483649u || type == 2147483650u || type == 2147483651u) continue;       // ADMIN$, IPC$, C$ ... are the built-in ones
                        if (name.EndsWith("$") && (name.Length == 2 || name == "ADMIN$" || name == "IPC$" || name == "print$")) continue;
                        custom.Add(name + " -> " + Convert.ToString(o["Path"]));
                    }
            }
            catch { it.State = HealthState.Unknown; it.Text = L("The list of shares could not be read.", "Список общих ресурсов прочитать не удалось."); list.Add(it); return; }
            it.Details = string.Join("\n", custom);
            if (custom.Count == 0) { it.State = HealthState.Good; it.Text = L("Only Windows' own administrative shares exist.", "Есть только собственные административные ресурсы Windows."); }
            else { it.State = HealthState.Info; it.Text = L(custom.Count + " shared folder(s) besides Windows' own: ", custom.Count + " общих папок кроме встроенных: ") + string.Join(", ", custom.Select(x => x.Split(' ')[0]).Take(4)) + L(". Check that you shared them.", ". Убедитесь, что их открывали вы."); }
            list.Add(it);
        }

        // ------------------------------------------------------------------------------------------------ fixes (never run by a scan or a test)
        /// <summary>Applies one fix. Returns null on success or an error text. Only the fixes announced in HealthItem.FixId are accepted.</summary>
        public static string ApplyFix(string fixId)
        {
            try
            {
                if (fixId == "defender.rtp") return Ps("Set-MpPreference -DisableRealtimeMonitoring $false");
                if (fixId == "firewall.on") return Run("netsh.exe", "advfirewall set allprofiles state on");
                if (fixId == "smartscreen.on")
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", true)) { if (k == null) return "key not found"; k.SetValue("SmartScreenEnabled", "Warn", RegistryValueKind.String); }
                    return null;
                }
                if (fixId != null && fixId.StartsWith("defender.exclusion:"))
                {
                    string target = fixId.Substring("defender.exclusion:".Length);
                    if (target.StartsWith("*.") || target.StartsWith(".")) return Ps("Remove-MpPreference -ExclusionExtension '" + target.TrimStart('*').Replace("'", "''") + "'");
                    return Ps("Remove-MpPreference -ExclusionPath '" + target.Replace("'", "''") + "'");
                }
                return "unknown fix";
            }
            catch (Exception ex) { return ex.Message; }
        }

        static string Ps(string command) { return Run("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + command.Replace("\"", "\\\"") + "\""); }

        static string Run(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(psi))
            {
                string err = p.StandardError.ReadToEnd(); p.StandardOutput.ReadToEnd();
                if (!p.WaitForExit(30000)) { try { p.Kill(); } catch { } return "timed out"; }
                return p.ExitCode == 0 ? null : (string.IsNullOrWhiteSpace(err) ? "exit code " + p.ExitCode : err.Trim());
            }
        }
    }
}
