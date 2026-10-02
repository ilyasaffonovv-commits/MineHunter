using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MineHunter.Remediation;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter
{
    public sealed class DriverInfo
    {
        public string Name, Manufacturer, DeviceId, HardwareId, Version, Provider, Signer, Inf, DeviceClass, Category, Problem;
        public List<string> HardwareIds = new List<string>();
        public DateTime? Date; public bool Signed;
        public int AgeDays { get { return Date.HasValue ? (int)(DateTime.Now - Date.Value).TotalDays : -1; } }
    }

    public enum DriverRisk { Normal, NeedsConfirmation, Never }

    public sealed class DriverUpdate
    {
        public string Title, Manufacturer, Provider, Class, UpdateId, Source = "Windows Update", Reason;
        public DateTime? Date; public string Version; public long SizeBytes; public bool Downloaded;
        public List<string> HardwareIds = new List<string>();
        public DriverRisk Risk = DriverRisk.Normal;
        public DriverInfo Installed;                // the device this update is for (matched by Hardware ID)
        public object Handle;                       // the source's own object (Windows Update update), not used by tests
    }

    public interface IDriverUpdateSource { List<DriverUpdate> Search(CancellationToken ct); }
    public interface IDriverInstaller { string Install(DriverUpdate u, Action<string> log); }

    /// <summary>The technical driver page. It lists what is installed (device, maker, Hardware ID, version, date, provider, signature, state) and asks Windows Update - Microsoft's own,
    /// signed channel - what newer drivers exist for exactly these devices. It never fetches drivers from third-party sites, and it never touches BIOS or firmware.
    /// For vendors with their own download pages (NVIDIA, AMD, Intel, the PC maker) it only points to the official page.</summary>
    public static class Drivers
    {
        static string L(string en, string ru) { return Loc.L(en, ru); }

        // ------------------------------------------------------------------------------------------------ inventory
        public static List<DriverInfo> Inventory()
        {
            var list = new List<DriverInfo>();
            var problems = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT DeviceID, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0"))
                    foreach (ManagementObject o in s.Get()) problems[Convert.ToString(o["DeviceID"])] = Convert.ToInt32(o["ConfigManagerErrorCode"]);
            }
            catch { }
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT DeviceName, Manufacturer, DeviceID, HardWareID, DriverVersion, DriverDate, DriverProviderName, IsSigned, Signer, InfName, DeviceClass FROM Win32_PnPSignedDriver WHERE DeviceName IS NOT NULL"))
                    foreach (ManagementObject o in s.Get())
                    {
                        var d = new DriverInfo
                        {
                            Name = Convert.ToString(o["DeviceName"]), Manufacturer = Convert.ToString(o["Manufacturer"]), DeviceId = Convert.ToString(o["DeviceID"]),
                            Version = Convert.ToString(o["DriverVersion"]), Provider = Convert.ToString(o["DriverProviderName"]), Signer = Convert.ToString(o["Signer"]),
                            Inf = Convert.ToString(o["InfName"]), DeviceClass = Convert.ToString(o["DeviceClass"])
                        };
                        try { d.Signed = Convert.ToBoolean(o["IsSigned"]); } catch { }
                        try { string dt = Convert.ToString(o["DriverDate"]); if (!string.IsNullOrEmpty(dt)) d.Date = ManagementDateTimeConverter.ToDateTime(dt); } catch { }
                        object hw = o["HardWareID"];
                        if (hw is string[]) d.HardwareIds.AddRange(((string[])hw).Where(x => !string.IsNullOrEmpty(x))); else if (hw is string && !string.IsNullOrEmpty((string)hw)) d.HardwareIds.Add((string)hw);
                        d.HardwareId = d.HardwareIds.FirstOrDefault() ?? d.DeviceId;
                        int pc; if (problems.TryGetValue(d.DeviceId ?? "", out pc)) d.Problem = L("problem code " + pc, "ошибка устройства, код " + pc);
                        d.Category = Category(d);
                        list.Add(d);
                    }
            }
            catch (Exception ex) { Log.Warn("driver inventory: " + ex.Message); }
            return list.OrderBy(d => CategoryOrder(d.Category)).ThenBy(d => d.Name).ToList();
        }

        public static string Category(DriverInfo d)
        {
            string c = (d.DeviceClass ?? "").ToUpperInvariant(), n = (d.Name ?? "").ToLowerInvariant();
            switch (c)
            {
                case "DISPLAY": return L("Graphics", "Видеокарта");
                case "NET":
                    return n.Contains("wi-fi") || n.Contains("wifi") || n.Contains("wireless") || n.Contains("802.11") || n.Contains("wlan") ? L("Wi-Fi", "Wi-Fi") : L("Network", "Сеть");
                case "BLUETOOTH": return "Bluetooth";
                case "MEDIA": case "AUDIOENDPOINT": return L("Audio", "Звук");
                case "HDC": case "SCSIADAPTER": case "STORAGEVOLUME": case "DISKDRIVE": case "NVME": return L("Storage", "Накопители");
                case "USB": return "USB";
                case "HIDCLASS": case "KEYBOARD": case "MOUSE": return L("Input", "Ввод");
                case "SYSTEM": case "PROCESSOR": case "COMPUTER": return L("System / chipset", "Система / чипсет");
                case "CAMERA": case "IMAGE": return L("Camera", "Камера");
                case "MONITOR": return L("Monitor", "Монитор");
                default: return L("Other", "Прочее");
            }
        }

        static int CategoryOrder(string c)
        {
            string[] order = { L("Graphics", "Видеокарта"), L("System / chipset", "Система / чипсет"), "Wi-Fi", L("Network", "Сеть"), "Bluetooth", L("Audio", "Звук"), L("Storage", "Накопители"), "USB", L("Input", "Ввод"), L("Camera", "Камера"), L("Monitor", "Монитор") };
            int i = Array.IndexOf(order, c); return i < 0 ? 99 : i;
        }

        /// <summary>Drivers that are worth showing first: not a Microsoft in-box driver, or with a problem.</summary>
        public static bool IsInteresting(DriverInfo d)
        {
            return d.Problem != null || !(d.Provider ?? "").StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) || !d.Signed;
        }

        // ------------------------------------------------------------------------------------------------ official vendor pages
        /// <summary>The official download page for the maker of this device (opened in the browser; MineHunter downloads nothing from it), or null.</summary>
        public static string VendorPage(DriverInfo d)
        {
            string hw = ((d.HardwareId ?? "") + " " + string.Join(" ", d.HardwareIds)).ToUpperInvariant();
            string maker = ((d.Manufacturer ?? "") + " " + (d.Provider ?? "")).ToLowerInvariant();
            if (hw.Contains("VEN_10DE") || maker.Contains("nvidia")) return "https://www.nvidia.com/Download/index.aspx";
            if (hw.Contains("VEN_1002") || maker.Contains("advanced micro devices") || maker.Contains("amd")) return "https://www.amd.com/en/support/download/drivers.html";
            if (hw.Contains("VEN_8086") || maker.Contains("intel")) return "https://www.intel.com/content/www/us/en/support/detect.html";
            if (maker.Contains("realtek")) return "https://www.realtek.com/Download";
            if (maker.Contains("qualcomm") || maker.Contains("atheros")) return "https://www.qualcomm.com/support";
            if (maker.Contains("mediatek") || maker.Contains("ralink")) return "https://www.mediatek.com/products/connectivity-and-networking/software-and-driver-downloads";
            return null;
        }

        /// <summary>The support page of the maker of this PC (from the system information), or null.</summary>
        public static string OemSupportPage()
        {
            string m = "";
            try { using (var s = new ManagementObjectSearcher("SELECT Manufacturer FROM Win32_ComputerSystem")) foreach (ManagementObject o in s.Get()) m = Convert.ToString(o["Manufacturer"]).ToLowerInvariant(); } catch { }
            if (m.Contains("asus")) return "https://www.asus.com/support/download-center/";
            if (m.Contains("dell")) return "https://www.dell.com/support/home";
            if (m.Contains("hewlett") || m.Contains("hp")) return "https://support.hp.com/drivers";
            if (m.Contains("lenovo")) return "https://support.lenovo.com";
            if (m.Contains("micro-star") || m.Contains("msi")) return "https://www.msi.com/support/download/";
            if (m.Contains("gigabyte")) return "https://www.gigabyte.com/Support";
            if (m.Contains("acer")) return "https://www.acer.com/support";
            if (m.Contains("samsung")) return "https://www.samsung.com/support/";
            return null;
        }

        // ------------------------------------------------------------------------------------------------ classification of updates
        static readonly string[] NeverWords = { "bios", "uefi", "firmware", "microcode", "embedded controller", "ec firmware", "prom" };
        static readonly string[] ConfirmWords = { "storage controller", "rapid storage", "raid", "nvme", "ahci", "management engine", "chipset", "sata", "smbus", "serial io", "hid event filter", "thunderbolt", "dock", "platform" };

        /// <summary>BIOS, UEFI, firmware and microcode are never automated; storage controllers, chipset and management-engine drivers need an explicit confirmation.</summary>
        public static DriverRisk Classify(DriverUpdate u)
        {
            string t = ((u.Title ?? "") + " " + (u.Class ?? "") + " " + (u.Manufacturer ?? "")).ToLowerInvariant();
            if (NeverWords.Any(w => System.Text.RegularExpressions.Regex.IsMatch(t, @"\b" + System.Text.RegularExpressions.Regex.Escape(w) + @"\b"))) { u.Reason = L("Firmware and BIOS updates are not automated by MineHunter: take them from the PC maker's site, with the PC on mains power.", "Обновления прошивки и BIOS MineHunter не автоматизирует: берите их на сайте производителя ПК, при питании от сети."); return DriverRisk.Never; }
            if (ConfirmWords.Any(w => t.Contains(w)) || string.Equals(u.Class, "SCSIAdapter", StringComparison.OrdinalIgnoreCase) || string.Equals(u.Class, "HDC", StringComparison.OrdinalIgnoreCase)) { u.Reason = L("This driver controls storage or the chipset: a bad one can stop Windows from starting. Install only with a backup and a restore point.", "Этот драйвер управляет накопителями или чипсетом: неудачный может помешать запуску Windows. Ставьте только с резервной копией и точкой восстановления."); return DriverRisk.NeedsConfirmation; }
            return DriverRisk.Normal;
        }

        /// <summary>The device an update is meant for: it must share a Hardware ID with an installed device. Null when none matches.</summary>
        public static DriverInfo MatchDevice(DriverUpdate u, IEnumerable<DriverInfo> installed)
        {
            var ids = new HashSet<string>(u.HardwareIds.Select(Norm), StringComparer.OrdinalIgnoreCase);
            if (ids.Count == 0) return null;
            foreach (var d in installed)
                foreach (var h in d.HardwareIds) if (ids.Contains(Norm(h))) return d;
            return null;
        }

        static string Norm(string h) { return (h ?? "").Trim().ToUpperInvariant(); }

        /// <summary>Why this update must NOT be installed, or null when it may go ahead (to be asked again right before installing).</summary>
        public static string CheckInstallable(DriverUpdate u, IEnumerable<DriverInfo> installed)
        {
            if (u == null) return L("no update", "обновление не выбрано");
            if (Classify(u) == DriverRisk.Never) return u.Reason;
            var dev = MatchDevice(u, installed);
            if (dev == null) return L("Its Hardware ID does not match any installed device, so it is not installed.", "Его Hardware ID не совпадает ни с одним установленным устройством, поэтому оно не ставится.");
            u.Installed = dev;
            if (string.IsNullOrEmpty(u.UpdateId)) return L("The update has no identity from its source.", "У обновления нет идентификатора от источника.");
            if (!string.Equals(u.Source, "Windows Update", StringComparison.OrdinalIgnoreCase)) return L("Only Windows Update (Microsoft's signed channel) is accepted as a source.", "Принимается только Windows Update (подписанный канал Microsoft).");
            if (u.Date.HasValue && dev.Date.HasValue && u.Date.Value < dev.Date.Value.AddDays(-1)) return L("The offered driver is older than the installed one.", "Предлагаемый драйвер старше установленного.");
            return null;
        }

        // ------------------------------------------------------------------------------------------------ update search
        public static List<DriverUpdate> SearchUpdates(CancellationToken ct, IDriverUpdateSource source = null)
        {
            var found = (source ?? new WindowsUpdateSource()).Search(ct) ?? new List<DriverUpdate>();
            var installed = Inventory();
            foreach (var u in found) { u.Installed = MatchDevice(u, installed); Classify(u); u.Risk = Classify(u); }
            return found;
        }

        // ------------------------------------------------------------------------------------------------ backup, install, rollback
        public static string BackupRoot { get { return Path.Combine(RulePack.DataDir, "drivers"); } }

        /// <summary>Saves what is installed for the device (a JSON note) and exports the driver package (pnputil /export-driver) so it can be put back. Returns the folder.</summary>
        public static string Backup(DriverInfo d, Action<string> log)
        {
            string dir = Path.Combine(BackupRoot, DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Safe(d.Name));
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "driver.json"), Json.Pretty(Json.Serialize(new Dictionary<string, object>
            {
                { "device", d.Name }, { "deviceId", d.DeviceId }, { "hardwareId", d.HardwareId }, { "hardwareIds", d.HardwareIds.ToArray() }, { "manufacturer", d.Manufacturer }, { "provider", d.Provider },
                { "version", d.Version }, { "date", d.Date.HasValue ? d.Date.Value.ToString("yyyy-MM-dd") : null }, { "inf", d.Inf }, { "signer", d.Signer }, { "signed", d.Signed }, { "saved", DateTime.Now.ToString("o") }
            })), new UTF8Encoding(false));
            if (!string.IsNullOrEmpty(d.Inf) && d.Inf.StartsWith("oem", StringComparison.OrdinalIgnoreCase))
            {
                string err = Run("pnputil.exe", "/export-driver " + d.Inf + " \"" + Path.Combine(dir, "package") + "\"");
                if (log != null) log(err == null ? "old driver package exported" : "old driver package not exported: " + err);
                if (err == null) Directory.CreateDirectory(Path.Combine(dir, "package"));
            }
            return dir;
        }

        /// <summary>Puts the saved driver package back (pnputil /add-driver ... /install). Returns null on success.</summary>
        public static string Rollback(string backupDir)
        {
            string pkg = Path.Combine(backupDir, "package");
            if (!Directory.Exists(pkg)) return L("The backup folder has no driver package (the old driver was a Windows in-box one: use Device Manager > Roll Back Driver).", "В резервной папке нет пакета драйвера (старый драйвер был встроенным в Windows: используйте Диспетчер устройств > Откатить драйвер).");
            var inf = Directory.GetFiles(pkg, "*.inf", SearchOption.AllDirectories).FirstOrDefault();
            if (inf == null) return L("No .inf file in the backup.", "В резервной копии нет .inf файла.");
            return Run("pnputil.exe", "/add-driver \"" + inf + "\" /install");
        }

        public static List<string> Backups()
        {
            try { return Directory.Exists(BackupRoot) ? Directory.GetDirectories(BackupRoot).OrderByDescending(x => x).ToList() : new List<string>(); } catch { return new List<string>(); }
        }

        /// <summary>Installs one update: re-checks everything (never trusts the list the window showed), makes a restore point, saves the old driver, installs through the source.
        /// <paramref name="confirmedRisk"/> must be true for drivers that need confirmation. Returns null on success or the reason.</summary>
        public static string Install(DriverUpdate u, bool confirmedRisk, Action<string> log, IDriverInstaller installer = null, Func<string, string> restorePoint = null, IEnumerable<DriverInfo> installedNow = null)
        {
            log = log ?? (m => { });
            var installed = (installedNow ?? Inventory()).ToList();
            string bad = CheckInstallable(u, installed);
            if (bad != null) return bad;
            if (Classify(u) == DriverRisk.NeedsConfirmation && !confirmedRisk) return L("This driver needs an explicit confirmation (storage / chipset).", "Для этого драйвера нужно явное подтверждение (накопители / чипсет).");
            log("checked: Hardware ID matches " + u.Installed.Name + ", source Windows Update");
            string rp = (restorePoint ?? (t => SafetyNet.TryCreateRestorePoint(t)))("MineHunter: driver " + u.Title);
            log("restore point: " + rp);
            string backup = null;
            try { backup = Backup(u.Installed, log); log("old driver saved: " + backup); }
            catch (Exception ex) { return L("The old driver could not be saved (" + ex.Message + "), so nothing was installed.", "Старый драйвер не удалось сохранить (" + ex.Message + "), поэтому ничего не установлено."); }
            string err = (installer ?? new WindowsUpdateInstaller()).Install(u, log);
            if (err != null) return err + L("  The old driver note is in " + backup + ".", "  Данные о старом драйвере: " + backup + ".");
            log("installed");
            return null;
        }

        static string Safe(string s) { foreach (var c in Path.GetInvalidFileNameChars()) s = (s ?? "device").Replace(c, '_'); return s.Length > 40 ? s.Substring(0, 40) : s; }

        static string Run(string exe, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd(), e = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(120000)) { try { p.Kill(); } catch { } return "timed out"; }
                    return p.ExitCode == 0 ? null : (string.IsNullOrWhiteSpace(e) ? o.Trim() : e.Trim());
                }
            }
            catch (Exception ex) { return ex.Message; }
        }
    }

    /// <summary>Asks the Windows Update Agent (the same component Windows uses) for driver updates that apply to this PC. Read-only.</summary>
    public sealed class WindowsUpdateSource : IDriverUpdateSource
    {
        public List<DriverUpdate> Search(CancellationToken ct)
        {
            var res = new List<DriverUpdate>();
            Type t = Type.GetTypeFromProgID("Microsoft.Update.Session");
            if (t == null) throw new InvalidOperationException("Windows Update Agent is not available");
            dynamic session = Activator.CreateInstance(t);
            dynamic searcher = session.CreateUpdateSearcher();
            dynamic result = null; Exception err = null;
            var task = Task.Run(() => { try { result = searcher.Search("IsInstalled=0 and Type='Driver'"); } catch (Exception ex) { err = ex; } });
            while (!task.Wait(500)) { if (ct.IsCancellationRequested) throw new OperationCanceledException(); }
            if (err != null) throw err;
            foreach (dynamic u in result.Updates)
            {
                var d = new DriverUpdate { Title = Convert.ToString(u.Title), Manufacturer = Convert.ToString(u.DriverManufacturer), Provider = Convert.ToString(u.DriverProvider), Class = Convert.ToString(u.DriverClass), Handle = (object)u };
                try { d.UpdateId = Convert.ToString(u.Identity.UpdateID); } catch { }
                try { d.Date = (DateTime)u.DriverVerDate; } catch { }
                try { d.SizeBytes = (long)(decimal)u.MaxDownloadSize; } catch { }
                try { d.Downloaded = (bool)u.IsDownloaded; } catch { }
                try { string hw = Convert.ToString(u.DriverHardwareID); if (!string.IsNullOrEmpty(hw)) d.HardwareIds.Add(hw); } catch { }
                string title = d.Title ?? ""; var m = System.Text.RegularExpressions.Regex.Match(title, @"(\d+(\.\d+){1,3})\s*$"); if (m.Success) d.Version = m.Groups[1].Value;
                res.Add(d);
            }
            return res;
        }
    }

    public sealed class WindowsUpdateInstaller : IDriverInstaller
    {
        public string Install(DriverUpdate u, Action<string> log)
        {
            try
            {
                Type ts = Type.GetTypeFromProgID("Microsoft.Update.Session"), tc = Type.GetTypeFromProgID("Microsoft.Update.UpdateColl");
                dynamic session = Activator.CreateInstance(ts);
                dynamic found = session.CreateUpdateSearcher().Search("UpdateID='" + u.UpdateId.Replace("'", "") + "'");
                if (found.Updates.Count == 0) return "Windows Update no longer offers this driver";
                dynamic coll = Activator.CreateInstance(tc);
                coll.Add(found.Updates.Item(0));
                dynamic dl = session.CreateUpdateDownloader(); dl.Updates = coll;
                log("downloading from Windows Update");
                dynamic dr = dl.Download(); if ((int)dr.ResultCode != 2) return "download did not succeed (code " + (int)dr.ResultCode + ")";
                dynamic inst = session.CreateUpdateInstaller(); inst.Updates = coll;
                log("installing");
                dynamic ir = inst.Install();
                int code = (int)ir.ResultCode;
                if (code != 2) return "installation did not succeed (code " + code + ")";
                if ((bool)ir.RebootRequired) log("restart required");
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }
    }
}
