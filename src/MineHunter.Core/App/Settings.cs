using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter
{
    /// <summary>Everything the user can set in the program. Stored in the protected data folder (settings.json): a program without administrator rights cannot
    /// widen the exclusions or switch protection off by editing it. Unknown or damaged values fall back to the defaults, never to "less protection".</summary>
    public sealed class Settings
    {
        // ---- general
        public string Preset = "Normal";            // Normal | Strict | Developer
        public bool StartTrayAtLogon = false;       // the tray program starts when the user signs in (scheduled task, no Windows prompt)
        public bool CloseToTray = false;
        public bool GameMode = true;                // no heavy work and no non-critical notifications while a full-screen game or presentation is on screen

        // ---- scanning
        public string Sensitivity = "Normal";       // Normal | Strict | Paranoid: how many independent signals are needed before something is reported
        public int CpuLimit = 0;                    // 0 = automatic (the scan yields to other programs); 10..100 = the scan will not use more than this share of the CPU
        public int Threads = 0;                     // 0 = automatic
        public bool ScanArchives = true;
        public int MaxFileSizeMb = 512;             // files above this size are not read for markers (they are still checked by signature and name)
        public bool ScanNetworkDrives = false;
        public bool ScanRemovable = false;          // a full scan also walks USB drives and memory cards
        public bool ScanMemory = true;
        public bool ScanBrowsers = true;
        public int FullScanMaxMinutes = 0;          // 0 = until it is finished (you can stop it at any moment)
        public bool OtherUserHives = true;

        // ---- real-time layer (works while the tray program runs; monitors and reacts, it does not sit in the kernel)
        public bool FileGuard = true;
        public bool DownloadGuard = true;
        public bool ProcessGuard = true;
        public bool ScriptGuard = true;
        public bool PersistenceGuard = true;
        public bool NetworkGuard = true;
        public bool UsbGuard = true;
        public bool RansomwareGuard = false;
        public bool UsbAutoCheck = true;

        // ---- exclusions (the user's own, checked by the scanner; a file is also excluded by its SHA-256 in the allow-list)
        public List<string> ExcludedPaths = new List<string>();
        public List<string> ExcludedPublishers = new List<string>();

        // ---- schedule (Windows Task Scheduler)
        public bool ScheduleEnabled = false;
        public string ScheduleMode = "Quick";       // Quick | Full | Custom
        public string ScheduleEvery = "Daily";      // Daily | Every3Days | Weekly | Monthly | CustomDays
        public int ScheduleCustomDays = 2;
        public string ScheduleTime = "13:00";
        public string ScheduleDayOfWeek = "Sunday";
        public int ScheduleDayOfMonth = 1;
        public bool ScheduleRunMissed = true;
        public bool ScheduleOnlyIdle = false;
        public bool ScheduleNotOnBattery = true;
        public bool ScheduleStopOnBattery = true;
        public bool ScheduleNotifyOnlyIfFound = true;
        public List<string> ScheduleCustomPaths = new List<string>();

        // ---- updates
        public bool AutoUpdateApp = true;           // download verified new versions in the background; installing needs a click (or the next start)
        public bool InstallAppUpdateSilently = false;
        public string LastUpdateCheck = "";

        // ---- notifications
        public string NotifyLevel = "Suspicious";   // Info | Suspicious | Dangerous: the lowest level that shows a notification
        public bool NotifySound = false;

        // ---- reputation and privacy
        public bool CloudLookup = false;            // MineHunter Cloud (hash + size only). Off: nothing leaves the PC
        public bool VirusTotalLookup = false;       // optional, hash lookup only, your own key
        public string VirusTotalKeyProtected = "";  // DPAPI (machine scope) protected API key, base64

        // ---- interface
        public string Theme = "Dark";
        public bool ShowNotesInResults = false;

        // ---- remembered facts
        public string LastQuickScan = "", LastFullScan = "";
        public string FirstRunDone = "";

        public static string FilePath { get { return Path.Combine(RulePack.DataDir, "settings.json"); } }

        static readonly object Lock = new object();
        static Settings _current;
        /// <summary>The loaded settings (re-read when <see cref="Reload"/> is called).</summary>
        public static Settings Current { get { lock (Lock) return _current ?? (_current = Load()); } }
        public static void Reload() { lock (Lock) _current = Load(); }

        public static Settings Load() { return Load(FilePath); }

        public static Settings Load(string file)
        {
            var s = new Settings();
            try
            {
                if (!File.Exists(file)) return s;
                var d = Json.Obj(Json.Parse(File.ReadAllText(file)));
                if (d == null) return s;
                foreach (var f in typeof(Settings).GetFields(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (!d.ContainsKey(f.Name)) continue;
                    object v = d[f.Name];
                    try
                    {
                        if (f.FieldType == typeof(bool)) f.SetValue(s, Convert.ToBoolean(v));
                        else if (f.FieldType == typeof(int)) f.SetValue(s, Convert.ToInt32(v));
                        else if (f.FieldType == typeof(string)) f.SetValue(s, Convert.ToString(v) ?? "");
                        else if (f.FieldType == typeof(List<string>)) f.SetValue(s, (Json.Arr(v) ?? new object[0]).Select(x => Convert.ToString(x)).Where(x => !string.IsNullOrWhiteSpace(x)).ToList());
                    }
                    catch { }
                }
                s.Normalize();
            }
            catch (Exception ex) { Log.Warn("settings " + file + ": " + ex.Message); }
            return s;
        }

        public void Save() { Save(FilePath); }

        public void Save(string file)
        {
            try
            {
                Normalize();
                Directory.CreateDirectory(Path.GetDirectoryName(file));
                var d = new Dictionary<string, object>();
                foreach (var f in typeof(Settings).GetFields(BindingFlags.Public | BindingFlags.Instance))
                {
                    object v = f.GetValue(this);
                    if (v is List<string>) v = ((List<string>)v).ToArray();
                    d[f.Name] = v;
                }
                Fs.WriteDurable(file, new System.Text.UTF8Encoding(false).GetBytes(Json.Pretty(Json.Serialize(d))));
                lock (Lock) _current = this;
            }
            catch (Exception ex) { Log.Warn("settings not saved: " + ex.Message); }
        }

        /// <summary>Puts every value into its allowed range.</summary>
        public void Normalize()
        {
            Preset = OneOf(Preset, "Normal", "Strict", "Developer");
            Sensitivity = OneOf(Sensitivity, "Normal", "Strict", "Paranoid");
            ScheduleMode = OneOf(ScheduleMode, "Quick", "Full", "Custom");
            ScheduleEvery = OneOf(ScheduleEvery, "Daily", "Every3Days", "Weekly", "Monthly", "CustomDays");
            NotifyLevel = OneOf(NotifyLevel, "Info", "Suspicious", "Dangerous");
            Theme = OneOf(Theme, "Dark");
            ScheduleDayOfWeek = OneOf(ScheduleDayOfWeek, "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday");
            if (CpuLimit != 0) CpuLimit = Math.Max(10, Math.Min(100, CpuLimit));
            Threads = Math.Max(0, Math.Min(32, Threads));
            MaxFileSizeMb = Math.Max(1, Math.Min(8192, MaxFileSizeMb));
            FullScanMaxMinutes = Math.Max(0, Math.Min(24 * 60, FullScanMaxMinutes));
            ScheduleCustomDays = Math.Max(1, Math.Min(365, ScheduleCustomDays));
            ScheduleDayOfMonth = Math.Max(1, Math.Min(28, ScheduleDayOfMonth));
            TimeSpan t; if (!TimeSpan.TryParseExact(ScheduleTime ?? "", @"hh\:mm", null, out t)) ScheduleTime = "13:00";
            ExcludedPaths = (ExcludedPaths ?? new List<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            ExcludedPublishers = (ExcludedPublishers ?? new List<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            ScheduleCustomPaths = (ScheduleCustomPaths ?? new List<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        static string OneOf(string v, params string[] allowed)
        {
            foreach (var a in allowed) if (string.Equals(a, v, StringComparison.OrdinalIgnoreCase)) return a;
            return allowed[0];
        }

        /// <summary>The preset changes only the scan behaviour that depends on the kind of PC: a developer's machine is full of unsigned build output.</summary>
        public void ApplyPreset(string preset)
        {
            Preset = OneOf(preset, "Normal", "Strict", "Developer");
            switch (Preset)
            {
                case "Strict": Sensitivity = "Strict"; ScanArchives = true; ScanRemovable = true; NotifyLevel = "Info"; break;
                case "Developer": Sensitivity = "Normal"; NotifyLevel = "Suspicious"; break;
                default: Sensitivity = "Normal"; ScanRemovable = false; NotifyLevel = "Suspicious"; break;
            }
        }

        /// <summary>0 = Normal, 1 = Strict, 2 = Paranoid.</summary>
        public int SensitivityLevel { get { return Sensitivity == "Paranoid" ? 2 : Sensitivity == "Strict" ? 1 : 0; } }
        public bool DeveloperContext { get { return Preset == "Developer"; } }

        // ---- exclusions -------------------------------------------------------------------------------------------------
        public bool IsExcludedPath(string path)
        {
            if (string.IsNullOrEmpty(path) || ExcludedPaths.Count == 0) return false;
            foreach (var e in ExcludedPaths)
            {
                try { if (PathUtil.Same(path, e) || PathUtil.IsUnder(path, e)) return true; } catch { }
            }
            return false;
        }

        public bool AddExclusion(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            // the Windows folder, the drive root and the whole user profile are not valid exclusions: they would switch the scan off
            string n = PathUtil.Normalize(path).TrimEnd('\\');
            if (n.Length <= 3 || PathUtil.Same(n, PathUtil.WinDir) || PathUtil.Same(n, PathUtil.System32) || PathUtil.Same(n, PathUtil.ProgramFiles) || PathUtil.Same(n, PathUtil.ProgramData)) return false;
            foreach (var up in PathUtil.UserProfiles()) if (PathUtil.Same(n, up)) return false;
            if (!ExcludedPaths.Contains(path, StringComparer.OrdinalIgnoreCase)) ExcludedPaths.Add(path);
            return true;
        }

        // ---- protected API key (DPAPI, machine scope) -----------------------------------------------------------------------
        public void SetVirusTotalKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) { VirusTotalKeyProtected = ""; return; }
            var raw = System.Text.Encoding.UTF8.GetBytes(key.Trim());
            VirusTotalKeyProtected = Convert.ToBase64String(System.Security.Cryptography.ProtectedData.Protect(raw, null, System.Security.Cryptography.DataProtectionScope.LocalMachine));
        }

        public string GetVirusTotalKey()
        {
            try
            {
                if (string.IsNullOrEmpty(VirusTotalKeyProtected)) return null;
                return System.Text.Encoding.UTF8.GetString(System.Security.Cryptography.ProtectedData.Unprotect(Convert.FromBase64String(VirusTotalKeyProtected), null, System.Security.Cryptography.DataProtectionScope.LocalMachine));
            }
            catch { return null; }
        }
    }
}
