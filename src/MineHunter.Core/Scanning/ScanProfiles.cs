using System;
using System.Collections.Generic;
using System.Linq;
using MineHunter.Update;

namespace MineHunter.Scanning
{
    /// <summary>The one place that turns "Quick / Full / Custom" plus the user's settings into scan options. The main window, Quick Scan.exe, Full Scan.exe, the
    /// scheduled scan and the command line all call this, so the same profile always gives the same scan.</summary>
    public static class ScanProfiles
    {
        public static ScanOptions Build(ScanMode mode, Settings s, AppConfig cfg, IEnumerable<string> paths = null, ScanProgress live = null)
        {
            s = s ?? new Settings(); cfg = cfg ?? new AppConfig();
            var o = new ScanOptions
            {
                Mode = mode,
                Browsers = s.ScanBrowsers && cfg.ScanBrowsers,
                MemoryInspection = s.ScanMemory && cfg.ScanMemory,
                MaxFileSizeMbForContentScan = s.MaxFileSizeMb,
                ScanArchives = s.ScanArchives,
                OtherUserHives = s.OtherUserHives,
                Sensitivity = s.SensitivityLevel,
                DeveloperContext = s.DeveloperContext,
                CpuLimit = s.CpuLimit,
                IncludeRemovable = s.ScanRemovable,
                IncludeNetwork = s.ScanNetworkDrives,
                MaxFullScanMinutes = s.FullScanMaxMinutes,
                UserSettings = s,
                Live = live
            };
            if (s.Threads > 0) o.Parallelism = s.Threads;
            else if (s.CpuLimit > 0 && s.CpuLimit <= 40) o.Parallelism = Math.Max(1, Math.Min(o.Parallelism, 2));
            if (paths != null) { o.CustomPaths = paths.Where(p => !string.IsNullOrWhiteSpace(p)).ToList(); if (o.CustomPaths.Count > 0) o.CustomPath = o.CustomPaths[0]; }
            return o;
        }

        public static ScanOptions Quick(Settings s, AppConfig cfg, ScanProgress live = null) { return Build(ScanMode.Quick, s, cfg, null, live); }
        public static ScanOptions Full(Settings s, AppConfig cfg, ScanProgress live = null) { return Build(ScanMode.Full, s, cfg, null, live); }
        public static ScanOptions Custom(Settings s, AppConfig cfg, IEnumerable<string> paths, ScanProgress live = null) { return Build(ScanMode.Custom, s, cfg, paths, live); }

        /// <summary>The name shown for a mode ("Quick scan" / "Быстрая проверка").</summary>
        public static string ModeName(string mode)
        {
            switch (mode)
            {
                case "Quick": return Loc.L("Quick scan", "Быстрая проверка");
                case "Full": return Loc.L("Full scan", "Полная проверка");
                case "Custom": return Loc.L("Custom scan", "Выборочная проверка");
                default: return mode ?? "";
            }
        }
    }
}
