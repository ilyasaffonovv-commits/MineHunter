using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Risk;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Remediation
{
    /// <summary>Catches a threat that comes back after it was cleaned (a watchdog, a dropper or a scheduled job that was still alive, or a reboot that
    /// re-ran a persistence entry). The quarantine is the memory: everything MineHunter removed is recorded there with its original location, so any
    /// later scan - the next day, after a reboot - can ask "is it there again?". Restoring an item deliberately (Quarantine tab) is not a relapse and
    /// never counts.</summary>
    public static class Reappearance
    {
        public static readonly TimeSpan MinAge = TimeSpan.FromMinutes(3);      // a respawn inside a cleaning session is caught by the rescan verification itself
        public static readonly TimeSpan MaxAge = TimeSpan.FromDays(90);

        public static void Check(ScanContext ctx, ScanResult res)
        {
            List<QuarantineItem> items;
            try { items = Quarantine.List(); } catch { return; }
            int back = 0;
            foreach (var it in items)
            {
                try
                {
                    DateTime created;
                    if (!DateTime.TryParse(it.Created, null, System.Globalization.DateTimeStyles.RoundtripKind, out created)) continue;
                    var age = DateTime.Now - created;
                    if (age < MinAge || age > MaxAge) continue;
                    if (it.Extra != null && it.Extra.ContainsKey("restoredAt")) continue;
                    bool identical;
                    string where = Present(it, out identical);
                    if (where == null) continue;
                    if (Flag(ctx, it, where, identical, created)) back++;
                }
                catch (Exception ex) { Log.Warn("reappearance " + it.Id + ": " + ex.Message); }
            }
            if (back > 0)
                res.PreviousScanIssues.Add(back + " item(s) that MineHunter removed earlier are back. Something is re-creating them - a watchdog process, a dropper or a scheduled job that is still active. See the findings marked \"came back\".");
        }

        /// <summary>Where the removed item is present again (null = it is not).</summary>
        static string Present(QuarantineItem it, out bool identical)
        {
            identical = false;
            switch (it.Type)
            {
                case "File":
                case "StartupItem":
                    {
                        string p = it.OriginalPath;
                        if (string.IsNullOrEmpty(p) || !File.Exists(p)) return null;
                        string sha = Hashing.Sha256(p);
                        identical = sha != null && string.Equals(sha, it.Sha256, StringComparison.OrdinalIgnoreCase);
                        return p;
                    }
                case "Task":
                    {
                        string tp = Str(it, "taskPath") ?? it.OriginalPath;
                        if (string.IsNullOrEmpty(tp)) return null;
                        if (File.Exists(Path.Combine(PathUtil.System32, "Tasks", tp.TrimStart('\\')))) return tp;
                        try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" + tp.TrimStart('\\'))) if (k != null) return tp; } catch { }
                        return null;
                    }
                case "Service":
                    {
                        string name = Str(it, "serviceName");
                        if (string.IsNullOrEmpty(name)) return null;
                        using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name)) return k == null ? null : "service " + name;
                    }
                case "RegistryValue":
                    {
                        string hive = Str(it, "hive"), key = Str(it, "key"), value = Str(it, "value");
                        if (hive == null || key == null || value == null) return null;
                        using (var k = RegExport.OpenHive(hive, key, false))
                        {
                            if (k == null || Array.IndexOf(k.GetValueNames(), value) < 0) return null;
                            object data = Str(it, "data");
                            string now = Convert.ToString(k.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                            identical = data != null && string.Equals(now, Convert.ToString(data), StringComparison.OrdinalIgnoreCase);
                            // a value that was RESTORED to its default (Winlogon Shell ...) exists by design: it only counts when it again holds what we removed
                            var kind = it.Extra.ContainsKey("kind") ? Convert.ToString(it.Extra["kind"]) : "String";
                            if (!identical && (key.IndexOf("Winlogon", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("Lsa", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("Windows NT\\CurrentVersion\\Windows", StringComparison.OrdinalIgnoreCase) >= 0)) return null;
                            return hive + "\\" + key + "\\" + value;
                        }
                    }
                case "DefenderExclusion":
                    {
                        string kind = Str(it, "kind"), value = Str(it, "value");
                        bool policy = it.Extra != null && it.Extra.ContainsKey("policy") && Convert.ToBoolean(it.Extra["policy"]);
                        if (kind == null || value == null) return null;
                        string sub = (policy ? @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\" : @"SOFTWARE\Microsoft\Windows Defender\Exclusions\") + kind;
                        try { using (var k = Registry.LocalMachine.OpenSubKey(sub)) if (k != null && Array.IndexOf(k.GetValueNames(), value) >= 0) return "Defender exclusion " + value; } catch { }
                        return null;
                    }
                case "Wmi":
                    {
                        string cls = Str(it, "consumerClass"), name = Str(it, "consumerName");
                        if (cls == null || name == null) return null;
                        try
                        {
                            string wns = it.Extra != null && it.Extra.ContainsKey("namespace") ? Convert.ToString(it.Extra["namespace"]) : @"root\subscription";
                            if (!System.Text.RegularExpressions.Regex.IsMatch(wns, @"^root(\\[A-Za-z0-9_]+)*$")) return null;
                            var scope = new ManagementScope(@"\\.\" + wns); scope.Connect();
                            using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name FROM " + cls + " WHERE Name='" + name.Replace("'", "''") + "'")))
                                foreach (ManagementBaseObject o in q.Get()) return "WMI " + cls + " " + name;
                        }
                        catch { }
                        return null;
                    }
                case "BrowserExtension":
                    {
                        string dir = Str(it, "dir");
                        return !string.IsNullOrEmpty(dir) && Directory.Exists(dir) ? dir : null;
                    }
                case "Stream":
                    {
                        string host = Str(it, "host"), stream = Str(it, "stream");
                        if (host == null || stream == null || !File.Exists(host)) return null;
                        return AdsScanner.Streams(host).Any(x => string.Equals(x.Name, stream, StringComparison.OrdinalIgnoreCase)) ? host + ":" + stream : null;
                    }
            }
            return null;
        }

        static string Str(QuarantineItem it, string key) { object v; return it.Extra != null && it.Extra.TryGetValue(key, out v) && v != null ? Convert.ToString(v) : null; }

        static bool Flag(ScanContext ctx, QuarantineItem it, string where, bool identical, DateTime removed)
        {
            string text = "Removed by MineHunter on " + removed.ToString("yyyy-MM-dd HH:mm") + " and found here again" + (identical ? " with exactly the same content" : "") + ": something is re-creating it";
            Entity target = FindEntity(ctx, it, where);
            if (target != null && target.Trusted) return false;                               // approved by the user since: not a relapse
            if (target == null)
                target = ctx.GetOrAdd("relapse:" + it.Id, EntityKind.PolicyValue, () => new Entity { Title = "Came back after cleaning: " + it.Title, Location = where });
            target.Add(new Evidence("REL.REAPPEARED", EvidenceCategory.Reputation, identical ? 60 : 45, text, where, identical));
            return true;
        }

        static Entity FindEntity(ScanContext ctx, QuarantineItem it, string where)
        {
            switch (it.Type)
            {
                case "File":
                case "StartupItem":
                    return ctx.Files.Inspect(it.OriginalPath, FileRole.Referenced);
                case "Stream":
                    return ctx.Files.Inspect(Str(it, "host"), FileRole.Referenced);
                case "Task":
                    {
                        string tp = Str(it, "taskPath") ?? it.OriginalPath;
                        return ctx.Entities.Values.FirstOrDefault(e => e.Kind == EntityKind.Task && string.Equals(e.P("taskPath"), tp, StringComparison.OrdinalIgnoreCase));
                    }
                case "Service":
                    {
                        string name = Str(it, "serviceName");
                        return ctx.Entities.Values.FirstOrDefault(e => (e.Kind == EntityKind.Service || e.Kind == EntityKind.Driver) && string.Equals(e.Title, name, StringComparison.OrdinalIgnoreCase));
                    }
                case "RegistryValue":
                    return ctx.Entities.Values.FirstOrDefault(e => string.Equals(e.P("hive"), Str(it, "hive"), StringComparison.OrdinalIgnoreCase) && string.Equals(e.P("key"), Str(it, "key"), StringComparison.OrdinalIgnoreCase) && string.Equals(e.P("value"), Str(it, "value"), StringComparison.OrdinalIgnoreCase));
                case "Wmi":
                    return ctx.Entities.Values.FirstOrDefault(e => e.Kind == EntityKind.Wmi && string.Equals(e.P("consumer"), Str(it, "consumerName"), StringComparison.OrdinalIgnoreCase));
                case "DefenderExclusion":
                    return ctx.Entities.Values.FirstOrDefault(e => e.Kind == EntityKind.DefenderExclusion && string.Equals(e.P("value"), Str(it, "value"), StringComparison.OrdinalIgnoreCase));
                case "BrowserExtension":
                    return ctx.Entities.Values.FirstOrDefault(e => e.Kind == EntityKind.BrowserExtension && string.Equals(e.P("dir"), Str(it, "dir"), StringComparison.OrdinalIgnoreCase));
            }
            return null;
        }
    }

    /// <summary>Safety nets taken before MineHunter changes anything: a Windows restore point when Windows will make one. MineHunter's own backup (the
    /// quarantine, which keeps the original file, task XML, service and registry data of everything it removes) always exists in addition.</summary>
    public static class SafetyNet
    {
        /// <summary>Tries to create a System Restore point. Never throws; returns a plain-language result for the log/report.</summary>
        public static string TryCreateRestorePoint(string description)
        {
            try
            {
                int before = CountPoints();
                var cls = new ManagementClass(new ManagementScope(@"\\.\root\default"), new ManagementPath("SystemRestore"), null);
                var args = cls.GetMethodParameters("CreateRestorePoint");
                args["Description"] = description; args["RestorePointType"] = 12; args["EventType"] = 100;          // MODIFY_SETTINGS / BEGIN_SYSTEM_CHANGE
                var ret = cls.InvokeMethod("CreateRestorePoint", args, null);
                uint rc = ret == null ? 0xFFFFFFFF : Convert.ToUInt32(ret["ReturnValue"]);
                int after = CountPoints();
                if (rc == 0 && after > before) return "A Windows restore point was created (\"" + description + "\").";
                if (rc == 0) return "Windows did not create a restore point (by default it makes at most one per 24 hours). MineHunter's own quarantine backup covers everything it removes.";
                return "Windows could not create a restore point (code " + rc + "; System Protection may be off). MineHunter's own quarantine backup covers everything it removes.";
            }
            catch (Exception ex)
            {
                return "No restore point (" + ex.Message.Split('\n')[0].Trim() + "; System Protection may be off). MineHunter's own quarantine backup covers everything it removes.";
            }
        }

        static int CountPoints()
        {
            try
            {
                using (var q = new ManagementObjectSearcher(@"root\default", "SELECT SequenceNumber FROM SystemRestore"))
                    return q.Get().Count;
            }
            catch { return -1; }
        }
    }
}
