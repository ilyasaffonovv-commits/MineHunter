using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Risk;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Remediation
{
    public sealed class StepResult
    {
        public RemediationStep Step; public bool Success; public string Message; public bool RebootPending; public string QuarantineId;
    }

    public sealed class RemediationOutcome
    {
        public List<StepResult> Results = new List<StepResult>();
        public bool RebootRequired { get { return Results.Any(r => r.RebootPending); } }
        public int Ok { get { return Results.Count(r => r.Success); } }
        public int Failed { get { return Results.Count(r => !r.Success && r.Step.Type != ActionType.ReviewOnly); } }
    }

    // ==================================================================================================
    //   registry helpers (export/import as JSON so that deleted keys can be restored exactly)
    // ==================================================================================================
    public static class RegExport
    {
        public static RegistryKey OpenHive(string hive, string subKey, bool writable, bool create = false)
        {
            RegistryKey root; string sub = subKey;
            if (hive == "HKLM") root = Registry.LocalMachine;
            else if (hive == "HKCU") root = Registry.CurrentUser;
            else if (hive != null && hive.StartsWith("HKU\\")) { root = Registry.Users; sub = hive.Substring(4) + "\\" + subKey; }
            else throw new ArgumentException("unknown hive " + hive);
            return create ? root.CreateSubKey(sub) : root.OpenSubKey(sub, writable);
        }

        public static Dictionary<string, object> Export(RegistryKey k)
        {
            var d = new Dictionary<string, object>();
            var vals = new List<object>();
            foreach (var n in k.GetValueNames())
            {
                var kind = k.GetValueKind(n); object v = k.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                var e = new Dictionary<string, object> { { "n", n }, { "k", kind.ToString() } };
                switch (kind)
                {
                    case RegistryValueKind.Binary: case RegistryValueKind.None: e["v"] = Convert.ToBase64String((byte[])v); break;
                    case RegistryValueKind.MultiString: e["v"] = (string[])v; break;
                    case RegistryValueKind.QWord: e["v"] = Convert.ToString((long)v); break;
                    case RegistryValueKind.DWord: e["v"] = Convert.ToString(unchecked((uint)(int)v)); break;
                    default: e["v"] = Convert.ToString(v); break;
                }
                vals.Add(e);
            }
            d["values"] = vals.ToArray();
            var subs = new Dictionary<string, object>();
            foreach (var s in k.GetSubKeyNames()) using (var sk = k.OpenSubKey(s)) if (sk != null) subs[s] = Export(sk);
            d["subkeys"] = subs;
            return d;
        }

        public static void Import(RegistryKey target, Dictionary<string, object> d, bool overwrite = true)
        {
            var vals = Json.Arr(d.ContainsKey("values") ? d["values"] : null);
            if (vals != null)
                foreach (var o in vals)
                {
                    var e = Json.Obj(o); string n = Json.Str(e, "n", ""); string kind = Json.Str(e, "k", "String");
                    if (!overwrite && Array.IndexOf(target.GetValueNames(), n) >= 0) continue;
                    var kd = (RegistryValueKind)Enum.Parse(typeof(RegistryValueKind), kind);
                    object v = e.ContainsKey("v") ? e["v"] : null;
                    switch (kd)
                    {
                        case RegistryValueKind.Binary: case RegistryValueKind.None: target.SetValue(n, Convert.FromBase64String(Convert.ToString(v)), RegistryValueKind.Binary); break;
                        case RegistryValueKind.MultiString: target.SetValue(n, Json.Arr(v).Select(x => Convert.ToString(x)).ToArray(), kd); break;
                        case RegistryValueKind.QWord: target.SetValue(n, Convert.ToInt64(Convert.ToString(v)), kd); break;
                        case RegistryValueKind.DWord: target.SetValue(n, unchecked((int)Convert.ToUInt32(Convert.ToString(v))), kd); break;
                        default: target.SetValue(n, Convert.ToString(v), kd); break;
                    }
                }
            var subs = Json.Obj(d.ContainsKey("subkeys") ? d["subkeys"] : null);
            if (subs != null) foreach (var kv in subs) using (var sk = target.CreateSubKey(kv.Key)) Import(sk, Json.Obj(kv.Value), overwrite);
        }
    }

    // ==================================================================================================
    //   the engine
    // ==================================================================================================
    public static class RemediationEngine
    {
        static string Sys32(string exe) { return Path.Combine(PathUtil.System32, exe); }

        public static int RunTool(string exe, string args, int timeoutMs, out string output)
        {
            output = "";
            try
            {
                var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.GetEncoding(866), StandardErrorEncoding = Encoding.GetEncoding(866) };
                using (var p = Process.Start(psi))
                {
                    var so = p.StandardOutputReadToEndAsync(); var se = p.StandardErrorReadToEndAsync();
                    if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } output = "timeout"; return -1; }
                    output = (so.Result + " " + se.Result).Trim();
                    return p.ExitCode;
                }
            }
            catch (Exception ex) { output = ex.Message; return -2; }
        }

        static System.Threading.Tasks.Task<string> StandardOutputReadToEndAsync(this StreamReader r) { return System.Threading.Tasks.Task.Run(() => r.ReadToEnd()); }
        static System.Threading.Tasks.Task<string> StandardOutputReadToEndAsync(this Process p) { return System.Threading.Tasks.Task.Run(() => p.StandardOutput.ReadToEnd()); }
        static System.Threading.Tasks.Task<string> StandardErrorReadToEndAsync(this Process p) { return System.Threading.Tasks.Task.Run(() => p.StandardError.ReadToEnd()); }

        public static RemediationOutcome Execute(ScanContext ctx, Finding f, IEnumerable<RemediationStep> selected, Action<string> log)
        {
            var outcome = new RemediationOutcome();
            var steps = selected.Where(s => s.Type != ActionType.ReviewOnly).OrderBy(s => s.Order).ToList();
            var byId = f.Entities.ToDictionary(e => e.Id, e => e, StringComparer.OrdinalIgnoreCase);
            Action<string> L = m => { Log.Info(m); if (log != null) log(m); };

            // 0. freeze every targeted process first so that a watchdog cannot respawn things while we clean
            var frozen = new List<int>();
            foreach (var s in steps.Where(x => x.Type == ActionType.KillProcess))
            {
                int pid; DateTime start;
                if (!ParseProc(s.Target, out pid, out start) || !SameProcess(pid, start)) continue;
                if (SystemOps.Suspend(pid)) { frozen.Add(pid); L("suspended PID " + pid); }
            }

            foreach (var s in steps)
            {
                Entity e; byId.TryGetValue(s.EntityId, out e);
                var r = new StepResult { Step = s };
                try { Do(ctx, f, s, e, r, L); }
                catch (Exception ex) { r.Success = false; r.Message = "unexpected error: " + ex.Message; }
                L((r.Success ? "[OK] " : "[FAILED] ") + s.Description + (string.IsNullOrEmpty(r.Message) ? "" : " - " + r.Message));
                outcome.Results.Add(r);
            }
            foreach (var pid in frozen) { try { using (var p = Process.GetProcessById(pid)) { if (!p.HasExited) SystemOps.Resume(pid); } } catch { } }   // anything still alive but not killed is released again
            return outcome;
        }

        static bool ParseProc(string t, out int pid, out DateTime start)
        {
            pid = 0; start = default(DateTime);
            var parts = (t ?? "").Split('|');
            if (parts.Length < 1 || !int.TryParse(parts[0], out pid)) return false;
            if (parts.Length > 1 && !string.IsNullOrEmpty(parts[1])) DateTime.TryParse(parts[1], null, System.Globalization.DateTimeStyles.RoundtripKind, out start);
            return true;
        }

        static bool SameProcess(int pid, DateTime startUtc)
        {
            try
            {
                using (var p = Process.GetProcessById(pid))
                {
                    if (p.HasExited) return false;
                    if (startUtc == default(DateTime)) return true;
                    return Math.Abs((p.StartTime.ToUniversalTime() - startUtc.ToUniversalTime()).TotalSeconds) < 3;
                }
            }
            catch { return false; }
        }

        static void Do(ScanContext ctx, Finding f, RemediationStep s, Entity e, StepResult r, Action<string> L)
        {
            switch (s.Type)
            {
                case ActionType.KillProcess: KillProcess(s, e, r); break;
                case ActionType.QuarantineFile: case ActionType.RemoveStartupItem: QuarantineFile(f, s, e, r); break;
                case ActionType.QuarantineTask: QuarantineTask(f, s, e, r); break;
                case ActionType.QuarantineService: QuarantineService(f, s, e, r); break;
                case ActionType.RemoveRunValue: case ActionType.RemoveRegistryValue: case ActionType.RestoreDefaultValue: RegistryValue(f, s, e, r); break;
                case ActionType.RemoveWmiSubscription: RemoveWmi(f, s, e, r); break;
                case ActionType.RemoveDefenderExclusion: RemoveExclusion(f, s, e, r); break;
                case ActionType.RemoveHostsLines: RemoveHosts(f, s, e, r); break;
                case ActionType.RemoveFirewallRule: RemoveFirewall(f, s, e, r); break;
                case ActionType.RemoveBrowserExtension: RemoveExtension(f, s, e, r); break;
                default: r.Success = false; r.Message = "not supported"; break;
            }
        }

        // ------------------------------------------------------------------------------------------ processes
        static void KillProcess(RemediationStep s, Entity e, StepResult r)
        {
            int pid; DateTime start;
            if (!ParseProc(s.Target, out pid, out start)) { r.Message = "bad target"; return; }
            if (e != null && Decision.IsProtectedProcess(e)) { r.Message = "critical Windows process - refused"; return; }
            if (!SameProcess(pid, start)) { r.Success = true; r.Message = "already gone"; return; }
            try
            {
                using (var p = Process.GetProcessById(pid))
                {
                    p.Kill();
                    if (!p.WaitForExit(5000)) { r.Message = "the process did not exit"; return; }
                }
                r.Success = true;
            }
            catch (Exception ex) { r.Success = !SameProcess(pid, start); r.Message = r.Success ? "already gone" : ex.Message; }
        }

        // ------------------------------------------------------------------------------------------ files
        static void QuarantineFile(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            string path = s.Target;
            if (!File.Exists(path)) { r.Success = true; r.Message = "already gone"; return; }
            if (e != null && Decision.IsProtectedFile(null, e)) { r.Message = "trusted/system file - refused"; return; }
            string err;
            string type = s.Type == ActionType.RemoveStartupItem ? "StartupItem" : "File";
            var it = Quarantine.StoreFile(type, path, f.Title, string.Join("; ", f.TopEvidence.Take(3).Select(x => x.Text)), out err);
            if (it == null) { r.Message = "could not make a safe copy first (" + err + ") - the file was left untouched"; return; }
            r.QuarantineId = it.Id;
            try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
            for (int i = 0; i < 4; i++)
            {
                try { File.Delete(path); if (!File.Exists(path)) { r.Success = true; r.Message = "moved to quarantine (id " + it.Id + ")"; return; } }
                catch { }
                System.Threading.Thread.Sleep(400);
            }
            // locked: rename (allowed for running images) so it can never be started from that path again, then delete at reboot
            string renamed = path + ".mh_quarantined";
            try { File.Move(path, renamed); } catch { renamed = path; }
            if (SystemOps.ScheduleDeleteOnReboot(renamed)) { r.Success = true; r.RebootPending = true; r.Message = "file is in use - safe copy stored (id " + it.Id + "), the original is renamed and will be deleted at the next restart"; }
            else { r.Message = "file is locked and could not be scheduled for deletion; safe copy stored (id " + it.Id + ")"; }
        }

        // ------------------------------------------------------------------------------------------ tasks
        static void QuarantineTask(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            string tp = s.Target;
            string xmlFile = Path.Combine(PathUtil.System32, "Tasks", tp.TrimStart('\\'));
            byte[] raw = File.Exists(xmlFile) ? File.ReadAllBytes(xmlFile) : null;
            var extra = new Dictionary<string, object> { { "taskPath", tp } };
            var it = raw != null
                ? Quarantine.StoreBytes("Task", tp, tp, raw, f.Title, "scheduled task", extra)
                : Quarantine.StoreRecord("Task", tp, tp, extra, f.Title, "scheduled task (XML was missing - hidden from the task store)");
            r.QuarantineId = it.Id;
            string outp;
            int rc = RunTool(Sys32("schtasks.exe"), "/delete /tn \"" + tp + "\" /f", 20000, out outp);
            bool gone = !File.Exists(xmlFile);
            if (!gone || rc != 0) RemoveTaskCache(tp);
            gone = !File.Exists(xmlFile) && !TaskCacheHas(tp);
            r.Success = gone; r.Message = gone ? "removed (saved as quarantine item " + it.Id + ")" : "task still present: " + outp;
        }

        static bool TaskCacheHas(string tp)
        {
            try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" + tp.TrimStart('\\'))) return k != null; } catch { return false; }
        }
        static void RemoveTaskCache(string tp)
        {
            try
            {
                string tree = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" + tp.TrimStart('\\');
                string id = null;
                using (var k = Registry.LocalMachine.OpenSubKey(tree)) if (k != null) id = Convert.ToString(k.GetValue("Id"));
                Registry.LocalMachine.DeleteSubKeyTree(tree, false);
                if (!string.IsNullOrEmpty(id)) Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\" + id, false);
                string file = Path.Combine(PathUtil.System32, "Tasks", tp.TrimStart('\\')); if (File.Exists(file)) File.Delete(file);
            }
            catch { }
        }

        // ------------------------------------------------------------------------------------------ services / drivers
        static void QuarantineService(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            string name = s.Target;
            if (!Regex.IsMatch(name, @"^[A-Za-z0-9_\-\.\$@ ]{1,256}$")) { r.Message = "unsafe service name"; return; }
            string keyPath = @"SYSTEM\CurrentControlSet\Services\" + name;
            Dictionary<string, object> export;
            using (var k = Registry.LocalMachine.OpenSubKey(keyPath))
            {
                if (k == null) { r.Success = true; r.Message = "already gone"; return; }
                export = RegExport.Export(k);
            }
            var extra = new Dictionary<string, object> { { "serviceName", name }, { "registry", export } };
            var it = Quarantine.StoreRecord("Service", name, "Service " + name, extra, f.Title, "service / driver");
            r.QuarantineId = it.Id;
            string o;
            RunTool(Sys32("sc.exe"), "stop \"" + name + "\"", 15000, out o);
            // if the service process refuses to stop, kill the service process itself
            try
            {
                using (var q = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Service WHERE Name='" + name.Replace("'", "''") + "'"))
                    foreach (ManagementObject m in q.Get()) { int pid = Convert.ToInt32(m["ProcessId"]); if (pid > 4) try { using (var p = Process.GetProcessById(pid)) if (Path.GetFileName(p.MainModule.FileName).ToLowerInvariant() != "svchost.exe") { p.Kill(); p.WaitForExit(4000); } } catch { } }
            }
            catch { }
            RunTool(Sys32("sc.exe"), "config \"" + name + "\" start= disabled", 10000, out o);
            int rc = RunTool(Sys32("sc.exe"), "delete \"" + name + "\"", 15000, out o);
            bool gone; using (var k2 = Registry.LocalMachine.OpenSubKey(keyPath)) gone = k2 == null;
            if (gone) { r.Success = true; r.Message = "removed (saved as quarantine item " + it.Id + ")"; }
            else if (o.IndexOf("marked for deletion", StringComparison.OrdinalIgnoreCase) >= 0 || o.IndexOf("1072", StringComparison.OrdinalIgnoreCase) >= 0 || rc == 0) { r.Success = true; r.RebootPending = true; r.Message = "disabled and marked for deletion - it disappears after the next restart"; }
            else r.Message = "could not delete: " + o;
        }

        // ------------------------------------------------------------------------------------------ registry values
        static void RegistryValue(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            if (e == null) { r.Message = "entity missing"; return; }
            string hive = e.P("hive"), key = e.P("key"), value = e.P("value");
            if (hive == null || key == null || value == null)
            {
                // policy values carry hive\key\value in the target
                var m = Regex.Match(s.Target ?? "", @"^(HKLM|HKCU)\\(.+)\\([^\\]+)$");
                if (!m.Success) { r.Message = "registry location unknown"; return; }
                hive = m.Groups[1].Value; key = m.Groups[2].Value; value = m.Groups[3].Value;
            }
            using (var k = RegExport.OpenHive(hive, key, true))
            {
                if (k == null) { r.Success = true; r.Message = "already gone"; return; }
                if (Array.IndexOf(k.GetValueNames(), value) < 0) { r.Success = true; r.Message = "already gone"; return; }
                var kind = k.GetValueKind(value); object old = k.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                var rec = new Dictionary<string, object> { { "hive", hive }, { "key", key }, { "value", value }, { "kind", kind.ToString() }, { "data", RegValueToJson(kind, old) } };
                var it = Quarantine.StoreRecord("RegistryValue", hive + "\\" + key + "\\" + value, hive + "\\" + key + "\\" + value, rec, f.Title, "autostart / policy value");
                r.QuarantineId = it.Id;

                if (s.Type == ActionType.RestoreDefaultValue && !string.IsNullOrEmpty(e.P("default")))
                    k.SetValue(value, e.P("default"), RegistryValueKind.String);
                else if ((value == "Authentication Packages" || value == "Notification Packages" || value == "Security Packages") && old is string[])
                    k.SetValue(value, ((string[])old).Where(x => !string.Equals(x.Trim().Trim('"'), e.P("data"), StringComparison.OrdinalIgnoreCase)).ToArray(), RegistryValueKind.MultiString);
                else if (value == "AppInit_DLLs") { k.SetValue(value, "", RegistryValueKind.String); try { k.SetValue("LoadAppInit_DLLs", 0, RegistryValueKind.DWord); } catch { } }
                else if (kind == RegistryValueKind.MultiString && e.P("data") != null && old is string[] && value == "BootExecute")
                    k.SetValue(value, ((string[])old).Where(x => x.Trim() != e.P("data")).ToArray(), RegistryValueKind.MultiString);
                else k.DeleteValue(value, false);
                r.Success = true; r.Message = "changed (saved as quarantine item " + it.Id + ")";
            }
        }

        static object RegValueToJson(RegistryValueKind kind, object v)
        {
            switch (kind)
            {
                case RegistryValueKind.Binary: case RegistryValueKind.None: return Convert.ToBase64String((byte[])v);
                case RegistryValueKind.MultiString: return (string[])v;
                case RegistryValueKind.QWord: return Convert.ToString((long)v);
                case RegistryValueKind.DWord: return Convert.ToString(unchecked((uint)(int)v));
                default: return Convert.ToString(v);
            }
        }
        public static void SetRegValueFromJson(RegistryKey k, string name, string kind, object data)
        {
            var kd = (RegistryValueKind)Enum.Parse(typeof(RegistryValueKind), kind);
            switch (kd)
            {
                case RegistryValueKind.Binary: case RegistryValueKind.None: k.SetValue(name, Convert.FromBase64String(Convert.ToString(data)), RegistryValueKind.Binary); break;
                case RegistryValueKind.MultiString: k.SetValue(name, Json.Arr(data).Select(x => Convert.ToString(x)).ToArray(), kd); break;
                case RegistryValueKind.QWord: k.SetValue(name, Convert.ToInt64(Convert.ToString(data)), kd); break;
                case RegistryValueKind.DWord: k.SetValue(name, unchecked((int)Convert.ToUInt32(Convert.ToString(data))), kd); break;
                default: k.SetValue(name, Convert.ToString(data), kd); break;
            }
        }

        // ------------------------------------------------------------------------------------------ WMI
        static void RemoveWmi(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            if (e == null) { r.Message = "entity missing"; return; }
            string cls = e.P("wmiClass"), cname = e.P("consumer"), fname = e.P("filter");
            var scope = new ManagementScope(@"\\.\root\subscription"); scope.Connect();
            var rec = new Dictionary<string, object> { { "consumerClass", cls }, { "consumerName", cname }, { "filterName", fname } };
            ManagementObject consumer = null, filter = null;
            using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + cls + " WHERE Name='" + cname.Replace("'", "''") + "'"))) foreach (ManagementObject o in q.Get()) { consumer = o; break; }
            if (!string.IsNullOrEmpty(fname))
                using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter WHERE Name='" + fname.Replace("'", "''") + "'"))) foreach (ManagementObject o in q.Get()) { filter = o; break; }
            if (consumer == null && filter == null) { r.Success = true; r.Message = "already gone"; return; }
            if (consumer != null) rec["consumer"] = PropsOf(consumer);
            if (filter != null) rec["filter"] = PropsOf(filter);
            var it = Quarantine.StoreRecord("Wmi", cls + ":" + cname, "WMI " + cls + " " + cname, rec, f.Title, "WMI permanent event subscription");
            r.QuarantineId = it.Id;
            using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
                foreach (ManagementObject b in q.Get())
                {
                    string c = Convert.ToString(b["Consumer"]), fl = Convert.ToString(b["Filter"]);
                    if (c.IndexOf("Name=\"" + cname + "\"", StringComparison.OrdinalIgnoreCase) >= 0) b.Delete();
                }
            if (consumer != null) consumer.Delete();
            if (filter != null)
            {
                bool used = false;
                using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
                    foreach (ManagementObject b in q.Get()) if (Convert.ToString(b["Filter"]).IndexOf("Name=\"" + fname + "\"", StringComparison.OrdinalIgnoreCase) >= 0) used = true;
                if (!used) filter.Delete();
            }
            // verify
            bool still = false;
            using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + cls + " WHERE Name='" + cname.Replace("'", "''") + "'"))) foreach (ManagementObject o in q.Get()) still = true;
            r.Success = !still; r.Message = still ? "the subscription is still present" : "removed (saved as quarantine item " + it.Id + ")";
        }

        static Dictionary<string, object> PropsOf(ManagementObject o)
        {
            var d = new Dictionary<string, object>();
            foreach (PropertyData p in o.Properties)
            {
                if (p.Value == null || p.Name.StartsWith("__")) continue;
                if (p.Value is string || p.Value is bool || p.Value is int || p.Value is uint || p.Value is long) d[p.Name] = Convert.ToString(p.Value);
                else if (p.Value is string[]) d[p.Name] = (string[])p.Value;
            }
            return d;
        }

        // ------------------------------------------------------------------------------------------ Defender exclusions
        static void RemoveExclusion(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            var parts = s.Target.Split('|');
            if (parts.Length < 3) { r.Message = "bad target"; return; }
            string kind = parts[0], value = parts[1]; bool policy = parts[2] == "True";
            string sub = (policy ? @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\" : @"SOFTWARE\Microsoft\Windows Defender\Exclusions\") + kind;
            var rec = new Dictionary<string, object> { { "kind", kind }, { "value", value }, { "policy", policy } };
            var it = Quarantine.StoreRecord("DefenderExclusion", kind + ": " + value, kind + ": " + value, rec, f.Title, "Defender exclusion");
            r.QuarantineId = it.Id;
            try { using (var k = Registry.LocalMachine.OpenSubKey(sub, true)) if (k != null) k.DeleteValue(value, false); } catch { }
            bool still = ExclusionExists(sub, value);
            if (still && !policy && Regex.IsMatch(value, @"^[^'""`;$&|<>]{1,400}$"))
            {
                string cmdlet = kind == "Paths" ? "Remove-MpPreference -ExclusionPath" : kind == "Processes" ? "Remove-MpPreference -ExclusionProcess" : "Remove-MpPreference -ExclusionExtension";
                string o;
                RunTool(Sys32(@"WindowsPowerShell\v1.0\powershell.exe"), "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + cmdlet + " '" + value + "'\"", 30000, out o);
                still = ExclusionExists(sub, value);
            }
            r.Success = !still;
            r.Message = still ? "Windows refused to remove it (Tamper Protection or a policy) - remove it manually in Windows Security" : "removed (saved as quarantine item " + it.Id + ")";
        }
        static bool ExclusionExists(string sub, string value)
        {
            try { using (var k = Registry.LocalMachine.OpenSubKey(sub)) return k != null && Array.IndexOf(k.GetValueNames(), value) >= 0; } catch { return false; }
        }

        // ------------------------------------------------------------------------------------------ hosts
        static void RemoveHosts(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            string hosts = Path.Combine(PathUtil.System32, @"drivers\etc\hosts");
            var bad = new HashSet<string>((e.P("lines") ?? "").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0));
            if (bad.Count == 0) { r.Message = "nothing to remove"; return; }
            var lines = File.ReadAllLines(hosts);
            var it = Quarantine.StoreBytes("HostsBackup", "hosts", hosts, File.ReadAllBytes(hosts), f.Title, "hosts file backup before removing security-site blocks");
            r.QuarantineId = it.Id;
            var kept = lines.Where(l => !bad.Contains(l.Trim())).ToArray();
            try { File.SetAttributes(hosts, FileAttributes.Normal); } catch { }
            File.WriteAllLines(hosts, kept, new UTF8Encoding(false));
            r.Success = true; r.Message = "removed " + (lines.Length - kept.Length) + " line(s); full backup saved as item " + it.Id;
        }

        // ------------------------------------------------------------------------------------------ firewall
        static void RemoveFirewall(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            string name = s.Target;
            var rec = new Dictionary<string, object> { { "name", name }, { "app", e == null ? "" : e.P("app") } };
            var it = Quarantine.StoreRecord("FirewallRule", name, "Firewall rule " + name, rec, f.Title, "firewall rule");
            r.QuarantineId = it.Id;
            Type t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            dynamic pol = Activator.CreateInstance(t);
            pol.Rules.Remove(name);
            r.Success = true; r.Message = "removed";
        }

        // ------------------------------------------------------------------------------------------ browser extension
        static void RemoveExtension(Finding f, RemediationStep s, Entity e, StepResult r)
        {
            string dir = s.Target;
            if (!Directory.Exists(dir)) { r.Success = true; r.Message = "already gone"; return; }
            string tmp = Path.Combine(Path.GetTempPath(), "mh_ext_" + Guid.NewGuid().ToString("N") + ".zip");
            try
            {
                ZipFile.CreateFromDirectory(dir, tmp, CompressionLevel.Fastest, true);
                var it = Quarantine.StoreBytes("BrowserExtension", e == null ? Path.GetFileName(dir) : (e.P("name") ?? e.Title), dir, File.ReadAllBytes(tmp), f.Title, "browser/editor extension", new Dictionary<string, object> { { "dir", dir } });
                r.QuarantineId = it.Id;
                Directory.Delete(dir, true);
                r.Success = !Directory.Exists(dir);
                r.Message = r.Success ? "removed (saved as quarantine item " + it.Id + ")" : "some files are locked - close the browser and try again";
            }
            catch (Exception ex) { r.Message = ex.Message + " (close the browser and try again)"; }
            finally { try { File.Delete(tmp); } catch { } }
        }

        // ==================================================================================================
        //   restore
        // ==================================================================================================
        public static string Restore(QuarantineItem it, string alternateFilePath = null)
        {
            try
            {
                switch (it.Type)
                {
                    case "File": case "StartupItem":
                        {
                            string target = alternateFilePath ?? it.OriginalPath;
                            return Quarantine.RestoreFileTo(it, target, false);
                        }
                    case "Task":
                        {
                            string tp = Convert.ToString(it.Extra["taskPath"]);
                            if (it.PayloadFile == null) return "this item has no stored task XML (the task was hidden), cannot restore";
                            byte[] xml = Quarantine.ReadPayload(it);
                            string tmp = Path.Combine(Path.GetTempPath(), "mh_task_" + Guid.NewGuid().ToString("N") + ".xml");
                            File.WriteAllBytes(tmp, xml);
                            try { string o; int rc = RunTool(Sys32("schtasks.exe"), "/create /xml \"" + tmp + "\" /tn \"" + tp + "\" /f", 30000, out o); return rc == 0 ? null : o; }
                            finally { try { File.Delete(tmp); } catch { } }
                        }
                    case "Service":
                        {
                            string name = Convert.ToString(it.Extra["serviceName"]);
                            var reg = Json.Obj(it.Extra["registry"]);
                            string image = null, disp = null, obj = null; int type = 0x10, start = 3;
                            foreach (var o in Json.Arr(reg["values"]))
                            {
                                var v = Json.Obj(o); string n = Json.Str(v, "n");
                                if (n == "ImagePath") image = Json.Str(v, "v"); else if (n == "DisplayName") disp = Json.Str(v, "v"); else if (n == "ObjectName") obj = Json.Str(v, "v");
                                else if (n == "Type") type = (int)Convert.ToUInt32(Json.Str(v, "v")); else if (n == "Start") start = (int)Convert.ToUInt32(Json.Str(v, "v"));
                            }
                            string kp = @"SYSTEM\CurrentControlSet\Services\" + name;
                            using (var probe = Registry.LocalMachine.OpenSubKey(kp)) if (probe != null) return "a service with this name exists already";
                            string startWord = start == 2 ? "auto" : start == 3 ? "demand" : start == 4 ? "disabled" : start == 1 ? "system" : "boot";
                            string args = "create \"" + name + "\" binPath= \"" + (image ?? "").Replace("\"", "\\\"") + "\" start= " + startWord + " type= " + ((type & 0x1) != 0 ? "kernel" : (type & 0x20) != 0 ? "share" : "own") + (string.IsNullOrEmpty(disp) ? "" : " DisplayName= \"" + disp + "\"") + (string.IsNullOrEmpty(obj) || obj == "LocalSystem" ? "" : " obj= \"" + obj + "\"");
                            string outp; RunTool(Sys32("sc.exe"), args, 15000, out outp);
                            using (var k = Registry.LocalMachine.CreateSubKey(kp)) RegExport.Import(k, reg, true);
                            return null;
                        }
                    case "RegistryValue":
                        {
                            string hive = Convert.ToString(it.Extra["hive"]), key = Convert.ToString(it.Extra["key"]), value = Convert.ToString(it.Extra["value"]);
                            using (var k = RegExport.OpenHive(hive, key, true, true)) SetRegValueFromJson(k, value, Convert.ToString(it.Extra["kind"]), it.Extra["data"]);
                            return null;
                        }
                    case "DefenderExclusion":
                        {
                            string kind = Convert.ToString(it.Extra["kind"]), value = Convert.ToString(it.Extra["value"]); bool policy = Convert.ToBoolean(it.Extra["policy"]);
                            string sub = (policy ? @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\" : @"SOFTWARE\Microsoft\Windows Defender\Exclusions\") + kind;
                            using (var k = Registry.LocalMachine.CreateSubKey(sub)) k.SetValue(value, 0, RegistryValueKind.DWord);
                            return null;
                        }
                    case "HostsBackup":
                        {
                            string hosts = Path.Combine(PathUtil.System32, @"drivers\etc\hosts");
                            try { File.SetAttributes(hosts, FileAttributes.Normal); } catch { }
                            File.WriteAllBytes(hosts, Quarantine.ReadPayload(it));
                            return null;
                        }
                    case "BrowserExtension":
                        {
                            string dir = Convert.ToString(it.Extra["dir"]);
                            if (Directory.Exists(dir)) return "the folder exists already";
                            string tmp = Path.Combine(Path.GetTempPath(), "mh_ext_" + Guid.NewGuid().ToString("N") + ".zip");
                            try { File.WriteAllBytes(tmp, Quarantine.ReadPayload(it)); ZipFile.ExtractToDirectory(tmp, dir); return null; }
                            finally { try { File.Delete(tmp); } catch { } }
                        }
                    case "Wmi":
                        return RestoreWmi(it);
                    case "FirewallRule": return "firewall rules are only recorded, not restorable automatically";
                    default: return "unknown item type " + it.Type;
                }
            }
            catch (Exception ex) { return ex.Message; }
        }

        static string RestoreWmi(QuarantineItem it)
        {
            var scope = new ManagementScope(@"\\.\root\subscription"); scope.Connect();
            string cls = Convert.ToString(it.Extra["consumerClass"]);
            Func<string, Dictionary<string, object>, ManagementObject> make = (c, props) =>
            {
                var mc = new ManagementClass(scope, new ManagementPath(c), null);
                var o = mc.CreateInstance();
                foreach (var kv in props)
                {
                    var arr = kv.Value as object[];
                    if (arr != null) o[kv.Key] = arr.Select(x => Convert.ToString(x)).ToArray(); else o[kv.Key] = Convert.ToString(kv.Value);
                }
                o.Put(); return o;
            };
            ManagementObject filter = null, consumer = null;
            if (it.Extra.ContainsKey("filter")) filter = make("__EventFilter", Json.Obj(it.Extra["filter"]));
            if (it.Extra.ContainsKey("consumer")) consumer = make(cls, Json.Obj(it.Extra["consumer"]));
            if (filter != null && consumer != null)
            {
                var bc = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null);
                var b = bc.CreateInstance();
                b["Filter"] = filter.Path.RelativePath; b["Consumer"] = consumer.Path.RelativePath;
                b.Put();
            }
            return null;
        }
    }
}
