using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter
{
    public sealed class StartupItem
    {
        public string Id, Kind, Name, Command, Target, Source, Publisher, Note, OriginalStart;
        public bool Enabled = true, Trusted, CanChange = true, Exists = true;
        public string KindText
        {
            get
            {
                switch (Kind)
                {
                    case "run": return Loc.L("Run key", "Автозапуск (реестр)");
                    case "folder": return Loc.L("Startup folder", "Папка автозагрузки");
                    case "task": return Loc.L("Scheduled task", "Задача планировщика");
                    case "service": return Loc.L("Service", "Служба");
                    default: return Loc.L("Special place", "Особое место");
                }
            }
        }
    }

    /// <summary>One list of everything that starts by itself, and a safe way to turn an item off and back on. Registry and folder items are switched with the same flag the Task Manager
    /// uses (StartupApproved), so nothing is deleted; tasks are disabled, not removed; a service's original start type is remembered so it can be put back exactly.</summary>
    public static class StartupManager
    {
        const string Approved = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\";
        static string L(string en, string ru) { return Loc.L(en, ru); }

        public static List<StartupItem> List(RulePack rules)
        {
            var list = new List<StartupItem>();
            try { RunKeys(list); } catch (Exception ex) { Log.Warn("startup (run): " + ex.Message); }
            try { Folders(list); } catch (Exception ex) { Log.Warn("startup (folders): " + ex.Message); }
            try { Tasks(list); } catch (Exception ex) { Log.Warn("startup (tasks): " + ex.Message); }
            try { Services(list); } catch (Exception ex) { Log.Warn("startup (services): " + ex.Message); }
            try { Special(list); } catch (Exception ex) { Log.Warn("startup (special): " + ex.Message); }
            foreach (var it in list.Where(i => !string.IsNullOrEmpty(i.Target)).ToList())
            {
                try
                {
                    it.Exists = File.Exists(it.Target) || Directory.Exists(it.Target);
                    if (!it.Exists) continue;
                    var ti = Trust.Check(it.Target);
                    if (ti != null) { it.Publisher = ti.Publisher; it.Trusted = ti.IsValid && (rules == null ? (ti.Publisher ?? "").StartsWith("Microsoft") : rules.IsTrustedPublisher(ti.Publisher) || (ti.Publisher ?? "").StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)); }
                }
                catch { }
            }
            return list.OrderBy(i => i.Trusted ? 1 : 0).ThenBy(i => i.Kind).ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // ------------------------------------------------------------------------------------------------ sources
        static bool IsDisabledFlag(byte[] b) { return b != null && b.Length >= 1 && (b[0] & 1) == 1; }

        static byte[] FlagBytes(bool enabled)
        {
            var b = new byte[12];
            if (enabled) b[0] = 2;
            else { b[0] = 3; BitConverter.GetBytes(DateTime.Now.ToFileTimeUtc()).CopyTo(b, 4); }
            return b;
        }

        static void RunKeys(List<StartupItem> list)
        {
            foreach (var hive in new[] { Tuple.Create(Registry.CurrentUser, "HKCU"), Tuple.Create(Registry.LocalMachine, "HKLM") })
                foreach (var sub in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" })
                {
                    if (hive.Item2 == "HKCU" && sub.Contains("WOW6432Node")) continue;
                    using (var k = hive.Item1.OpenSubKey(sub))
                    using (var ap = hive.Item1.OpenSubKey(Approved + "Run"))
                    {
                        if (k == null) continue;
                        foreach (var n in k.GetValueNames())
                        {
                            string cmd = Convert.ToString(k.GetValue(n));
                            byte[] flag = ap == null ? null : ap.GetValue(n) as byte[];
                            list.Add(new StartupItem { Id = "run|" + hive.Item2 + "|" + sub + "|" + n, Kind = "run", Name = n, Command = cmd, Target = PathUtil.ExtractExecutable(cmd), Source = hive.Item2 + "\\" + sub.Replace(@"Software\", ""), Enabled = !IsDisabledFlag(flag) });
                        }
                    }
                }
        }

        static void Folders(List<StartupItem> list)
        {
            var places = new List<Tuple<string, RegistryKey, string>> { Tuple.Create(Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows\Start Menu\Programs\StartUp"), Registry.LocalMachine, "HKLM") };
            foreach (var up in PathUtil.UserProfiles()) places.Add(Tuple.Create(Path.Combine(up, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), Registry.CurrentUser, "HKCU"));
            foreach (var pl in places)
            {
                if (!Directory.Exists(pl.Item1)) continue;
                bool isCurrent = pl.Item3 == "HKLM" || pl.Item1.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase);
                using (var ap = isCurrent ? pl.Item2.OpenSubKey(Approved + "StartupFolder") : null)
                    foreach (var f in Directory.GetFiles(pl.Item1))
                    {
                        string name = Path.GetFileName(f);
                        if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                        string target = f, cmd = f;
                        if (name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                        {
                            try { Type t = Type.GetTypeFromProgID("WScript.Shell"); dynamic sh = Activator.CreateInstance(t); dynamic lnk = sh.CreateShortcut(f); target = Convert.ToString(lnk.TargetPath); cmd = target + " " + Convert.ToString(lnk.Arguments); } catch { }
                        }
                        byte[] flag = ap == null ? null : ap.GetValue(name) as byte[];
                        list.Add(new StartupItem { Id = "folder|" + pl.Item3 + "|" + f, Kind = "folder", Name = name, Command = cmd, Target = target, Source = pl.Item1, Enabled = !IsDisabledFlag(flag), CanChange = isCurrent });
                    }
            }
        }

        static void Tasks(List<StartupItem> list)
        {
            Type t = Type.GetTypeFromProgID("Schedule.Service"); if (t == null) return;
            dynamic svc = Activator.CreateInstance(t); svc.Connect();
            Action<dynamic, string> walk = null;
            walk = (folder, path) =>
            {
                if (path.StartsWith("\\Microsoft", StringComparison.OrdinalIgnoreCase)) return;       // Windows' own tasks
                try
                {
                    foreach (dynamic task in folder.GetTasks(1))
                    {
                        try
                        {
                            bool boot = false;
                            foreach (dynamic tr in task.Definition.Triggers) { int type = (int)tr.Type; if (type == 8 || type == 9) boot = true; }
                            if (!boot) continue;
                            string cmd = "", args = "";
                            foreach (dynamic a in task.Definition.Actions) { if ((int)a.Type == 0) { cmd = Convert.ToString(a.Path); args = Convert.ToString(a.Arguments); break; } }
                            string full = Environment.ExpandEnvironmentVariables(cmd).Trim('"');
                            list.Add(new StartupItem { Id = "task|" + task.Path, Kind = "task", Name = Convert.ToString(task.Name), Command = (cmd + " " + args).Trim(), Target = full, Source = Convert.ToString(task.Path), Enabled = (bool)task.Enabled });
                        }
                        catch { }
                    }
                    foreach (dynamic sub in folder.GetFolders(0)) walk(sub, Convert.ToString(sub.Path));
                }
                catch { }
            };
            walk(svc.GetFolder("\\"), "\\");
        }

        static void Services(List<StartupItem> list)
        {
            using (var s = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, StartMode, State FROM Win32_Service"))
                foreach (ManagementObject o in s.Get())
                {
                    string mode = Convert.ToString(o["StartMode"]), path = Convert.ToString(o["PathName"]);
                    if (string.IsNullOrEmpty(path) || (mode != "Auto" && mode != "Disabled")) continue;
                    string exe = PathUtil.ExtractExecutable(path);
                    if (string.IsNullOrEmpty(exe)) continue;
                    string low = exe.ToLowerInvariant();
                    if (low.StartsWith((PathUtil.System32 + "\\").ToLowerInvariant()) || low.StartsWith((PathUtil.WinDir + "\\").ToLowerInvariant())) continue;     // Windows' own services
                    list.Add(new StartupItem { Id = "service|" + o["Name"], Kind = "service", Name = Convert.ToString(o["DisplayName"]) ?? Convert.ToString(o["Name"]), Command = path, Target = exe, Source = Convert.ToString(o["Name"]), Enabled = mode == "Auto", Note = Convert.ToString(o["State"]) });
                }
        }

        static void Special(List<StartupItem> list)
        {
            Func<RegistryKey, string, string, string> get = (root, p, n) => { try { using (var k = root.OpenSubKey(p)) return k == null ? null : Convert.ToString(k.GetValue(n)); } catch { return null; } };
            string shell = get(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"), ui = get(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit");
            if (shell != null && !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)) list.Add(new StartupItem { Id = "special|shell", Kind = "special", Name = "Winlogon Shell", Command = shell, Target = PathUtil.ExtractExecutable(shell), Source = "HKLM\\...\\Winlogon", CanChange = false, Note = L("Not the default value", "Не значение по умолчанию") });
            if (ui != null && ui.TrimEnd(',').Trim().ToLowerInvariant() != (PathUtil.System32 + "\\userinit.exe").ToLowerInvariant()) list.Add(new StartupItem { Id = "special|userinit", Kind = "special", Name = "Winlogon Userinit", Command = ui, Target = PathUtil.ExtractExecutable(ui), Source = "HKLM\\...\\Winlogon", CanChange = false, Note = L("Not the default value", "Не значение по умолчанию") });
            string appinit = get(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs");
            if (!string.IsNullOrWhiteSpace(appinit)) list.Add(new StartupItem { Id = "special|appinit", Kind = "special", Name = "AppInit_DLLs", Command = appinit, Target = PathUtil.ExtractExecutable(appinit), Source = "HKLM\\...\\Windows", CanChange = false, Note = L("A library loaded into every program", "Библиотека, загружаемая в каждую программу") });
        }

        // ------------------------------------------------------------------------------------------------ switching
        public static string ChangesFile { get { return Path.Combine(RulePack.DataDir, "startup-changes.json"); } }

        /// <summary>Turns an item off (enable = false) or back on. Returns null on success or the reason.</summary>
        public static string SetEnabled(StartupItem it, bool enable)
        {
            try
            {
                if (!it.CanChange) return L("This item is only shown; it cannot be changed from here.", "Этот пункт только показан; менять его отсюда нельзя.");
                var parts = it.Id.Split('|');
                switch (it.Kind)
                {
                    case "run":
                        {
                            var root = parts[1] == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                            using (var k = root.CreateSubKey(Approved + "Run")) k.SetValue(it.Name, FlagBytes(enable), RegistryValueKind.Binary);
                            Record(it, enable); return null;
                        }
                    case "folder":
                        {
                            var root = parts[1] == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                            using (var k = root.CreateSubKey(Approved + "StartupFolder")) k.SetValue(it.Name, FlagBytes(enable), RegistryValueKind.Binary);
                            Record(it, enable); return null;
                        }
                    case "task":
                        {
                            Type t = Type.GetTypeFromProgID("Schedule.Service"); dynamic svc = Activator.CreateInstance(t); svc.Connect();
                            dynamic task = svc.GetFolder("\\").GetTask(it.Id.Substring(5)); task.Enabled = enable;
                            Record(it, enable); return null;
                        }
                    case "service":
                        {
                            string name = it.Source;
                            using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name, true))
                            {
                                if (k == null) return L("The service was not found.", "Служба не найдена.");
                                if (!enable) { it.OriginalStart = Convert.ToString(k.GetValue("Start")); Record(it, false); k.SetValue("Start", 4, RegistryValueKind.DWord); }
                                else { string orig = OriginalStart(it) ?? "2"; k.SetValue("Start", int.Parse(orig), RegistryValueKind.DWord); Record(it, true); }
                            }
                            return null;
                        }
                }
                return "unknown item";
            }
            catch (Exception ex) { return ex.Message; }
        }

        static void Record(StartupItem it, bool enabled)
        {
            try
            {
                var d = Load();
                d.RemoveAll(x => Json.Str(x, "id") == it.Id);
                if (!enabled) d.Add(new Dictionary<string, object> { { "id", it.Id }, { "kind", it.Kind }, { "name", it.Name }, { "command", it.Command }, { "originalStart", it.OriginalStart }, { "when", DateTime.Now.ToString("o") } });
                Directory.CreateDirectory(RulePack.DataDir);
                Fs.WriteDurable(ChangesFile, new UTF8Encoding(false).GetBytes(Json.Pretty(Json.Serialize(new Dictionary<string, object> { { "disabled", d.Cast<object>().ToArray() } }))));
            }
            catch { }
        }

        static List<Dictionary<string, object>> Load()
        {
            var l = new List<Dictionary<string, object>>();
            try
            {
                if (!File.Exists(ChangesFile)) return l;
                var d = Json.Obj(Json.Parse(File.ReadAllText(ChangesFile)));
                foreach (var o in Json.Arr(d["disabled"]) ?? new object[0]) { var x = Json.Obj(o); if (x != null) l.Add(x); }
            }
            catch { }
            return l;
        }

        static string OriginalStart(StartupItem it) { var m = Load().FirstOrDefault(x => Json.Str(x, "id") == it.Id); return m == null ? null : Json.Str(m, "originalStart"); }

        /// <summary>Items MineHunter turned off (so the page can offer to turn them back on even when they no longer show up as "enabled" entries).</summary>
        public static List<string> DisabledByUs() { return Load().Select(x => Json.Str(x, "id")).ToList(); }
    }
}
