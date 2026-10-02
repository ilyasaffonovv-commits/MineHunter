using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Guards
{
    /// <summary>One place a program can make itself start again, reduced to "name -> what it holds". The guard keeps the last picture and reports the difference.</summary>
    public sealed class WatchSpec
    {
        public string Kind;                  // run | startup | tasks | services | exclusions | hosts | firewall | wmi | profile | custom
        public string Title;
        public Func<Dictionary<string, string>> Snapshot;
    }

    public sealed class PersistenceChange
    {
        public string Kind, Title, Key, Value, OldValue; public bool Added, Changed, Removed;
    }

    /// <summary>Persistence Guard: every few seconds it looks at the places that start programs (Run keys, Startup folders, scheduled tasks, services, Defender exclusions, hosts,
    /// firewall rules, WMI subscriptions, PowerShell profiles) and reports what is new. Windows does not say WHO changed an entry, so the program named in the message is the
    /// one that was started a moment before (and it says so) or the one the new entry itself launches.</summary>
    public sealed class PersistenceGuard : IGuard
    {
        GuardContext g; GuardState state = GuardState.Off; string detail = "";
        readonly List<WatchSpec> specs = new List<WatchSpec>();
        readonly Dictionary<string, Dictionary<string, string>> last = new Dictionary<string, Dictionary<string, string>>();
        Timer timer; int busy;
        public TimeSpan Interval = TimeSpan.FromSeconds(15);
        ProcessGuard linked;

        public string Name { get { return "persistence"; } }
        public string Title { get { return Loc.L("Persistence Guard", "Контроль автозапуска"); } }
        public GuardStatus Status { get { return new GuardStatus { Name = Name, Title = Title, State = state, Detail = detail }; } }

        public PersistenceGuard() { }

        /// <summary>Tests add their own spec (a key under HKCU that only the test uses).</summary>
        public void AddSpec(WatchSpec s) { specs.Add(s); }
        public void UseDefaultSpecs() { specs.AddRange(DefaultSpecs()); }

        public void Start(GuardContext ctx)
        {
            g = ctx;
            if (specs.Count == 0) UseDefaultSpecs();
            foreach (var s in specs) { try { last[s.Kind + "|" + s.Title] = s.Snapshot(); } catch (Exception ex) { Log.Warn("persistence baseline " + s.Title + ": " + ex.Message); last[s.Kind + "|" + s.Title] = new Dictionary<string, string>(); } }
            timer = new Timer(_ => Tick(), null, Interval, Interval);
            state = GuardState.On; detail = Loc.L("watching " + specs.Count + " autostart places, every " + (int)Interval.TotalSeconds + " s", "следит за " + specs.Count + " местами автозапуска, раз в " + (int)Interval.TotalSeconds + " с");
        }

        public void Stop() { state = GuardState.Off; if (timer != null) { timer.Dispose(); timer = null; } }

        void Tick()
        {
            if (Interlocked.Exchange(ref busy, 1) == 1) return;
            try { CheckNow(); } catch (Exception ex) { Log.Warn("persistence guard: " + ex.Message); }
            finally { Interlocked.Exchange(ref busy, 0); }
        }

        /// <summary>Takes a new picture, compares, handles the differences. Public for tests.</summary>
        public List<PersistenceChange> CheckNow()
        {
            var changes = new List<PersistenceChange>();
            foreach (var s in specs)
            {
                Dictionary<string, string> now;
                try { now = s.Snapshot(); } catch { continue; }
                string k = s.Kind + "|" + s.Title;
                Dictionary<string, string> before; if (!last.TryGetValue(k, out before)) before = new Dictionary<string, string>();
                foreach (var kv in now)
                {
                    string old;
                    if (!before.TryGetValue(kv.Key, out old)) changes.Add(new PersistenceChange { Kind = s.Kind, Title = s.Title, Key = kv.Key, Value = kv.Value, Added = true });
                    else if (old != kv.Value) changes.Add(new PersistenceChange { Kind = s.Kind, Title = s.Title, Key = kv.Key, Value = kv.Value, OldValue = old, Changed = true });
                }
                foreach (var kv in before) if (!now.ContainsKey(kv.Key)) changes.Add(new PersistenceChange { Kind = s.Kind, Title = s.Title, Key = kv.Key, OldValue = kv.Value, Removed = true });
                last[k] = now;
            }
            foreach (var c in changes) { try { Handle(c); } catch (Exception ex) { Log.Warn("persistence change: " + ex.Message); } }
            return changes;
        }

        // ------------------------------------------------------------------------------------------------ judging a change
        void Handle(PersistenceChange c)
        {
            if (c.Removed) { g.Journal.Add(c.Kind, Loc.L("Removed from " + c.Title + ": ", "Удалено из «" + c.Title + "»: ") + c.Key); return; }
            string cmd = c.Value ?? "";
            string target = PathUtil.ExtractExecutable(cmd);
            if (string.IsNullOrEmpty(target) && (c.Kind == "startup" || c.Kind == "profile")) target = c.Key;
            string recentName; ProcRec recent = Recent(target, out recentName);
            string who = recent != null ? Loc.L(" (probably added by \"" + recent.Name + "\", started " + (int)(DateTime.Now - recent.Started).TotalSeconds + " s earlier)", " (вероятно, добавила «" + recent.Name + "», запущена " + (int)(DateTime.Now - recent.Started).TotalSeconds + " с назад)") : "";
            string what = Loc.L(c.Added ? "New entry in " : "Changed entry in ", c.Added ? "Новая запись в «" : "Изменена запись в «") + c.Title + (Loc.Ru ? "»" : "") + ": " + Text.Trunc(c.Key + (string.IsNullOrEmpty(cmd) || c.Kind == "tasks" ? "" : " = " + cmd), 200);
            g.Journal.Add(c.Kind, what + who, target, recent != null ? recent.Path : null);

            var signals = new List<Signal>();
            Action<string, EvidenceCategory, int, string, bool, string> add = (actor, cat, w, text, def, rule) => { if (!string.IsNullOrEmpty(actor)) signals.Add(new Signal { Actor = PathUtil.Normalize(actor), Category = cat, Weight = w, Rule = rule, Text = text, Definitive = def }); };

            if (c.Kind == "exclusions")
            {
                bool broad = WindowsHealth.DangerousExclusion(c.Key);
                string actor = recent != null && !IsTrusted(recent.Path) ? recent.Path : "(system)";
                add(actor, EvidenceCategory.Tamper, broad ? 55 : 40, Loc.L("added an exclusion for Defender: " + c.Key, "добавила исключение для Защитника: " + c.Key), false, "PERSIST.DEF_EXCLUSION");
            }
            else if (c.Kind == "hosts")
            {
                string actor = recent != null && !IsTrusted(recent.Path) ? recent.Path : "(system)";
                bool sec = g.Rules != null && g.Rules.AvDomains.Any(d => (c.Value ?? "").IndexOf(d, StringComparison.OrdinalIgnoreCase) >= 0);
                add(actor, EvidenceCategory.Tamper, sec ? 50 : 20, sec ? Loc.L("changed the hosts file to block a security site", "изменила файл hosts, заблокировав сайт защиты") : Loc.L("changed the hosts file", "изменила файл hosts"), false, "PERSIST.HOSTS");
            }
            else if (c.Kind == "wmi")
            {
                string actor = recent != null && !IsTrusted(recent.Path) ? recent.Path : "(system)";
                add(actor, EvidenceCategory.Persistence, 40, Loc.L("created a WMI event subscription (a hidden way to start code)", "создала подписку WMI (скрытый способ запускать код)"), false, "PERSIST.WMI");
            }
            else if (c.Kind == "firewall")
            {
                string app = FirewallApp(c.Value);
                if (!string.IsNullOrEmpty(app) && PathUtil.IsUserWritable(app) && !IsTrusted(app)) add(app, EvidenceCategory.Persistence, 20, Loc.L("a firewall rule was added that lets this program through", "добавлено правило брандмауэра, пропускающее эту программу"), false, "PERSIST.FIREWALL");
            }
            else
            {
                // an autostart entry (Run key, startup folder, task, service, profile): what matters is the program it starts
                if (string.IsNullOrEmpty(target) || (!File.Exists(target) && !Directory.Exists(target))) { add(recent != null && !IsTrusted(recent.Path) ? recent.Path : null, EvidenceCategory.Persistence, 14, Loc.L("created an autostart entry that points to a file that is missing", "создала запись автозапуска, указывающую на отсутствующий файл"), false, "PERSIST.MISSING"); }
                else if (!IsTrusted(target))
                {
                    string what2 = c.Kind == "tasks" ? Loc.L("created a scheduled task", "создала задачу автозапуска") : c.Kind == "services" ? Loc.L("installed a service", "установила службу") : c.Kind == "startup" ? Loc.L("put itself into the Startup folder", "поместила себя в папку автозагрузки") : c.Kind == "profile" ? Loc.L("changed a PowerShell profile", "изменила профиль PowerShell") : Loc.L("added itself to autostart", "добавила себя в автозапуск");
                    add(target, EvidenceCategory.Persistence, 28, what2, false, "PERSIST.NEW_ENTRY");
                    if (PathUtil.IsUserWritable(target)) add(target, EvidenceCategory.Location, 8, Loc.L("it starts a program from a folder any program can write to", "она запускает программу из папки, куда может писать любая программа"), false, "PERSIST.USERPATH");
                    var lr = new LightCheck(g).Check(target);
                    if (lr != null && !lr.MissingOrUnreadable && !lr.Trusted) foreach (var s in lr.Signals) signals.Add(new Signal { Actor = PathUtil.Normalize(target), Category = s.Category, Weight = s.Weight, Rule = s.Rule, Text = s.Text, Definitive = s.Definitive });
                }
                // a trusted program that registers itself is the normal case: only the journal hears about it
                foreach (var r in g.Rules.CmdRules.Where(r => r.Id.StartsWith("CMD.MINER") && r.Rx.IsMatch(cmd))) add(target ?? c.Key, FileIntelCat(r.Category), r.Weight, r.Text, r.Definitive, "PERSIST." + r.Id);
            }

            Assessment lastA = null; string lastActor = null;
            foreach (var s in signals) { var a = g.Correlator.Add(s); if (a != null) { lastA = a; lastActor = s.Actor; } }
            if (lastA == null) return;
            var alert = new GuardAlert { Guard = Name, Level = lastA.Level.Value, Path = target, Actor = lastActor };
            alert.Title = c.Kind == "exclusions" ? Loc.L("Defender exclusion added", "В исключения Защитника добавлено") : c.Kind == "hosts" ? Loc.L("hosts file changed", "Файл hosts изменён") : Loc.L("A program set itself up to start again", "Программа настроила свой повторный запуск");
            alert.Reasons = lastA.Signals.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Select(x => x.Text).Distinct().ToList();
            alert.Text = (lastActor == "(system)" ? Loc.L("Something ", "Что-то ") + string.Join("; ", alert.Reasons.Take(3)) + "." : Correlator.Story(lastActor, lastA.Signals)) + who;
            if (File.Exists(target ?? "")) { try { alert.Sha256 = Hashing.Sha256(target); } catch { } }
            g.Alert(alert);
        }

        static EvidenceCategory FileIntelCat(string c) { EvidenceCategory ec; return Enum.TryParse(c, true, out ec) ? ec : EvidenceCategory.Content; }

        ProcRec Recent(string target, out string name)
        {
            name = null;
            // the program the entry starts is the clearest answer; otherwise the most recent untrusted program that started in the last two minutes
            if (!string.IsNullOrEmpty(target)) { var byPath = g.Processes.ByPath(PathUtil.Normalize(target)); if (byPath != null) { name = byPath.Name; return byPath; } }
            var cand = g.Processes.StartedWithin(TimeSpan.FromMinutes(2), g.Now()).Where(p => !string.IsNullOrEmpty(p.Path) && PathUtil.IsUserWritable(p.Path) && !IsTrusted(p.Path)).OrderByDescending(p => p.Started).FirstOrDefault();
            if (cand != null) name = cand.Name;
            return cand;
        }

        bool IsTrusted(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
                if (g.Allow != null) { string h = Hashing.Sha256(path); if (h != null && g.Allow.Sha256.Contains(h)) return true; }
                if (g.Settings != null && g.Settings.IsExcludedPath(path)) return true;
                var ti = Trust.Check(path);
                if (ti == null || !ti.IsValid) return false;
                if (ti.State == TrustState.ValidCatalog && PathUtil.Classify(path) == PathClass.WindowsSystem) return true;
                return g.Rules.IsTrustedPublisher(ti.Publisher) || (ti.Publisher ?? "").StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        static string FirewallApp(string rule)
        {
            if (string.IsNullOrEmpty(rule)) return null;
            foreach (var part in rule.Split('|')) if (part.StartsWith("App=", StringComparison.OrdinalIgnoreCase)) return Environment.ExpandEnvironmentVariables(part.Substring(4));
            return null;
        }

        // ------------------------------------------------------------------------------------------------ what is watched
        static Dictionary<string, string> RegValues(RegistryKey root, string path)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var k = root.OpenSubKey(path))
                    if (k != null) foreach (var n in k.GetValueNames()) d[n] = Convert.ToString(k.GetValue(n));
            }
            catch { }
            return d;
        }

        static void Merge(Dictionary<string, string> into, string prefix, Dictionary<string, string> from) { foreach (var kv in from) into[prefix + kv.Key] = kv.Value; }

        public static List<WatchSpec> DefaultSpecs()
        {
            var l = new List<WatchSpec>();
            l.Add(new WatchSpec
            {
                Kind = "run", Title = "Run / RunOnce",
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var p in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", @"Software\Microsoft\Windows NT\CurrentVersion\Windows", @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" })
                    {
                        var hk = RegValues(Registry.CurrentUser, p); if (p.EndsWith("Windows")) hk = hk.Where(kv => kv.Key == "Load" || kv.Key == "Run").ToDictionary(kv => kv.Key, kv => kv.Value);
                        Merge(d, "HKCU\\" + p + "\\", hk);
                        var hm = RegValues(Registry.LocalMachine, p); if (p.EndsWith("Windows")) hm = hm.Where(kv => kv.Key == "Load" || kv.Key == "Run" || kv.Key == "AppInit_DLLs").ToDictionary(kv => kv.Key, kv => kv.Value);
                        Merge(d, "HKLM\\" + p + "\\", hm);
                    }
                    Merge(d, "HKLM\\WOW6432Node\\Run\\", RegValues(Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"));
                    Merge(d, "HKLM\\Winlogon\\", RegValues(Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon").Where(kv => kv.Key == "Shell" || kv.Key == "Userinit" || kv.Key == "Taskman").ToDictionary(kv => kv.Key, kv => kv.Value));
                    try { foreach (var sid in Registry.Users.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21") && !s.EndsWith("_Classes"))) Merge(d, "HKU\\" + sid + "\\Run\\", RegValues(Registry.Users, sid + @"\Software\Microsoft\Windows\CurrentVersion\Run")); } catch { }
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "startup", Title = Loc.L("Startup folders", "Папки автозагрузки"),
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    var dirs = new List<string> { Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows\Start Menu\Programs\StartUp") };
                    foreach (var up in PathUtil.UserProfiles()) dirs.Add(Path.Combine(up, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
                    foreach (var dir in dirs) try { if (Directory.Exists(dir)) foreach (var f in Directory.GetFiles(dir)) { if (Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue; d[f] = new FileInfo(f).Length + "|" + new FileInfo(f).LastWriteTimeUtc.Ticks; } } catch { }
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "tasks", Title = Loc.L("Scheduled tasks", "Задачи планировщика"),
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    string root = Path.Combine(PathUtil.System32, "Tasks");
                    try
                    {
                        foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                        {
                            if (f.IndexOf("\\Microsoft\\", StringComparison.OrdinalIgnoreCase) >= 0) continue;     // Windows' own tasks: thousands of them, and they have their own checks in a scan
                            string cmd = ""; try { var m = System.Text.RegularExpressions.Regex.Match(File.ReadAllText(f), "<Command>([^<]+)</Command>"); if (m.Success) cmd = System.Net.WebUtility.HtmlDecode(m.Groups[1].Value); } catch { }
                            d[f.Substring(root.Length + 1)] = cmd;
                        }
                    }
                    catch { }
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "services", Title = Loc.L("Services", "Службы"),
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    try
                    {
                        using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                            foreach (var n in k.GetSubKeyNames())
                                using (var s = k.OpenSubKey(n))
                                {
                                    string img = Convert.ToString(s.GetValue("ImagePath")); int type = 0; try { type = Convert.ToInt32(s.GetValue("Type")); } catch { }
                                    if (string.IsNullOrEmpty(img) || (type & 0x10) == 0 && (type & 0x20) == 0 && type != 1) continue;       // own/shared process services and kernel drivers
                                    if (img.IndexOf("\\system32\\drivers\\", StringComparison.OrdinalIgnoreCase) >= 0 || img.IndexOf("\\windows\\system32\\", StringComparison.OrdinalIgnoreCase) >= 0 || img.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) continue;
                                    d[n] = img;
                                }
                    }
                    catch { }
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "exclusions", Title = Loc.L("Defender exclusions", "Исключения Защитника"),
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var sub in new[] { "Paths", "Processes", "Extensions" })
                        foreach (var kv in RegValues(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\" + sub)) d[kv.Key] = sub;
                    foreach (var sub in new[] { "Paths", "Processes", "Extensions" })
                        foreach (var kv in RegValues(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\" + sub)) d[kv.Key] = sub;
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "hosts", Title = "hosts",
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    try { foreach (var line in File.ReadAllLines(Path.Combine(PathUtil.System32, @"drivers\etc\hosts")).Select(x => x.Trim()).Where(x => x.Length > 0 && !x.StartsWith("#"))) d[line] = line; } catch { }
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "firewall", Title = Loc.L("Firewall rules", "Правила брандмауэра"),
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var kv in RegValues(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"))
                        if (kv.Value.IndexOf("Action=Allow", StringComparison.OrdinalIgnoreCase) >= 0 && kv.Value.IndexOf("Dir=In", StringComparison.OrdinalIgnoreCase) >= 0) d[kv.Key] = kv.Value;
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "wmi", Title = Loc.L("WMI subscriptions", "Подписки WMI"),
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    try
                    {
                        using (var s = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM __FilterToConsumerBinding"))
                            foreach (ManagementObject o in s.Get()) d[Convert.ToString(o["Consumer"])] = Convert.ToString(o["Filter"]);
                    }
                    catch { }
                    return d;
                }
            });
            l.Add(new WatchSpec
            {
                Kind = "profile", Title = Loc.L("PowerShell profiles", "Профили PowerShell"),
                Snapshot = () =>
                {
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    var files = new List<string> { Path.Combine(PathUtil.System32, @"WindowsPowerShell\v1.0\profile.ps1"), Path.Combine(PathUtil.System32, @"WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1") };
                    foreach (var up in PathUtil.UserProfiles()) { files.Add(Path.Combine(up, @"Documents\WindowsPowerShell\profile.ps1")); files.Add(Path.Combine(up, @"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1")); files.Add(Path.Combine(up, @"Documents\PowerShell\profile.ps1")); files.Add(Path.Combine(up, @"Documents\PowerShell\Microsoft.PowerShell_profile.ps1")); }
                    foreach (var f in files) try { if (File.Exists(f)) d[f] = new FileInfo(f).Length + "|" + new FileInfo(f).LastWriteTimeUtc.Ticks; } catch { }
                    return d;
                }
            });
            return l;
        }
    }
}
