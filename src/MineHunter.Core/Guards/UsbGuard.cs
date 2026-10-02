using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Guards
{
    public sealed class UsbFinding { public string Kind, Path, Text; public int Weight; public EvidenceCategory Category = EvidenceCategory.Behavior; public bool Definitive; }

    /// <summary>The quick smart look at a newly connected drive: not a scan of every byte, but the places and tricks that USB worms and droppers use - autorun.inf, shortcuts that replace
    /// folders, programs named like folders, hidden programs in the root, scripts in the root.</summary>
    public static class UsbScanner
    {
        static string L(string en, string ru) { return Loc.L(en, ru); }
        static readonly string[] Exec = { ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".cpl", ".pif" };

        public static List<UsbFinding> Scan(string root, LightCheck light = null)
        {
            var res = new List<UsbFinding>();
            try
            {
                var files = Directory.GetFiles(root).Select(f => new FileInfo(f)).ToList();
                var dirs = Directory.GetDirectories(root).Select(d => new DirectoryInfo(d)).Where(d => !d.Name.StartsWith("$") && !d.Name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)).ToList();

                // autorun.inf that runs something
                var ar = files.FirstOrDefault(f => f.Name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase));
                if (ar != null)
                {
                    string txt = ""; try { txt = File.ReadAllText(ar.FullName).ToLowerInvariant(); } catch { }
                    if (txt.Contains("open=") || txt.Contains("shellexecute=") || txt.Contains("shell\\open") || txt.Contains("action="))
                        res.Add(new UsbFinding { Kind = "autorun", Path = ar.FullName, Weight = 35, Category = EvidenceCategory.Behavior, Text = L("autorun.inf that starts a program when the drive is opened (the classic USB-worm trick)", "autorun.inf, запускающий программу при открытии диска (классический приём USB-червей)") });
                }

                // the "folder shortcut" trick: the real folders are hidden and a .lnk with the same name takes their place
                foreach (var lnk in files.Where(f => f.Extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase)))
                {
                    string baseName = Path.GetFileNameWithoutExtension(lnk.Name);
                    var hiddenDir = dirs.FirstOrDefault(d => d.Name.Equals(baseName, StringComparison.OrdinalIgnoreCase) && (d.Attributes & FileAttributes.Hidden) != 0);
                    string target = null, args = null; ShortcutTarget(lnk.FullName, out target, out args);
                    string tn = Path.GetFileNameWithoutExtension(target ?? "").ToLowerInvariant();
                    bool shell = tn == "cmd" || tn == "powershell" || tn == "pwsh" || tn == "wscript" || tn == "cscript" || tn == "mshta" || tn == "rundll32";
                    if (hiddenDir != null && shell) res.Add(new UsbFinding { Kind = "lnk-folder", Path = lnk.FullName, Weight = 60, Category = EvidenceCategory.Behavior, Text = L("a shortcut stands in for the hidden folder \"" + baseName + "\" and starts a command shell (the USB shortcut virus)", "ярлык подменяет скрытую папку «" + baseName + "» и запускает командную оболочку (USB-вирус с ярлыками)") });
                    else if (hiddenDir != null) res.Add(new UsbFinding { Kind = "lnk-folder", Path = lnk.FullName, Weight = 25, Category = EvidenceCategory.Behavior, Text = L("a shortcut stands in for the hidden folder \"" + baseName + "\"", "ярлык подменяет скрытую папку «" + baseName + "»") });
                    else if (shell) res.Add(new UsbFinding { Kind = "lnk-shell", Path = lnk.FullName, Weight = 30, Category = EvidenceCategory.Behavior, Text = L("a shortcut on the drive that starts a command shell", "ярлык на диске, запускающий командную оболочку") });
                }

                // programs and scripts in the root
                foreach (var f in files.Where(f => Exec.Contains(f.Extension.ToLowerInvariant())))
                {
                    string b = Path.GetFileNameWithoutExtension(f.Name);
                    bool hidden = (f.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0;
                    bool named = dirs.Any(d => d.Name.Equals(b, StringComparison.OrdinalIgnoreCase));
                    if (named) res.Add(new UsbFinding { Kind = "exe-folder", Path = f.FullName, Weight = 45, Category = EvidenceCategory.Masquerade, Text = L("the program \"" + f.Name + "\" has the name of a folder next to it (people double-click it thinking it is the folder)", "программа «" + f.Name + "» носит имя соседней папки (на неё нажимают, думая, что это папка)") });
                    if (hidden) res.Add(new UsbFinding { Kind = "hidden-exec", Path = f.FullName, Weight = 35, Category = EvidenceCategory.Behavior, Text = L("a hidden program or script in the root: " + f.Name, "скрытая программа или скрипт в корне: " + f.Name) });
                    if (light != null)
                    {
                        var lr = light.Check(f.FullName);
                        if (lr != null && !lr.MissingOrUnreadable && !lr.Trusted)
                        {
                            var strong = lr.Signals.Where(s => s.Weight >= 20).OrderByDescending(s => s.Weight).FirstOrDefault();
                            if (strong != null) res.Add(new UsbFinding { Kind = "exec-content", Path = f.FullName, Weight = Math.Min(60, strong.Weight + 10), Category = strong.Category, Definitive = strong.Definitive, Text = f.Name + ": " + strong.Text });
                        }
                    }
                }
                // a drive that is mostly hidden folders and nothing visible but shortcuts
                int hiddenDirs = dirs.Count(d => (d.Attributes & FileAttributes.Hidden) != 0), lnks = files.Count(f => f.Extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase));
                if (hiddenDirs >= 2 && lnks >= 2 && dirs.Count == hiddenDirs) res.Add(new UsbFinding { Kind = "all-hidden", Path = root, Weight = 20, Category = EvidenceCategory.Behavior, Text = L("all folders on the drive are hidden and replaced by shortcuts", "все папки на диске скрыты и заменены ярлыками") });
            }
            catch (Exception ex) { Log.Warn("usb scan " + root + ": " + ex.Message); }
            return res;
        }

        static void ShortcutTarget(string lnk, out string target, out string args)
        {
            target = null; args = null;
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell"); if (t == null) return;
                dynamic sh = Activator.CreateInstance(t); dynamic s = sh.CreateShortcut(lnk);
                target = Convert.ToString(s.TargetPath); args = Convert.ToString(s.Arguments);
            }
            catch { }
        }
    }

    /// <summary>USB Guard: when a drive is plugged in, the quick look above runs (if "check automatically" is on) and the result is reported either way, so the user knows it was looked at.</summary>
    public sealed class UsbGuard : IGuard
    {
        GuardContext g; GuardState state = GuardState.Off; string detail = "";
        Timer timer; readonly HashSet<string> known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        LightCheck light;
        public string Name { get { return "usb"; } }
        public string Title { get { return Loc.L("USB Guard", "Контроль USB"); } }
        public GuardStatus Status { get { return new GuardStatus { Name = Name, Title = Title, State = state, Detail = detail }; } }

        public void Start(GuardContext ctx)
        {
            g = ctx; light = new LightCheck(g);
            foreach (var d in Removable()) known.Add(d);
            timer = new Timer(_ => Tick(), null, 3000, 3000);
            state = GuardState.On; detail = g.Settings.UsbAutoCheck ? Loc.L("checks a drive when it is plugged in", "проверяет диск при подключении") : Loc.L("notices a new drive, checks only when asked", "замечает новый диск, проверяет только по запросу");
        }

        public void Stop() { state = GuardState.Off; if (timer != null) { timer.Dispose(); timer = null; } }

        static List<string> Removable()
        {
            try { return DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady).Select(d => d.RootDirectory.FullName).ToList(); } catch { return new List<string>(); }
        }

        void Tick()
        {
            try
            {
                var now = Removable();
                foreach (var d in now) if (known.Add(d)) { string root = d; ThreadPool.QueueUserWorkItem(_ => Inspect(root)); }
                known.IntersectWith(now);
            }
            catch { }
        }

        /// <summary>Looks at one drive now (public for tests and the "check this drive" button).</summary>
        public GuardAlert Inspect(string root)
        {
            try
            {
                g.Journal.Add("usb", Loc.L("A drive was connected: ", "Подключён накопитель: ") + root);
                if (!g.Settings.UsbAutoCheck) return null;
                var findings = UsbScanner.Scan(root, light);
                string actor = "usb:" + root;
                Assessment last = null;
                foreach (var f in findings) { var a = g.Correlator.Add(new Signal { Actor = actor, Category = f.Category, Weight = f.Weight, Rule = "USB." + f.Kind, Text = f.Text, Definitive = f.Definitive }); if (a != null) last = a; }
                if (last == null)
                {
                    var ok = new GuardAlert { Guard = Name, Level = AlertLevel.Info, Path = root, Title = Loc.L("Drive checked", "Диск проверен"), Text = Loc.L("Drive " + root + " was looked at (autorun, shortcuts, hidden programs, scripts): nothing suspicious.", "Диск " + root + " просмотрен (автозапуск, ярлыки, скрытые программы, скрипты): подозрительного нет.") };
                    g.Alert(ok); return ok;
                }
                var alert = new GuardAlert { Guard = Name, Level = last.Level.Value, Path = root, Actor = actor, Title = Loc.L("Suspicious things on a connected drive", "Подозрительное на подключённом диске") };
                alert.Reasons = last.Signals.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Select(x => x.Text).Distinct().ToList();
                alert.Text = Loc.L("Drive " + root + ": ", "Диск " + root + ": ") + string.Join("; ", alert.Reasons.Take(4)) + ". " + Loc.L("Do not open the shortcuts or programs on it; scan the drive from MineHunter.", "Не открывайте ярлыки и программы на нём; проверьте диск в MineHunter.");
                g.Alert(alert);
                return alert;
            }
            catch (Exception ex) { Log.Warn("usb guard: " + ex.Message); return null; }
        }
    }
}
