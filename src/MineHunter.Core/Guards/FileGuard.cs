using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Guards
{
    /// <summary>Where files from the internet land.</summary>
    public static class WatchPlaces
    {
        public static List<string> BrowserDownloadDirs(string profile)
        {
            var dirs = new List<string>();
            try
            {
                foreach (var rel in new[] { @"AppData\Local\Google\Chrome\User Data\Default\Preferences", @"AppData\Local\Microsoft\Edge\User Data\Default\Preferences", @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Preferences", @"AppData\Local\Yandex\YandexBrowser\User Data\Default\Preferences", @"AppData\Roaming\Opera Software\Opera Stable\Preferences" })
                {
                    string f = Path.Combine(profile, rel);
                    if (!File.Exists(f)) continue;
                    var m = Regex.Match(File.ReadAllText(f), "\"default_directory\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                    if (m.Success) { string d = m.Groups[1].Value.Replace("\\\\", "\\"); if (Directory.Exists(d)) dirs.Add(d); }
                }
                string ff = Path.Combine(profile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
                if (Directory.Exists(ff))
                    foreach (var prefs in Directory.GetFiles(ff, "prefs.js", SearchOption.AllDirectories).Take(6))
                    {
                        var m = Regex.Match(File.ReadAllText(prefs), "user_pref\\(\"browser\\.download\\.dir\",\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\)");
                        if (m.Success) { string d = m.Groups[1].Value.Replace("\\\\", "\\"); if (Directory.Exists(d)) dirs.Add(d); }
                    }
            }
            catch { }
            return dirs;
        }
    }

    /// <summary>File Guard and Download Guard. A watcher on the places where programs land (Downloads, Desktop, Temp, AppData, the Startup folder, USB drives) notices a new
    /// program or script, waits until it is completely written, and gives it the same quick look a scan gives: signature, Mark of the Web, PE layout, markers, scripts,
    /// reputation. Alerts only when independent signs agree. It never claims to stop a file from starting: it finds out after the file has appeared.</summary>
    public sealed class FileGuard : IGuard
    {
        readonly bool downloads;
        GuardContext g; GuardState state = GuardState.Off; string detail = "";
        readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        readonly ConcurrentDictionary<string, DateTime> pending = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        readonly ConcurrentDictionary<string, DateTime> done = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        Thread worker; volatile bool stop;
        LightCheck light; ScriptGuard scripts;
        public int Checked;
        public TimeSpan Settle = TimeSpan.FromSeconds(2);

        public FileGuard(bool downloadMode) { downloads = downloadMode; }
        public string Name { get { return downloads ? "download" : "file"; } }
        public string Title { get { return downloads ? Loc.L("Download Guard", "Контроль загрузок") : Loc.L("File Guard", "Контроль файлов"); } }
        public GuardStatus Status { get { return new GuardStatus { Name = Name, Title = Title, State = state, Detail = detail }; } }

        static readonly string[] Watched = { ".exe", ".dll", ".sys", ".msi", ".msix", ".msixbundle", ".appx", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".cpl", ".zip", ".iso", ".img", ".vhd", ".vhdx" };
        static readonly string[] Partial = { ".crdownload", ".part", ".tmp", ".download", ".opdownload", ".partial" };

        public static bool IsWatchedFile(string path)
        {
            string e = Path.GetExtension(path ?? "").ToLowerInvariant();
            return e.Length > 0 && Array.IndexOf(Watched, e) >= 0;
        }

        /// <summary>The folders this guard watches (and whether each is watched recursively).</summary>
        public List<KeyValuePair<string, bool>> Places()
        {
            var list = new List<KeyValuePair<string, bool>>();
            Action<string, bool> add = (p, rec) => { try { if (Directory.Exists(p) && !list.Any(x => string.Equals(x.Key, p, StringComparison.OrdinalIgnoreCase))) list.Add(new KeyValuePair<string, bool>(p, rec)); } catch { } };
            foreach (var up in PathUtil.UserProfiles())
            {
                add(Path.Combine(up, "Downloads"), true);
                foreach (var d in WatchPlaces.BrowserDownloadDirs(up)) add(d, true);
                add(Path.Combine(up, "Desktop"), false);
                if (!downloads)
                {
                    add(Path.Combine(up, @"AppData\Local\Temp"), true);
                    add(Path.Combine(up, @"AppData\Roaming"), false);
                    add(Path.Combine(up, @"AppData\Local"), false);
                    add(Path.Combine(up, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), false);
                    add(Path.Combine(up, "Documents"), false);
                }
            }
            if (!downloads)
            {
                add(PathUtil.ProgramData, false);
                add(Path.Combine(PathUtil.WinDir, "Temp"), true);
                add(Path.Combine(PathUtil.SystemDrive + "\\", @"Users\Public"), true);
                add(Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows\Start Menu\Programs\StartUp"), false);
            }
            return list;
        }

        public void Start(GuardContext ctx) { StartOn(ctx, Places()); }

        /// <summary>Starts watching the given folders (tests use their own folder).</summary>
        public void StartOn(GuardContext ctx, IEnumerable<KeyValuePair<string, bool>> places)
        {
            g = ctx; light = new LightCheck(g); scripts = new ScriptGuard(); scripts.Start(g);
            int ok = 0, failed = 0;
            foreach (var pl in places) { if (Watch(pl.Key, pl.Value)) ok++; else failed++; }
            stop = false;
            worker = new Thread(Loop) { IsBackground = true, Name = "MineHunter " + Name, Priority = ThreadPriority.BelowNormal };
            worker.Start();
            state = ok == 0 ? GuardState.Error : failed > 0 ? GuardState.Limited : GuardState.On;
            detail = Loc.L("watching " + ok + " folder(s)" + (failed > 0 ? ", " + failed + " could not be watched" : ""), "следит за папками: " + ok + (failed > 0 ? ", не удалось следить за: " + failed : ""));
        }

        public bool Watch(string dir, bool recursive)
        {
            try
            {
                var w = new FileSystemWatcher(dir) { IncludeSubdirectories = recursive, InternalBufferSize = 64 * 1024, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime };
                w.Created += (s, e) => Enqueue(e.FullPath);
                w.Changed += (s, e) => Enqueue(e.FullPath);
                w.Renamed += (s, e) => Enqueue(e.FullPath);
                w.Error += (s, e) => Log.Warn(Name + " watcher: " + e.GetException().Message);
                w.EnableRaisingEvents = true;
                watchers.Add(w);
                return true;
            }
            catch (Exception ex) { Log.Warn(Name + ": cannot watch " + dir + ": " + ex.Message); return false; }
        }

        public void Stop()
        {
            state = GuardState.Off; stop = true;
            foreach (var w in watchers) { try { w.EnableRaisingEvents = false; w.Dispose(); } catch { } }
            watchers.Clear();
        }

        /// <summary>Public so the tests (and the USB guard) can hand it a path directly.</summary>
        public void Enqueue(string path)
        {
            if (string.IsNullOrEmpty(path) || !IsWatchedFile(path)) return;
            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (Array.IndexOf(Partial, ext) >= 0) return;
            if (pending.Count > 800) return;
            pending[path] = DateTime.Now;
        }

        void Loop()
        {
            while (!stop)
            {
                try
                {
                    Thread.Sleep(700);
                    if (Native.SystemState.FullScreenAppActive() && g.Settings.GameMode) continue;        // nothing heavy while a game has the screen
                    foreach (var kv in pending.ToArray())
                    {
                        if (stop) return;
                        if (DateTime.Now - kv.Value < Settle) continue;
                        DateTime t; pending.TryRemove(kv.Key, out t);
                        CheckOne(kv.Key, kv.Value);
                        Thread.Sleep(150);
                    }
                }
                catch (Exception ex) { Log.Warn(Name + " loop: " + ex.Message); }
            }
        }

        static bool Stable(string path)
        {
            try
            {
                long a = new FileInfo(path).Length; Thread.Sleep(400); long b = new FileInfo(path).Length;
                if (a != b) return false;
                using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) return true;
            }
            catch { return false; }
        }

        /// <summary>Looks at one file now (called by the loop; public for tests).</summary>
        public GuardAlert CheckOne(string path, DateTime seen)
        {
            try
            {
                if (!File.Exists(path)) return null;
                if (!Stable(path)) { pending[path] = DateTime.Now; return null; }       // still being written: look again in a moment
                var fi = new FileInfo(path);
                string key = path + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks;
                if (done.ContainsKey(key)) return null;
                done[key] = DateTime.Now; if (done.Count > 4000) done.Clear();
                Interlocked.Increment(ref Checked);
                var lr = light.Check(path);
                if (lr == null || lr.MissingOrUnreadable || lr.Trusted) return null;
                var signals = new List<Signal>(lr.Signals);
                string actor = PathUtil.Normalize(path);
                string ext = Path.GetExtension(path).ToLowerInvariant();
                string display = Path.GetFileName(path);

                if (ext == ".ps1" || ext == ".psm1" || ext == ".vbs" || ext == ".vbe" || ext == ".js" || ext == ".jse" || ext == ".wsf" || ext == ".hta" || ext == ".bat" || ext == ".cmd")
                    signals.AddRange(scripts.Check(path, actor).Signals);
                if (ext == ".lnk") signals.AddRange(CheckShortcut(path, actor));
                if (ext == ".zip" && lr.FromInternet) { var z = ZipExecutables(path); if (z != null) signals.Add(new Signal { Actor = actor, Category = EvidenceCategory.Content, Weight = 8, Rule = "FILE.ZIP_EXE", Text = Loc.L("an archive from the internet that holds a program (" + z + ")", "архив из интернета, внутри которого программа (" + z + ")") }); }
                if (lr.FromInternet && lr.Unsigned && lr.UserWritable && (ext == ".exe" || ext == ".scr" || ext == ".msi")) signals.Add(new Signal { Actor = actor, Category = EvidenceCategory.Reputation, Weight = 6, Rule = "FILE.UNKNOWN_DOWNLOAD", Text = Loc.L("downloaded from the internet, not signed, nobody knows it yet", "скачан из интернета, без подписи, нигде не известен") });
                if (lr.Tool) signals.RemoveAll(x => !x.Rule.StartsWith("MINER") && !x.Rule.StartsWith("REP."));      // a game cheat is not a miner

                Assessment last = null;
                foreach (var s in signals) { var a = g.Correlator.Add(s); if (a != null) last = a; }
                if (last == null) return null;
                var alert = new GuardAlert { Guard = Name, Level = last.Level.Value, Path = path, Sha256 = lr.Sha256, Actor = path };
                string verb = downloads ? Loc.L("Downloaded file", "Скачанный файл") : Loc.L("New file", "Новый файл");
                alert.Title = last.Level == AlertLevel.Dangerous ? verb + Loc.L(": dangerous", ": опасно") : verb + Loc.L(": looks suspicious", ": выглядит подозрительно");
                alert.Reasons = last.Signals.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Select(x => x.Text).Distinct().ToList();
                string where = Correlator.PlaceOf(path);
                alert.Text = "\"" + display + "\"" + (where != null ? " (" + where + ")" : "") + Loc.L(" - ", " - ") + string.Join("; ", alert.Reasons.Take(4)) + "." + (lr.Origin != null ? " " + Loc.Origin(lr.Origin) + "." : "")
                           + " " + Loc.L("MineHunter noticed it after it appeared; it does not stop a file from starting.", "MineHunter заметил его уже после появления; он не мешает файлу запуститься.");
                g.Alert(alert);
                return alert;
            }
            catch (Exception ex) { Log.Warn(Name + " check " + path + ": " + ex.Message); return null; }
        }

        static List<Signal> CheckShortcut(string path, string actor)
        {
            var list = new List<Signal>();
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell"); if (t == null) return list;
                dynamic sh = Activator.CreateInstance(t); dynamic lnk = sh.CreateShortcut(path);
                string target = Convert.ToString(lnk.TargetPath), args = Convert.ToString(lnk.Arguments);
                string tn = Path.GetFileNameWithoutExtension(target ?? "").ToLowerInvariant(), al = (args ?? "").ToLowerInvariant();
                bool host = tn == "powershell" || tn == "pwsh" || tn == "cmd" || tn == "wscript" || tn == "cscript" || tn == "mshta" || tn == "rundll32" || tn == "regsvr32";
                if (host && (al.Contains("http") || al.Contains("-enc") || al.Contains("downloadstring") || al.Contains("-w hidden") || al.Contains("-windowstyle hidden") || al.Contains("/c start") || al.Contains("javascript:")))
                    list.Add(new Signal { Actor = actor, Category = EvidenceCategory.Behavior, Weight = 35, Rule = "FILE.LNK_SHELL", Text = Loc.L("a shortcut that runs a command shell with a download or a hidden command", "ярлык, который запускает командную оболочку со скачиванием или скрытой командой") });
            }
            catch { }
            return list;
        }

        static string ZipExecutables(string path)
        {
            try
            {
                using (var za = ZipFile.OpenRead(path))
                {
                    var hit = za.Entries.Where(e => new[] { ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk", ".ps1", ".msi" }.Contains(Path.GetExtension(e.Name).ToLowerInvariant())).Select(e => e.Name).Take(2).ToList();
                    return hit.Count == 0 ? null : string.Join(", ", hit);
                }
            }
            catch { return null; }
        }
    }
}
