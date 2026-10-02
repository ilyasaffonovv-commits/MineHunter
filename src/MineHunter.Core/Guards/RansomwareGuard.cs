using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Guards
{
    public enum FileEventKind { Created, Modified, Renamed, Deleted }

    public sealed class RansomAssessment { public AlertLevel? Level; public int Score; public List<string> Reasons = new List<string>(); public bool CanaryHit; }

    /// <summary>The logic that tells ransomware from a busy program, with no file system in it (so it can be tested with made-up events). What counts:
    /// a canary file (a decoy placed in the folders) touched; many files renamed to the same new extension in many folders; a ransom note written into several folders;
    /// many documents rewritten very quickly. Backup tools, archivers and photo editors also rewrite a lot, so rewriting alone is never more than a note, and a program that is
    /// signed by a trusted publisher is only mentioned unless a canary was hit.</summary>
    public sealed class RansomDetector
    {
        public TimeSpan Window = TimeSpan.FromSeconds(25);
        public int RenameThreshold = 12, ModifyThreshold = 60, NoteFolders = 3;

        sealed class Ev { public string Path, Old; public FileEventKind Kind; public DateTime Time; }
        readonly List<Ev> events = new List<Ev>();
        readonly HashSet<string> canaries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly object lk = new object();

        static readonly Regex Note = new Regex(@"(readme|decrypt|restore|recover|how[_ -]?to|instruction|unlock|your[_ -]?files|_help_|!!!)[^\\]*\.(txt|html?|hta|url)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly HashSet<string> CommonExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z", ".mp3", ".mp4", ".mkv", ".avi", ".psd", ".bak", ".tmp", ".log", ".json", ".xml", ".html", ".csv", ".exe", ".dll", ".crdownload", ".part", ".old", ".new", ".swp", ".docm", ".odt", ".rtf", ".bmp", ".webp", ".svg", ".iso", ".msi" };

        public void AddCanary(string path) { lock (lk) canaries.Add(path); }
        public int CanaryCount { get { lock (lk) return canaries.Count; } }

        public void Event(string path, FileEventKind kind, string oldPath, DateTime t)
        {
            lock (lk)
            {
                events.Add(new Ev { Path = path, Old = oldPath, Kind = kind, Time = t });
                if (events.Count > 20000) events.RemoveRange(0, 5000);
            }
        }

        public RansomAssessment Evaluate(DateTime now, bool actorTrusted = false)
        {
            var a = new RansomAssessment();
            List<Ev> w;
            lock (lk) { events.RemoveAll(e => now - e.Time > Window); w = events.ToList(); }
            if (w.Count == 0) return a;
            // canary
            var hit = w.Where(e => (canaries.Contains(e.Path) || (e.Old != null && canaries.Contains(e.Old))) && e.Kind != FileEventKind.Created).ToList();
            if (hit.Count > 0) { a.CanaryHit = true; a.Score += 60; a.Reasons.Add(Loc.L("a decoy file that only ransomware would touch was changed", "изменён файл-приманка, который тронет только шифровальщик")); }
            // renames to one new extension
            var ren = w.Where(e => e.Kind == FileEventKind.Renamed && e.Old != null && !string.Equals(Path.GetExtension(e.Old), Path.GetExtension(e.Path), StringComparison.OrdinalIgnoreCase)).ToList();
            var byExt = ren.GroupBy(e => Path.GetExtension(e.Path).ToLowerInvariant()).Where(g => g.Key.Length > 1 && !CommonExt.Contains(g.Key)).OrderByDescending(g => g.Count()).FirstOrDefault();
            if (byExt != null && byExt.Count() >= RenameThreshold && byExt.Select(e => Path.GetDirectoryName(e.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2)
            { a.Score += 50; a.Reasons.Add(Loc.L(byExt.Count() + " files were renamed to the same unknown extension \"" + byExt.Key + "\" in a few seconds", byExt.Count() + " файлов за несколько секунд переименованы в одно неизвестное расширение «" + byExt.Key + "»")); }
            // ransom notes
            var notes = w.Where(e => e.Kind == FileEventKind.Created && Note.IsMatch(e.Path)).Select(e => Path.GetDirectoryName(e.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (notes >= NoteFolders) { a.Score += 40; a.Reasons.Add(Loc.L("the same kind of \"how to get your files back\" note appeared in " + notes + " folders", "в " + notes + " папках появилась одинаковая записка «как вернуть файлы»")); }
            // many rewrites
            int modified = w.Where(e => e.Kind == FileEventKind.Modified || e.Kind == FileEventKind.Renamed).Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            int folders = w.Where(e => e.Kind == FileEventKind.Modified || e.Kind == FileEventKind.Renamed).Select(e => Path.GetDirectoryName(e.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (modified >= ModifyThreshold && folders >= 3) { a.Score += 18; a.Reasons.Add(Loc.L(modified + " files in " + folders + " folders were rewritten within seconds", modified + " файлов в " + folders + " папках перезаписаны за секунды")); }

            bool strong = a.CanaryHit || a.Score >= 50;
            if (a.CanaryHit && a.Score >= 80) a.Level = AlertLevel.Dangerous;
            else if (!actorTrusted && a.Score >= 85) a.Level = AlertLevel.Dangerous;
            else if (!actorTrusted && strong) a.Level = AlertLevel.Suspicious;
            else if (a.Score >= 40) a.Level = AlertLevel.Info;          // a trusted program doing something big: mentioned, not an alarm
            return a;
        }
    }

    /// <summary>The write activity of programs, to name the one doing the damage. Windows keeps a count of bytes written per process; two looks a moment apart show who is writing.</summary>
    public static class WriteSampler
    {
        [StructLayout(LayoutKind.Sequential)]
        struct IO_COUNTERS { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
        [DllImport("kernel32.dll")] static extern bool GetProcessIoCounters(IntPtr h, out IO_COUNTERS c);

        public static Dictionary<int, ulong> Snapshot()
        {
            var d = new Dictionary<int, ulong>();
            foreach (var p in System.Diagnostics.Process.GetProcesses())
                using (p)
                {
                    try { IO_COUNTERS c; if (GetProcessIoCounters(p.Handle, out c)) d[p.Id] = c.WriteBytes; } catch { }
                }
            return d;
        }

        public static List<KeyValuePair<int, ulong>> TopWriters(Dictionary<int, ulong> before, Dictionary<int, ulong> after, int n)
        {
            return after.Where(kv => before.ContainsKey(kv.Key) && kv.Value > before[kv.Key]).Select(kv => new KeyValuePair<int, ulong>(kv.Key, kv.Value - before[kv.Key])).OrderByDescending(kv => kv.Value).Take(n).ToList();
        }
    }

    /// <summary>Ransomware Guard (off by default: it places hidden decoy files in your document folders). It watches the user's folders, feeds the detector, and when it fires it names the
    /// program that is writing the most and offers to freeze it. Freezing is the user's choice, never automatic.</summary>
    public sealed class RansomwareGuard : IGuard
    {
        public const string CanaryName = "~MineHunter-canary-do-not-delete.docx";
        GuardContext g; GuardState state = GuardState.Off; string detail = "";
        readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        public RansomDetector Detector = new RansomDetector();
        Timer timer; int busy; DateTime lastAlert = DateTime.MinValue;
        readonly List<string> canaryFiles = new List<string>(); readonly Dictionary<string, string> canaryHash = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string Name { get { return "ransomware"; } }
        public string Title { get { return Loc.L("Ransomware Guard", "Защита от шифровальщиков"); } }
        public GuardStatus Status { get { return new GuardStatus { Name = Name, Title = Title, State = state, Detail = detail }; } }

        public static List<string> ProtectedFolders()
        {
            var l = new List<string>();
            foreach (var up in PathUtil.UserProfiles()) foreach (var n in new[] { "Documents", "Desktop", "Pictures", "Videos", "Music" }) { string d = Path.Combine(up, n); if (Directory.Exists(d)) l.Add(d); }
            return l;
        }

        public void Start(GuardContext ctx) { StartOn(ctx, ProtectedFolders(), true); }

        /// <summary>Starts watching the given folders (tests use their own folder).</summary>
        public void StartOn(GuardContext ctx, IEnumerable<string> folders, bool placeCanaries)
        {
            g = ctx;
            int ok = 0;
            foreach (var f in folders)
            {
                if (placeCanaries) PlaceCanary(f);
                try
                {
                    var w = new FileSystemWatcher(f) { IncludeSubdirectories = true, InternalBufferSize = 64 * 1024, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size };
                    w.Created += (s, e) => Detector.Event(e.FullPath, FileEventKind.Created, null, DateTime.Now);
                    w.Changed += (s, e) => Detector.Event(e.FullPath, FileEventKind.Modified, null, DateTime.Now);
                    w.Renamed += (s, e) => Detector.Event(e.FullPath, FileEventKind.Renamed, e.OldFullPath, DateTime.Now);
                    w.Deleted += (s, e) => Detector.Event(e.FullPath, FileEventKind.Deleted, null, DateTime.Now);
                    w.EnableRaisingEvents = true; watchers.Add(w); ok++;
                }
                catch (Exception ex) { Log.Warn("ransomware guard: cannot watch " + f + ": " + ex.Message); }
            }
            timer = new Timer(_ => Tick(), null, 2000, 2000);
            state = ok == 0 ? GuardState.Error : GuardState.On;
            detail = Loc.L("watching " + ok + " folder(s), " + canaryFiles.Count + " decoy file(s)", "следит за папками: " + ok + ", файлов-приманок: " + canaryFiles.Count);
        }

        public void Stop()
        {
            state = GuardState.Off;
            if (timer != null) { timer.Dispose(); timer = null; }
            foreach (var w in watchers) { try { w.EnableRaisingEvents = false; w.Dispose(); } catch { } }
            watchers.Clear();
        }

        /// <summary>A small, valid .docx with hidden attributes. Ransomware encrypts everything it can reach; this file is not something a person opens.</summary>
        void PlaceCanary(string folder)
        {
            try
            {
                string p = Path.Combine(folder, CanaryName);
                if (!File.Exists(p))
                {
                    using (var fs = File.Create(p))
                    using (var za = new ZipArchive(fs, ZipArchiveMode.Create))
                    {
                        Action<string, string> put = (n, t) => { var e = za.CreateEntry(n); using (var w = new StreamWriter(e.Open())) w.Write(t); };
                        put("[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
                        put("_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>");
                        put("word/document.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>MineHunter decoy file. Safe to delete; if it changes, something is encrypting files.</w:t></w:r></w:p></w:body></w:document>");
                    }
                    File.SetAttributes(p, FileAttributes.Hidden);
                }
                canaryFiles.Add(p); Detector.AddCanary(p); canaryHash[p] = Hashing.Sha256(p);
            }
            catch (Exception ex) { Log.Warn("canary " + folder + ": " + ex.Message); }
        }

        /// <summary>Removes the decoy files (called when the guard is switched off).</summary>
        public static void RemoveCanaries(IEnumerable<string> folders)
        {
            foreach (var f in folders) { try { string p = Path.Combine(f, CanaryName); if (File.Exists(p)) { File.SetAttributes(p, FileAttributes.Normal); File.Delete(p); } } catch { } }
        }

        void Tick()
        {
            if (Interlocked.Exchange(ref busy, 1) == 1) return;
            try
            {
                // a canary that vanished or changed without an event (the watcher buffer overflowed) still counts
                foreach (var p in canaryFiles.ToArray())
                {
                    bool gone = !File.Exists(p); string h = gone ? null : Hashing.Sha256(p);
                    string was; canaryHash.TryGetValue(p, out was);
                    if (gone || (h != null && was != null && h != was)) { Detector.Event(p, gone ? FileEventKind.Deleted : FileEventKind.Modified, null, DateTime.Now); canaryHash[p] = h; }
                }
                Evaluate(DateTime.Now);
            }
            catch (Exception ex) { Log.Warn("ransomware guard: " + ex.Message); }
            finally { Interlocked.Exchange(ref busy, 0); }
        }

        /// <summary>Asks the detector and, when it fires, names the likely program and raises the alert. Public for tests.</summary>
        public GuardAlert Evaluate(DateTime now, Func<List<KeyValuePair<int, ulong>>> writers = null, Func<int, string> pathOf = null, Func<string, bool> isTrusted = null)
        {
            var quick = Detector.Evaluate(now);
            if (quick.Level == null && quick.Score < 40) return null;
            // who is writing? two looks one second apart
            List<KeyValuePair<int, ulong>> top;
            if (writers != null) top = writers();
            else { var a = WriteSampler.Snapshot(); Thread.Sleep(1000); top = WriteSampler.TopWriters(a, WriteSampler.Snapshot(), 3); }
            int pid = 0; string path = null; bool trusted = false;
            pathOf = pathOf ?? (p => { try { using (var pr = System.Diagnostics.Process.GetProcessById(p)) return pr.MainModule.FileName; } catch { return null; } });
            isTrusted = isTrusted ?? (pp => { try { var ti = Trust.Check(pp); return ti != null && ti.IsValid && (g.Rules.IsTrustedPublisher(ti.Publisher) || (ti.Publisher ?? "").StartsWith("Microsoft")); } catch { return false; } });
            foreach (var kv in top)
            {
                string pp = pathOf(kv.Key); if (string.IsNullOrEmpty(pp)) continue;
                pid = kv.Key; path = pp; trusted = isTrusted(pp); break;
            }
            var a2 = Detector.Evaluate(now, trusted && !quick.CanaryHit);
            if (a2.Level == null) return null;
            if (now - lastAlert < TimeSpan.FromMinutes(2)) return null;
            lastAlert = now;
            var alert = new GuardAlert { Guard = Name, Level = a2.Level.Value, Pid = pid, Path = path, Actor = path };
            alert.Title = a2.Level == AlertLevel.Dangerous ? Loc.L("Files are being encrypted", "Идёт шифрование файлов") : a2.Level == AlertLevel.Suspicious ? Loc.L("Many files are changing very fast", "Очень быстро меняется много файлов") : Loc.L("A program is rewriting many files", "Программа перезаписывает много файлов");
            alert.Reasons = a2.Reasons;
            alert.Text = string.Join("; ", a2.Reasons) + "." + (path != null ? " " + Loc.L("The program writing the most right now: \"" + Path.GetFileName(path) + "\"" + (trusted ? " (signed by a trusted publisher)" : "") + ".", "Больше всего сейчас пишет программа «" + Path.GetFileName(path) + "»" + (trusted ? " (подпись доверенного издателя)" : "") + ".") : "")
                       + (a2.Level == AlertLevel.Dangerous && pid > 0 ? " " + Loc.L("You can freeze it right now from this notification; MineHunter will not do it by itself.", "Вы можете заморозить её прямо из этого уведомления; сам MineHunter этого не сделает.") : "");
            if (path != null) { try { alert.Sha256 = Hashing.Sha256(path); } catch { } }
            g.Alert(alert);
            return alert;
        }
    }
}
