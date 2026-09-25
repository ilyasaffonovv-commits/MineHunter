using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Persistent memory of files that were already judged (signature trusted / low risk), keyed by path+size+mtime.
    /// It makes repeat scans fast: only new or changed files are examined again. Low-risk entries expire whenever the rule pack changes.</summary>
    public sealed class ScanCache
    {
        readonly ConcurrentDictionary<string, byte> map = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        public string RulesVersion = "";
        public int Count { get { return map.Count; } }
        public static string FilePath { get { return Path.Combine(RulePack.DataDir, "scancache.bin.gz"); } }

        static string Key(FileInfo fi) { return fi.FullName + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks; }
        public bool TryGet(FileInfo fi, out byte code) { return map.TryGetValue(Key(fi), out code); }
        public void Set(FileInfo fi, byte code) { map[Key(fi)] = code; }

        public static ScanCache Load(string rulesVersion)
        {
            var c = new ScanCache { RulesVersion = rulesVersion };
            try
            {
                if (!File.Exists(FilePath)) return c;
                using (var fs = File.OpenRead(FilePath))
                using (var gz = new GZipStream(fs, CompressionMode.Decompress))
                using (var br = new BinaryReader(gz, System.Text.Encoding.UTF8))
                {
                    if (br.ReadInt32() != 0x4D48434B) return c;               // "MHCK"
                    string ver = br.ReadString();
                    int n = br.ReadInt32();
                    bool sameRules = ver == rulesVersion;
                    for (int i = 0; i < n; i++)
                    {
                        string k = br.ReadString(); byte code = br.ReadByte();
                        if (code == 1 || sameRules) c.map[k] = code;         // "trusted" entries are signature-based and survive rule updates
                    }
                }
            }
            catch (Exception ex) { Log.Warn("scan cache ignored: " + ex.Message); }
            return c;
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(RulePack.DataDir);
                string tmp = FilePath + ".tmp";
                using (var fs = File.Create(tmp))
                using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
                using (var bw = new BinaryWriter(gz, System.Text.Encoding.UTF8))
                {
                    bw.Write(0x4D48434B); bw.Write(RulesVersion ?? "");
                    var items = map.ToArray();
                    bw.Write(items.Length);
                    foreach (var kv in items) { bw.Write(kv.Key); bw.Write(kv.Value); }
                }
                if (File.Exists(FilePath)) File.Delete(FilePath);
                File.Move(tmp, FilePath);
            }
            catch (Exception ex) { Log.Warn("scan cache not saved: " + ex.Message); }
        }
    }

    public static class FileSystemScanner
    {
        static readonly HashSet<string> SkipDirNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "node_modules", ".git", "winsxs", "$recycle.bin", "system volume information", "windowsapps", "servicing", "softwaredistribution", "$winreagent", "recovery",
            "config.msi", "package cache", "crashdumps", "cache", "code cache", "gpucache", "shadercache", "dawncache", "grshadercache", "indexeddb", "service worker", "local storage",
            "session storage", "crashpad", "__pycache__", "assembly", "installer", "windows.old", "$windows.~bt", "$windows.~ws", "logs", "temporary internet files", "inetcache", "webcache"
        };

        static readonly string[] PeExts = { ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".drv" };
        static readonly string[] ScriptExts = { ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".wsf", ".hta", ".jse" };

        sealed class Root { public string Path; public int Depth; public Func<string, int, bool> FileFilter; public bool SkipStd = true; }

        static bool Has(string[] set, string ext) { return Array.IndexOf(set, ext) >= 0; }

        public static void Run(ScanContext ctx)
        {
            var sw = Stopwatch.StartNew();
            var roots = BuildRoots(ctx);
            long screened = 0;
            int total = roots.Count, idx = 0;
            var opts = new ParallelOptions { MaxDegreeOfParallelism = ctx.Options.Parallelism, CancellationToken = ctx.Cancel };
            bool budgetHit = false;
            TimeSpan budget = TimeSpan.FromMinutes(ctx.Options.Mode == ScanMode.Full ? ctx.Options.MaxFullScanMinutes : 12);

            var doneRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);     // a later, wider root (a whole drive) must not walk these folders a second time
            foreach (var root in roots)
            {
                ctx.ThrowIfCancelled();
                idx++;
                if (!Directory.Exists(root.Path)) continue;
                if (sw.Elapsed > budget) { budgetHit = true; break; }
                ctx.Report("Files: " + root.Path, 70 + (int)(25.0 * idx / Math.Max(1, total)));
                var files = Fs.EnumerateFiles(root.Path, d => (!root.SkipStd || !SkipDirNames.Contains(Path.GetFileName(d))) && !doneRoots.Contains(d.TrimEnd(Path.DirectorySeparatorChar)), f => root.FileFilter(f, 0), root.Depth, d => ctx.Denied("Files", d));
                var part = Partitioner.Create(files, EnumerablePartitionerOptions.NoBuffering);
                try
                {
                    Parallel.ForEach(part, opts, (f, state) =>
                    {
                        if (sw.Elapsed > budget) { budgetHit = true; state.Stop(); return; }
                        if (ctx.IsSelf(f)) return;
                        ctx.Files.Screen(f);
                        long n = Interlocked.Increment(ref screened);
                        if (n % 2000 == 0) ctx.Report("Files examined: " + n + "  (" + root.Path + ")", 70 + (int)(25.0 * idx / Math.Max(1, total)));
                    });
                }
                catch (OperationCanceledException) { throw; }
                catch (AggregateException ae) { if (ae.InnerExceptions.Any(x => x is OperationCanceledException)) throw new OperationCanceledException(); Log.Warn("file scan: " + ae.InnerExceptions.First().Message); }
                if (ctx.Options.Mode == ScanMode.Full && root.Depth >= 12) doneRoots.Add(root.Path.TrimEnd(Path.DirectorySeparatorChar));
            }
            if (budgetHit)
                ctx.AddBlind("Full scan", "stopped after " + (int)sw.Elapsed.TotalMinutes + " minutes (time budget): part of the disks was not examined. Run again - the cache makes the next pass much faster.");
        }

        static List<Root> BuildRoots(ScanContext ctx)
        {
            var list = new List<Root>();
            Func<string, int, bool> exeOnly = (f, d) => { string e = Path.GetExtension(f).ToLowerInvariant(); return e == ".exe" || e == ".scr" || e == ".com" || e == ".cpl" || Has(ScriptExts, e); };
            Func<string, int, bool> exeAndDll = (f, d) => { string e = Path.GetExtension(f).ToLowerInvariant(); return Has(PeExts, e) || Has(ScriptExts, e); };
            Func<string, int, bool> rootLevel = (f, d) =>
            {
                string e = Path.GetExtension(f).ToLowerInvariant();
                if (e.Length == 0) { try { var len = new FileInfo(f).Length; return len > 30 * 1024 && len < 300L * 1024 * 1024; } catch { return false; } }
                return Has(PeExts, e) || Has(ScriptExts, e);
            };

            if (ctx.Options.Mode == ScanMode.Custom)
            {
                if (!string.IsNullOrEmpty(ctx.Options.CustomPath)) list.Add(new Root { Path = ctx.Options.CustomPath, Depth = 40, FileFilter = exeAndDll, SkipStd = false });
                return list;
            }

            if (ctx.Options.Mode == ScanMode.Full)
            {
                foreach (var d in DriveInfo.GetDrives().Where(x => x.DriveType == DriveType.Fixed && x.IsReady))
                    list.Add(new Root { Path = d.RootDirectory.FullName, Depth = 40, FileFilter = exeAndDll });
                // user areas first are covered by the drive walk; also make sure the profile roots are visited early
                foreach (var up in PathUtil.UserProfiles()) list.Insert(0, new Root { Path = up, Depth = 40, FileFilter = exeAndDll });
                list.Insert(0, new Root { Path = PathUtil.ProgramData, Depth = 40, FileFilter = exeAndDll });
                return list;
            }

            // ---- Quick: the places where droppers, miners and their persistence actually live
            foreach (var up in PathUtil.UserProfiles())
            {
                list.Add(new Root { Path = Path.Combine(up, @"AppData\Local\Temp"), Depth = 3, FileFilter = rootLevel });
                list.Add(new Root { Path = Path.Combine(up, @"AppData\Roaming"), Depth = 4, FileFilter = (f, d) => IsRootOrExe(f, up, "AppData\\Roaming", exeOnly, rootLevel) });
                list.Add(new Root { Path = Path.Combine(up, @"AppData\Local"), Depth = 4, FileFilter = (f, d) => IsRootOrExe(f, up, "AppData\\Local", exeOnly, rootLevel) });
                list.Add(new Root { Path = Path.Combine(up, "Downloads"), Depth = 2, FileFilter = exeOnly });
                list.Add(new Root { Path = Path.Combine(up, "Desktop"), Depth = 2, FileFilter = exeOnly });
                list.Add(new Root { Path = Path.Combine(up, "Documents"), Depth = 1, FileFilter = exeOnly });
                list.Add(new Root { Path = Path.Combine(up, "Music"), Depth = 1, FileFilter = exeOnly });
                list.Add(new Root { Path = Path.Combine(up, "Videos"), Depth = 1, FileFilter = exeOnly });
            }
            list.Add(new Root { Path = PathUtil.ProgramData, Depth = 4, FileFilter = (f, d) => exeOnly(f, d) || (Path.GetDirectoryName(f).Equals(PathUtil.ProgramData, StringComparison.OrdinalIgnoreCase) && rootLevel(f, d)) });
            list.Add(new Root { Path = Path.Combine(PathUtil.SystemDrive + "\\", @"Users\Public"), Depth = 3, FileFilter = exeAndDll });
            list.Add(new Root { Path = Path.Combine(PathUtil.WinDir, "Temp"), Depth = 3, FileFilter = exeAndDll });
            list.Add(new Root { Path = Path.Combine(PathUtil.WinDir, "Tasks"), Depth = 2, FileFilter = exeAndDll });
            list.Add(new Root { Path = PathUtil.WinDir, Depth = 0, FileFilter = exeOnly });
            list.Add(new Root { Path = PathUtil.System32, Depth = 0, FileFilter = (f, d) => { string e = Path.GetExtension(f).ToLowerInvariant(); return e == ".exe" || e == ".scr" || e == ".com"; } });
            list.Add(new Root { Path = PathUtil.SysWow64, Depth = 0, FileFilter = (f, d) => { string e = Path.GetExtension(f).ToLowerInvariant(); return e == ".exe" || e == ".scr" || e == ".com"; } });
            list.Add(new Root { Path = Path.Combine(PathUtil.System32, "drivers"), Depth = 0, FileFilter = (f, d) => f.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) });
            foreach (var d in DriveInfo.GetDrives().Where(x => x.DriveType == DriveType.Fixed && x.IsReady))
                list.Add(new Root { Path = d.RootDirectory.FullName, Depth = 0, FileFilter = exeAndDll });
            // Program Files: only look one level deep for loose unsigned files dropped next to real applications
            list.Add(new Root { Path = PathUtil.ProgramFiles, Depth = 1, FileFilter = exeOnly });
            list.Add(new Root { Path = PathUtil.ProgramFilesX86, Depth = 1, FileFilter = exeOnly });
            // Recycle Bin (executables stored there are a classic hiding place)
            try
            {
                foreach (var d in DriveInfo.GetDrives().Where(x => x.DriveType == DriveType.Fixed && x.IsReady))
                    list.Add(new Root { Path = Path.Combine(d.RootDirectory.FullName, "$Recycle.Bin"), Depth = 2, FileFilter = exeAndDll, SkipStd = false });
            }
            catch { }
            return list;
        }

        static bool IsRootOrExe(string f, string userRoot, string relBase, Func<string, int, bool> exeOnly, Func<string, int, bool> rootLevel)
        {
            string dir = Path.GetDirectoryName(f);
            string baseDir = Path.Combine(userRoot, relBase);
            if (string.Equals(dir, baseDir, StringComparison.OrdinalIgnoreCase)) return rootLevel(f, 0);      // files directly in AppData\Roaming / AppData\Local
            return exeOnly(f, 0);
        }
    }
}
