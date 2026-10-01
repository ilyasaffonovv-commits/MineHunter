using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using MineHunter.Model;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>NTFS alternate data streams: a program can be hidden inside a stream of an innocent-looking file (<c>notes.txt:payload.exe</c>); Explorer and
    /// the file size never show it. Looks for executable or script content inside streams of files in the places malware drops things.</summary>
    public static class AdsScanner
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_STREAM_DATA { public long StreamSize; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstStreamW(string fileName, int infoLevel, out WIN32_FIND_STREAM_DATA data, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool FindNextStreamW(IntPtr h, out WIN32_FIND_STREAM_DATA data);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool FindClose(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool DeleteFileW(string name);

        public sealed class StreamInfo { public string Name; public long Size; }

        // streams Windows and common programs create on their own
        static readonly string[] Benign =
        {
            "zone.identifier", "smartscreen", "afp_afpinfo", "afp_resource", "favicon", "com.dropbox", "encryptable", "oecustomproperty", "summaryinformation", "docsummaryinformation",
            "$cmdtcid", "ms.onedrive", "ms.icloud", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}", "wofcompresseddata", "$kernel.", "$ea", "thumbnail", "com.apple."
        };

        /// <summary>The named streams of a file or folder (the default data stream is not listed). Empty when none or when the file system has no streams.</summary>
        public static List<StreamInfo> Streams(string path)
        {
            var list = new List<StreamInfo>();
            WIN32_FIND_STREAM_DATA d;
            IntPtr h = FindFirstStreamW(path, 0, out d, 0);
            if (h == new IntPtr(-1)) return list;
            try
            {
                do
                {
                    string n = d.cStreamName ?? "";
                    if (n == "::$DATA" || n.Length == 0) continue;
                    // ":name:$DATA" -> "name"
                    string name = n.StartsWith(":") ? n.Substring(1) : n;
                    int c = name.LastIndexOf(":$", StringComparison.Ordinal);
                    if (c > 0) name = name.Substring(0, c);
                    list.Add(new StreamInfo { Name = name, Size = d.StreamSize });
                }
                while (FindNextStreamW(h, out d));
            }
            finally { FindClose(h); }
            return list;
        }

        static bool IsBenign(string name)
        {
            string l = name.ToLowerInvariant();
            return Benign.Any(b => l.Contains(b)) || (l.Length > 0 && l[0] < 0x20);
        }

        // .NET Framework rejects "file:stream" in File.* and FileStream(string) ("path format not supported"); the Win32 calls take it as it is.
        static string Win32Name(string path, string stream)
        {
            string full = path + ":" + stream;
            if (full.StartsWith(@"\\?\")) return full;
            return full.StartsWith(@"\\") ? @"\\?\UNC\" + full.Substring(2) : @"\\?\" + full;
        }

        /// <summary>Reads the start of a stream (at most <paramref name="max"/> bytes). Null when the stream cannot be opened.</summary>
        public static byte[] Head(string path, string stream, int max = 4096)
        {
            try
            {
                using (var h = CreateFileW(Win32Name(path, stream), 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero))
                {
                    if (h.IsInvalid) return null;
                    using (var fs = new FileStream(h, FileAccess.Read, 4096, false))
                    {
                        var buf = new byte[(int)Math.Min(max, fs.Length)];
                        int n = 0, got;
                        while (n < buf.Length && (got = fs.Read(buf, n, buf.Length - n)) > 0) n += got;
                        return n == buf.Length ? buf : buf.Take(n).ToArray();
                    }
                }
            }
            catch { return null; }
        }

        /// <summary>The whole stream, or null when it cannot be read or is larger than <paramref name="limit"/> bytes.</summary>
        public static byte[] ReadAll(string path, string stream, long limit = 256L * 1024 * 1024)
        {
            foreach (var s in Streams(path))
                if (string.Equals(s.Name, stream, StringComparison.OrdinalIgnoreCase))
                    return s.Size > limit ? null : Head(path, s.Name, (int)s.Size);
            return null;
        }

        /// <summary>Creates or overwrites a stream of an existing file.</summary>
        public static bool Write(string path, string stream, byte[] data)
        {
            try
            {
                using (var h = CreateFileW(Win32Name(path, stream), 0x40000000, 0, IntPtr.Zero, 2, 0x80, IntPtr.Zero))
                {
                    if (h.IsInvalid) return false;
                    using (var fs = new FileStream(h, FileAccess.Write, 4096, false)) { fs.Write(data, 0, data.Length); fs.Flush(); }
                    return true;
                }
            }
            catch { return false; }
        }

        /// <summary>Deletes one stream; the file itself stays.</summary>
        public static bool Delete(string path, string stream)
        {
            try { return DeleteFileW(Win32Name(path, stream)); } catch { return false; }
        }

        public static void Run(ScanContext ctx)
        {
            var roots = new List<KeyValuePair<string, int>>();
            foreach (var up in PathUtil.UserProfiles())
            {
                roots.Add(new KeyValuePair<string, int>(Path.Combine(up, @"AppData\Local\Temp"), 3));
                roots.Add(new KeyValuePair<string, int>(Path.Combine(up, @"AppData\Roaming"), 3));
                roots.Add(new KeyValuePair<string, int>(Path.Combine(up, @"AppData\Local"), 2));
                roots.Add(new KeyValuePair<string, int>(Path.Combine(up, "Downloads"), 2));
                roots.Add(new KeyValuePair<string, int>(Path.Combine(up, "Desktop"), 2));
                roots.Add(new KeyValuePair<string, int>(Path.Combine(up, "Documents"), 1));
                roots.Add(new KeyValuePair<string, int>(Path.Combine(up, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), 1));
            }
            roots.Add(new KeyValuePair<string, int>(PathUtil.ProgramData, 3));
            roots.Add(new KeyValuePair<string, int>(Path.Combine(PathUtil.SystemDrive + "\\", @"Users\Public"), 3));
            roots.Add(new KeyValuePair<string, int>(Path.Combine(PathUtil.WinDir, "Temp"), 2));
            roots.Add(new KeyValuePair<string, int>(PathUtil.SystemDrive + "\\", 0));

            var sw = Stopwatch.StartNew();
            int seen = 0, withStreams = 0;
            var done = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in roots)
            {
                if (!Directory.Exists(r.Key) || !done.Add(PathUtil.Key(r.Key))) continue;
                IEnumerable<string> files;
                try { files = Fs.EnumerateFiles(r.Key, d => !IsNoise(d), f => true, r.Value, d => ctx.Denied("Alternate data streams", d)); }
                catch { continue; }
                foreach (var f in files)
                {
                    ctx.ThrowIfCancelled();
                    if (++seen > 80000 || sw.Elapsed > TimeSpan.FromSeconds(25)) { ctx.AddBlind("Alternate data streams", "stopped after " + seen + " files / " + (int)sw.Elapsed.TotalSeconds + " s (budget): the rest of the folders was not looked at"); return; }
                    List<StreamInfo> streams;
                    try { streams = Streams(f); } catch { continue; }
                    if (streams.Count == 0) continue;
                    var odd = streams.Where(s => !IsBenign(s.Name)).ToList();
                    if (odd.Count == 0) continue;
                    withStreams++;
                    Evaluate(ctx, f, odd);
                }
            }
            ctx.Stats.StreamFilesChecked = seen;
        }

        static bool IsNoise(string dir)
        {
            string n = Path.GetFileName(dir.TrimEnd('\\'));
            return n.Equals("node_modules", StringComparison.OrdinalIgnoreCase) || n.Equals(".git", StringComparison.OrdinalIgnoreCase) || n.Equals("Cache", StringComparison.OrdinalIgnoreCase)
                || n.Equals("Code Cache", StringComparison.OrdinalIgnoreCase) || n.Equals("GPUCache", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>What the start of a stream looks like: an executable, a script, or just a large block of hidden data.</summary>
        internal static bool Classify(byte[] head, long size, out string rule, out int weight, out bool definitive, out string text, out string kind)
        {
            rule = null; weight = 0; definitive = false; text = null; kind = null;
            if (head == null || head.Length == 0) return false;
            if (head.Length >= 2 && head[0] == 'M' && head[1] == 'Z')
            { rule = "ADS.PE_STREAM"; weight = 55; definitive = true; text = "A program (PE executable) is hidden inside an alternate data stream of this file: Explorer shows nothing"; kind = "PE"; return true; }
            string l = Encoding.UTF8.GetString(head).ToLowerInvariant();
            if (l.Contains("powershell") || l.Contains("cmd /c") || l.Contains("cmd.exe") || l.Contains("wscript") || l.Contains("createobject(") || l.Contains("<script") || l.StartsWith("#!") || l.Contains("invoke-expression") || l.Contains("@echo off"))
            { rule = "ADS.SCRIPT_STREAM"; weight = 30; text = "A script is hidden inside an alternate data stream of this file"; kind = "script"; return true; }
            if (size > 4096)
            { rule = "ADS.HIDDEN_DATA"; weight = 8; text = "A large block of data (" + (size / 1024) + " KB) is hidden in an alternate data stream of this file"; kind = "data"; return true; }
            return false;
        }

        internal static bool IsBenignStream(string name) { return IsBenign(name); }

        static void Evaluate(ScanContext ctx, string path, List<StreamInfo> odd)
        {
            Entity e = null;
            foreach (var s in odd)
            {
                var head = Head(path, s.Name);
                if (head == null || head.Length == 0) continue;
                string kind, rule, text; int w; bool def;
                if (!Classify(head, s.Size, out rule, out w, out def, out text, out kind)) continue;
                if (e == null) e = ctx.Files.Inspect(path, FileRole.Referenced);
                if (e == null) return;
                e.Add(new Evidence(rule, EvidenceCategory.Content, w, text, path + ":" + s.Name + " (" + s.Size + " bytes, " + kind + ")", def));
                string have = e.P("adsStreams");
                e.Set("adsStreams", string.IsNullOrEmpty(have) ? s.Name : have + "|" + s.Name);
            }
        }
    }

    /// <summary>Names inside a ZIP archive (no extraction): a miner shipped in an archive keeps its name until it is unpacked.</summary>
    public static class ArchiveNames
    {
        static readonly string[] CodeExt = { ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".scr" };

        public static bool Wanted(string path, long length)
        {
            return string.Equals(Path.GetExtension(path), ".zip", StringComparison.OrdinalIgnoreCase) && length > 100 && length <= 400L * 1024 * 1024 && PathUtil.IsUserWritable(path);
        }

        /// <summary>Returns a description of the first suspicious name, or null.</summary>
        public static string Find(ScanContext ctx, string path, out int weight)
        {
            weight = 0;
            try
            {
                using (var za = ZipFile.OpenRead(path))
                {
                    int n = 0;
                    foreach (var en in za.Entries)
                    {
                        if (++n > 3000) break;
                        string name = en.Name;
                        if (string.IsNullOrEmpty(name)) continue;
                        string ext = Path.GetExtension(name).ToLowerInvariant();
                        string stem = Path.GetFileNameWithoutExtension(name).ToLowerInvariant();
                        if (!CodeExt.Contains(ext)) continue;
                        if (ctx.Rules.MinerFileNames.Any(m => stem == m || (m.Length >= 5 && stem.StartsWith(m + "-")) || (m.Length >= 5 && stem.StartsWith(m + "_"))))
                        { weight = 20; return "\"" + en.FullName + "\" is named like a known cryptominer"; }
                        if (ext == ".sys" && ctx.Rules.VulnerableDrivers.Any(v => stem.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0))
                        { weight = 10; return "\"" + en.FullName + "\" is a known vulnerable driver"; }
                    }
                }
            }
            catch { }
            return null;
        }
    }
}
