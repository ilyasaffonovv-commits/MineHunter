using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using MineHunter.Util;

namespace MineHunter.Analysis
{
    public sealed class PeSection
    {
        public string Name; public uint VirtualSize, VirtualAddress, RawSize, RawPointer, Characteristics; public double Entropy;
        public bool Executable { get { return (Characteristics & 0x20000000) != 0 || (Characteristics & 0x20) != 0; } }
        public bool Writable { get { return (Characteristics & 0x80000000) != 0; } }
    }

    public sealed class PeInfo
    {
        public bool IsPe, Is64, IsDll, IsDotNet, IsDriver, HasCertTable, HasTls, HasResources, HasExports;
        public ushort Machine, Subsystem; public uint TimeDateStamp, SizeOfImage, EntryPoint, Checksum, CertSize;
        public long FileSize, Overlay;
        public List<PeSection> Sections = new List<PeSection>();
        public List<string> ImportDlls = new List<string>();
        public HashSet<string> ApiOfInterest = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public int ImportFuncCount, ExportCount;
        public bool Packed; public string PackerName;
        public double MaxExecEntropy;
        public bool Bloated;
        public string Company, Product, Description, OriginalName, FileVersion, InternalName;
        public string Error;

        public bool LooksInjector
        {
            get
            {
                int n = 0;
                foreach (var a in new[] { "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "NtUnmapViewOfSection", "SetThreadContext", "NtWriteVirtualMemory", "QueueUserAPC", "NtCreateThreadEx", "ZwUnmapViewOfSection", "RtlCreateUserThread" })
                    if (ApiOfInterest.Contains(a)) n++;
                return n >= 3;
            }
        }
        public bool ImportsNativeKernel { get { return ImportDlls.Any(d => d.Equals("ntoskrnl.exe", StringComparison.OrdinalIgnoreCase) || d.Equals("hal.dll", StringComparison.OrdinalIgnoreCase)); } }
    }

    public static class PeAnalyzer
    {
        static readonly Dictionary<string, string> PackerSections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "UPX0", "UPX" }, { "UPX1", "UPX" }, { "UPX2", "UPX" }, { ".aspack", "ASPack" }, { ".adata", "ASPack" }, { ".themida", "Themida" }, { ".winlice", "Themida/WinLicense" },
            { ".vmp0", "VMProtect" }, { ".vmp1", "VMProtect" }, { ".vmp2", "VMProtect" }, { ".petite", "Petite" }, { ".mpress1", "MPRESS" }, { ".mpress2", "MPRESS" },
            { ".enigma1", "Enigma" }, { ".enigma2", "Enigma" }, { ".nsp0", "NsPack" }, { ".nsp1", "NsPack" }, { ".pec1", "PECompact" }, { "PEC2", "PECompact" }, { ".boom", "Boom" },
            { ".yp", "Y0da" }, { "pebundle", "PEBundle" }, { ".perplex", "Perplex" }
        };

        static uint U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
        static ushort U16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }

        static long RvaToOffset(List<PeSection> secs, uint rva, uint sizeOfHeaders)
        {
            if (rva < sizeOfHeaders) return rva;
            foreach (var s in secs)
            {
                uint span = Math.Max(s.VirtualSize, s.RawSize);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span) return (long)s.RawPointer + (rva - s.VirtualAddress);
            }
            return -1;
        }

        /// <summary>Parses headers, section entropy, imports and overlay. Cheap: a few reads per file.</summary>
        public static PeInfo Analyze(string path, bool deep = true)
        {
            var pe = new PeInfo();
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.RandomAccess))
                {
                    pe.FileSize = fs.Length;
                    if (fs.Length < 512) return pe;
                    var dos = new byte[64];
                    if (fs.Read(dos, 0, 64) < 64 || dos[0] != 'M' || dos[1] != 'Z') return pe;
                    int lfanew = (int)U32(dos, 0x3C);
                    if (lfanew < 64 || lfanew > fs.Length - 264) return pe;
                    fs.Seek(lfanew, SeekOrigin.Begin);
                    var hdr = new byte[24 + 240];
                    int got = fs.Read(hdr, 0, hdr.Length);
                    if (got < 24 + 96 || hdr[0] != 'P' || hdr[1] != 'E' || hdr[2] != 0 || hdr[3] != 0) return pe;
                    pe.IsPe = true;
                    pe.Machine = U16(hdr, 4);
                    int nsec = U16(hdr, 6);
                    pe.TimeDateStamp = U32(hdr, 8);
                    int optSize = U16(hdr, 20);
                    ushort chars = U16(hdr, 22);
                    pe.IsDll = (chars & 0x2000) != 0;
                    int opt = 24;
                    ushort magic = U16(hdr, opt);
                    pe.Is64 = magic == 0x20B;
                    pe.EntryPoint = U32(hdr, opt + 16);
                    pe.SizeOfImage = U32(hdr, opt + 56);
                    uint sizeOfHeaders = U32(hdr, opt + 60);
                    pe.Checksum = U32(hdr, opt + 64);
                    pe.Subsystem = U16(hdr, opt + 68);
                    pe.IsDriver = pe.Subsystem == 1;
                    int ddOff = opt + (pe.Is64 ? 112 : 96);
                    int nDirs = (int)Math.Min(16u, U32(hdr, ddOff - 4));
                    Func<int, uint[]> dir = i => (i < nDirs && ddOff + i * 8 + 8 <= hdr.Length) ? new[] { U32(hdr, ddOff + i * 8), U32(hdr, ddOff + i * 8 + 4) } : new uint[] { 0, 0 };
                    var exp = dir(0); var imp = dir(1); var res = dir(2); var sec = dir(4); var tls = dir(9); var clr = dir(14);
                    pe.HasExports = exp[0] != 0; pe.HasResources = res[0] != 0; pe.HasTls = tls[0] != 0; pe.IsDotNet = clr[0] != 0;
                    pe.HasCertTable = sec[0] != 0 && sec[1] != 0; pe.CertSize = sec[1];

                    // sections
                    fs.Seek(lfanew + 24 + optSize, SeekOrigin.Begin);
                    var sh = new byte[40 * Math.Min(nsec, 96)];
                    if (fs.Read(sh, 0, sh.Length) < sh.Length) return pe;
                    long lastRaw = 0;
                    for (int i = 0; i < sh.Length / 40; i++)
                    {
                        int o = i * 40;
                        var s = new PeSection
                        {
                            Name = Encoding.ASCII.GetString(sh, o, 8).TrimEnd('\0'), VirtualSize = U32(sh, o + 8), VirtualAddress = U32(sh, o + 12),
                            RawSize = U32(sh, o + 16), RawPointer = U32(sh, o + 20), Characteristics = U32(sh, o + 36)
                        };
                        pe.Sections.Add(s);
                        lastRaw = Math.Max(lastRaw, (long)s.RawPointer + s.RawSize);
                        string pk;
                        if (PackerSections.TryGetValue(s.Name, out pk)) { pe.Packed = true; pe.PackerName = pk; }
                    }
                    long overlay = pe.FileSize - lastRaw;
                    if (pe.HasCertTable && sec[0] >= lastRaw) overlay -= sec[1];
                    pe.Overlay = Math.Max(0, overlay);

                    if (deep)
                    {
                        // entropy of each section (first 256 KB sample)
                        var buf = new byte[256 * 1024];
                        foreach (var s in pe.Sections)
                        {
                            if (s.RawSize == 0 || s.RawPointer >= pe.FileSize) continue;
                            int want = (int)Math.Min(buf.Length, Math.Min(s.RawSize, pe.FileSize - s.RawPointer));
                            fs.Seek(s.RawPointer, SeekOrigin.Begin);
                            int r = fs.Read(buf, 0, want);
                            s.Entropy = Text.Entropy(buf, r);
                            if (s.Executable && r > 32 * 1024) pe.MaxExecEntropy = Math.Max(pe.MaxExecEntropy, s.Entropy);
                        }

                        // imports
                        if (imp[0] != 0) ReadImports(fs, pe, imp[0], sizeOfHeaders);
                        if (pe.HasExports && exp[0] != 0)
                        {
                            long eo = RvaToOffset(pe.Sections, exp[0], sizeOfHeaders);
                            if (eo > 0 && eo + 40 < pe.FileSize) { var eb = new byte[40]; fs.Seek(eo, SeekOrigin.Begin); if (fs.Read(eb, 0, 40) == 40) pe.ExportCount = (int)Math.Min(U32(eb, 24), 100000); }
                        }

                        // bloat: huge file whose overlay / tail is a repeated pattern (used to hide from sandboxes / cloud AV)
                        if (pe.FileSize > 100L * 1024 * 1024 && pe.Overlay > 50L * 1024 * 1024)
                        {
                            int repeated = 0, tested = 0;
                            var blk = new byte[8192];
                            foreach (double frac in new[] { 0.25, 0.5, 0.75, 0.95 })
                            {
                                long pos = lastRaw + (long)(pe.Overlay * frac);
                                if (pos + blk.Length > pe.FileSize) pos = pe.FileSize - blk.Length;
                                fs.Seek(pos, SeekOrigin.Begin);
                                int r = fs.Read(blk, 0, blk.Length);
                                if (r < 1024) continue;
                                tested++;
                                var freq = new int[256];
                                for (int i = 0; i < r; i++) freq[blk[i]]++;
                                if ((double)freq.Max() / r >= 0.9 || Text.Entropy(blk, r) < 1.0) repeated++;
                            }
                            pe.Bloated = tested >= 3 && repeated >= tested - 1;
                        }
                    }
                }
                try
                {
                    var vi = FileVersionInfo.GetVersionInfo(path);
                    pe.Company = vi.CompanyName; pe.Product = vi.ProductName; pe.Description = vi.FileDescription;
                    pe.OriginalName = vi.OriginalFilename; pe.FileVersion = vi.FileVersion; pe.InternalName = vi.InternalName;
                }
                catch { }
            }
            catch (Exception ex) { pe.Error = ex.Message; }
            return pe;
        }

        static void ReadImports(FileStream fs, PeInfo pe, uint importRva, uint sizeOfHeaders)
        {
            try
            {
                long io = RvaToOffset(pe.Sections, importRva, sizeOfHeaders);
                if (io < 0 || io >= pe.FileSize) return;
                int thunkSize = pe.Is64 ? 8 : 4;
                var desc = new byte[20];
                int totalFuncs = 0;
                for (int d = 0; d < 300; d++)
                {
                    fs.Seek(io + d * 20, SeekOrigin.Begin);
                    if (fs.Read(desc, 0, 20) < 20) break;
                    uint oft = U32(desc, 0), nameRva = U32(desc, 12), ft = U32(desc, 16);
                    if (nameRva == 0 && ft == 0) break;
                    long no = RvaToOffset(pe.Sections, nameRva, sizeOfHeaders);
                    if (no < 0) continue;
                    string dll = ReadCString(fs, no, 128);
                    if (!string.IsNullOrEmpty(dll)) pe.ImportDlls.Add(dll.ToLowerInvariant());
                    uint thunkRva = oft != 0 ? oft : ft;
                    long to = RvaToOffset(pe.Sections, thunkRva, sizeOfHeaders);
                    if (to < 0) continue;
                    var tb = new byte[thunkSize];
                    for (int f = 0; f < 1500; f++)
                    {
                        fs.Seek(to + f * thunkSize, SeekOrigin.Begin);
                        if (fs.Read(tb, 0, thunkSize) < thunkSize) break;
                        ulong v = thunkSize == 8 ? BitConverter.ToUInt64(tb, 0) : BitConverter.ToUInt32(tb, 0);
                        if (v == 0) break;
                        totalFuncs++;
                        bool ordinal = thunkSize == 8 ? (v & 0x8000000000000000UL) != 0 : (v & 0x80000000UL) != 0;
                        if (ordinal) continue;
                        long fo = RvaToOffset(pe.Sections, (uint)(v & 0x7FFFFFFF), sizeOfHeaders);
                        if (fo < 0) continue;
                        string fn = ReadCString(fs, fo + 2, 64);
                        if (fn != null && IsInteresting(fn)) pe.ApiOfInterest.Add(fn);
                        if (totalFuncs > 6000) break;
                    }
                    if (totalFuncs > 6000) break;
                }
                pe.ImportFuncCount = totalFuncs;
            }
            catch { }
        }

        static readonly HashSet<string> Interesting = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "WriteProcessMemory","VirtualAllocEx","CreateRemoteThread","NtUnmapViewOfSection","ZwUnmapViewOfSection","SetThreadContext","NtWriteVirtualMemory","QueueUserAPC",
            "NtCreateThreadEx","RtlCreateUserThread","ResumeThread","NtResumeThread","OpenProcess","VirtualProtectEx","NtSuspendProcess","CryptAcquireContextW","InternetOpenUrlA","URLDownloadToFileW",
            "URLDownloadToFileA","WinHttpOpen","InternetOpenA","SetWindowsHookExW","GetAsyncKeyState","NtQuerySystemInformation","RegSetValueExW","CreateServiceW","StartServiceW","AdjustTokenPrivileges"
        };
        static bool IsInteresting(string fn) { return Interesting.Contains(fn); }

        static string ReadCString(FileStream fs, long off, int max)
        {
            if (off < 0 || off >= fs.Length) return null;
            fs.Seek(off, SeekOrigin.Begin);
            var b = new byte[max];
            int r = fs.Read(b, 0, max);
            int n = 0; while (n < r && b[n] != 0) n++;
            return n == 0 ? null : Encoding.ASCII.GetString(b, 0, n);
        }
    }

    /// <summary>Multi-pattern, case-insensitive byte scanner (Aho–Corasick DFA). Each pattern is searched as ASCII and UTF-16LE.</summary>
    public sealed class StringScanner
    {
        readonly int[] go;           // states * 256
        readonly int[][] outputs;    // per state: pattern ids
        readonly int states;
        public readonly int PatternCount;

        public StringScanner(IList<string> patterns)
        {
            PatternCount = patterns.Count;
            var trie = new List<int[]>();
            var outs = new List<List<int>>();
            Func<int> newState = () => { var a = new int[256]; for (int i = 0; i < 256; i++) a[i] = -1; trie.Add(a); outs.Add(null); return trie.Count - 1; };
            newState();
            Action<byte[], int> add = (bytes, id) =>
            {
                int s = 0;
                foreach (var raw in bytes)
                {
                    byte b = (raw >= 'A' && raw <= 'Z') ? (byte)(raw + 32) : raw;
                    if (trie[s][b] < 0) { int ns = newState(); trie[s][b] = ns; }
                    s = trie[s][b];
                }
                if (outs[s] == null) outs[s] = new List<int>();
                if (!outs[s].Contains(id)) outs[s].Add(id);
            };
            for (int id = 0; id < patterns.Count; id++)
            {
                var a = Encoding.ASCII.GetBytes(patterns[id]);
                if (a.Length < 3) continue;
                add(a, id);
                var u = new byte[a.Length * 2];
                for (int i = 0; i < a.Length; i++) { u[i * 2] = a[i]; u[i * 2 + 1] = 0; }
                add(u, id);
            }
            states = trie.Count;
            go = new int[states * 256];
            var fail = new int[states];
            var queue = new Queue<int>();
            for (int c = 0; c < 256; c++)
            {
                int t = trie[0][c];
                if (t < 0) go[c] = 0; else { go[c] = t; fail[t] = 0; queue.Enqueue(t); }
            }
            while (queue.Count > 0)
            {
                int r = queue.Dequeue();
                if (outs[fail[r]] != null)
                {
                    if (outs[r] == null) outs[r] = new List<int>();
                    foreach (var o in outs[fail[r]]) if (!outs[r].Contains(o)) outs[r].Add(o);
                }
                for (int c = 0; c < 256; c++)
                {
                    int t = trie[r][c];
                    if (t < 0) go[r * 256 + c] = go[fail[r] * 256 + c];
                    else { go[r * 256 + c] = t; fail[t] = go[fail[r] * 256 + c]; queue.Enqueue(t); }
                }
            }
            outputs = outs.Select(l => l == null ? null : l.ToArray()).ToArray();
        }

        /// <summary>Scans the head and tail of a file. Returns pattern id → hit count.</summary>
        public Dictionary<int, int> ScanFile(string path, long headBytes, long tailBytes, out long bytesRead)
        {
            var hits = new Dictionary<int, int>();
            bytesRead = 0;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan))
                {
                    long len = fs.Length;
                    var buf = new byte[1 << 20];
                    int state = 0;
                    long remaining = Math.Min(len, headBytes);
                    while (remaining > 0)
                    {
                        int r = fs.Read(buf, 0, (int)Math.Min(buf.Length, remaining));
                        if (r <= 0) break;
                        remaining -= r; bytesRead += r;
                        state = Feed(buf, r, state, hits);
                    }
                    if (len > headBytes && tailBytes > 0)
                    {
                        long start = Math.Max(headBytes, len - tailBytes);
                        fs.Seek(start, SeekOrigin.Begin);
                        state = 0;
                        while (true)
                        {
                            int r = fs.Read(buf, 0, buf.Length);
                            if (r <= 0) break;
                            bytesRead += r;
                            state = Feed(buf, r, state, hits);
                        }
                    }
                }
            }
            catch { }
            return hits;
        }

        public Dictionary<int, int> ScanBytes(byte[] data, int count)
        {
            var hits = new Dictionary<int, int>();
            Feed(data, count, 0, hits);
            return hits;
        }

        int Feed(byte[] buf, int count, int state, Dictionary<int, int> hits)
        {
            for (int i = 0; i < count; i++)
            {
                byte b = buf[i];
                if (b >= 'A' && b <= 'Z') b += 32;
                state = go[state * 256 + b];
                var o = outputs[state];
                if (o != null) foreach (var id in o) { int c; hits.TryGetValue(id, out c); hits[id] = c + 1; }
            }
            return state;
        }
    }
}
