using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MineHunter.Analysis;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Reads a text file and decides whether it is the configuration of a cryptominer (pools + user/wallet + mining options).
    /// Packed or renamed miners hide their strings inside the EXE, but they still need a pool address and a wallet from somewhere: very often a
    /// config.json lying next to them.</summary>
    internal static class MinerConfigAnalyzer
    {
        static readonly Regex Pools = new Regex("\"pools?\"\\s*:\\s*[\\[{]", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex PoolUrl = new Regex("\"(url|host|server|pool|address)\"\\s*:\\s*\"[^\"\\r\\n]*[a-z0-9.\\-\\]]:\\d{2,5}\"", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex User = new Regex("\"(user|wallet|login|username|worker)\"\\s*:\\s*\"[^\"\\s]{6,}\"", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly string[] ConfigExt = { ".json", ".txt", ".cfg", ".conf", ".ini" };

        /// <summary>Names miners and their bundles use for configuration files (xmrig: config.json, lolMiner: user_config.json, SRBMiner: Config-*.json ...).</summary>
        public static bool IsCandidateName(string path)
        {
            string name = Path.GetFileName(path ?? "").ToLowerInvariant();
            string ext = Path.GetExtension(name);
            if (!ConfigExt.Contains(ext)) return false;
            return name.StartsWith("config") || name.StartsWith("user_config") || name.StartsWith("pool") || name.StartsWith("miner") || name.StartsWith(Obf.J("xm", "rig")) || name == "start.json";
        }

        public static bool IsConfigExtension(string path) { return ConfigExt.Contains(Path.GetExtension(path ?? "").ToLowerInvariant()); }

        public sealed class Result { public int Weight; public bool Definitive; public string RuleId, Text, Detail; }

        /// <summary>Null when the file is not a miner configuration.</summary>
        public static Result Analyze(ScanContext ctx, string path, long maxBytes = 256 * 1024)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || fi.Length < 20 || fi.Length > maxBytes) return null;
                byte[] data = File.ReadAllBytes(path);
                int n = Math.Min(data.Length, 4096);
                for (int i = 0; i < n; i++) if (data[i] == 0 && (i + 1 >= data.Length || data[i + 1] != 0) && !(data.Length > 1 && (data[0] == 0xFF || data[0] == 0xFE))) return null;       // binary, not a text config
                string text = (data.Length > 1 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF))) ? Encoding.Unicode.GetString(data) : Encoding.UTF8.GetString(data);

                bool pools = Pools.IsMatch(text), url = PoolUrl.IsMatch(text), user = User.IsMatch(text), mining = ctx.Rules.MiningKeysRx != null && ctx.Rules.MiningKeysRx.IsMatch(text);
                var hits = ctx.Rules.MinerScanner == null ? new Dictionary<int, int>() : ctx.Rules.MinerScanner.ScanBytes(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetByteCount(text));
                var byGroup = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                foreach (var id in hits.Keys)
                {
                    if (id >= ctx.Rules.ScanIndex.Count) continue;
                    var kv = ctx.Rules.ScanIndex[id];
                    List<string> l; if (!byGroup.TryGetValue(kv.Key, out l)) byGroup[kv.Key] = l = new List<string>();
                    if (!l.Contains(kv.Value)) l.Add(kv.Value);
                }
                int markers = byGroup.Where(kv => kv.Key != "tuning").Sum(kv => kv.Value.Count);
                int groups = byGroup.Count(kv => kv.Key != "tuning" && kv.Value.Count > 0);
                string sample = string.Join(", ", byGroup.SelectMany(kv => kv.Value).Take(6));

                if (pools && url && user && (mining || markers >= 1))
                    return new Result { RuleId = "MINER.CONFIG_FILE", Weight = 45, Definitive = true, Text = "A cryptominer configuration: mining pool address, user/wallet and mining options", Detail = path + (sample.Length > 0 ? "  [" + sample + "]" : "") };
                if (markers >= 3 && groups >= 2)
                    return new Result { RuleId = "MINER.CONFIG_STRINGS", Weight = 30, Definitive = false, Text = "A configuration file full of cryptominer markers (" + markers + ")", Detail = path + "  [" + sample + "]" };
            }
            catch { }
            return null;
        }
    }

    /// <summary>What a running program looks like when it is a miner that does not announce itself: what it keeps in memory (a packed miner
    /// decrypts itself there), the configuration lying next to it, GPU compute libraries, odd privileges, and how all of it lines up with
    /// CPU/GPU load and network activity. Weak signals stay weak: the combination is what is scored.</summary>
    internal static class MinerProfile
    {
        static readonly string[] GpuComputeLibs = { "nvcuda.dll", "nvml.dll", "nvrtc64_", "cudart64_", "cublas64_", "opencl.dll", "amdocl64.dll", "amdhip64", "libcuda" };
        static readonly string[] SystemOwners = { "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE" };

        // hashes of this program (and its console twin, which differs only in the PE subsystem byte): never treated as a miner because its own memory holds the rule markers
        static HashSet<string> _selfFamily;
        static HashSet<string> SelfFamily(ScanContext ctx)
        {
            if (_selfFamily != null) return _selfFamily;
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!string.IsNullOrEmpty(ctx.SelfPath) && File.Exists(ctx.SelfPath))
                {
                    byte[] b = File.ReadAllBytes(ctx.SelfPath);
                    set.Add(Hashing.Sha256(b));
                    int pe = BitConverter.ToInt32(b, 0x3C), off = pe + 4 + 20 + 68;
                    if (off > 0 && off < b.Length && (b[off] == 2 || b[off] == 3)) { b[off] = (byte)(b[off] == 2 ? 3 : 2); set.Add(Hashing.Sha256(b)); }
                }
            }
            catch { }
            return _selfFamily = set;
        }

        public static bool IsSelfFamily(ScanContext ctx, ProcInfo p) { return p.Image != null && !string.IsNullOrEmpty(p.Image.Sha256) && SelfFamily(ctx).Contains(p.Image.Sha256); }

        static bool Untrusted(ProcInfo p) { return p.Image == null || !p.Image.Trusted; }

        static bool Exempt(ScanContext ctx, ProcInfo p)
        {
            if (p.Entity == null || p.Pid <= 4 || IsSelfFamily(ctx, p)) return true;
            if (!string.IsNullOrEmpty(p.Path) && ctx.IsSelf(p.Path)) return true;
            bool heavyInstalled = ctx.Rules.HeavyApps.Contains(System.IO.Path.GetFileNameWithoutExtension(p.Name ?? "")) && !string.IsNullOrEmpty(p.Path) && PathUtil.Classify(p.Path) == PathClass.ProgramFiles;
            return heavyInstalled;
        }

        static bool UserWritableOrUnknown(ProcInfo p) { return string.IsNullOrEmpty(p.Path) || PathUtil.IsUserWritable(p.Path); }

        static double CpuThreshold(ScanContext ctx) { return ctx.CoreCount <= 4 ? 45 : 22; }

        /// <summary>Rules that mean "foreign code lives inside this process": a miner that was injected into or hollowed out of a signed Windows program has a trusted image, so the
        /// image's signature says nothing about it. Such a process is read for miner markers although it is "trusted".</summary>
        static readonly string[] InjectionRules = { "PROC.PE_IN_PRIVATE_MEMORY", "PROC.ORPHAN_THREADS", "PROC.HOLLOW", "PROC.SIDELOAD_CANDIDATE", "PROC.SYSTEM_PROC_UNSIGNED_MODULE", "PROC.SUSPENDED_LOLBIN", "NET.SYSTEM_TOOL_EXTERNAL" };

        static bool InjectionFlagged(ProcInfo p)
        {
            return p.Entity != null && p.Entity.Evidence.Any(x => x.Weight > 0 && InjectionRules.Any(r => x.RuleId.StartsWith(r, StringComparison.OrdinalIgnoreCase)));
        }

        internal static List<ProcInfo> Candidates(ScanContext ctx, List<ProcInfo> procs)
        {
            return procs.Where(p => !Exempt(ctx, p) &&
                ((Untrusted(p) && (UserWritableOrUnknown(p) || p.ExternalConnections > 0 || p.CpuPercent >= CpuThreshold(ctx) || p.GpuPercent >= 35))
                 || (!Untrusted(p) && p.Entity.Evidence.Any(x => x.Weight > 0 && InjectionRules.Any(r => x.RuleId.StartsWith(r, StringComparison.OrdinalIgnoreCase)))))).ToList();
        }

        public static void Run(ScanContext ctx, List<ProcInfo> procs)
        {
            foreach (var p in procs) { if (Exempt(ctx, p)) continue; try { Cheap(ctx, p); } catch (Exception ex) { Log.Warn("profile " + p.Name + ": " + ex.Message); } }

            // expensive checks (reading process memory and the folder next to the program) only for programs that could plausibly be a miner
            var cands = Candidates(ctx, procs);
            ctx.Stats.MemoryScanCandidates = cands.Count;
            var sw = Stopwatch.StartNew();
            long totalBytes = 0;
            int done = 0;
            var po = new ParallelOptions { MaxDegreeOfParallelism = Math.Min(3, ctx.Options.Parallelism), CancellationToken = ctx.Cancel };
            try
            {
                Parallel.ForEach(cands, po, p =>
                {
                    if (sw.Elapsed > TimeSpan.FromSeconds(30)) return;
                    try
                    {
                        if (ctx.Options.MemoryInspection)
                        {
                            long read;
                            ScanMemory(ctx, p, out read);
                            Interlocked.Add(ref totalBytes, read);
                        }
                        if (Untrusted(p)) ScanConfigFiles(ctx, p);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { Log.Warn("profile scan " + p.Name + ": " + ex.Message); }
                    Interlocked.Increment(ref done);
                });
            }
            catch (AggregateException ae) { if (ae.InnerExceptions.Any(x => x is OperationCanceledException)) throw new OperationCanceledException(); }
            ctx.Stats.MemoryBytesScanned = totalBytes;
            if (done < cands.Count) ctx.AddBlind("Miner memory scan", (cands.Count - done) + " program(s) were not checked: the 30 s budget for this step ran out");

            foreach (var p in procs) { if (Exempt(ctx, p)) continue; try { Triad(ctx, p); } catch { } }
        }

        // ------------------------------------------------------------------------------------------------ cheap, per-process
        internal static void Cheap(ScanContext ctx, ProcInfo p)
        {
            if (!Untrusted(p)) return;
            bool uw = UserWritableOrUnknown(p);

            // an unsigned program in a folder any user can write to, running with SYSTEM-level rights: normal installs of services go to Program Files
            if (uw && !string.IsNullOrEmpty(p.Path) && !string.IsNullOrEmpty(p.Owner))
            {
                string owner = p.Owner.Substring(p.Owner.LastIndexOf('\\') + 1).ToUpperInvariant();
                if (SystemOwners.Contains(owner) || string.Equals(p.Integrity, "System", StringComparison.OrdinalIgnoreCase))
                    p.Entity.Add(new Evidence("PROC.SYSTEM_FROM_USERPATH", EvidenceCategory.Behavior, 15, "Runs with " + (SystemOwners.Contains(owner) ? p.Owner : "SYSTEM") + " rights, but its file is not signed and lies in a folder any user can write to", p.Path));
            }

            // CUDA / OpenCL / HIP: the libraries a GPU miner needs. Many legitimate tools load them too, so only for unsigned, user-folder, windowless programs.
            if (uw && !p.HasWindow && p.Modules != null)
            {
                string lib = p.Modules.Select(m => System.IO.Path.GetFileName(m ?? "").ToLowerInvariant()).FirstOrDefault(n => GpuComputeLibs.Any(g => n.StartsWith(g) || n == g));
                if (lib != null)
                    p.Entity.Add(new Evidence("PROC.GPU_COMPUTE_LIBS", EvidenceCategory.Behavior, 8, "An unsigned background program from a user folder loaded GPU compute libraries (" + lib + ")", lib));
            }
        }

        // ------------------------------------------------------------------------------------------------ memory
        internal static bool ScanMemory(ScanContext ctx, ProcInfo p, out long bytesRead)
        {
            bytesRead = 0;
            var scanner = ctx.Rules.MinerScanner;
            if (scanner == null) return false;
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, p.Pid);
            if (h == IntPtr.Zero) return false;
            var hits = new Dictionary<int, int>();
            bool truncated = false;
            try
            {
                IntPtr mainBase = MainModuleBase(h);
                var sw = Stopwatch.StartNew();
                const long maxBytes = 192L * 1024 * 1024, maxRegion = 256L * 1024 * 1024;
                var buf = new byte[1 << 20];
                long addr = 0; int guard = 0;
                var mbi = new NativeMethods.MEMORY_BASIC_INFORMATION();
                while (guard++ < 200000)
                {
                    ctx.ThrowIfCancelled();
                    if (bytesRead >= maxBytes || sw.Elapsed > TimeSpan.FromSeconds(6)) { truncated = true; break; }
                    UIntPtr r = NativeMethods.VirtualQueryEx(h, new IntPtr(addr), out mbi, (UIntPtr)System.Runtime.InteropServices.Marshal.SizeOf(mbi));
                    if (r == UIntPtr.Zero) break;
                    long size = (long)(ulong)mbi.RegionSize;
                    bool readable = mbi.State == NativeMethods.MEM_COMMIT && (mbi.Protect & 0x101) == 0 && mbi.Protect != 0;       // not PAGE_NOACCESS (0x01) / PAGE_GUARD (0x100)
                    bool eligible = mbi.Type == NativeMethods.MEM_PRIVATE || (mbi.Type == NativeMethods.MEM_IMAGE && mainBase != IntPtr.Zero && mbi.AllocationBase == mainBase);
                    if (readable && eligible && size > 0 && size <= maxRegion)
                    {
                        long off = 0; int state = 0;
                        while (off < size && bytesRead < maxBytes)
                        {
                            int want = (int)Math.Min(buf.Length, size - off);
                            IntPtr got;
                            if (!NativeMethods.ReadProcessMemory(h, new IntPtr(mbi.BaseAddress.ToInt64() + off), buf, (IntPtr)want, out got) || (long)got <= 0) break;
                            int g = (int)(long)got;
                            state = scanner.Feed(buf, g, state, hits);
                            bytesRead += g; off += g;
                        }
                    }
                    long next = mbi.BaseAddress.ToInt64() + size;
                    if (next <= addr || next > 0x7FFFFFFF0000L) break;
                    addr = next;
                }
            }
            finally { NativeMethods.CloseHandle(h); }

            p.Entity.Set("memoryScan", truncated ? "partial (size/time limit)" : "complete");
            if (hits.Count == 0) return false;
            var byGroup = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var id in hits.Keys)
            {
                if (id >= ctx.Rules.ScanIndex.Count) continue;
                var kv = ctx.Rules.ScanIndex[id];
                List<string> l; if (!byGroup.TryGetValue(kv.Key, out l)) byGroup[kv.Key] = l = new List<string>();
                if (!l.Contains(kv.Value)) l.Add(kv.Value);
            }
            int distinct = byGroup.Where(kv => kv.Key != "tuning").Sum(kv => kv.Value.Count);
            int groups = byGroup.Count(kv => kv.Key != "tuning" && kv.Value.Count > 0);
            bool proto = byGroup.ContainsKey("protocol");
            string sample = string.Join(", ", byGroup.SelectMany(kv => kv.Value).Take(8));
            // Memory is noisier than a file: a chat, an editor, a browser tab, a log or a security tool can hold all of these words without being a miner. The words alone
            // therefore only count as a note; they count fully when the program is also doing what a miner does (using the CPU or GPU).
            bool working = p.CpuPercent >= 8 || p.GpuPercent >= 15 || InjectionFlagged(p);
            if (proto && distinct >= 3 && groups >= 2)
                p.Entity.Add(new Evidence("PROC.MEM.MINER_STRONG", EvidenceCategory.Content, working ? 45 : 14, "The program's memory holds cryptominer protocol, algorithm and program markers (" + distinct + ") - what a packed miner looks like after it unpacks itself" + (working ? "" : ". The program is idle, so this may just be a document, a chat or a log that mentions them"), sample));
            else if (distinct >= 4 && groups >= 2)
                p.Entity.Add(new Evidence("PROC.MEM.MINER_MANY", EvidenceCategory.Content, working ? 32 : 10, "The program's memory holds many cryptominer markers (" + distinct + ")" + (working ? "" : ". The program is idle, so this may just be a document, a chat or a log that mentions them"), sample));
            return true;
        }

        static IntPtr MainModuleBase(IntPtr h)
        {
            try
            {
                uint needed; var mods = new IntPtr[8];
                if (NativeMethods.EnumProcessModulesEx(h, mods, (uint)(mods.Length * IntPtr.Size), out needed, 3)) return mods[0];
            }
            catch { }
            return IntPtr.Zero;
        }

        // ------------------------------------------------------------------------------------------------ config next to the program
        static void ScanConfigFiles(ScanContext ctx, ProcInfo p)
        {
            if (string.IsNullOrEmpty(p.Path) || !UserWritableOrUnknown(p)) return;
            string dir = System.IO.Path.GetDirectoryName(p.Path);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            string[] files;
            try { files = Directory.GetFiles(dir); } catch { return; }
            int looked = 0;
            foreach (var f in files.OrderByDescending(x => MinerConfigAnalyzer.IsCandidateName(x)))
            {
                if (!MinerConfigAnalyzer.IsConfigExtension(f)) continue;
                if (++looked > 30) break;
                var res = MinerConfigAnalyzer.Analyze(ctx, f);
                if (res == null) continue;
                var ce = ctx.Files.Inspect(f, FileRole.Referenced);
                if (ce == null) continue;
                ce.Add(new Evidence(res.RuleId, EvidenceCategory.Content, res.Weight, res.Text, res.Detail, res.Definitive));
                ctx.Link(p.Entity.Id, ce.Id, "references");
                p.Entity.Add(new Evidence("PROC." + res.RuleId, EvidenceCategory.Content, res.Weight, "Next to the running program: " + res.Text.ToLowerInvariant(), f, res.Definitive));
                break;
            }
        }

        // ------------------------------------------------------------------------------------------------ correlation
        /// <summary>The classic miner fingerprint: unsigned program in a user folder with no window, burning CPU/GPU while it keeps a connection to a
        /// public address. Each part alone is common (servers, tools, games); all of them together are rare. Scored under Network so that it counts as an
        /// independent kind of evidence next to the load itself, yet stays below High Risk without something more (autostart, memory markers, config).</summary>
        internal static void Triad(ScanContext ctx, ProcInfo p)
        {
            if (!Untrusted(p) || p.Entity == null) return;
            bool load = p.CpuPercent >= CpuThreshold(ctx) || p.GpuPercent >= 35;
            bool netEvidence = p.Entity.Evidence.Any(x => x.Weight > 0 && x.Category == EvidenceCategory.Network);
            if (load && netEvidence && !p.HasWindow && UserWritableOrUnknown(p))
                p.Entity.Add(new Evidence("BEH.MINER_PROFILE", EvidenceCategory.Network, 22, "Unsigned program in a user folder, no window, " + (p.GpuPercent >= 35 ? "using the GPU" : "using the CPU") + " heavily while keeping a connection to a public address - the usual behaviour of a miner", p.Path));
        }
    }
}
