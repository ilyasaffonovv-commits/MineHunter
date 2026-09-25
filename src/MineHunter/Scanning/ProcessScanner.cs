using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MineHunter.Analysis;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    public sealed class ProcInfo
    {
        public int Pid, Ppid; public string Name, Path, Cmd; public DateTime Start; public string Owner, Integrity;
        public int Threads; public long PrivateBytes; public double CpuPercent, GpuPercent; public bool HasWindow;
        public List<string> Modules = new List<string>(); public Entity Entity; public Entity Image;
        public int ExternalConnections;
    }

    public static class ProcessScanner
    {
        // expected parents for a few core system processes (only enforced when the parent process exists)
        static readonly Dictionary<string, string[]> ExpectedParent = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "svchost.exe", new[] { "services.exe" } }, { "taskhostw.exe", new[] { "svchost.exe" } }, { "runtimebroker.exe", new[] { "svchost.exe" } },
            { "sihost.exe", new[] { "svchost.exe" } }, { "audiodg.exe", new[] { "svchost.exe" } }, { "wmiprvse.exe", new[] { "svchost.exe" } },
            { "spoolsv.exe", new[] { "services.exe" } }, { "services.exe", new[] { "wininit.exe" } }, { "lsass.exe", new[] { "wininit.exe" } },
            { "fontdrvhost.exe", new[] { "wininit.exe", "winlogon.exe" } }, { "dllhost.exe", new[] { "svchost.exe", "services.exe" } }
        };

        public static List<ProcInfo> Run(ScanContext ctx)
        {
            var procs = Enumerate(ctx);
            ctx.Report("Processes: " + procs.Count, 5);

            // ---- sampling window starts now (CPU time + network snapshot), the heavy analysis below overlaps with it
            var cpu0 = new Dictionary<int, double>();
            var t0 = DateTime.UtcNow;
            foreach (var p in procs) { double v; if (TryCpu(p.Pid, out v)) cpu0[p.Pid] = v; }
            var tcp0 = Net.GetTcp();
            var gpuTask = Task.Run(() => GpuSampler.Sample(ctx.Options.CpuSampleMs));

            // ---- images
            var imageTasks = new List<Task>();
            var sem = new SemaphoreSlim(ctx.Options.Parallelism);
            foreach (var p in procs.Where(x => !string.IsNullOrEmpty(x.Path)))
            {
                ctx.ThrowIfCancelled();
                sem.Wait();
                var pp = p;
                imageTasks.Add(Task.Run(() => { try { pp.Image = ctx.Files.Inspect(pp.Path, FileRole.ProcessImage); } finally { sem.Release(); } }));
            }
            Task.WaitAll(imageTasks.ToArray());
            ctx.Report("Process images checked", 15);

            // ---- modules (unique across processes)
            CollectModules(ctx, procs);

            // ---- process entities, memory, threads
            var dns = DnsCache.Load();
            var byPid = procs.ToDictionary(x => x.Pid);
            int n = 0;
            foreach (var p in procs)
            {
                ctx.ThrowIfCancelled();
                BuildEntity(ctx, p, byPid);
                if (ctx.Options.MemoryInspection && p.Pid > 4) { try { InspectMemory(ctx, p); } catch (Exception ex) { Log.Warn("memory " + p.Name + ": " + ex.Message); } }
                CheckCommandLine(ctx, p);
                CheckParent(ctx, p, byPid);
                CheckRunningMasquerade(p);
                n++;
                if (n % 25 == 0) ctx.Report("Processes inspected: " + n + "/" + procs.Count, 25 + (int)(25.0 * n / procs.Count));
            }

            // ---- finish the CPU / GPU / network sampling window
            int wait = ctx.Options.CpuSampleMs - (int)(DateTime.UtcNow - t0).TotalMilliseconds;
            if (wait > 0) Thread.Sleep(wait);
            double dt = (DateTime.UtcNow - t0).TotalSeconds;
            var tcp1 = Net.GetTcp();
            Dictionary<int, double> gpu = null;
            try { gpu = gpuTask.Result; } catch { }
            foreach (var p in procs)
            {
                double c1;
                if (cpu0.ContainsKey(p.Pid) && TryCpu(p.Pid, out c1) && dt > 0.5)
                    p.CpuPercent = Math.Max(0, (c1 - cpu0[p.Pid]) / (dt * ctx.CoreCount) * 100.0);
                double g; if (gpu != null && gpu.TryGetValue(p.Pid, out g)) p.GpuPercent = g;
            }
            AnalyzeNetwork(ctx, procs, tcp0, tcp1, dns);
            foreach (var p in procs) AnalyzeLoad(ctx, p);
            ctx.Stats.ProcessesScanned = procs.Count;
            return procs;
        }

        // =====================================================================================================
        static List<ProcInfo> Enumerate(ScanContext ctx)
        {
            var list = new Dictionary<int, ProcInfo>();
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate,ThreadCount FROM Win32_Process"))
                    foreach (ManagementObject o in s.Get())
                    {
                        int pid = Convert.ToInt32(o["ProcessId"]);
                        var pi = new ProcInfo { Pid = pid, Ppid = Convert.ToInt32(o["ParentProcessId"]), Name = Convert.ToString(o["Name"]) ?? "", Path = PathUtil.Normalize(Convert.ToString(o["ExecutablePath"])), Cmd = Convert.ToString(o["CommandLine"]) };
                        try { pi.Start = ManagementDateTimeConverter.ToDateTime(Convert.ToString(o["CreationDate"])).ToUniversalTime(); } catch { }
                        try { pi.Threads = Convert.ToInt32(o["ThreadCount"]); } catch { }
                        list[pid] = pi;
                    }
            }
            catch (Exception ex) { Log.Warn("WMI process query failed: " + ex.Message); ctx.AddBlind("Processes", "WMI Win32_Process query failed: " + ex.Message); }

            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    using (p)
                    {
                        ProcInfo pi;
                        if (!list.TryGetValue(p.Id, out pi)) { pi = new ProcInfo { Pid = p.Id, Name = p.ProcessName + ".exe" }; list[p.Id] = pi; }
                        try { pi.PrivateBytes = p.PrivateMemorySize64; } catch { }
                        try { pi.HasWindow = p.MainWindowHandle != IntPtr.Zero; } catch { }
                        if (string.IsNullOrEmpty(pi.Path)) { try { pi.Path = PathUtil.Normalize(p.MainModule.FileName); } catch { } }
                        if (pi.Start == default(DateTime)) { try { pi.Start = p.StartTime.ToUniversalTime(); } catch { } }
                    }
                }
            }
            catch (Exception ex) { Log.Warn("Process.GetProcesses: " + ex.Message); }

            foreach (var p in list.Values)
            {
                if (p.Pid <= 4) continue;
                IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, p.Pid);
                if (h == IntPtr.Zero) continue;
                try
                {
                    p.Owner = Tokens.GetOwner(h); p.Integrity = Tokens.GetIntegrity(h);
                    if (string.IsNullOrEmpty(p.Path))
                    {
                        var sb = new StringBuilder(1024); int sz = sb.Capacity;
                        if (NativeMethods.QueryFullProcessImageName(h, 0, sb, ref sz)) p.Path = PathUtil.Normalize(sb.ToString());
                    }
                }
                finally { NativeMethods.CloseHandle(h); }
            }
            int selfPid = Process.GetCurrentProcess().Id;
            return list.Values.Where(p => p.Pid != 0 && p.Pid != selfPid).OrderBy(p => p.Pid).ToList();
        }

        static bool TryCpu(int pid, out double seconds)
        {
            seconds = 0;
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                long c, e, k, u;
                if (!NativeMethods.GetProcessTimes(h, out c, out e, out k, out u)) return false;
                seconds = (k + u) / 1e7;
                return true;
            }
            finally { NativeMethods.CloseHandle(h); }
        }

        static void BuildEntity(ScanContext ctx, ProcInfo p, Dictionary<int, ProcInfo> byPid)
        {
            string id = "proc:" + p.Pid + ":" + p.Start.Ticks;
            var e = ctx.GetOrAdd(id, EntityKind.Process, () => new Entity { Title = p.Name });
            p.Entity = e;
            e.Location = p.Path;
            e.Set("pid", p.Pid.ToString()); e.Set("ppid", p.Ppid.ToString()); e.Set("cmd", p.Cmd); e.Set("owner", p.Owner); e.Set("integrity", p.Integrity);
            e.Set("start", p.Start == default(DateTime) ? null : p.Start.ToString("o"));
            e.Set("threads", p.Threads.ToString());
            if (p.PrivateBytes > 0) e.Set("privateMB", (p.PrivateBytes / 1048576).ToString());
            if (p.Image != null) { ctx.Link(e.Id, p.Image.Id, "runs image"); e.Sha256 = p.Image.Sha256; e.Trusted = p.Image.Trusted; e.Set("trustClass", p.Image.P("trustClass")); e.Set("publisher", p.Image.P("publisher")); }
            ProcInfo par;
            if (byPid.TryGetValue(p.Ppid, out par) && par.Start <= p.Start && par.Start != default(DateTime))
            {
                string pid2 = "proc:" + par.Pid + ":" + par.Start.Ticks;
                ctx.Link(e.Id, pid2, "started by");
                e.Set("parent", par.Name + " (" + par.Pid + ")");
            }
            else e.Set("parent", p.Ppid > 0 ? "(exited) " + p.Ppid : "");
        }

        static void CheckCommandLine(ScanContext ctx, ProcInfo p)
        {
            if (string.IsNullOrEmpty(p.Cmd) || p.Entity == null) return;
            if (ctx.IsSelf(p.Path)) return;
            // explorer / MS-signed shells contain harmless flags; miner-specific rules are safe to apply everywhere
            var hitRules = new List<string>();
            foreach (var r in ctx.Rules.CmdRules)
                if (r.Rx.IsMatch(p.Cmd))
                {
                    p.Entity.Add(new Evidence("PROC." + r.Id, FileIntel.ParseCat(r.Category), r.Weight, r.Text, Text.Trunc(p.Cmd, 240), r.Definitive));
                    hitRules.Add(r.Id);
                }
            if (hitRules.Contains("CMD.MINER.STRATUM_URL") && (hitRules.Contains("CMD.MINER.POOL_USER") || hitRules.Contains("CMD.MINER.WALLET_XMR") || hitRules.Contains("CMD.MINER.ALGO_FLAG")))
                p.Entity.Add(new Evidence("PROC.MINER.CMDLINE_COMPLETE", EvidenceCategory.Content, 30, "Command line has pool, user/wallet and algorithm - a complete miner invocation", Text.Trunc(p.Cmd, 240), true));

            // files referenced by the command line (configs, scripts, payloads) become part of the same story
            foreach (var path in PathUtil.ExtractPaths(p.Cmd).Skip(1).Take(4))
            {
                if (!File.Exists(path) || string.Equals(path, p.Path, StringComparison.OrdinalIgnoreCase)) continue;
                if (!PathUtil.IsUserWritable(path)) continue;
                var f = ctx.Files.Inspect(path, FileRole.Referenced);
                if (f != null) ctx.Link(p.Entity.Id, f.Id, "references");
            }
        }

        /// <summary>A file named like a Windows / vendor program but living in the wrong place is only "odd" while it sits on disk;
        /// once it is actually RUNNING under that name, that is behaviour, and independent evidence from the file's name.</summary>
        static void CheckRunningMasquerade(ProcInfo p)
        {
            if (p.Entity == null || p.Image == null || p.Image.Trusted) return;
            var m = p.Image.Evidence.FirstOrDefault(x => x.Weight > 0 && (x.RuleId == "MASQ.SYSTEM_NAME_WRONG_PATH" || x.RuleId == "MASQ.HOMOGLYPH"));
            if (m == null) return;
            p.Entity.Add(new Evidence("PROC.MASQUERADE_RUNNING", EvidenceCategory.Behavior, 25, p.Name + " is running right now under the name of a Windows/vendor program, but the file behind it is not the real one", p.Path));
        }

        static void CheckParent(ScanContext ctx, ProcInfo p, Dictionary<int, ProcInfo> byPid)
        {
            if (p.Entity == null) return;
            string[] expect;
            if (!ExpectedParent.TryGetValue(p.Name, out expect)) return;
            ProcInfo par;
            if (!byPid.TryGetValue(p.Ppid, out par) || par.Start > p.Start || par.Start == default(DateTime)) return;     // parent gone / pid reused: cannot judge
            if (!expect.Contains(par.Name, StringComparer.OrdinalIgnoreCase))
                p.Entity.Add(new Evidence("PROC.PARENT_ANOMALY", EvidenceCategory.Behavior, 25, p.Name + " should be started by " + string.Join("/", expect) + " but was started by " + par.Name, par.Name + " (" + par.Pid + ") -> " + p.Name));
        }

        // =====================================================================================================
        //   modules
        // =====================================================================================================
        static void CollectModules(ScanContext ctx, List<ProcInfo> procs)
        {
            var moduleOwners = new ConcurrentDictionary<string, ConcurrentBag<int>>(StringComparer.OrdinalIgnoreCase);
            Parallel.ForEach(procs.Where(p => p.Pid > 4), new ParallelOptions { MaxDegreeOfParallelism = ctx.Options.Parallelism, CancellationToken = ctx.Cancel }, p =>
            {
                var mods = EnumModules(p.Pid);
                if (mods == null) return;
                p.Modules = mods;
                foreach (var m in mods) moduleOwners.GetOrAdd(m, _ => new ConcurrentBag<int>()).Add(p.Pid);
            });
            var unique = moduleOwners.Keys.Where(m => !ctx.IsSelf(m)).ToList();
            int done = 0;
            Parallel.ForEach(unique, new ParallelOptions { MaxDegreeOfParallelism = ctx.Options.Parallelism, CancellationToken = ctx.Cancel }, m =>
            {
                ctx.Files.Inspect(m, FileRole.Module);
                int d = Interlocked.Increment(ref done);
                if (d % 400 == 0) ctx.Report("Loaded libraries checked: " + d + "/" + unique.Count, 15 + (int)(10.0 * d / Math.Max(1, unique.Count)));
            });
            ctx.Stats.ModulesChecked = unique.Count;

            // sideloading / suspicious modules: link them to the processes that load them
            var procByPid = procs.ToDictionary(p => p.Pid);
            foreach (var kv in moduleOwners)
            {
                var mf = ctx.Files.Get(kv.Key);
                if (mf == null || mf.Trusted) continue;
                int posWeight = mf.Evidence.Where(x => x.Weight > 0 && x.Category != EvidenceCategory.Signature && x.Category != EvidenceCategory.Location).Sum(x => x.Weight);
                bool userDir = PathUtil.IsUserWritable(kv.Key);
                foreach (var pid in kv.Value.Distinct())
                {
                    ProcInfo p; if (!procByPid.TryGetValue(pid, out p) || p.Image == null || ctx.IsSelf(p.Path)) continue;
                    bool sameDir = !string.IsNullOrEmpty(p.Path) && string.Equals(Path.GetDirectoryName(kv.Key), Path.GetDirectoryName(p.Path), StringComparison.OrdinalIgnoreCase);
                    string sig = mf.P("sig");
                    bool unsignedMod = sig == "Unsigned" || sig == "Tampered" || sig == "Revoked";
                    if (p.Image.Trusted && unsignedMod && userDir && sameDir)
                    {
                        var ev = new Evidence("PROC.SIDELOAD_CANDIDATE", EvidenceCategory.Behavior, 22, "A signed program loaded an unsigned library from its own user-writable folder (DLL side-loading pattern)", kv.Key);
                        p.Entity?.Add(ev);
                        if (p.Entity != null) ctx.Link(p.Entity.Id, mf.Id, "loads");
                    }
                    else if (p.Image.Trusted && (p.Image.P("pathClass") == "WindowsSystem") && unsignedMod && userDir)
                    {
                        p.Entity?.Add(new Evidence("PROC.SYSTEM_PROC_UNSIGNED_MODULE", EvidenceCategory.Behavior, 14, "A Windows process loaded an unsigned library from a user folder", kv.Key));
                        if (p.Entity != null) ctx.Link(p.Entity.Id, mf.Id, "loads");
                    }
                    else if (posWeight >= 10 && p.Entity != null) ctx.Link(p.Entity.Id, mf.Id, "loads");
                }
            }
        }

        static List<string> EnumModules(int pid)
        {
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                uint needed;
                if (!NativeMethods.EnumProcessModulesEx(h, null, 0, out needed, 3) || needed == 0) return null;
                var mods = new IntPtr[needed / (uint)IntPtr.Size + 16];
                if (!NativeMethods.EnumProcessModulesEx(h, mods, (uint)(mods.Length * IntPtr.Size), out needed, 3)) return null;
                int count = (int)Math.Min(needed / (uint)IntPtr.Size, (uint)mods.Length);
                var res = new List<string>(count);
                var sb = new StringBuilder(1024);
                for (int i = 0; i < count; i++)
                {
                    sb.Clear();
                    if (NativeMethods.GetModuleFileNameEx(h, mods[i], sb, 1024) == 0) continue;
                    string p = PathUtil.Normalize(sb.ToString());
                    if (p.Length > 3) res.Add(p);
                }
                return res;
            }
            catch { return null; }
            finally { NativeMethods.CloseHandle(h); }
        }

        // =====================================================================================================
        //   memory: hollowing, unbacked executable memory, orphan threads
        // =====================================================================================================
        static void InspectMemory(ScanContext ctx, ProcInfo p)
        {
            if (p.Entity == null) return;
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, p.Pid);
            if (h == IntPtr.Zero) { ctx.Denied("Process memory", p.Name + " (" + p.Pid + ")"); return; }
            try
            {
                // ---- image header in memory vs. file on disk
                if (!string.IsNullOrEmpty(p.Path) && File.Exists(p.Path) && p.Modules.Count > 0)
                {
                    CheckHollowing(ctx, p, h);
                }

                // ---- executable private memory
                long execPrivate = 0; int rwx = 0; var peRegions = new List<string>();
                long addr = 0; var mbi = new NativeMethods.MEMORY_BASIC_INFORMATION(); int guard = 0;
                var head = new byte[0x400];
                while (guard++ < 200000)
                {
                    UIntPtr r = NativeMethods.VirtualQueryEx(h, new IntPtr(addr), out mbi, (UIntPtr)Marshal.SizeOf(mbi));
                    if (r == UIntPtr.Zero) break;
                    long size = (long)(ulong)mbi.RegionSize;
                    if (mbi.State == NativeMethods.MEM_COMMIT && mbi.Type == NativeMethods.MEM_PRIVATE)
                    {
                        uint prot = mbi.Protect & 0xFF;
                        bool exec = prot == NativeMethods.PAGE_EXECUTE || prot == NativeMethods.PAGE_EXECUTE_READ || prot == NativeMethods.PAGE_EXECUTE_READWRITE || prot == NativeMethods.PAGE_EXECUTE_WRITECOPY;
                        if (exec)
                        {
                            execPrivate += size;
                            if (prot == NativeMethods.PAGE_EXECUTE_READWRITE) rwx++;
                            if (size >= 0x1000 && peRegions.Count < 5)
                            {
                                IntPtr got;
                                if (NativeMethods.ReadProcessMemory(h, mbi.BaseAddress, head, (IntPtr)head.Length, out got) && (long)got >= 0x100 && head[0] == 'M' && head[1] == 'Z')
                                {
                                    int lf = BitConverter.ToInt32(head, 0x3C);
                                    if (lf > 0 && lf < 0x300 && lf + 4 <= (long)got && head[lf] == 'P' && head[lf + 1] == 'E')
                                        peRegions.Add("0x" + mbi.BaseAddress.ToInt64().ToString("X") + " (" + (size / 1024) + " KB)");
                                }
                            }
                        }
                    }
                    long next = mbi.BaseAddress.ToInt64() + size;
                    if (next <= addr || next > 0x7FFFFFFF0000L) break;
                    addr = next;
                }
                p.Entity.Set("execPrivateKB", (execPrivate / 1024).ToString());
                p.Entity.Set("rwxRegions", rwx.ToString());
                if (peRegions.Count > 0)
                    p.Entity.Add(new Evidence("PROC.PE_IN_PRIVATE_MEMORY", EvidenceCategory.Behavior, 30, "A Windows executable image is loaded from private (unbacked) memory - manual mapping / injection", string.Join(", ", peRegions)));

                // ---- threads whose start address is not inside any loaded module
                int orphan = CountOrphanThreads(p, mbi);
                if (orphan > 0) p.Entity.Add(new Evidence("PROC.ORPHAN_THREADS", EvidenceCategory.Behavior, 10, orphan + " thread(s) started at an address that belongs to no loaded module", orphan.ToString()));
            }
            finally { NativeMethods.CloseHandle(h); }
        }

        static void CheckHollowing(ScanContext ctx, ProcInfo p, IntPtr h)
        {
            try
            {
                uint needed;
                var mods = new IntPtr[1024];
                if (!NativeMethods.EnumProcessModulesEx(h, mods, (uint)(mods.Length * IntPtr.Size), out needed, 3)) return;
                IntPtr baseAddr = mods[0];
                var sb = new StringBuilder(1024);
                if (NativeMethods.GetModuleFileNameEx(h, baseAddr, sb, 1024) == 0) return;
                string main = PathUtil.Normalize(sb.ToString());
                if (!string.Equals(main, p.Path, StringComparison.OrdinalIgnoreCase)) return;

                var fi = new FileInfo(p.Path);
                bool fileChangedSinceStart = p.Start != default(DateTime) && fi.LastWriteTimeUtc > p.Start.AddSeconds(-2);
                if (fileChangedSinceStart) return;              // updated while running: memory legitimately differs from disk

                var head = new byte[0x400]; IntPtr got;
                if (!NativeMethods.ReadProcessMemory(h, baseAddr, head, (IntPtr)head.Length, out got) || (long)got < 0x200 || head[0] != 'M' || head[1] != 'Z') return;
                int lf = BitConverter.ToInt32(head, 0x3C);
                if (lf <= 0 || lf > 0x300) return;
                if (head[lf] != 'P' || head[lf + 1] != 'E') return;
                bool is64 = BitConverter.ToUInt16(head, lf + 24) == 0x20B;
                uint memTs = BitConverter.ToUInt32(head, lf + 8);
                uint memEntry = BitConverter.ToUInt32(head, lf + 24 + 16);
                uint memSize = BitConverter.ToUInt32(head, lf + 24 + 56);

                var disk = PeAnalyzer.Analyze(p.Path, false);
                if (!disk.IsPe) return;
                var diffs = new List<string>();
                if (disk.SizeOfImage != memSize) diffs.Add("SizeOfImage disk=0x" + disk.SizeOfImage.ToString("X") + " mem=0x" + memSize.ToString("X"));
                if (disk.EntryPoint != memEntry) diffs.Add("EntryPoint disk=0x" + disk.EntryPoint.ToString("X") + " mem=0x" + memEntry.ToString("X"));
                if (disk.TimeDateStamp != memTs) diffs.Add("TimeDateStamp disk=0x" + disk.TimeDateStamp.ToString("X") + " mem=0x" + memTs.ToString("X"));
                if (diffs.Count >= 2)
                    p.Entity.Add(new Evidence("PROC.HOLLOW.IMAGE_MISMATCH", EvidenceCategory.Behavior, 62, "The program image in memory is different from the file on disk (process hollowing)", string.Join("; ", diffs), true));

                var mapped = new StringBuilder(1024);
                if (NativeMethods.GetMappedFileName(h, baseAddr, mapped, 1024) == 0 && diffs.Count >= 1)
                    p.Entity.Add(new Evidence("PROC.HOLLOW.NO_MAPPED_FILE", EvidenceCategory.Behavior, 30, "The main image region is not backed by the file on disk", p.Path));
            }
            catch { }
        }

        static int CountOrphanThreads(ProcInfo p, NativeMethods.MEMORY_BASIC_INFORMATION scratch)
        {
            int orphan = 0;
            try
            {
                using (var proc = Process.GetProcessById(p.Pid))
                {
                    IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, p.Pid);
                    if (h == IntPtr.Zero) return 0;
                    try
                    {
                        // module ranges
                        uint needed; var mods = new IntPtr[2048];
                        if (!NativeMethods.EnumProcessModulesEx(h, mods, (uint)(mods.Length * IntPtr.Size), out needed, 3)) return 0;
                        int count = (int)Math.Min(needed / (uint)IntPtr.Size, (uint)mods.Length);
                        var ranges = new List<KeyValuePair<long, long>>();
                        for (int i = 0; i < count; i++)
                        {
                            NativeMethods.MODULEINFO mi;
                            if (NativeMethods.GetModuleInformation(h, mods[i], out mi, (uint)Marshal.SizeOf(typeof(NativeMethods.MODULEINFO))))
                                ranges.Add(new KeyValuePair<long, long>(mi.BaseOfDll.ToInt64(), mi.BaseOfDll.ToInt64() + mi.SizeOfImage));
                        }
                        if (ranges.Count == 0) return 0;
                        foreach (ProcessThread t in proc.Threads)
                        {
                            IntPtr ht = NativeMethods.OpenThread(NativeMethods.THREAD_QUERY_INFORMATION, false, (uint)t.Id);
                            if (ht == IntPtr.Zero) ht = NativeMethods.OpenThread(NativeMethods.THREAD_QUERY_LIMITED_INFORMATION, false, (uint)t.Id);
                            if (ht == IntPtr.Zero) continue;
                            try
                            {
                                IntPtr start; int ret;
                                if (NativeMethods.NtQueryInformationThread(ht, 9, out start, IntPtr.Size, out ret) != 0) continue;
                                long a = start.ToInt64();
                                if (a == 0) continue;
                                bool inside = false;
                                foreach (var r in ranges) if (a >= r.Key && a < r.Value) { inside = true; break; }
                                if (!inside)
                                {
                                    // confirm it is executable private memory, not a stack/system stub
                                    var mbi = new NativeMethods.MEMORY_BASIC_INFORMATION();
                                    if (NativeMethods.VirtualQueryEx(h, start, out mbi, (UIntPtr)Marshal.SizeOf(mbi)) != UIntPtr.Zero && mbi.Type == NativeMethods.MEM_PRIVATE && mbi.State == NativeMethods.MEM_COMMIT)
                                        orphan++;
                                }
                            }
                            finally { NativeMethods.CloseHandle(ht); }
                        }
                    }
                    finally { NativeMethods.CloseHandle(h); }
                }
            }
            catch { }
            return orphan;
        }

        // =====================================================================================================
        //   network
        // =====================================================================================================
        static void AnalyzeNetwork(ScanContext ctx, List<ProcInfo> procs, List<TcpConn> t0, List<TcpConn> t1, DnsCache dns)
        {
            var byPid = procs.ToDictionary(p => p.Pid);
            var before = new HashSet<string>(t0.Select(c => c.Pid + "|" + c.Remote + ":" + c.RemotePort));
            var groups = t1.Where(c => c.State == "Established" && !c.IsLoopbackRemote && c.Remote != "0.0.0.0" && c.Remote != "::" && !IsPrivate(c.Remote)).GroupBy(c => c.Pid);
            foreach (var g in groups)
            {
                ProcInfo p; if (!byPid.TryGetValue(g.Key, out p) || p.Entity == null) continue;
                p.ExternalConnections = g.Count();
                ctx.Stats.Connections += g.Count();
                var eps = g.Select(c => c.Remote + ":" + c.RemotePort).Distinct().Take(12).ToList();
                p.Entity.Set("connections", string.Join(", ", eps));
                bool untrusted = p.Image == null || !p.Image.Trusted;

                foreach (var c in g)
                {
                    bool persistent = before.Contains(c.Pid + "|" + c.Remote + ":" + c.RemotePort);
                    string name = dns.NameFor(c.Remote);
                    if (name != null && ctx.Rules.IsPoolDomain(name))
                        p.Entity.Add(new Evidence("NET.POOL_DOMAIN", EvidenceCategory.Network, 32, "Connected to an address that resolves to a mining-pool-like host: " + name, c.Remote + ":" + c.RemotePort + " (" + name + ")"));
                    if (ctx.Rules.MiningPorts.Contains(c.RemotePort) && untrusted)
                        p.Entity.Add(new Evidence("NET.MINING_PORT", EvidenceCategory.Network, 6, "Connection to a port commonly used by mining pools (" + c.RemotePort + ")", c.Remote + ":" + c.RemotePort));
                    if (persistent && untrusted && (PathUtil.IsUserWritable(p.Path ?? "") || string.IsNullOrEmpty(p.Path)))
                        p.Entity.Add(new Evidence("NET.PERSISTENT_UNTRUSTED", EvidenceCategory.Network, 4, "Untrusted program keeps a persistent connection to an external address", c.Remote + ":" + c.RemotePort));
                }
                if (ctx.Rules.NeverExternal.Contains(p.Name))
                    p.Entity.Add(new Evidence("NET.SYSTEM_TOOL_EXTERNAL", EvidenceCategory.Network, 35, p.Name + " never talks to the internet normally, but has external connections (typical for hollowed processes)", string.Join(", ", eps)));
            }
        }

        static bool IsPrivate(string ip)
        {
            System.Net.IPAddress a;
            if (!System.Net.IPAddress.TryParse(ip, out a)) return false;
            var b = a.GetAddressBytes();
            if (b.Length == 4) return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || b[0] == 127;
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || ip.StartsWith("fe80") || ip.StartsWith("fc") || ip.StartsWith("fd");
        }

        // =====================================================================================================
        //   sustained CPU / GPU load: only ever a weak, corroborating signal
        // =====================================================================================================
        static void AnalyzeLoad(ScanContext ctx, ProcInfo p)
        {
            if (p.Entity == null) return;
            p.Entity.Set("cpuPercent", p.CpuPercent.ToString("0.0"));
            if (p.GpuPercent > 0) p.Entity.Set("gpuPercent", p.GpuPercent.ToString("0.0"));
            bool trusted = p.Image != null && p.Image.Trusted;
            bool heavyName = ctx.Rules.HeavyApps.Contains(Path.GetFileNameWithoutExtension(p.Name ?? ""));
            bool installed = !string.IsNullOrEmpty(p.Path) && (PathUtil.Classify(p.Path) == PathClass.ProgramFiles);
            if (trusted || (heavyName && installed) || p.Name.Equals("MineHunter.exe", StringComparison.OrdinalIgnoreCase)) return;   // games, compilers, VMs, browsers are allowed to be busy
            double threshold = ctx.CoreCount <= 4 ? 45 : 22;
            if (p.CpuPercent >= threshold)
                p.Entity.Add(new Evidence("BEH.CPU_SUSTAINED", EvidenceCategory.Behavior, 12, "Uses " + p.CpuPercent.ToString("0") + "% of the whole CPU while running in the background (measured over " + (ctx.Options.CpuSampleMs / 1000.0).ToString("0.#") + " s)", p.CpuPercent.ToString("0.0") + "%"));
            if (p.GpuPercent >= 35)
                p.Entity.Add(new Evidence("BEH.GPU_SUSTAINED", EvidenceCategory.Behavior, 8, "Uses " + p.GpuPercent.ToString("0") + "% of the GPU", p.GpuPercent.ToString("0.0") + "%"));
            if (p.CpuPercent >= threshold && !p.HasWindow)
                p.Entity.Add(new Evidence("BEH.CPU_NO_WINDOW", EvidenceCategory.Behavior, 4, "High CPU use by a program without any visible window"));
            if (p.Threads > 0 && ctx.Rules.HollowTargets.Contains(p.Name) && AllThreadsSuspended(p.Pid) && (DateTime.UtcNow - p.Start).TotalSeconds > 60)
                p.Entity.Add(new Evidence("PROC.SUSPENDED_LOLBIN", EvidenceCategory.Behavior, 30, p.Name + " has been sitting fully suspended for over a minute (payload injection pattern)"));
        }

        static bool AllThreadsSuspended(int pid)
        {
            try
            {
                using (var proc = Process.GetProcessById(pid))
                {
                    if (proc.Threads.Count == 0) return false;
                    foreach (ProcessThread t in proc.Threads)
                        if (t.ThreadState != System.Diagnostics.ThreadState.Wait || t.WaitReason != ThreadWaitReason.Suspended) return false;
                    return true;
                }
            }
            catch { return false; }
        }
    }

    /// <summary>Client DNS cache (IP -> host names) so that a connection to an IP can be tied to a mining-pool-like host name.</summary>
    public sealed class DnsCache
    {
        readonly Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string NameFor(string ip) { string n; return map.TryGetValue(ip, out n) ? n : null; }
        public static DnsCache Load()
        {
            var d = new DnsCache();
            try
            {
                var scope = new ManagementScope(@"\\.\root\StandardCimv2");
                scope.Connect();
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name,Data,Type FROM MSFT_DNSClientCache")))
                    foreach (ManagementObject o in s.Get())
                    {
                        string data = Convert.ToString(o["Data"]); string name = Convert.ToString(o["Name"]);
                        int type = 0; try { type = Convert.ToInt32(o["Type"]); } catch { }
                        if ((type == 1 || type == 28) && !string.IsNullOrEmpty(data) && !string.IsNullOrEmpty(name)) d.map[data] = name;
                    }
            }
            catch { }
            return d;
        }
    }

    public static class GpuSampler
    {
        /// <summary>pid -> GPU utilisation % over the window (Windows "GPU Engine" performance counters; empty when unavailable).</summary>
        public static Dictionary<int, double> Sample(int windowMs)
        {
            var res = new Dictionary<int, double>();
            try
            {
                if (!PerformanceCounterCategory.Exists("GPU Engine")) return res;
                var cat = new PerformanceCounterCategory("GPU Engine");
                var a = cat.ReadCategory();
                Thread.Sleep(Math.Max(700, Math.Min(windowMs, 2000)));
                var b = cat.ReadCategory();
                if (!a.Contains("Utilization Percentage") || !b.Contains("Utilization Percentage")) return res;
                var ia = a["Utilization Percentage"]; var ib = b["Utilization Percentage"];
                foreach (System.Collections.DictionaryEntry de in ib)
                {
                    string inst = (string)de.Key;
                    if (!inst.StartsWith("pid_") || !ia.Contains(inst)) continue;
                    int us = inst.IndexOf('_', 4);
                    int pid; if (us < 0 || !int.TryParse(inst.Substring(4, us - 4), out pid)) continue;
                    float v = CounterSampleCalculator.ComputeCounterValue(((InstanceData)ia[inst]).Sample, ((InstanceData)de.Value).Sample);
                    if (inst.IndexOf("engtype_3D", StringComparison.OrdinalIgnoreCase) < 0 && inst.IndexOf("engtype_Compute", StringComparison.OrdinalIgnoreCase) < 0 && inst.IndexOf("engtype_Cuda", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    double cur; res.TryGetValue(pid, out cur);
                    res[pid] = Math.Max(cur, v);
                }
            }
            catch { }
            return res;
        }
    }
}
