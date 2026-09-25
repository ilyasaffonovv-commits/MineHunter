// MinerLab - BENIGN synthetic test harness for anti-miner detectors.
//
// What it can do (and nothing else):
//   sim      : optional duty-cycle CPU load, optional RAM hold, optional localhost-only chatter, then exits
//   worker   : same as sim (a separate role so that a Launcher -> Sim -> Worker chain can be built from copies)
//   launcher : starts ONE child that must be a byte-identical copy of this very executable (hash checked)
//   server   : localhost-only TCP echo server (127.0.0.1)
//   service  : runs as a Windows service that idles and stops itself
//   idle     : sleeps
//
// Hard safety rules (enforced in code):
//   * every mode terminates by itself: default 30 s, absolute maximum 60 s
//   * CPU load runs on BelowNormal threads; total memory hold is capped at 1024 MB
//   * sockets are only ever opened to / listened on 127.0.0.1
//   * a kill-switch file (MinerLab.STOP in %TEMP%\MinerLab or %ProgramData%\MinerLab) ends every mode within 1 s
//   * launcher refuses to start anything that is not a hash-identical copy of itself
//   * no network access to anything but loopback, no file writes except its own optional log
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace MinerLab
{
    internal static class Program
    {
        const int DefaultSeconds = 30;
        const int MaxSeconds = 60;
        const int MaxMemMb = 1024;

        static readonly DateTime Started = DateTime.UtcNow;
        static int deadlineSec = DefaultSeconds;
        static volatile bool stop;
        static string label = "MinerLabTest";

        static int Main(string[] args)
        {
            var o = Parse(args);
            string mode = o.ContainsKey("mode") ? o["mode"] : "idle";
            label = o.ContainsKey("label") ? o["label"] : label;
            int seconds = GetInt(o, "seconds", DefaultSeconds);
            deadlineSec = Math.Max(1, Math.Min(seconds, MaxSeconds));
            int cpu = Math.Max(0, Math.Min(GetInt(o, "cpu", 0), 100));
            int memMb = Math.Max(0, Math.Min(GetInt(o, "mem", 0), MaxMemMb));
            int port = GetInt(o, "port", 0);

            if (KillSwitch()) return 3;

            if (mode == "service")
            {
                ServiceBase.Run(new LabService(o.ContainsKey("svcname") ? o["svcname"] : "MinerLabTestService", deadlineSec));
                return 0;
            }

            var watchdog = new Thread(() =>
            {
                // Independent hard stop: even if a worker thread hangs, the process ends at the deadline.
                while (!stop)
                {
                    Thread.Sleep(500);
                    if ((DateTime.UtcNow - Started).TotalSeconds >= deadlineSec || KillSwitch()) { stop = true; }
                }
                Thread.Sleep(1500);
                Environment.Exit(0);
            }) { IsBackground = true, Name = "deadline" };
            watchdog.Start();

            var threads = new List<Thread>();
            byte[] hold = null;

            switch (mode)
            {
                case "sim":
                case "worker":
                    if (cpu > 0) threads.AddRange(StartCpuLoad(cpu));
                    if (memMb > 0) hold = HoldMemory(memMb);
                    if (port > 0) { var t = new Thread(() => LoopbackClient(port)) { IsBackground = true }; t.Start(); threads.Add(t); }
                    if (o.ContainsKey("child")) StartChild(o["child"], ChildArgs(o));
                    break;
                case "launcher":
                    if (o.ContainsKey("child")) StartChild(o["child"], ChildArgs(o));
                    break;
                case "server":
                    if (port > 0) { var t = new Thread(() => LoopbackServer(port)) { IsBackground = true }; t.Start(); threads.Add(t); }
                    break;
                default: // idle
                    break;
            }

            while (!stop) Thread.Sleep(200);
            GC.KeepAlive(hold);
            return 0;
        }

        // ---- CPU: N threads (one per logical core), each busy `duty` ms out of every 100 ms
        static List<Thread> StartCpuLoad(int dutyPercent)
        {
            var list = new List<Thread>();
            int n = Environment.ProcessorCount;
            for (int i = 0; i < n; i++)
            {
                var t = new Thread(() =>
                {
                    var sw = new Stopwatch();
                    double sink = 1.0;
                    while (!stop)
                    {
                        sw.Restart();
                        while (sw.ElapsedMilliseconds < dutyPercent && !stop) { sink = Math.Sqrt(sink + 12345.6789) * 1.0000001; }
                        int rest = 100 - dutyPercent;
                        if (rest > 0) Thread.Sleep(rest);
                    }
                    GC.KeepAlive(sink);
                }) { IsBackground = true, Priority = ThreadPriority.BelowNormal, Name = "load" };
                t.Start();
                list.Add(t);
            }
            return list;
        }

        // ---- RAM: allocate and touch every page, hold until the deadline
        static byte[] HoldMemory(int mb)
        {
            var buf = new byte[(long)mb * 1024 * 1024];
            for (long i = 0; i < buf.LongLength; i += 4096) buf[i] = 1;
            return buf;
        }

        // ---- network: loopback only. Sends harmless, clearly labelled test lines.
        static void LoopbackClient(int port)
        {
            int n = 0;
            while (!stop)
            {
                try
                {
                    using (var c = new TcpClient())
                    {
                        c.Connect(IPAddress.Loopback, port);
                        var s = c.GetStream();
                        s.ReadTimeout = 1500;
                        while (!stop && c.Connected)
                        {
                            byte[] line = Encoding.ASCII.GetBytes("MINERLAB_TEST_PING " + (++n) + " " + label + "\n");
                            s.Write(line, 0, line.Length);
                            try { var buf = new byte[256]; s.Read(buf, 0, buf.Length); } catch { }
                            Thread.Sleep(2000);
                        }
                    }
                }
                catch { Thread.Sleep(1000); }
            }
        }

        static void LoopbackServer(int port)
        {
            TcpListener l = null;
            try
            {
                l = new TcpListener(IPAddress.Loopback, port);   // 127.0.0.1 only - never 0.0.0.0
                l.Start();
                while (!stop)
                {
                    if (!l.Pending()) { Thread.Sleep(100); continue; }
                    var c = l.AcceptTcpClient();
                    var t = new Thread(() =>
                    {
                        try
                        {
                            using (c)
                            {
                                var s = c.GetStream();
                                var buf = new byte[512];
                                s.ReadTimeout = 2000;
                                while (!stop)
                                {
                                    int r = s.Read(buf, 0, buf.Length);
                                    if (r <= 0) break;
                                    byte[] ack = Encoding.ASCII.GetBytes("MINERLAB_TEST_ACK\n");
                                    s.Write(ack, 0, ack.Length);
                                }
                            }
                        }
                        catch { }
                    }) { IsBackground = true };
                    t.Start();
                }
            }
            catch { }
            finally { try { if (l != null) l.Stop(); } catch { } }
        }

        // default child arguments: a low-load worker for whatever time is left (no nested quoting needed)
        static string ChildArgs(Dictionary<string, string> o)
        {
            if (o.ContainsKey("childargs")) return o["childargs"];
            int left = Math.Max(1, deadlineSec - (int)(DateTime.UtcNow - Started).TotalSeconds);
            return "--mode worker --cpu 10 --seconds " + left + " --label " + label + "_w";
        }

        // ---- process chain: only a hash-identical copy of this executable may be launched
        static void StartChild(string childPath, string childArgs)
        {
            try
            {
                string self = Process.GetCurrentProcess().MainModule.FileName;
                if (!File.Exists(childPath) || Sha256(childPath) != Sha256(self))
                {
                    Console.Error.WriteLine("refusing to start a child that is not an identical copy of MinerLab");
                    return;
                }
                var psi = new ProcessStartInfo(childPath, childArgs) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
                Process.Start(psi);
            }
            catch { }
        }

        static string Sha256(string path)
        {
            using (var sha = SHA256.Create())
            using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                return BitConverter.ToString(sha.ComputeHash(f));
        }

        static bool KillSwitch()
        {
            try
            {
                return File.Exists(Path.Combine(Path.GetTempPath(), "MinerLab", "MinerLab.STOP"))
                    || File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinerLab", "MinerLab.STOP"));
            }
            catch { return false; }
        }

        static Dictionary<string, string> Parse(string[] a)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < a.Length; i++)
            {
                if (!a[i].StartsWith("--")) continue;
                string k = a[i].Substring(2);
                string v = (i + 1 < a.Length && !a[i + 1].StartsWith("--")) ? a[++i] : "1";
                d[k] = v;
            }
            return d;
        }
        static int GetInt(Dictionary<string, string> d, string k, int def)
        {
            int v; return d.ContainsKey(k) && int.TryParse(d[k], out v) ? v : def;
        }
    }

    // Benign Windows service: does nothing but idle, then stops itself.
    internal sealed class LabService : ServiceBase
    {
        readonly int seconds;
        Timer timer;
        public LabService(string name, int seconds) { ServiceName = name; this.seconds = seconds; CanStop = true; }
        protected override void OnStart(string[] args)
        {
            timer = new Timer(_ => { try { Stop(); } catch { } }, null, seconds * 1000, Timeout.Infinite);
        }
        protected override void OnStop() { if (timer != null) timer.Dispose(); }
    }
}
