using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Guards
{
    public sealed class ConnectionInfo
    {
        public int Pid; public string Process, Path, Local, Remote, State, Trust, Publisher, Protocol = "TCP";
        public int LocalPort, RemotePort;
        public bool External, Trusted, UserWritable; public DateTime? FirstSeen;
        public string Direction { get { return State == "Listen" ? "in" : "out"; } }
    }

    /// <summary>The live connection list: which program talks to which address. Built from the Windows TCP table, no packet capture. UDP is not shown.</summary>
    public static class NetworkView
    {
        static readonly Dictionary<string, DateTime> FirstSeen = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        static readonly object Lock = new object();

        public static bool IsPrivate(string ip)
        {
            IPAddress a; if (!IPAddress.TryParse(ip, out a)) return true;
            if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)) return true;
            var b = a.GetAddressBytes();
            if (b.Length == 4) return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || b[0] == 0 || b[0] >= 224;
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC || b[0] == 0xFF;
        }

        /// <summary>One look at all TCP connections with the program behind each. Trusted = a valid signature of a trusted publisher (looked up once per file).</summary>
        public static List<ConnectionInfo> Snapshot(RulePack rules, bool includeListening = true)
        {
            var list = new List<ConnectionInfo>();
            var names = new Dictionary<int, Tuple<string, string>>();
            foreach (var c in Net.GetTcp())
            {
                if (c.State == "TimeWait" || c.State == "Closed" || c.State == "DeleteTcb") continue;
                if (c.State == "Listen" && !includeListening) continue;
                Tuple<string, string> who;
                if (!names.TryGetValue(c.Pid, out who))
                {
                    string name = c.Pid == 0 ? "System Idle" : c.Pid == 4 ? "System" : null, path = null;
                    if (c.Pid > 4) { try { using (var p = Process.GetProcessById(c.Pid)) { name = p.ProcessName; try { path = p.MainModule.FileName; } catch { } } } catch { } }
                    names[c.Pid] = who = Tuple.Create(name ?? "?", path);
                }
                var ci = new ConnectionInfo { Pid = c.Pid, Process = who.Item1, Path = who.Item2, Local = c.Local, Remote = c.Remote, LocalPort = c.LocalPort, RemotePort = c.RemotePort, State = c.State, External = !IsPrivate(c.Remote) && c.State != "Listen" };
                if (!string.IsNullOrEmpty(ci.Path))
                {
                    ci.UserWritable = PathUtil.IsUserWritable(ci.Path);
                    try
                    {
                        var ti = Trust.Check(ci.Path);
                        if (ti != null) { ci.Publisher = ti.Publisher; ci.Trusted = ti.IsValid && (ti.Publisher != null && (rules == null ? ti.Publisher.StartsWith("Microsoft") : (rules.IsTrustedPublisher(ti.Publisher) || ti.Publisher.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)))); ci.Trust = ti.State.ToString(); }
                    }
                    catch { }
                }
                if (ci.External)
                {
                    string key = (ci.Path ?? ci.Process) + "|" + ci.Remote;
                    lock (Lock)
                    {
                        DateTime t; if (!FirstSeen.TryGetValue(key, out t)) { FirstSeen[key] = t = DateTime.Now; if (FirstSeen.Count > 20000) FirstSeen.Clear(); }
                        ci.FirstSeen = t;
                    }
                }
                list.Add(ci);
            }
            return list;
        }
    }

    /// <summary>Blocking a program's network access is done with Windows Firewall rules (the system's own firewall), never with a filter of our own. These functions only BUILD the
    /// commands; the window runs them after a click and a confirmation.</summary>
    public static class FirewallBlock
    {
        public const string Prefix = "MineHunter block - ";

        public static string RuleName(string exePath) { return Prefix + Path.GetFileName(exePath); }

        /// <summary>The two netsh commands (outgoing and incoming) that block a program. Returns null when the path is not a plain absolute file path.</summary>
        public static List<string> BuildBlockCommands(string exePath)
        {
            if (string.IsNullOrWhiteSpace(exePath) || exePath.IndexOfAny(new[] { '"', '\r', '\n', '|', '&', '<', '>' }) >= 0 || !Path.IsPathRooted(exePath)) return null;
            string n = RuleName(exePath).Replace("\"", "");
            return new List<string>
            {
                "advfirewall firewall add rule name=\"" + n + "\" dir=out action=block program=\"" + exePath + "\" enable=yes profile=any",
                "advfirewall firewall add rule name=\"" + n + "\" dir=in action=block program=\"" + exePath + "\" enable=yes profile=any"
            };
        }

        public static string BuildUnblockCommand(string exePath) { return "advfirewall firewall delete rule name=\"" + RuleName(exePath).Replace("\"", "") + "\""; }

        /// <summary>Blocks the program. Returns null on success or the error text.</summary>
        public static string Block(string exePath)
        {
            var cmds = BuildBlockCommands(exePath); if (cmds == null) return "not a valid program path";
            if (!File.Exists(exePath)) return "the program file does not exist";
            foreach (var c in cmds) { string err = Netsh(c); if (err != null) return err; }
            return null;
        }

        public static string Unblock(string exePath) { return Netsh(BuildUnblockCommand(exePath)); }

        /// <summary>The programs blocked by MineHunter (read from the firewall's own rule list).</summary>
        public static List<string> Blocked()
        {
            var l = new List<string>();
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"))
                    if (k != null) foreach (var n in k.GetValueNames()) { string v = Convert.ToString(k.GetValue(n)); if (v.IndexOf("Name=" + Prefix, StringComparison.OrdinalIgnoreCase) >= 0) foreach (var part in v.Split('|')) if (part.StartsWith("App=")) { string a = part.Substring(4); if (!l.Contains(a, StringComparer.OrdinalIgnoreCase)) l.Add(a); } }
            }
            catch { }
            return l;
        }

        static string Netsh(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe", args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd(), e = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(20000)) { try { p.Kill(); } catch { } return "timed out"; }
                    return p.ExitCode == 0 ? null : (string.IsNullOrWhiteSpace(e) ? o.Trim() : e.Trim());
                }
            }
            catch (Exception ex) { return ex.Message; }
        }
    }

    /// <summary>Network Guard: watches which programs open connections to the outside. A trusted program is not interesting. An unknown one from a user folder that connects to an
    /// address for the first time is one more signal for the correlator - alone it is nothing, together with "started from Temp" and "made an autostart entry" it is a story.</summary>
    public sealed class NetworkGuard : IGuard
    {
        GuardContext g; GuardState state = GuardState.Off; string detail = "";
        Timer timer; int busy;
        readonly HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public TimeSpan Interval = TimeSpan.FromSeconds(6);
        public string Name { get { return "network"; } }
        public string Title { get { return Loc.L("Network Guard", "Контроль сети"); } }
        public GuardStatus Status { get { return new GuardStatus { Name = Name, Title = Title, State = state, Detail = detail }; } }

        public void Start(GuardContext ctx)
        {
            g = ctx;
            try { foreach (var c in NetworkView.Snapshot(g.Rules, false)) seen.Add(Key(c)); } catch { }
            timer = new Timer(_ => Tick(), null, Interval, Interval);
            state = GuardState.On; detail = Loc.L("watching connections to the outside (TCP, every " + (int)Interval.TotalSeconds + " s)", "следит за соединениями наружу (TCP, раз в " + (int)Interval.TotalSeconds + " с)");
        }

        public void Stop() { state = GuardState.Off; if (timer != null) { timer.Dispose(); timer = null; } }

        static string Key(ConnectionInfo c) { return c.Pid + "|" + c.Remote + ":" + c.RemotePort; }

        void Tick()
        {
            if (Interlocked.Exchange(ref busy, 1) == 1) return;
            try { Evaluate(NetworkView.Snapshot(g.Rules, false)); }
            catch (Exception ex) { Log.Warn("network guard: " + ex.Message); }
            finally { Interlocked.Exchange(ref busy, 0); }
        }

        /// <summary>Judges a list of connections (public so a test can feed it a synthetic one).</summary>
        public void Evaluate(List<ConnectionInfo> conns)
        {
            foreach (var c in conns)
            {
                if (!c.External || c.State != "Established" && c.State != "SynSent") continue;
                if (!seen.Add(Key(c))) continue;
                if (string.IsNullOrEmpty(c.Path) || c.Trusted) continue;
                if (g.Settings != null && g.Settings.IsExcludedPath(c.Path)) continue;
                string actor = PathUtil.Normalize(c.Path);
                var signals = new List<Signal>();
                if (g.Rules.MiningPorts.Contains(c.RemotePort)) signals.Add(new Signal { Actor = actor, Category = EvidenceCategory.Network, Weight = 22, Rule = "NET.MINING_PORT", Text = Loc.L("connected to port " + c.RemotePort + ", which mining pools use (" + c.Remote + ")", "подключилась к порту " + c.RemotePort + ", который используют майнинг-пулы (" + c.Remote + ")"), Pid = c.Pid });
                if (c.UserWritable) signals.Add(new Signal { Actor = actor, Category = EvidenceCategory.Network, Weight = 12, Rule = "NET.NEW_EXTERNAL", Text = Loc.L("connected to a new external address " + c.Remote + ":" + c.RemotePort, "подключилась к новому внешнему адресу " + c.Remote + ":" + c.RemotePort), Pid = c.Pid });
                if (signals.Count == 0) continue;
                // is this program one of the ones the other guards already worry about?
                Assessment last = null;
                foreach (var s in signals) { var a = g.Correlator.Add(s); if (a != null) last = a; }
                if (last == null) continue;
                var alert = new GuardAlert { Guard = Name, Level = last.Level.Value, Path = c.Path, Pid = c.Pid, Actor = c.Path, Title = Loc.L("An unknown program is talking to the internet", "Неизвестная программа выходит в интернет") };
                alert.Reasons = last.Signals.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Select(x => x.Text).Distinct().ToList();
                alert.Text = Correlator.Story(c.Path, last.Signals);
                try { alert.Sha256 = Hashing.Sha256(c.Path); } catch { }
                g.Alert(alert);
            }
        }
    }
}
