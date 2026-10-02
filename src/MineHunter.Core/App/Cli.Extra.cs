using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Remediation;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter
{
    /// <summary>The command-line side of the product layer: look at one file, hash it, ask the reputation sources, show the status of the program and of Windows' protection, list what runs,
    /// what starts by itself and who talks to the network. Every one of them uses the same engine as the windows.</summary>
    public static partial class Cli
    {
        public static string HelpExtra()
        {
            return @"
  MineHunter.exe quick | full             same as  scan --quick | scan --full
  MineHunter.exe scan <file>              analyse one file (verdict, reasons, signature, hashes); a folder is scanned like --path
  MineHunter.exe check <file> [--deep]    the same, with the technical data (sections, imports, strings, certificate chain)
  MineHunter.exe hash <file>              size and SHA-256 / SHA-1 / MD5
  MineHunter.exe reputation <sha256>      what the reputation sources say about a hash (VirusTotal only if you switched it on)
  MineHunter.exe status                   program, rules, protection settings, last scans, quarantine, Windows protection in short
  MineHunter.exe health                   Windows protection in detail (Defender, firewall, SmartScreen, UAC, updates, ...)
  MineHunter.exe processes | connections  running programs with their trust / external network connections
  MineHunter.exe startup | drivers | history      what starts by itself / installed drivers / past scans";
        }

        static bool RunExtra(string cmd, string[] a, AppConfig cfg, out int code)
        {
            code = 0;
            switch (cmd)
            {
                case "quick": code = Scan(new[] { "--quick" }.Concat(a).ToArray(), cfg); return true;
                case "full": code = Scan(new[] { "--full" }.Concat(a).ToArray(), cfg); return true;
                case "check": code = Check(a, true); return true;
                case "hash": code = HashCmd(a); return true;
                case "reputation": code = ReputationCmd(a); return true;
                case "status": code = Status(cfg); return true;
                case "health": code = Health(); return true;
                case "processes": code = Processes(); return true;
                case "connections": code = Connections(); return true;
                case "startup": code = StartupCmd(); return true;
                case "drivers": code = DriversCmd(); return true;
                case "history": code = HistoryCmd(); return true;
            }
            return false;
        }

        /// <summary>"scan &lt;file&gt;" : a file is checked, a folder is scanned.</summary>
        static bool ScanTarget(string[] a, AppConfig cfg, out int code)
        {
            code = 0;
            string target = a.FirstOrDefault(x => !x.StartsWith("--") && (File.Exists(x) || Directory.Exists(x)));
            if (target == null) return false;
            if (a.Length > 0 && a[0].StartsWith("--")) return false;
            if (File.Exists(target)) { code = Check(new[] { target }, false); return true; }
            code = Scan(a.Where(x => x != target).Concat(new[] { "--path", target }).ToArray(), cfg); return true;
        }

        static int Check(string[] a, bool defaultDeep)
        {
            string path = a.FirstOrDefault(x => !x.StartsWith("--"));
            if (path == null || !File.Exists(path)) { Console.Error.WriteLine("check: give an existing file."); return 3; }
            bool deep = Has(a, "--deep") || defaultDeep;
            var r = FileAnalyzer.Analyze(Path.GetFullPath(path), Settings.Current, true);
            O.WriteLine(r.Name + "  -  " + r.VerdictText);
            O.WriteLine("  " + r.Explanation);
            O.WriteLine("  Type: " + r.Kind + "   Size: " + r.Size + " bytes   Where: " + r.Location);
            O.WriteLine("  SHA-256: " + r.Sha256 + "\n  SHA-1:   " + r.Sha1 + "\n  MD5:     " + r.Md5);
            O.WriteLine("  Signature: " + r.SignatureText + (r.Publisher != null ? "  (" + r.Publisher + ")" : ""));
            if (r.Origin != null) O.WriteLine("  Origin: " + r.Origin + (r.HostUrl != null ? "  " + r.HostUrl : ""));
            foreach (var x in r.Reputation) O.WriteLine("  Reputation [" + x.Provider + "]: " + (x.Available ? Reputation.StatusText(x.Status) : "not available") + " - " + x.Detail);
            O.WriteLine("  Score: " + r.Score + " / 100");
            foreach (var e in r.Evidence) O.WriteLine("    " + (e.Weight >= 0 ? "+" : "") + e.Weight + "  [" + e.Category + "] " + Loc.Ev(e) + (string.IsNullOrEmpty(e.Detail) ? "" : "  {" + Text.Trunc(e.Detail, 100) + "}"));
            if (deep && r.Pe != null)
            {
                O.WriteLine("  PE: " + (r.Pe.Is64 ? "x64" : "x86") + (r.Pe.IsDotNet ? " .NET" : "") + (r.Pe.IsDll ? " DLL" : "") + (r.Pe.IsDriver ? " driver" : "") + "  entry 0x" + r.Pe.EntryPoint.ToString("X") + "  overlay " + r.Pe.Overlay + "  max code entropy " + r.Pe.MaxExecEntropy.ToString("0.00"));
                foreach (var s in r.Pe.Sections) O.WriteLine("    section " + s.Name.PadRight(8) + " raw " + s.RawSize.ToString().PadLeft(9) + "  entropy " + s.Entropy.ToString("0.00") + "  " + (s.Executable ? "X" : "-") + (s.Writable ? "W" : "-"));
                if (r.Pe.ImportDlls.Count > 0) O.WriteLine("  Imports: " + string.Join(", ", r.Pe.ImportDlls.Take(25)) + (r.Pe.ImportDlls.Count > 25 ? ", ..." : ""));
                if (r.Pe.ApiOfInterest.Count > 0) O.WriteLine("  Notable functions: " + string.Join(", ", r.Pe.ApiOfInterest));
                if (r.Pe.ExportNames.Count > 0) O.WriteLine("  Exports: " + string.Join(", ", r.Pe.ExportNames.Take(30)));
            }
            if (deep)
            {
                if (r.CertChain.Count > 0) { O.WriteLine("  Certificate chain:"); foreach (var c in r.CertChain) O.WriteLine("    " + c); }
                if (r.Urls.Count > 0) O.WriteLine("  URLs: " + string.Join(" ", r.Urls.Take(10)));
                if (r.Domains.Count > 0) O.WriteLine("  Domains: " + string.Join(" ", r.Domains.Take(15)));
                if (r.Ips.Count > 0) O.WriteLine("  IPs: " + string.Join(" ", r.Ips.Take(15)));
                if (r.PowerShell.Count > 0) O.WriteLine("  PowerShell fragments: " + string.Join(", ", r.PowerShell));
                if (r.MinerMarkers.Count > 0) O.WriteLine("  Miner markers: " + string.Join(", ", r.MinerMarkers));
            }
            return r.Verdict == FileVerdict.KnownMalware || r.Verdict == FileVerdict.Dangerous ? 2 : r.Verdict == FileVerdict.Suspicious ? 1 : r.Verdict == FileVerdict.Unreadable ? 3 : 0;
        }

        static int HashCmd(string[] a)
        {
            string path = a.FirstOrDefault(x => !x.StartsWith("--"));
            if (path == null || !File.Exists(path)) { Console.Error.WriteLine("hash: give an existing file."); return 3; }
            string sha = Hashing.Sha256(path);
            if (sha == null) { Console.Error.WriteLine("hash: the file cannot be read."); return 3; }
            O.WriteLine("SHA-256  " + sha); O.WriteLine("SHA-1    " + Hashing.Sha1(path)); O.WriteLine("MD5      " + Hashing.Md5(path)); O.WriteLine("Size     " + new FileInfo(path).Length + " bytes");
            return 0;
        }

        static int ReputationCmd(string[] a)
        {
            string h = a.FirstOrDefault(x => !x.StartsWith("--"));
            if (h == null || h.Length != 64 || !h.All(Uri.IsHexDigit)) { Console.Error.WriteLine("reputation: give a SHA-256 (64 hex characters)."); return 3; }
            var list = Reputation.Lookup(h.ToLowerInvariant(), 0, RulePack.Load(), Allowlist.Load(), Settings.Current);
            foreach (var r in list) O.WriteLine(r.Provider.PadRight(34) + (r.Available ? Reputation.StatusText(r.Status) : "not available").PadRight(24) + r.Detail);
            O.WriteLine("Overall: " + Reputation.StatusText(Reputation.Combine(list)) + "   (\"No data\" does not mean safe.)");
            return Reputation.Combine(list) == RepStatus.KnownBad ? 2 : 0;
        }

        static int Status(AppConfig cfg)
        {
            var s = Settings.Current;
            O.WriteLine("MineHunter " + AppInfo.Version + "   rules " + RulePack.Load().Version + "   data folder " + RulePack.DataDir);
            O.WriteLine("Administrator: " + new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator));
            var q = History.Last("Quick"); var f = History.Last("Full");
            O.WriteLine("Last quick scan: " + (q == null ? "never" : q.StartedTime.ToString("yyyy-MM-dd HH:mm") + "  threats " + q.Threats + "  notes " + q.Notes));
            O.WriteLine("Last full scan:  " + (f == null ? "never" : f.StartedTime.ToString("yyyy-MM-dd HH:mm") + "  threats " + f.Threats + "  notes " + f.Notes));
            O.WriteLine("Quarantine: " + Quarantine.List().Count + " item(s)");
            O.WriteLine("Preset " + s.Preset + ", sensitivity " + s.Sensitivity + ", notifications from " + s.NotifyLevel);
            O.WriteLine("Real-time components switched on: " + string.Join(", ", new[] { s.FileGuard ? "file" : null, s.DownloadGuard ? "download" : null, s.ProcessGuard ? "process" : null, s.ScriptGuard ? "script" : null, s.PersistenceGuard ? "persistence" : null, s.NetworkGuard ? "network" : null, s.UsbGuard ? "usb" : null, s.RansomwareGuard ? "ransomware" : null }.Where(x => x != null)) + "   (they work while the tray program or the window runs)");
            var st = ScheduleManager.Query(ScheduleManager.ScanTaskName);
            O.WriteLine("Scheduled scan: " + (s.ScheduleEnabled ? s.ScheduleMode + ", " + s.ScheduleEvery + " at " + s.ScheduleTime : "off") + (st.Exists && st.NextRun.HasValue ? "   next run " + st.NextRun.Value.ToString("yyyy-MM-dd HH:mm") : ""));
            O.WriteLine("Windows protection:");
            foreach (var h in WindowsHealth.Run().Where(x => x.State == HealthState.Bad || x.State == HealthState.Warn || x.Id == "defender" || x.Id == "firewall")) O.WriteLine("  [" + h.State + "] " + h.Title + ": " + h.Text);
            return 0;
        }

        static int Health()
        {
            foreach (var h in WindowsHealth.Run())
            {
                O.WriteLine("[" + h.State.ToString().ToUpperInvariant().PadRight(7) + "] " + h.Title + ": " + h.Text);
                if (!string.IsNullOrEmpty(h.Details)) foreach (var l in h.Details.Split('\n').Take(6)) O.WriteLine("             " + l);
            }
            return 0;
        }

        static int Processes()
        {
            var rules = RulePack.Load();
            foreach (var p in System.Diagnostics.Process.GetProcesses().OrderBy(x => x.ProcessName, StringComparer.OrdinalIgnoreCase))
                using (p)
                {
                    string path = null; try { path = p.MainModule.FileName; } catch { }
                    string trust = "?";
                    if (path != null) { var ti = Trust.Check(path); trust = ti == null ? "?" : ti.State == TrustState.Unsigned ? "unsigned" : ti.IsValid && (rules.IsTrustedPublisher(ti.Publisher) || (ti.Publisher ?? "").StartsWith("Microsoft")) ? "trusted" : ti.IsValid ? "signed" : "unsigned"; }
                    O.WriteLine(p.Id.ToString().PadLeft(7) + "  " + p.ProcessName.PadRight(32) + trust.PadRight(9) + (path ?? ""));
                }
            return 0;
        }

        static int Connections()
        {
            foreach (var c in NetworkView.Snapshot(RulePack.Load(), false).Where(x => x.External).OrderBy(x => x.Process, StringComparer.OrdinalIgnoreCase))
                O.WriteLine(c.Pid.ToString().PadLeft(7) + "  " + c.Process.PadRight(26) + (c.Trusted ? "trusted  " : "         ") + (c.Remote + ":" + c.RemotePort).PadRight(26) + c.State.PadRight(12) + (c.Path ?? ""));
            return 0;
        }

        static int StartupCmd()
        {
            foreach (var i in StartupManager.List(RulePack.Load())) O.WriteLine((i.Enabled ? "[on ] " : "[off] ") + (i.Trusted ? "trusted  " : "         ") + i.KindText.PadRight(22) + i.Name.PadRight(34) + Text.Trunc(i.Command ?? "", 90));
            return 0;
        }

        static int DriversCmd()
        {
            foreach (var d in Drivers.Inventory().Where(Drivers.IsInteresting)) O.WriteLine(d.Category.PadRight(18) + d.Name.PadRight(48) + (d.Version ?? "").PadRight(18) + (d.Date.HasValue ? d.Date.Value.ToString("yyyy-MM-dd") : "").PadRight(12) + (d.Signed ? "signed" : "NOT signed") + (d.Problem != null ? "  " + d.Problem : ""));
            return 0;
        }

        static int HistoryCmd()
        {
            foreach (var h in History.List().Take(50)) O.WriteLine(h.StartedTime.ToString("yyyy-MM-dd HH:mm") + "  " + h.Mode.PadRight(7) + (h.Trigger ?? "").PadRight(10) + h.Seconds.ToString("0").PadLeft(5) + " s  critical " + h.Critical + " high " + h.High + " medium " + h.Medium + " notes " + h.Notes + (h.Aborted ? "  (stopped)" : ""));
            return 0;
        }
    }
}
