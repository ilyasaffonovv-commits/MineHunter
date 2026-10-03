using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace MineHunter.UpdateHelper
{
    /// <summary>
    /// MineHunter.UpdateHelper.exe - the small program that installs a verified update. It does not talk to the network and does not decide anything about trust:
    /// the main program has already checked the signed announcement, the SHA-256 and the package. The helper only
    ///   1. waits until every MineHunter program has closed,
    ///   2. saves every file it is about to replace into the backup folder,
    ///   3. copies the new files in and compares each copy with the source (SHA-256),
    ///   4. on ANY problem puts the old files back, so the installed version keeps working,
    ///   5. writes result.json (the program shows it at the next start) and starts the program again.
    /// It runs from a temporary copy of itself so that its own file can be replaced too.
    ///   apply    --src DIR --dst DIR --backup DIR --result FILE --from V --to V [--pid N] [--restart EXE] [--cleanup DIR]
    ///   rollback --dst DIR --backup DIR --result FILE [--restart EXE]
    /// </summary>
    static class Program
    {
        static string _logFile;

        static int Main(string[] argv)
        {
            var a = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string cmd = argv.Length > 0 ? argv[0] : "";
            for (int i = 1; i < argv.Length; i++)
                if (argv[i].StartsWith("--")) { string k = argv[i].Substring(2); a[k] = i + 1 < argv.Length && !argv[i + 1].StartsWith("--") ? argv[++i] : "1"; }
            try
            {
                string resultFile = Get(a, "result");
                if (resultFile != null) _logFile = Path.Combine(Path.GetDirectoryName(resultFile) ?? ".", "helper.log");
                if (cmd == "apply") return Apply(a);
                if (cmd == "rollback") return Rollback(a);
                return 2;
            }
            catch (Exception ex)
            {
                Log("fatal: " + ex);
                return 3;
            }
        }

        static string Get(Dictionary<string, string> a, string k) { string v; return a.TryGetValue(k, out v) ? v : null; }

        static void Log(string m)
        {
            try { if (_logFile != null) File.AppendAllText(_logFile, DateTime.Now.ToString("HH:mm:ss") + " " + m + "\r\n"); } catch { }
        }

        // ------------------------------------------------------------------------------------------------ apply
        static int Apply(Dictionary<string, string> a)
        {
            string src = Get(a, "src"), dst = Get(a, "dst"), backup = Get(a, "backup"), result = Get(a, "result"), from = Get(a, "from") ?? "", to = Get(a, "to") ?? "", restart = Get(a, "restart"), cleanup = Get(a, "cleanup");
            if (src == null || dst == null || backup == null || result == null) return 2;
            Log("apply " + from + " -> " + to + "  src=" + src + "  dst=" + dst);
            int pid; if (int.TryParse(Get(a, "pid"), out pid)) WaitForExit(pid, 90);

            var running = StillRunning(dst);
            int waitSeconds; if (!int.TryParse(Get(a, "wait"), out waitSeconds)) waitSeconds = 60;
            for (int i = 0; i < waitSeconds * 2 / 3 && running.Count > 0; i++) { Thread.Sleep(1500); running = StillRunning(dst); }
            if (running.Count > 0)
            {
                Log("still running: " + string.Join(", ", running));
                Report(result, false, false, from, to, "MineHunter is still open (" + string.Join(", ", running) + "). Close it and try the update again. Nothing was changed.");
                Restart(restart, dst); Clean(cleanup);
                return 1;
            }

            var files = Directory.GetFiles(src, "*", SearchOption.AllDirectories).Select(f => f.Substring(src.TrimEnd('\\').Length + 1)).Where(r => !Skip(r)).ToList();
            if (files.Count == 0) { Report(result, false, false, from, to, "The update package is empty. Nothing was changed."); Restart(restart, dst); Clean(cleanup); return 1; }

            // 1. backup of everything that will be replaced
            var created = new List<string>();
            try
            {
                if (Directory.Exists(backup)) Directory.Delete(backup, true);
                Directory.CreateDirectory(backup);
                foreach (var rel in files)
                {
                    string target = Path.Combine(dst, rel);
                    if (File.Exists(target)) { string b = Path.Combine(backup, rel); Directory.CreateDirectory(Path.GetDirectoryName(b)); File.Copy(target, b, true); }
                    else created.Add(rel);
                }
                File.WriteAllLines(Path.Combine(backup, "_created.txt"), created);
            }
            catch (Exception ex)
            {
                Log("backup failed: " + ex.Message);
                Report(result, false, false, from, to, "Could not back up the current version (" + ex.Message + "). Nothing was changed.");
                Restart(restart, dst); Clean(cleanup);
                return 1;
            }

            // 2. copy
            string error = null;
            try
            {
                foreach (var rel in files)
                {
                    string source = Path.Combine(src, rel), target = Path.Combine(dst, rel), tmp = target + ".mhnew";
                    Directory.CreateDirectory(Path.GetDirectoryName(target));
                    File.Copy(source, tmp, true);
                    if (File.Exists(target)) File.Replace(tmp, target, null); else File.Move(tmp, target);
                }
                // 3. verify
                foreach (var rel in files)
                    if (Hash(Path.Combine(src, rel)) != Hash(Path.Combine(dst, rel))) { error = "The copy of " + rel + " does not match the package."; break; }
            }
            catch (Exception ex) { error = ex.Message; }

            if (error != null)
            {
                Log("failed: " + error + " - rolling back");
                bool ok = Restore(dst, backup);
                foreach (var f in Directory.GetFiles(dst, "*.mhnew", SearchOption.AllDirectories)) { try { File.Delete(f); } catch { } }
                Report(result, false, ok, from, to, error + (ok ? " The previous version was put back and keeps working." : " The previous version could NOT be fully restored: reinstall from the release page."));
                Restart(restart, dst); Clean(cleanup);
                return 1;
            }

            Log("done");
            Report(result, true, false, from, to, "");
            Restart(restart, dst); Clean(cleanup);
            return 0;
        }

        static int Rollback(Dictionary<string, string> a)
        {
            string dst = Get(a, "dst"), backup = Get(a, "backup"), result = Get(a, "result"), restart = Get(a, "restart");
            if (dst == null || backup == null || !Directory.Exists(backup)) return 2;
            int pid; if (int.TryParse(Get(a, "pid"), out pid)) WaitForExit(pid, 60);
            bool ok = Restore(dst, backup);
            if (result != null) Report(result, ok, ok, "", "", ok ? "" : "The previous version could not be restored.");
            Restart(restart, dst);
            return ok ? 0 : 1;
        }

        static bool Restore(string dst, string backup)
        {
            bool ok = true;
            try
            {
                foreach (var f in Directory.GetFiles(backup, "*", SearchOption.AllDirectories))
                {
                    string rel = f.Substring(backup.TrimEnd('\\').Length + 1);
                    if (rel == "_created.txt") continue;
                    try
                    {
                        string t = Path.Combine(dst, rel);
                        // a file that was never replaced (it is the one that could not be, for example) is already what it was: nothing to put back
                        try { if (File.Exists(t) && Hash(t) == Hash(f)) continue; } catch { }
                        Directory.CreateDirectory(Path.GetDirectoryName(t));
                        for (int attempt = 1; ; attempt++)
                        {
                            try { File.Copy(f, t, true); break; }
                            catch (IOException) when (attempt < 4) { Thread.Sleep(500); }
                        }
                    }
                    catch (Exception ex) { ok = false; Log("restore " + rel + ": " + ex.Message); }
                }
                string list = Path.Combine(backup, "_created.txt");
                if (File.Exists(list)) foreach (var rel in File.ReadAllLines(list)) { try { File.Delete(Path.Combine(dst, rel)); } catch { } }
            }
            catch (Exception ex) { ok = false; Log("restore: " + ex.Message); }
            return ok;
        }

        // ------------------------------------------------------------------------------------------------ helpers
        static bool Skip(string rel)
        {
            string r = rel.Replace('/', '\\');
            return r.Equals("config.json", StringComparison.OrdinalIgnoreCase) || r.StartsWith("Reports\\", StringComparison.OrdinalIgnoreCase) || r.EndsWith(".mhnew", StringComparison.OrdinalIgnoreCase);
        }

        static string Hash(string path)
        {
            using (var fs = File.OpenRead(path)) using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(fs));
        }

        static void WaitForExit(int pid, int seconds)
        {
            try { using (var p = Process.GetProcessById(pid)) p.WaitForExit(seconds * 1000); } catch { }
        }

        /// <summary>MineHunter programs (not this helper) that run from the folder being updated.</summary>
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        static extern int GetLongPathNameW(string shortPath, StringBuilder longPath, int size);

        static string LongPath(string path)
        {
            try
            {
                var sb = new StringBuilder(1024);
                int n = GetLongPathNameW(path, sb, sb.Capacity);
                return n > 0 && n < sb.Capacity ? sb.ToString() : path;
            }
            catch { return path; }
        }

        static List<string> StillRunning(string dst)
        {
            var list = new List<string>();
            // a process reports its long path; the folder may have been given in the 8.3 form (C:\Users\RUNNER~1\...), and then no running program would ever match
            string d = LongPath(Path.GetFullPath(dst)).TrimEnd('\\') + "\\";
            int me = Process.GetCurrentProcess().Id;
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    try
                    {
                        if (p.Id == me || !p.ProcessName.StartsWith("MineHunter", StringComparison.OrdinalIgnoreCase) || p.ProcessName.IndexOf("UpdateHelper", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        string path = LongPath(p.MainModule.FileName);
                        if (path.StartsWith(d, StringComparison.OrdinalIgnoreCase)) list.Add(p.ProcessName + "#" + p.Id);
                    }
                    catch { }
                }
            }
            return list;
        }

        static void Report(string file, bool ok, bool rolledBack, string from, string to, string error)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(file));
                var sb = new StringBuilder("{");
                sb.Append("\"ok\":" + (ok ? "true" : "false") + ",\"rolledBack\":" + (rolledBack ? "true" : "false") + ",\"from\":\"" + Esc(from) + "\",\"to\":\"" + Esc(to) + "\",\"error\":\"" + Esc(error) + "\",\"time\":\"" + DateTime.Now.ToString("o") + "\"}");
                File.WriteAllText(file, sb.ToString(), new UTF8Encoding(false));
            }
            catch (Exception ex) { Log("report: " + ex.Message); }
        }

        static string Esc(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                if (c == '"') sb.Append("\\\""); else if (c == '\\') sb.Append("\\\\"); else if (c == '\n') sb.Append("\\n"); else if (c == '\r') { }
                else if (c < 32) sb.Append(' '); else sb.Append(c);
            }
            return sb.ToString();
        }

        static void Restart(string exe, string dst)
        {
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return;
            try { Process.Start(new ProcessStartInfo(exe) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(exe), Arguments = "--after-update" }); }
            catch (Exception ex) { Log("restart: " + ex.Message); }
        }

        static void Clean(string tmp)
        {
            if (string.IsNullOrEmpty(tmp)) return;
            try
            {
                // this very program runs from that folder: let it end first, then remove it
                Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 4 127.0.0.1 >nul & rmdir /s /q \"" + tmp + "\"") { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden });
            }
            catch { }
        }
    }
}
