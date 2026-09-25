using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace MineHunter.Util
{
    /// <summary>Where a file lives, as far as risk is concerned.</summary>
    public enum PathClass
    {
        WindowsSystem,          // %SystemRoot%\System32, SysWOW64, WinSxS, servicing ...
        WindowsOther,           // other places under %SystemRoot% (except Temp/Tasks)
        WindowsTemp,            // %SystemRoot%\Temp, %SystemRoot%\Tasks ... (writable by users/services)
        ProgramFiles,
        ProgramData,            // C:\ProgramData root or sub-folder (writable by everyone)
        UserTemp,
        UserAppDataRoamingRoot, // %APPDATA%\file.exe
        UserAppDataRoaming,
        UserAppDataLocalRoot,   // %LOCALAPPDATA%\file.exe
        UserAppDataLocalPrograms, // %LOCALAPPDATA%\Programs\... (legit per-user install location)
        UserAppDataLocal,
        UserDownloads,
        UserDesktopDocs,
        UserProfileOther,
        Public,
        RecycleBin,
        DriveRoot,
        Other
    }

    public static class PathUtil
    {
        public static readonly string WinDir = (Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows").TrimEnd('\\');
        public static readonly string System32 = WinDir + @"\System32";
        public static readonly string SysWow64 = WinDir + @"\SysWOW64";
        public static readonly string ProgramFiles = (Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files").TrimEnd('\\');
        public static readonly string ProgramFilesX86 = (Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)").TrimEnd('\\');
        public static readonly string ProgramData = (Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData").TrimEnd('\\');
        public static readonly string SystemDrive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');

        static readonly Regex UserRootRx = new Regex(@"^(?<root>[a-z]:\\users\\[^\\]+)(\\(?<rest>.*))?$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        static readonly char[] Quotes = { '"', '\'' };

        /// <summary>Canonical form for comparisons: env vars expanded, quotes and NT/extended prefixes removed, forward slashes fixed.</summary>
        public static string Normalize(string p)
        {
            if (string.IsNullOrWhiteSpace(p)) return "";
            p = p.Trim().Trim(Quotes).Trim();
            if (p.Length == 0) return "";
            if (p.IndexOf('%') >= 0) { try { p = Environment.ExpandEnvironmentVariables(p); } catch { } }
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p.Substring(8);
            else if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal)) p = p.Substring(4);
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = WinDir + p.Substring(11);
            p = p.Replace('/', '\\');
            // trailing separators
            while (p.Length > 3 && p.EndsWith("\\")) p = p.Substring(0, p.Length - 1);
            return p;
        }

        public static string Key(string p) { return Normalize(p).ToLowerInvariant(); }

        public static bool Same(string a, string b) { return string.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase); }

        public static bool IsUnder(string path, string dir)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(dir)) return false;
            string p = Normalize(path), d = Normalize(dir);
            if (p.Length < d.Length) return false;
            if (!p.StartsWith(d, StringComparison.OrdinalIgnoreCase)) return false;
            return p.Length == d.Length || p[d.Length] == '\\' || d.EndsWith("\\");
        }

        /// <summary>All user profile roots present on this machine.</summary>
        public static List<string> UserProfiles()
        {
            var list = new List<string>();
            try
            {
                string users = SystemDrive + @"\Users";
                if (Directory.Exists(users))
                    foreach (var d in Directory.GetDirectories(users))
                    {
                        string n = Path.GetFileName(d);
                        if (n.Equals("Default", StringComparison.OrdinalIgnoreCase) || n.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                            n.Equals("All Users", StringComparison.OrdinalIgnoreCase) || n.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                            n.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                        // junctions such as the localised "All Users" ("Все пользователи") point at C:\ProgramData: not a profile, and scanning it twice wastes minutes
                        try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; } catch { }
                        list.Add(d);
                    }
            }
            catch { }
            return list;
        }

        public static PathClass Classify(string path)
        {
            string p = Normalize(path);
            if (p.Length < 3) return PathClass.Other;
            string lower = p.ToLowerInvariant();

            if (lower.Contains(@"\$recycle.bin\") || lower.Contains(@"\recycler\") || lower.Contains(@"\recycled\")) return PathClass.RecycleBin;

            string win = WinDir.ToLowerInvariant();
            if (lower.StartsWith(win + "\\") || lower == win)
            {
                string rest = lower.Substring(Math.Min(lower.Length, win.Length + 1));
                if (rest.StartsWith("temp\\") || rest.StartsWith("tasks\\") || rest.StartsWith("debug\\") || rest.StartsWith("tracing\\") || rest.StartsWith("registration\\") ||
                    rest.StartsWith("system32\\tasks\\") || rest.StartsWith("system32\\spool\\") || rest.StartsWith("system32\\com\\dmp\\") || rest.StartsWith("system32\\microsoft\\crypto\\") ||
                    rest.StartsWith("syswow64\\tasks\\") || rest.StartsWith("serviceprofiles\\") || rest.StartsWith("system32\\config\\systemprofile\\"))
                    return PathClass.WindowsTemp;
                if (rest.StartsWith("system32\\") || rest.StartsWith("syswow64\\") || rest.StartsWith("winsxs\\") || rest.StartsWith("servicing\\") ||
                    rest.StartsWith("systemapps\\") || rest.StartsWith("immersivecontrolpanel\\") || rest.StartsWith("microsoft.net\\") || rest.StartsWith("assembly\\") ||
                    rest.StartsWith("uus\\") || rest.StartsWith("softwaredistribution\\") || rest.StartsWith("installer\\") || rest.StartsWith("sysnative\\") || rest.IndexOf('\\') < 0)
                    return PathClass.WindowsSystem;
                return PathClass.WindowsOther;
            }
            if (lower.StartsWith(ProgramFiles.ToLowerInvariant() + "\\") || lower.StartsWith(ProgramFilesX86.ToLowerInvariant() + "\\") ||
                lower.StartsWith(@"c:\program files\") || lower.StartsWith(@"c:\program files (x86)\")) return PathClass.ProgramFiles;
            string pd = ProgramData.ToLowerInvariant();
            if (lower.StartsWith(pd + "\\") || lower == pd) return PathClass.ProgramData;

            var m = UserRootRx.Match(p);
            if (m.Success)
            {
                string rest = m.Groups["rest"].Value.ToLowerInvariant();
                if (rest.StartsWith(@"appdata\local\temp\") || rest == @"appdata\local\temp") return PathClass.UserTemp;
                if (rest.StartsWith(@"appdata\local\programs\")) return PathClass.UserAppDataLocalPrograms;
                if (rest.StartsWith(@"appdata\local\"))
                    return rest.IndexOf('\\', @"appdata\local\".Length) < 0 ? PathClass.UserAppDataLocalRoot : PathClass.UserAppDataLocal;
                if (rest.StartsWith(@"appdata\roaming\"))
                    return rest.IndexOf('\\', @"appdata\roaming\".Length) < 0 ? PathClass.UserAppDataRoamingRoot : PathClass.UserAppDataRoaming;
                if (rest.StartsWith(@"appdata\locallow\")) return PathClass.UserAppDataLocal;
                if (rest.StartsWith(@"downloads\") || rest == "downloads") return PathClass.UserDownloads;
                if (rest.StartsWith(@"desktop\") || rest.StartsWith(@"documents\") || rest == "desktop" || rest == "documents") return PathClass.UserDesktopDocs;
                return PathClass.UserProfileOther;
            }
            if (lower.StartsWith(@"c:\users\public\") || lower.StartsWith(SystemDrive.ToLowerInvariant() + @"\users\public\")) return PathClass.Public;
            if (lower.Length == 3 || (lower.Length > 3 && lower.LastIndexOf('\\') == 2)) return PathClass.DriveRoot;
            return PathClass.Other;
        }

        /// <summary>Directories any standard user (or malware running as one) can write to.</summary>
        public static bool IsUserWritable(string path)
        {
            switch (Classify(path))
            {
                case PathClass.WindowsTemp:
                case PathClass.ProgramData:
                case PathClass.UserTemp:
                case PathClass.UserAppDataRoamingRoot:
                case PathClass.UserAppDataRoaming:
                case PathClass.UserAppDataLocalRoot:
                case PathClass.UserAppDataLocal:
                case PathClass.UserAppDataLocalPrograms:
                case PathClass.UserDownloads:
                case PathClass.UserDesktopDocs:
                case PathClass.UserProfileOther:
                case PathClass.Public:
                case PathClass.RecycleBin:
                    return true;
                default: return false;
            }
        }

        public static bool IsExecutableExt(string path)
        {
            string e = (Path.GetExtension(path ?? "") ?? "").ToLowerInvariant();
            return e == ".exe" || e == ".dll" || e == ".sys" || e == ".scr" || e == ".cpl" || e == ".ocx" || e == ".com" || e == ".drv" || e == ".efi";
        }

        public static bool IsScriptExt(string path)
        {
            string e = (Path.GetExtension(path ?? "") ?? "").ToLowerInvariant();
            return e == ".bat" || e == ".cmd" || e == ".ps1" || e == ".vbs" || e == ".vbe" || e == ".js" || e == ".jse" || e == ".wsf" || e == ".hta" || e == ".psm1" || e == ".jar";
        }

        static readonly Regex PathTokenRx = new Regex(
            @"(?<p>(?:""[^""]+""|'[^']+'|[A-Za-z]:\\[^\s""'<>|,;]+(?:\s[^\s""'<>|,;:]+)*?(?=\.[A-Za-z0-9]{2,4}(?:[\s""',;]|$))\.[A-Za-z0-9]{2,4}|%[A-Za-z0-9_]+%\\[^\s""'<>|,;]+))",
            RegexOptions.Compiled);

        static readonly string[] ExecExts = { ".exe", ".com", ".bat", ".cmd", ".scr", ".dll", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".msi", ".cpl", ".sys" };

        /// <summary>Best guess of the executable that a command line launches (first token, quoted or not).</summary>
        public static string ExtractExecutable(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return null;
            string s = commandLine.Trim();
            if (s.StartsWith("\""))
            {
                int q = s.IndexOf('"', 1);
                if (q > 1) return ResolveCommand(s.Substring(1, q - 1));
            }
            // unquoted: try the longest prefix that ends with a known extension and exists
            string expanded = s;
            try { expanded = Environment.ExpandEnvironmentVariables(s); } catch { }
            expanded = Normalize(expanded);
            int best = -1; string bestPath = null;
            foreach (var ext in ExecExts)
            {
                int from = 0;
                while (true)
                {
                    int i = expanded.IndexOf(ext, from, StringComparison.OrdinalIgnoreCase);
                    if (i < 0) break;
                    int end = i + ext.Length;
                    if (end == expanded.Length || char.IsWhiteSpace(expanded[end]) || expanded[end] == '"' || expanded[end] == ',')
                    {
                        string cand = expanded.Substring(0, end);
                        string r = ResolveCommand(cand);
                        if (r != null && File.Exists(r) && end > best) { best = end; bestPath = r; }
                    }
                    from = i + 1;
                }
            }
            if (bestPath != null) return bestPath;
            int sp = expanded.IndexOf(' ');
            return ResolveCommand(sp > 0 ? expanded.Substring(0, sp) : expanded);
        }

        /// <summary>Resolves a bare command such as "cmd.exe" via System32 / PATH; returns normalised path otherwise.</summary>
        public static string ResolveCommand(string cmd)
        {
            string p = Normalize(cmd);
            if (p.Length == 0) return null;
            if (p.IndexOf('\\') >= 0 || (p.Length > 1 && p[1] == ':')) return p;
            string name = p;
            if (Path.GetExtension(name).Length == 0) name += ".exe";
            foreach (var dir in new[] { System32, WinDir, SysWow64, System32 + @"\WindowsPowerShell\v1.0", System32 + @"\wbem" })
            {
                string c = Path.Combine(dir, name);
                try { if (File.Exists(c)) return c; } catch { }
            }
            try
            {
                foreach (var d in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
                {
                    if (string.IsNullOrWhiteSpace(d)) continue;
                    string c = Path.Combine(d.Trim().Trim('"'), name);
                    if (File.Exists(c)) return c;
                }
            }
            catch { }
            return p;
        }

        /// <summary>Every file-looking path referenced in a command line (executables, scripts, dlls, configs).</summary>
        public static List<string> ExtractPaths(string commandLine)
        {
            var res = new List<string>();
            if (string.IsNullOrWhiteSpace(commandLine)) return res;
            string exe = ExtractExecutable(commandLine);
            if (!string.IsNullOrEmpty(exe)) res.Add(exe);
            string expanded = commandLine;
            try { expanded = Environment.ExpandEnvironmentVariables(commandLine); } catch { }
            foreach (Match m in PathTokenRx.Matches(expanded))
            {
                string v = Normalize(m.Groups["p"].Value);
                if (v.Length > 3 && v.IndexOf(':') == 1 && !res.Contains(v, StringComparer.OrdinalIgnoreCase)) res.Add(v);
            }
            // rundll32 x.dll,Export
            var rd = Regex.Match(expanded, @"rundll32(?:\.exe)?""?\s+(?<d>""?[^,""]+?\.[a-z]{3}""?)\s*,", RegexOptions.IgnoreCase);
            if (rd.Success) { string v = Normalize(rd.Groups["d"].Value); if (!res.Contains(v, StringComparer.OrdinalIgnoreCase)) res.Add(v); }
            return res;
        }

        public static string SafeFileName(string p) { try { return Path.GetFileName(p ?? ""); } catch { return p ?? ""; } }
    }

    public static class Hashing
    {
        public static string Sha256(string path, long maxBytes = long.MaxValue)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan))
                using (var sha = SHA256.Create())
                {
                    if (fs.Length <= maxBytes) return Hex(sha.ComputeHash(fs));
                    return null;
                }
            }
            catch { return null; }
        }

        public static string Sha256(byte[] data) { using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(data)); }
        public static string Md5(string path) { try { using (var fs = File.OpenRead(path)) using (var h = MD5.Create()) return Hex(h.ComputeHash(fs)); } catch { return null; } }
        public static string Sha1(string path) { try { using (var fs = File.OpenRead(path)) using (var h = SHA1.Create()) return Hex(h.ComputeHash(fs)); } catch { return null; } }

        public static string Hex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }

    public static class Json
    {
        static JavaScriptSerializer Ser() { return new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 200 }; }
        public static object Parse(string json) { return Ser().DeserializeObject(json); }
        public static string Serialize(object o) { return Ser().Serialize(o); }

        public static string Pretty(string json)
        {
            var sb = new StringBuilder(json.Length * 2);
            int indent = 0; bool inStr = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inStr)
                {
                    sb.Append(c);
                    if (c == '\\' && i + 1 < json.Length) { sb.Append(json[++i]); }
                    else if (c == '"') inStr = false;
                    continue;
                }
                switch (c)
                {
                    case '"': inStr = true; sb.Append(c); break;
                    case '{': case '[': sb.Append(c); if (i + 1 < json.Length && (json[i + 1] == '}' || json[i + 1] == ']')) break; indent++; sb.Append('\n').Append(' ', indent * 2); break;
                    case '}': case ']':
                        if (i > 0 && (json[i - 1] == '{' || json[i - 1] == '[')) { sb.Append(c); break; }
                        indent--; sb.Append('\n').Append(' ', Math.Max(0, indent) * 2).Append(c); break;
                    case ',': sb.Append(c).Append('\n').Append(' ', indent * 2); break;
                    case ':': sb.Append(": "); break;
                    default: if (!char.IsWhiteSpace(c)) sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        public static Dictionary<string, object> Obj(object o) { return o as Dictionary<string, object>; }
        public static object[] Arr(object o) { var a = o as object[]; if (a != null) return a; var l = o as System.Collections.ArrayList; return l != null ? l.ToArray() : null; }
        public static string Str(Dictionary<string, object> d, string k, string def = null) { object v; return d != null && d.TryGetValue(k, out v) && v != null ? Convert.ToString(v) : def; }
        public static int Int(Dictionary<string, object> d, string k, int def = 0) { object v; if (d != null && d.TryGetValue(k, out v) && v != null) { try { return Convert.ToInt32(v); } catch { } } return def; }
        public static bool Bool(Dictionary<string, object> d, string k, bool def = false) { object v; if (d != null && d.TryGetValue(k, out v) && v != null) { try { return Convert.ToBoolean(v); } catch { } } return def; }
        public static List<string> Strs(Dictionary<string, object> d, string k)
        {
            var res = new List<string>(); object v;
            if (d != null && d.TryGetValue(k, out v)) { var a = Arr(v); if (a != null) foreach (var x in a) if (x != null) res.Add(Convert.ToString(x)); }
            return res;
        }
    }

    /// <summary>Joins string pieces at run time. The C# compiler folds "a" + "b" into one literal; a method call is not folded, so a security tool can keep words that
    /// its own rules look for (miner names, protocols) out of its own binary - otherwise the tool would flag itself and be flagged by other scanners.</summary>
    public static class Obf
    {
        public static string J(params string[] parts) { return string.Concat(parts); }
    }

    public static class Log
    {
        static readonly List<string> Lines = new List<string>();
        static readonly object Lock = new object();
        public static Action<string> Sink;      // GUI / console subscribers
        public static string FilePath;          // optional

        public static void Info(string m) { Write("[i] " + m); }
        public static void Warn(string m) { Write("[!] " + m); }
        public static void Error(string m) { Write("[x] " + m); }
        static void Write(string m)
        {
            string line = DateTime.Now.ToString("HH:mm:ss") + " " + m;
            lock (Lock)
            {
                Lines.Add(line);
                if (Lines.Count > 20000) Lines.RemoveRange(0, 5000);
                if (FilePath != null) { try { File.AppendAllText(FilePath, line + Environment.NewLine); } catch { } }
            }
            var s = Sink; if (s != null) { try { s(line); } catch { } }
        }
        public static string[] Snapshot() { lock (Lock) return Lines.ToArray(); }
    }

    public static class Fs
    {
        /// <summary>Safe recursive enumeration: skips reparse points and unreadable directories, never throws.</summary>
        public static IEnumerable<string> EnumerateFiles(string root, Func<string, bool> dirFilter, Func<string, bool> fileFilter, int maxDepth, Action<string> onDenied = null)
        {
            var stack = new Stack<KeyValuePair<string, int>>();
            stack.Push(new KeyValuePair<string, int>(root, 0));
            while (stack.Count > 0)
            {
                var cur = stack.Pop();
                string[] files = null, dirs = null;
                try { files = Directory.GetFiles(cur.Key); } catch (Exception e) { if (onDenied != null && e is UnauthorizedAccessException) onDenied(cur.Key); }
                if (files != null)
                    foreach (var f in files)
                    {
                        bool ok = false;
                        try { ok = fileFilter == null || fileFilter(f); } catch { }
                        if (ok) yield return f;
                    }
                if (cur.Value >= maxDepth) continue;
                try { dirs = Directory.GetDirectories(cur.Key); } catch (Exception e) { if (onDenied != null && e is UnauthorizedAccessException) onDenied(cur.Key); }
                if (dirs == null) continue;
                foreach (var d in dirs)
                {
                    try
                    {
                        var attr = File.GetAttributes(d);
                        if ((attr & FileAttributes.ReparsePoint) != 0) continue;
                        if (dirFilter != null && !dirFilter(d)) continue;
                    }
                    catch { continue; }
                    stack.Push(new KeyValuePair<string, int>(d, cur.Value + 1));
                }
            }
        }

        public static bool IsHiddenSystem(string path)
        {
            try { var a = File.GetAttributes(path); return (a & FileAttributes.Hidden) != 0 && (a & FileAttributes.System) != 0; } catch { return false; }
        }
        public static bool IsHidden(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.Hidden) != 0; } catch { return false; }
        }
        public static bool IsReparse(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; } catch { return false; }
        }
    }

    public static class Text
    {
        /// <summary>Fold visually confusable characters so "ReaItek" (capital I) maps to "realtek".</summary>
        public static string FoldConfusables(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            s = s.ToLowerInvariant();
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == 'i' || c == '1' || c == '|' || c == '\u0131') sb.Append('l');
                else if (c == '0') sb.Append('o');
                else if (c == '5') sb.Append('s');
                else if (c == 'r' && i + 1 < s.Length && s[i + 1] == 'n') { sb.Append('m'); i++; }
                else if (c == 'v' && i + 1 < s.Length && s[i + 1] == 'v') { sb.Append('w'); i++; }
                else if (c > 0x7f)
                {
                    // common cyrillic/greek lookalikes
                    switch (c)
                    {
                        case '\u0430': sb.Append('a'); break; case '\u0435': sb.Append('e'); break; case '\u043E': sb.Append('o'); break;
                        case '\u0440': sb.Append('p'); break; case '\u0441': sb.Append('c'); break; case '\u0445': sb.Append('x'); break;
                        case '\u0443': sb.Append('y'); break; case '\u0456': sb.Append('l'); break;
                        default: sb.Append(c); break;
                    }
                }
                else sb.Append(c);
            }
            return sb.ToString();
        }

        public static double Entropy(byte[] data, int count)
        {
            if (count <= 0) return 0;
            var freq = new int[256];
            for (int i = 0; i < count; i++) freq[data[i]]++;
            double e = 0;
            for (int i = 0; i < 256; i++) if (freq[i] > 0) { double p = (double)freq[i] / count; e -= p * Math.Log(p, 2); }
            return e;
        }

        public static string Trunc(string s, int n) { if (s == null) return ""; return s.Length <= n ? s : s.Substring(0, n - 1) + "…"; }
    }
}
