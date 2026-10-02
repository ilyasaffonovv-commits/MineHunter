using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using MineHunter.Model;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Guards
{
    /// <summary>Asks the antivirus engine that is registered with Windows (Defender or another one) about a piece of script text, through AMSI. MineHunter is only a client of
    /// this interface: it hands the text over and reads the answer. With no antivirus registered the answer is simply "nothing found".</summary>
    public static class Amsi
    {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)] static extern int AmsiInitialize(string appName, out IntPtr ctx);
        [DllImport("amsi.dll")] static extern void AmsiUninitialize(IntPtr ctx);
        [DllImport("amsi.dll")] static extern int AmsiOpenSession(IntPtr ctx, out IntPtr session);
        [DllImport("amsi.dll")] static extern void AmsiCloseSession(IntPtr ctx, IntPtr session);
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)] static extern int AmsiScanBuffer(IntPtr ctx, byte[] buffer, uint length, string contentName, IntPtr session, out int result);

        /// <summary>0 = nothing found, 1 = blocked by the administrator's policy, 2 = detected as malicious, -1 = AMSI is not available.</summary>
        public static int Scan(string content, string name)
        {
            IntPtr ctx = IntPtr.Zero, session = IntPtr.Zero;
            try
            {
                if (AmsiInitialize("MineHunter", out ctx) != 0) return -1;
                if (AmsiOpenSession(ctx, out session) != 0) return -1;
                var bytes = Encoding.Unicode.GetBytes(content.Length > 200000 ? content.Substring(0, 200000) : content);
                int res;
                if (AmsiScanBuffer(ctx, bytes, (uint)bytes.Length, name ?? "script", session, out res) != 0) return -1;
                if (res >= 32768) return 2;                  // AMSI_RESULT_DETECTED
                if (res >= 16384 && res <= 20479) return 1;  // blocked by admin
                return 0;
            }
            catch { return -1; }
            finally { try { if (session != IntPtr.Zero) AmsiCloseSession(ctx, session); if (ctx != IntPtr.Zero) AmsiUninitialize(ctx); } catch { } }
        }
    }

    public sealed class ScriptResult
    {
        public List<Signal> Signals = new List<Signal>(); public int AmsiResult = -2; public string Decoded;
    }

    /// <summary>Reads a script (PowerShell, VBScript, JScript, HTA, batch) as text and looks for what droppers and loaders do. Single ordinary actions do not count: a script that
    /// downloads a file with Invoke-WebRequest is normal, one that downloads text, decodes a hidden payload and runs it in memory is not.</summary>
    public static class ScriptAnalyzer
    {
        static string L(string en, string ru) { return Loc.L(en, ru); }

        static readonly Regex B64 = new Regex(@"[A-Za-z0-9+/]{120,}={0,2}", RegexOptions.Compiled);
        static readonly Regex EncodedCmd = new Regex(@"-(e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{40,})", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static ScriptResult Analyze(string text, string fileName, RulePack rules, bool useAmsi, string actor)
        {
            var r = new ScriptResult();
            if (string.IsNullOrWhiteSpace(text)) return r;
            if (text.Length > 3 * 1024 * 1024) text = text.Substring(0, 3 * 1024 * 1024);
            string ext = (Path.GetExtension(fileName ?? "") ?? "").ToLowerInvariant();
            Action<EvidenceCategory, int, string, string, bool> add = (cat, w, rule, t, def) => r.Signals.Add(new Signal { Actor = actor, Category = cat, Weight = w, Rule = rule, Text = t, Definitive = def });

            // 1. decode what is hidden in a -EncodedCommand and look at the inside as well
            string decoded = null;
            var em = EncodedCmd.Match(text);
            if (em.Success)
            {
                try { decoded = Encoding.Unicode.GetString(Convert.FromBase64String(em.Groups[2].Value)); r.Decoded = decoded; }
                catch { }
            }
            string all = decoded != null ? text + "\n" + decoded : text;
            string low = all.ToLowerInvariant();

            // 2. the command-line rules of the rule pack apply to scripts as well
            if (rules != null)
                foreach (var cr in rules.CmdRules)
                    if (cr.Rx.IsMatch(all)) add(FileIntelCat(cr.Category), cr.Weight, "SCRIPT." + cr.Id, cr.Text, cr.Definitive);

            // 3. script specific patterns
            bool download = low.Contains("downloadstring") || low.Contains("downloadfile") || low.Contains("invoke-webrequest") || low.Contains("invoke-restmethod") || low.Contains("net.webclient") || low.Contains("xmlhttp") || low.Contains("urldownloadtofile") || low.Contains("bitsadmin") || low.Contains("start-bitstransfer");
            bool exec = Regex.IsMatch(low, @"\b(iex|invoke-expression)\b") || low.Contains("start-process") || low.Contains("wscript.shell") || low.Contains(".run(") || low.Contains("shellexecute") || low.Contains("cmd /c") || low.Contains("cmd.exe /c") || low.Contains("[reflection.assembly]::load") || low.Contains("eval(") || low.Contains("execute(");
            bool hidden = Regex.IsMatch(low, @"-w(indowstyle)?\s+h(idden)?|-nop\b|-noprofile\b.*-w") || low.Contains("vbhide") || low.Contains("windowstyle=0") || low.Contains(".run(") && Regex.IsMatch(low, @",\s*0\s*[,)]");
            bool decode = low.Contains("frombase64string") || low.Contains("atob(") || low.Contains("base64decode") || low.Contains("certutil") && low.Contains("-decode");
            bool memory = low.Contains("[reflection.assembly]::load") || low.Contains("virtualalloc") || low.Contains("createthread") || low.Contains("add-type") && low.Contains("dllimport") && low.Contains("kernel32");
            if (download && exec && (decode || hidden || memory)) add(EvidenceCategory.Behavior, 40, "SCRIPT.DROPPER", L("downloads something, hides it or decodes it, and runs it", "скачивает что-то, прячет или раскодирует и запускает"), false);
            else if (download && decode && exec) add(EvidenceCategory.Behavior, 30, "SCRIPT.DOWNLOAD_DECODE_EXEC", L("downloads, decodes and runs code", "скачивает, раскодирует и запускает код"), false);
            if (memory && decode) add(EvidenceCategory.Behavior, 30, "SCRIPT.IN_MEMORY_PAYLOAD", L("decodes a payload and loads it into memory instead of a file", "раскодирует полезную нагрузку и загружает её в память, а не в файл"), false);
            if (low.Contains("amsiutils") || low.Contains("amsiinitfailed") || low.Contains("amsicontext")) add(EvidenceCategory.Tamper, 35, "SCRIPT.AMSI_BYPASS", L("tries to switch off the script scanning interface (AMSI)", "пытается отключить интерфейс проверки скриптов (AMSI)"), false);
            if (low.Contains("vssadmin") && low.Contains("delete") && low.Contains("shadow") || low.Contains("wbadmin") && low.Contains("delete") || low.Contains("bcdedit") && low.Contains("recoveryenabled") && low.Contains("no")) add(EvidenceCategory.Tamper, 50, "SCRIPT.DELETE_BACKUPS", L("deletes shadow copies / backups (what ransomware does first)", "удаляет теневые копии / резервные копии (то, с чего начинают шифровальщики)"), false);
            if (ext == ".vbs" || ext == ".vbe" || ext == ".js" || ext == ".jse" || ext == ".wsf" || ext == ".hta")
            {
                if (low.Contains("adodb.stream") && (low.Contains("xmlhttp") || low.Contains("winhttp"))) add(EvidenceCategory.Behavior, 35, "SCRIPT.DOWNLOAD_TO_DISK", L("downloads a file and writes it to disk (a typical dropper)", "скачивает файл и записывает его на диск (типичный дроппер)"), false);
                int chr = Regex.Matches(low, @"\bchr\w?\(").Count + Regex.Matches(low, @"string\.fromcharcode").Count;
                if (chr > 40) add(EvidenceCategory.Content, 20, "SCRIPT.OBFUSCATED_CHARCODES", L("the text is built from character codes (obfuscation)", "текст собирается из кодов символов (обфускация)"), false);
            }
            if (ext == ".ps1" || ext == ".psm1" || low.Contains("powershell"))
            {
                int ticks = Regex.Matches(all, @"\w`\w").Count, concat = Regex.Matches(all, @"'\s*\+\s*'").Count, chars = Regex.Matches(low, @"\[char\]\s*(0x)?\d+").Count;
                if (ticks > 25 || concat > 40 || chars > 30) add(EvidenceCategory.Content, 18, "SCRIPT.OBFUSCATED", L("heavily obfuscated (broken-up words, character codes)", "сильно запутан (разбитые слова, коды символов)"), false);
                var big = B64.Match(all);
                if (big.Success && big.Length > 2000 && decode) add(EvidenceCategory.Content, 18, "SCRIPT.BIG_PAYLOAD", L("carries a large encoded block that it decodes", "несёт большой закодированный блок и раскодирует его"), false);
            }
            if (hidden && download && !exec) add(EvidenceCategory.Behavior, 12, "SCRIPT.HIDDEN_DOWNLOAD", L("a hidden window plus a download", "скрытое окно и загрузка"), false);

            // 4. the registered antivirus engine's own opinion
            if (useAmsi)
            {
                int a = Amsi.Scan(all, fileName);
                r.AmsiResult = a;
                if (a == 2) add(EvidenceCategory.Reputation, 70, "SCRIPT.AMSI_DETECTED", L("the antivirus engine installed in Windows (through AMSI) says this script is malicious", "антивирусный движок Windows (через AMSI) считает этот скрипт вредоносным"), true);
            }
            return r;
        }

        static EvidenceCategory FileIntelCat(string c) { EvidenceCategory ec; return Enum.TryParse(c, true, out ec) ? ec : EvidenceCategory.Content; }

        /// <summary>The script a command line runs, if it is a small local script file.</summary>
        public static string ScriptPathOf(string cmd)
        {
            if (string.IsNullOrEmpty(cmd)) return null;
            foreach (var p in PathUtil.ExtractPaths(cmd))
            {
                string e = Path.GetExtension(p).ToLowerInvariant();
                if ((e == ".ps1" || e == ".vbs" || e == ".vbe" || e == ".js" || e == ".jse" || e == ".wsf" || e == ".hta" || e == ".bat" || e == ".cmd") && File.Exists(p))
                {
                    try { if (new FileInfo(p).Length <= 2 * 1024 * 1024) return p; } catch { }
                }
            }
            return null;
        }
    }

    /// <summary>Script Guard: when a script host starts a script from disk, or a script file appears in a place programs drop things, the text is read and judged.</summary>
    public sealed class ScriptGuard : IGuard
    {
        GuardContext g; GuardState state = GuardState.Off; string detail = "";
        public string Name { get { return "script"; } }
        public string Title { get { return Loc.L("Script Guard", "Контроль скриптов"); } }
        public GuardStatus Status { get { return new GuardStatus { Name = Name, Title = Title, State = state, Detail = detail }; } }

        public void Start(GuardContext ctx) { g = ctx; state = GuardState.On; detail = Loc.L("reads scripts that are started or dropped (PowerShell, VBScript, JScript, HTA, batch)", "читает запускаемые и подброшенные скрипты (PowerShell, VBScript, JScript, HTA, bat)"); }
        public void Stop() { state = GuardState.Off; }

        /// <summary>Called by the other guards with a script path; returns signals about it (empty for an ordinary script).</summary>
        public ScriptResult Check(string scriptPath, string actor)
        {
            try
            {
                var fi = new FileInfo(scriptPath);
                if (!fi.Exists || fi.Length > 3 * 1024 * 1024) return new ScriptResult();
                string text = File.ReadAllText(scriptPath);
                return ScriptAnalyzer.Analyze(text, scriptPath, g.Rules, true, actor ?? PathUtil.Normalize(scriptPath));
            }
            catch { return new ScriptResult(); }
        }
    }
}
