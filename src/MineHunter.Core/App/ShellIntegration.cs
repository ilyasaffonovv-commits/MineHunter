using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MineHunter.Util;

namespace MineHunter
{
    /// <summary>The Explorer right-click entries ("Check with MineHunter", "Deep analysis", "Scan this folder"). They are per-user (HKCU), need no administrator rights to add or remove,
    /// and removing them leaves nothing behind. Only a path is handed to the program; nothing runs from the menu itself.</summary>
    public static class ShellIntegration
    {
        /// <summary>Where the verbs are written; tests point it at a key of their own.</summary>
        public static string ClassesRoot = @"Software\Classes";

        static readonly string[] Targets = { @"*\shell\MineHunter.Check", @"*\shell\MineHunter.Deep", @"Directory\shell\MineHunter.Scan", @"Drive\shell\MineHunter.Scan" };

        static string L(string en, string ru) { return Loc.L(en, ru); }

        public static string Install(string exePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath) || exePath.IndexOf('"') >= 0) return "the program path is not valid";
                Write(Targets[0], L("Check with MineHunter", "Проверить с MineHunter"), exePath, "--check-file \"%1\"");
                Write(Targets[1], L("Deep analysis with MineHunter", "Глубокий анализ MineHunter"), exePath, "--analyze-file \"%1\"");
                Write(Targets[2], L("Scan this folder with MineHunter", "Проверить папку с MineHunter"), exePath, "--scan-folder \"%1\"");
                Write(Targets[3], L("Scan this drive with MineHunter", "Проверить диск с MineHunter"), exePath, "--scan-folder \"%1\"");
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        static void Write(string target, string text, string exe, string args)
        {
            using (var k = Registry.CurrentUser.CreateSubKey(ClassesRoot + "\\" + target))
            {
                k.SetValue("", text); k.SetValue("MUIVerb", text); k.SetValue("Icon", "\"" + exe + "\"");
                using (var c = k.CreateSubKey("command")) c.SetValue("", "\"" + exe + "\" " + args);
            }
        }

        public static string Remove()
        {
            try
            {
                foreach (var t in Targets) Registry.CurrentUser.DeleteSubKeyTree(ClassesRoot + "\\" + t, false);
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static bool IsInstalled()
        {
            try { using (var k = Registry.CurrentUser.OpenSubKey(ClassesRoot + "\\" + Targets[0] + "\\command")) return k != null; } catch { return false; }
        }

        /// <summary>The path a menu verb passes: only a single existing file or folder is accepted, nothing else is ever executed from it.</summary>
        public static string SafePath(string arg)
        {
            if (string.IsNullOrWhiteSpace(arg) || arg.IndexOfAny(new[] { '\0', '\r', '\n', '|', '<', '>' }) >= 0) return null;
            try { string full = Path.GetFullPath(arg.Trim().Trim('"')); return File.Exists(full) || Directory.Exists(full) ? full : null; } catch { return null; }
        }
    }

    /// <summary>The report a person can send by hand when MineHunter flagged something that is fine: what the file is and why it was flagged, with names that identify the PC or the
    /// person removed. Nothing is sent by the program.</summary>
    public static class FalsePositiveReport
    {
        public static string Anonymize(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            // The placeholders are private tokens that are turned into the readable ones at the very end, so that a user called "User" cannot be found again inside "<user>" (or in "Users").
            const string U = "\u0001\u0001", P = "\u0002\u0002";       // control characters only: no name can be found inside them
            string t = text;
            if (!string.IsNullOrEmpty(Environment.UserName)) t = Regex.Replace(t, @"(?<![\p{L}\p{N}_])" + Regex.Escape(Environment.UserName) + @"(?![\p{L}\p{N}_])", U, RegexOptions.IgnoreCase);
            if (!string.IsNullOrEmpty(Environment.MachineName)) t = Regex.Replace(t, @"(?<![\p{L}\p{N}_])" + Regex.Escape(Environment.MachineName) + @"(?![\p{L}\p{N}_])", P, RegexOptions.IgnoreCase);
            t = Regex.Replace(t, @"([A-Za-z]:\\Users\\)[^\\\s""'\u0001\u0002]+", "$1" + U, RegexOptions.IgnoreCase);       // any other user's profile folder
            return t.Replace(U, "<user>").Replace(P, "<pc>");
        }

        public static string Build(FileReport r, string comment)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("MineHunter false-positive report (made on the user's request; nothing was sent)");
            sb.AppendLine("Program version: " + MineHunter.Scanning.AppInfo.Version);
            try { sb.AppendLine("Rules: " + MineHunter.Rules.RulePack.Load().Version); } catch { }
            sb.AppendLine("Windows: " + Environment.OSVersion.VersionString);
            sb.AppendLine();
            sb.AppendLine("File name: " + System.IO.Path.GetFileName(r.Path));
            sb.AppendLine("Folder kind: " + r.Location);
            sb.AppendLine("Size: " + r.Size + " bytes");
            sb.AppendLine("SHA-256: " + r.Sha256);
            sb.AppendLine("Signature: " + r.SignatureText + (r.Publisher != null ? " (" + r.Publisher + ")" : ""));
            sb.AppendLine("Version info: " + r.Company + " | " + r.Product + " | " + r.Description + " | " + r.FileVersion);
            sb.AppendLine("Verdict: " + r.VerdictText + " (score " + r.Score + ")");
            sb.AppendLine("Rules that fired: " + string.Join(", ", r.RulesFired));
            sb.AppendLine("Evidence:");
            foreach (var e in r.Evidence) sb.AppendLine("  " + (e.Weight >= 0 ? "+" : "") + e.Weight + " [" + e.Category + "] " + e.Text);
            if (!string.IsNullOrWhiteSpace(comment)) { sb.AppendLine(); sb.AppendLine("User's comment: " + comment); }
            return Anonymize(sb.ToString());
        }

        public static string Export(FileReport r, string comment, string path)
        {
            try { Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))); File.WriteAllText(path, Build(r, comment), new System.Text.UTF8Encoding(true)); return null; }
            catch (Exception ex) { return ex.Message; }
        }
    }
}
