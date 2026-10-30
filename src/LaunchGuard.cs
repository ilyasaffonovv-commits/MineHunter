using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace MineHunter
{
    /// <summary>Shared by the four programs (linked into each project). The small EXE needs MineHunter.Core.dll from the components folder. When someone opens only the EXE
    /// (from the preview of a zip file, or copied alone to the desktop) .NET would show a crash window with a technical message. This turns that into one clear sentence.</summary>
    static class LaunchGuard
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

        public static bool IsMissingOwnFile(Exception ex)
        {
            var f = ex as FileNotFoundException;
            return f != null && f.FileName != null && f.FileName.StartsWith("MineHunter.", StringComparison.OrdinalIgnoreCase);
        }

        public const string Message =
            "MineHunter не нашёл свои файлы (папку components). Распакуйте весь архив целиком и запускайте программу из распакованной папки, а не из окна архива.\r\n\r\n" +
            "MineHunter cannot find its files (the components folder). Unpack the whole archive and run the program from the unpacked folder, not from inside the archive window.";

        static string Field(string json, string name)
        {
            var m = Regex.Match(json ?? "", "\"" + name + @"""\s*:\s*""((?:[^""\\]|\\.)*)""");
            return m.Success ? m.Groups[1].Value.Replace(@"\\", @"\").Replace(@"\""", "\"") : null;
        }

        /// <summary>Runs before anything from the components folder is loaded. If an update was cut short (power loss, the helper killed in the middle of the copy), the helper
        /// left a marker; this puts the saved files back by starting the helper in its rollback mode, one attempt, and ends this start (the helper starts the program again).
        /// Returns true when the program must exit now.</summary>
        public static bool RecoverInterruptedUpdate()
        {
            try
            {
                string updates = Path.Combine(Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData", "MineHunter", "updates");
                string marker = Path.Combine(updates, "inprogress.json");
                if (!File.Exists(marker)) return false;
                if (Process.GetProcessesByName("MineHunter.UpdateHelper").Length > 0) return false;   // an update is running right now
                string text = File.ReadAllText(marker);
                string dst = Field(text, "dst"), backup = Field(text, "backup");
                string here = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
                if (string.IsNullOrEmpty(dst) || string.IsNullOrEmpty(backup) || !Directory.Exists(backup)) return false;
                if (!string.Equals(Path.GetFullPath(dst).TrimEnd('\\'), Path.GetFullPath(here), StringComparison.OrdinalIgnoreCase)) return false;   // somebody else's installation
                File.Delete(marker);   // one attempt only: a failing restore must not lock the user out of the program on every start
                string helperSrc = Path.Combine(here, "components", "MineHunter.UpdateHelper.exe");
                if (!File.Exists(helperSrc)) helperSrc = Path.Combine(backup, "components", "MineHunter.UpdateHelper.exe");
                if (!File.Exists(helperSrc)) return false;
                string tmp = Path.Combine(Path.GetTempPath(), "mh-rec-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                Directory.CreateDirectory(tmp);
                string helper = Path.Combine(tmp, "MineHunter.UpdateHelper.exe");
                File.Copy(helperSrc, helper, true);
                if (File.Exists(helperSrc + ".config")) File.Copy(helperSrc + ".config", helper + ".config", true);
                string exe = Process.GetCurrentProcess().MainModule.FileName;
                string args = "rollback --interrupted --dst \"" + here + "\" --backup \"" + backup + "\" --result \"" + Path.Combine(updates, "result.json") + "\" --from \"" + (Field(text, "from") ?? "") + "\" --to \"" + (Field(text, "to") ?? "") + "\" --pid " + Process.GetCurrentProcess().Id + " --cleanup \"" + tmp + "\" --restart \"" + exe + "\"";
                Process.Start(new ProcessStartInfo(helper, args) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = tmp });
                return true;
            }
            catch { return false; }
        }

        public static int ShowGui()
        {
            try { MessageBoxW(IntPtr.Zero, Message, "MineHunter", 0x10); } catch { }
            return 3;
        }

        public static int ShowConsole()
        {
            Console.Error.WriteLine(Message);
            return 3;
        }
    }
}
