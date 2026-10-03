using System;
using System.IO;
using System.Runtime.InteropServices;

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
