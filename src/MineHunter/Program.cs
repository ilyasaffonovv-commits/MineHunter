using System;
using System.Runtime.InteropServices;
using MineHunter.Update;

namespace MineHunter
{
    public static class Program
    {
        [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);
        [DllImport("kernel32.dll")] static extern bool AllocConsole();
        [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int h);

        [STAThread]
        public static int Main(string[] args)
        {
            AppConfig cfg = Bootstrap.Init();
            if (Gui.GuiApp.IsGuiInvocation(args)) return Gui.GuiApp.Run(cfg, args);
            // WinExe has no console of its own: attach to the parent's console (or create one) unless output is redirected
            if (GetStdHandle(-11) == IntPtr.Zero || !AttachConsole(-1)) { if (GetStdHandle(-11) == IntPtr.Zero) AllocConsole(); }
            return Cli.Run(args, cfg);
        }
    }
}
