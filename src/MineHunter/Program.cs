using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
            try { return Run(args); }
            catch (Exception ex) when (LaunchGuard.IsMissingOwnFile(ex)) { return LaunchGuard.ShowGui(); }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static int Run(string[] args)
        {
            var cfg = Bootstrap.Init();
            if (Gui.GuiApp.IsGuiInvocation(args)) return Gui.GuiApp.Run(cfg, args);
            // WinExe has no console of its own: attach to the parent's console (or create one) unless output is redirected
            if (GetStdHandle(-11) == IntPtr.Zero || !AttachConsole(-1)) { if (GetStdHandle(-11) == IntPtr.Zero) AllocConsole(); }
            return Cli.Run(args, cfg);
        }
    }
}
