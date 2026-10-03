using System;
using System.Runtime.CompilerServices;

namespace MineHunter
{
    /// <summary>The console flavour: waits for completion, writes to stdout, returns an exit code (scripts, CI, ssh).</summary>
    public static class Program
    {
        public static int Main(string[] args)
        {
            try { return Run(args); }
            catch (Exception ex) when (LaunchGuard.IsMissingOwnFile(ex)) { return LaunchGuard.ShowConsole(); }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static int Run(string[] args)
        {
            var cfg = Bootstrap.Init();
            if (args.Length == 0 || args[0].Equals("--gui", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine(Cli.FullHelp());
                return 0;
            }
            return Cli.Run(args, cfg);
        }
    }
}
