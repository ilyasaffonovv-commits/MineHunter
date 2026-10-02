using System;
using MineHunter.Update;

namespace MineHunter
{
    /// <summary>The console flavour: waits for completion, writes to stdout, returns an exit code (scripts, CI, ssh).</summary>
    public static class Program
    {
        public static int Main(string[] args)
        {
            AppConfig cfg = Bootstrap.Init();
            if (args.Length == 0 || args[0].Equals("--gui", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine(Cli.Help());
                return 0;
            }
            return Cli.Run(args, cfg);
        }
    }
}
