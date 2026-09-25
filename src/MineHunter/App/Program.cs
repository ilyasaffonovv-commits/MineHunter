using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

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
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try
                {
                    Directory.CreateDirectory(RulePack.DataDir);
                    File.AppendAllText(Path.Combine(RulePack.DataDir, "crash.log"), DateTime.Now.ToString("o") + "\n" + e.ExceptionObject + "\n\n");
                }
                catch { }
            };
            var cfg = AppConfig.Load();
            Loc.Init(cfg.Language);
            try { Directory.CreateDirectory(RulePack.DataDir); HardenDataDir(); Log.FilePath = Path.Combine(RulePack.DataDir, "minehunter.log"); TrimLog(Log.FilePath); } catch { }

            bool gui = args.Length == 0 || args[0].Equals("--gui", StringComparison.OrdinalIgnoreCase);
            if (!gui)
            {
                // WinExe has no console of its own: attach to the parent's console (or create one) unless output is redirected
                if (GetStdHandle(-11) == IntPtr.Zero || !AttachConsole(-1)) { if (GetStdHandle(-11) == IntPtr.Zero) AllocConsole(); }
                return Cli.Run(args, cfg);
            }
            return Gui.GuiApp.Run(cfg, args.Skip(1).ToArray());
        }

        /// <summary>Self-protection: the data folder (quarantine, allow-list, rule updates, config) is writable only by SYSTEM and Administrators,
        /// so a non-elevated program cannot whitelist itself, plant rule files or tamper with quarantined samples.</summary>
        static void HardenDataDir()
        {
            try
            {
                string dir = RulePack.DataDir;
                if (Environment.GetEnvironmentVariable("MINEHUNTER_DATA_DIR") != null) return;
                var admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                var users = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                if (!new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)) return;
                var di = Directory.CreateDirectory(dir);
                var sec = new System.Security.AccessControl.DirectorySecurity();
                sec.SetAccessRuleProtection(true, false);
                var inh = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(admins, System.Security.AccessControl.FileSystemRights.FullControl, inh, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(system, System.Security.AccessControl.FileSystemRights.FullControl, inh, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(users, System.Security.AccessControl.FileSystemRights.ReadAndExecute, inh, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                sec.SetOwner(admins);
                di.SetAccessControl(sec);
            }
            catch (Exception ex) { Log.Warn("data folder hardening: " + ex.Message); }
        }

        static void TrimLog(string path)
        {
            try { var fi = new FileInfo(path); if (fi.Exists && fi.Length > 2 * 1024 * 1024) File.Delete(path); } catch { }
        }
    }
}
