using System;
using System.IO;
using MineHunter.Rules;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter
{
    /// <summary>Start-up work that every MineHunter program (main window, quick scan, full scan, command line) does the same way.</summary>
    public static class Bootstrap
    {
        static bool _done;
        static AppConfig _cfg;

        public static AppConfig Init()
        {
            if (_done) return _cfg;
            _done = true;
            AppDomain.CurrentDomain.UnhandledException += (s, e) => CrashLog("unhandled", e.ExceptionObject);
            _cfg = AppConfig.Load();
            Loc.Init(_cfg.Language);
            try { Directory.CreateDirectory(RulePack.DataDir); HardenDataDir(); Log.FilePath = Path.Combine(RulePack.DataDir, "minehunter.log"); TrimLog(Log.FilePath); } catch { }
            // a cleanup that was killed (or lost power) may have left programs frozen: let them go again before anything else
            try { MineHunter.Remediation.RemediationEngine.RecoverInterrupted(); } catch { }
            return _cfg;
        }

        public static void CrashLog(string where, object ex)
        {
            try
            {
                Directory.CreateDirectory(RulePack.DataDir);
                File.AppendAllText(Path.Combine(RulePack.DataDir, "crash.log"), DateTime.Now.ToString("o") + " " + where + "\n" + ex + "\n\n");
            }
            catch { }
        }

        /// <summary>Self-protection: the data folder (quarantine, allow-list, rule updates, config) is writable only by SYSTEM and Administrators,
        /// so a non-elevated program cannot whitelist itself, plant rule files or tamper with quarantined samples.</summary>
        public static void HardenDataDir()
        {
            try
            {
                string dir = RulePack.DataDir;
                if (!string.IsNullOrEmpty(RulePack.TestDataDirOverride)) return;
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
