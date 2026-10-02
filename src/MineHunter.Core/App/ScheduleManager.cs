using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using MineHunter.Util;

namespace MineHunter
{
    public sealed class TaskStatus
    {
        public bool Exists; public DateTime? NextRun, LastRun; public int LastResult; public string State = "";
    }

    /// <summary>Scheduled scans and the tray program's start at sign-in, both as ordinary Windows Task Scheduler tasks in the folder "MineHunter" (you can see them in
    /// taskschd.msc). Nothing runs in the background of its own: when the task fires, Windows starts the program, the scan runs, the program ends.</summary>
    public static class ScheduleManager
    {
        public const string Folder = "MineHunter";
        public const string ScanTaskName = "Scheduled scan";
        public const string TrayTaskName = "Tray";
        const string Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        // ------------------------------------------------------------------------------------------------ XML
        static string X(string s) { return SecurityElement.Escape(s ?? ""); }

        /// <summary>The first start time for the trigger: the chosen time of day, today if it has not passed yet, otherwise tomorrow.</summary>
        public static DateTime FirstStart(Settings s, DateTime now)
        {
            TimeSpan t; if (!TimeSpan.TryParseExact(s.ScheduleTime, @"hh\:mm", null, out t)) t = new TimeSpan(13, 0, 0);
            var d = now.Date + t;
            if (d <= now) d = d.AddDays(1);
            return d;
        }

        public static string BuildScanXml(Settings s, string exePath, string userSid, DateTime now)
        {
            string args = "--scheduled " + (s.ScheduleMode == "Full" ? "full" : s.ScheduleMode == "Custom" ? "custom" : "quick");
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.2\" xmlns=\"" + Ns + "\">\n");
            sb.Append("  <RegistrationInfo><Author>MineHunter</Author><Description>MineHunter scheduled scan (" + X(s.ScheduleMode) + "). Created by the program; delete it in the Schedule page or here.</Description></RegistrationInfo>\n");
            string start = FirstStart(s, now).ToString("yyyy-MM-ddTHH:mm:ss");
            sb.Append("  <Triggers>\n    <CalendarTrigger>\n      <StartBoundary>" + start + "</StartBoundary>\n      <Enabled>true</Enabled>\n");
            switch (s.ScheduleEvery)
            {
                case "Every3Days": sb.Append("      <ScheduleByDay><DaysInterval>3</DaysInterval></ScheduleByDay>\n"); break;
                case "CustomDays": sb.Append("      <ScheduleByDay><DaysInterval>" + Math.Max(1, s.ScheduleCustomDays) + "</DaysInterval></ScheduleByDay>\n"); break;
                case "Weekly": sb.Append("      <ScheduleByWeek><DaysOfWeek><" + s.ScheduleDayOfWeek + " /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>\n"); break;
                case "Monthly":
                    sb.Append("      <ScheduleByMonth><DaysOfMonth><Day>" + Math.Max(1, Math.Min(28, s.ScheduleDayOfMonth)) + "</Day></DaysOfMonth><Months><January /><February /><March /><April /><May /><June /><July /><August /><September /><October /><November /><December /></Months></ScheduleByMonth>\n"); break;
                default: sb.Append("      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\n"); break;
            }
            sb.Append("    </CalendarTrigger>\n  </Triggers>\n");
            sb.Append(PrincipalXml(userSid));
            sb.Append("  <Settings>\n");
            sb.Append("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n");
            sb.Append("    <DisallowStartIfOnBatteries>" + (s.ScheduleNotOnBattery ? "true" : "false") + "</DisallowStartIfOnBatteries>\n");
            sb.Append("    <StopIfGoingOnBatteries>" + (s.ScheduleStopOnBattery ? "true" : "false") + "</StopIfGoingOnBatteries>\n");
            sb.Append("    <AllowHardTerminate>true</AllowHardTerminate>\n");
            sb.Append("    <StartWhenAvailable>" + (s.ScheduleRunMissed ? "true" : "false") + "</StartWhenAvailable>\n");
            sb.Append("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n");
            sb.Append("    <IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT2H</WaitTimeout><StopOnIdleEnd>" + (s.ScheduleOnlyIdle ? "true" : "false") + "</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\n");
            sb.Append("    <AllowStartOnDemand>true</AllowStartOnDemand>\n    <Enabled>true</Enabled>\n    <Hidden>false</Hidden>\n");
            sb.Append("    <RunOnlyIfIdle>" + (s.ScheduleOnlyIdle ? "true" : "false") + "</RunOnlyIfIdle>\n");
            sb.Append("    <WakeToRun>false</WakeToRun>\n    <ExecutionTimeLimit>PT" + (s.ScheduleMode == "Full" ? "12" : "2") + "H</ExecutionTimeLimit>\n    <Priority>7</Priority>\n");
            sb.Append("  </Settings>\n");
            sb.Append("  <Actions Context=\"Author\"><Exec><Command>" + X(exePath) + "</Command><Arguments>" + X(args) + "</Arguments></Exec></Actions>\n</Task>\n");
            return sb.ToString();
        }

        public static string BuildTrayXml(string exePath, string userSid)
        {
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.2\" xmlns=\"" + Ns + "\">\n");
            sb.Append("  <RegistrationInfo><Author>MineHunter</Author><Description>Starts the MineHunter tray program (real-time protection) when you sign in.</Description></RegistrationInfo>\n");
            sb.Append("  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + X(userSid) + "</UserId><Delay>PT20S</Delay></LogonTrigger></Triggers>\n");
            sb.Append(PrincipalXml(userSid));
            sb.Append("  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
            sb.Append("<AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle>");
            sb.Append("<WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>\n");
            sb.Append("  <Actions Context=\"Author\"><Exec><Command>" + X(exePath) + "</Command><Arguments>--tray</Arguments></Exec></Actions>\n</Task>\n");
            return sb.ToString();
        }

        static string PrincipalXml(string sid)
        {
            // the signed-in user, with the highest rights that user has: no Windows prompt at start, and the notification shows on the user's desktop
            return "  <Principals><Principal id=\"Author\"><UserId>" + X(sid) + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\n";
        }

        public static string CurrentUserSid()
        {
            try { return System.Security.Principal.WindowsIdentity.GetCurrent().User.Value; } catch { return null; }
        }

        // ------------------------------------------------------------------------------------------------ Task Scheduler (COM, late bound)
        static dynamic Connect()
        {
            Type t = Type.GetTypeFromProgID("Schedule.Service");
            if (t == null) throw new InvalidOperationException("Windows Task Scheduler is not available");
            dynamic svc = Activator.CreateInstance(t);
            svc.Connect();
            return svc;
        }

        static dynamic GetOrCreateFolder(dynamic svc)
        {
            dynamic root = svc.GetFolder("\\");
            try { return root.GetFolder("\\" + Folder); }
            catch { return root.CreateFolder(Folder); }
        }

        /// <summary>Creates or replaces a task. Returns null when it worked, otherwise a short reason.</summary>
        public static string Register(string taskName, string xml)
        {
            try
            {
                dynamic svc = Connect();
                dynamic f = GetOrCreateFolder(svc);
                f.RegisterTask(taskName, xml, 6, null, null, 3, null);     // TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static string Delete(string taskName)
        {
            try
            {
                dynamic svc = Connect();
                dynamic f;
                try { f = svc.GetFolder("\\" + Folder); } catch { return null; }
                try { f.DeleteTask(taskName, 0); } catch (Exception ex) { if (Query(taskName).Exists) return ex.Message; }
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static TaskStatus Query(string taskName)
        {
            var st = new TaskStatus();
            try
            {
                dynamic svc = Connect();
                dynamic f = svc.GetFolder("\\" + Folder);
                dynamic task = f.GetTask(taskName);
                st.Exists = true;
                try { DateTime n = task.NextRunTime; if (n.Year > 1999) st.NextRun = n; } catch { }
                try { DateTime l = task.LastRunTime; if (l.Year > 1999) st.LastRun = l; } catch { }
                try { st.LastResult = (int)task.LastTaskResult; } catch { }
                try { int state = (int)task.State; st.State = state == 1 ? "Disabled" : state == 2 ? "Queued" : state == 3 ? "Ready" : state == 4 ? "Running" : "Unknown"; } catch { }
            }
            catch { }
            return st;
        }

        public static string ProgramPath()
        {
            // the main program is the one that starts scheduled scans and the tray
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            string main = Path.Combine(dir, "MineHunter.exe");
            return File.Exists(main) ? main : System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
        }

        /// <summary>Applies the schedule settings: creates/updates the scheduled-scan task when enabled, removes it when not; same for the tray task.</summary>
        public static string Apply(Settings s)
        {
            string sid = CurrentUserSid(); string exe = ProgramPath();
            if (sid == null) return "could not determine the user";
            string err = null;
            if (s.ScheduleEnabled) err = Register(ScanTaskName, BuildScanXml(s, exe, sid, DateTime.Now));
            else err = Delete(ScanTaskName);
            string err2 = s.StartTrayAtLogon ? Register(TrayTaskName, BuildTrayXml(exe, sid)) : Delete(TrayTaskName);
            return err ?? err2;
        }

        /// <summary>The scheduled scan is overdue when the last finished scan of that kind is older than the interval (used at start-up to run a missed scan).</summary>
        public static bool IsOverdue(Settings s, DateTime now, DateTime? lastScan)
        {
            if (!s.ScheduleEnabled || !s.ScheduleRunMissed) return false;
            TimeSpan every = s.ScheduleEvery == "Every3Days" ? TimeSpan.FromDays(3) : s.ScheduleEvery == "CustomDays" ? TimeSpan.FromDays(Math.Max(1, s.ScheduleCustomDays)) : s.ScheduleEvery == "Weekly" ? TimeSpan.FromDays(7) : s.ScheduleEvery == "Monthly" ? TimeSpan.FromDays(30) : TimeSpan.FromDays(1);
            if (lastScan == null) return true;
            return now - lastScan.Value > every + TimeSpan.FromHours(2);
        }

        /// <summary>The next time the scheduled scan is due according to the settings (computed here; the Task Scheduler's own value is in Query).</summary>
        public static DateTime NextDue(Settings s, DateTime now)
        {
            var first = FirstStart(s, now);
            switch (s.ScheduleEvery)
            {
                case "Weekly":
                    {
                        var d = first; DayOfWeek w; Enum.TryParse(s.ScheduleDayOfWeek, out w);
                        while (d.DayOfWeek != w) d = d.AddDays(1);
                        return d;
                    }
                case "Monthly":
                    {
                        var d = new DateTime(first.Year, first.Month, Math.Min(28, s.ScheduleDayOfMonth)) + first.TimeOfDay;
                        if (d <= now) d = d.AddMonths(1);
                        return d;
                    }
                default: return first;
            }
        }
    }
}
