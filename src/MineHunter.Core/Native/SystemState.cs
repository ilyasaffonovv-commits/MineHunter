using System;
using System.Runtime.InteropServices;

namespace MineHunter.Native
{
    /// <summary>Small questions about the PC that decide whether heavy work should wait: is a full-screen game running, is the laptop on battery, is the user idle.</summary>
    public static class SystemState
    {
        [DllImport("shell32.dll")] static extern int SHQueryUserNotificationState(out int state);

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }
        [DllImport("kernel32.dll")] static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);

        [StructLayout(LayoutKind.Sequential)]
        struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
        [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO p);

        /// <summary>A full-screen program (a game, a video, a presentation) has the screen. Windows tells this to every program that wants to pop up a notification.</summary>
        public static bool FullScreenAppActive()
        {
            try
            {
                int state;
                if (SHQueryUserNotificationState(out state) != 0) return false;
                return state == 2 || state == 3 || state == 4;       // busy (full screen), Direct3D full screen, presentation mode
            }
            catch { return false; }
        }

        public static bool OnBattery()
        {
            try { SYSTEM_POWER_STATUS s; return GetSystemPowerStatus(out s) && s.ACLineStatus == 0; }
            catch { return false; }
        }

        public static bool HasBattery()
        {
            try { SYSTEM_POWER_STATUS s; return GetSystemPowerStatus(out s) && s.BatteryFlag != 128 && s.BatteryFlag != 255; }
            catch { return false; }
        }

        /// <summary>Seconds since the last keyboard or mouse input of the signed-in user (0 when it cannot be read).</summary>
        public static int IdleSeconds()
        {
            try
            {
                var i = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO)) };
                if (!GetLastInputInfo(ref i)) return 0;
                return (int)Math.Max(0, (uint)Environment.TickCount - i.dwTime) / 1000;
            }
            catch { return 0; }
        }
    }
}
