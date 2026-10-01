using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>One user's registry hive: the signed-in user's own (HKCU), another signed-in user's (loaded under HKEY_USERS) or the file NTUSER.DAT of a user who is not
    /// signed in, which is mounted for the few moments it takes to read it.</summary>
    public sealed class UserHive
    {
        public string Label;        // "HKCU", "HKU\S-1-5-21-...", "HKUOFF\S-1-5-21-..." (the label is what is stored in an entity so that it can be reached again for removal)
        public RegistryKey Root;
    }

    /// <summary>All user registry hives of this computer. A miner that settled in the account of someone who is not signed in at the moment would otherwise
    /// never be seen, because only the hive of the signed-in user is open.</summary>
    public static class UserHives
    {
        // the predefined key handles are sign-extended on 64-bit Windows: 0x80000003 as an int becomes 0xFFFFFFFF80000003
        static readonly UIntPtr HKEY_USERS = new UIntPtr(unchecked((ulong)(long)unchecked((int)0x80000003)));
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegLoadKey(UIntPtr hKey, string subKey, string file);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegUnLoadKey(UIntPtr hKey, string subKey);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string system, string name, out long luid);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state, int len, IntPtr prev, IntPtr retLen);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        struct TokenPrivileges { public uint Count; public long Luid; public uint Attributes; }

        /// <summary>label -> NTUSER.DAT, for the self test (a real profile is found through the ProfileList).</summary>
        internal static readonly Dictionary<string, string> TestDat = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        static readonly object Gate = new object();
        static readonly Dictionary<string, string> Mounted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);       // label -> name under HKEY_USERS
        static readonly Dictionary<string, RegistryKey> MountedKeys = new Dictionary<string, RegistryKey>(StringComparer.OrdinalIgnoreCase);

        static bool EnablePrivilege(string name)
        {
            IntPtr tok = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out tok)) return false;     // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
                long luid; if (!LookupPrivilegeValue(null, name, out luid)) return false;
                var tp = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 2 };            // SE_PRIVILEGE_ENABLED
                AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return Marshal.GetLastWin32Error() == 0;
            }
            catch { return false; }
            finally { if (tok != IntPtr.Zero) CloseHandle(tok); }
        }

        /// <summary>profile folder -> SID, from the ProfileList of this computer (null when the folder is not listed).</summary>
        static string SidOfProfile(string dir)
        {
            try
            {
                using (var pl = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                {
                    if (pl == null) return null;
                    foreach (var sid in pl.GetSubKeyNames())
                        using (var k = pl.OpenSubKey(sid))
                        {
                            string p = k == null ? null : Convert.ToString(k.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                            if (!string.IsNullOrEmpty(p) && PathUtil.Same(p, dir)) return sid;
                        }
                }
            }
            catch { }
            return null;
        }

        static string ProfileOfSid(string sid)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid))
                    return k == null ? null : PathUtil.Normalize(Convert.ToString(k.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)));
            }
            catch { return null; }
        }

        /// <summary>Mounts an NTUSER.DAT under a temporary name. Returns the open root key, or null (with the reason) when it cannot be done.</summary>
        internal static RegistryKey Mount(string label, string dat, out string error)
        {
            error = null;
            lock (Gate)
            {
                RegistryKey have;
                if (MountedKeys.TryGetValue(label, out have)) return have;
                if (!EnablePrivilege("SeBackupPrivilege") | !EnablePrivilege("SeRestorePrivilege")) { error = "the privileges needed to read another user's registry are missing (run as administrator)"; return null; }
                string name = "MineHunter_" + Guid.NewGuid().ToString("N").Substring(0, 10);
                int rc = RegLoadKey(HKEY_USERS, name, dat);
                if (rc != 0) { error = "the registry file is in use or cannot be loaded (error " + rc + ")"; return null; }
                var key = Registry.Users.OpenSubKey(name, true);
                if (key == null) { RegUnLoadKey(HKEY_USERS, name); error = "the mounted registry could not be opened"; return null; }
                Mounted[label] = name; MountedKeys[label] = key;
                return key;
            }
        }

        /// <summary>Gives back every hive mounted by this process. Retries because the registry refuses to unload a hive while a handle to it is still open.</summary>
        public static void ReleaseAll()
        {
            lock (Gate)
            {
                foreach (var kv in MountedKeys.ToList()) { try { kv.Value.Dispose(); } catch { } }
                MountedKeys.Clear();
                foreach (var kv in Mounted.ToList())
                {
                    bool ok = false;
                    for (int i = 0; i < 20 && !ok; i++)
                    {
                        GC.Collect(); GC.WaitForPendingFinalizers();
                        ok = RegUnLoadKey(HKEY_USERS, kv.Value) == 0;
                        if (!ok) Thread.Sleep(100);
                    }
                    if (!ok) Log.Warn("could not unload the temporary registry mount " + kv.Value + " (it is released at the next restart)");
                    Mounted.Remove(kv.Key);
                }
            }
        }

        /// <summary>The root key for a stored hive label ("HKUOFF\..." mounts the file again). Used when something found there has to be removed or put back.</summary>
        public static RegistryKey Acquire(string label, out string error)
        {
            error = null;
            if (label == null || !label.StartsWith("HKUOFF\\", StringComparison.OrdinalIgnoreCase)) { error = "not an offline hive"; return null; }
            lock (Gate) { RegistryKey have; if (MountedKeys.TryGetValue(label, out have)) return have; }       // still mounted from the scan or an earlier step
            string known;
            if (TestDat.TryGetValue(label, out known)) return Mount(label, known, out error);
            string id = label.Substring(7);
            string dir = id.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) ? ProfileOfSid(id) : Path.Combine(PathUtil.SystemDrive + @"\Users", id);
            if (string.IsNullOrEmpty(dir)) { error = "the profile of " + id + " was not found"; return null; }
            string dat = Path.Combine(dir, "NTUSER.DAT");
            if (!File.Exists(dat)) { error = "no NTUSER.DAT in " + dir; return null; }
            return Mount(label, dat, out error);
        }

        /// <summary>The hive of the signed-in user, hives of other signed-in users, and (when <paramref name="offline"/>) every profile whose hive is not loaded.
        /// Offline hives stay mounted until <see cref="ReleaseAll"/>; call it when the scan is done with them.</summary>
        public static List<UserHive> Enumerate(ScanContext ctx, bool offline)
        {
            var list = new List<UserHive> { new UserHive { Label = "HKCU", Root = Registry.CurrentUser } };
            string mySid = null; try { mySid = System.Security.Principal.WindowsIdentity.GetCurrent().User.Value; } catch { }
            var loaded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var sid in Registry.Users.GetSubKeyNames())
                {
                    loaded.Add(sid);
                    if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase) || sid == ".DEFAULT" || sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || sid.StartsWith("MineHunter_")) continue;
                    if (mySid != null && string.Equals(sid, mySid, StringComparison.OrdinalIgnoreCase)) continue;
                    var k = Registry.Users.OpenSubKey(sid);
                    if (k != null) list.Add(new UserHive { Label = "HKU\\" + sid, Root = k });
                }
            }
            catch (Exception ex) { ctx.AddBlind("Registry", "HKEY_USERS enumeration: " + ex.Message); }

            if (!offline) return list;
            int skipped = 0; string why = null;
            foreach (var dir in PathUtil.UserProfiles())
            {
                try
                {
                    string dat = Path.Combine(dir, "NTUSER.DAT");
                    if (!File.Exists(dat)) continue;
                    string sid = SidOfProfile(dir);
                    if (sid != null && (loaded.Contains(sid) || string.Equals(sid, mySid, StringComparison.OrdinalIgnoreCase))) continue;       // already open above
                    if (sid == null && string.Equals(PathUtil.Normalize(dir), PathUtil.Normalize(Environment.GetEnvironmentVariable("USERPROFILE") ?? ""), StringComparison.OrdinalIgnoreCase)) continue;
                    string label = "HKUOFF\\" + (sid ?? Path.GetFileName(dir));
                    string err; var key = Mount(label, dat, out err);
                    if (key == null) { skipped++; why = err; continue; }
                    list.Add(new UserHive { Label = label, Root = key });
                }
                catch (Exception ex) { skipped++; why = ex.Message; }
            }
            if (skipped > 0) ctx.AddBlind("Registry", skipped + " other user profile(s) could not be read: " + why);
            return list;
        }
    }
}
