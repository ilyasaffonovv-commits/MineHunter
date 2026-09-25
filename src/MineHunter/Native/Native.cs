using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace MineHunter.Native
{
    internal static class NativeMethods
    {
        // ---------------- kernel32
        public const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, PROCESS_VM_READ = 0x0010,
                          PROCESS_TERMINATE = 0x0001, PROCESS_SUSPEND_RESUME = 0x0800, THREAD_QUERY_INFORMATION = 0x0040, THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        public const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, MEM_IMAGE = 0x1000000, MEM_MAPPED = 0x40000;
        public const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x4, MOVEFILE_REPLACE_EXISTING = 0x1;

        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr baseAddr, byte[] buf, IntPtr size, out IntPtr read);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, UIntPtr len);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool IsWow64Process(IntPtr h, [MarshalAs(UnmanagedType.Bool)] out bool wow64);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool MoveFileEx(string existing, string newName, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern uint GetProcessId(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern uint GetLongPathName(string shortPath, StringBuilder longPath, uint len);
        [DllImport("kernel32.dll")] public static extern bool SetPriorityClass(IntPtr h, uint cls);
        [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] public static extern bool SetProcessWorkingSetSize(IntPtr h, IntPtr min, IntPtr max);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(int pid);
        [DllImport("kernel32.dll")] public static extern bool FreeConsole();

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress, AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public UIntPtr RegionSize;
            public uint State, Protect, Type;
        }

        // ---------------- psapi
        [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcessModulesEx(IntPtr h, [Out] IntPtr[] modules, uint cb, out uint needed, uint filter);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern uint GetModuleFileNameEx(IntPtr h, IntPtr module, StringBuilder name, uint size);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern uint GetMappedFileName(IntPtr h, IntPtr addr, StringBuilder name, uint size);
        [DllImport("psapi.dll", SetLastError = true)] public static extern bool GetModuleInformation(IntPtr h, IntPtr module, out MODULEINFO info, uint cb);
        [StructLayout(LayoutKind.Sequential)] public struct MODULEINFO { public IntPtr BaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint; }

        // ---------------- ntdll
        [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
        [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
        [DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(IntPtr h, int cls, ref PROCESS_BASIC_INFORMATION info, int len, out int ret);
        [DllImport("ntdll.dll")] public static extern int NtQueryInformationThread(IntPtr h, int cls, out IntPtr info, int len, out int ret);
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION { public IntPtr ExitStatus, PebBaseAddress, AffinityMask, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId; }

        // ---------------- advapi32 (tokens)
        public const uint TOKEN_QUERY = 0x8;
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buf, int len, out int ret);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool LookupAccountSid(string sys, IntPtr sid, StringBuilder name, ref int cchName, StringBuilder domain, ref int cchDomain, out int use);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern IntPtr GetSidSubAuthority(IntPtr sid, int idx);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        // ---------------- iphlpapi
        public const int AF_INET = 2, AF_INET6 = 23;
        [DllImport("iphlpapi.dll", SetLastError = true)] public static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int cls, uint reserved);
        public const int TCP_TABLE_OWNER_PID_ALL = 5;
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID { public uint state, localAddr, localPort, remoteAddr, remotePort, owningPid; }
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
            public uint localScope, localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
            public uint remoteScope, remotePort, state, owningPid;
        }
    }

    public sealed class TcpConn
    {
        public string Local, Remote; public int LocalPort, RemotePort, Pid; public string State; public bool V6;
        public bool IsLoopbackRemote { get { return Remote == "127.0.0.1" || Remote == "::1" || Remote.StartsWith("127."); } }
    }

    public static class Net
    {
        static string StateName(uint s)
        {
            switch (s) { case 1: return "Closed"; case 2: return "Listen"; case 3: return "SynSent"; case 4: return "SynRcvd"; case 5: return "Established"; case 6: return "FinWait1"; case 7: return "FinWait2"; case 8: return "CloseWait"; case 9: return "Closing"; case 10: return "LastAck"; case 11: return "TimeWait"; case 12: return "DeleteTcb"; default: return s.ToString(); }
        }
        static int Port(uint p) { return (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF)); }

        public static List<TcpConn> GetTcp()
        {
            var res = new List<TcpConn>();
            foreach (int af in new[] { NativeMethods.AF_INET, NativeMethods.AF_INET6 })
            {
                int size = 0;
                NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, true, af, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
                if (size <= 0) continue;
                IntPtr buf = Marshal.AllocHGlobal(size + 64);
                try
                {
                    uint r = NativeMethods.GetExtendedTcpTable(buf, ref size, true, af, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
                    if (r != 0) continue;
                    int n = Marshal.ReadInt32(buf);
                    if (af == NativeMethods.AF_INET)
                    {
                        int rs = Marshal.SizeOf(typeof(NativeMethods.MIB_TCPROW_OWNER_PID));
                        for (int i = 0; i < n; i++)
                        {
                            var row = (NativeMethods.MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(IntPtr.Add(buf, 4 + i * rs), typeof(NativeMethods.MIB_TCPROW_OWNER_PID));
                            res.Add(new TcpConn
                            {
                                Local = new System.Net.IPAddress(row.localAddr).ToString(), Remote = new System.Net.IPAddress(row.remoteAddr).ToString(),
                                LocalPort = Port(row.localPort), RemotePort = Port(row.remotePort), Pid = (int)row.owningPid, State = StateName(row.state)
                            });
                        }
                    }
                    else
                    {
                        int rs = Marshal.SizeOf(typeof(NativeMethods.MIB_TCP6ROW_OWNER_PID));
                        for (int i = 0; i < n; i++)
                        {
                            var row = (NativeMethods.MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(IntPtr.Add(buf, 4 + i * rs), typeof(NativeMethods.MIB_TCP6ROW_OWNER_PID));
                            res.Add(new TcpConn
                            {
                                Local = new System.Net.IPAddress(row.localAddr).ToString(), Remote = new System.Net.IPAddress(row.remoteAddr).ToString(),
                                LocalPort = Port(row.localPort), RemotePort = Port(row.remotePort), Pid = (int)row.owningPid, State = StateName(row.state), V6 = true
                            });
                        }
                    }
                }
                catch { }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return res;
        }
    }

    /// <summary>Process token helpers: owner and integrity level.</summary>
    public static class Tokens
    {
        public static string GetOwner(IntPtr hProcess)
        {
            IntPtr tok = IntPtr.Zero, buf = IntPtr.Zero;
            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out tok)) return null;
                int need; NativeMethods.GetTokenInformation(tok, 1, IntPtr.Zero, 0, out need); // TokenUser
                if (need <= 0) return null;
                buf = Marshal.AllocHGlobal(need);
                if (!NativeMethods.GetTokenInformation(tok, 1, buf, need, out need)) return null;
                IntPtr sid = Marshal.ReadIntPtr(buf);
                var name = new StringBuilder(256); var dom = new StringBuilder(256); int cn = 256, cd = 256, use;
                if (!NativeMethods.LookupAccountSid(null, sid, name, ref cn, dom, ref cd, out use)) return null;
                return dom.Length > 0 ? dom + "\\" + name : name.ToString();
            }
            catch { return null; }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); if (tok != IntPtr.Zero) NativeMethods.CloseHandle(tok); }
        }

        /// <summary>Returns "Low"/"Medium"/"High"/"System" or null.</summary>
        public static string GetIntegrity(IntPtr hProcess)
        {
            IntPtr tok = IntPtr.Zero, buf = IntPtr.Zero;
            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out tok)) return null;
                int need; NativeMethods.GetTokenInformation(tok, 25, IntPtr.Zero, 0, out need); // TokenIntegrityLevel
                if (need <= 0) return null;
                buf = Marshal.AllocHGlobal(need);
                if (!NativeMethods.GetTokenInformation(tok, 25, buf, need, out need)) return null;
                IntPtr sid = Marshal.ReadIntPtr(buf);
                int cnt = Marshal.ReadByte(NativeMethods.GetSidSubAuthorityCount(sid));
                int rid = Marshal.ReadInt32(NativeMethods.GetSidSubAuthority(sid, cnt - 1));
                if (rid >= 0x4000) return "System";
                if (rid >= 0x3000) return "High";
                if (rid >= 0x2000) return "Medium";
                if (rid >= 0x1000) return "Low";
                return "Untrusted";
            }
            catch { return null; }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); if (tok != IntPtr.Zero) NativeMethods.CloseHandle(tok); }
        }
    }

    // =======================================================================================================
    //   Authenticode / catalog verification (WinVerifyTrust), no network access (cache-only revocation)
    // =======================================================================================================
    public enum TrustState { Unsigned, Valid, ValidCatalog, ExpiredCert, UntrustedRoot, Tampered, Revoked, Error }

    public sealed class TrustInfo
    {
        public TrustState State;
        public string Publisher;        // CN or O of the signer
        public string Subject;          // full subject
        public string CatalogFile;
        public uint HResult;
        public bool IsValid { get { return State == TrustState.Valid || State == TrustState.ValidCatalog; } }
        public override string ToString() { return State + (Publisher != null ? " (" + Publisher + ")" : ""); }
    }

    internal static class WinTrust
    {
        static readonly Guid ActionGenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO { public uint cbStruct; public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct, dwCatalogVersion;
            public string pcwszCatalogFilePath, pcwszMemberTag, pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext, hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData, pSIPClientData;
            public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice;
            public IntPtr pInfo;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags, dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);

        [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminAcquireContext(out IntPtr hCatAdmin, IntPtr pgSubsystem, uint flags);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptCATAdminAcquireContext2")]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr pgSubsystem, string algorithm, IntPtr policy, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint cbHash, byte[] pbHash, uint flags);
        [DllImport("wintrust.dll", SetLastError = true, EntryPoint = "CryptCATAdminCalcHashFromFileHandle2")]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint cbHash, byte[] pbHash, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint flags, ref IntPtr prevCatInfo);
        [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO info, uint flags);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO { public uint cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile; }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr template);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

        const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2, WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
        const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000, WTD_REVOCATION_CHECK_NONE = 0x10;

        static TrustState Map(int hr)
        {
            uint u = unchecked((uint)hr);
            switch (u)
            {
                case 0: return TrustState.Valid;
                case 0x800B0100: return TrustState.Unsigned;      // TRUST_E_NOSIGNATURE
                case 0x800B0003: return TrustState.Unsigned;      // TRUST_E_SUBJECT_FORM_UNKNOWN
                case 0x800B0004: return TrustState.Unsigned;      // TRUST_E_SUBJECT_NOT_TRUSTED (treated below by caller)
                case 0x80096010: return TrustState.Tampered;      // TRUST_E_BAD_DIGEST
                case 0x800B0101: return TrustState.ExpiredCert;   // CERT_E_EXPIRED
                case 0x800B0109: return TrustState.UntrustedRoot; // CERT_E_UNTRUSTEDROOT
                case 0x800B010A: return TrustState.UntrustedRoot; // CERT_E_CHAINING
                case 0x800B010C: return TrustState.Revoked;       // CERT_E_REVOKED
                case 0x80092026: return TrustState.Tampered;      // CRYPT_E_SECURITY_SETTINGS
                case 0x80096001: return TrustState.Error;
                default: return TrustState.Error;
            }
        }

        static int Verify(uint choice, IntPtr info)
        {
            var d = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)), dwUIChoice = WTD_UI_NONE, fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = choice, pInfo = info, dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
            };
            int hr = WinVerifyTrust(new IntPtr(-1), ActionGenericVerifyV2, ref d);
            d.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ActionGenericVerifyV2, ref d);
            return hr;
        }

        public static TrustInfo Check(string path)
        {
            var ti = new TrustInfo();
            IntPtr pFile = IntPtr.Zero;
            try
            {
                var fi = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fi, pFile, false);
                int hr = Verify(WTD_CHOICE_FILE, pFile);
                ti.HResult = unchecked((uint)hr);
                if (hr == 0)
                {
                    ti.State = TrustState.Valid;
                    FillEmbeddedSigner(path, ti);
                    return ti;
                }
                uint u = ti.HResult;
                if (u == 0x800B0100 || u == 0x800B0003 || u == 0x800B0004 || u == 0x80096011)
                {
                    // no embedded signature -> try the Windows catalogs
                    var cat = CheckCatalog(path, ti);
                    if (cat != null) return cat;
                    ti.State = TrustState.Unsigned;
                    return ti;
                }
                ti.State = Map(hr);
                FillEmbeddedSigner(path, ti);
                return ti;
            }
            catch (Exception) { ti.State = TrustState.Error; return ti; }
            finally { if (pFile != IntPtr.Zero) { Marshal.FreeHGlobal(pFile); } }
        }

        static void FillEmbeddedSigner(string path, TrustInfo ti)
        {
            try
            {
                var c = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                var c2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(c);
                ti.Subject = c2.Subject;
                ti.Publisher = c2.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);
                if (string.IsNullOrEmpty(ti.Publisher)) ti.Publisher = c2.Subject;
            }
            catch { }
        }

        static TrustInfo CheckCatalog(string path, TrustInfo ti)
        {
            IntPtr hCatAdmin = IntPtr.Zero, hFile = IntPtr.Zero, hCatInfo = IntPtr.Zero, pHash = IntPtr.Zero, pCat = IntPtr.Zero;
            try
            {
                hFile = CreateFile(path, 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);   // GENERIC_READ, share all, OPEN_EXISTING
                if (hFile == new IntPtr(-1)) { hFile = IntPtr.Zero; return null; }
                foreach (bool sha256 in new[] { true, false })
                {
                    IntPtr admin;
                    bool ok = sha256 ? CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0) : CryptCATAdminAcquireContext(out admin, IntPtr.Zero, 0);
                    if (!ok) continue;
                    hCatAdmin = admin;
                    uint cb = 0;
                    if (sha256) CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cb, null, 0); else CryptCATAdminCalcHashFromFileHandle(hFile, ref cb, null, 0);
                    if (cb == 0) { CryptCATAdminReleaseContext(hCatAdmin, 0); hCatAdmin = IntPtr.Zero; continue; }
                    var hash = new byte[cb];
                    bool hok = sha256 ? CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cb, hash, 0) : CryptCATAdminCalcHashFromFileHandle(hFile, ref cb, hash, 0);
                    if (!hok) { CryptCATAdminReleaseContext(hCatAdmin, 0); hCatAdmin = IntPtr.Zero; continue; }
                    IntPtr prev = IntPtr.Zero;
                    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cb, 0, ref prev);
                    if (hCatInfo == IntPtr.Zero) { CryptCATAdminReleaseContext(hCatAdmin, 0); hCatAdmin = IntPtr.Zero; continue; }

                    var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO)) };
                    if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) { CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0); hCatInfo = IntPtr.Zero; CryptCATAdminReleaseContext(hCatAdmin, 0); hCatAdmin = IntPtr.Zero; continue; }

                    pHash = Marshal.AllocHGlobal(hash.Length);
                    Marshal.Copy(hash, 0, pHash, hash.Length);
                    var cat = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)), dwCatalogVersion = 0, pcwszCatalogFilePath = ci.wszCatalogFile,
                        pcwszMemberTag = Hashing2.HexUpper(hash), pcwszMemberFilePath = path, hMemberFile = hFile, pbCalculatedFileHash = pHash,
                        cbCalculatedFileHash = cb, pcCatalogContext = IntPtr.Zero, hCatAdmin = hCatAdmin
                    };
                    pCat = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                    Marshal.StructureToPtr(cat, pCat, false);
                    int hr = Verify(WTD_CHOICE_CATALOG, pCat);
                    ti.HResult = unchecked((uint)hr);
                    ti.CatalogFile = ci.wszCatalogFile;
                    if (hr == 0)
                    {
                        ti.State = TrustState.ValidCatalog;
                        try
                        {
                            var c = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(ci.wszCatalogFile);
                            var c2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(c);
                            ti.Subject = c2.Subject;
                            ti.Publisher = c2.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);
                        }
                        catch { }
                        if (string.IsNullOrEmpty(ti.Publisher)) ti.Publisher = "Windows catalog";
                        return ti;
                    }
                    ti.State = Map(hr);
                    return ti;
                }
                return null;
            }
            catch { return null; }
            finally
            {
                if (pCat != IntPtr.Zero) Marshal.FreeHGlobal(pCat);
                if (pHash != IntPtr.Zero) Marshal.FreeHGlobal(pHash);
                if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
                if (hFile != IntPtr.Zero) CloseHandle(hFile);
            }
        }
    }

    internal static class Hashing2 { public static string HexUpper(byte[] b) { var sb = new StringBuilder(); foreach (var x in b) sb.Append(x.ToString("X2")); return sb.ToString(); } }

    /// <summary>Thin public facade with a cache keyed by (path, size, mtime).</summary>
    public static class Trust
    {
        static readonly Dictionary<string, TrustInfo> Cache = new Dictionary<string, TrustInfo>(StringComparer.OrdinalIgnoreCase);
        static readonly object Lock = new object();

        public static TrustInfo Check(string path)
        {
            if (string.IsNullOrEmpty(path)) return new TrustInfo { State = TrustState.Error };
            string key;
            try { var fi = new System.IO.FileInfo(path); if (!fi.Exists) return new TrustInfo { State = TrustState.Error }; key = path + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks; }
            catch { return new TrustInfo { State = TrustState.Error }; }
            lock (Lock) { TrustInfo c; if (Cache.TryGetValue(key, out c)) return c; }
            var r = WinTrust.Check(path);
            lock (Lock) { Cache[key] = r; }
            return r;
        }

        public static int CacheSize { get { lock (Lock) return Cache.Count; } }
    }

    /// <summary>Delete-on-reboot queue and safe process control.</summary>
    public static class SystemOps
    {
        public static bool ScheduleDeleteOnReboot(string path) { return NativeMethods.MoveFileEx(path, null, NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT); }

        public static bool Suspend(int pid)
        {
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return NativeMethods.NtSuspendProcess(h) >= 0; } finally { NativeMethods.CloseHandle(h); }
        }
        public static bool Resume(int pid)
        {
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return NativeMethods.NtResumeProcess(h) >= 0; } finally { NativeMethods.CloseHandle(h); }
        }
        public static int ParentPid(int pid)
        {
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return -1;
            try
            {
                var pbi = new NativeMethods.PROCESS_BASIC_INFORMATION(); int ret;
                if (NativeMethods.NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf(pbi), out ret) != 0) return -1;
                return (int)pbi.InheritedFromUniqueProcessId;
            }
            finally { NativeMethods.CloseHandle(h); }
        }
    }
}
