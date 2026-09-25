using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using MineHunter.Analysis;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    public enum TrustClass { MicrosoftSigned, TrustedPublisher, SignedOther, SignedExpired, Unsigned, Invalid, NotChecked }

    [Flags]
    public enum FileRole { HotDir = 1, ProcessImage = 2, PersistenceTarget = 4, Module = 8, Referenced = 16 }

    /// <summary>Turns a path into a File entity carrying all static evidence (signature, PE layout, strings, location, masquerade).</summary>
    public sealed class FileIntel
    {
        readonly ScanContext ctx;
        public FileIntel(ScanContext c) { ctx = c; }

        static readonly Regex DoubleExtRx = new Regex(@"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt|mp3|mp4|zip|rar)\s*\.(exe|scr|com|bat|cmd|js|vbs)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly string[] UserTemplateDirsToSkipForLocation = { @"\microsoft\windowsapps\", @"\microsoft\windows\start menu\", @"\microsoft\edge\", @"\microsoft\onedrive\", @"\microsoft\teams\" };

        public static string IdFor(string path) { return "file:" + PathUtil.Key(path); }

        // temp folders that installers / unpackers create by design (Inno Setup, NSIS, PyInstaller, 7-Zip, WinRAR, Windows Installer ...)
        static readonly Regex InstallerTempRx = new Regex(@"\\temp\\(is-[a-z0-9]{4,}\.tmp|nsu[a-z0-9]{3,}\.tmp|nsz[a-z0-9]{3,}\.tmp|\{[0-9a-f\-]{36}\}|[0-9a-z]{6,8}\.tmp|~[a-z0-9]{3,}|7z[0-9a-z]+|wz[a-z0-9]+|rar\$[a-z0-9\.]+|_mei\d+|pip-[a-z0-9\-]+|chocolatey|npm-[a-z0-9\-]+|msdownld\.tmp|dotnet-installer[^\\]*|vs_[a-z0-9_]+|setup[a-z0-9]*)\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex SysFolderLookalikeRx = new Regex(@"^(system|syswow)[0-9]{2}$|^system32$|^syswow64$|^system-?32[a-z]$|^sys(tem)?32(\.|_)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        static bool IsNgenImage(string path)
        {
            string lp = path.ToLowerInvariant();
            return PathUtil.IsUnder(path, PathUtil.WinDir) && lp.Contains(@"\assembly\nativeimages_") && (lp.EndsWith(".ni.dll") || lp.EndsWith(".ni.exe"));
        }

        public Entity Get(string path) { Entity e; ctx.Entities.TryGetValue(IdFor(path), out e); return e; }

        /// <summary>Inspects a file once per scan; later calls return the same entity (roles are merged).</summary>
        public Entity Inspect(string rawPath, FileRole role)
        {
            string norm = PathUtil.Normalize(rawPath);
            if (norm.Length < 4) return null;
            string id = IdFor(norm);
            Entity existing;
            if (ctx.Entities.TryGetValue(id, out existing)) { MergeRole(existing, role); return existing; }
            var e = new Entity { Id = id, Kind = EntityKind.File, Title = PathUtil.SafeFileName(norm), Location = norm };
            e = ctx.Entities.GetOrAdd(id, e);
            if (!object.ReferenceEquals(e.P("inspected"), null)) { MergeRole(e, role); return e; }
            lock (e)
            {
                if (e.P("inspected") != null) { MergeRole(e, role); return e; }
                MergeRole(e, role);
                try { Analyze(e, norm, role); }
                catch (Exception ex) { Log.Warn("inspect " + norm + ": " + ex.Message); }
                e.Set("inspected", "1");
            }
            return e;
        }

        /// <summary>Cheap gate for bulk scanning: skips files judged earlier (cache), inspects the rest and keeps an entity
        /// only when it carries meaningful suspicion. Returns null for trusted / low-risk files.</summary>
        public Entity Screen(string path)
        {
            FileInfo fi;
            try { fi = new FileInfo(path); if (!fi.Exists) return null; } catch { return null; }
            byte code;
            if (ctx.Options.UseCache && ctx.Cache.TryGet(fi, out code)) { Interlocked.Increment(ref ctx.Stats.FilesSkippedByCache); return null; }
            Interlocked.Increment(ref ctx.Stats.FilesInspected);
            var e = Inspect(path, FileRole.HotDir);
            if (e == null) return null;
            int role; int.TryParse(e.P("role") ?? "0", out role);
            bool onlyHot = role == (int)FileRole.HotDir;
            int pos = e.Evidence.Where(x => x.Weight > 0).Sum(x => x.Weight);
            if (e.Trusted) { if (ctx.Options.UseCache) ctx.Cache.Set(fi, 1); if (onlyHot) { Entity rm; ctx.Entities.TryRemove(e.Id, out rm); } return null; }
            if (pos < 12 && onlyHot && e.P("missing") == null)
            {
                if (ctx.Options.UseCache) ctx.Cache.Set(fi, 2);
                Entity rm; ctx.Entities.TryRemove(e.Id, out rm);
                return null;
            }
            return e;
        }

        static void MergeRole(Entity e, FileRole role)
        {
            int cur; int.TryParse(e.P("role") ?? "0", out cur);
            e.Set("role", ((int)role | cur).ToString());
        }

        void Analyze(Entity e, string path, FileRole role)
        {
            FileInfo fi;
            try { fi = new FileInfo(path); } catch { return; }
            if (!fi.Exists) { e.Set("missing", "1"); return; }
            e.Set("size", fi.Length.ToString());
            e.Set("mtime", fi.LastWriteTimeUtc.ToString("o"));
            PathClass pc = PathUtil.Classify(path);
            e.Set("pathClass", pc.ToString());
            string name = fi.Name;
            string nameLower = name.ToLowerInvariant();
            bool nameExec = PathUtil.IsExecutableExt(name);
            bool nameScript = PathUtil.IsScriptExt(name);
            bool noExt = Path.GetExtension(name).Length == 0;
            bool wantPe = nameExec || noExt || (role & (FileRole.ProcessImage | FileRole.PersistenceTarget)) != 0;

            if (ctx.Allow.Contains(path, null)) { e.Trusted = true; e.Set("allowlisted", "path"); e.Add(new Evidence("TRUST.USER_ALLOWLIST", EvidenceCategory.Trust, -100, "Approved by you (allow-list)")); return; }

            PeInfo pe = null;
            if (wantPe)
            {
                pe = PeAnalyzer.Analyze(path, false);
                if (!pe.IsPe) pe = null;
            }
            bool isPe = pe != null;
            e.Set("isPe", isPe ? "1" : "0");
            if (!isPe && !nameScript) return;                       // not executable content: nothing to judge

            // ---------- attributes / naming tricks (apply to anything executable, before any trust shortcut)
            if (nameLower.IndexOf('\u202e') >= 0 || path.IndexOf('\u202e') >= 0)
                e.Add(new Evidence("MASQ.RTL_OVERRIDE", EvidenceCategory.Masquerade, 30, "Right-to-left override character hides the real extension", path));
            if (DoubleExtRx.IsMatch(name))
                e.Add(new Evidence("MASQ.DOUBLE_EXTENSION", EvidenceCategory.Masquerade, 25, "Executable disguised with a document/media extension", name));

            // ---------- signature
            TrustInfo ti = null;
            TrustClass tc = TrustClass.NotChecked;
            if (isPe)
            {
                ti = Trust.Check(path);
                tc = Upgrade(Classify(ti), ti);
                e.Set("sig", ti.State.ToString());
                if (ti.Publisher != null) e.Set("publisher", ti.Publisher);
            }
            e.Set("trustClass", tc.ToString());

            // ---------- Windows-generated NGEN native images are never signed by design
            if (isPe && (tc == TrustClass.Unsigned || tc == TrustClass.NotChecked) && IsNgenImage(path))
            {
                e.Trusted = true;
                e.Add(new Evidence("TRUST.NGEN_CACHE", EvidenceCategory.Trust, -60, "Windows-generated .NET native image cache (unsigned by design)"));
                return;
            }

            // ---------- masquerade by name (works even for signed copies)
            CheckNameMasquerade(e, path, nameLower, pc, ti, tc);

            // ---------- known-bad hash (cheap only for untrusted files)
            bool trusted = tc == TrustClass.MicrosoftSigned || tc == TrustClass.TrustedPublisher;
            if (trusted)
            {
                if (tc == TrustClass.MicrosoftSigned && (pc == PathClass.WindowsSystem || pc == PathClass.WindowsOther || pc == PathClass.ProgramFiles))
                    e.Add(new Evidence("TRUST.OS_SIGNED", EvidenceCategory.Trust, -70, "Signed by " + ti.Publisher, ti.CatalogFile ?? ""));
                else
                    e.Add(new Evidence("TRUST.PUBLISHER", EvidenceCategory.Trust, -45, "Valid signature by a known publisher: " + ti.Publisher));
                e.Trusted = true;
                // a trusted binary can still be an old, known-vulnerable driver etc. - handled by the driver scanner
                return;
            }

            // ---------- everything below is for files that are NOT trusted
            string sha = null;
            if (fi.Length <= 2L * 1024 * 1024 * 1024) { sha = Hashing.Sha256(path); Interlocked.Increment(ref ctx.Stats.FilesHashed); }
            if (sha != null)
            {
                e.Sha256 = sha; e.Set("sha256", sha);
                if (ctx.Allow.Contains(null, sha)) { e.Trusted = true; e.Set("allowlisted", "hash"); e.Add(new Evidence("TRUST.USER_ALLOWLIST", EvidenceCategory.Trust, -100, "Approved by you (allow-list)")); return; }
                string bad;
                if (ctx.Rules.BadHashes.TryGetValue(sha, out bad))
                    e.Add(new Evidence("REP.KNOWN_BAD_HASH", EvidenceCategory.Reputation, 100, "SHA-256 is in the known-malware list: " + bad, sha, true));
                else
                {
                    string good;
                    if (ctx.Rules.GoodHashes.TryGetValue(sha, out good))
                    {
                        // a rule update vouches for this exact file (false-positive fix without a new EXE)
                        e.Trusted = true; e.Set("knownGood", good);
                        e.Add(new Evidence("TRUST.KNOWN_GOOD_HASH", EvidenceCategory.Trust, -100, "SHA-256 is on the known-legitimate list: " + good, sha));
                        return;
                    }
                }
            }

            AddSignatureEvidence(e, ti, tc, pc, isPe);
            AddLocationEvidence(e, path, pc, isPe, tc);

            if (isPe)
            {
                var deep = PeAnalyzer.Analyze(path, true);
                pe = deep.IsPe ? deep : pe;
                StorePe(e, pe);
                AddPeEvidence(e, pe, tc, pc, ti);
            }

            // ---------- content scan (strings) - only for untrusted files, bounded
            if (fi.Length <= (long)ctx.Options.MaxFileSizeMbForContentScan * 1024 * 1024 * 4 && !ctx.IsSelf(path))
            {
                if (isPe) StringScan(e, path);
                else if (nameScript) ScriptScan(e, path, fi.Length);
            }

            // ---------- IOC path rules
            string lp = path.ToLowerInvariant();
            foreach (var r in ctx.Rules.IocPaths)
                if (r.Rx.IsMatch(lp)) e.Add(new Evidence(r.Id, EvidenceCategory.Reputation, r.Weight, r.Text, path));
        }

        public static TrustClass Classify(TrustInfo ti)
        {
            if (ti == null) return TrustClass.NotChecked;
            switch (ti.State)
            {
                case TrustState.Valid:
                case TrustState.ValidCatalog:
                    if (ti.Publisher != null && ti.Publisher.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) return TrustClass.MicrosoftSigned;
                    if (ti.State == TrustState.ValidCatalog && (ti.Publisher == null || ti.Publisher == "Windows catalog")) return TrustClass.MicrosoftSigned;
                    return TrustClass.SignedOther;      // may be upgraded to TrustedPublisher below by caller with rules
                case TrustState.ExpiredCert: return TrustClass.SignedExpired;
                case TrustState.Tampered: case TrustState.Revoked: return TrustClass.Invalid;
                case TrustState.Unsigned: return TrustClass.Unsigned;
                case TrustState.UntrustedRoot: return TrustClass.SignedOther;
                default: return TrustClass.Unsigned;
            }
        }

        // The TrustedPublisher upgrade needs the rule pack, so it is applied here.
        TrustClass Upgrade(TrustClass tc, TrustInfo ti)
        {
            if (tc == TrustClass.SignedOther && ti != null && ti.IsValid && ctx.Rules.IsTrustedPublisher(ti.Publisher)) return TrustClass.TrustedPublisher;
            if (tc == TrustClass.SignedExpired && ti != null && ctx.Rules.IsTrustedPublisher(ti.Publisher)) return TrustClass.TrustedPublisher;
            return tc;
        }

        void CheckNameMasquerade(Entity e, string path, string nameLower, PathClass pc, TrustInfo ti, TrustClass tc)
        {
            bool inWindows = pc == PathClass.WindowsSystem || pc == PathClass.WindowsOther;
            if (ctx.Rules.SystemBinaries.Contains(nameLower) && !PathUtil.IsUnder(path, PathUtil.WinDir))
            {
                bool msSigned = tc == TrustClass.MicrosoftSigned;
                if (msSigned) e.Add(new Evidence("MASQ.SIGNED_COPY", EvidenceCategory.Masquerade, 5, "Genuine Microsoft file copied outside the Windows folder", path));
                else e.Add(new Evidence("MASQ.SYSTEM_NAME_WRONG_PATH", EvidenceCategory.Masquerade, 32, "Named like a Windows system file but is not in the Windows folder", path));
            }
            else if (ctx.Rules.SystemBinaries.Contains(nameLower) && inWindows && ti != null && !ti.IsValid && tc != TrustClass.NotChecked)
            {
                e.Add(new Evidence("MASQ.SYSTEM_NAME_UNSIGNED", EvidenceCategory.Masquerade, 35, "System-file name in the Windows folder without a valid Microsoft signature", path));
            }

            // look-alike spellings of well-known brands in the file name or any folder name of the path
            string stem = Path.GetFileNameWithoutExtension(nameLower);
            var segs = new List<string> { stem };
            try { segs.AddRange(path.Split('\\').Skip(1).Take(12).Select(s => s.ToLowerInvariant())); } catch { }
            foreach (var seg in segs.Distinct())
            {
                if (seg.Length < 5) continue;
                string folded = Text.FoldConfusables(seg);
                foreach (var b in ctx.Rules.Brands)
                {
                    if (b.Length < 5) continue;
                    string fb = Text.FoldConfusables(b);
                    if (folded.Contains(fb) && !seg.Contains(b))
                    {
                        e.Add(new Evidence("MASQ.HOMOGLYPH", EvidenceCategory.Masquerade, 25, "Look-alike spelling of \"" + b + "\" (e.g. capital I instead of l)", seg));
                        break;
                    }
                }
            }

            // folders imitating the Windows system folders: ...\system92, ...\ProgramData\System32 (outside the Windows directory)
            foreach (var seg in path.Split('\\').Skip(1).Take(14))
            {
                if (!SysFolderLookalikeRx.IsMatch(seg)) continue;
                bool genuine = (seg.Equals("system32", StringComparison.OrdinalIgnoreCase) || seg.Equals("syswow64", StringComparison.OrdinalIgnoreCase)) && PathUtil.IsUnder(path, PathUtil.WinDir);
                if (!genuine) { e.Add(new Evidence("MASQ.SYSFOLDER_LOOKALIKE", EvidenceCategory.Masquerade, 25, "Located in a folder that imitates the Windows system folder (\"" + seg + "\")", path)); break; }
            }
        }

        void AddSignatureEvidence(Entity e, TrustInfo ti, TrustClass tc, PathClass pc, bool isPe)
        {
            if (!isPe || ti == null) return;
            switch (ti.State)
            {
                case TrustState.Unsigned:
                    string dirOf = (Path.GetDirectoryName(e.Location) ?? "").TrimEnd('\\');
                    if (pc == PathClass.WindowsSystem && (dirOf.Equals(PathUtil.System32, StringComparison.OrdinalIgnoreCase) || dirOf.Equals(PathUtil.SysWow64, StringComparison.OrdinalIgnoreCase) || dirOf.Equals(PathUtil.WinDir, StringComparison.OrdinalIgnoreCase)))
                        e.Add(new Evidence("SIG.UNSIGNED_IN_SYSTEM", EvidenceCategory.Signature, 16, "Unsigned executable inside the Windows system folder"));
                    else if (pc == PathClass.WindowsSystem) e.Add(new Evidence("SIG.UNSIGNED_MINOR", EvidenceCategory.Signature, 1, "No digital signature"));
                    else if (PathUtil.IsUserWritable(e.Location) && !InstallerTempRx.IsMatch(e.Location)) e.Add(new Evidence("SIG.UNSIGNED", EvidenceCategory.Signature, 6, "No digital signature"));
                    else e.Add(new Evidence("SIG.UNSIGNED_MINOR", EvidenceCategory.Signature, 1, "No digital signature"));
                    break;
                case TrustState.Tampered:
                    e.Add(new Evidence("SIG.TAMPERED", EvidenceCategory.Signature, 28, "Signature does not match the file contents (file was modified after signing)"));
                    break;
                case TrustState.Revoked:
                    e.Add(new Evidence("SIG.REVOKED", EvidenceCategory.Signature, 28, "Signing certificate has been revoked"));
                    break;
                case TrustState.UntrustedRoot:
                    e.Add(new Evidence("SIG.UNTRUSTED_ROOT", EvidenceCategory.Signature, 5, "Signed with a certificate that does not chain to a trusted root", ti.Subject));
                    break;
                case TrustState.ExpiredCert:
                    e.Add(new Evidence("SIG.EXPIRED", EvidenceCategory.Signature, 1, "Signing certificate has expired", ti.Publisher));
                    break;
                case TrustState.Valid:
                case TrustState.ValidCatalog:
                    e.Add(new Evidence("TRUST.VALID_OTHER", EvidenceCategory.Trust, -14, "Valid signature by " + ti.Publisher));
                    break;
            }
        }

        void AddLocationEvidence(Entity e, string path, PathClass pc, bool isPe, TrustClass tc)
        {
            string lp = path.ToLowerInvariant();
            foreach (var skip in UserTemplateDirsToSkipForLocation) if (lp.Contains(skip)) return;
            if (pc == PathClass.UserTemp && InstallerTempRx.IsMatch(path)) return;      // installer / unpacker scratch folders live in Temp by design
            int w = 0; string rule = "LOC.USER_WRITABLE"; string text = null;
            switch (pc)
            {
                case PathClass.UserTemp: w = 6; rule = "LOC.TEMP"; text = "Runs from a temporary folder"; break;
                case PathClass.UserAppDataRoamingRoot: w = 12; rule = "LOC.APPDATA_ROOT"; text = "Executable placed directly in the root of %APPDATA%"; break;
                case PathClass.UserAppDataLocalRoot: w = 12; rule = "LOC.LOCALAPPDATA_ROOT"; text = "Executable placed directly in the root of %LOCALAPPDATA%"; break;
                case PathClass.UserAppDataRoaming: w = 4; rule = "LOC.APPDATA"; text = "Runs from %APPDATA%"; break;
                case PathClass.UserAppDataLocal: w = 3; rule = "LOC.LOCALAPPDATA"; text = "Runs from %LOCALAPPDATA%"; break;
                case PathClass.ProgramData: w = 4; rule = "LOC.PROGRAMDATA"; text = "Runs from C:\\ProgramData (writable by every user)"; break;
                case PathClass.Public: w = 6; rule = "LOC.PUBLIC"; text = "Runs from the Public profile"; break;
                case PathClass.WindowsTemp: w = 8; rule = "LOC.WINTEMP"; text = "Runs from a writable Windows sub-folder (Temp/Tasks)"; break;
                case PathClass.RecycleBin: w = 8; rule = "LOC.RECYCLE_BIN"; text = "Executable stored in the Recycle Bin (deleted item, cannot run from there)"; break;
                case PathClass.UserDownloads: w = 2; rule = "LOC.DOWNLOADS"; text = "Located in Downloads"; break;
                case PathClass.UserDesktopDocs: w = 2; rule = "LOC.DESKTOP_DOCS"; text = "Located on Desktop/Documents"; break;
                case PathClass.UserProfileOther: w = 3; rule = "LOC.PROFILE"; text = "Located in a user-profile folder"; break;
                case PathClass.DriveRoot: w = 5; rule = "LOC.DRIVE_ROOT"; text = "Executable in a drive root"; break;
            }
            if (w > 0 && text != null) e.Add(new Evidence(rule, EvidenceCategory.Location, w, text, path));

            // AppData\...\Microsoft\Windows\... normally holds no executables at all
            if (isPe && (lp.Contains(@"\appdata\local\microsoft\windows\") || lp.Contains(@"\appdata\roaming\microsoft\windows\")) &&
                !lp.Contains(@"\microsoft\windows\start menu\") && !lp.Contains(@"\microsoft\windowsapps\"))
                e.Add(new Evidence("LOC.APPDATA_MS_WINDOWS", EvidenceCategory.Location, 18, "Executable hidden inside AppData\\Microsoft\\Windows (no legitimate program lives there)", path));

            if (isPe && PathUtil.IsUserWritable(path))
            {
                if (Fs.IsHiddenSystem(path)) e.Add(new Evidence("ATTR.HIDDEN_SYSTEM", EvidenceCategory.Location, 12, "File has both Hidden and System attributes", path));
                else if (Fs.IsHidden(path)) e.Add(new Evidence("ATTR.HIDDEN", EvidenceCategory.Location, 5, "Hidden executable", path));
            }
        }

        void StorePe(Entity e, PeInfo pe)
        {
            if (pe == null || !pe.IsPe) return;
            e.Set("company", pe.Company); e.Set("product", pe.Product); e.Set("description", pe.Description); e.Set("originalName", pe.OriginalName);
            e.Set("dotnet", pe.IsDotNet ? "1" : "0"); e.Set("is64", pe.Is64 ? "1" : "0"); e.Set("dll", pe.IsDll ? "1" : "0");
            e.Set("sections", string.Join(",", pe.Sections.Select(s => s.Name + ":" + s.Entropy.ToString("0.0"))));
            e.Set("maxExecEntropy", pe.MaxExecEntropy.ToString("0.00"));
            e.Set("overlay", pe.Overlay.ToString());
            if (pe.Packed) e.Set("packer", pe.PackerName);
            if (pe.ImportDlls.Count > 0) e.Set("imports", string.Join(",", pe.ImportDlls.Take(40)));
        }

        void AddPeEvidence(Entity e, PeInfo pe, TrustClass tc, PathClass pc, TrustInfo ti)
        {
            if (pe == null || !pe.IsPe) return;
            bool userWritable = PathUtil.IsUserWritable(e.Location);
            if (pe.Bloated) e.Add(new Evidence("PE.BLOATED", EvidenceCategory.Content, 35, "Executable inflated with hundreds of MB of repeated padding (used to slip past scanners)", FormatSize(pe.FileSize)));
            else if (pe.Overlay > 50L * 1024 * 1024 && !(tc == TrustClass.TrustedPublisher)) e.Add(new Evidence("PE.HUGE_OVERLAY", EvidenceCategory.Content, 6, "Very large appended data after the program image", FormatSize(pe.Overlay)));
            if (pe.Packed && userWritable) e.Add(new Evidence("PE.PACKED", EvidenceCategory.Content, 5, "Packed/protected with " + pe.PackerName, pe.PackerName));
            if (pe.MaxExecEntropy >= 7.3 && userWritable && tc != TrustClass.TrustedPublisher) e.Add(new Evidence("PE.HIGH_ENTROPY", EvidenceCategory.Content, 7, "Executable code section is encrypted/compressed (entropy " + pe.MaxExecEntropy.ToString("0.0") + ")"));
            if (pe.LooksInjector && userWritable) e.Add(new Evidence("PE.INJECTOR_IMPORTS", EvidenceCategory.Content, 4, "Imports the API set used for process injection/hollowing", string.Join(",", pe.ApiOfInterest.Take(8))));
            // obfuscated / encrypted .NET loaders: big managed file, no version information at all, high entropy, unsigned, in a user folder
            if (pe.IsDotNet && userWritable && tc != TrustClass.TrustedPublisher && string.IsNullOrWhiteSpace(pe.Company) && string.IsNullOrWhiteSpace(pe.Product) && string.IsNullOrWhiteSpace(pe.Description) && pe.MaxExecEntropy >= 6.4 && pe.FileSize > 300 * 1024)
                e.Add(new Evidence("PE.DOTNET_OBFUSCATED_HINT", EvidenceCategory.Content, 12, ".NET program without any version information and with encrypted/obfuscated content (typical of malware loaders)", "entropy " + pe.MaxExecEntropy.ToString("0.0") + ", " + FormatSize(pe.FileSize)));
            if (pe.IsDriver && pe.ImportsNativeKernel && userWritable) e.Add(new Evidence("PE.DRIVER_USER_PATH", EvidenceCategory.Content, 20, "Kernel driver stored in a user-writable location"));

            // version information claims a big vendor but the file is not signed by it
            // (only a strong signal when the file pretends to be a Windows OS component; redistributed Microsoft/Google/etc. builds - OpenJDK, VC++ redist,
            //  Chrome for Testing - legitimately ship unsigned copies, so they only get a token weight)
            string claim = (pe.Company ?? "") + " " + (pe.Product ?? "");
            string osClaim = claim + " " + (pe.Description ?? "");
            // every real Windows component says exactly "Microsoft(R) Windows(R) Operating System"; other Microsoft-branded products (DirectX Shader Compiler
            // shipped inside Chrome/Dawn, VC++ runtimes, .NET) are redistributed unsigned by many vendors and must not be treated as impersonation
            bool claimsOs = Regex.IsMatch(pe.Product ?? "", @"^\s*Microsoft.{0,3}\s+Windows.{0,3}\s+Operating\s+System\s*$", RegexOptions.IgnoreCase) && (pe.Company ?? "").IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
            if (claimsOs && tc != TrustClass.MicrosoftSigned && userWritable)
                e.Add(new Evidence("MASQ.FAKE_VENDOR_INFO", EvidenceCategory.Masquerade, 22, "Version info says \"Microsoft Windows\" but the file is not signed by Microsoft", claim.Trim()));
            else if (tc != TrustClass.MicrosoftSigned && tc != TrustClass.TrustedPublisher && (ti == null || !ti.IsValid) && userWritable)
            {
                foreach (var v in new[] { "Microsoft", "NVIDIA", "Intel", "Realtek", "Advanced Micro Devices", "Google", "Adobe" })
                    if (claim.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0)
                    { e.Add(new Evidence("MASQ.FAKE_VENDOR_INFO", EvidenceCategory.Masquerade, 3, "Version info claims \"" + v + "\" but the file is unsigned (common for redistributed/bundled builds)", claim.Trim())); break; }
            }

            // miner tool file names
            string stem = Path.GetFileNameWithoutExtension(e.Location).ToLowerInvariant();
            foreach (var m in ctx.Rules.MinerFileNames)
                if (stem == m || stem.StartsWith(m + "-") || stem.StartsWith(m + "_") || stem.StartsWith(m + "."))
                { e.Add(new Evidence("NAME.MINER_TOOL", EvidenceCategory.Content, 25, "File name matches a known miner program (" + m + ")", e.Title)); break; }
            if (pe.OriginalName != null)
            {
                string on = Path.GetFileNameWithoutExtension(pe.OriginalName).ToLowerInvariant();
                foreach (var m in ctx.Rules.MinerFileNames)
                    if (on == m) { e.Add(new Evidence("NAME.MINER_ORIGINAL", EvidenceCategory.Content, 30, "Embedded original file name is a known miner (" + m + ")", pe.OriginalName)); break; }
            }
        }

        static string FormatSize(long n)
        {
            if (n > 1L << 30) return (n / (double)(1L << 30)).ToString("0.0") + " GB";
            if (n > 1L << 20) return (n / (double)(1L << 20)).ToString("0.0") + " MB";
            return (n / 1024.0).ToString("0") + " KB";
        }

        void StringScan(Entity e, string path)
        {
            long read;
            var hits = ctx.Rules.MinerScanner.ScanFile(path, ctx.Options.StringScanHeadBytes, ctx.Options.StringScanTailBytes, out read);
            Interlocked.Add(ref ctx.Stats.BytesRead, read);
            EvaluateMinerStrings(e, hits, "binary");
        }

        void ScriptScan(Entity e, string path, long len)
        {
            try
            {
                int take = (int)Math.Min(len, 512 * 1024);
                var buf = new byte[take];
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) take = fs.Read(buf, 0, take);
                var hits = ctx.Rules.MinerScanner.ScanBytes(buf, take);
                EvaluateMinerStrings(e, hits, "script");
                string text = Encoding.UTF8.GetString(buf, 0, take);
                bool? partOfSignedProduct = null;      // evaluated lazily: only scripts that actually match something need the (slower) sibling signature check
                foreach (var r in ctx.Rules.CmdRules)
                    if (r.Rx.IsMatch(text) && (r.Category == "Tamper" || r.Category == "Persistence" || r.Id.StartsWith("CMD.MINER")))
                    {
                        bool miner = r.Id.StartsWith("CMD.MINER");
                        int w = Math.Max(6, r.Weight - 6);
                        // installer/helper scripts of real, signed products (Node.js install_tools.bat, Python, JetBrains ...) legitimately download and run things;
                        // miner-specific content is never softened
                        bool downloader = !miner && r.Id.IndexOf("DOWNLOAD", StringComparison.OrdinalIgnoreCase) >= 0;     // only download-and-run patterns are softened, never Defender tampering
                        if (downloader)
                        {
                            if (partOfSignedProduct == null) partOfSignedProduct = SiblingIsSignedProduct(path);
                            if (partOfSignedProduct == true) w = Math.Max(4, w / 3);
                        }
                        e.Add(new Evidence("SCRIPT." + r.Id.Substring(4), ParseCat(r.Category), w, "Script contains: " + r.Text + (downloader && partOfSignedProduct == true ? " (the script sits next to a signed program of a known publisher: weight reduced)" : ""), e.Location, r.Definitive && r.Id.StartsWith("CMD.MINER.DONATE")));
                    }
            }
            catch { }
        }

        /// <summary>True when the folder (or its parent) holds a validly signed executable of Microsoft or a trusted publisher - the script is then part of that product.</summary>
        bool SiblingIsSignedProduct(string scriptPath)
        {
            try
            {
                var pc = PathUtil.Classify(scriptPath);
                if (pc == PathClass.UserTemp || pc == PathClass.WindowsTemp || pc == PathClass.UserDownloads || pc == PathClass.RecycleBin || pc == PathClass.Public) return false;     // droppers live there; a signed program copied next to a script proves nothing
                string dir = Path.GetDirectoryName(scriptPath);
                for (int up = 0; up < 2 && !string.IsNullOrEmpty(dir); up++, dir = Path.GetDirectoryName(dir))
                {
                    int checkedFiles = 0;
                    foreach (var f in Directory.EnumerateFiles(dir, "*.exe"))
                    {
                        if (++checkedFiles > 6) break;
                        var ti = Trust.Check(f);
                        if (ti.IsValid) return true;       // any validly signed program (trusted root chain): the folder is an installed product, not a dropper directory
                    }
                }
            }
            catch { }
            return false;
        }

        public static EvidenceCategory ParseCat(string c) { EvidenceCategory ec; return Enum.TryParse(c, true, out ec) ? ec : EvidenceCategory.Content; }

        void EvaluateMinerStrings(Entity e, Dictionary<int, int> hits, string kind)
        {
            if (hits.Count == 0) return;
            var byGroup = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var id in hits.Keys)
            {
                if (id >= ctx.Rules.ScanIndex.Count) continue;
                var kv = ctx.Rules.ScanIndex[id];
                List<string> l; if (!byGroup.TryGetValue(kv.Key, out l)) byGroup[kv.Key] = l = new List<string>();
                if (!l.Contains(kv.Value)) l.Add(kv.Value);
            }
            int distinct = byGroup.Values.Sum(l => l.Count);
            int groups = byGroup.Count(kv => kv.Value.Count > 0 && kv.Key != "tuning");
            bool proto = byGroup.ContainsKey("protocol");
            string sample = string.Join(", ", byGroup.SelectMany(kv => kv.Value).Take(8));
            if (proto && distinct >= 3 && groups >= 2)
                e.Add(new Evidence("CONTENT.MINER.STRINGS_STRONG", EvidenceCategory.Content, 48, "Contains cryptominer protocol, algorithm and program strings (" + distinct + " markers)", sample, true));
            else if (distinct >= 4 && groups >= 2)
                e.Add(new Evidence("CONTENT.MINER.STRINGS_MANY", EvidenceCategory.Content, 40, "Contains many cryptominer markers (" + distinct + ")", sample, false));
            else if (distinct >= 2 && groups >= 2)
                e.Add(new Evidence("CONTENT.MINER.STRINGS_SOME", EvidenceCategory.Content, 20, "Contains several cryptominer markers (" + distinct + ")", sample));
            else if (proto || byGroup.ContainsKey("program"))
                e.Add(new Evidence("CONTENT.MINER.STRINGS_ONE", EvidenceCategory.Content, 8, "Contains a cryptominer marker", sample));
        }
    }
}
