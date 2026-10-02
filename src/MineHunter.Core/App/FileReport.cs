using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using MineHunter.Analysis;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter
{
    public enum FileVerdict { NoThreatSigns, KnownTrusted, NoData, Suspicious, Dangerous, KnownMalware, Unreadable }

    /// <summary>Everything the local static analyzer knows about one file, in the three groups the window shows: overview, why it is (not) suspicious, technical data.</summary>
    public sealed class FileReport
    {
        // overview
        public string Path, Name, Kind, Sha256, Sha1, Md5, Location, Origin, ZoneId, HostUrl, ReferrerUrl, Owner;
        public long Size; public DateTime Created, Modified;
        public string Publisher, SignatureText, CertSubject; public TrustInfo Trust; public bool TrustedPublisher;
        public string Company, Product, Description, FileVersion, OriginalName, InternalName;
        public FileVerdict Verdict; public string VerdictText, Explanation; public int Score; public RiskEngine.Score Detail;
        public List<RepResult> Reputation = new List<RepResult>(); public RepStatus ReputationOverall;
        // why
        public List<Evidence> Evidence = new List<Evidence>();
        public List<string> RulesFired = new List<string>();
        // technical
        public PeInfo Pe; public List<string> CertChain = new List<string>(); public string Manifest, ExecutionLevel;
        public List<string> Packers = new List<string>();
        public List<string> Urls = new List<string>(), Domains = new List<string>(), Ips = new List<string>(), PowerShell = new List<string>(), MinerMarkers = new List<string>();
        public string Error;

        public bool IsPe { get { return Pe != null && Pe.IsPe; } }
    }

    /// <summary>The local static analyzer. It reads a file, never runs it. It uses the same engine as the scans (signature, PE layout, strings, rule pack, scoring), so the
    /// verdict of "check this file" is the verdict a scan would give the same file.</summary>
    public static class FileAnalyzer
    {
        static string L(string en, string ru) { return Loc.L(en, ru); }

        static readonly Regex UrlRx = new Regex(@"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}", RegexOptions.Compiled);
        static readonly Regex IpRx = new Regex(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", RegexOptions.Compiled);
        static readonly Regex DomainRx = new Regex(@"\b(?:[a-z0-9](?:[a-z0-9\-]{0,40}[a-z0-9])?\.)+(?:com|net|org|ru|io|xyz|top|info|biz|cc|su|me|tk|ml|ga|cf|gq|pw|site|online|cloud|dev|app|to|ws|in|cn|ua|kz|by)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly string[] PsFragments = { "powershell", "-enc ", "-encodedcommand", "invoke-expression", "iex(", "iex ", "frombase64string", "downloadstring", "downloadfile", "net.webclient", "-windowstyle hidden", "-executionpolicy bypass", "-nop ", "invoke-webrequest", "start-bitstransfer", "add-mppreference", "set-mppreference", "[reflection.assembly]::load", "amsiutils", "vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set", "schtasks /create", "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run" };

        public static FileReport Analyze(string path, Settings settings = null, bool online = true, IReputationProvider extraProvider = null, CancellationToken ct = default(CancellationToken))
        {
            var r = new FileReport { Path = path, Name = System.IO.Path.GetFileName(path) };
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) { r.Verdict = FileVerdict.Unreadable; r.VerdictText = L("The file does not exist.", "Файл не найден."); r.Error = "missing"; return r; }
                r.Size = fi.Length; r.Created = fi.CreationTime; r.Modified = fi.LastWriteTime;
                try { r.Sha256 = Hashing.Sha256(path); r.Sha1 = Hashing.Sha1(path); r.Md5 = Hashing.Md5(path); } catch { }
                if (r.Sha256 == null) { r.Verdict = FileVerdict.Unreadable; r.VerdictText = L("The file cannot be read (in use or no access).", "Файл не читается (занят или нет доступа)."); r.Error = "unreadable"; return r; }

                // run the engine on this one file
                var rules = RulePack.Load();
                if (settings != null) foreach (var p in settings.ExcludedPublishers) rules.UserTrustedPublishers.Add(p);
                var allow = Allowlist.Load();
                var opt = new ScanOptions { Mode = ScanMode.Custom, UseCache = false, UserSettings = settings, IncludeSelf = true };
                var ctx = new ScanContext(rules, allow, opt, ct);
                var e = ctx.Files.Inspect(path, FileRole.HotDir);
                if (e != null)
                {
                    r.Location = PathClassText(e.P("pathClass"));
                    Provenance.Fill(e);
                    r.Origin = e.P("origin") == null ? null : Loc.Origin(e.P("origin")); r.ZoneId = e.P("zoneId"); r.HostUrl = e.P("hostUrl"); r.ReferrerUrl = e.P("referrerUrl"); r.Owner = e.P("fileOwner");
                    r.Evidence = e.Evidence.Where(x => x.Weight != 0).OrderByDescending(x => x.Weight).ToList();
                    r.RulesFired = r.Evidence.Select(x => x.RuleId).Distinct().ToList();
                    r.Detail = RiskEngine.Compute(new[] { e });
                    r.Score = (int)Math.Round(Math.Min(100, r.Detail.Total));
                }
                r.Trust = Trust.Check(path);
                if (r.Trust != null)
                {
                    r.Publisher = r.Trust.Publisher; r.CertSubject = r.Trust.Subject;
                    r.TrustedPublisher = r.Trust.IsValid && (rules.IsTrustedPublisher(r.Trust.Publisher) || (r.Trust.Publisher ?? "").StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase));
                    r.SignatureText = SignatureText(r.Trust);
                }
                // type and PE data
                var pe = PeAnalyzer.Analyze(path, true, true);
                if (pe.IsPe) { r.Pe = pe; r.Company = pe.Company; r.Product = pe.Product; r.Description = pe.Description; r.FileVersion = pe.FileVersion; r.OriginalName = pe.OriginalName; r.InternalName = pe.InternalName; }
                r.Kind = KindOf(path, pe);
                if (pe.IsPe) { if (pe.PackerName != null) r.Packers.Add(pe.PackerName); if (pe.MaxExecEntropy >= 7.3) r.Packers.Add(L("high entropy in the code section (packed or encrypted)", "высокая энтропия секции кода (упакован или зашифрован)")); }
                if (pe.IsPe) ReadManifest(path, r);
                r.CertChain = CertChain(path);
                ExtractStrings(path, r, rules);
                // reputation
                r.Reputation = Reputation.Lookup(r.Sha256, r.Size, rules, allow, online ? settings : null, extraProvider);
                if (!online) r.Reputation = r.Reputation.Where(x => x.Provider != "VirusTotal").ToList();
                r.ReputationOverall = Reputation.Combine(r.Reputation);
                Decide(r, rules);
            }
            catch (Exception ex) { r.Error = ex.Message; if (r.VerdictText == null) { r.Verdict = FileVerdict.Unreadable; r.VerdictText = L("The file could not be analysed: ", "Файл не удалось проанализировать: ") + ex.Message; } }
            return r;
        }

        // ------------------------------------------------------------------------------------------------ verdict
        static void Decide(FileReport r, RulePack rules)
        {
            string why;
            Verdict v = r.Detail != null ? RiskEngine.Decide(r.Detail, out why) : Model.Verdict.Clean;
            bool tool = r.Evidence.Any(x => x.RuleId.StartsWith("TOOL."));
            bool mnr = r.Evidence.Any(x => !x.RuleId.StartsWith("TOOL.") && x.Weight > 0 && RiskEngine.HasThreatEvidence(new[] { new Entity { Evidence = new List<Evidence> { x } } }));
            if (tool && !mnr && v > Model.Verdict.Suspicious) v = Model.Verdict.Suspicious;
            bool trustedSig = r.TrustedPublisher || (r.Trust != null && r.Trust.State == TrustState.ValidCatalog);
            var strongest = r.Evidence.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Take(3).Select(x => Loc.Ev(x)).ToList();

            if (r.ReputationOverall == RepStatus.KnownBad || r.Evidence.Any(x => x.RuleId.StartsWith("REP.KNOWN_BAD")))
            {
                r.Verdict = FileVerdict.KnownMalware; r.VerdictText = L("Known malicious file", "Известный вредоносный файл");
                r.Explanation = L("Its SHA-256 matches a file that is known to be malicious. Do not run it.", "Его SHA-256 совпадает с известным вредоносным файлом. Не запускайте его.");
            }
            else if (v >= Model.Verdict.HighRisk)
            {
                r.Verdict = FileVerdict.Dangerous; r.VerdictText = L("Dangerous: several independent signs of a threat", "Опасно: несколько независимых признаков угрозы");
                r.Explanation = L("Different kinds of evidence agree: ", "Разные виды признаков совпали: ") + string.Join("; ", strongest) + ".";
            }
            else if (v == Model.Verdict.Suspicious || r.Score >= RiskEngine.ObservationAt && !trustedSig)
            {
                r.Verdict = FileVerdict.Suspicious; r.VerdictText = L("Suspicious signs found", "Есть подозрительные признаки");
                r.Explanation = (tool ? L("It looks like a game cheat / hack tool: such programs are packed and unsigned and look alarming, but that does not make them a miner or a virus. ", "Похоже на игровой чит / хак-утилиту: такие программы упакованы, без подписи и выглядят тревожно, но это ещё не майнер и не вирус. ") : "")
                                + (strongest.Count > 0 ? L("What was noticed: ", "Что замечено: ") + string.Join("; ", strongest) + "." : "")
                                + L(" This is a reason to look closer, not proof.", " Это повод присмотреться, а не доказательство.");
            }
            else if (trustedSig || r.ReputationOverall == RepStatus.KnownGood)
            {
                r.Verdict = FileVerdict.KnownTrusted; r.VerdictText = L("Known trusted file", "Известный доверенный файл");
                r.Explanation = trustedSig ? L("It carries a valid digital signature of " + r.Publisher + ", a publisher on the trusted list, and nothing in it contradicts that.", "Он несёт действующую цифровую подпись " + r.Publisher + " (издатель из списка доверенных), и ничто в файле этому не противоречит.")
                                           : L("Local reputation lists know this exact file as good.", "Локальные списки репутации знают именно этот файл как безопасный.");
            }
            else if (r.Trust != null && r.Trust.IsValid)
            {
                r.Verdict = FileVerdict.NoThreatSigns; r.VerdictText = L("No signs of a threat found", "Признаков угрозы не обнаружено");
                r.Explanation = L("It is signed by " + r.Publisher + " (not on the trusted list) and nothing suspicious was found. A signature shows who published it, not that it is harmless.", "Он подписан " + r.Publisher + " (нет в списке доверенных), ничего подозрительного не найдено. Подпись показывает, кто издатель, но не гарантирует безвредность.");
            }
            else
            {
                r.Verdict = FileVerdict.NoData; r.VerdictText = L("No signs of a threat found, but no data about this file", "Признаков угрозы не обнаружено, но данных об этом файле нет");
                r.Explanation = L("It is not signed and no reputation source knows it. Nothing suspicious was found by the checks, which is not the same as the file being safe: if you do not know where it came from, do not run it.", "Файл без подписи, и ни один источник репутации его не знает. Проверки ничего подозрительного не нашли, но это не значит, что файл безопасен: если не знаете, откуда он, не запускайте.");
            }
            if (r.Origin != null && r.Verdict != FileVerdict.KnownTrusted) r.Explanation += " " + r.Origin + ".";
        }

        static string PathClassText(string pc)
        {
            switch (pc)
            {
                case "WindowsSystem": return L("Windows system folder", "Системная папка Windows");
                case "WindowsOther": return L("Windows folder", "Папка Windows");
                case "WindowsTemp": return L("Windows temporary folder", "Временная папка Windows");
                case "ProgramFiles": return L("Program Files", "Program Files");
                case "ProgramData": return "ProgramData";
                case "UserTemp": return L("Temp folder of a user", "Папка Temp пользователя");
                case "UserAppDataRoamingRoot": case "UserAppDataRoaming": return @"AppData\Roaming";
                case "UserAppDataLocalRoot": case "UserAppDataLocal": return @"AppData\Local";
                case "UserAppDataLocalPrograms": return @"AppData\Local\Programs";
                case "UserDownloads": return L("Downloads", "Загрузки");
                case "UserDesktopDocs": return L("Desktop / Documents", "Рабочий стол / Документы");
                case "UserProfileOther": return L("User profile", "Профиль пользователя");
                case "Public": return L("Public folder", "Общая папка (Public)");
                case "RecycleBin": return L("Recycle Bin", "Корзина");
                case "DriveRoot": return L("Drive root", "Корень диска");
                default: return L("Other place", "Другое место");
            }
        }

        static string SignatureText(TrustInfo t)
        {
            switch (t.State)
            {
                case TrustState.Valid: return L("Valid signature", "Подпись действительна") + (t.Publisher != null ? ": " + t.Publisher : "");
                case TrustState.ValidCatalog: return L("Signed through the Windows catalog", "Подписан через каталог Windows") + (t.Publisher != null ? ": " + t.Publisher : "");
                case TrustState.Unsigned: return L("Not signed", "Не подписан");
                case TrustState.ExpiredCert: return L("The certificate has expired", "Срок сертификата истёк") + (t.Publisher != null ? ": " + t.Publisher : "");
                case TrustState.UntrustedRoot: return L("Signed, but the issuer is not trusted by Windows", "Подписан, но издатель не доверен Windows");
                case TrustState.Tampered: return L("The signature is BROKEN: the file was changed after signing", "Подпись НАРУШЕНА: файл изменён после подписания");
                case TrustState.Revoked: return L("The certificate was revoked", "Сертификат отозван");
                default: return L("The signature could not be checked", "Подпись проверить не удалось");
            }
        }

        static string KindOf(string path, PeInfo pe)
        {
            string ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
            if (pe.IsPe)
            {
                string bits = pe.Is64 ? "64-bit" : "32-bit";
                if (pe.IsDriver) return L("Windows driver (" + bits + ")", "Драйвер Windows (" + bits + ")");
                if (pe.IsDotNet) return pe.IsDll ? L(".NET library (" + bits + ")", "Библиотека .NET (" + bits + ")") : L(".NET program (" + bits + ")", "Программа .NET (" + bits + ")");
                return pe.IsDll ? L("Program library, DLL (" + bits + ")", "Библиотека DLL (" + bits + ")") : L("Windows program, EXE (" + bits + ")", "Программа Windows, EXE (" + bits + ")");
            }
            switch (ext)
            {
                case ".ps1": case ".psm1": return L("PowerShell script", "Скрипт PowerShell");
                case ".bat": case ".cmd": return L("Command script", "Командный скрипт");
                case ".vbs": case ".vbe": return L("VBScript", "Скрипт VBScript");
                case ".js": case ".jse": return L("JavaScript (Windows Script Host)", "Скрипт JavaScript (Windows Script Host)");
                case ".hta": return L("HTML application", "HTML-приложение");
                case ".lnk": return L("Shortcut", "Ярлык");
                case ".zip": case ".7z": case ".rar": return L("Archive", "Архив");
                case ".iso": case ".vhd": case ".vhdx": return L("Disk image", "Образ диска");
                case ".jar": return L("Java archive", "Java-архив");
                case ".msi": return L("Windows Installer package", "Пакет Windows Installer");
                default: return L("File", "Файл") + (ext.Length > 0 ? " " + ext : "");
            }
        }

        static void ReadManifest(string path, FileReport r)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long len = Math.Min(fs.Length, 16L * 1024 * 1024);
                    var buf = new byte[len]; int got = fs.Read(buf, 0, buf.Length);
                    string s = Encoding.UTF8.GetString(buf, 0, got);
                    int a = s.IndexOf("<assembly", StringComparison.Ordinal), b = a < 0 ? -1 : s.IndexOf("</assembly>", a, StringComparison.Ordinal);
                    if (a >= 0 && b > a)
                    {
                        r.Manifest = s.Substring(a, Math.Min(b + 11 - a, 6000));
                        var m = Regex.Match(r.Manifest, "requestedExecutionLevel[^>]*level=\"([A-Za-z]+)\"");
                        if (m.Success) r.ExecutionLevel = m.Groups[1].Value;
                    }
                }
            }
            catch { }
        }

        static List<string> CertChain(string path)
        {
            var list = new List<string>();
            try
            {
                var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.Build(cert);
                    foreach (var el in chain.ChainElements) list.Add(el.Certificate.Subject + "  [" + el.Certificate.NotBefore.ToString("yyyy-MM-dd") + " .. " + el.Certificate.NotAfter.ToString("yyyy-MM-dd") + "]");
                }
            }
            catch { }
            return list;
        }

        // ------------------------------------------------------------------------------------------------ strings
        static void ExtractStrings(string path, FileReport r, RulePack rules)
        {
            try
            {
                byte[] data;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long head = Math.Min(fs.Length, 8L * 1024 * 1024);
                    data = new byte[head]; int got = fs.Read(data, 0, data.Length); if (got < data.Length) Array.Resize(ref data, got);
                }
                var text = new StringBuilder();
                // ASCII runs
                int start = -1;
                for (int i = 0; i <= data.Length; i++)
                {
                    bool printable = i < data.Length && data[i] >= 0x20 && data[i] < 0x7F;
                    if (printable) { if (start < 0) start = i; }
                    else { if (start >= 0 && i - start >= 6) text.Append(Encoding.ASCII.GetString(data, start, Math.Min(i - start, 400))).Append('\n'); start = -1; }
                    if (text.Length > 3_000_000) break;
                }
                // UTF-16LE runs (letters followed by a zero byte)
                var sb = new StringBuilder();
                for (int i = 0; i + 1 < data.Length && text.Length < 4_000_000; i += 2)
                {
                    if (data[i + 1] == 0 && data[i] >= 0x20 && data[i] < 0x7F) sb.Append((char)data[i]);
                    else { if (sb.Length >= 6) text.Append(sb.ToString(0, Math.Min(sb.Length, 400))).Append('\n'); sb.Clear(); }
                }
                string all = text.ToString();
                foreach (Match m in UrlRx.Matches(all)) { if (r.Urls.Count < 40 && !r.Urls.Contains(m.Value) && !IsNoiseUrl(m.Value)) r.Urls.Add(m.Value); }
                foreach (Match m in IpRx.Matches(all)) { if (r.Ips.Count < 40 && !r.Ips.Contains(m.Value) && !m.Value.StartsWith("0.") && !m.Value.StartsWith("127.") && !m.Value.EndsWith(".0.0")) r.Ips.Add(m.Value); }
                foreach (Match m in DomainRx.Matches(all)) { string d = m.Value.ToLowerInvariant(); if (r.Domains.Count < 60 && !r.Domains.Contains(d) && !IsNoiseDomain(d)) r.Domains.Add(d); }
                string low = all.ToLowerInvariant();
                foreach (var f in PsFragments) if (low.Contains(f) && r.PowerShell.Count < 20) r.PowerShell.Add(f.Trim());
                if (rules != null && rules.MinerScanner != null)
                {
                    try
                    {
                        var hits = rules.MinerScanner.ScanBytes(data, data.Length);
                        foreach (var id in hits.Keys.Take(12)) { if (id < 0 || id >= rules.ScanIndex.Count) continue; var kv = rules.ScanIndex[id]; r.MinerMarkers.Add(kv.Key + ": " + kv.Value); }
                    }
                    catch { }
                }
            }
            catch { }
        }

        static bool IsNoiseUrl(string u) { return u.Contains("schemas.microsoft.com") || u.Contains("www.w3.org") || u.Contains("schemas.openxmlformats") || u.Contains("purl.org") || u.Contains("ns.adobe.com") || u.Contains("crl.") || u.Contains("ocsp.") || u.Contains("verisign.com") || u.Contains("digicert.com") || u.Contains("globalsign.com") || u.Contains("sectigo.com") || u.Contains("example.com"); }
        static bool IsNoiseDomain(string d) { return d.EndsWith("microsoft.com") || d.EndsWith("w3.org") || d.EndsWith("digicert.com") || d.EndsWith("verisign.com") || d.EndsWith("example.com") || d.EndsWith("openxmlformats.org") || d.EndsWith("globalsign.com") || d.EndsWith("sectigo.com") || d.Length < 5; }
    }
}
