using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Update
{
    public sealed class AppConfig
    {
        /// <summary>Public location of version.json (for example the raw file of your GitHub repository). Empty = update checks are off.</summary>
        public string UpdateManifestUrl = DefaultManifestUrl;
        public bool CheckUpdatesOnStart = true;
        public bool AutoScanOnStart = true;
        public bool AutoUpdateRules = true;   // install newer, verified rule packs automatically
        public bool ScanBrowsers = true;
        public bool ScanMemory = true;
        public string Language = "auto";
        /// <summary>RSA public key (XML) used to verify signed rule packs. Empty = packs are verified by SHA-256 only.</summary>
        public string UpdatePublicKeyXml = DefaultPublicKeyXml;
        public string GitHubRepo = DefaultGitHubRepo;       // shown in the UI as the project page

        // Where the official project lives. Forks change these three constants (and sign their own rule packs with their own key).
        public const string DefaultGitHubRepo = "https://github.com/ilyasaffonovv-commits/MineHunter";
        public const string DefaultManifestUrl = "https://raw.githubusercontent.com/ilyasaffonovv-commits/MineHunter/main/version.json";
        // RSA public key of the project's rule-pack signing key. Rule packs are accepted only if signed by the matching private key (kept off GitHub).
        public const string DefaultPublicKeyXml = "<RSAKeyValue><Modulus>1DqbLCV1COyHXhRdv3AZBqqrUEcbibDNREmbJ+9r/gGK65gGLiZYtUTHjPB/78bAdfnCYsV0ZVn0NCIb76iU0yydmMzmjD7GusHZmdqSak9XHIufDCcTGGALUay+posdB9u7OmDdsa6XGQf7C4EQkZ4zHWNKQzKA1Hg7JitUfCnnH+mQ/JA1W7lGuXbkqwcvz8ec9J+5QXcrsI3GTOCPoLzdAe3FMvXz3knU5BF1Mke0veGf7zVxwRibAyeeyh6vPO5Eppob7PzhWZqBwX+2/AAKAlG8DwlnQSqPX9t0sWvlHMerR0TdLbrxGbIIzVFKf65/UXRrWDqL7keT212HBJ2m3sPK77eBOIfu4YDj96vV7bbdTerKMvwuzjwOVEXJTmnEr5J6+7Y4pkJqmjY4ud7yF+9s50tQN9hUrT2Hnf8LTYkNJ3CqutZ/xeK3yXG16/lQuYhCfxEmFkpPeDCnX6BBHHm3/6dc8JzGR3bCr0Z2nQS6S4aBKSVuu7fZM+oZ</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public static string InstallConfig { get { return Path.Combine(RulePack.InstallDir, "config.json"); } }
        public static string UserConfig { get { return Path.Combine(RulePack.DataDir, "config.json"); } }

        public static AppConfig Load()
        {
            var c = new AppConfig();
            foreach (var f in new[] { InstallConfig, UserConfig })
            {
                try
                {
                    if (!File.Exists(f)) continue;
                    var d = Json.Obj(Json.Parse(File.ReadAllText(f)));
                    if (d.ContainsKey("updateManifestUrl")) c.UpdateManifestUrl = Json.Str(d, "updateManifestUrl", c.UpdateManifestUrl);
                    if (d.ContainsKey("checkUpdatesOnStart")) c.CheckUpdatesOnStart = Json.Bool(d, "checkUpdatesOnStart", true);
                    if (d.ContainsKey("autoScanOnStart")) c.AutoScanOnStart = Json.Bool(d, "autoScanOnStart", true);
                    if (d.ContainsKey("autoUpdateRules")) c.AutoUpdateRules = Json.Bool(d, "autoUpdateRules", true);
                    if (d.ContainsKey("scanBrowsers")) c.ScanBrowsers = Json.Bool(d, "scanBrowsers", true);
                    if (d.ContainsKey("scanMemory")) c.ScanMemory = Json.Bool(d, "scanMemory", true);
                    if (d.ContainsKey("language")) c.Language = Json.Str(d, "language", "auto");
                    if (!string.IsNullOrWhiteSpace(Json.Str(d, "updatePublicKeyXml", ""))) c.UpdatePublicKeyXml = Json.Str(d, "updatePublicKeyXml", "");
                    if (!string.IsNullOrWhiteSpace(Json.Str(d, "gitHubRepo", ""))) c.GitHubRepo = Json.Str(d, "gitHubRepo", "");
                }
                catch (Exception ex) { Log.Warn("config " + f + ": " + ex.Message); }
            }
            return c;
        }

        public void SaveUser()
        {
            try
            {
                Directory.CreateDirectory(RulePack.DataDir);
                // Only values that differ from the built-in defaults are stored, so a later version that changes a default (new signing key, new repository) is not
                // silently overridden by an old copy saved here.
                var d = new Dictionary<string, object>
                { { "checkUpdatesOnStart", CheckUpdatesOnStart }, { "autoScanOnStart", AutoScanOnStart }, { "autoUpdateRules", AutoUpdateRules }, { "scanBrowsers", ScanBrowsers }, { "scanMemory", ScanMemory }, { "language", Language } };
                if (UpdateManifestUrl != DefaultManifestUrl) d["updateManifestUrl"] = UpdateManifestUrl ?? "";
                if (UpdatePublicKeyXml != DefaultPublicKeyXml) d["updatePublicKeyXml"] = UpdatePublicKeyXml ?? "";
                if (GitHubRepo != DefaultGitHubRepo) d["gitHubRepo"] = GitHubRepo ?? "";
                File.WriteAllText(UserConfig, Json.Pretty(Json.Serialize(d)));
            }
            catch (Exception ex) { Log.Warn("config save: " + ex.Message); }
        }
    }

    public enum UpdateState { NotConfigured, Disabled, UpToDate, UpdateAvailable, Offline, Error }

    public sealed class UpdateInfo
    {
        public UpdateState State; public string Current = AppInfo.Version, Latest, ReleaseUrl, Notes, Message;
        public string RulesVersion, RulesUrl, RulesSha256, RulesSignature, LocalRulesVersion; public bool RulesNewer;
    }

    /// <summary>Update check. Privacy: it only DOWNLOADS the public version.json (a plain HTTPS GET, no identifiers, no telemetry,
    /// nothing from this computer is sent). Rule packs are accepted only after SHA-256 (and, if a key is configured, RSA signature) verification.</summary>
    public static class Updater
    {
        static HttpClient Client()
        {
            try { ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | (SecurityProtocolType)12288 | SecurityProtocolType.Tls12; } catch { try { ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; } catch { } }
            var c = new HttpClient { Timeout = TimeSpan.FromSeconds(7) };
            c.DefaultRequestHeaders.UserAgent.ParseAdd("MineHunter/" + AppInfo.Version);
            c.DefaultRequestHeaders.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true };
            return c;
        }

        /// <summary>https only. Plain http is accepted for loopback addresses (127.0.0.1 / localhost) so the update flow can be tested without leaving the machine.</summary>
        static bool AllowedScheme(Uri u) { return u.Scheme == Uri.UriSchemeHttps || (u.Scheme == Uri.UriSchemeHttp && u.IsLoopback); }

        public static int CompareVersions(string a, string b)
        {
            Func<string, int[]> p = s => (s ?? "0").TrimStart('v', 'V').Split('.', '-', '+').Select(x => { int n; return int.TryParse(new string(x.TakeWhile(char.IsDigit).ToArray()), out n) ? n : 0; }).Concat(new[] { 0, 0, 0, 0 }).Take(4).ToArray();
            var x1 = p(a); var y1 = p(b);
            for (int i = 0; i < 4; i++) if (x1[i] != y1[i]) return x1[i].CompareTo(y1[i]);
            return 0;
        }

        public static UpdateInfo Check(AppConfig cfg, string localRulesVersion)
        {
            var u = new UpdateInfo { LocalRulesVersion = localRulesVersion };
            if (!cfg.CheckUpdatesOnStart) { u.State = UpdateState.Disabled; u.Message = "Update check is switched off in the settings."; return u; }
            if (string.IsNullOrWhiteSpace(cfg.UpdateManifestUrl)) { u.State = UpdateState.NotConfigured; u.Message = "Update source is not configured yet (set updateManifestUrl in config.json once the project is on GitHub)."; return u; }
            try
            {
                Uri uri;
                if (!Uri.TryCreate(cfg.UpdateManifestUrl, UriKind.Absolute, out uri) || !AllowedScheme(uri)) { u.State = UpdateState.Error; u.Message = "The update address must be an https:// URL."; return u; }
                string body;
                using (var c = Client()) body = c.GetStringAsync(uri).GetAwaiter().GetResult();
                var d = Json.Obj(Json.Parse(body.TrimStart('﻿')));
                u.Latest = Json.Str(d, "latestVersion"); u.ReleaseUrl = Json.Str(d, "releaseUrl"); u.Notes = Json.Str(d, "notes");
                var rules = d.ContainsKey("rules") ? Json.Obj(d["rules"]) : null;
                if (rules != null) { u.RulesVersion = Json.Str(rules, "version"); u.RulesUrl = Json.Str(rules, "url"); u.RulesSha256 = Json.Str(rules, "sha256"); u.RulesSignature = Json.Str(rules, "signature"); u.RulesNewer = !string.IsNullOrEmpty(u.RulesVersion) && string.CompareOrdinal(u.RulesVersion, localRulesVersion ?? "") > 0; }
                if (string.IsNullOrEmpty(u.Latest)) { u.State = UpdateState.Error; u.Message = "version.json has no latestVersion."; return u; }
                if (CompareVersions(u.Latest, AppInfo.Version) > 0) { u.State = UpdateState.UpdateAvailable; u.Message = "A newer version " + u.Latest + " is available."; }
                else { u.State = UpdateState.UpToDate; u.Message = "You have the latest version (" + AppInfo.Version + ")."; }
            }
            catch (Exception ex)
            {
                var inner = ex is AggregateException ? ((AggregateException)ex).Flatten().InnerException : ex;
                bool net = inner is HttpRequestException || inner is WebException || inner is System.Threading.Tasks.TaskCanceledException || inner is System.Net.Sockets.SocketException;
                u.State = net ? UpdateState.Offline : UpdateState.Error; u.Message = net ? "Could not reach the update server (offline?). The scan works fully without internet." : "Update check failed: " + inner.Message;
            }
            return u;
        }

        /// <summary>Downloads and installs a newer rule pack. Returns null on success or an error text.</summary>
        public static string UpdateRules(AppConfig cfg, UpdateInfo info)
        {
            try
            {
                if (info == null || string.IsNullOrEmpty(info.RulesUrl)) return "no rule pack announced";
                Uri uri; if (!Uri.TryCreate(info.RulesUrl, UriKind.Absolute, out uri) || !AllowedScheme(uri)) return "rule pack address must be https";
                byte[] data;
                using (var c = Client()) { c.Timeout = TimeSpan.FromSeconds(30); data = c.GetByteArrayAsync(uri).GetAwaiter().GetResult(); }
                if (data.Length > 8 * 1024 * 1024) return "rule pack is unreasonably large";
                if (!string.IsNullOrEmpty(info.RulesSha256) && !string.Equals(Hashing.Sha256(data), info.RulesSha256.Trim(), StringComparison.OrdinalIgnoreCase)) return "SHA-256 of the downloaded rule pack does not match version.json - rejected";
                if (string.IsNullOrEmpty(info.RulesSha256)) return "version.json gives no SHA-256 for the rule pack - rejected";
                if (!string.IsNullOrWhiteSpace(cfg.UpdatePublicKeyXml))
                {
                    if (string.IsNullOrEmpty(info.RulesSignature)) return "a signing key is configured but the rule pack is not signed - rejected";
                    if (!VerifySignature(data, info.RulesSignature, cfg.UpdatePublicKeyXml)) return "the signature of the rule pack is invalid - rejected";
                }
                string text = Encoding.UTF8.GetString(data);
                var test = new RulePack(); test.Merge(text, "downloaded");    // must parse
                if (string.IsNullOrEmpty(test.Version)) return "rule pack has no version";
                string dir = Path.Combine(RulePack.DataDir, "rules");
                Directory.CreateDirectory(dir);
                string dst = Path.Combine(dir, "update-" + Path.GetFileName(uri.LocalPath).Replace("..", ""));
                if (!dst.EndsWith(".json")) dst += ".json";
                string tmp = dst + ".tmp";
                File.WriteAllBytes(tmp, data);
                if (File.Exists(dst)) File.Delete(dst);
                File.Move(tmp, dst);
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static bool VerifySignature(byte[] data, string signatureB64, string publicKeyXml)
        {
            try
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKeyXml);
                    return rsa.VerifyData(data, CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(signatureB64));
                }
            }
            catch { return false; }
        }

        // maintainer tools: create a key pair, sign a pack
        public static void GenerateKeys(string dir)
        {
            Directory.CreateDirectory(dir);
            using (var rsa = new RSACryptoServiceProvider(3072))
            {
                File.WriteAllText(Path.Combine(dir, "update_private.xml"), rsa.ToXmlString(true));
                File.WriteAllText(Path.Combine(dir, "update_public.xml"), rsa.ToXmlString(false));
            }
        }

        public static string Sign(string file, string privateXmlPath)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(File.ReadAllText(privateXmlPath));
                return Convert.ToBase64String(rsa.SignData(File.ReadAllBytes(file), CryptoConfig.MapNameToOID("SHA256")));
            }
        }
    }
}
