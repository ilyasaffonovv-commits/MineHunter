using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter
{
    /// <summary>What a source of reputation says about one file. "NoData" is not "safe": it only means that source has never seen the file.</summary>
    public enum RepStatus { NoData, KnownGood, Suspicious, KnownBad }

    public sealed class RepResult
    {
        public string Provider; public RepStatus Status = RepStatus.NoData; public string Detail;
        public int? Malicious, Total; public string FirstSeen, Signer; public bool Available = true;
    }

    public interface IReputationProvider
    {
        string Name { get; }
        RepResult Lookup(string sha256, long size);
    }

    /// <summary>Reputation sources, from the ones that never leave the PC to the optional online one. Only a SHA-256 (and a size) is ever sent anywhere, and only to a source
    /// the user switched on; a file is never uploaded by MineHunter.</summary>
    public static class Reputation
    {
        static string L(string en, string ru) { return Loc.L(en, ru); }

        public static List<RepResult> Lookup(string sha256, long size, RulePack rules, Allowlist allow, Settings s, IReputationProvider extra = null)
        {
            var list = new List<RepResult>();
            list.Add(new LocalReputation(rules, allow).Lookup(sha256, size));
            list.Add(new CloudReputation().Lookup(sha256, size));
            if (s != null && s.VirusTotalLookup)
            {
                string key = s.GetVirusTotalKey();
                list.Add(string.IsNullOrEmpty(key) ? new RepResult { Provider = "VirusTotal", Available = false, Detail = L("switched on, but no API key is set", "включено, но ключ API не задан") } : new VirusTotalProvider(key).Lookup(sha256, size));
            }
            if (extra != null) list.Add(extra.Lookup(sha256, size));
            return list;
        }

        /// <summary>The overall reading: a known-bad answer from any source wins; "suspicious" next; known-good only if some source says it and none disagrees; otherwise no data.</summary>
        public static RepStatus Combine(IEnumerable<RepResult> results)
        {
            var r = results.Where(x => x.Available).ToList();
            if (r.Any(x => x.Status == RepStatus.KnownBad)) return RepStatus.KnownBad;
            if (r.Any(x => x.Status == RepStatus.Suspicious)) return RepStatus.Suspicious;
            if (r.Any(x => x.Status == RepStatus.KnownGood)) return RepStatus.KnownGood;
            return RepStatus.NoData;
        }

        public static string StatusText(RepStatus s)
        {
            switch (s)
            {
                case RepStatus.KnownBad: return L("Known malicious", "Известное вредоносное");
                case RepStatus.Suspicious: return L("Suspicious", "Подозрительное");
                case RepStatus.KnownGood: return L("Known good", "Известный доверенный файл");
                default: return L("No data", "Нет данных");
            }
        }
    }

    /// <summary>The hash lists inside the rule pack (known bad / known good) and the user's own "this is mine" list. Nothing leaves the PC.</summary>
    public sealed class LocalReputation : IReputationProvider
    {
        readonly RulePack rules; readonly Allowlist allow;
        public LocalReputation(RulePack r, Allowlist a) { rules = r; allow = a; }
        public string Name { get { return Loc.L("This PC (rule pack)", "Этот ПК (набор правил)"); } }

        public RepResult Lookup(string sha256, long size)
        {
            var r = new RepResult { Provider = Name };
            if (string.IsNullOrEmpty(sha256)) { r.Detail = Loc.L("no hash", "нет хеша"); return r; }
            string family;
            if (rules != null && rules.BadHashes.TryGetValue(sha256, out family)) { r.Status = RepStatus.KnownBad; r.Detail = Loc.L("the hash is in the list of known malicious files: ", "хеш есть в списке известных вредоносных файлов: ") + family; return r; }
            if (allow != null && allow.Sha256.Contains(sha256)) { r.Status = RepStatus.KnownGood; r.Detail = Loc.L("you marked this exact file as safe", "вы пометили именно этот файл безопасным"); return r; }
            string good;
            if (rules != null && rules.GoodHashes.TryGetValue(sha256, out good)) { r.Status = RepStatus.KnownGood; r.Detail = Loc.L("the hash is in the list of known good files: ", "хеш есть в списке известных безопасных файлов: ") + good; return r; }
            r.Detail = Loc.L("this hash is in none of the local lists", "этого хеша нет ни в одном из локальных списков");
            return r;
        }
    }

    /// <summary>MineHunter Cloud (hash and size only) is a planned source. There is no server behind it in this version, so it answers "not available" and nothing is sent.</summary>
    public sealed class CloudReputation : IReputationProvider
    {
        public string Name { get { return "MineHunter Cloud"; } }
        public RepResult Lookup(string sha256, long size)
        {
            return new RepResult { Provider = Name, Available = false, Detail = Loc.L("not available in this version (no server yet); nothing is sent", "в этой версии недоступно (сервера пока нет); ничего не отправляется") };
        }
    }

    /// <summary>Optional: asks VirusTotal about a SHA-256 with the user's own key. It is a lookup of a hash, never an upload. The number of engines that flag a file is shown as
    /// a fact about the file, not as MineHunter's verdict.</summary>
    public sealed class VirusTotalProvider : IReputationProvider
    {
        readonly string key; readonly string baseUrl;
        public VirusTotalProvider(string apiKey, string baseUrlOverride = null) { key = apiKey; baseUrl = (baseUrlOverride ?? "https://www.virustotal.com/api/v3").TrimEnd('/'); }
        public string Name { get { return "VirusTotal"; } }

        public RepResult Lookup(string sha256, long size)
        {
            var r = new RepResult { Provider = Name };
            try
            {
                if (string.IsNullOrEmpty(sha256) || sha256.Length != 64 || !sha256.All(Uri.IsHexDigit)) { r.Detail = "no valid hash"; return r; }
                using (var c = Update.Updater.Client())
                {
                    c.Timeout = TimeSpan.FromSeconds(12);
                    c.DefaultRequestHeaders.Add("x-apikey", key);
                    var resp = c.GetAsync(baseUrl + "/files/" + sha256.ToLowerInvariant()).GetAwaiter().GetResult();
                    if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) { r.Detail = Loc.L("VirusTotal has never seen this file (no data)", "VirusTotal не видел этот файл (нет данных)"); return r; }
                    if ((int)resp.StatusCode == 429) { r.Available = false; r.Detail = Loc.L("request limit reached", "достигнут лимит запросов"); return r; }
                    if ((int)resp.StatusCode == 401 || (int)resp.StatusCode == 403) { r.Available = false; r.Detail = Loc.L("the API key was rejected", "ключ API отклонён"); return r; }
                    resp.EnsureSuccessStatusCode();
                    var d = Json.Obj(Json.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()));
                    var attr = Json.Obj(Json.Obj(d["data"])["attributes"]);
                    var stats = Json.Obj(attr["last_analysis_stats"]);
                    int mal = Json.Int(stats, "malicious"), sus = Json.Int(stats, "suspicious"), harm = Json.Int(stats, "harmless"), und = Json.Int(stats, "undetected");
                    r.Malicious = mal; r.Total = mal + sus + harm + und;
                    long ts; if (long.TryParse(Json.Str(attr, "first_submission_date", "0"), out ts) && ts > 0) r.FirstSeen = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(ts).ToString("yyyy-MM-dd");
                    r.Status = mal >= 5 ? RepStatus.KnownBad : (mal + sus) >= 1 ? RepStatus.Suspicious : (r.Total >= 10 ? RepStatus.KnownGood : RepStatus.NoData);
                    r.Detail = Loc.L(mal + " of " + r.Total + " engines flag this file", mal + " из " + r.Total + " движков отмечают этот файл") + (r.FirstSeen != null ? Loc.L("; first seen " + r.FirstSeen, "; впервые замечен " + r.FirstSeen) : "")
                        + Loc.L(". Many engines saying nothing does not make a file safe, and one or two flags on a rare tool is often a false alarm.", ". Молчание многих движков не делает файл безопасным, а 1-2 срабатывания на редкую утилиту часто ложные.");
                }
            }
            catch (Exception ex)
            {
                var inner = ex is AggregateException ? ((AggregateException)ex).Flatten().InnerException : ex;
                r.Available = false; r.Detail = Loc.L("could not ask (offline?): ", "не удалось спросить (нет сети?): ") + inner.Message;
            }
            return r;
        }
    }
}
