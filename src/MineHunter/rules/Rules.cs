using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using MineHunter.Analysis;
using MineHunter.Util;

namespace MineHunter.Rules
{
    public sealed class CmdRule
    {
        public string Id, Category, Text; public Regex Rx; public int Weight; public bool Definitive;
    }
    public sealed class NameRule { public string Id, Text; public Regex Rx; public int Weight; }
    public sealed class TaskFolderRule { public string Id, Folder, Text; public HashSet<string> Allowed; public int Weight; }

    /// <summary>All detection data. Loaded from embedded defaults + rules folders; lists are unions, so packs only ever add knowledge.</summary>
    public sealed class RulePack
    {
        public readonly List<string> Sources = new List<string>();
        public string Version = "0";

        // miner strings by group
        public readonly Dictionary<string, List<string>> MinerStrings = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public StringScanner MinerScanner;
        public List<KeyValuePair<string, string>> ScanIndex = new List<KeyValuePair<string, string>>();   // pattern id -> (group, text)

        public readonly List<CmdRule> CmdRules = new List<CmdRule>();
        public readonly List<Regex> PoolDomainRx = new List<Regex>();
        public readonly HashSet<int> MiningPorts = new HashSet<int>();
        public readonly HashSet<string> MinerFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> SystemBinaries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> HollowTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> NeverExternal = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> HeavyApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> SecurityTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> SecurityToolsBenign = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> AvDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Brands = new List<string>();
        public readonly List<string> TrustedPublishers = new List<string>();
        public readonly List<string> DefenderExt = new List<string>();
        public readonly List<Regex> DefenderPathDanger = new List<Regex>();
        public readonly List<NameRule> NameRules = new List<NameRule>();
        public readonly List<NameRule> IocPaths = new List<NameRule>();
        public readonly List<TaskFolderRule> TaskFolderRules = new List<TaskFolderRule>();
        public readonly HashSet<string> VulnerableDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> BrowserMinerStrings = new List<string>();
        public readonly List<string> BrowserMinerStringsStrong = new List<string>();
        public readonly List<string> BrowserSearchHosts = new List<string>();
        public readonly List<string> BrowserRiskyPermissions = new List<string>();
        public readonly List<string> BrowserLaunchFlagsRisky = new List<string>();
        public StringScanner BrowserScanner;
        public readonly Dictionary<string, string> BadHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static string InstallDir { get { return AppDomain.CurrentDomain.BaseDirectory; } }
        public static string DataDir
        {
            get
            {
                string over = Environment.GetEnvironmentVariable("MINEHUNTER_DATA_DIR");      // used by the automated tests only
                if (!string.IsNullOrEmpty(over)) return over;
                return Path.Combine(Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData", "MineHunter");
            }
        }

        public static RulePack Load(params string[] extraDirs)
        {
            var rp = new RulePack();
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith("rules.") && (n.EndsWith(".json") || n.EndsWith(".bin"))).OrderBy(n => n))
                    using (var s = asm.GetManifestResourceStream(name))
                    {
                        if (name.EndsWith(".bin")) rp.Merge(Unmask(s), "embedded:" + name);
                        else using (var r = new StreamReader(s, Encoding.UTF8)) rp.Merge(r.ReadToEnd(), "embedded:" + name);
                    }
            }
            catch (Exception ex) { Log.Warn("embedded rules: " + ex.Message); }

            var dirs = new List<string> { Path.Combine(InstallDir, "rules"), Path.Combine(DataDir, "rules") };
            if (extraDirs != null) dirs.AddRange(extraDirs);
            foreach (var d in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (!Directory.Exists(d)) continue;
                    foreach (var f in Directory.GetFiles(d, "*.json").OrderBy(x => x))
                    {
                        try { rp.Merge(File.ReadAllText(f, Encoding.UTF8), f); }
                        catch (Exception ex) { Log.Warn("rule file ignored (" + Path.GetFileName(f) + "): " + ex.Message); }
                    }
                    foreach (var f in Directory.GetFiles(d, "hashes*.txt")) rp.LoadHashes(f);
                }
                catch { }
            }
            rp.Build();
            return rp;
        }

        // Embedded packs are stored compressed and XOR-masked (see MineHunter.csproj, target MaskRules): the EXE must not contain a readable list
        // of miner strings, otherwise other scanners flag the security tool itself. The key is not a secret, it only defeats plain string matching.
        static readonly byte[] MaskKey = { 0x4D, 0x48, 0x2D, 0x72, 0x75, 0x6C, 0x65, 0x73, 0x2D, 0x6D, 0x61, 0x73, 0x6B, 0x2D, 0x76, 0x31, 0xA7, 0x3C, 0x91, 0x5E, 0x0B, 0xD4, 0x62, 0xF8 };

        static string Unmask(Stream s)
        {
            byte[] data;
            using (var ms = new MemoryStream()) { s.CopyTo(ms); data = ms.ToArray(); }
            for (int i = 0; i < data.Length; i++) data[i] ^= MaskKey[i % MaskKey.Length];
            using (var z = new System.IO.Compression.GZipStream(new MemoryStream(data), System.IO.Compression.CompressionMode.Decompress))
            using (var r = new StreamReader(z, Encoding.UTF8)) return r.ReadToEnd();
        }

        static void AddAll<T>(ICollection<T> dst, IEnumerable<T> src) { foreach (var x in src) if (!dst.Contains(x)) dst.Add(x); }
        static Regex Rx(string p) { return new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled); }

        public void Merge(string json, string source)
        {
            var root = Json.Obj(Json.Parse(json));
            if (root == null) return;
            Sources.Add(source);
            string ver = Json.Str(root, "version");
            if (!string.IsNullOrEmpty(ver) && string.CompareOrdinal(ver, Version) > 0) Version = ver;

            var ms = Json.Obj(root.ContainsKey("minerStrings") ? root["minerStrings"] : null);
            if (ms != null)
                foreach (var kv in ms)
                {
                    List<string> l; if (!MinerStrings.TryGetValue(kv.Key, out l)) MinerStrings[kv.Key] = l = new List<string>();
                    var arr = Json.Arr(kv.Value); if (arr != null) foreach (var x in arr) { string s = Convert.ToString(x); if (!string.IsNullOrEmpty(s) && !l.Contains(s, StringComparer.OrdinalIgnoreCase)) l.Add(s); }
                }
            var cr = Json.Arr(root.ContainsKey("cmdlinePatterns") ? root["cmdlinePatterns"] : null);
            if (cr != null)
                foreach (var o in cr)
                {
                    var d = Json.Obj(o); if (d == null) continue;
                    string id = Json.Str(d, "id");
                    if (CmdRules.Any(c => c.Id == id)) continue;
                    try
                    {
                        CmdRules.Add(new CmdRule { Id = id, Rx = Rx(Json.Str(d, "regex")), Weight = Json.Int(d, "weight", 10), Definitive = Json.Bool(d, "definitive"), Category = Json.Str(d, "category", "Content"), Text = Json.Str(d, "text", id) });
                    }
                    catch (Exception ex) { Log.Warn("bad regex in rule " + id + ": " + ex.Message); }
                }
            foreach (var p in Json.Strs(root, "poolDomainRegex")) { try { PoolDomainRx.Add(Rx(p)); } catch { } }
            var ports = Json.Arr(root.ContainsKey("miningPorts") ? root["miningPorts"] : null);
            if (ports != null) foreach (var p in ports) MiningPorts.Add(Convert.ToInt32(p));
            AddAll(MinerFileNames, Json.Strs(root, "minerFileNames"));
            AddAll(SystemBinaries, Json.Strs(root, "systemBinaries"));
            AddAll(HollowTargets, Json.Strs(root, "hollowTargets"));
            AddAll(NeverExternal, Json.Strs(root, "neverExternalNetwork"));
            AddAll(HeavyApps, Json.Strs(root, "heavyAppNames"));
            AddAll(SecurityTools, Json.Strs(root, "securityTools"));
            AddAll(SecurityToolsBenign, Json.Strs(root, "securityToolsBenign"));
            AddAll(AvDomains, Json.Strs(root, "avDomains"));
            AddAll(Brands, Json.Strs(root, "brands"));
            AddAll(TrustedPublishers, Json.Strs(root, "trustedPublishers"));
            AddAll(BrowserMinerStrings, Json.Strs(root, "browserMinerStrings"));
            AddAll(BrowserMinerStringsStrong, Json.Strs(root, "browserMinerStringsStrong"));
            AddAll(BrowserSearchHosts, Json.Strs(root, "browserSearchHosts"));
            AddAll(BrowserRiskyPermissions, Json.Strs(root, "browserRiskyPermissions"));
            AddAll(BrowserLaunchFlagsRisky, Json.Strs(root, "browserLaunchFlagsRisky"));

            var dd = Json.Obj(root.ContainsKey("defenderExclusionDanger") ? root["defenderExclusionDanger"] : null);
            if (dd != null)
            {
                AddAll(DefenderExt, Json.Strs(dd, "extensions"));
                foreach (var p in Json.Strs(dd, "pathRegex")) { try { DefenderPathDanger.Add(Rx(p)); } catch { } }
            }
            foreach (var key in new[] { "persistenceNameRules", "knownIocPaths" })
            {
                var arr = Json.Arr(root.ContainsKey(key) ? root[key] : null);
                if (arr == null) continue;
                foreach (var o in arr)
                {
                    var d = Json.Obj(o); if (d == null) continue;
                    try
                    {
                        var nr = new NameRule { Id = Json.Str(d, "id"), Rx = Rx(Json.Str(d, "regex")), Weight = Json.Int(d, "weight", 10), Text = Json.Str(d, "text") };
                        (key == "knownIocPaths" ? IocPaths : NameRules).Add(nr);
                    }
                    catch { }
                }
            }
            var tf = Json.Arr(root.ContainsKey("knownIocTaskFolders") ? root["knownIocTaskFolders"] : null);
            if (tf != null)
                foreach (var o in tf)
                {
                    var d = Json.Obj(o); if (d == null) continue;
                    TaskFolderRules.Add(new TaskFolderRule { Id = Json.Str(d, "id"), Folder = Json.Str(d, "folder"), Weight = Json.Int(d, "weight", 25), Text = Json.Str(d, "text"), Allowed = new HashSet<string>(Json.Strs(d, "allowedNames"), StringComparer.OrdinalIgnoreCase) });
                }
            var vd = Json.Obj(root.ContainsKey("vulnerableDrivers") ? root["vulnerableDrivers"] : null);
            if (vd != null) AddAll(VulnerableDrivers, Json.Strs(vd, "names"));
            var bh = Json.Obj(root.ContainsKey("badHashes") ? root["badHashes"] : null);
            if (bh != null) foreach (var kv in bh) BadHashes[kv.Key.ToLowerInvariant()] = Convert.ToString(kv.Value);
        }

        void LoadHashes(string file)
        {
            try
            {
                foreach (var line in File.ReadAllLines(file))
                {
                    string l = line.Trim();
                    if (l.Length == 0 || l.StartsWith("#")) continue;
                    var parts = l.Split(new[] { ' ', '\t', ',', ';' }, 2, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 0 || parts[0].Length != 64) continue;
                    BadHashes[parts[0].ToLowerInvariant()] = parts.Length > 1 ? parts[1].Trim() : "known bad hash";
                }
                Sources.Add(file);
            }
            catch { }
        }

        void Build()
        {
            var pats = new List<string>();
            ScanIndex.Clear();
            foreach (var kv in MinerStrings)
                foreach (var s in kv.Value)
                {
                    pats.Add(s);
                    ScanIndex.Add(new KeyValuePair<string, string>(kv.Key, s));
                }
            MinerScanner = new StringScanner(pats);
            BrowserScanner = new StringScanner(BrowserMinerStrings.ToList());
        }

        public bool IsTrustedPublisher(string publisher)
        {
            // The certificate subject must START with a known publisher name followed by a word boundary. Plain substring matching would
            // trust "Intelligent Systems Ltd" because it contains "Intel", or "Pineapple Corp" because it contains "apple".
            string p = NormPublisher(publisher);
            if (p.Length == 0) return false;
            foreach (var t in TrustedPublishers)
            {
                string q = NormPublisher(t);
                if (q.Length == 0 || !p.StartsWith(q, StringComparison.Ordinal)) continue;
                if (p.Length == q.Length || !char.IsLetterOrDigit(p[q.Length])) return true;
            }
            return false;
        }

        static string NormPublisher(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return "";
            return Regex.Replace(s.ToLowerInvariant().Replace(' ', ' ').Replace("\"", ""), @"\s+", " ").Trim();
        }

        public bool IsPoolDomain(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            foreach (var rx in PoolDomainRx) if (rx.IsMatch(host)) return true;
            return false;
        }
    }

    /// <summary>User-approved exceptions ("I know this one, it is mine"). Stored locally, matched by SHA-256 or exact path.</summary>
    public sealed class Allowlist
    {
        public readonly HashSet<string> Sha256 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> Paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static string FilePath { get { return Path.Combine(RulePack.DataDir, "allowlist.json"); } }

        public static Allowlist Load()
        {
            var a = new Allowlist();
            try
            {
                if (!File.Exists(FilePath)) return a;
                var d = Json.Obj(Json.Parse(File.ReadAllText(FilePath)));
                foreach (var h in Json.Strs(d, "sha256")) a.Sha256.Add(h);
                foreach (var p in Json.Strs(d, "paths")) a.Paths.Add(PathUtil.Normalize(p));
            }
            catch { }
            return a;
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(RulePack.DataDir);
                File.WriteAllText(FilePath, Json.Pretty(Json.Serialize(new Dictionary<string, object> { { "sha256", Sha256.ToArray() }, { "paths", Paths.ToArray() } })));
            }
            catch (Exception ex) { Log.Warn("allowlist save: " + ex.Message); }
        }

        public bool Contains(string path, string sha256)
        {
            if (!string.IsNullOrEmpty(sha256) && Sha256.Contains(sha256)) return true;
            return !string.IsNullOrEmpty(path) && Paths.Contains(PathUtil.Normalize(path));
        }
    }
}
