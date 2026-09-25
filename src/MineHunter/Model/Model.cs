using System;
using System.Collections.Generic;
using System.Linq;

namespace MineHunter.Model
{
    public enum EntityKind
    {
        Process, File, Service, Driver, Task, RunKey, StartupItem, Wmi, DefenderExclusion,
        FirewallRule, HostsEntry, Network, BrowserExtension, BrowserSetting, PolicyValue, Registry
    }

    public enum Verdict { Clean = 0, Suspicious = 1, HighRisk = 2, Malware = 3 }

    /// <summary>Evidence categories. The risk engine requires corroboration ACROSS categories before it will call
    /// something High Risk / Malware, so one loud signal (CPU, unsigned, odd path) can never condemn a program alone.</summary>
    public enum EvidenceCategory
    {
        Signature,    // unsigned / broken signature (weak on its own)
        Location,     // executes from Temp/AppData/etc. (weak on its own)
        Masquerade,   // system-like name in the wrong place, homoglyph brand, fake vendor
        Content,      // miner strings, packer, bloat, PE anomalies
        Behavior,     // hollowing, unbacked memory, sustained CPU/GPU, process-tree anomalies
        Network,      // pool-like connections, unexpected external connections
        Persistence,  // autorun / task / service / WMI / startup
        Tamper,       // Defender exclusions, hosts blocking AV, DisallowRun, ...
        Reputation,   // known hash / known rule family
        Trust         // negative evidence: valid signature by a trusted publisher, OS file, allow-list
    }

    public sealed class Evidence
    {
        public string RuleId;            // stable id, e.g. "PROC.HOLLOW.IMAGE_MISMATCH"
        public EvidenceCategory Category;
        public int Weight;               // >0 raises risk, <0 lowers it (Trust)
        public string Text;              // one-line human explanation
        public string Detail;            // optional technical detail (paths, values)
        public bool Definitive;          // strong enough on its own (known hash, wallet+pool cmdline, hollowing proof)

        public Evidence() { }
        public Evidence(string ruleId, EvidenceCategory cat, int weight, string text, string detail = null, bool definitive = false)
        { RuleId = ruleId; Category = cat; Weight = weight; Text = text; Detail = detail; Definitive = definitive; }
    }

    public sealed class Link
    {
        public string From, To, Relation;
        public Link(string from, string to, string relation) { From = from; To = to; Relation = relation; }
    }

    public sealed class Entity
    {
        public string Id;
        public EntityKind Kind;
        public string Title;                       // short display name
        public string Location;                    // path / key / task path
        public Dictionary<string, string> Props = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public List<Evidence> Evidence = new List<Evidence>();
        public int Score;                          // filled by the risk engine
        public Verdict Verdict;
        public bool Trusted;                       // allow-listed / OS / trusted publisher
        public string Sha256;                      // for files / process images

        public string P(string key) { string v; return Props.TryGetValue(key, out v) ? v : null; }
        public void Set(string key, string value) { if (value != null) Props[key] = value; }
        public void Add(Evidence e) { if (e != null && !Evidence.Any(x => x.RuleId == e.RuleId && x.Detail == e.Detail)) Evidence.Add(e); }
        public override string ToString() { return Kind + ":" + Title; }
    }

    public enum ActionType
    {
        KillProcess, SuspendProcess, QuarantineFile, DisableTask, QuarantineTask, StopDisableService, QuarantineService,
        RemoveRunValue, RemoveStartupItem, RemoveWmiSubscription, RemoveDefenderExclusion, RemoveRegistryValue,
        RestoreDefaultValue, RemoveHostsLines, RemoveFirewallRule, RemoveBrowserExtension, ResetBrowserSetting, ReviewOnly
    }

    public sealed class RemediationStep
    {
        public ActionType Type;
        public string EntityId;
        public string Description;
        public string Target;            // path / name / key the step operates on
        public bool Reversible = true;
        public bool RecommendedByDefault = true;
        public int Order;                // execution order inside a finding (persistence first, then processes, then files)
    }

    /// <summary>A "finding" is one connected component of the threat graph: a miner + its watchdog + its persistence.</summary>
    public sealed class Finding
    {
        public string Id;
        public string Title;
        public Verdict Verdict;
        public int Score;
        public List<Entity> Entities = new List<Entity>();
        public List<Link> Links = new List<Link>();
        public List<Evidence> TopEvidence = new List<Evidence>();
        public List<string> ChainLines = new List<string>();     // rendered infection chain
        public List<RemediationStep> Steps = new List<RemediationStep>();
        public string Recommendation;
        public string WhyNotHigher;                               // shown when the corroboration gate capped the verdict
        public string RemediationOutcome;                         // filled after neutralisation + rescan
    }

    public sealed class BlindSpot
    {
        public string Area, Reason;
        public BlindSpot(string area, string reason) { Area = area; Reason = reason; }
    }

    public sealed class SystemStatus
    {
        public string OsVersion, Architecture, Machine, User;
        public bool IsAdmin;
        public string DefenderState;        // human text
        public bool RealtimeProtectionOn;
        public bool DefenderServiceRunning;
        public List<string> PostureWarnings = new List<string>();
        public List<string> PostureInfo = new List<string>();
        public string ThirdPartyAv;
        public int QuarantineCount;
        public string LastScan;
    }

    public sealed class ScanStats
    {
        public int ProcessesScanned, ModulesChecked, FilesInspected, FilesHashed, FilesSkippedByCache, PersistenceItems, ServicesScanned,
                   TasksScanned, WmiObjects, RunEntries, BrowserExtensions, Connections, AccessDenied;
        public long BytesRead;
        public double Seconds;
    }
}
