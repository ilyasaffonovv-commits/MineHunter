using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using MineHunter.Model;

namespace MineHunter.Scanning
{
    /// <summary>Where a file comes from and who owns it. Windows tags files that arrive through a browser or mail client with a "Mark of the Web"
    /// (the Zone.Identifier stream: zone 3 = Internet, plus the address it came from); the NTFS owner shows which account created the file. Read only for the
    /// files that ended up in a finding, because it costs a few file operations per file.</summary>
    public static class Provenance
    {
        public static void Enrich(IEnumerable<Entity> entities)
        {
            foreach (var e in entities.Where(x => x.Kind == EntityKind.File && !string.IsNullOrEmpty(x.Location)).GroupBy(x => x.Id).Select(g => g.First()))
            {
                try { Fill(e); } catch { }
            }
        }

        public static void Fill(Entity e)
        {
            string path = e.Location;
            if (!File.Exists(path)) return;
            try
            {
                var owner = new FileInfo(path).GetAccessControl().GetOwner(typeof(NTAccount));
                if (owner != null) e.Set("fileOwner", owner.Value);
            }
            catch { }
            try
            {
                var zb = AdsScanner.Head(path, "Zone.Identifier", 8192);
                if (zb == null) return;
                string z = Encoding.UTF8.GetString(zb);
                string zone = null, host = null, referrer = null;
                foreach (var raw in z.Split('\n'))
                {
                    string l = raw.Trim();
                    if (l.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase)) zone = l.Substring(7).Trim();
                    else if (l.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase)) host = l.Substring(8).Trim();
                    else if (l.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase)) referrer = l.Substring(12).Trim();
                }
                if (zone != null) e.Set("zoneId", zone);
                if (host != null) e.Set("hostUrl", host);
                if (referrer != null) e.Set("referrerUrl", referrer);
                e.Set("origin", Describe(zone, host, referrer));
            }
            catch { /* no Zone.Identifier stream: the file did not come through a browser or mail client that tags downloads */ }
        }

        static string Describe(string zone, string host, string referrer)
        {
            string where = zone == "3" ? "Downloaded from the Internet" : zone == "4" ? "Marked as coming from a restricted site" : zone == "2" ? "Marked as coming from a trusted site" : zone == "1" ? "Marked as coming from the local intranet" : "Has a Mark of the Web (zone " + zone + ")";
            string from = !string.IsNullOrEmpty(host) && host != "about:internet" ? host : referrer;
            return where + (string.IsNullOrEmpty(from) ? "" : " - " + (from.Length > 120 ? from.Substring(0, 120) + "..." : from));
        }
    }
}
