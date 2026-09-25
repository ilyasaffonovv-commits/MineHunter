using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MineHunter.Model;
using MineHunter.Util;

namespace MineHunter.Scanning
{
    /// <summary>Browser junk: cryptojacking / hijacking extensions, force-installed extensions, hijacked search and start pages,
    /// launch flags in shortcuts, VS Code extensions. Chromium family (Chrome, Edge, Brave, Opera, Opera GX, Yandex, Vivaldi...) and Firefox.</summary>
    public static class BrowserScanner
    {
        sealed class Browser { public string Name; public string RelRoot; public bool Roaming; public bool RootIsProfile; }

        static readonly Browser[] Chromium =
        {
            new Browser { Name = "Google Chrome", RelRoot = @"Google\Chrome\User Data" },
            new Browser { Name = "Microsoft Edge", RelRoot = @"Microsoft\Edge\User Data" },
            new Browser { Name = "Brave", RelRoot = @"BraveSoftware\Brave-Browser\User Data" },
            new Browser { Name = "Yandex Browser", RelRoot = @"Yandex\YandexBrowser\User Data" },
            new Browser { Name = "Vivaldi", RelRoot = @"Vivaldi\User Data" },
            new Browser { Name = "Avast Secure Browser", RelRoot = @"AVAST Software\Browser\User Data" },
            new Browser { Name = "Chromium", RelRoot = @"Chromium\User Data" },
            new Browser { Name = "Opera", RelRoot = @"Opera Software\Opera Stable", Roaming = true, RootIsProfile = true },
            new Browser { Name = "Opera GX", RelRoot = @"Opera Software\Opera GX Stable", Roaming = true, RootIsProfile = true },
        };

        public static void Run(ScanContext ctx)
        {
            var strong = new HashSet<string>(ctx.Rules.BrowserMinerStringsStrong.Concat(new[] { Obf.J("xm", "rig"), Obf.J("random", "x") }), StringComparer.OrdinalIgnoreCase);
            foreach (var up in PathUtil.UserProfiles())
            {
                foreach (var b in Chromium)
                {
                    string root = Path.Combine(up, b.Roaming ? @"AppData\Roaming" : @"AppData\Local", b.RelRoot);
                    if (!Directory.Exists(root)) continue;
                    var profiles = new List<string>();
                    if (b.RootIsProfile) profiles.Add(root);
                    else
                        try { profiles.AddRange(Directory.GetDirectories(root).Where(d => { string n = Path.GetFileName(d); return n == "Default" || n.StartsWith("Profile ") || n == "Guest Profile"; })); }
                        catch { ctx.Denied("Browser profiles", root); }
                    foreach (var prof in profiles)
                    {
                        ctx.ThrowIfCancelled();
                        try { ChromiumProfile(ctx, b.Name, prof, up, strong); }
                        catch (Exception ex) { Log.Warn("browser " + b.Name + ": " + ex.Message); }
                    }
                }
                try { FirefoxProfiles(ctx, up, strong); } catch (Exception ex) { Log.Warn("firefox: " + ex.Message); }
                try { VsCodeExtensions(ctx, up, strong); } catch (Exception ex) { Log.Warn("vscode: " + ex.Message); }
            }
            try { ForceInstallPolicies(ctx); } catch { }
            try { BrowserShortcuts(ctx); } catch { }
        }

        static bool IsKnownSearch(ScanContext ctx, string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return true;
            string u = url.Trim().ToLowerInvariant();
            foreach (var h in ctx.Rules.BrowserSearchHosts) if (u.Contains(h)) return true;
            return false;
        }

        static string ReadText(string path, int max = 8 * 1024 * 1024)
        {
            try { var fi = new FileInfo(path); if (!fi.Exists || fi.Length > max) return null; return File.ReadAllText(path, Encoding.UTF8); } catch { return null; }
        }

        // ---------------------------------------------------------------------------------------------- Chromium
        static void ChromiumProfile(ScanContext ctx, string browser, string prof, string userRoot, HashSet<string> strong)
        {
            // Preferences (both files exist; Secure Preferences holds extension install metadata)
            Dictionary<string, object> prefs = null, secure = null;
            string pj = ReadText(Path.Combine(prof, "Preferences")); if (pj != null) try { prefs = Json.Obj(Json.Parse(pj)); } catch { }
            string sj = ReadText(Path.Combine(prof, "Secure Preferences")); if (sj != null) try { secure = Json.Obj(Json.Parse(sj)); } catch { }
            string profName = Path.GetFileName(prof);
            string owner = Path.GetFileName(userRoot);

            // ---- hijacked search / start pages
            if (prefs != null)
            {
                string searchUrl = Dig(prefs, "default_search_provider_data", "template_url_data", "url") as string;
                if (!string.IsNullOrEmpty(searchUrl) && !IsKnownSearch(ctx, searchUrl))
                {
                    var e = ctx.GetOrAdd("browsersetting:" + browser + ":" + owner + ":" + profName + ":search", EntityKind.BrowserSetting, () => new Entity { Title = browser + ": unusual default search engine", Location = Path.Combine(prof, "Preferences") });
                    e.Set("browser", browser); e.Set("profile", profName); e.Set("setting", "default_search"); e.Set("value", searchUrl); e.Set("file", Path.Combine(prof, "Preferences"));
                    e.Add(new Evidence("BROWSER.SEARCH_HIJACK", EvidenceCategory.Tamper, 12, "The default search engine is not a well-known one (search hijacker pattern)", searchUrl));
                }
                var startup = Dig(prefs, "session", "startup_urls") as object[];
                var hp = Dig(prefs, "homepage") as string;
                var urls = new List<string>(); if (startup != null) urls.AddRange(startup.Select(x => Convert.ToString(x))); if (!string.IsNullOrEmpty(hp)) urls.Add(hp);
                foreach (var u in urls.Distinct())
                    if (!string.IsNullOrWhiteSpace(u) && !IsKnownSearch(ctx, u))
                    {
                        var e = ctx.GetOrAdd("browsersetting:" + browser + ":" + owner + ":" + profName + ":start:" + u.ToLowerInvariant(), EntityKind.BrowserSetting, () => new Entity { Title = browser + ": unusual start/home page", Location = Path.Combine(prof, "Preferences") });
                        e.Set("browser", browser); e.Set("profile", profName); e.Set("setting", "start_page"); e.Set("value", u); e.Set("file", Path.Combine(prof, "Preferences"));
                        e.Add(new Evidence("BROWSER.START_PAGE", EvidenceCategory.Tamper, 6, "The start/home page points to an unfamiliar site", u));
                    }
            }

            // ---- extensions
            string extRoot = Path.Combine(prof, "Extensions");
            if (!Directory.Exists(extRoot)) return;
            Dictionary<string, object> settings = null;
            var src = secure ?? prefs;
            if (src != null) settings = Dig(src, "extensions", "settings") as Dictionary<string, object>;
            string[] extDirs; try { extDirs = Directory.GetDirectories(extRoot); } catch { ctx.Denied("Browser extensions", extRoot); return; }
            foreach (var ed in extDirs)
            {
                string id = Path.GetFileName(ed);
                if (id == "Temp") continue;
                string ver = null;
                try { ver = Directory.GetDirectories(ed).OrderByDescending(d => d).FirstOrDefault(); } catch { }
                if (ver == null) continue;
                ctx.Stats.BrowserExtensions++;
                string manifest = ReadText(Path.Combine(ver, "manifest.json"), 1024 * 1024);
                string name = id; List<string> perms = new List<string>(); string updateUrl = null; bool hasContentScripts = false;
                if (manifest != null)
                {
                    try
                    {
                        var m = Json.Obj(Json.Parse(manifest.TrimStart('﻿')));
                        name = Json.Str(m, "name", id);
                        if (name.StartsWith("__MSG_")) name = LocalizedName(ver, name) ?? id;
                        foreach (var key in new[] { "permissions", "host_permissions", "optional_permissions" })
                        { var a = Json.Arr(m.ContainsKey(key) ? m[key] : null); if (a != null) foreach (var x in a) perms.Add(Convert.ToString(x)); }
                        updateUrl = Json.Str(m, "update_url");
                        hasContentScripts = m.ContainsKey("content_scripts");
                    }
                    catch { }
                }

                var ent = new Entity { Id = "browserext:" + browser + ":" + owner + ":" + profName + ":" + id, Kind = EntityKind.BrowserExtension, Title = browser + " extension: " + name, Location = ver };
                ent.Set("browser", browser); ent.Set("profile", profName); ent.Set("extensionId", id); ent.Set("name", name); ent.Set("version", Path.GetFileName(ver)); ent.Set("dir", ed);
                ent.Set("permissions", string.Join(",", perms.Take(30)));

                // installation origin
                if (settings != null && settings.ContainsKey(id))
                {
                    var s = Json.Obj(settings[id]);
                    int loc = Json.Int(s, "location", 1); bool web = Json.Bool(s, "from_webstore", loc == 1);
                    if (loc == 4) ent.Add(new Evidence("BROWSER.EXT_UNPACKED", EvidenceCategory.Persistence, 14, "Extension was loaded unpacked from a folder (developer mode), not from the web store", ver));
                    else if (loc == 2 || loc == 3 || loc == 6) ent.Add(new Evidence("BROWSER.EXT_EXTERNAL", EvidenceCategory.Persistence, 8, "Extension was installed by another program (external install), not by you from the store", id));
                    else if (loc == 7 || loc == 9 || loc == 10) ent.Add(new Evidence("BROWSER.EXT_POLICY", EvidenceCategory.Persistence, 8, "Extension is installed by a system policy", id));
                    if (!web && loc == 1 && updateUrl != null && !updateUrl.Contains("google.com") && !updateUrl.Contains("microsoft.com") && !updateUrl.Contains("yandex") && !updateUrl.Contains("opera.com"))
                        ent.Add(new Evidence("BROWSER.EXT_FOREIGN_UPDATE", EvidenceCategory.Persistence, 12, "Extension updates itself from a non-store address", updateUrl));
                }

                // permission profile: only a weak, combined signal
                int risky = perms.Count(p => ctx.Rules.BrowserRiskyPermissions.Any(r => string.Equals(r, p, StringComparison.OrdinalIgnoreCase)));
                if (perms.Contains("<all_urls>") && perms.Contains("webRequestBlocking") && (perms.Contains("proxy") || perms.Contains("cookies")))
                    ent.Add(new Evidence("BROWSER.EXT_POWERFUL", EvidenceCategory.Behavior, 4, "Extension can read and rewrite all your web traffic and cookies", string.Join(",", perms.Take(12))));

                // mining code inside the extension (JavaScript / WebAssembly)
                try
                {
                    // Only code files count (JS / WebAssembly / HTML). Data files such as filter lists legitimately NAME miners in order to block them.
                    long budget = 40L * 1024 * 1024; int wasm = 0; var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase); int bestInOneFile = 0;
                    foreach (var f in Fs.EnumerateFiles(ver, null, p => { string x = Path.GetExtension(p).ToLowerInvariant(); return x == ".js" || x == ".wasm" || x == ".html" || x == ".mjs"; }, 6))
                    {
                        if (budget <= 0) break;
                        var fi = new FileInfo(f); if (fi.Length > 16 * 1024 * 1024) continue;
                        if (f.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase)) wasm++;
                        long rd; var hits = ctx.Rules.BrowserScanner.ScanFile(f, 12 * 1024 * 1024, 0, out rd);
                        budget -= rd;
                        var inFile = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var h in hits.Keys) { if (h < ctx.Rules.BrowserMinerStrings.Count) { string m = ctx.Rules.BrowserMinerStrings[h]; if (strong.Contains(m)) { inFile.Add(m); found.Add(m); } } }
                        bestInOneFile = Math.Max(bestInOneFile, inFile.Count);
                    }
                    bool securityLike = Regex.IsMatch((name ?? "") + " " + id, @"adblock|ublock|nocoin|miner ?block|protection|security|antivirus|anti-?virus|malware|privacy|shield|guard|adguard|ghostery|kaspersky|avast|avira|bitdefender|norton|mcafee|eset|malwarebytes|trend micro|phishing|safe ", RegexOptions.IgnoreCase);
                    var sf = found.ToList();
                    if (sf.Count > 0 && wasm > 0)
                        ent.Add(new Evidence("BROWSER.EXT_MINER_CODE", EvidenceCategory.Content, 55, "The extension contains WebAssembly and cryptocurrency-mining code (" + string.Join(", ", sf.Take(4)) + ")", ver, true));
                    else if (!securityLike && bestInOneFile >= 2)
                        ent.Add(new Evidence("BROWSER.EXT_MINER_CODE", EvidenceCategory.Content, 55, "The extension contains cryptocurrency-mining code (" + string.Join(", ", sf.Take(4)) + ")", ver, true));
                    else if (!securityLike && sf.Count > 0)
                        ent.Add(new Evidence("BROWSER.EXT_MINER_MENTION", EvidenceCategory.Content, 12, "The extension's code mentions cryptocurrency mining (" + string.Join(", ", sf.Take(3)) + ")", ver));
                    else if (wasm > 0 && perms.Contains("<all_urls>") && hasContentScripts)
                        ent.Add(new Evidence("BROWSER.EXT_WASM_ALLURLS", EvidenceCategory.Behavior, 4, "Extension ships WebAssembly and runs on every site", ver));
                }
                catch { }
                if (ent.Evidence.Any(x => x.Weight > 0)) { ctx.Entities[ent.Id] = ent; }
            }
        }

        static string LocalizedName(string verDir, string msg)
        {
            try
            {
                string key = msg.Trim('_').Replace("MSG_", "");
                foreach (var loc in new[] { "en", "en_US", "ru" })
                {
                    string p = Path.Combine(verDir, "_locales", loc, "messages.json");
                    string t = ReadText(p, 512 * 1024); if (t == null) continue;
                    var o = Json.Obj(Json.Parse(t.TrimStart('﻿')));
                    foreach (var kv in o) if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)) return Json.Str(Json.Obj(kv.Value), "message");
                }
            }
            catch { }
            return null;
        }

        static object Dig(Dictionary<string, object> d, params string[] path)
        {
            object cur = d;
            foreach (var p in path)
            {
                var o = cur as Dictionary<string, object>;
                if (o == null || !o.TryGetValue(p, out cur)) return null;
            }
            return cur;
        }

        // ---------------------------------------------------------------------------------------------- Firefox
        static void FirefoxProfiles(ScanContext ctx, string userRoot, HashSet<string> strong)
        {
            string root = Path.Combine(userRoot, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            if (!Directory.Exists(root)) return;
            string owner = Path.GetFileName(userRoot);
            foreach (var prof in Directory.GetDirectories(root))
            {
                string pn = Path.GetFileName(prof);
                string prefs = ReadText(Path.Combine(prof, "prefs.js"), 8 * 1024 * 1024);
                if (prefs != null)
                {
                    var m = Regex.Match(prefs, @"user_pref\(""browser\.startup\.homepage"",\s*""([^""]*)""\)");
                    if (m.Success && !IsKnownSearch(ctx, m.Groups[1].Value))
                    {
                        var e = ctx.GetOrAdd("browsersetting:firefox:" + owner + ":" + pn + ":home", EntityKind.BrowserSetting, () => new Entity { Title = "Firefox: unusual home page", Location = Path.Combine(prof, "prefs.js") });
                        e.Set("browser", "Firefox"); e.Set("profile", pn); e.Set("setting", "home_page"); e.Set("value", m.Groups[1].Value); e.Set("file", Path.Combine(prof, "prefs.js"));
                        e.Add(new Evidence("BROWSER.START_PAGE", EvidenceCategory.Tamper, 6, "The home page points to an unfamiliar site", m.Groups[1].Value));
                    }
                    var px = Regex.Match(prefs, @"user_pref\(""network\.proxy\.type"",\s*([0-9]+)\)");
                    if (px.Success && (px.Groups[1].Value == "1" || px.Groups[1].Value == "2"))
                    {
                        string host = Regex.Match(prefs, @"user_pref\(""network\.proxy\.(http|ssl|socks)"",\s*""([^""]*)""\)").Groups[2].Value;
                        var e = ctx.GetOrAdd("browsersetting:firefox:" + owner + ":" + pn + ":proxy", EntityKind.BrowserSetting, () => new Entity { Title = "Firefox: manual proxy configured", Location = Path.Combine(prof, "prefs.js") });
                        e.Set("browser", "Firefox"); e.Set("profile", pn); e.Set("setting", "proxy"); e.Set("value", host);
                        e.Add(new Evidence("BROWSER.PROXY", EvidenceCategory.Tamper, 5, "Firefox routes traffic through a proxy", host));
                    }
                }
                string ext = ReadText(Path.Combine(prof, "extensions.json"), 8 * 1024 * 1024);
                if (ext != null)
                {
                    try
                    {
                        var d = Json.Obj(Json.Parse(ext.TrimStart('﻿')));
                        var addons = Json.Arr(d.ContainsKey("addons") ? d["addons"] : null);
                        if (addons != null)
                            foreach (var a in addons)
                            {
                                var ad = Json.Obj(a); if (ad == null) continue;
                                string type = Json.Str(ad, "type"); if (type != "extension") continue;
                                ctx.Stats.BrowserExtensions++;
                                string id = Json.Str(ad, "id"); string loc = Json.Str(ad, "location");
                                var dl = Json.Obj(ad.ContainsKey("defaultLocale") ? ad["defaultLocale"] : null); string name = Json.Str(dl, "name", id);
                                int signed = Json.Int(ad, "signedState", 2);
                                string path = Json.Str(ad, "path");
                                var ent = new Entity { Id = "browserext:firefox:" + owner + ":" + pn + ":" + id, Kind = EntityKind.BrowserExtension, Title = "Firefox extension: " + name, Location = path ?? id };
                                ent.Set("browser", "Firefox"); ent.Set("profile", pn); ent.Set("extensionId", id); ent.Set("name", name); ent.Set("location", loc);
                                if (loc == "app-profile" && signed < 2 && signed != 0)
                                    ent.Add(new Evidence("BROWSER.EXT_UNSIGNED", EvidenceCategory.Persistence, 10, "Firefox extension is not signed by Mozilla", id));
                                if (!string.IsNullOrEmpty(path) && File.Exists(path) && path.EndsWith(".xpi", StringComparison.OrdinalIgnoreCase))
                                {
                                    long rd; var hits = ctx.Rules.BrowserScanner.ScanFile(path, 12 * 1024 * 1024, 0, out rd);
                                    var found = hits.Keys.Where(h => h < ctx.Rules.BrowserMinerStrings.Count).Select(h => ctx.Rules.BrowserMinerStrings[h]).Where(x => strong.Contains(x)).ToList();
                                    if (found.Count > 0) ent.Add(new Evidence("BROWSER.EXT_MINER_CODE", EvidenceCategory.Content, 55, "The extension package contains cryptocurrency-mining code (" + string.Join(", ", found.Take(4)) + ")", path, true));
                                }
                                if (ent.Evidence.Any(x => x.Weight > 0)) ctx.Entities[ent.Id] = ent;
                            }
                    }
                    catch { }
                }
            }
        }

        // ---------------------------------------------------------------------------------------------- VS Code (2026 cryptojacking via extensions)
        static void VsCodeExtensions(ScanContext ctx, string userRoot, HashSet<string> strong)
        {
            foreach (var rel in new[] { @".vscode\extensions", @".cursor\extensions", @".vscode-insiders\extensions", @".windsurf\extensions" })
            {
                string root = Path.Combine(userRoot, rel);
                if (!Directory.Exists(root)) continue;
                string[] dirs; try { dirs = Directory.GetDirectories(root); } catch { continue; }
                foreach (var d in dirs)
                {
                    string name = Path.GetFileName(d);
                    long budget = 20L * 1024 * 1024; var found = new HashSet<string>(); var dl = new List<string>();
                    try
                    {
                        foreach (var f in Fs.EnumerateFiles(d, sub => !Path.GetFileName(sub).Equals("node_modules", StringComparison.OrdinalIgnoreCase), p => { string x = Path.GetExtension(p).ToLowerInvariant(); return x == ".js" || x == ".ts" || x == ".mjs" || x == ".cjs" || x == ".ps1" || x == ".bat" || x == ".cmd" || x == ".exe" || x == ".dll" || x == ".vbs"; }, 4))
                        {
                            if (budget <= 0) break;
                            string ext = Path.GetExtension(f).ToLowerInvariant();
                            if (ext == ".exe" || ext == ".dll" || ext == ".ps1" || ext == ".bat" || ext == ".cmd" || ext == ".vbs") { dl.Add(f); }
                            var fi = new FileInfo(f); if (fi.Length > 8 * 1024 * 1024) continue;
                            long rd; var hits = ctx.Rules.BrowserScanner.ScanFile(f, 8 * 1024 * 1024, 0, out rd); budget -= rd;
                            foreach (var h in hits.Keys) if (h < ctx.Rules.BrowserMinerStrings.Count) found.Add(ctx.Rules.BrowserMinerStrings[h]);
                        }
                    }
                    catch { }
                    var sf = found.Where(x => strong.Contains(x)).ToList();
                    string text = null;
                    try { text = ReadText(Path.Combine(d, "package.json"), 512 * 1024); } catch { }
                    var ent = new Entity { Id = "browserext:vscode:" + Path.GetFileName(userRoot) + ":" + name, Kind = EntityKind.BrowserExtension, Title = "VS Code extension: " + name, Location = d };
                    ent.Set("browser", "VS Code"); ent.Set("dir", d); ent.Set("name", name);
                    if (sf.Count > 0) ent.Add(new Evidence("BROWSER.EXT_MINER_CODE", EvidenceCategory.Content, 55, "The editor extension contains cryptocurrency-mining code (" + string.Join(", ", sf.Take(4)) + ")", d, true));
                    // script-dropping extension that also disables Defender or downloads code
                    foreach (var f in dl.Take(5))
                    {
                        string body = ReadText(f, 256 * 1024); if (body == null || !(f.EndsWith(".ps1") || f.EndsWith(".bat") || f.EndsWith(".cmd"))) continue;
                        foreach (var r in ctx.Rules.CmdRules.Where(r => r.Category == "Tamper" || r.Id.StartsWith("CMD.PS.")))
                            if (r.Rx.IsMatch(body)) ent.Add(new Evidence("BROWSER.VSCODE_SCRIPT", EvidenceCategory.Persistence, 20, "Editor extension ships a script that " + r.Text.ToLowerInvariant(), f));
                    }
                    if (ent.Evidence.Any(x => x.Weight > 0)) ctx.Entities[ent.Id] = ent;
                }
            }
        }

        // ---------------------------------------------------------------------------------------------- policies
        static void ForceInstallPolicies(ScanContext ctx)
        {
            foreach (var pair in new[] { new[] { "Google Chrome", @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" }, new[] { "Microsoft Edge", @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" }, new[] { "Chromium", @"SOFTWARE\Policies\Chromium\ExtensionInstallForcelist" } })
            {
                foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    try
                    {
                        using (var k = hive.OpenSubKey(pair[1]))
                        {
                            if (k == null) continue;
                            foreach (var vn in k.GetValueNames())
                            {
                                string v = Convert.ToString(k.GetValue(vn));
                                if (string.IsNullOrWhiteSpace(v)) continue;
                                string id = v.Split(';')[0]; string url = v.Contains(";") ? v.Substring(v.IndexOf(';') + 1) : "";
                                bool store = url.Contains("clients2.google.com") || url.Contains("edge.microsoft.com") || url == "";
                                var e = ctx.GetOrAdd("policy:forcelist:" + pair[0] + ":" + id, EntityKind.PolicyValue, () => new Entity { Title = pair[0] + ": extension force-installed by policy (" + id + ")", Location = (hive == Registry.LocalMachine ? "HKLM\\" : "HKCU\\") + pair[1] });
                                e.Set("hive", hive == Registry.LocalMachine ? "HKLM" : "HKCU"); e.Set("key", pair[1]); e.Set("value", vn); e.Set("data", v);
                                e.Add(new Evidence("BROWSER.FORCELIST", EvidenceCategory.Tamper, store ? 12 : 30, "A browser extension is force-installed by registry policy and cannot be removed from the browser" + (store ? "" : " (update address is not the official store)"), v));
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        static void BrowserShortcuts(ScanContext ctx)
        {
            var dirs = new List<string>();
            foreach (var up in PathUtil.UserProfiles())
            {
                dirs.Add(Path.Combine(up, "Desktop"));
                dirs.Add(Path.Combine(up, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
                dirs.Add(Path.Combine(up, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"));
            }
            dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms));
            var browsers = new[] { "chrome", "msedge", "brave", "opera", "browser", "vivaldi", "firefox", "launcher" };
            foreach (var d in dirs.Where(x => !string.IsNullOrEmpty(x) && Directory.Exists(x)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                IEnumerable<string> lnks;
                try { lnks = Fs.EnumerateFiles(d, null, p => p.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase), 2).Take(600).ToList(); } catch { continue; }
                foreach (var l in lnks)
                {
                    string target, args;
                    if (!StartupScanner.ResolveShortcut(l, out target, out args) || string.IsNullOrEmpty(target)) continue;
                    string tn = Path.GetFileNameWithoutExtension(target).ToLowerInvariant();
                    if (!browsers.Contains(tn)) continue;
                    string a = args ?? "";
                    var flags = ctx.Rules.BrowserLaunchFlagsRisky.Where(f => a.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
                    bool urlOnly = Regex.IsMatch(a.Trim(), @"^(https?://)\S+$", RegexOptions.IgnoreCase) && !IsKnownSearch(ctx, a);
                    if (flags.Count == 0 && !urlOnly) continue;
                    var e = ctx.GetOrAdd("browsershortcut:" + PathUtil.Key(l), EntityKind.BrowserSetting, () => new Entity { Title = "Browser shortcut with unusual launch options: " + Path.GetFileName(l), Location = l });
                    e.Set("file", l); e.Set("target", target); e.Set("args", a); e.Set("setting", "shortcut");
                    if (flags.Count > 0) e.Add(new Evidence("BROWSER.SHORTCUT_FLAGS", EvidenceCategory.Tamper, 20, "Browser shortcut starts the browser with risky options (" + string.Join(" ", flags) + ")", a));
                    if (urlOnly) e.Add(new Evidence("BROWSER.SHORTCUT_URL", EvidenceCategory.Tamper, 12, "Browser shortcut opens an unfamiliar site every time (start-page hijack)", a));
                }
            }
        }
    }
}
