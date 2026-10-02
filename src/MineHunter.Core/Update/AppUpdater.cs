using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using MineHunter.Native;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Update
{
    /// <summary>One program release as announced in version.json (section "app"). The signature covers the canonical text below, so neither the address nor the hash nor
    /// the version can be swapped without the maintainer's private key.</summary>
    public sealed class AppRelease
    {
        public string Version, Url, Sha256, MinVersion, Notes, Signature, ReleaseUrl;
        public long Size;

        public string Canonical()
        {
            return "MineHunter-app|" + Version + "|" + (Sha256 ?? "").ToLowerInvariant() + "|" + Size + "|" + (MinVersion ?? "") + "|" + Url;
        }
    }

    public enum AppUpdateState { Disabled, UpToDate, Available, Ready, NeedsManualInstall, Offline, Error }

    public sealed class AppUpdateStatus
    {
        public AppUpdateState State; public AppRelease Release; public string Message, StagedDir, StagedVersion;
    }

    public sealed class UpdateResult
    {
        public bool Ok, RolledBack; public string From, To, Error, Time;
    }

    /// <summary>Self-update that cannot make things worse: the announcement is signed (RSA, same key as the rule packs), the download is checked against the signed
    /// SHA-256 and size before anything is unpacked, the package is unpacked into a staging folder (never over the running program), and only a small separate
    /// helper program copies it in - after the running programs have closed, with a backup of every replaced file and an automatic rollback if anything fails.
    /// If a step fails, the installed version simply keeps working.</summary>
    public static class AppUpdater
    {
        public static string UpdatesDir { get { return Path.Combine(RulePack.DataDir, "updates"); } }
        public static string ResultFile { get { return Path.Combine(UpdatesDir, "result.json"); } }
        public static string PendingFile { get { return Path.Combine(UpdatesDir, "pending.json"); } }

        /// <summary>The version that counts as "installed" (replaceable in tests).</summary>
        internal static string CurrentVersion = AppInfo.Version;
        static readonly string[] RequiredFiles = { "MineHunter.exe", "components/MineHunter.Core.dll", "components/MineHunter.UI.dll", "components/MineHunter.UpdateHelper.exe" };

        // ------------------------------------------------------------------------------------------------ manifest
        public static AppRelease ParseRelease(Dictionary<string, object> manifest)
        {
            var app = manifest != null && manifest.ContainsKey("app") ? Json.Obj(manifest["app"]) : null;
            if (app == null) return null;
            var r = new AppRelease
            {
                Version = Json.Str(app, "version"), Url = Json.Str(app, "url"), Sha256 = Json.Str(app, "sha256"), MinVersion = Json.Str(app, "minVersion", "0.0.0"), Notes = Json.Str(app, "notes"),
                Signature = Json.Str(app, "signature"), ReleaseUrl = Json.Str(manifest, "releaseUrl")
            };
            long size; long.TryParse(Json.Str(app, "size", "0"), out size); r.Size = size;
            return string.IsNullOrEmpty(r.Version) || string.IsNullOrEmpty(r.Url) ? null : r;
        }

        /// <summary>Why a release is not acceptable, or null when it is fine.</summary>
        public static string Validate(AppRelease r, AppConfig cfg)
        {
            if (r == null) return "no release announced";
            Uri u;
            if (!Uri.TryCreate(r.Url, UriKind.Absolute, out u) || !(u.Scheme == Uri.UriSchemeHttps || (u.Scheme == Uri.UriSchemeHttp && u.IsLoopback))) return "the package address must be https";
            if (string.IsNullOrEmpty(r.Sha256) || r.Sha256.Length != 64 || !r.Sha256.All(Uri.IsHexDigit)) return "the announcement has no valid SHA-256 for the package";
            if (r.Size <= 0 || r.Size > 600L * 1024 * 1024) return "the announcement has no sensible package size";
            if (string.IsNullOrEmpty(r.Signature)) return "the announcement is not signed";
            if (string.IsNullOrWhiteSpace(cfg.UpdatePublicKeyXml)) return "no signing key is configured, so an update cannot be verified";
            if (!Updater.VerifySignature(Encoding.UTF8.GetBytes(r.Canonical()), r.Signature, cfg.UpdatePublicKeyXml)) return "the signature of the announcement is invalid";
            return null;
        }

        public static AppUpdateStatus Check(AppConfig cfg, Settings settings)
        {
            var st = new AppUpdateStatus { State = AppUpdateState.UpToDate };
            try
            {
                if (string.IsNullOrWhiteSpace(cfg.UpdateManifestUrl) || !cfg.CheckUpdatesOnStart) { st.State = AppUpdateState.Disabled; st.Message = "Update check is switched off."; return st; }
                Uri uri;
                if (!Uri.TryCreate(cfg.UpdateManifestUrl, UriKind.Absolute, out uri) || !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))) { st.State = AppUpdateState.Error; st.Message = "The update address must be https."; return st; }
                string body;
                using (var c = Updater.Client()) body = c.GetStringAsync(uri).GetAwaiter().GetResult();
                var manifest = Json.Obj(Json.Parse(body.TrimStart('﻿')));
                var rel = ParseRelease(manifest);
                if (rel == null) { st.Message = "No program update is announced."; return st; }
                string bad = Validate(rel, cfg);
                if (bad != null) { st.State = AppUpdateState.Error; st.Message = "The announced update was ignored: " + bad + "."; Log.Warn(st.Message); return st; }
                st.Release = rel;
                if (Updater.CompareVersions(rel.Version, CurrentVersion) <= 0) { st.Message = "You have the latest version (" + CurrentVersion + ")."; return st; }
                if (Updater.CompareVersions(CurrentVersion, rel.MinVersion) < 0) { st.State = AppUpdateState.NeedsManualInstall; st.Message = "Version " + rel.Version + " cannot be installed over " + CurrentVersion + " automatically: download the full package from the release page."; return st; }
                var pend = Pending();
                if (pend != null && pend.Item1 == rel.Version && Directory.Exists(pend.Item2) && File.Exists(Path.Combine(pend.Item2, "MineHunter.exe"))) { st.State = AppUpdateState.Ready; st.StagedDir = pend.Item2; st.StagedVersion = rel.Version; st.Message = "Version " + rel.Version + " is downloaded and verified."; return st; }
                st.State = AppUpdateState.Available; st.Message = "Version " + rel.Version + " is available.";
            }
            catch (Exception ex)
            {
                var inner = ex is AggregateException ? ((AggregateException)ex).Flatten().InnerException : ex;
                bool net = inner is HttpRequestException || inner is System.Net.WebException || inner is System.Threading.Tasks.TaskCanceledException || inner is System.Net.Sockets.SocketException;
                st.State = net ? AppUpdateState.Offline : AppUpdateState.Error;
                st.Message = net ? "Could not reach the update server (offline?)." : "Update check failed: " + inner.Message;
            }
            return st;
        }

        // ------------------------------------------------------------------------------------------------ download + verify + stage
        /// <summary>Downloads the package, verifies size and SHA-256 against the signed announcement, unpacks it into a staging folder and checks its content.
        /// Returns null on success (state is then Ready) or the reason it was rejected. The installed program is not touched.</summary>
        public static string Download(AppRelease rel, AppConfig cfg, Action<int> progress, CancellationToken ct, out string stagedDir)
        {
            stagedDir = null;
            string bad = Validate(rel, cfg);
            if (bad != null) return bad;
            try
            {
                string dir = Path.Combine(UpdatesDir, rel.Version);
                if (Directory.Exists(dir)) Directory.Delete(dir, true);
                Directory.CreateDirectory(dir);
                string part = Path.Combine(dir, "package.zip.part"), zip = Path.Combine(dir, "package.zip");
                using (var c = Updater.Client())
                {
                    c.Timeout = TimeSpan.FromMinutes(30);
                    using (var resp = c.GetAsync(new Uri(rel.Url), HttpCompletionOption.ResponseHeadersRead, ct).GetAwaiter().GetResult())
                    {
                        resp.EnsureSuccessStatusCode();
                        long len = resp.Content.Headers.ContentLength ?? -1;
                        if (len > 0 && len != rel.Size) return "the package size (" + len + ") differs from the announced size (" + rel.Size + ") - rejected";
                        using (var src = resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                        using (var dst = File.Create(part))
                        {
                            var buf = new byte[81920]; long got = 0; int n;
                            while ((n = src.Read(buf, 0, buf.Length)) > 0)
                            {
                                ct.ThrowIfCancellationRequested();
                                got += n;
                                if (got > rel.Size) return "the package is larger than announced - rejected";
                                dst.Write(buf, 0, n);
                                if (progress != null) progress((int)(100 * got / Math.Max(1, rel.Size)));
                            }
                        }
                    }
                }
                if (new FileInfo(part).Length != rel.Size) { File.Delete(part); return "the package size does not match the announcement - rejected"; }
                string sha = Hashing.Sha256(part);
                if (!string.Equals(sha, rel.Sha256, StringComparison.OrdinalIgnoreCase)) { File.Delete(part); return "the SHA-256 of the package does not match the signed announcement - rejected"; }
                File.Move(part, zip);
                string pkg = Path.Combine(dir, "pkg");
                string err = Unpack(zip, pkg);
                if (err != null) return err;
                foreach (var req in RequiredFiles) if (!File.Exists(Path.Combine(pkg, req.Replace('/', '\\')))) return "the package does not contain " + req + " - rejected";
                // Authenticode, where the files carry it: a signature that is present must be valid (our own builds are not code-signed unless a certificate is added)
                foreach (var f in new[] { "MineHunter.exe", "components/MineHunter.Core.dll" })
                {
                    var ti = Trust.Check(Path.Combine(pkg, f.Replace('/', '\\')));
                    if (ti != null && (ti.State == TrustState.Tampered || ti.State == TrustState.Revoked)) return "the code signature of " + f + " is broken - rejected";
                }
                File.WriteAllText(PendingFile, Json.Serialize(new Dictionary<string, object> { { "version", rel.Version }, { "dir", pkg }, { "sha256", rel.Sha256 }, { "verified", DateTime.Now.ToString("o") } }));
                stagedDir = pkg;
                return null;
            }
            catch (OperationCanceledException) { return "cancelled"; }
            catch (Exception ex) { return "download failed: " + (ex is AggregateException ? ((AggregateException)ex).Flatten().InnerException.Message : ex.Message); }
        }

        /// <summary>Unpacks a zip into an empty folder; entries that would land outside it (".." or absolute paths) reject the whole package.</summary>
        internal static string Unpack(string zip, string dest)
        {
            try
            {
                if (Directory.Exists(dest)) Directory.Delete(dest, true);
                Directory.CreateDirectory(dest);
                string full = Path.GetFullPath(dest).TrimEnd('\\') + "\\";
                using (var za = ZipFile.OpenRead(zip))
                {
                    long total = 0;
                    foreach (var e in za.Entries)
                    {
                        string target = Path.GetFullPath(Path.Combine(dest, e.FullName.Replace('/', '\\')));
                        if (!target.StartsWith(full, StringComparison.OrdinalIgnoreCase)) return "the package holds a path that leaves its folder (" + e.FullName + ") - rejected";
                        total += e.Length; if (total > 1500L * 1024 * 1024) return "the package unpacks to an unreasonable size - rejected";
                        if (string.IsNullOrEmpty(e.Name)) { Directory.CreateDirectory(target); continue; }
                        Directory.CreateDirectory(Path.GetDirectoryName(target));
                        e.ExtractToFile(target, true);
                    }
                }
                return null;
            }
            catch (Exception ex) { return "the package could not be unpacked: " + ex.Message; }
        }

        static Tuple<string, string> Pending()
        {
            try
            {
                if (!File.Exists(PendingFile)) return null;
                var d = Json.Obj(Json.Parse(File.ReadAllText(PendingFile)));
                return Tuple.Create(Json.Str(d, "version"), Json.Str(d, "dir"));
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------------------------------------ install (through the helper)
        /// <summary>Starts the helper and returns. The caller must close the program straight away: the helper waits for it, replaces the files and starts it again.
        /// Returns null when the helper was started, otherwise the reason.</summary>
        public static string StartInstall(string stagedDir, string newVersion, string installDir, string restartExe, bool restart)
        {
            try
            {
                string helperSrc = Path.Combine(installDir, "components", "MineHunter.UpdateHelper.exe");
                if (!File.Exists(helperSrc)) helperSrc = Path.Combine(stagedDir, "components", "MineHunter.UpdateHelper.exe");
                if (!File.Exists(helperSrc)) return "the updater helper is missing";
                string tmp = Path.Combine(Path.GetTempPath(), "mh-upd-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                Directory.CreateDirectory(tmp);
                string helper = Path.Combine(tmp, "MineHunter.UpdateHelper.exe");
                File.Copy(helperSrc, helper, true);
                string cfg = helperSrc + ".config"; if (File.Exists(cfg)) File.Copy(cfg, helper + ".config", true);
                string backup = Path.Combine(UpdatesDir, "backup", CurrentVersion);
                Directory.CreateDirectory(UpdatesDir);
                var args = new List<string> { "apply", "--src", stagedDir, "--dst", installDir.TrimEnd('\\'), "--backup", backup, "--result", ResultFile, "--from", CurrentVersion, "--to", newVersion,
                    "--pid", Process.GetCurrentProcess().Id.ToString(), "--cleanup", tmp };
                if (restart && !string.IsNullOrEmpty(restartExe)) { args.Add("--restart"); args.Add(restartExe); }
                var psi = new ProcessStartInfo(helper) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = tmp };
                psi.Arguments = string.Join(" ", args.Select(Quote));
                Process.Start(psi);
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        static string Quote(string a) { return a.IndexOfAny(new[] { ' ', '\t', '"' }) >= 0 ? "\"" + a.Replace("\"", "\\\"") + "\"" : a; }

        /// <summary>What the helper reported after the last update attempt (read once, then removed).</summary>
        public static UpdateResult TakeResult()
        {
            try
            {
                if (!File.Exists(ResultFile)) return null;
                var d = Json.Obj(Json.Parse(File.ReadAllText(ResultFile)));
                File.Delete(ResultFile);
                var r = new UpdateResult { Ok = Json.Bool(d, "ok"), RolledBack = Json.Bool(d, "rolledBack"), From = Json.Str(d, "from"), To = Json.Str(d, "to"), Error = Json.Str(d, "error"), Time = Json.Str(d, "time") };
                if (r.Ok) { try { File.Delete(PendingFile); Directory.Delete(Path.Combine(UpdatesDir, r.To ?? "x"), true); } catch { } }
                return r;
            }
            catch { return null; }
        }

        /// <summary>The version in the backup folder, if there is one the user could go back to.</summary>
        public static string BackupVersion()
        {
            try
            {
                string b = Path.Combine(UpdatesDir, "backup");
                if (!Directory.Exists(b)) return null;
                return Directory.GetDirectories(b).Select(Path.GetFileName).OrderByDescending(v => v, Comparer<string>.Create(Updater.CompareVersions)).FirstOrDefault();
            }
            catch { return null; }
        }
    }
}
