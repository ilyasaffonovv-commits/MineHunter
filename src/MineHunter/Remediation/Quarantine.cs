using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Model
{
    public sealed class QuarantineItem
    {
        public string Id, Type, Title, OriginalPath, Sha256, Created, FindingTitle, Reason, Key, Machine, PayloadFile;
        public long Size;
        public Dictionary<string, object> Extra = new Dictionary<string, object>();
        public bool Restorable = true;
        public string Dir;
        public string RestoreNote;
    }
}

namespace MineHunter
{
    using MineHunter.Model;

    /// <summary>Reversible quarantine. Files are stored XOR-obfuscated with a random per-item key (so they can not run and are not re-flagged),
    /// with SHA-256 recorded and verified both when stored and when restored. Every item has its own folder and unique id -
    /// identical copies never overwrite each other.</summary>
    public static class Quarantine
    {
        public static string Root { get { return Path.Combine(RulePack.DataDir, "Quarantine"); } }

        static string NewId() { return DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 6); }

        static byte[] NewKey() { var k = new byte[32]; using (var r = RandomNumberGenerator.Create()) r.GetBytes(k); return k; }

        static void Xor(byte[] buf, int count, byte[] key, long offset)
        {
            for (int i = 0; i < count; i++) buf[i] ^= key[(offset + i) % key.Length];
        }

        static string Manifest(string dir) { return Path.Combine(dir, "manifest.json"); }

        public static QuarantineItem NewItem(string type, string title, string original, string findingTitle, string reason)
        {
            var it = new QuarantineItem { Id = NewId(), Type = type, Title = title, OriginalPath = original, Created = DateTime.Now.ToString("o"), FindingTitle = findingTitle, Reason = reason, Machine = Environment.MachineName };
            it.Dir = Path.Combine(Root, it.Id);
            Directory.CreateDirectory(it.Dir);
            return it;
        }

        public static void Save(QuarantineItem it)
        {
            var d = new Dictionary<string, object>
            {
                { "id", it.Id }, { "type", it.Type }, { "title", it.Title }, { "originalPath", it.OriginalPath }, { "sha256", it.Sha256 }, { "size", it.Size },
                { "created", it.Created }, { "findingTitle", it.FindingTitle }, { "reason", it.Reason }, { "key", it.Key }, { "machine", it.Machine },
                { "payloadFile", it.PayloadFile }, { "restorable", it.Restorable }, { "extra", it.Extra }, { "restoreNote", it.RestoreNote }
            };
            File.WriteAllText(Manifest(it.Dir), Json.Pretty(Json.Serialize(d)), Encoding.UTF8);
        }

        public static QuarantineItem Load(string dir)
        {
            try
            {
                string mf = Manifest(dir);
                if (!File.Exists(mf)) return null;
                var d = Json.Obj(Json.Parse(File.ReadAllText(mf, Encoding.UTF8)));
                var it = new QuarantineItem
                {
                    Id = Json.Str(d, "id"), Type = Json.Str(d, "type"), Title = Json.Str(d, "title"), OriginalPath = Json.Str(d, "originalPath"), Sha256 = Json.Str(d, "sha256"),
                    Created = Json.Str(d, "created"), FindingTitle = Json.Str(d, "findingTitle"), Reason = Json.Str(d, "reason"), Key = Json.Str(d, "key"), Machine = Json.Str(d, "machine"),
                    PayloadFile = Json.Str(d, "payloadFile"), Restorable = Json.Bool(d, "restorable", true), Dir = dir, RestoreNote = Json.Str(d, "restoreNote")
                };
                try { it.Size = Convert.ToInt64(d["size"]); } catch { }
                var ex = d.ContainsKey("extra") ? Json.Obj(d["extra"]) : null; if (ex != null) it.Extra = ex;
                return it;
            }
            catch { return null; }
        }

        public static List<QuarantineItem> List()
        {
            var list = new List<QuarantineItem>();
            try
            {
                if (!Directory.Exists(Root)) return list;
                foreach (var d in Directory.GetDirectories(Root)) { var it = Load(d); if (it != null) list.Add(it); }
            }
            catch { }
            return list.OrderByDescending(i => i.Created).ToList();
        }

        /// <summary>Stores raw bytes (obfuscated) and returns the item with SHA-256 filled in. Verifies by reading the payload back.</summary>
        public static QuarantineItem StoreFile(string type, string path, string findingTitle, string reason, out string error)
        {
            error = null;
            QuarantineItem it = null;
            try
            {
                it = NewItem(type, Path.GetFileName(path), path, findingTitle, reason);
                byte[] key = NewKey(); it.Key = Convert.ToBase64String(key);
                it.PayloadFile = "payload.mhq";
                string payload = Path.Combine(it.Dir, it.PayloadFile);
                string sha;
                long total = 0;
                using (var src = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var dst = new FileStream(payload, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var h = SHA256.Create())
                {
                    var buf = new byte[1 << 20]; int r; long off = 0;
                    while ((r = src.Read(buf, 0, buf.Length)) > 0)
                    {
                        h.TransformBlock(buf, 0, r, null, 0);
                        Xor(buf, r, key, off); off += r; total += r;
                        dst.Write(buf, 0, r);
                    }
                    h.TransformFinalBlock(new byte[0], 0, 0);
                    sha = Hashing.Hex(h.Hash);
                }
                it.Sha256 = sha; it.Size = total;
                try { it.Extra["attributes"] = (int)File.GetAttributes(path); it.Extra["mtimeUtc"] = File.GetLastWriteTimeUtc(path).ToString("o"); } catch { }
                // verify what we stored
                string check = ReadSha256(it);
                if (check != sha) { error = "verification of the stored copy failed"; try { Directory.Delete(it.Dir, true); } catch { } return null; }
                Save(it);
                return it;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                try { if (it != null) Directory.Delete(it.Dir, true); } catch { }
                return null;
            }
        }

        public static QuarantineItem StoreBytes(string type, string title, string original, byte[] data, string findingTitle, string reason, Dictionary<string, object> extra = null)
        {
            var it = NewItem(type, title, original, findingTitle, reason);
            byte[] key = NewKey(); it.Key = Convert.ToBase64String(key);
            it.PayloadFile = "payload.mhq";
            var copy = (byte[])data.Clone();
            Xor(copy, copy.Length, key, 0);
            File.WriteAllBytes(Path.Combine(it.Dir, it.PayloadFile), copy);
            it.Sha256 = Hashing.Sha256(data); it.Size = data.Length;
            if (extra != null) foreach (var kv in extra) it.Extra[kv.Key] = kv.Value;
            Save(it);
            return it;
        }

        /// <summary>Metadata-only item (registry values, WMI, exclusions ...).</summary>
        public static QuarantineItem StoreRecord(string type, string title, string original, Dictionary<string, object> extra, string findingTitle, string reason)
        {
            var it = NewItem(type, title, original, findingTitle, reason);
            foreach (var kv in extra) it.Extra[kv.Key] = kv.Value;
            Save(it);
            return it;
        }

        public static byte[] ReadPayload(QuarantineItem it)
        {
            string p = Path.Combine(it.Dir, it.PayloadFile ?? "payload.mhq");
            var data = File.ReadAllBytes(p);
            var key = Convert.FromBase64String(it.Key);
            Xor(data, data.Length, key, 0);
            return data;
        }

        public static string ReadSha256(QuarantineItem it)
        {
            string p = Path.Combine(it.Dir, it.PayloadFile ?? "payload.mhq");
            var key = Convert.FromBase64String(it.Key);
            using (var fs = File.OpenRead(p))
            using (var h = SHA256.Create())
            {
                var buf = new byte[1 << 20]; int r; long off = 0;
                while ((r = fs.Read(buf, 0, buf.Length)) > 0) { Xor(buf, r, key, off); off += r; h.TransformBlock(buf, 0, r, null, 0); }
                h.TransformFinalBlock(new byte[0], 0, 0);
                return Hashing.Hex(h.Hash);
            }
        }

        public static void Delete(QuarantineItem it) { try { Directory.Delete(it.Dir, true); } catch (Exception ex) { Log.Warn("quarantine delete: " + ex.Message); } }

        /// <summary>Restores a quarantined FILE item to its original place (or to alternatePath). Returns null on success or an error text.</summary>
        public static string RestoreFileTo(QuarantineItem it, string target, bool overwrite)
        {
            try
            {
                string check = ReadSha256(it);
                if (check != it.Sha256) return "the stored copy is damaged (SHA-256 mismatch) - refusing to restore";
                if (File.Exists(target) && !overwrite) return "a file already exists at " + target;
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                var key = Convert.FromBase64String(it.Key);
                using (var src = File.OpenRead(Path.Combine(it.Dir, it.PayloadFile)))
                using (var dst = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var buf = new byte[1 << 20]; int r; long off = 0;
                    while ((r = src.Read(buf, 0, buf.Length)) > 0) { Xor(buf, r, key, off); off += r; dst.Write(buf, 0, r); }
                }
                string after = Hashing.Sha256(target);
                if (after != it.Sha256) { try { File.Delete(target); } catch { } return "restored file failed verification"; }
                try { if (it.Extra.ContainsKey("attributes")) File.SetAttributes(target, (FileAttributes)Convert.ToInt32(it.Extra["attributes"])); if (it.Extra.ContainsKey("mtimeUtc")) File.SetLastWriteTimeUtc(target, DateTime.Parse(Convert.ToString(it.Extra["mtimeUtc"])).ToUniversalTime()); } catch { }
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }
    }
}
