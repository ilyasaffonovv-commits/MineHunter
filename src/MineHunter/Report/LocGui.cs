using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using MineHunter.Model;

namespace MineHunter
{
    /// <summary>Translation helpers for text that the engine produces in English (finding titles, action descriptions, chain lines, progress messages).</summary>
    public static partial class Loc
    {
        static readonly Dictionary<string, string[]> UiGui = new Dictionary<string, string[]>();

        /// <summary>Russian texts that come with rule packs ("textRu"), so a rule update is bilingual without a new EXE.</summary>
        static readonly Dictionary<string, string> PackRu = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public static void RegisterRuleText(string id, string ru) { if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(ru)) lock (PackRu) PackRu[id] = ru; }
        public static string PackText(string id) { string t; lock (PackRu) return id != null && PackRu.TryGetValue(id, out t) ? t : null; }

        /// <summary>Inline bilingual string (used by the window code).</summary>
        public static string L(string en, string ru) { return Ru ? ru : en; }

        static readonly string[][] TitlePrefixes =
        {
            new[] { "Known malware: ", "Известное вредоносное ПО: " },
            new[] { "Hijacked (hollowed) process: ", "Подменённый (hollowed) процесс: " },
            new[] { "Cryptominer running: ", "Работает криптомайнер: " },
            new[] { "Cryptominer files: ", "Файлы криптомайнера: " },
            new[] { "Mining code in a browser/editor extension: ", "Код майнинга в расширении браузера/редактора: " },
            new[] { "Fake system/vendor program: ", "Подделка под системную/фирменную программу: " },
            new[] { "WMI persistence: ", "Закрепление через WMI: " },
            new[] { "Protection weakened: ", "Ослаблена защита: " },
            new[] { "Browser: ", "Браузер: " },
            new[] { "Persistent program: ", "Программа с автозапуском: " },
            new[] { "Suspicious item: ", "Подозрительный объект: " },
            new[] { "Dangerous item: ", "Опасный объект: " },
        };

        public static string Title(string t)
        {
            if (!Ru || string.IsNullOrEmpty(t)) return t;
            foreach (var p in TitlePrefixes) if (t.StartsWith(p[0], StringComparison.Ordinal)) return p[1] + t.Substring(p[0].Length);
            return t;
        }

        static readonly Tuple<Regex, string>[] StepRules =
        {
            Tuple.Create(new Regex(@"^Remove scheduled task (.+?) \(a copy is kept.*\)$"), "Удалить задачу планировщика {0} (копия сохраняется — можно восстановить)"),
            Tuple.Create(new Regex(@"^Stop and remove driver service (.+?) \(.*\)$"), "Остановить и удалить драйвер {0} (настройки сохраняются для восстановления)"),
            Tuple.Create(new Regex(@"^Stop and remove service (.+?) \(.*\)$"), "Остановить и удалить службу {0} (настройки сохраняются для восстановления)"),
            Tuple.Create(new Regex(@"^Remove autorun entry (.+)$"), "Удалить запись автозапуска {0}"),
            Tuple.Create(new Regex(@"^Restore the Windows default for (.+)$"), "Вернуть значение Windows по умолчанию: {0}"),
            Tuple.Create(new Regex(@"^Remove registry value (.+)$"), "Удалить значение реестра {0}"),
            Tuple.Create(new Regex(@"^Move startup item (.+?) to quarantine$"), "Переместить элемент автозагрузки {0} в карантин"),
            Tuple.Create(new Regex(@"^Delete WMI subscription (.+?) \(.*\)$"), "Удалить WMI-подписку {0} (сохраняется для восстановления)"),
            Tuple.Create(new Regex(@"^Remove Defender exclusion: (.+)$"), "Убрать исключение Защитника: {0}"),
            Tuple.Create(new Regex(@"^Remove the hosts-file lines that block security sites \(backup saved\)$"), "Удалить из файла hosts строки, блокирующие сайты безопасности (копия сохраняется)"),
            Tuple.Create(new Regex(@"^Remove policy value (.+)$"), "Удалить значение политики {0}"),
            Tuple.Create(new Regex(@"^Remove firewall rule (.+)$"), "Удалить правило брандмауэра {0}"),
            Tuple.Create(new Regex(@"^Remove extension ""(.+)"" \(files moved to quarantine; close the browser first\)$"), "Удалить расширение «{0}» (файлы уходят в карантин; сначала закройте браузер)"),
            Tuple.Create(new Regex(@"^Review manually: (.+)$"), "Проверьте вручную: {0}"),
            Tuple.Create(new Regex(@"^Stop process (.+?) \(PID (\d+)\)$"), "Остановить процесс {0} (PID {1})"),
            Tuple.Create(new Regex(@"^Quarantine file (.+?) \(encrypted copy kept, restorable\)$"), "Поместить файл {0} в карантин (копия хранится в зашифрованном виде — можно восстановить)"),
        };

        public static string Step(RemediationStep s)
        {
            if (!Ru || s == null || s.Description == null) return s == null ? "" : s.Description;
            foreach (var r in StepRules)
            {
                var m = r.Item1.Match(s.Description);
                if (m.Success) return string.Format(r.Item2, m.Groups.Cast<Group>().Skip(1).Select(g => (object)g.Value).ToArray());
            }
            return s.Description;
        }


        static readonly Tuple<Regex, string>[] MsgRules =
        {
            Tuple.Create(new Regex(@"^removed \(saved as quarantine item (.+)\)$"), "удалено (копия в карантине: {0})"),
            Tuple.Create(new Regex(@"^changed \(saved as quarantine item (.+)\)$"), "изменено (прежнее значение в карантине: {0})"),
            Tuple.Create(new Regex(@"^moved to quarantine \(id (.+)\)$"), "перемещено в карантин (id {0})"),
            Tuple.Create(new Regex(@"^file is in use - safe copy stored \(id (.+?)\), the original is renamed and will be deleted.*$"), "файл занят — копия сохранена (id {0}), оригинал переименован и будет удалён при перезагрузке"),
            Tuple.Create(new Regex(@"^already gone$"), "уже отсутствует"),
            Tuple.Create(new Regex(@"^critical Windows process - refused$"), "критический процесс Windows — отказано"),
            Tuple.Create(new Regex(@"^trusted/system file - refused$"), "доверенный/системный файл — отказано"),
            Tuple.Create(new Regex(@"^the process did not exit$"), "процесс не завершился"),
            Tuple.Create(new Regex(@"^the subscription is still present$"), "подписка всё ещё на месте"),
            Tuple.Create(new Regex(@"^Windows refused to remove it.*$"), "Windows отказалась удалять (защита от подделки или политика) — удалите вручную в «Безопасность Windows»"),
            Tuple.Create(new Regex(@"^some files are locked - close the browser and try again$"), "часть файлов занята — закройте браузер и повторите"),
        };

        public static string StepMessage(string m)
        {
            if (!Ru || string.IsNullOrEmpty(m)) return m;
            foreach (var r in MsgRules) { var x = r.Item1.Match(m); if (x.Success) return string.Format(r.Item2, x.Groups.Cast<Group>().Skip(1).Select(g => (object)g.Value).ToArray()); }
            return m;
        }

        public static string RescanNote(string n)
        {
            if (!Ru || string.IsNullOrEmpty(n)) return n;
            if (n.StartsWith("Verified by rescan")) return "Проверено повторным сканированием: процесс исчез, файлы обезврежены, записи автозапуска удалены.";
            if (n.StartsWith("Everything possible is done")) return "Всё возможное сделано и подтверждено повторной проверкой; для завершения перезагрузите Windows.";
            if (n.StartsWith("Some steps failed")) return "Часть шагов не удалась (см. подробности); повторная проверка этот объект больше не видит.";
            if (n.StartsWith("The rescan still sees")) return "Повторная проверка всё ещё видит части этого заражения.";
            if (n.StartsWith("no action was selected")) return "ни одно действие не было выбрано";
            return n;
        }

        public static string Recommendation(Finding f)
        {
            if (f == null) return "";
            if (!Ru) return f.Recommendation;
            string r = f.Recommendation ?? "";
            if (r.StartsWith("Review only")) return "Только для просмотра — автоматически здесь ничего отменить нельзя.";
            if (r.StartsWith("Review.")) return "Проверьте. Если вы это не узнаёте — отметьте нужные действия и нажмите «Обезвредить»; всё можно вернуть из карантина.";
            if (r.StartsWith("Neutralize")) return "Обезвредить: остановить процессы, убрать записи автозапуска и поместить файлы в карантин (всё обратимо).";
            return r;
        }

        public static string WhyNotHigher(string en)
        {
            if (!Ru || string.IsNullOrEmpty(en)) return en;
            return "Балл высокий, но все улики — одного типа (" + (en.Contains("only weak signals") ? "только слабые признаки вроде пути и подписи" : "одна категория") + "). Программу называют «высокий риск» только когда сходятся независимые виды улик — так обычные программы не попадают под ложные тревоги.";
        }

        static readonly Dictionary<string, string> Rel = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "launches", "запускает" }, { "is running as", "работает как" }, { "started", "запустил" }, { "loads", "загружает" }, { "references", "ссылается на" },
            { "same content", "тот же файл" }, { "same folder", "та же папка" }, { "excludes", "исключает из проверки" }, { "same list", "тот же список" },
            { "hosts", "содержит" }, { "runs image", "работает как" }, { "started by", "запущен из" }, { "connects to", "подключается к" },
        };

        public static string Relation(string rel) { string v; return Ru && rel != null && Rel.TryGetValue(rel, out v) ? v : rel; }

        public static string KindName(EntityKind k)
        {
            if (!Ru) return Regex.Replace(k.ToString(), "(?<=[a-z])(?=[A-Z])", " ");
            switch (k)
            {
                case EntityKind.Process: return "Процесс"; case EntityKind.File: return "Файл"; case EntityKind.Service: return "Служба"; case EntityKind.Driver: return "Драйвер";
                case EntityKind.Task: return "Задача"; case EntityKind.RunKey: return "Автозапуск"; case EntityKind.StartupItem: return "Автозагрузка"; case EntityKind.Wmi: return "WMI";
                case EntityKind.DefenderExclusion: return "Исключение Защитника"; case EntityKind.FirewallRule: return "Правило брандмауэра"; case EntityKind.HostsEntry: return "Файл hosts";
                case EntityKind.Network: return "Сеть"; case EntityKind.BrowserExtension: return "Расширение"; case EntityKind.BrowserSetting: return "Настройка браузера";
                case EntityKind.PolicyValue: return "Политика"; case EntityKind.Registry: return "Реестр";
            }
            return k.ToString();
        }

        public static string CategoryName(EvidenceCategory c)
        {
            if (!Ru) return c.ToString();
            switch (c)
            {
                case EvidenceCategory.Signature: return "Подпись"; case EvidenceCategory.Location: return "Расположение"; case EvidenceCategory.Masquerade: return "Маскировка";
                case EvidenceCategory.Content: return "Содержимое"; case EvidenceCategory.Behavior: return "Поведение"; case EvidenceCategory.Network: return "Сеть";
                case EvidenceCategory.Persistence: return "Автозапуск"; case EvidenceCategory.Tamper: return "Вмешательство"; case EvidenceCategory.Reputation: return "Репутация"; case EvidenceCategory.Trust: return "Доверие";
            }
            return c.ToString();
        }

        public static string VerdictMeaning(Verdict v)
        {
            switch (v)
            {
                case Model.Verdict.Malware: return L("Several independent kinds of evidence agree. This is very likely malicious.", "Сошлись несколько независимых видов улик. Это почти наверняка вредоносное.");
                case Model.Verdict.HighRisk: return L("Strong, corroborated signs of a hidden miner or malware. Neutralizing is recommended.", "Сильные, подтверждающие друг друга признаки скрытого майнера или вредоносной программы. Рекомендуется обезвредить.");
                case Model.Verdict.Suspicious: return L("Something unusual, but not enough to be sure. Look at the evidence; if you do not recognise the program, neutralize it (everything is restorable).", "Что-то необычное, но не настолько, чтобы быть уверенным. Посмотрите улики; если программу не узнаёте — обезвредьте (всё можно вернуть).");
                default: return L("Minor note, not a threat. Shown only for completeness.", "Мелкая заметка, не угроза. Показана для полноты картины.");
            }
        }

        public static string Describe(Entity e)
        {
            if (!Ru) return MineHunter.Risk.ThreatGraph.Describe(e);
            switch (e.Kind)
            {
                case EntityKind.Process: return "Процесс " + e.Title + " (PID " + e.P("pid") + ")";
                case EntityKind.File: return "Файл " + e.Title + "  [" + Short(e.Location, 70) + "]";
                case EntityKind.Task: return "Задача планировщика " + e.P("taskPath");
                case EntityKind.Service: return "Служба " + e.Title;
                case EntityKind.Driver: return "Драйвер " + e.Title;
                case EntityKind.RunKey: return "Автозапуск (реестр) " + e.Location;
                case EntityKind.StartupItem: return "Элемент автозагрузки " + e.Title;
                case EntityKind.Wmi: return "WMI " + e.Title;
                case EntityKind.DefenderExclusion: return e.Title;
                case EntityKind.Registry: return "Реестр " + e.Title;
                default: return KindName(e.Kind) + " " + e.Title;
            }
        }

        static string Short(string s, int n) { if (string.IsNullOrEmpty(s) || s.Length <= n) return s; return s.Substring(0, 20) + "..." + s.Substring(s.Length - (n - 23)); }

        public static string Progress(string s)
        {
            if (!Ru || string.IsNullOrEmpty(s)) return s;
            var m = Regex.Match(s, @"^Processes: (\d+)$"); if (m.Success) return "Процессов в системе: " + m.Groups[1].Value;
            m = Regex.Match(s, @"^Processes inspected: (\d+)/(\d+)$"); if (m.Success) return "Проверено процессов: " + m.Groups[1].Value + " из " + m.Groups[2].Value;
            m = Regex.Match(s, @"^Loaded libraries checked: (\d+)/(\d+)$"); if (m.Success) return "Проверено загруженных библиотек: " + m.Groups[1].Value + " из " + m.Groups[2].Value;
            m = Regex.Match(s, @"^Files examined: (\d+)\s+\((.*)\)$"); if (m.Success) return "Проверено файлов: " + m.Groups[1].Value + "  (" + m.Groups[2].Value + ")";
            m = Regex.Match(s, @"^Files: (.*)$"); if (m.Success) return "Файлы: " + m.Groups[1].Value;
            switch (s)
            {
                case "Preparing...": return "Подготовка…"; case "Process images checked": return "Файлы процессов проверены"; case "Autostart locations...": return "Автозапуск: реестр, службы, задачи, WMI…";
                case "System tampering checks...": return "Проверка вмешательства в защиту…"; case "Browsers and extensions...": return "Браузеры и расширения…"; case "Files...": return "Файлы…";
                case "Analysing evidence...": return "Анализ улик…"; case "Done": return "Готово";
            }
            return s;
        }
    }
}
