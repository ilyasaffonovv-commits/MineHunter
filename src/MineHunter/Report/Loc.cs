using System;
using System.Collections.Generic;
using System.Globalization;
using MineHunter.Model;

namespace MineHunter
{
    /// <summary>Two-language (en/ru) UI and explanation texts. Engine code stays language-neutral: evidence carries a rule id and an English sentence,
    /// the Russian text is looked up here by rule id.</summary>
    public static partial class Loc
    {
        public static string Lang = "en";

        public static void Init(string configured)
        {
            string l = (configured ?? "auto").ToLowerInvariant();
            if (l == "ru" || l == "en") { Lang = l; return; }
            try { Lang = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru" || CultureInfo.InstalledUICulture.TwoLetterISOLanguageName == "ru" ? "ru" : "en"; } catch { Lang = "en"; }
        }

        public static bool Ru { get { return Lang == "ru"; } }

        public static string T(string key)
        {
            string[] v;
            if (Ui.TryGetValue(key, out v) || UiGui.TryGetValue(key, out v)) return Ru ? v[1] : v[0];
            return key;
        }

        public static string F(string key, params object[] args) { return string.Format(T(key), args); }

        public static string Ev(Evidence e)
        {
            if (!Ru || e == null) return e == null ? "" : e.Text;
            string ru;
            if (EvRu.TryGetValue(e.RuleId, out ru)) return ru;
            ru = PackText(e.RuleId); if (ru != null) return ru;
            // rule ids derived from command-line rules: PROC.CMD.x / PERSIST.CMD.x / SCRIPT.CMD.x / WMI.SCRIPT.x
            string id = e.RuleId;
            foreach (var p in new[] { "PROC.", "PERSIST.", "SCRIPT.", "WMI.SCRIPT." })
                if (id.StartsWith(p, StringComparison.Ordinal))
                {
                    string baseId = id.Substring(p.Length); string t;
                    if (!baseId.StartsWith("CMD.")) baseId = "CMD." + baseId;
                    t = PackText(baseId);
                    if (t != null || EvRu.TryGetValue(baseId, out t)) return (p == "PERSIST." ? "(автозапуск) " : p == "SCRIPT." ? "(скрипт) " : p == "WMI.SCRIPT." ? "(WMI-скрипт) " : "") + t;
                }
            return e.Text;
        }

        public static string Posture(string coded)
        {
            if (string.IsNullOrEmpty(coded)) return "";
            int i = coded.IndexOf('|'); string code = i > 0 ? coded.Substring(0, i) : ""; string en = i > 0 ? coded.Substring(i + 1) : coded;
            if (!Ru) return en;
            string ru;
            return PostureRu.TryGetValue(code, out ru) ? ru : en;
        }

        public static string Verdict(Verdict v)
        {
            switch (v)
            {
                case Model.Verdict.Malware: return Ru ? "ВРЕДОНОСНОЕ" : "MALWARE";
                case Model.Verdict.HighRisk: return Ru ? "ВЫСОКИЙ РИСК" : "HIGH RISK";
                case Model.Verdict.Suspicious: return Ru ? "ПОДОЗРИТЕЛЬНОЕ" : "SUSPICIOUS";
                default: return Ru ? "ЧИСТО" : "CLEAN";
            }
        }

        // ------------------------------------------------------------------------------------------------ UI strings  {en, ru}
        static readonly Dictionary<string, string[]> Ui = new Dictionary<string, string[]>
        {
            { "app.tagline", new[] { "Local hunter of hidden miners and persistence", "Локальный охотник за скрытыми майнерами и автозапуском" } },
            { "status.title", new[] { "System status", "Состояние системы" } },
            { "status.protection", new[] { "Protection", "Защита" } },
            { "status.lastscan", new[] { "Last scan", "Последняя проверка" } },
            { "status.never", new[] { "never", "ещё не было" } },
            { "status.quarantine", new[] { "In quarantine", "В карантине" } },
            { "status.rules", new[] { "Rules", "Правила" } },
            { "status.version", new[] { "Version", "Версия" } },
            { "btn.quick", new[] { "Quick scan", "Быстрая проверка" } },
            { "btn.full", new[] { "Full scan", "Полная проверка" } },
            { "btn.custom", new[] { "Custom scan…", "Выборочная проверка…" } },
            { "btn.cancel", new[] { "Cancel", "Отмена" } },
            { "btn.neutralize", new[] { "Neutralize selected", "Обезвредить выбранное" } },
            { "btn.neutralize_all", new[] { "Neutralize all recommended", "Обезвредить всё рекомендованное" } },
            { "btn.allow", new[] { "Mark as safe", "Пометить как безопасное" } },
            { "btn.restore", new[] { "Restore", "Восстановить" } },
            { "btn.delete", new[] { "Delete forever", "Удалить навсегда" } },
            { "btn.openreport", new[] { "Open report", "Открыть отчёт" } },
            { "btn.rescan", new[] { "Rescan", "Перепроверить" } },
            { "tab.results", new[] { "Results", "Результаты" } },
            { "tab.quarantine", new[] { "Quarantine", "Карантин" } },
            { "tab.graph", new[] { "Threat graph", "Граф угрозы" } },
            { "tab.log", new[] { "Log", "Журнал" } },
            { "tab.about", new[] { "About & privacy", "О программе и приватность" } },
            { "sum.malware", new[] { "MALWARE", "ВРЕДОНОСНЫХ" } },
            { "sum.high", new[] { "HIGH RISK", "ВЫСОКИЙ РИСК" } },
            { "sum.susp", new[] { "SUSPICIOUS", "ПОДОЗРИТЕЛЬНЫХ" } },
            { "sum.notes", new[] { "low-risk notes", "мелких заметок" } },
            { "sum.clean", new[] { "CLEAN", "ЧИСТО" } },
            { "det.what", new[] { "What was found", "Что найдено" } },
            { "det.where", new[] { "Where", "Где" } },
            { "det.why", new[] { "Why (evidence and score)", "Почему (улики и баллы)" } },
            { "det.chain", new[] { "Infection chain", "Цепочка заражения" } },
            { "det.action", new[] { "Recommended action", "Рекомендуемое действие" } },
            { "det.steps", new[] { "Actions (untick anything you do not want)", "Действия (снимите галочки с ненужных)" } },
            { "det.capped", new[] { "Why not higher", "Почему не выше" } },
            { "scan.idle", new[] { "Ready. Press a scan button.", "Готово. Нажмите кнопку проверки." } },
            { "scan.running", new[] { "Scanning…", "Идёт проверка…" } },
            { "scan.done", new[] { "Scan finished", "Проверка завершена" } },
            { "scan.clean", new[] { "Nothing dangerous was found.", "Ничего опасного не найдено." } },
            { "upd.checking", new[] { "Checking for updates…", "Проверка обновлений…" } },
            { "upd.uptodate", new[] { "You have the latest version", "У вас последняя версия" } },
            { "upd.available", new[] { "New version available", "Доступна новая версия" } },
            { "upd.offline", new[] { "Offline - update check skipped", "Нет сети — проверка обновлений пропущена" } },
            { "upd.notconfigured", new[] { "Update source not set yet", "Источник обновлений ещё не задан" } },
            { "upd.disabled", new[] { "Update check is off", "Проверка обновлений отключена" } },
            { "upd.rules", new[] { "Newer detection rules are available", "Доступны более новые правила детекта" } },
            { "upd.install_rules", new[] { "Install new rules", "Установить новые правила" } },
            { "privacy.text", new[] { "MineHunter works completely locally. It does not upload files, hashes, logs or anything else, has no account and no telemetry. The only network request is an optional download of the public version.json to see whether a newer version or rule pack exists; nothing from your computer is sent.", "MineHunter работает полностью локально. Он не отправляет файлы, хеши, логи и вообще ничего, не требует аккаунта и не собирает телеметрию. Единственный сетевой запрос — необязательная загрузка публичного version.json, чтобы узнать о новой версии или правилах; с вашего компьютера при этом ничего не отправляется." } },
            { "report.title", new[] { "scan report", "отчёт о проверке" } },
            { "report.generated", new[] { "Generated", "Создан" } }, { "report.os", new[] { "System", "Система" } }, { "report.protection", new[] { "Protection", "Защита" } },
            { "report.scan", new[] { "Scan", "Проверка" } }, { "report.scanned", new[] { "Examined", "Проверено" } }, { "report.summary", new[] { "Summary", "Итог" } }, { "report.notes", new[] { "notes", "заметок" } },
            { "report.nothing", new[] { "Nothing dangerous was found.", "Ничего опасного не найдено." } },
            { "report.why", new[] { "Why", "Почему" } }, { "report.capped", new[] { "Why not higher", "Почему не выше" } }, { "report.chain", new[] { "Chain", "Цепочка" } },
            { "report.hashes", new[] { "SHA-256", "SHA-256" } }, { "report.action", new[] { "Recommended", "Рекомендуется" } }, { "report.result", new[] { "Result", "Результат" } },
            { "report.reboot", new[] { "RESTART REQUIRED to finish the cleanup", "ТРЕБУЕТСЯ ПЕРЕЗАГРУЗКА для завершения очистки" } },
            { "report.notes.head", new[] { "Low-risk notes (not findings)", "Мелкие заметки (не угрозы)" } },
            { "report.blind", new[] { "What could NOT be checked (blind spots):", "Что НЕ удалось проверить (слепые зоны):" } },
            { "report.selfprot", new[] { "Scanner self-protection notes:", "Заметки о самозащите сканера:" } },
            { "report.privacy", new[] { "This report was created locally. Nothing was uploaded.", "Этот отчёт создан локально. Ничего не отправлялось." } },
        };

        static readonly Dictionary<string, string> PostureRu = new Dictionary<string, string>
        {
            { "NO_AV", "Защитник Windows не запущен, и другого антивируса нет — на этом компьютере нет работающей защиты в реальном времени." },
            { "OTHER_AV", "Защитник Windows выключен, но зарегистрирован другой антивирус." },
            { "UAC_OFF", "Контроль учётных записей (UAC) выключен — программы получают права администратора без запроса." },
            { "WU_OFF", "Служба обновлений Windows отключена." },
            { "WU_POLICY", "Автоматические обновления Windows отключены политикой." },
            { "FW_OFF", "Брандмауэр Windows выключен для одного из сетевых профилей." },
            { "SMARTSCREEN_OFF", "SmartScreen отключён." },
        };

        static readonly Dictionary<string, string> EvRu = new Dictionary<string, string>
        {
            { "SIG.UNSIGNED", "Нет цифровой подписи" }, { "SIG.UNSIGNED_MINOR", "Нет цифровой подписи" }, { "SIG.UNSIGNED_IN_SYSTEM", "Неподписанный исполняемый файл в системной папке Windows" },
            { "SIG.TAMPERED", "Подпись не совпадает с содержимым (файл изменён после подписания)" }, { "SIG.REVOKED", "Сертификат подписи отозван" },
            { "SIG.UNTRUSTED_ROOT", "Подписан сертификатом, который не ведёт к доверенному корню" }, { "SIG.EXPIRED", "Срок действия сертификата подписи истёк" },
            { "TRUST.OS_SIGNED", "Подписан Microsoft / каталогом Windows" }, { "TRUST.PUBLISHER", "Действительная подпись известного издателя" }, { "TRUST.VALID_OTHER", "Действительная цифровая подпись" }, { "TRUST.USER_ALLOWLIST", "Вы отметили это как безопасное" },
            { "LOC.TEMP", "Запускается из временной папки" }, { "LOC.APPDATA_ROOT", "Исполняемый файл лежит прямо в корне %APPDATA%" }, { "LOC.LOCALAPPDATA_ROOT", "Исполняемый файл лежит прямо в корне %LOCALAPPDATA%" },
            { "LOC.APPDATA", "Запускается из %APPDATA%" }, { "LOC.LOCALAPPDATA", "Запускается из %LOCALAPPDATA%" }, { "LOC.PROGRAMDATA", "Запускается из C:\\ProgramData (доступна на запись всем пользователям)" },
            { "LOC.PUBLIC", "Запускается из общего профиля Public" }, { "LOC.WINTEMP", "Запускается из доступной на запись подпапки Windows (Temp/Tasks)" }, { "LOC.RECYCLE_BIN", "Исполняемый файл хранится в Корзине" },
            { "LOC.DOWNLOADS", "Лежит в Загрузках" }, { "LOC.DESKTOP_DOCS", "Лежит на Рабочем столе / в Документах" }, { "LOC.PROFILE", "Лежит в папке профиля пользователя" }, { "LOC.DRIVE_ROOT", "Исполняемый файл в корне диска" },
            { "LOC.APPDATA_MS_WINDOWS", "Исполняемый файл спрятан в AppData\\Microsoft\\Windows (там не бывает законных программ)" },
            { "ATTR.HIDDEN_SYSTEM", "У файла одновременно атрибуты «Скрытый» и «Системный»" }, { "ATTR.HIDDEN", "Скрытый исполняемый файл" },
            { "MASQ.SYSTEM_NAME_WRONG_PATH", "Имя как у системного файла Windows, но лежит не в папке Windows" }, { "MASQ.SYSTEM_NAME_UNSIGNED", "Имя системного файла в папке Windows, но нет подписи Microsoft" },
            { "MASQ.SIGNED_COPY", "Настоящий файл Microsoft, скопированный за пределы папки Windows" }, { "MASQ.HOMOGLYPH", "Имя — «двойник» известного бренда (например, заглавная I вместо l)" },
            { "MASQ.FAKE_VENDOR_INFO", "В свойствах файла указан известный производитель, но подписи этого производителя нет" }, { "MASQ.RTL_OVERRIDE", "Скрытый символ подмены направления текста маскирует настоящее расширение" },
            { "MASQ.DOUBLE_EXTENSION", "Программа выдаёт себя за документ/картинку (двойное расширение)" },
            { "CONTENT.MINER.STRINGS_STRONG", "Внутри протокол, алгоритмы и названия криптомайнера (много совпадений)" }, { "CONTENT.MINER.STRINGS_MANY", "Внутри много признаков криптомайнера" },
            { "CONTENT.MINER.STRINGS_SOME", "Внутри несколько признаков криптомайнера" }, { "CONTENT.MINER.STRINGS_ONE", "Внутри есть признак криптомайнера" },
            { "NAME.MINER_TOOL", "Имя файла совпадает с известной программой-майнером" }, { "NAME.MINER_ORIGINAL", "Внутреннее оригинальное имя файла — известный майнер" },
            { "PE.BLOATED", "Файл раздут сотнями МБ одинаковых данных (приём против сканеров и песочниц)" }, { "PE.HUGE_OVERLAY", "Огромный блок данных после программы" },
            { "PE.PACKED", "Файл упакован/защищён упаковщиком" }, { "PE.HIGH_ENTROPY", "Код зашифрован или сжат (высокая энтропия)" },
            { "PE.INJECTOR_IMPORTS", "Использует набор функций для внедрения кода в другие процессы" }, { "PE.DRIVER_USER_PATH", "Драйвер ядра лежит в пользовательской папке" },
            { "REP.KNOWN_BAD_HASH", "SHA-256 файла есть в списке известного вредоносного ПО" }, { "TRUST.KNOWN_GOOD_HASH", "SHA-256 файла есть в списке заведомо безопасных файлов (обновление правил)" },
            { "PROC.HOLLOW.IMAGE_MISMATCH", "Образ программы в памяти отличается от файла на диске (подмена процесса, hollowing)" }, { "PROC.HOLLOW.NO_MAPPED_FILE", "Основной образ в памяти не связан с файлом на диске" },
            { "PROC.PE_IN_PRIVATE_MEMORY", "Исполняемый образ загружен из «ничейной» памяти — ручная загрузка / внедрение кода" },
            { "PROC.ORPHAN_THREADS", "Есть потоки, стартовавшие с адреса, который не принадлежит ни одной библиотеке" },
            { "PROC.PARENT_ANOMALY", "Системный процесс запущен не тем родителем, которым положено" },
            { "PROC.SIDELOAD_CANDIDATE", "Подписанная программа загрузила неподписанную DLL из своей же пользовательской папки (подмена DLL, side-loading)" },
            { "PROC.SYSTEM_PROC_UNSIGNED_MODULE", "Системный процесс Windows загрузил неподписанную библиотеку из пользовательской папки" },
            { "PROC.SUSPENDED_LOLBIN", "Системная утилита полностью заморожена больше минуты (типично для внедрения кода)" },
            { "PROC.MINER.CMDLINE_COMPLETE", "В командной строке пул, кошелёк и алгоритм — полноценный запуск майнера" },
            { "NET.POOL_DOMAIN", "Соединение с адресом, который распознаётся как пул майнинга" }, { "NET.MINING_PORT", "Соединение с портом, типичным для майнинг-пулов" },
            { "NET.PERSISTENT_UNTRUSTED", "Непроверенная программа держит постоянное соединение с внешним адресом" },
            { "NET.SYSTEM_TOOL_EXTERNAL", "Эта системная утилита обычно не выходит в интернет, а здесь есть внешние соединения (типично для подменённых процессов)" },
            { "BEH.CPU_SUSTAINED", "Держит высокую загрузку процессора в фоне" }, { "BEH.GPU_SUSTAINED", "Держит высокую загрузку видеокарты" }, { "BEH.CPU_NO_WINDOW", "Высокая загрузка CPU у программы без окна" },
            { "REL.DUPLICATES", "Точные копии лежат в других местах (признак разброса копий)" }, { "WATCHDOG.MULTI_PAYLOAD", "Несколько программ одной группы стоят в автозапуске — одна может перезапускать другую (watchdog)" },
            { "PERSIST.MULTI", "Несколько независимых способов автозапуска запускают одну и ту же программу — так заражения переживают чистку" },
            { "PERSIST.TARGET_USER_PATH", "Автозапуск запускает непроверенную программу из пользовательской папки" }, { "PERSIST.TARGET_UNSIGNED", "Автозапуск запускает неподписанную программу" },
            { "PERSIST.TARGET_MISSING", "Программы, которую запускает этот элемент, уже нет" }, { "PERSIST.LOLBIN_USERPATH", "Системный интерпретатор запускает файл из пользовательской папки" },
            { "TASK.HIDDEN", "Скрытая задача (не видна в Планировщике по умолчанию)" }, { "TASK.HIGHEST", "Запускается с наивысшими правами из пользовательской папки" },
            { "TASK.REPEAT_SHORT", "Перезапускается каждые несколько минут (признак watchdog/респавна)" }, { "TASK.MULTI_TRIGGER", "Несколько разных триггеров (загрузка + вход + таймер)" },
            { "TASK.MS_NAMESPACE_UNTRUSTED", "Задача спрятана в \\Microsoft\\…, но запускает программу без подписи Microsoft" }, { "TASK.XML_MISSING", "Остаток в кэше Планировщика: XML-файла задачи больше нет (мусор после чистильщиков, не угроза)" }, { "TASK.SD_MISSING", "У задачи удалён дескриптор безопасности — она не видна в Планировщике, но может выполняться (приём реальных вредоносных программ)" },
            { "SVC.IMAGE_USER_PATH", "Файл службы/драйвера лежит в пользовательской папке" }, { "SVC.NAME_EQUALS_TEMP_IMAGE", "Имя службы = имени exe, образ лежит во временной папке" },
            { "SVC.RANDOM_NAME", "Автозапускаемая служба со случайным именем из пользовательской папки" }, { "SVC.FAKE_DESCRIPTION", "Служба выдаёт себя за компонент Windows/Microsoft, но файл без подписи" },
            { "SVC.AUTO_RESTART_UNTRUSTED", "Служба сама перезапускается при остановке (watchdog) и лежит в пользовательской папке" }, { "SVC.SERVICEDLL_UNTRUSTED", "DLL службы (svchost) не подписана доверенным издателем" },
            { "DRV.UNSIGNED", "Драйвер ядра без действительной подписи" }, { "DRV.VULNERABLE_KNOWN", "Подписанный, но уязвимый драйвер, который майнеры используют для тюнинга процессора (его же применяют утилиты мониторинга железа)" },
            { "REG.WINLOGON_NONDEFAULT", "Параметр Winlogon отличается от стандартного Windows (запускается при каждом входе)" }, { "REG.APPINIT_DLLS", "AppInit_DLLs внедряет DLL в каждую программу" },
            { "REG.IFEO_DEBUGGER", "Подмена отладчика IFEO: при каждом запуске программы сначала стартует другая" }, { "REG.IFEO_BLOCK", "Запуск программы заблокирован через IFEO (так часто делают утилиты для «чистки» Windows; безобидно, если это сделали вы)" },
            { "REG.SILENT_PROCESS_EXIT", "При завершении процесса запускается программа (SilentProcessExit)" }, { "REG.LSA_PACKAGE", "Нестандартный пакет LSA загружается в подсистему безопасности" },
            { "REG.APPCERT_DLLS", "AppCertDLLs внедряет DLL в каждый запуск процесса" }, { "REG.BOOT_EXECUTE", "Нестандартный BootExecute запускается до полной загрузки Windows" },
            { "REG.ENV_PROFILER", "Переменная профилировщика заставляет каждую .NET/Java-программу загружать чужой код" },
            { "STARTUP.HIDDEN", "Скрытый файл в папке автозагрузки" }, { "STARTUP.INVISIBLE_NAME", "Элемент автозагрузки с невидимым/пустым именем" }, { "STARTUP.LNK_CMD", "Ярлык запускает cmd.exe /c (типично для подброшенных вирусных ярлыков)" },
            { "WMI.CMDLINE_CONSUMER", "Пользовательская WMI-подписка запускает команду (бесфайловый автозапуск)" }, { "WMI.SCRIPT_CONSUMER", "WMI-подписка выполняет скрипт (классический бесфайловый вирусный автозапуск)" },
            { "WMI.OTHER_CONSUMER", "Необычный WMI-потребитель событий" }, { "WMI.EVENTLOG_CONSUMER", "Дополнительный WMI-потребитель журнала событий" }, { "WMI.UNBOUND", "Потребитель без привязки (остаток)" }, { "WMI.ORPHAN_BINDING", "WMI-привязка указывает на потребителя, который нельзя прочитать" },
            { "TAMPER.DEF_EXCL_BROAD", "Защитнику велено игнорировать очень широкую область (диск / ProgramData / Temp / AppData / профиль)" }, { "TAMPER.DEF_EXCL_EXT", "Защитнику велено игнорировать целый тип файлов" },
            { "TAMPER.DEF_EXCL_MINER", "Защитнику велено игнорировать известный майнер" }, { "TAMPER.DEF_EXCL_USERPATH", "Защитнику велено игнорировать папку в пользовательской области" },
            { "TAMPER.HOSTS_BLOCKS_AV", "Файл hosts блокирует/перенаправляет сайты антивирусов и безопасности" }, { "TAMPER.HOSTS_BLOCKS_UPDATE", "Файл hosts блокирует серверы Windows Update / Защитника" },
            { "TAMPER.DISALLOWRUN_SECURITY", "Windows настроена не запускать программы безопасности/анализа" }, { "TAMPER.DISALLOWRUN_OTHER", "Проводник отказывается запускать некоторые программы (DisallowRun)" },
            { "TAMPER.TOOL_DISABLED", "Включён запрет на использование системного инструмента (диспетчер задач / редактор реестра / командная строка)" }, { "TAMPER.PROXY_SET", "Задан системный прокси / скрипт автонастройки" },
            { "TAMPER.PSHISTORY_DEFENDER", "В истории PowerShell есть команды, добавляющие исключения Защитника или выключающие защиту (так делают установщики майнеров; возможно, это вы)" },
            { "TAMPER.TERMSERVICE_DLL", "Служба удалённого рабочего стола загружает нестандартную DLL (как RDP Wrapper; встречается в наборах майнеров/RAT)" },
            { "FW.RULE_UNTRUSTED_APP", "Правило брандмауэра разрешает непроверенную программу из пользовательской папки" },
            { "BROWSER.EXT_MINER_CODE", "В расширении есть код майнинга криптовалют" }, { "BROWSER.EXT_UNPACKED", "Расширение загружено из папки (режим разработчика), а не из магазина" },
            { "BROWSER.EXT_EXTERNAL", "Расширение установлено другой программой, а не вами из магазина" }, { "BROWSER.EXT_POLICY", "Расширение установлено системной политикой" },
            { "BROWSER.EXT_FOREIGN_UPDATE", "Расширение обновляется не из официального магазина" }, { "BROWSER.EXT_POWERFUL", "Расширение может читать и менять весь ваш веб-трафик и куки" },
            { "BROWSER.EXT_WASM_ALLURLS", "Расширение содержит WebAssembly и работает на всех сайтах" }, { "BROWSER.EXT_UNSIGNED", "Расширение Firefox не подписано Mozilla" },
            { "BROWSER.FORCELIST", "Расширение принудительно установлено политикой реестра и не удаляется из браузера" }, { "BROWSER.SEARCH_HIJACK", "Поиск по умолчанию — незнакомый (признак угонщика поиска)" },
            { "BROWSER.START_PAGE", "Стартовая страница ведёт на незнакомый сайт" }, { "BROWSER.PROXY", "Браузер направляет трафик через прокси" },
            { "BROWSER.SHORTCUT_FLAGS", "Ярлык запускает браузер с опасными параметрами" }, { "BROWSER.SHORTCUT_URL", "Ярлык браузера каждый раз открывает незнакомый сайт (угон стартовой страницы)" },
            { "BROWSER.VSCODE_SCRIPT", "Расширение редактора содержит скрипт, отключающий защиту или скачивающий код" },
            // command-line rules (also used with PROC./PERSIST./SCRIPT. prefixes)
            { "CMD.MINER.STRATUM_URL", "В командной строке адрес майнинг-пула (stratum)" }, { "CMD.MINER.DONATE_LEVEL", "В командной строке параметр «donate» (комиссия автору майнера)" },
            { "CMD.MINER.ALGO_FLAG", "В командной строке выбран алгоритм майнинга" }, { "CMD.MINER.POOL_USER", "В командной строке адрес пула и пользователь/кошелёк" },
            { "CMD.MINER.WALLET_XMR", "В командной строке адрес кошелька Monero" }, { "CMD.MINER.POOL_NAME", "В командной строке известный майнинг-пул" },
            { "CMD.MINER.CPU_TUNING", "Параметры настройки майнера в командной строке" }, { "CMD.PS.ENCODED", "Скрытый PowerShell с закодированной командой" },
            { "CMD.PS.DOWNLOAD_EXEC", "PowerShell скачивает и запускает код" }, { "CMD.DEFENDER.EXCLUSION", "Команда добавляет исключения Защитника Windows" },
            { "CMD.DEFENDER.DISABLE", "Команда отключает Защитник Windows" }, { "CMD.DEFENDER.EXCLUSION_BROAD", "Команда исключает из проверки Защитника целый диск или системную папку" },
            { "PE.DOTNET_OBFUSCATED_HINT", ".NET-программа без каких-либо сведений о версии и с зашифрованным/обфусцированным содержимым (типично для вредоносных загрузчиков)" },
            { "MASQ.SYSFOLDER_LOOKALIKE", "Лежит в папке, которая имитирует системную папку Windows (например, system92)" }, { "TRUST.NGEN_CACHE", "Образ .NET, созданный самой Windows (кэш NGEN, без подписи по замыслу)" },
            { "BEH.CPU_AND_AUTOSTART", "Программа, которая нагружает процессор в фоне, ещё и сама запускается при старте системы" }, { "BROWSER.EXT_MINER_MENTION", "В коде расширения упоминается майнинг криптовалют" }, { "PROC.MASQUERADE_RUNNING", "Прямо сейчас работает процесс под именем системной/фирменной программы, но файл за ним — не настоящий" }, { "CMD.LOLBIN.REMOTE", "Системная утилита скачивает содержимое из интернета" },
            { "CMD.CMD.CHAIN", "Цепочка cmd.exe, запускающая другие инструменты" }, { "CMD.SCHTASKS.MINUTE", "Создаётся задача, запускающаяся каждые несколько минут (признак watchdog)" },
            { "CMD.POWERCFG.NEVER", "Отключён сон/гибернация (часто в установщиках майнеров)" }, { "CMD.RDP.WRAPPER", "Установка RDP Wrapper (встречается в наборах майнеров/RAT)" },
            { "NAME.MS.SYSTEM_HEALTH", "Имя под «здоровье системы Windows» (встречалось в кампании GPU-майнера 2026 года)" }, { "NAME.RUN.WINSYSCACHE", "Имя значения автозапуска из известной майнер-кампании" },
            { "NAME.SVC.DRVSVC", "Имя службы SilentCryptoMiner (выдаёт себя за службу драйвера)" }, { "NAME.MS.UPDATER_FAKE", "Имя похоже на «обновлятор» известного вендора (проверьте, какой файл запускается)" },
            { "NAME.MS.GENERIC", "Общее «виндоусоподобное» имя" }, { "NAME.HOMOGLYPH_TAG", "«Двойник» написания известного вендора" },
            { "IOC.PATH.RUNTIMEHOST_CACHES", "Исполняемый файл в Windows\\Caches\\<8hex> (путь установки кампании 2026 года)" },
            { "IOC.PATH.PROGRAMDATA_FAKE_VENDOR", "Папка ProgramData из набора майнера/RAT, встречавшегося в прежних кампаниях" }, { "IOC.PATH.SYSFILES_APPDATA", "Папка AppData с «системным» именем, используемая дропперами майнеров" },
            { "IOC.TASK.WINDOWSBACKUP_EXTRA", "Неизвестная задача в \\Microsoft\\Windows\\WindowsBackup (использовалась набором майнера из прежних кампаний)" },
        };
    }
}
