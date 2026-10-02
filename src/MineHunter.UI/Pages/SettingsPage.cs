using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Report;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>All settings in one scrolling page, in the groups the product describes: general, scan, protection, exclusions, schedule, updates, notifications, performance, interface, privacy, advanced.
    /// A change is saved at once; nothing needs an "apply" button except the few things that touch Windows (the Explorer menu, the tray task).</summary>
    public sealed class SettingsPage : PageBase
    {
        public override string Key { get { return "settings"; } }
        public override string Title { get { return L("Settings", "Настройки"); } }
        public override string Icon { get { return "sliders"; } }
        readonly StackPanel body = new StackPanel(); readonly Dictionary<string, FrameworkElement> anchors = new Dictionary<string, FrameworkElement>();
        ScrollViewer scroll; readonly WrapPanel jump = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };

        public SettingsPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            scroll = Ui.Scroll(body);
            var top = new StackPanel(); top.Children.Add(Header(L("Settings", "Настройки"), L("Everything is saved as soon as you change it.", "Всё сохраняется сразу, как только вы это меняете."))); top.Children.Add(jump);
            View = Frame(top, scroll);
        }

        public override void OnShow(object arg) { Build(); string a = arg as string; if (a != null && anchors.ContainsKey(a)) { var f = anchors[a]; View.Dispatcher.BeginInvoke(new Action(() => f.BringIntoView()), System.Windows.Threading.DispatcherPriority.Loaded); } }

        UIElement Section(string id, string title, params UIElement[] kids)
        {
            var sp = new StackPanel { Margin = new Thickness(0, 0, 0, 14) };
            var h = Ui.Txt(title, 16, null, FontWeights.Bold, true, new Thickness(2, 0, 0, 8)); anchors[id] = h; sp.Children.Add(h);
            var inner = new StackPanel(); foreach (var k in kids) if (k != null) inner.Children.Add(k);
            sp.Children.Add(Ui.Card(inner, 20)); return sp;
        }

        UIElement Note(string text) { return Ui.Txt(text, 12, Ui.Muted, null, true, new Thickness(0, 2, 0, 6)); }
        UIElement Label(string text) { return Ui.Txt(text, 12.5, Ui.Muted, FontWeights.SemiBold, true, new Thickness(0, 10, 0, 4)); }

        void Build()
        {
            var s = m.S; body.Children.Clear(); anchors.Clear(); jump.Children.Clear();

            // ---- general
            var preset = Ui.Combo(new[] { Ui.Kv("Normal", L("Normal", "Обычный")), Ui.Kv("Strict", L("Strict (more reports, archives and USB too)", "Строгий (больше сообщений, архивы и USB)")), Ui.Kv("Developer", L("Developer (build output and packages do not raise notes)", "Разработчик (сборки и пакеты не дают заметок)")) }, s.Preset, v => { s.ApplyPreset(v); s.Save(); Build(); }, 420);
            var shell = Ui.Sw(L("Add “Check with MineHunter” to the Explorer right-click menu", "Добавить «Проверить с MineHunter» в контекстное меню Проводника"), ShellIntegration.IsInstalled(), v =>
            {
                string err = v ? ShellIntegration.Install(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MineHunter.exe")) : ShellIntegration.Remove();
                if (err != null) Info(err);
            });
            body.Children.Add(Section("general", L("General", "Общие"),
                Label(L("Mode", "Режим")), preset, Note(L("The preset changes how many reports you get and what is looked at; protection stays on in every preset.", "Режим меняет количество сообщений и что проверяется; защита включена в любом режиме.")),
                Label(L("Language", "Язык")), Ui.Combo(new[] { Ui.Kv("ru", "Русский"), Ui.Kv("en", "English") }, Loc.Lang, v => { Loc.Init(v); m.Cfg.Language = v; m.Cfg.SaveUser(); m.Raise(); m.Navigate("settings", "general"); }, 220),
                Ui.Gap(8), shell, Note(L("Per-user entries; removing them leaves nothing behind. Windows asks for administrator rights each time MineHunter starts from the menu.", "Записи для текущего пользователя; при отключении ничего не остаётся. Windows запрашивает права администратора при каждом запуске MineHunter из меню.")),
                Ui.Sw(L("Closing the window keeps MineHunter in the tray (protection keeps working)", "Закрытие окна оставляет MineHunter в трее (защита продолжает работать)"), s.CloseToTray, v => { s.CloseToTray = v; s.Save(); })));

            // ---- scan
            body.Children.Add(Section("scan", L("Scan and performance", "Проверка и производительность"),
                Label(L("Sensitivity: how many independent signs are needed to report something", "Чувствительность: сколько независимых признаков нужно, чтобы сообщить о находке")),
                Ui.Combo(new[] { Ui.Kv("Normal", L("Normal (recommended)", "Обычная (рекомендуется)")), Ui.Kv("Strict", L("Strict: reports weaker evidence", "Строгая: сообщает и о слабых признаках")), Ui.Kv("Paranoid", L("Paranoid: reports almost every oddity (many false alarms)", "Параноидальная: сообщает почти о любой странности (много ложных тревог)")) }, s.Sensitivity, v => { s.Sensitivity = v; s.Save(); }, 460),
                Note(L("The level never lowers the evidence needed for “Critical”, and unknown files are never deleted automatically at any level.", "Уровень не снижает требований к улике для «Критической» находки, а неизвестные файлы не удаляются автоматически ни на одном уровне.")),
                Label(L("How much of the CPU a scan may use", "Сколько процессора может занять проверка")), Ui.Combo(new[] { Ui.Kv("0", L("Automatic (it yields to your programs)", "Автоматически (уступает вашим программам)")), Ui.Kv("25", "25 %"), Ui.Kv("50", "50 %"), Ui.Kv("75", "75 %") }, s.CpuLimit.ToString(), v => { s.CpuLimit = int.Parse(v); s.Save(); }, 340),
                Label(L("Scan threads", "Потоков проверки")), Ui.Combo(new[] { Ui.Kv("0", L("Automatic", "Автоматически")), Ui.Kv("1", "1"), Ui.Kv("2", "2"), Ui.Kv("4", "4"), Ui.Kv("8", "8") }, s.Threads.ToString(), v => { s.Threads = int.Parse(v); s.Save(); }, 220),
                Label(L("Largest file whose contents are read", "Самый большой файл, содержимое которого читается")), Ui.Combo(new[] { Ui.Kv("128", "128 MB"), Ui.Kv("256", "256 MB"), Ui.Kv("512", "512 MB"), Ui.Kv("1024", "1 GB"), Ui.Kv("2048", "2 GB") }, s.MaxFileSizeMb.ToString(), v => { s.MaxFileSizeMb = int.Parse(v); s.Save(); }, 220),
                Label(L("Full scan time limit", "Ограничение времени полной проверки")), Ui.Combo(new[] { Ui.Kv("0", L("None: until it is finished", "Без ограничения: до конца")), Ui.Kv("60", L("1 hour", "1 час")), Ui.Kv("180", L("3 hours", "3 часа")), Ui.Kv("360", L("6 hours", "6 часов")) }, s.FullScanMaxMinutes.ToString(), v => { s.FullScanMaxMinutes = int.Parse(v); s.Save(); }, 280),
                Ui.Gap(8), Ui.Sw(L("Look inside archives (ZIP)", "Заглядывать в архивы (ZIP)"), s.ScanArchives, v => { s.ScanArchives = v; s.Save(); }),
                Ui.Sw(L("Full scan also covers USB drives and memory cards", "Полная проверка охватывает и USB-накопители, карты памяти"), s.ScanRemovable, v => { s.ScanRemovable = v; s.Save(); }),
                Ui.Sw(L("Full scan also covers network drives", "Полная проверка охватывает и сетевые диски"), s.ScanNetworkDrives, v => { s.ScanNetworkDrives = v; s.Save(); }),
                Ui.Sw(L("Check the memory of running programs (hidden miners)", "Проверять память запущенных программ (спрятанные майнеры)"), s.ScanMemory, v => { s.ScanMemory = v; m.Cfg.ScanMemory = v; m.Cfg.SaveUser(); s.Save(); }),
                Ui.Sw(L("Check browsers and their extensions", "Проверять браузеры и их расширения"), s.ScanBrowsers, v => { s.ScanBrowsers = v; m.Cfg.ScanBrowsers = v; m.Cfg.SaveUser(); s.Save(); }),
                Ui.Sw(L("Also read the registry of users who are not signed in", "Читать также реестр пользователей, которые не вошли в систему"), s.OtherUserHives, v => { s.OtherUserHives = v; s.Save(); }),
                Ui.Sw(L("Game mode: no heavy work while a full-screen game is running", "Игровой режим: никакой тяжёлой работы, пока идёт полноэкранная игра"), s.GameMode, v => { s.GameMode = v; s.Save(); })));

            // ---- protection / schedule pointers
            body.Children.Add(Section("protection", L("Protection and schedule", "Защита и расписание"),
                Note(L("Real-time components and scheduled scans have their own pages.", "Компоненты защиты в реальном времени и плановые проверки вынесены на отдельные страницы.")),
                Ui.Wrap(Ui.Btn(L("Open Protection", "Открыть «Защита»"), () => m.Navigate("protection", null), "Btn"), Ui.Btn(L("Open Schedule", "Открыть «Расписание»"), () => m.Navigate("schedule", null), "Btn"))));

            // ---- exclusions
            var ex = new StackPanel();
            ex.Children.Add(Note(L("Folders and publishers MineHunter will not report. A file can also be trusted by its exact SHA-256 (“This file is safe”). Exclude only what you know.", "Папки и издатели, о которых MineHunter не будет сообщать. Файлу также можно доверять по точному SHA-256 («Это безопасный файл»). Исключайте только то, что знаете.")));
            ex.Children.Add(Label(L("Excluded folders and files", "Исключённые папки и файлы")));
            foreach (var p in s.ExcludedPaths.ToList()) { var path = p; var row = Ui.Cols(new[] { "*", "Auto" }, Ui.Mono(path, 12, Ui.TextB, false), Ui.Btn(L("Remove", "Убрать"), () => { s.ExcludedPaths.Remove(path); s.Save(); Build(); }, "BtnGhost")); row.Margin = new Thickness(0, 2, 0, 2); ex.Children.Add(row); }
            if (s.ExcludedPaths.Count == 0) ex.Children.Add(Ui.Txt(L("None.", "Нет."), 12.5, Ui.Muted));
            ex.Children.Add(Ui.Wrap(Ui.Btn(L("Add a folder…", "Добавить папку…"), () => { using (var dlg = new System.Windows.Forms.FolderBrowserDialog { ShowNewFolderButton = false }) if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) { if (!s.AddExclusion(dlg.SelectedPath)) Info(L("This folder is too broad to be excluded (a whole drive, Windows, Program Files or the user profile).", "Эта папка слишком широкая для исключения (весь диск, Windows, Program Files или профиль пользователя).")); else { s.Save(); Build(); } } }, "Btn")));
            ex.Children.Add(Label(L("Trusted publishers (valid signatures only)", "Доверенные издатели (только действующие подписи)")));
            foreach (var p in s.ExcludedPublishers.ToList()) { var pub = p; var row = Ui.Cols(new[] { "*", "Auto" }, Ui.Txt(pub, 12.5, Ui.TextB, null, false), Ui.Btn(L("Remove", "Убрать"), () => { s.ExcludedPublishers.Remove(pub); s.Save(); Build(); }, "BtnGhost")); row.Margin = new Thickness(0, 2, 0, 2); ex.Children.Add(row); }
            if (s.ExcludedPublishers.Count == 0) ex.Children.Add(Ui.Txt(L("None. Add a publisher from a file's report (“This file is safe” > “Its publisher”).", "Нет. Издателя можно добавить из отчёта о файле («Это безопасный файл» > «Его издателя»)."), 12.5, Ui.Muted));
            int hashes = Allowlist.Load().Sha256.Count;
            ex.Children.Add(Label(L("Files trusted by SHA-256: ", "Файлов, которым доверяют по SHA-256: ") + hashes));
            if (hashes > 0) ex.Children.Add(Ui.Btn(L("Forget all of them", "Забыть все"), () => { if (Ask(L("Stop trusting every file you marked as safe?", "Перестать доверять всем файлам, которые вы пометили безопасными?"), null, true)) { var al = new Allowlist(); al.Save(); Build(); } }, "BtnGhost"));
            body.Children.Add(Section("exclusions", L("Exclusions", "Исключения"), ex));

            // ---- updates
            var up = m.AppUpdate; string upText = m.CheckingUpdates ? L("Checking…", "Проверяю…") : up == null ? L("Not checked yet.", "Ещё не проверялось.") : up.State == AppUpdateState.UpToDate ? L("You have the latest version.", "У вас последняя версия.") : up.State == AppUpdateState.Ready ? L("Version " + up.StagedVersion + " is downloaded and verified: ready to install.", "Версия " + up.StagedVersion + " скачана и проверена: готова к установке.") : up.State == AppUpdateState.Available ? L("Version " + (up.Release == null ? "" : up.Release.Version) + " is available.", "Доступна версия " + (up.Release == null ? "" : up.Release.Version) + ".") : (up.Message ?? "");
            var upBtns = Ui.Wrap(Ui.Btn(L("Check now", "Проверить сейчас"), () => { m.CheckUpdates(true, Build); }, "Btn"));
            if (up != null && up.State == AppUpdateState.Ready) upBtns.Children.Add(Ui.Btn(L("Install now", "Установить сейчас"), () => { if (Ask(L("Install the update now? MineHunter closes, installs it and starts again; if anything fails, the current version is put back.", "Установить обновление сейчас? MineHunter закроется, установит и запустится снова; если что-то пойдёт не так, текущая версия вернётся."), L("Install", "Установить"))) { string err = m.InstallUpdate(); if (err != null) Info(err); } }, "BtnPrimary"));
            string back = AppUpdater.BackupVersion();
            if (back != null) upBtns.Children.Add(Ui.Btn(L("Go back to version ", "Вернуться к версии ") + back, () => { if (Ask(L("Put the previous version " + back + " back? MineHunter closes and restarts.", "Вернуть предыдущую версию " + back + "? MineHunter закроется и запустится снова."), L("Go back", "Вернуться"))) { string err = AppUpdater.StartRollback(AppDomain.CurrentDomain.BaseDirectory, Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MineHunter.exe")); if (err != null) Info(err); else System.Windows.Application.Current.Shutdown(); } }, "BtnGhost"));
            body.Children.Add(Section("updates", L("Updates", "Обновления"),
                Ui.Txt(L("Program version ", "Версия программы ") + AppInfo.Version + "   ·   " + L("rules ", "правила ") + m.RulesVersion, 13.5, null, FontWeights.SemiBold), Ui.Txt(upText, 12.5, Ui.Muted, null, true, new Thickness(0, 4, 0, 8)),
                Ui.Sw(L("Download new program versions automatically (installing needs your click)", "Скачивать новые версии программы автоматически (установка — по вашему клику)"), s.AutoUpdateApp, v => { s.AutoUpdateApp = v; s.Save(); }),
                Ui.Sw(L("Install newer detection rules automatically", "Устанавливать новые правила обнаружения автоматически"), m.Cfg.AutoUpdateRules, v => { m.Cfg.AutoUpdateRules = v; m.Cfg.SaveUser(); }),
                Ui.Sw(L("Check for updates when the program starts", "Проверять обновления при запуске программы"), m.Cfg.CheckUpdatesOnStart, v => { m.Cfg.CheckUpdatesOnStart = v; m.Cfg.SaveUser(); }),
                Note(L("An update is accepted only after its announcement is verified (RSA signature), the package matches the signed SHA-256 and size, and the files are unpacked safely. A separate helper installs it after MineHunter closes, keeps a copy of everything it replaces and puts it back if anything goes wrong. Only the official GitHub release is used.", "Обновление принимается только после проверки объявления (подпись RSA), совпадения пакета с подписанными SHA-256 и размером и безопасной распаковки. Отдельный помощник устанавливает его после закрытия MineHunter, хранит копию всего заменяемого и возвращает её, если что-то пошло не так. Используется только официальный релиз на GitHub.")), upBtns));

            // ---- notifications
            body.Children.Add(Section("notifications", L("Notifications", "Уведомления"),
                Label(L("Show warnings from this level up", "Показывать предупреждения начиная с уровня")), Ui.Combo(new[] { Ui.Kv("Info", L("Information (everything)", "Информация (всё)")), Ui.Kv("Suspicious", L("Suspicious (recommended)", "Подозрительное (рекомендуется)")), Ui.Kv("Dangerous", L("Dangerous only", "Только опасное")) }, s.NotifyLevel, v => { s.NotifyLevel = v; s.Save(); }, 340),
                Ui.Sw(L("Play a sound", "Проигрывать звук"), s.NotifySound, v => { s.NotifySound = v; s.Save(); }),
                Note(L("Warnings say what concretely happened (“a program from Temp created an autostart task and connected to a new address”), not a score.", "Предупреждения говорят, что именно произошло («программа из Temp создала задачу автозапуска и подключилась к новому адресу»), а не оценку в баллах."))));

            // ---- interface
            body.Children.Add(Section("interface", L("Interface", "Интерфейс"),
                Label(L("Theme", "Тема")), Ui.Combo(new[] { Ui.Kv("Dark", L("Dark", "Тёмная")) }, "Dark", v => { }, 220), Note(L("More themes may come later.", "Другие темы могут появиться позже.")),
                Ui.Sw(L("Show minor notes in scan results by default", "Показывать мелкие заметки в результатах по умолчанию"), s.ShowNotesInResults, v => { s.ShowNotesInResults = v; s.Save(); })));

            // ---- privacy
            var key = new PasswordBox { Width = 380, HorizontalAlignment = HorizontalAlignment.Left, ToolTip = L("Your VirusTotal API key (kept encrypted on this PC)", "Ваш ключ API VirusTotal (хранится на этом ПК в зашифрованном виде)") };
            var keyBtns = Ui.Wrap(Ui.Btn(L("Save the key", "Сохранить ключ"), () => { s.SetVirusTotalKey(key.Password); s.Save(); key.Password = ""; Info(string.IsNullOrEmpty(s.VirusTotalKeyProtected) ? L("The key was removed.", "Ключ удалён.") : L("The key is saved (encrypted).", "Ключ сохранён (в зашифрованном виде).")); }, "Btn"));
            body.Children.Add(Section("privacy", L("Privacy", "Приватность"),
                Ui.Txt(Loc.T("privacy.text"), 13, Ui.TextB),
                Ui.Txt(L("What MineHunter sends and when: nothing about your files or PC is ever sent automatically. It downloads the public version.json and rule/program packages from the official GitHub repository (a plain download: no identifiers). If you switch on VirusTotal below, only the SHA-256 of a file you check is sent, to VirusTotal, with your own key; a file is never uploaded.", "Что и когда отправляет MineHunter: ничего о ваших файлах и ПК не отправляется автоматически. Он скачивает публичный version.json и пакеты правил/программы из официального репозитория GitHub (обычная загрузка, без идентификаторов). Если ниже включить VirusTotal, отправляется только SHA-256 проверяемого вами файла — в VirusTotal, с вашим ключом; сам файл не загружается никогда."), 12.5, Ui.Muted, null, true, new Thickness(0, 8, 0, 8)),
                Ui.Sw(L("Ask VirusTotal about the hash of files I check (off by default)", "Спрашивать VirusTotal о хеше проверяемых мной файлов (по умолчанию выключено)"), s.VirusTotalLookup, v => { s.VirusTotalLookup = v; s.Save(); }),
                Label(L("VirusTotal API key", "Ключ API VirusTotal")), key, keyBtns,
                Ui.Sw(L("MineHunter Cloud lookup (not available in this version)", "Поиск в MineHunter Cloud (в этой версии недоступен)"), false, v => { }), Note(L("MineHunter Cloud is planned; there is no server yet, so nothing can be sent to it.", "MineHunter Cloud запланирован; сервера пока нет, поэтому отправлять нечего.")),
                Ui.Btn(L("Open the reports folder", "Открыть папку отчётов"), () => AppModel.Open(ReportWriter.DefaultDir), "BtnGhost")));

            // ---- advanced
            string exe = ""; try { exe = System.Reflection.Assembly.GetEntryAssembly().Location; } catch { }
            body.Children.Add(Section("advanced", L("Advanced", "Дополнительно"),
                Ui.Txt("MineHunter " + AppInfo.Version + "   ·   " + L("rules ", "правила ") + m.RulesVersion + "   ·   " + (m.Cfg.GitHubRepo ?? ""), 12.5, Ui.Muted, null, true, new Thickness(0, 0, 0, 4)),
                Ui.Mono(L("Program: ", "Программа: ") + exe + "\n" + L("Data folder: ", "Папка данных: ") + RulePack.DataDir + "\n" + L("Reports: ", "Отчёты: ") + ReportWriter.DefaultDir + "\n" + L("Quarantine: ", "Карантин: ") + Quarantine.Root, 11.5, Ui.Muted, true),
                Ui.Gap(8),
                Ui.Wrap(Ui.Btn(L("Open the data folder", "Открыть папку данных"), () => AppModel.Open(RulePack.DataDir), "Btn"), Ui.Btn(L("Show the log", "Показать журнал"), () => { try { string f = Log.FilePath; if (f != null && File.Exists(f)) AppModel.Open(f); else Info(string.Join("\n", Log.Snapshot().Reverse().Take(60).Reverse())); } catch { } }, "Btn"),
                    Ui.Btn(L("Reset all settings…", "Сбросить все настройки…"), () => { if (Ask(L("Reset every setting to its default? Exclusions are cleared too. Quarantine and history are kept.", "Сбросить все настройки по умолчанию? Исключения тоже очистятся. Карантин и история сохранятся."), L("Reset", "Сбросить"), true)) { var n = new Settings(); n.Save(); Settings.Reload(); Build(); } }, "BtnGhost"))));

            foreach (var kv in new[] { Tuple.Create("general", L("General", "Общие")), Tuple.Create("scan", L("Scan", "Проверка")), Tuple.Create("exclusions", L("Exclusions", "Исключения")), Tuple.Create("updates", L("Updates", "Обновления")), Tuple.Create("notifications", L("Notifications", "Уведомления")), Tuple.Create("privacy", L("Privacy", "Приватность")), Tuple.Create("advanced", L("Advanced", "Дополнительно")) })
            {
                string id = kv.Item1; var b = Ui.Btn(kv.Item2, () => { if (anchors.ContainsKey(id)) anchors[id].BringIntoView(); }, "BtnSmall"); b.Margin = new Thickness(0, 0, 6, 6); jump.Children.Add(b);
            }
        }
    }
}
