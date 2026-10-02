using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Analysis;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>"Check a file": drop a file here (or choose one, or use the Explorer right-click menu) and get the verdict in plain words, the reasons, and every technical detail. The program
    /// only reads the file; it never runs it. A folder or a drive is handed to the scan.</summary>
    public sealed class FilesPage : PageBase
    {
        public override string Key { get { return "files"; } }
        public override string Title { get { return L("Check a file", "Проверка файла"); } }
        public override string Icon { get { return "file"; } }
        readonly ContentControl result = new ContentControl();
        readonly Border dropZone;
        FileReport current; int tabToShow;

        public FilesPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            var title = Header(L("Check a file", "Проверка файла"), L("Drop a file anywhere on this page. It is only read, never run.", "Перетащите файл в любое место этой страницы. Он только читается, но не запускается."));
            var pick = Ui.Btn(L("Choose a file…", "Выбрать файл…"), PickFile, "BtnPrimary");
            var folder = Ui.Btn(L("Scan a folder or drive…", "Проверить папку или диск…"), PickFolder, "Btn");
            dropZone = new Border { BorderBrush = Ui.B("Line"), BorderThickness = new Thickness(1.5), CornerRadius = new CornerRadius(14), Background = Ui.B("Surface"), Padding = new Thickness(20, 16, 20, 8), Margin = new Thickness(0, 0, 0, 14) };
            dropZone.Child = Ui.Cols(new[] { "Auto", "*", "Auto" }, Ui.Badge("download", Ui.Accent, 44), new StackPanel { Margin = new Thickness(16, 0, 16, 8), VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Txt(L("Drag a file here", "Перетащите файл сюда"), 15, null, FontWeights.Bold), Ui.Txt(L("or use Explorer: right-click a file > “Check with MineHunter”.", "или в Проводнике: правый клик по файлу > «Проверить с MineHunter»."), 12, Ui.Muted) } }, Ui.H(pick, folder));
            var top = new StackPanel(); top.Children.Add(title); top.Children.Add(dropZone);
            var grid = Frame(top, result);
            var root = new Border { Background = Brushes.Transparent, Child = grid, AllowDrop = true };
            root.DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) { dropZone.BorderBrush = Ui.Accent; e.Effects = DragDropEffects.Copy; } else e.Effects = DragDropEffects.None; e.Handled = true; };
            root.DragLeave += (s, e) => dropZone.BorderBrush = Ui.B("Line");
            root.Drop += (s, e) =>
            {
                dropZone.BorderBrush = Ui.B("Line");
                var files = e.Data.GetData(DataFormats.FileDrop) as string[]; if (files == null || files.Length == 0) return;
                if (Directory.Exists(files[0])) { AskScanFolder(files[0]); return; }
                Analyze(files[0], 0);
            };
            View = root;
            result.Content = Ui.Txt(L("The report appears here.", "Здесь появится отчёт."), 13, Ui.Muted);
        }

        public override void OnShow(object arg)
        {
            string path = arg as string;
            if (!string.IsNullOrEmpty(path)) { if (Directory.Exists(path)) AskScanFolder(path); else Analyze(path, 0); }
        }

        public void OpenDeep(string path) { Analyze(path, 2); }

        void PickFile()
        {
            using (var dlg = new System.Windows.Forms.OpenFileDialog { Title = L("Choose a file to check", "Выберите файл для проверки"), CheckFileExists = true })
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) Analyze(dlg.FileName, 0);
        }

        void PickFolder()
        {
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = L("Choose a folder or a drive to scan", "Выберите папку или диск для проверки"), ShowNewFolderButton = false })
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedPath)) AskScanFolder(dlg.SelectedPath);
        }

        void AskScanFolder(string path)
        {
            if (Ask(L("Scan this folder with MineHunter?\n\n", "Проверить эту папку с помощью MineHunter?\n\n") + path, L("Scan", "Проверить"))) m.Navigate("scan", new[] { path });
        }

        // ============================================================================================ analysis
        void Analyze(string path, int tab)
        {
            tabToShow = tab;
            result.Content = Ui.Card(Ui.Txt(L("Analysing ", "Анализирую ") + Path.GetFileName(path) + "…", 14, Ui.Muted), 22);
            Ui.Async(m.UiThread, () => FileAnalyzer.Analyze(path, m.S, true), (r, ex) =>
            {
                if (ex != null) { result.Content = Ui.Card(Ui.Txt(L("The file could not be analysed: ", "Файл не удалось проанализировать: ") + ex.Message, 13, Ui.Bad), 22); return; }
                current = r; Render(r);
            });
        }

        static Brush VerdictBrush(FileVerdict v)
        {
            switch (v)
            {
                case FileVerdict.KnownMalware: case FileVerdict.Dangerous: return Ui.Bad;
                case FileVerdict.Suspicious: return Ui.Warn;
                case FileVerdict.KnownTrusted: return Ui.Good;
                case FileVerdict.Unreadable: return Ui.Muted;
                default: return Ui.Accent;
            }
        }

        static string VerdictIcon(FileVerdict v)
        {
            switch (v) { case FileVerdict.KnownMalware: case FileVerdict.Dangerous: return "cross"; case FileVerdict.Suspicious: return "warn"; case FileVerdict.KnownTrusted: return "shieldcheck"; case FileVerdict.Unreadable: return "info"; default: return "shield"; }
        }

        void Render(FileReport r)
        {
            Brush col = VerdictBrush(r.Verdict);
            var hero = Ui.Cols(new[] { "Auto", "*" }, new Border { Width = 64, Height = 64, CornerRadius = new CornerRadius(32), Background = col, Child = Ui.Icon(VerdictIcon(r.Verdict), Brushes.White, 32, 2.4), VerticalAlignment = VerticalAlignment.Top },
                new StackPanel { Margin = new Thickness(18, 0, 0, 0), Children = { Ui.Txt(r.Name, 13, Ui.Muted, FontWeights.SemiBold, false), Ui.Txt(r.VerdictText ?? "", 20, null, FontWeights.Bold, true, new Thickness(0, 2, 0, 0)), Ui.Txt(r.Explanation ?? "", 13, Ui.Muted, null, true, new Thickness(0, 6, 0, 0)) } });
            var heroCard = Ui.Card(hero, 20); heroCard.Margin = new Thickness(0, 0, 0, 12);

            var tabs = new TabControl();
            tabs.Items.Add(new TabItem { Header = L("Overview", "Обзор"), Content = Ui.Scroll(OverviewTab(r)) });
            tabs.Items.Add(new TabItem { Header = L("Why suspicious", "Почему подозрительно"), Content = Ui.Scroll(WhyTab(r)) });
            tabs.Items.Add(new TabItem { Header = L("Technical data", "Технические данные"), Content = Ui.Scroll(TechTab(r)) });
            tabs.SelectedIndex = Math.Min(2, Math.Max(0, tabToShow));
            var g = new Grid(); g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); g.RowDefinitions.Add(new RowDefinition());
            Grid.SetRow(tabs, 1); g.Children.Add(heroCard); g.Children.Add(tabs);
            result.Content = g;
        }

        // ------------------------------------------------------------------------------------------------ overview
        static UIElement Fact(string label, string value, bool mono = false)
        {
            if (string.IsNullOrEmpty(value)) return null;
            var v = mono ? (FrameworkElement)Ui.Mono(value, 12, Ui.TextB, true) : Ui.Txt(value, 13, Ui.TextB, null, true);
            var g = Ui.Cols(new[] { "170", "*" }, Ui.Txt(label, 12.5, Ui.Muted, FontWeights.SemiBold), v); g.Margin = new Thickness(0, 4, 0, 4); return g;
        }

        UIElement OverviewTab(FileReport r)
        {
            var p = new StackPanel();
            var facts = Ui.V(Fact(L("Name", "Имя"), r.Name), Fact(L("Folder", "Папка"), Path.GetDirectoryName(r.Path), true), Fact(L("Where it lies", "Где лежит"), r.Location), Fact(L("Type", "Тип"), r.Kind), Fact(L("Size", "Размер"), r.Size > 0 ? Ui.FormatSize(r.Size) + "  (" + Ui.FormatNumber(r.Size) + " " + L("bytes", "байт") + ")" : null),
                Fact(L("Created / changed", "Создан / изменён"), r.Created.ToString("dd.MM.yyyy HH:mm") + "  /  " + r.Modified.ToString("dd.MM.yyyy HH:mm")), Fact("SHA-256", r.Sha256, true), Fact("SHA-1", r.Sha1, true), Fact("MD5", r.Md5, true),
                Fact(L("Digital signature", "Цифровая подпись"), r.SignatureText), Fact(L("Publisher", "Издатель"), r.Publisher), Fact(L("Product", "Продукт"), string.Join(" · ", new[] { r.Company, r.Product, r.Description, r.FileVersion }.Where(x => !string.IsNullOrWhiteSpace(x)))),
                Fact(L("Origin", "Источник"), r.Origin), Fact(L("Downloaded from", "Скачан с"), r.HostUrl, true), Fact(L("Owner", "Владелец"), r.Owner));
            p.Children.Add(Ui.Card(facts, 16));
            p.Children.Add(Ui.Head(L("Reputation", "Репутация")));
            var rep = new StackPanel();
            foreach (var x in r.Reputation)
            {
                Brush c = !x.Available ? Ui.Muted : x.Status == RepStatus.KnownBad ? Ui.Bad : x.Status == RepStatus.Suspicious ? Ui.Warn : x.Status == RepStatus.KnownGood ? Ui.Good : Ui.Muted;
                string st = !x.Available ? L("not available", "недоступно") : Reputation.StatusText(x.Status);
                rep.Children.Add(Ui.Cols(new[] { "190", "*" }, Ui.Txt(x.Provider, 12.5, Ui.TextB, FontWeights.SemiBold, false), new StackPanel { Children = { Ui.Txt(st, 12.5, c, FontWeights.Bold), Ui.Txt(x.Detail ?? "", 11.5, Ui.Muted) } }));
                rep.Children.Add(Ui.Gap(6));
            }
            rep.Children.Add(Ui.Txt(L("“No data” does not mean “safe”: it means that source has never seen this file. A signature shows who published a file, not that it is harmless.", "«Нет данных» не значит «безопасно»: это значит, что источник такой файл не видел. Подпись показывает издателя, а не безвредность."), 11.5, Ui.Muted));
            p.Children.Add(Ui.Card(rep, 16));

            p.Children.Add(Ui.Head(L("Actions", "Действия")));
            var btns = new WrapPanel();
            btns.Children.Add(Ui.Btn(L("Show in folder", "Показать в папке"), () => ShowInFolder(r.Path), "Btn"));
            btns.Children.Add(Ui.Btn(L("Copy SHA-256", "Копировать SHA-256"), () => { try { Clipboard.SetText(r.Sha256); } catch { } }, "BtnGhost"));
            if (r.Verdict == FileVerdict.Suspicious || r.Verdict == FileVerdict.Dangerous || r.Verdict == FileVerdict.KnownMalware)
                btns.Children.Add(Ui.Btn(L("Move to quarantine", "В карантин"), () => ToQuarantine(r), "BtnDanger"));
            btns.Children.Add(Ui.Btn(L("This file is safe…", "Это безопасный файл…"), () => MarkSafe(r), "Btn"));
            btns.Children.Add(Ui.Btn(L("False-positive report…", "Отчёт о ложном срабатывании…"), () => FalsePositive(r), "BtnGhost"));
            btns.Children.Add(Ui.Btn(L("Open on VirusTotal (sends only the hash)", "Открыть на VirusTotal (уйдёт только хеш)"), () => OpenVt(r), "BtnGhost"));
            p.Children.Add(btns);
            return p;
        }

        // ------------------------------------------------------------------------------------------------ why
        UIElement WhyTab(FileReport r)
        {
            var p = new StackPanel();
            p.Children.Add(Ui.Txt(r.Explanation ?? "", 13.5));
            p.Children.Add(Ui.Head(L("Evidence (what was found, with its weight)", "Улики (что найдено и сколько это весит)")));
            if (r.Evidence.Count == 0) p.Children.Add(Ui.Card(Ui.Txt(L("No signs of a threat were found by the checks. That is not a guarantee of safety: it is the absence of the signs MineHunter looks for.", "Признаков угрозы проверки не нашли. Это не гарантия безопасности: это отсутствие тех признаков, которые ищет MineHunter."), 13), 16));
            foreach (var ev in r.Evidence)
            {
                Brush wc = ev.Weight < 0 ? Ui.Good : ev.Weight >= 40 ? Ui.Bad : ev.Weight >= 20 ? Ui.Orange : ev.Weight >= 10 ? Ui.Warn : Ui.Muted;
                var sp = new StackPanel(); sp.Children.Add(Ui.Txt(Loc.Ev(ev), 13));
                sp.Children.Add(Ui.Mono("[" + Loc.CategoryName(ev.Category) + "]  " + ev.RuleId + (ev.Definitive ? "  " + L("decisive", "решающая") : "") + (string.IsNullOrEmpty(ev.Detail) ? "" : "  " + Text.Trunc(ev.Detail, 140)), 11, null, true));
                var row = Ui.Cols(new[] { "54", "*" }, Ui.Txt((ev.Weight >= 0 ? "+" : "") + ev.Weight, 14, wc, FontWeights.Bold), sp); row.Margin = new Thickness(0, 5, 0, 5);
                p.Children.Add(row);
            }
            if (r.Detail != null)
            {
                p.Children.Add(Ui.Head(L("How the verdict is made", "Как складывается вердикт")));
                p.Children.Add(Ui.Txt(L("Total score ", "Сумма баллов ") + r.Score + " / 100. " + L("Each kind of evidence is capped, and High Risk needs several independent kinds to agree (not one loud signal). Categories: ", "Каждый вид улик ограничен, а «высокий риск» требует согласия нескольких независимых видов (а не одного громкого признака). Категории: ") + string.Join(", ", r.Detail.ByCategory.Select(kv => Loc.CategoryName(kv.Key) + " " + (int)kv.Value)) + ".", 12.5, Ui.Muted));
            }
            if (r.RulesFired.Count > 0) { p.Children.Add(Ui.Head(L("Rules that fired", "Сработавшие правила"))); p.Children.Add(Ui.Mono(string.Join("\n", r.RulesFired), 12, null, true)); }
            return p;
        }

        // ------------------------------------------------------------------------------------------------ technical
        UIElement TechTab(FileReport r)
        {
            var p = new StackPanel();
            var pe = r.Pe;
            if (pe != null)
            {
                p.Children.Add(Ui.Head(L("Program header", "Заголовок программы"), new Thickness(0, 0, 0, 8)));
                p.Children.Add(Ui.Card(Ui.V(Fact(L("Architecture", "Архитектура"), pe.Is64 ? "x64" : "x86"), Fact(L("Subsystem", "Подсистема"), pe.IsDriver ? "Native / driver" : pe.Subsystem == 3 ? "Console" : pe.Subsystem == 2 ? "Windows GUI" : pe.Subsystem.ToString()), Fact(L("Compiled", "Скомпилирован"), pe.TimeDateStamp == 0 ? null : new DateTime(1970, 1, 1).AddSeconds(pe.TimeDateStamp).ToString("yyyy-MM-dd HH:mm") + " UTC"),
                    Fact(L("Entry point", "Точка входа"), "0x" + pe.EntryPoint.ToString("X")), Fact(L("Image size", "Размер образа"), Ui.FormatSize(pe.SizeOfImage)), Fact(".NET", pe.IsDotNet ? L("yes", "да") : L("no", "нет")), Fact(L("Has TLS callbacks", "TLS-обратные вызовы"), pe.HasTls ? L("yes", "да") : L("no", "нет")), Fact(L("Resources", "Ресурсы"), pe.HasResources ? L("yes", "да") : L("no", "нет")),
                    Fact(L("Appended data (overlay)", "Данные в конце (overlay)"), pe.Overlay > 0 ? Ui.FormatSize(pe.Overlay) : L("none", "нет")), Fact(L("Highest entropy of code", "Макс. энтропия кода"), pe.MaxExecEntropy > 0 ? pe.MaxExecEntropy.ToString("0.00") + " / 8" : null),
                    Fact(L("Packer hints", "Признаки упаковщика"), r.Packers.Count == 0 ? L("none", "нет") : string.Join("; ", r.Packers)), Fact(L("Requested rights", "Запрашиваемые права"), r.ExecutionLevel), Fact(L("Original name", "Исходное имя"), r.OriginalName), Fact(L("Internal name", "Внутреннее имя"), r.InternalName)), 16));
                if (pe.Sections.Count > 0)
                {
                    p.Children.Add(Ui.Head(L("Sections", "Секции")));
                    var rows = new StackPanel();
                    rows.Children.Add(TableRow(true, L("Name", "Имя"), L("Virtual size", "Вирт. размер"), L("Raw size", "Размер в файле"), L("Entropy", "Энтропия"), L("Flags", "Флаги")));
                    foreach (var s in pe.Sections) rows.Children.Add(TableRow(false, s.Name, Ui.FormatNumber(s.VirtualSize), Ui.FormatNumber(s.RawSize), s.Entropy > 0 ? s.Entropy.ToString("0.00") : "-", (s.Executable ? "X" : "-") + (s.Writable ? "W" : "-")));
                    p.Children.Add(Ui.Card(rows, 16));
                }
                if (pe.ImportNames.Count > 0)
                {
                    p.Children.Add(Ui.Head(L("Imports (" + pe.ImportDlls.Count + " libraries, " + pe.ImportFuncCount + " functions)", "Импорт (" + pe.ImportDlls.Count + " библиотек, " + pe.ImportFuncCount + " функций)")));
                    var groups = pe.ImportNames.GroupBy(x => x.Split('!')[0]).OrderByDescending(g => g.Count()).Take(14);
                    var sp = new StackPanel();
                    foreach (var g in groups) sp.Children.Add(Ui.Mono(g.Key + "  (" + g.Count() + "):  " + string.Join(", ", g.Select(x => x.Substring(x.IndexOf('!') + 1)).Take(10)) + (g.Count() > 10 ? ", …" : ""), 11.5, Ui.TextB, true));
                    if (pe.ApiOfInterest.Count > 0) sp.Children.Insert(0, Ui.Txt(L("Functions that programs use to inject code or download files: ", "Функции, которыми программы внедряют код или качают файлы: ") + string.Join(", ", pe.ApiOfInterest), 12, Ui.Warn, null, true, new Thickness(0, 0, 0, 8)));
                    p.Children.Add(Ui.Card(sp, 16));
                }
                if (pe.ExportNames.Count > 0) { p.Children.Add(Ui.Head(L("Exports", "Экспорт") + " (" + pe.ExportCount + ")")); p.Children.Add(Ui.Card(Ui.Mono(string.Join(", ", pe.ExportNames.Take(60)), 11.5, Ui.TextB, true), 16)); }
            }
            if (r.CertChain.Count > 0) { p.Children.Add(Ui.Head(L("Certificate chain", "Цепочка сертификатов"))); p.Children.Add(Ui.Card(Ui.Mono(string.Join("\n", r.CertChain), 11.5, Ui.TextB, true), 16)); }
            if (!string.IsNullOrEmpty(r.Manifest)) { p.Children.Add(Ui.Head(L("Manifest", "Манифест"))); p.Children.Add(Ui.Card(Ui.Mono(r.Manifest, 11, Ui.TextB, true), 16)); }
            p.Children.Add(Ui.Head(L("Strings found in the file", "Строки в файле")));
            var strings = new StackPanel();
            Action<string, List<string>> block = (t, l) => { if (l.Count == 0) return; strings.Children.Add(Ui.Txt(t, 12, Ui.Muted, FontWeights.SemiBold, true, new Thickness(0, 6, 0, 2))); strings.Children.Add(Ui.Mono(string.Join("\n", l.Take(25)), 11.5, Ui.TextB, true)); };
            block(L("Web addresses", "Веб-адреса"), r.Urls); block(L("Domains", "Домены"), r.Domains); block(L("IP addresses", "IP-адреса"), r.Ips); block(L("PowerShell / script fragments", "Фрагменты PowerShell / скриптов"), r.PowerShell); block(L("Miner markers from the rule pack", "Маркеры майнера из набора правил"), r.MinerMarkers);
            if (strings.Children.Count == 0) strings.Children.Add(Ui.Txt(L("No addresses, scripts or miner markers were found in the readable strings.", "В читаемых строках не найдено адресов, скриптов и маркеров майнера."), 12.5, Ui.Muted));
            p.Children.Add(Ui.Card(strings, 16));
            return p;
        }

        static UIElement TableRow(bool head, params string[] cells)
        {
            var g = new Grid { Margin = new Thickness(0, 2, 0, 2) };
            double[] w = { 130, 120, 120, 80, 70 };
            for (int i = 0; i < cells.Length; i++)
            {
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(w[Math.Min(i, w.Length - 1)]) });
                var t = head ? Ui.Txt(cells[i], 11, Ui.Muted, FontWeights.Bold, false) : Ui.Mono(cells[i], 12, Ui.TextB, false);
                Grid.SetColumn(t, i); g.Children.Add(t);
            }
            return g;
        }

        // ------------------------------------------------------------------------------------------------ actions
        static void ShowInFolder(string p) { try { if (File.Exists(p)) Process.Start("explorer.exe", "/select,\"" + p + "\""); } catch { } }

        void ToQuarantine(FileReport r)
        {
            if (!Ask(L("Move this file to the quarantine? It is not deleted: you can restore it from the Quarantine page. A program that runs from it will be stopped.", "Переместить файл в карантин? Он не удаляется: его можно вернуть на странице «Карантин». Запущенная из него программа будет остановлена."), L("Move to quarantine", "В карантин"), true)) return;
            string err = GuardHost.QuarantineFile(r.Path, "File check", 0);
            Info(err == null ? L("The file is in the quarantine.", "Файл в карантине.") : err);
        }

        void MarkSafe(FileReport r)
        {
            int c = Dlg.Choose(owner(), L("This file is safe", "Это безопасный файл"), L("How should MineHunter treat it from now on?\n\n• This exact file: only a file with this SHA-256 is trusted; if it changes, it is checked again.\n• Its folder: nothing in the folder is scanned any more (less safe).\n• Its publisher: every valid signature of this publisher is trusted.", "Как MineHunter должен относиться к нему дальше?\n\n• Именно этот файл: доверяется только файл с таким SHA-256; если он изменится, проверится заново.\n• Его папка: ничего в папке больше не проверяется (менее безопасно).\n• Его издатель: доверяется любая действующая подпись этого издателя."),
                L("This exact file", "Именно этот файл"), L("Its folder", "Его папку"), !string.IsNullOrEmpty(r.Publisher) && r.Trust != null && r.Trust.IsValid ? L("Its publisher", "Его издателя") : null, L("Cancel", "Отмена"));
            var buttons = new List<string> { "file", "folder" }; if (!string.IsNullOrEmpty(r.Publisher) && r.Trust != null && r.Trust.IsValid) buttons.Add("publisher");
            if (c < 0 || c >= buttons.Count) return;
            var s = Settings.Current;
            switch (buttons[c])
            {
                case "file": { var al = Rules.Allowlist.Load(); if (al.Approve(r.Path) == null) { Info(L("The file could not be read, nothing was approved.", "Файл не удалось прочитать, ничего не одобрено.")); return; } al.Save(); break; }
                case "folder": if (!s.AddExclusion(Path.GetDirectoryName(r.Path))) { Info(L("This folder is too broad to be excluded.", "Эта папка слишком широкая для исключения.")); return; } s.Save(); break;
                case "publisher": if (!s.ExcludedPublishers.Contains(r.Publisher, StringComparer.OrdinalIgnoreCase)) s.ExcludedPublishers.Add(r.Publisher); s.Save(); break;
            }
            Info(L("Done. The setting is saved; see Settings > Exclusions to review or remove it.", "Готово. Настройка сохранена; посмотреть или убрать её можно в Настройки > Исключения."));
        }

        void FalsePositive(FileReport r)
        {
            string comment = Dlg.Prompt(owner(), L("False-positive report", "Отчёт о ложном срабатывании"), L("A text file will be created with what MineHunter knows about this file (hash, signature, reasons), with your user and PC names removed. NOTHING is sent anywhere: you decide whether to send it. You can add a comment:", "Будет создан текстовый файл с тем, что MineHunter знает об этом файле (хеш, подпись, причины), без имени пользователя и ПК. НИЧЕГО никуда не отправляется: отправлять или нет, решаете вы. Можно добавить комментарий:"), "", true);
            if (comment == null) return;
            string file = Path.Combine(Report.ReportWriter.DefaultDir, "false-positive-" + Path.GetFileNameWithoutExtension(r.Name) + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
            string err = FalsePositiveReport.Export(r, comment, file);
            if (err != null) { Info(err); return; }
            AppModel.Open(Path.GetDirectoryName(file));
            Info(L("The report is saved: ", "Отчёт сохранён: ") + file);
        }

        void OpenVt(FileReport r)
        {
            if (!Ask(L("This opens virustotal.com in your browser with this file's SHA-256 in the address. Only the hash is sent, the file is not uploaded. Continue?", "Откроется virustotal.com в браузере, а в адресе будет SHA-256 этого файла. Уходит только хеш, сам файл не загружается. Продолжить?"), L("Open", "Открыть"))) return;
            AppModel.Open("https://www.virustotal.com/gui/file/" + r.Sha256);
        }
    }
}
