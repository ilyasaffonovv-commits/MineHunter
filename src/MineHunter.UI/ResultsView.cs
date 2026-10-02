using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Gui
{
    public sealed class CleanupRow { public Finding F; public FindingOutcome Outcome; }

    /// <summary>The list of findings on the left and the explanation of the selected one on the right: what it is, where, why (every piece of evidence with its weight), the chain from the
    /// start to the file, what will be done, and the buttons. Used by the Scan page of the main window and by the Quick Scan / Full Scan windows.</summary>
    public sealed class ResultsView
    {
        sealed class Item { public Finding F; public Entity Note; }
        sealed class StepRow { public RemediationStep Step; public CheckBox Box; }

        public readonly FrameworkElement Root;
        readonly Func<Window> owner;
        readonly ListBox list; readonly StackPanel detail; readonly ScrollViewer detailScroll; readonly CheckBox notesBox; readonly TextBlock emptyText;
        readonly bool compact;
        ScanResult res; List<CleanupRow> cleanup; readonly List<StepRow> stepRows = new List<StepRow>();

        /// <summary>The user chose to neutralize: the host runs it (confirmation, restore point, progress) and shows the outcome.</summary>
        public Action<List<KeyValuePair<Finding, List<RemediationStep>>>> NeutralizeRequested = p => { };
        public Action<string> CheckFileRequested = p => { };
        public Action ResultChanged = () => { };

        static string L(string en, string ru) { return Loc.L(en, ru); }

        public ResultsView(Func<Window> ownerFn, bool compactMode = false)
        {
            owner = ownerFn; compact = compactMode;
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(compact ? 330 : 380) }); grid.ColumnDefinitions.Add(new ColumnDefinition());
            var left = new Grid(); left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); left.RowDefinitions.Add(new RowDefinition());
            notesBox = new CheckBox { Content = L("Show minor notes (not threats)", "Показывать мелкие заметки (не угрозы)"), Margin = new Thickness(2, 0, 0, 10) };
            notesBox.Checked += (s, e) => Populate(); notesBox.Unchecked += (s, e) => Populate();
            list = new ListBox { Style = Ui.S("FlatList") }; Grid.SetRow(list, 1);
            list.SelectionChanged += (s, e) => ShowSelected();
            emptyText = Ui.Txt("", 13.5, Ui.Muted); emptyText.Margin = new Thickness(4, 10, 16, 0); Grid.SetRow(emptyText, 1); emptyText.Visibility = Visibility.Collapsed;
            left.Children.Add(notesBox); left.Children.Add(list); left.Children.Add(emptyText);
            detail = new StackPanel { Margin = new Thickness(22, 18, 22, 18) };
            detailScroll = new ScrollViewer { Content = detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
            var card = Ui.Card(detailScroll, 0); Grid.SetColumn(card, 1);
            grid.Children.Add(left); grid.Children.Add(card);
            Root = grid;
        }

        // ============================================================================================ data in
        public void Show(ScanResult r, List<CleanupRow> cleanupRows = null)
        {
            res = r; cleanup = cleanupRows;
            Populate();
        }

        public ScanResult Result { get { return res; } }

        void Populate()
        {
            var items = new List<Item>();
            if (res != null)
            {
                foreach (var f in res.Findings) items.Add(new Item { F = f });
                if (notesBox.IsChecked == true) foreach (var n in res.Observations) items.Add(new Item { Note = n });
            }
            list.ItemsSource = null;
            list.Items.Clear();
            foreach (var it in items) list.Items.Add(Row(it));
            if (items.Count == 0)
            {
                emptyText.Visibility = Visibility.Visible;
                emptyText.Text = res == null ? L("No scan yet.", "Проверки ещё не было.") : L("Nothing suspicious was found.", "Ничего подозрительного не найдено.") + (res.Observations.Count > 0 ? "\n\n" + L("There are " + res.Observations.Count + " minor notes (not threats). Tick the box above to see them.", "Есть " + res.Observations.Count + " мелких заметок (не угроз). Отметьте галочку выше, чтобы их увидеть.") : "");
                ShowEmpty();
            }
            else { emptyText.Visibility = Visibility.Collapsed; list.SelectedIndex = 0; }
        }

        static Brush AccentOf(Verdict v) { return v == Verdict.Malware ? Ui.Bad : v == Verdict.HighRisk ? Ui.Orange : v == Verdict.Suspicious ? Ui.Warn : Ui.Muted; }

        static string MainLocation(Finding f)
        {
            var e = f.Entities.Where(x => x.Kind == EntityKind.File).OrderByDescending(x => x.Score).FirstOrDefault() ?? f.Entities.OrderByDescending(x => x.Score).FirstOrDefault();
            if (e == null) return "";
            return e.Kind == EntityKind.Task ? (e.P("taskPath") ?? e.Location) : (e.Location ?? e.Title);
        }

        ListBoxItem Row(Item it)
        {
            Brush acc = it.F != null ? AccentOf(it.F.Verdict) : Ui.Muted;
            string title = it.F != null ? Loc.Title(it.F.Title) : it.Note.Title;
            string sub = it.F != null ? MainLocation(it.F) : (it.Note.Kind == EntityKind.Task ? (it.Note.P("taskPath") ?? it.Note.Location) : it.Note.Location);
            string verdict = it.F != null ? (it.F.ToolClass != null ? L("GAME CHEAT  ·  KEPT", "ЧИТ  ·  ОСТАВЛЕНО") : Loc.Severity(it.F.Verdict).ToUpperInvariant()) : L("NOTE", "ЗАМЕТКА") + "  ·  " + Loc.KindName(it.Note.Kind);
            int score = it.F != null ? it.F.Score : it.Note.Score;
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) }); g.ColumnDefinitions.Add(new ColumnDefinition()); g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.Children.Add(new Border { Background = acc, CornerRadius = new CornerRadius(9, 0, 0, 9) });
            var sp = new StackPanel { Margin = new Thickness(12, 10, 8, 10) };
            sp.Children.Add(Ui.Txt(title, 13, null, FontWeights.SemiBold, false));
            sp.Children.Add(Ui.Txt(sub, 11.5, Ui.Muted, null, false, new Thickness(0, 2, 0, 0)));
            sp.Children.Add(Ui.Txt(verdict, 11, acc, FontWeights.SemiBold, false, new Thickness(0, 5, 0, 0)));
            Grid.SetColumn(sp, 1); g.Children.Add(sp);
            var badge = new Border { Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center, CornerRadius = new CornerRadius(12), Background = Ui.Soft(acc), Padding = new Thickness(9, 3, 9, 3), Child = Ui.Txt(score.ToString(), 13, acc, FontWeights.Bold) };
            Grid.SetColumn(badge, 2); g.Children.Add(badge);
            return new ListBoxItem { Content = g, Tag = it };
        }

        void ShowEmpty()
        {
            detail.Children.Clear();
            if (cleanup != null && cleanup.Count > 0) { ShowCleanup(); return; }
            detail.Children.Add(Ui.Txt(res == null ? L("Press “Quick scan” to check this computer.", "Нажмите «Быстрая проверка», чтобы проверить компьютер.") : Loc.T("scan.clean"), 15, Ui.Muted));
        }

        void ShowSelected()
        {
            var li = list.SelectedItem as ListBoxItem; var it = li == null ? null : li.Tag as Item;
            if (it == null) { if (list.Items.Count == 0) ShowEmpty(); return; }
            if (it.F != null) ShowFinding(it.F); else ShowNote(it.Note);
        }

        public void SelectFirst() { if (list.Items.Count > 0) list.SelectedIndex = 0; }
        public void SelectIndex(int i) { if (i >= 0 && i < list.Items.Count) list.SelectedIndex = i; }
        public void ShowNotes(bool on) { notesBox.IsChecked = on; }

        // ============================================================================================ details
        UIElement ScoreBar(int score, Brush acc)
        {
            var g = new Grid { Height = 8, Margin = new Thickness(0, 12, 0, 0) };
            g.Children.Add(new Border { CornerRadius = new CornerRadius(4), Background = Ui.B("Surface3") });
            var fill = new Border { CornerRadius = new CornerRadius(4), Background = acc, HorizontalAlignment = HorizontalAlignment.Left };
            g.Children.Add(fill);
            g.SizeChanged += (s, e) => fill.Width = Math.Max(6, g.ActualWidth * Math.Min(100, Math.Max(0, score)) / 100.0);
            return Ui.V(g, Ui.Txt(L("Suspicious ≥ 30   ·   High risk ≥ 60   ·   Malware ≥ 85 (only with corroborating evidence)", "Подозрительное ≥ 30   ·   Высокий риск ≥ 60   ·   Вредоносное ≥ 85 (только при подтверждении разными уликами)"), 10.5, Ui.Muted, null, true, new Thickness(0, 4, 0, 0)));
        }

        UIElement EvidenceRow(Evidence ev)
        {
            Brush wc = ev.Weight >= 40 ? Ui.Bad : ev.Weight >= 20 ? Ui.Orange : ev.Weight >= 10 ? Ui.Warn : Ui.Muted;
            var sp = new StackPanel();
            sp.Children.Add(Ui.Txt(Loc.Ev(ev), 13));
            string meta = "[" + Loc.CategoryName(ev.Category) + "]" + (ev.Definitive ? "  " + L("decisive", "решающая") : "") + (string.IsNullOrEmpty(ev.Detail) ? "" : "  " + Text.Trunc(ev.Detail, 120));
            sp.Children.Add(Ui.Mono(meta, 11, null, true));
            var g = Ui.Cols(new[] { "50", "*" }, Ui.Txt((ev.Weight >= 0 ? "+" : "") + ev.Weight, 13, wc, FontWeights.Bold), sp);
            g.Margin = new Thickness(0, 4, 0, 4); return g;
        }

        static int EntityOrder(Entity e) { switch (e.Kind) { case EntityKind.Task: case EntityKind.Service: case EntityKind.RunKey: case EntityKind.StartupItem: case EntityKind.Wmi: case EntityKind.Driver: case EntityKind.KernelDriver: return 0; case EntityKind.File: return 1; case EntityKind.Process: return 2; default: return 3; } }

        void ShowFinding(Finding f)
        {
            var P = detail; P.Children.Clear(); stepRows.Clear();
            var acc = AccentOf(f.Verdict);
            var top = Ui.H(Ui.Pill(f.ToolClass != null ? L("GAME CHEAT  ·  KEPT", "ЧИТ  ·  ОСТАВЛЕНО") : Loc.Severity(f.Verdict).ToUpperInvariant() + "  ·  " + Loc.Verdict(f.Verdict), acc), new Border { Margin = new Thickness(8, 0, 0, 0), CornerRadius = new CornerRadius(12), Background = Ui.B("Surface2"), Padding = new Thickness(11, 3, 11, 3), Child = Ui.Txt(L("score ", "балл ") + f.Score + " / 100", 11.5, Ui.Muted, FontWeights.SemiBold) });
            P.Children.Add(top);
            P.Children.Add(Ui.Txt(Loc.Title(f.Title), 21, null, FontWeights.Bold, true, new Thickness(0, 10, 0, 0)));
            P.Children.Add(Ui.Txt(f.ToolClass != null ? Loc.Recommendation(f) : Loc.VerdictMeaning(f.Verdict), 13, Ui.Muted, null, true, new Thickness(0, 6, 0, 0)));
            P.Children.Add(ScoreBar(f.Score, acc));

            P.Children.Add(Ui.Head(Loc.T("det.what")));
            foreach (var e in f.Entities.OrderBy(EntityOrder).ThenByDescending(x => x.Score).Take(14))
            {
                var sp = new StackPanel();
                sp.Children.Add(Ui.Txt(e.Title, 13, null, FontWeights.SemiBold));
                string loc = e.Kind == EntityKind.Task ? (e.P("taskPath") ?? e.Location) : e.Location;
                if (!string.IsNullOrEmpty(loc) && loc != e.Title) sp.Children.Add(Ui.Mono(loc, 11.5, null, true));
                var row = Ui.Cols(new[] { "112", "*" }, Ui.Txt(Loc.KindName(e.Kind), 12, Ui.Muted, FontWeights.SemiBold), sp); row.Margin = new Thickness(0, 3, 0, 3);
                P.Children.Add(row);
            }
            if (f.Entities.Count > 14) P.Children.Add(Ui.Txt("… +" + (f.Entities.Count - 14), 12, Ui.Muted));

            P.Children.Add(Ui.Head(Loc.T("det.why")));
            foreach (var ev in f.TopEvidence) P.Children.Add(EvidenceRow(ev));
            P.Children.Add(Ui.Txt(L("Each kind of evidence is capped and repeated signals count less, so a single signal cannot raise a program to High Risk.", "Каждый вид улик ограничен, повторяющиеся сигналы весят меньше, поэтому один признак не поднимает программу до высокого риска."), 11, Ui.Muted, null, true, new Thickness(0, 6, 0, 0)));
            if (!string.IsNullOrEmpty(f.WhyNotHigher)) P.Children.Add(Ui.Txt(Loc.T("det.capped") + ": " + Loc.WhyNotHigher(f.WhyNotHigher), 12, Ui.Warn, null, true, new Thickness(0, 8, 0, 0)));

            P.Children.Add(Ui.Head(Loc.T("det.chain")));
            P.Children.Add(new Border { Background = Ui.Hex("#0E1426"), CornerRadius = new CornerRadius(9), Padding = new Thickness(14, 10, 14, 10), Child = Ui.Mono(string.Join("\n", ThreatGraph.Render(f, true)), 12, Ui.TextB, true) });
            var graphHost = new Border { Visibility = Visibility.Collapsed, Margin = new Thickness(0, 10, 0, 0), Background = Ui.Hex("#0E1426"), CornerRadius = new CornerRadius(9), Height = 330, Child = null };
            var canvas = new Canvas { Width = 900, Height = 400, HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top };
            graphHost.Child = new ScrollViewer { Content = canvas, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
            var graphBtn = Ui.Btn(L("Show the connection diagram", "Показать схему связей"), null, "BtnSmall"); graphBtn.Margin = new Thickness(0, 10, 0, 0);
            graphBtn.Click += (s, e) => { bool on = graphHost.Visibility != Visibility.Visible; graphHost.Visibility = on ? Visibility.Visible : Visibility.Collapsed; graphBtn.Content = on ? L("Hide the diagram", "Скрыть схему") : L("Show the connection diagram", "Показать схему связей"); if (on) GraphView.Render(canvas, f); };
            P.Children.Add(graphBtn); P.Children.Add(graphHost);

            P.Children.Add(Ui.Head(Loc.T("det.action")));
            P.Children.Add(Ui.Txt(Loc.Recommendation(f), 13));
            if (f.Steps.Count > 0)
            {
                P.Children.Add(Ui.Txt(Loc.T("det.steps"), 12, Ui.Muted, null, true, new Thickness(0, 10, 0, 2)));
                foreach (var s in f.Steps)
                {
                    bool enabled = s.Type != ActionType.ReviewOnly;
                    var box = new CheckBox { IsChecked = s.RecommendedByDefault && enabled, IsEnabled = enabled, Margin = new Thickness(0, 4, 0, 4), VerticalAlignment = VerticalAlignment.Top };
                    box.Content = new TextBlock { Text = (s.Type == ActionType.ReviewOnly ? "ℹ  " : "") + Loc.Step(s) + (s.Reversible || s.Type == ActionType.ReviewOnly ? "" : L("  (cannot be undone)", "  (необратимо)")), TextWrapping = TextWrapping.Wrap, Foreground = Ui.TextB, MaxWidth = 640 };
                    stepRows.Add(new StepRow { Step = s, Box = box }); P.Children.Add(box);
                }
            }
            var btns = new WrapPanel { Margin = new Thickness(0, 14, 0, 0) };
            if (stepRows.Any(r => r.Step.Type != ActionType.ReviewOnly)) btns.Children.Add(Ui.Btn(Loc.T("btn.neutralize"), () => NeutralizeSelected(f), "BtnDanger"));
            btns.Children.Add(Ui.Btn(Loc.T("btn.allow"), () => MarkSafe(f.Entities, f), "Btn"));
            AddUtilityButtons(btns, f.Entities);
            P.Children.Add(btns);
            detailScroll.ScrollToTop();
        }

        void ShowNote(Entity n)
        {
            var P = detail; P.Children.Clear(); stepRows.Clear();
            P.Children.Add(Ui.Pill(L("NOTE", "ЗАМЕТКА") + "  ·  " + Loc.KindName(n.Kind), Ui.Muted));
            P.Children.Add(Ui.Txt(n.Title, 21, null, FontWeights.Bold, true, new Thickness(0, 10, 0, 0)));
            string loc = n.Kind == EntityKind.Task ? (n.P("taskPath") ?? n.Location) : n.Location;
            if (!string.IsNullOrEmpty(loc)) P.Children.Add(Ui.Mono(loc, 12));
            P.Children.Add(Ui.Txt(Loc.VerdictMeaning(Verdict.Clean), 13, Ui.Muted, null, true, new Thickness(0, 8, 0, 0)));
            P.Children.Add(ScoreBar(n.Score, Ui.Muted));
            P.Children.Add(Ui.Head(Loc.T("det.why")));
            foreach (var ev in n.Evidence.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight)) P.Children.Add(EvidenceRow(ev));
            var btns = new WrapPanel { Margin = new Thickness(0, 14, 0, 0) };
            btns.Children.Add(Ui.Btn(Loc.T("btn.allow"), () => MarkSafe(new List<Entity> { n }, null), "Btn"));
            AddUtilityButtons(btns, new List<Entity> { n });
            P.Children.Add(btns);
            detailScroll.ScrollToTop();
        }

        void AddUtilityButtons(WrapPanel btns, IEnumerable<Entity> ents)
        {
            var path = ents.Select(e => e.Kind == EntityKind.Task || e.Kind == EntityKind.Registry ? null : (e.P("file") ?? e.Location)).FirstOrDefault(p => !string.IsNullOrEmpty(p) && (File.Exists(p) || Directory.Exists(p)));
            var sha = ents.Select(e => e.Sha256).FirstOrDefault(h => !string.IsNullOrEmpty(h));
            if (path != null && File.Exists(path)) btns.Children.Add(Ui.Btn(L("Analyse this file", "Анализ файла"), () => CheckFileRequested(path), "Btn", L("Opens the file report: signature, structure, why it is flagged", "Откроет отчёт о файле: подпись, структура, почему отмечен")));
            if (path != null) btns.Children.Add(Ui.Btn(L("Show in folder", "Показать в папке"), () => ShowInFolder(path), "BtnGhost"));
            if (sha != null) btns.Children.Add(Ui.Btn(L("Copy SHA-256", "Копировать SHA-256"), () => { try { Clipboard.SetText(sha); } catch { } }, "BtnGhost"));
            if (path != null && File.Exists(path)) btns.Children.Add(Ui.Btn(L("Exclude folder…", "Исключить папку…"), () => ExcludeFolder(path), "BtnGhost"));
        }

        // ============================================================================================ actions
        void ExcludeFolder(string path)
        {
            string dir = Path.GetDirectoryName(path);
            if (!Dlg.Ask(owner(), "MineHunter", L("Stop scanning this folder?\n\n", "Больше не проверять эту папку?\n\n") + dir + L("\n\nMalware hidden in an excluded folder will not be found. Do this only for folders you trust.", "\n\nВредоносное ПО в исключённой папке найдено не будет. Делайте это только для папок, которым доверяете."), L("Exclude", "Исключить"), L("Cancel", "Отмена"), true)) return;
            var s = Settings.Current;
            if (!s.AddExclusion(dir)) { Dlg.Info(owner(), "MineHunter", L("This folder is too broad to be excluded (a whole drive, Windows, Program Files or the user profile).", "Эта папка слишком широкая для исключения (весь диск, Windows, Program Files или профиль пользователя).")); return; }
            s.Save(); Log.Info("Excluded folder: " + dir);
        }

        void MarkSafe(IEnumerable<Entity> ents, Finding f)
        {
            var paths = ents.Where(e => e.Kind == EntityKind.File || e.Kind == EntityKind.StartupItem || e.Kind == EntityKind.Process).Select(e => e.P("file") ?? e.Location).Where(p => !string.IsNullOrEmpty(p) && File.Exists(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (paths.Count == 0) { Dlg.Info(owner(), "MineHunter", L("This item is not a single file, so it cannot be marked as safe.", "Этот объект — не отдельный файл, поэтому пометить его безопасным нельзя.")); return; }
            string msg = L("Mark as safe and stop reporting these files?\n\n", "Пометить безопасным и больше не сообщать об этих файлах?\n\n") + string.Join("\n", paths.Take(6)) + (paths.Count > 6 ? "\n…" : "") + L("\n\nThe mark is tied to the exact content (SHA-256) of each file: if the file is replaced, it is checked again. Only do this if you are sure you know what the program is.", "\n\nПометка привязана к точному содержимому (SHA-256) файла: если файл подменят, он проверится заново. Делайте это, только если точно знаете, что это за программа.");
            if (!Dlg.Ask(owner(), "MineHunter", msg, L("Mark as safe", "Пометить безопасным"), L("Cancel", "Отмена"))) return;
            var al = Allowlist.Load(); var unreadable = new List<string>();
            foreach (var p in paths) if (al.Approve(p) == null) unreadable.Add(p);
            al.Save();
            Log.Info("Marked as safe: " + string.Join("; ", paths.Except(unreadable)));
            if (unreadable.Count > 0) Dlg.Info(owner(), "MineHunter", L("These files could not be read, so they were NOT approved:\n", "Эти файлы не удалось прочитать, поэтому они НЕ помечены безопасными:\n") + string.Join("\n", unreadable));
            if (f != null && res != null) res.Findings.Remove(f); else if (res != null) res.Observations.RemoveAll(o => ents.Contains(o));
            Populate(); ResultChanged();
        }

        void NeutralizeSelected(Finding f)
        {
            var chosen = stepRows.Where(r => r.Box.IsChecked == true && r.Box.IsEnabled).Select(r => r.Step).ToList();
            if (chosen.Count == 0) { Dlg.Info(owner(), "MineHunter", L("No actions are ticked.", "Не отмечено ни одного действия.")); return; }
            NeutralizeRequested(new List<KeyValuePair<Finding, List<RemediationStep>>> { new KeyValuePair<Finding, List<RemediationStep>>(f, chosen) });
        }

        public void ShowCleanup(List<CleanupRow> rows = null)
        {
            if (rows != null) cleanup = rows;
            var P = detail; P.Children.Clear(); list.SelectedIndex = -1;
            if (cleanup == null) return;
            P.Children.Add(Ui.Txt(L("Cleanup result", "Результат обезвреживания"), 21, null, FontWeights.Bold));
            P.Children.Add(Ui.Txt(L("Every item was checked again after the cleanup (a new scan).", "После очистки каждый объект был проверен заново (новая проверка)."), 12.5, Ui.Muted, null, true, new Thickness(0, 4, 0, 0)));
            bool reboot = cleanup.Any(c => c.Outcome.Outcome != null && c.Outcome.Outcome.RebootRequired);
            if (reboot) P.Children.Add(new Border { Margin = new Thickness(0, 12, 0, 0), CornerRadius = new CornerRadius(9), Background = Ui.Soft(Ui.Warn), Padding = new Thickness(14, 10, 14, 10), Child = Ui.Txt(L("RESTART WINDOWS to finish the cleanup: some files were in use and are scheduled for deletion at the next start.", "ПЕРЕЗАГРУЗИТЕ WINDOWS, чтобы завершить очистку: часть файлов была занята и будет удалена при следующем запуске."), 13, Ui.Warn, FontWeights.SemiBold) });
            foreach (var c in cleanup)
            {
                var o = c.Outcome; Brush acc = o.Verdict == "Remediated" ? Ui.Good : o.Verdict == "RebootRequired" ? Ui.Warn : o.Verdict == "Partial" ? Ui.Orange : Ui.Bad;
                string vt = o.Verdict == "Remediated" ? L("REMOVED AND VERIFIED", "УДАЛЕНО И ПРОВЕРЕНО") : o.Verdict == "RebootRequired" ? L("RESTART REQUIRED", "НУЖНА ПЕРЕЗАГРУЗКА") : o.Verdict == "Partial" ? L("PARTIALLY", "ЧАСТИЧНО") : L("NOT DONE", "НЕ ВЫПОЛНЕНО");
                P.Children.Add(Ui.Head(Loc.Title(c.F.Title)));
                P.Children.Add(Ui.Pill(Loc.Severity(c.F.Verdict).ToUpperInvariant() + "  ·  " + vt, acc));
                P.Children.Add(Ui.Txt(Loc.RescanNote(o.RescanNote) ?? "", 12.5, Ui.Muted, null, true, new Thickness(0, 6, 0, 0)));
                foreach (var s in o.StillPresent) P.Children.Add(Ui.Txt("• " + s, 12, Ui.Orange, null, true, new Thickness(0, 2, 0, 0)));
                if (o.Outcome != null)
                    foreach (var r in o.Outcome.Results)
                        P.Children.Add(Ui.Txt((r.Success ? "✓  " : "✗  ") + Loc.Step(r.Step) + (string.IsNullOrEmpty(r.Message) ? "" : "  —  " + Loc.StepMessage(r.Message)), 12, r.Success ? Ui.TextB : Ui.Bad, null, true, new Thickness(0, 3, 0, 0)));
            }
            detailScroll.ScrollToTop();
        }

        static void ShowInFolder(string p) { try { if (File.Exists(p)) Process.Start("explorer.exe", "/select,\"" + p + "\""); else if (Directory.Exists(p)) Process.Start("explorer.exe", "\"" + p + "\""); } catch { } }
    }
}
