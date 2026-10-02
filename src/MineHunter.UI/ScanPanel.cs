using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Threading;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>The whole scanning experience in one control: the choice of what to scan, the live status while it runs (what is being checked, how long, how many objects, what was found),
    /// the verdict ("No threats found" or the findings with their explanations) and neutralizing. The Scan page of the main window and the Quick Scan / Full Scan windows are this control.</summary>
    public sealed class ScanPanel
    {
        readonly AppModel m; readonly Func<Window> owner; readonly bool fixedMode;
        public readonly ContentControl Root = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch, VerticalContentAlignment = VerticalAlignment.Stretch };
        readonly DispatcherTimer timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        ResultsView results; List<CleanupRow> cleanupRows;
        // running view
        ProgressBar bar; TextBlock stageText, itemText, timeText, objText, foundText, percentText, headText;
        Button cancelBtn; bool busyNeutralizing;
        string runTitle;
        public Action<bool> RunningChanged = r => { };
        public Action OpenMainRequested;

        static string L(string en, string ru) { return Loc.L(en, ru); }

        public ScanPanel(AppModel model, Func<Window> ownerFn, bool lockedMode)
        {
            m = model; owner = ownerFn; fixedMode = lockedMode;
            timer.Tick += (s, e) => Tick();
        }

        public bool IsBusy { get { return m.Scanner.Running || busyNeutralizing; } }

        // ============================================================================================ entry points
        public void ShowCurrent()
        {
            if (m.Scanner.Running) ShowRunning();
            else if (m.LastResult != null) ShowDone(m.LastResult, false);
            else ShowIdle();
        }

        public bool Start(ScanMode mode, IEnumerable<string> paths = null, string trigger = "manual")
        {
            string err = m.StartScan(mode, trigger, paths);
            if (err != null) { Dlg.Info(owner(), "MineHunter", err); return false; }
            runTitle = mode == ScanMode.Quick ? L("Quick scan", "Быстрая проверка") : mode == ScanMode.Full ? L("Full scan", "Полная проверка") : L("Custom scan", "Выборочная проверка");
            cleanupRows = null;
            ShowRunning();
            RunningChanged(true);
            return true;
        }

        void OnFinished(ScanRun run)
        {
            timer.Stop(); RunningChanged(false);
            var o = m.Scanner.Error;
            if (run == null || run.Result == null) { ShowError(o ?? L("The scan failed.", "Проверка не удалась.")); return; }
            ShowDone(run.Result, true);
        }

        // ============================================================================================ idle: what to scan
        public void ShowIdle()
        {
            timer.Stop();
            var cards = new List<UIElement>();
            cards.Add(ModeCard("bolt", L("Quick scan", "Быстрая проверка"), L("Autostart, services, tasks, running programs and the places where miners usually settle: Temp, AppData, Downloads. Usually a minute or two.", "Автозапуск, службы, задачи, запущенные программы и места, где обычно селятся майнеры: Temp, AppData, Загрузки. Обычно минута-две."), L("Start quick scan", "Запустить быструю"), "BtnPrimary", () => Start(ScanMode.Quick)));
            cards.Add(ModeCard("scan", L("Full scan", "Полная проверка"), L("Every fixed drive, deeply. It can take a long time; you can stop it at any moment and keep working meanwhile.", "Все постоянные диски, вглубь. Может занять много времени; можно остановить в любой момент и работать, пока она идёт."), L("Start full scan", "Запустить полную"), "Btn", () => Start(ScanMode.Full)));
            cards.Add(ModeCard("folder", L("Custom scan", "Выборочная проверка"), L("One folder or drive that you choose: a flash drive, a downloaded archive's folder, a game folder.", "Одна папка или диск на выбор: флешка, папка со скачанным, папка с игрой."), L("Choose a folder…", "Выбрать папку…"), "Btn", ChooseFolder));
            var grid = new UniformGrid { Columns = 3 };
            foreach (var c in cards) grid.Children.Add(c);
            var sp = new StackPanel();
            sp.Children.Add(Ui.Title(L("Scan", "Проверка")));
            sp.Children.Add(Ui.Txt(L("Nothing is deleted without your confirmation. Everything that is removed goes to the quarantine and can be restored.", "Ничего не удаляется без вашего подтверждения. Всё, что убирается, попадает в карантин и может быть восстановлено."), 13, Ui.Muted, null, true, new Thickness(0, 0, 0, 16)));
            sp.Children.Add(grid);
            if (m.LastResult != null)
            {
                var again = Ui.Btn(L("Show the result of the last scan", "Показать результат последней проверки"), () => ShowDone(m.LastResult, false), "BtnGhost"); again.Margin = new Thickness(0, 14, 0, 0);
                sp.Children.Add(again);
            }
            Root.Content = sp;
        }

        UIElement ModeCard(string icon, string title, string text, string btn, string style, Action click)
        {
            var b = Ui.Btn(btn, click, style); b.Margin = new Thickness(0, 14, 0, 0); b.HorizontalAlignment = HorizontalAlignment.Left;
            var card = Ui.Card(Ui.V(Ui.Badge(icon, Ui.Accent, 44), Ui.Txt(title, 17, null, FontWeights.Bold, true, new Thickness(0, 12, 0, 4)), Ui.Txt(text, 12.5, Ui.Muted), b), 20);
            card.Margin = new Thickness(0, 0, 14, 0); return card;
        }

        void ChooseFolder()
        {
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = L("Choose a folder (or a whole drive) to scan", "Выберите папку (или диск) для проверки"), ShowNewFolderButton = false })
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedPath)) Start(ScanMode.Custom, new[] { dlg.SelectedPath });
        }

        // ============================================================================================ running
        void ShowRunning()
        {
            var mode = m.Scanner.Mode;
            if (runTitle == null) runTitle = mode == ScanMode.Quick ? L("Quick scan", "Быстрая проверка") : mode == ScanMode.Full ? L("Full scan", "Полная проверка") : L("Custom scan", "Выборочная проверка");
            headText = Ui.Txt(runTitle + L(" is running", " идёт"), 22, null, FontWeights.Bold);
            percentText = Ui.Txt("0 %", 22, Ui.Accent, FontWeights.Bold, false);
            bar = new ProgressBar { Minimum = 0, Maximum = 100, Height = 12, Margin = new Thickness(0, 16, 0, 0) };
            stageText = Ui.Txt("", 13, Ui.TextB, FontWeights.SemiBold, false);
            itemText = Ui.Mono("", 11.5, null, false);
            timeText = Ui.Txt("00:00", 22, null, FontWeights.Bold, false); objText = Ui.Txt("0", 22, null, FontWeights.Bold, false); foundText = Ui.Txt("0", 22, Ui.Good, FontWeights.Bold, false);
            cancelBtn = Ui.Btn(L("Stop the scan", "Остановить проверку"), () => { m.Scanner.Cancel(); cancelBtn.IsEnabled = false; stageText.Text = L("Stopping… the work already done is kept.", "Останавливаю… уже сделанное сохранится."); }, "Btn");
            Func<string, TextBlock, UIElement> stat = (label, value) => { var c = Ui.Card(Ui.V(Ui.Txt(label, 11.5, Ui.Muted), value), 14, Ui.B("Surface2")); c.Margin = new Thickness(0, 0, 10, 0); return c; };
            var stats = new UniformGrid { Columns = 3, Margin = new Thickness(0, 18, 0, 0) };
            stats.Children.Add(stat(L("Time", "Прошло времени"), timeText)); stats.Children.Add(stat(L("Objects checked", "Проверено объектов"), objText)); stats.Children.Add(stat(L("Suspicious so far", "Подозрительного пока"), foundText));
            string note = mode == ScanMode.Full
                ? L("A full scan can take a long time. You may minimise this window and keep working: the scan runs at a low priority. Stopping is safe at any moment; what is found so far stays in the report.", "Полная проверка может идти долго. Окно можно свернуть и продолжать работать: проверка идёт с низким приоритетом. Остановить можно в любой момент без последствий; найденное к этому моменту останется в отчёте.")
                : L("Nothing is changed on your computer during a scan. You can stop it at any time.", "Во время проверки на компьютере ничего не меняется. Остановить её можно в любой момент.");
            var left = Ui.V(Ui.H(Ui.Badge("scan", Ui.Accent, 46), new StackPanel { Margin = new Thickness(14, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, Children = { headText, Ui.Txt(note, 12.5, Ui.Muted, null, true, new Thickness(0, 3, 0, 0)) } }));
            var card = Ui.Card(Ui.V(left, bar, Ui.Cols(new[] { "*", "Auto" }, stageText, percentText), Ui.Txt(L("Now looking at:", "Сейчас проверяется:"), 11.5, Ui.Muted, null, true, new Thickness(0, 12, 0, 2)), itemText, stats, cancelBtn), 24);
            ((Button)cancelBtn).Margin = new Thickness(0, 18, 0, 0);
            var wrap = new StackPanel(); wrap.Children.Add(card);
            Root.Content = wrap;
            m.Scanner.Finished -= FinishedHandler; m.Scanner.Finished += FinishedHandler;
            timer.Start(); Tick();
        }

        readonly Action<ScanRun> _fh = null;
        void FinishedHandler(ScanRun run) { m.UiThread.BeginInvoke(new Action(() => OnFinished(run))); }

        void Tick()
        {
            var live = m.Scanner.Live; if (live == null || bar == null) return;
            if (!m.Scanner.Running) return;
            int pct = Math.Max(0, Math.Min(100, live.Percent));
            bar.Value = pct; percentText.Text = pct + " %";
            timeText.Text = Ui.FormatDuration(live.Elapsed);
            objText.Text = Ui.FormatNumber(live.ObjectsChecked);
            int sus = live.Suspects; foundText.Text = sus.ToString(); foundText.Foreground = sus == 0 ? Ui.Good : Ui.Warn;
            stageText.Text = Loc.Progress(live.Status ?? "");
            itemText.Text = live.Item ?? "";
        }

        // ============================================================================================ done
        public void ShowDone(ScanResult r, bool justFinished)
        {
            timer.Stop();
            var res = r;
            int mal = res.Findings.Count(f => f.Verdict == Verdict.Malware), high = res.Findings.Count(f => f.Verdict == Verdict.HighRisk), susp = res.Findings.Count(f => f.Verdict == Verdict.Suspicious), notes = res.Observations.Count;
            Brush col; string icon, title, sub;
            string stats = L("Examined: ", "Проверено: ") + Ui.FormatNumber((long)res.Stats.ProcessesScanned + res.Stats.ModulesChecked + res.Stats.FilesInspected + res.Stats.FilesSkippedByCache + res.Stats.ServicesScanned + res.Stats.TasksScanned + res.Stats.RunEntries + res.Stats.BrowserExtensions) + L(" objects", " объектов") + L("  ·  in ", "  ·  за ") + Ui.FormatDuration(TimeSpan.FromSeconds(res.Stats.Seconds)) + "  ·  " + L("rules ", "правила ") + res.RulesVersion;
            if (res.Aborted) { col = Ui.Muted; icon = "stop"; title = L("Scan stopped", "Проверка остановлена"); sub = L("Partial result: only what was checked before you stopped it.", "Частичный результат: только то, что успели проверить."); }
            else if (mal > 0) { col = Ui.Bad; icon = "cross"; title = L("Dangerous items found", "Найдены опасные объекты"); sub = stats; }
            else if (high > 0) { col = Ui.Orange; icon = "warn"; title = L("Threats found", "Найдены угрозы"); sub = stats; }
            else if (susp > 0) { col = Ui.Warn; icon = "warn"; title = L("Something looks suspicious", "Есть подозрительное"); sub = stats; }
            else { col = Ui.Good; icon = "check"; title = L("No threats found", "Угроз не найдено"); sub = stats; }

            var chips = Ui.Wrap();
            if (mal > 0) chips.Children.Add(Chip(Loc.Severity(Verdict.Malware) + "  " + mal, Ui.Bad));
            if (high > 0) chips.Children.Add(Chip(Loc.Severity(Verdict.HighRisk) + "  " + high, Ui.Orange));
            if (susp > 0) chips.Children.Add(Chip(Loc.Severity(Verdict.Suspicious) + "  " + susp, Ui.Warn));
            if (mal + high + susp == 0 && !res.Aborted) chips.Children.Add(Chip(L("Clean", "Чисто"), Ui.Good));
            if (notes > 0) chips.Children.Add(Chip(notes + "  " + L("minor notes", "мелких заметок"), Ui.Muted));
            var warns = res.Status.PostureWarnings.Select(w => Loc.Posture(w)).Distinct().ToList();

            var hero = new Grid();
            hero.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); hero.ColumnDefinitions.Add(new ColumnDefinition()); hero.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var big = new Border { Width = 72, Height = 72, CornerRadius = new CornerRadius(36), Background = col, Child = Ui.Icon(icon, Brushes.White, 36, 2.6) }; hero.Children.Add(big);
            var mid = new StackPanel { Margin = new Thickness(20, 0, 20, 0), VerticalAlignment = VerticalAlignment.Center };
            mid.Children.Add(Ui.Txt(title, 24, null, FontWeights.Bold)); mid.Children.Add(Ui.Txt(sub, 12.5, Ui.Muted, null, true, new Thickness(0, 4, 0, 0))); mid.Children.Add(chips); chips.Margin = new Thickness(0, 10, 0, 0);
            if (mal + high + susp == 0 && !res.Aborted && res.Mode == "Quick") mid.Children.Add(Ui.Txt(L("The quick scan does not look into every folder. A full scan once in a while goes deeper.", "Быстрая проверка не заглядывает во все папки. Полная проверка время от времени заходит глубже."), 12, Ui.Muted, null, true, new Thickness(0, 8, 0, 0)));
            Grid.SetColumn(mid, 1); hero.Children.Add(mid);
            var acts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            if (Neutralizer.DefaultPlan(res).Count > 0) { var b = Ui.Btn(Loc.T("btn.neutralize_all"), () => Neutralize(Neutralizer.DefaultPlan(res)), "BtnDanger"); b.Padding = new Thickness(18, 11, 18, 11); acts.Children.Add(b); }
            var again = Ui.Btn(L("Scan again", "Проверить заново"), () => { ShowIdle(); RunningChanged(false); }, "Btn"); acts.Children.Add(again);
            if (OpenMainRequested != null) { var open = Ui.Btn(L("Open in MineHunter", "Открыть в MineHunter"), () => OpenMainRequested(), "BtnPrimary"); acts.Children.Insert(0, open); }
            if (!string.IsNullOrEmpty(m.LastReportTxt)) acts.Children.Add(Ui.Btn(L("Open the report", "Открыть отчёт"), () => AppModel.Open(!string.IsNullOrEmpty(m.LastReportHtml) && File.Exists(m.LastReportHtml) ? m.LastReportHtml : m.LastReportTxt), "BtnGhost"));
            Grid.SetColumn(acts, 2); hero.Children.Add(acts);
            var heroCard = Ui.Card(hero, 22);

            var body = new Grid();
            body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            if (warns.Count > 0) body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            body.RowDefinitions.Add(new RowDefinition());
            Grid.SetRow(heroCard, 0); body.Children.Add(heroCard);
            int row = 1;
            if (warns.Count > 0)
            {
                var wp = new StackPanel(); wp.Children.Add(Ui.Txt(L("Windows protection needs a look", "Защита Windows требует внимания"), 12.5, Ui.Warn, FontWeights.Bold));
                foreach (var w in warns.Take(4)) wp.Children.Add(Ui.Txt("•  " + w, 12, Ui.TextB, null, true, new Thickness(0, 2, 0, 0)));
                var wcard = Ui.Card(wp, 14, Ui.Soft(Ui.Warn, 20), Ui.Soft(Ui.Warn, 70)); wcard.Margin = new Thickness(0, 12, 0, 0); Grid.SetRow(wcard, row++); body.Children.Add(wcard);
            }
            Func<bool, UIElement> makeResults = showNotes =>
            {
                results = new ResultsView(owner, fixedMode);
                results.NeutralizeRequested = Neutralize;
                results.CheckFileRequested = p => m.Navigate("files", p);
                results.ResultChanged = () => { ResultSnapshot.Save(res); ShowDone(res, false); };
                if (showNotes) results.ShowNotes(true);
                results.Show(res, cleanupRows);
                results.Root.Margin = new Thickness(0, 14, 0, 0); return results.Root;
            };
            if (res.Findings.Count > 0 || (cleanupRows != null && cleanupRows.Count > 0)) { var rv = makeResults(false); Grid.SetRow(rv, row); body.Children.Add(rv); }
            else if (res.Observations.Count > 0)
            {
                // a clean result stays clean on screen: the minor notes are one click away
                var holder = new ContentControl();
                var more = Ui.Btn(L("Show the " + res.Observations.Count + " minor notes (not threats)", "Показать " + res.Observations.Count + " мелких заметок (не угроз)"), null, "BtnGhost"); more.Margin = new Thickness(0, 14, 0, 0); more.HorizontalAlignment = HorizontalAlignment.Left;
                more.Click += (s, e) => { holder.Content = makeResults(true); };
                holder.Content = more; Grid.SetRow(holder, row); body.Children.Add(holder);
            }
            Root.Content = body;
        }

        static UIElement Chip(string text, Brush color) { var p = Ui.Pill(text, color, 12); p.Margin = new Thickness(0, 0, 8, 0); return p; }

        void ShowError(string text)
        {
            Root.Content = Ui.Card(Ui.V(Ui.H(Ui.Badge("warn", Ui.Bad, 46), Ui.Txt(L("The scan did not finish", "Проверка не завершилась"), 22, null, FontWeights.Bold, true, new Thickness(14, 8, 0, 0))), Ui.Txt(text, 13, Ui.Muted, null, true, new Thickness(0, 12, 0, 12)), Ui.Btn(L("Try again", "Попробовать снова"), () => ShowIdle(), "BtnPrimary")), 24);
        }

        // ============================================================================================ neutralize
        void Neutralize(List<KeyValuePair<Finding, List<RemediationStep>>> plan)
        {
            var res = m.LastResult; if (res == null || plan.Count == 0 || IsBusy) return;
            var sb = new StringBuilder();
            sb.AppendLine(L("The following will be done. Removed files and settings are saved to Quarantine and can be restored; stopped programs are not restarted.", "Будет выполнено следующее. Удаляемые файлы и настройки сохраняются в карантине и могут быть восстановлены; остановленные программы заново не запускаются."));
            sb.AppendLine();
            foreach (var kv in plan.Take(6)) { sb.AppendLine("■ " + Loc.Title(kv.Key.Title)); foreach (var s in kv.Value.Take(6)) sb.AppendLine("     – " + Loc.Step(s)); if (kv.Value.Count > 6) sb.AppendLine("     …"); }
            if (plan.Count > 6) sb.AppendLine("… +" + (plan.Count - 6));
            sb.AppendLine(); sb.AppendLine(L("Continue?", "Продолжить?"));
            if (!Dlg.Ask(owner(), L("Neutralize", "Обезвредить"), sb.ToString(), L("Neutralize", "Обезвредить"), L("Cancel", "Отмена"), true)) return;

            busyNeutralizing = true; RunningChanged(true);
            var status = Ui.Txt("", 13, Ui.Muted, null, false); var bar2 = new ProgressBar { Minimum = 0, Maximum = 100, Margin = new Thickness(0, 14, 0, 0) };
            Root.Content = Ui.Card(Ui.V(Ui.H(Ui.Badge("shield", Ui.Accent, 46), Ui.Txt(L("Neutralizing…", "Обезвреживание…"), 22, null, FontWeights.Bold, true, new Thickness(14, 8, 0, 0))),
                Ui.Txt(L("Stopping programs, removing autostart entries and moving files to the quarantine. Please do not close the window.", "Останавливаю программы, убираю автозапуск и перемещаю файлы в карантин. Пожалуйста, не закрывайте окно."), 12.5, Ui.Muted, null, true, new Thickness(0, 10, 0, 0)), bar2, status), 24);
            var opt = m.LastOptions ?? ScanProfiles.Quick(m.S, m.Cfg);
            var cts = new CancellationTokenSource();
            Ui.Async(m.UiThread, () => Neutralizer.Run(res, opt, plan, m.Cfg, s => m.UiThread.BeginInvoke(new Action(() => status.Text = s)), (s, p) => m.UiThread.BeginInvoke(new Action(() => { bar2.Value = p; status.Text = Loc.Progress(s); })), cts.Token), (nr, ex) =>
            {
                busyNeutralizing = false; RunningChanged(false);
                if (ex != null) { Log.Error(ex.ToString()); ShowError(ex.GetBaseException().Message); return; }
                cleanupRows = nr.Outcomes.Select(o => new CleanupRow { F = res.Findings.First(x => x.Id == o.FindingId), Outcome = o }).ToList();
                foreach (var c in cleanupRows) Log.Info("Cleanup " + ReportWriter.Badge(c.F, c.Outcome) + " " + Loc.Title(c.F.Title) + ": " + c.Outcome.Verdict);
                m.LastResult = nr.Rescan; if (nr.ReportTxt != null) m.LastReportTxt = nr.ReportTxt;
                try { ResultSnapshot.Save(nr.Rescan); } catch { }
                m.Raise();
                ShowDone(nr.Rescan, false);
                if (results != null) results.ShowCleanup(cleanupRows);
                if (nr.AllOk && nr.Rescan.Findings.Count == 0) Dlg.Info(owner(), "MineHunter", nr.RebootRequired ? L("Done. Restart Windows to finish removing locked files.", "Готово. Перезагрузите Windows, чтобы завершить удаление занятых файлов.") : L("Cleaned and verified: a new scan confirms nothing dangerous is left.", "Очищено и проверено: повторная проверка подтверждает, что опасного не осталось."));
            });
        }

        public void Detach() { timer.Stop(); m.Scanner.Finished -= FinishedHandler; }
    }
}
