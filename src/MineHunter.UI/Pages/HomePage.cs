using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>The first screen: how the computer is doing right now, in facts (no invented score), the big scan buttons, and a card for everything that matters: last scans, threats, quarantine,
    /// versions, updates, the next scheduled scan, real-time protection and the state of Windows' own protection.</summary>
    public sealed class HomePage : PageBase
    {
        public override string Key { get { return "home"; } }
        public override string Title { get { return L("Home", "Главная"); } }
        public override string Icon { get { return "home"; } }
        readonly ContentControl body = new ContentControl();

        public HomePage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            View = new ScrollViewer { Content = body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Padding = new Thickness(0, 0, 8, 0) };
            m.StateChanged += () => { if (View.IsVisible) Build(); };
        }

        public override void OnShow(object arg) { Build(); m.RefreshHealth(false); }

        static UIElement Dot(Brush c) { var d = Ui.Dot(c, 9); d.Margin = new Thickness(0, 0, 8, 0); return d; }

        UIElement Row(string label, string value, Brush color)
        {
            var g = Ui.Cols(new[] { "Auto", "*", "Auto" }, Dot(color), Ui.Txt(label, 12.5, Ui.TextB, null, false), Ui.Txt(value, 12.5, color, FontWeights.SemiBold, false));
            g.Margin = new Thickness(0, 3, 0, 3); return g;
        }

        UIElement Tile(string icon, string title, string value, string sub, Brush accent, Action click = null, UIElement extra = null)
        {
            var sp = new StackPanel();
            sp.Children.Add(Ui.Cols(new[] { "Auto", "*" }, Ui.Icon(icon, accent, 18), Ui.Txt(title, 12, Ui.Muted, FontWeights.SemiBold, false, new Thickness(8, 0, 0, 0))));
            sp.Children.Add(Ui.Txt(value, 19, null, FontWeights.Bold, false, new Thickness(0, 8, 0, 0)));
            if (!string.IsNullOrEmpty(sub)) sp.Children.Add(Ui.Txt(sub, 11.5, Ui.Muted, null, true, new Thickness(0, 3, 0, 0)));
            if (extra != null) sp.Children.Add(extra);
            var c = Ui.Card(sp, 16); c.Margin = new Thickness(0, 0, 12, 12);
            if (click != null) { c.Cursor = System.Windows.Input.Cursors.Hand; c.MouseLeftButtonUp += (s, e) => click(); }
            return c;
        }

        void Build()
        {
            var S = m.S; var res = m.LastResult;
            int mal = res == null ? 0 : res.Findings.Count(f => f.Verdict == Verdict.Malware), high = res == null ? 0 : res.Findings.Count(f => f.Verdict == Verdict.HighRisk), susp = res == null ? 0 : res.Findings.Count(f => f.Verdict == Verdict.Suspicious);
            var health = m.HealthCache ?? new List<HealthItem>();
            var bad = health.Where(h => h.State == HealthState.Bad).ToList(); var warn = health.Where(h => h.State == HealthState.Warn).ToList();
            var lastAny = History.List().FirstOrDefault(h => !h.Aborted);

            // ---- the verdict of the day
            Brush col; string icon, title, sub;
            if (m.Scanner.Running) { col = Ui.Accent; icon = "scan"; title = L("A scan is running", "Идёт проверка"); sub = L("Open the Scan page to follow it.", "Откройте страницу «Проверка», чтобы следить за ней."); }
            else if (mal + high > 0) { col = Ui.Bad; icon = "cross"; title = L("Dangerous items were found", "Найдены опасные объекты"); sub = L("In the last scan: ", "В последней проверке: ") + (mal > 0 ? mal + L(" critical", " критических") : "") + (mal > 0 && high > 0 ? ", " : "") + (high > 0 ? high + L(" high risk", " высокого риска") : "") + L(". Open the Scan page.", ". Откройте страницу «Проверка»."); }
            else if (susp > 0) { col = Ui.Warn; icon = "warn"; title = L("Something looks suspicious", "Есть подозрительное"); sub = susp + L(" item(s) in the last scan need a look.", " объект(ов) в последней проверке стоит посмотреть."); }
            else if (bad.Count > 0) { col = Ui.Orange; icon = "warn"; title = L("Windows protection needs attention", "Защита Windows требует внимания"); sub = string.Join("; ", bad.Take(2).Select(b => b.Title)) + L(". See Windows health.", ". Смотрите «Здоровье Windows»."); }
            else if (lastAny == null) { col = Ui.Accent; icon = "shield"; title = L("No scan yet", "Проверки ещё не было"); sub = L("Run a quick scan: it takes a minute or two.", "Запустите быструю проверку: это минута-две."); }
            else { col = Ui.Good; icon = "shieldcheck"; title = L("No threats found", "Угроз не найдено"); sub = L("Last scan: ", "Последняя проверка: ") + m.LastScanText(lastAny.Mode) + L(". This is a fact about the last scan, not a guarantee for the future.", ". Это факт о последней проверке, а не гарантия на будущее."); }

            var hero = new Grid();
            hero.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); hero.ColumnDefinitions.Add(new ColumnDefinition());
            hero.Children.Add(new Border { Width = 76, Height = 76, CornerRadius = new CornerRadius(38), Background = col, Child = Ui.Icon(icon, Brushes.White, 38, 2.6) });
            var mid = new StackPanel { Margin = new Thickness(22, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            mid.Children.Add(Ui.Txt(title, 25, null, FontWeights.Bold)); mid.Children.Add(Ui.Txt(sub, 13, Ui.Muted, null, true, new Thickness(0, 4, 0, 0)));
            var actions = Ui.Wrap(); actions.Margin = new Thickness(0, 16, 0, 0);
            var q = Ui.Btn(L("Quick scan", "Быстрая проверка"), () => StartAndShow(ScanMode.Quick), "BtnPrimary"); q.Padding = new Thickness(22, 12, 22, 12);
            var f = Ui.Btn(L("Full scan", "Полная проверка"), () => StartAndShow(ScanMode.Full), "Btn"); f.Padding = new Thickness(22, 12, 22, 12);
            var c = Ui.Btn(L("Custom scan…", "Выборочная…"), () => m.Navigate("scan", "choose"), "Btn"); c.Padding = new Thickness(22, 12, 22, 12);
            var fc = Ui.Btn(L("Check a file…", "Проверить файл…"), () => m.Navigate("files", null), "BtnGhost"); fc.Padding = new Thickness(22, 12, 22, 12);
            actions.Children.Add(q); actions.Children.Add(f); actions.Children.Add(c); actions.Children.Add(fc);
            mid.Children.Add(actions);
            Grid.SetColumn(mid, 1); hero.Children.Add(mid);
            var heroCard = Ui.Card(hero, 26); heroCard.Margin = new Thickness(0, 0, 0, 14);

            var root = new StackPanel();
            root.Children.Add(heroCard);

            // ---- update banner
            var up = m.AppUpdate;
            if (up != null && (up.State == AppUpdateState.Ready || up.State == AppUpdateState.Available || up.State == AppUpdateState.NeedsManualInstall))
            {
                string text = up.State == AppUpdateState.Ready ? L("MineHunter " + up.StagedVersion + " is downloaded and verified (signature, SHA-256). Install it now: the program restarts by itself, and if anything goes wrong the current version keeps working.", "MineHunter " + up.StagedVersion + " скачан и проверен (подпись, SHA-256). Установите сейчас: программа перезапустится сама, а если что-то пойдёт не так, текущая версия продолжит работать.")
                            : up.State == AppUpdateState.NeedsManualInstall ? up.Message : L("MineHunter " + (up.Release == null ? "" : up.Release.Version) + " is available.", "Доступна версия MineHunter " + (up.Release == null ? "" : up.Release.Version) + ".");
                var line = Ui.Cols(new[] { "Auto", "*", "Auto" }, Ui.Badge("download", Ui.Accent, 36), Ui.Txt(text, 13, null, null, true, new Thickness(12, 0, 12, 0)), up.State == AppUpdateState.Ready ? Ui.Btn(L("Update now", "Обновить сейчас"), InstallNow, "BtnPrimary") : up.State == AppUpdateState.Available ? Ui.Btn(L("Download", "Скачать"), () => { m.S.AutoUpdateApp = true; m.CheckUpdates(true); }, "Btn") : null);
                var banner = Ui.Card(line, 14, Ui.Soft(Ui.Accent, 24), Ui.Soft(Ui.Accent, 90)); banner.Margin = new Thickness(0, 0, 0, 14); root.Children.Add(banner);
            }
            if (m.LastUpdateResult != null)
            {
                var r = m.LastUpdateResult; bool ok = r.Ok;
                var line = Ui.Cols(new[] { "Auto", "*" }, Ui.Badge(ok ? "check" : "warn", ok ? Ui.Good : Ui.Orange, 36), Ui.Txt(ok ? L("MineHunter was updated to " + r.To + ".", "MineHunter обновлён до версии " + r.To + ".") : L("The update to " + r.To + " did not work" + (r.RolledBack ? " and the previous version was put back; it keeps working. " : ". ") + r.Error, "Обновление до " + r.To + " не удалось" + (r.RolledBack ? ", предыдущая версия возвращена и работает. " : ". ") + r.Error), 13, null, null, true, new Thickness(12, 0, 0, 0)));
                var banner = Ui.Card(line, 14, Ui.Soft(ok ? Ui.Good : Ui.Orange, 24), Ui.Soft(ok ? Ui.Good : Ui.Orange, 90)); banner.Margin = new Thickness(0, 0, 0, 14); root.Children.Add(banner);
            }

            // ---- cards
            var grid = new UniformGrid { Columns = 3 };
            var qh = History.Last("Quick"); var fh = History.Last("Full");
            grid.Children.Add(Tile("bolt", L("Last quick scan", "Последняя быстрая"), m.LastScanText("Quick"), qh == null ? L("Press “Quick scan”", "Нажмите «Быстрая проверка»") : (qh.Threats == 0 ? L("no threats", "угроз нет") : qh.Threats + L(" threat(s)", " угроз(ы)")) + "  ·  " + Ui.FormatDuration(TimeSpan.FromSeconds(qh.Seconds)), qh != null && qh.Threats > 0 ? Ui.Warn : Ui.Accent, () => m.Navigate("scan", null)));
            grid.Children.Add(Tile("scan", L("Last full scan", "Последняя полная"), m.LastScanText("Full"), fh == null ? L("Never run: worth doing once", "Ещё не запускалась: стоит сделать хотя бы раз") : (fh.Threats == 0 ? L("no threats", "угроз нет") : fh.Threats + L(" threat(s)", " угроз(ы)")) + "  ·  " + Ui.FormatDuration(TimeSpan.FromSeconds(fh.Seconds)), fh != null && fh.Threats > 0 ? Ui.Warn : Ui.Accent, () => m.Navigate("scan", null)));
            Brush tc = mal + high > 0 ? Ui.Bad : susp > 0 ? Ui.Warn : Ui.Good;
            grid.Children.Add(Tile("shield", L("Threats in the last scan", "Угрозы в последней проверке"), res == null ? "—" : (mal + high + susp).ToString(), res == null ? L("no data yet", "данных пока нет") : L("critical ", "критических ") + mal + L(" · high ", " · высоких ") + high + L(" · medium ", " · средних ") + susp, res == null ? Ui.Muted : tc, () => m.Navigate("scan", null)));
            int qc = 0; try { qc = Quarantine.List().Count; } catch { }
            grid.Children.Add(Tile("box", L("Quarantine", "Карантин"), qc.ToString(), qc == 0 ? L("empty", "пусто") : L("items can be restored", "объектов, их можно вернуть"), Ui.Accent, () => m.Navigate("quarantine", null)));
            string updState = m.CheckingUpdates ? L("checking…", "проверяю…") : up == null ? L("not checked yet", "ещё не проверялось") : up.State == AppUpdateState.UpToDate ? L("latest version", "последняя версия") : up.State == AppUpdateState.Ready ? L("update ready", "обновление готово") : up.State == AppUpdateState.Available ? L("update available", "доступно обновление") : up.State == AppUpdateState.Offline ? L("offline", "нет сети") : up.State == AppUpdateState.Disabled ? L("update check is off", "проверка выключена") : (up.Message ?? "");
            var checkBtn = Ui.Btn(L("Check now", "Проверить сейчас"), () => m.CheckUpdates(true), "BtnSmall"); checkBtn.Margin = new Thickness(0, 8, 0, 0); checkBtn.HorizontalAlignment = HorizontalAlignment.Left; checkBtn.IsEnabled = !m.CheckingUpdates;
            grid.Children.Add(Tile("download", L("MineHunter version", "Версия MineHunter"), AppInfo.Version, updState, up != null && (up.State == AppUpdateState.Ready || up.State == AppUpdateState.Available) ? Ui.Warn : Ui.Accent, null, checkBtn));
            string ru = m.RulesVersion; string rState = m.RulesInfo == null ? "" : m.RulesInfo.State == UpdateState.Offline ? L("offline: using the rules on this PC", "нет сети: используются правила на этом ПК") : m.RulesInfo.RulesNewer ? L("a newer pack is available", "есть новый набор правил") : L("up to date", "актуальны");
            grid.Children.Add(Tile("file", L("Detection rules", "Правила обнаружения"), ru, rState, Ui.Accent, () => m.Navigate("settings", "updates")));
            string next = S.ScheduleEnabled ? ScheduleManager.NextDue(S, DateTime.Now).ToString("dd.MM HH:mm") : L("off", "выключено");
            grid.Children.Add(Tile("clock", L("Next scheduled scan", "Следующая плановая проверка"), next, S.ScheduleEnabled ? ScheduleModeText(S.ScheduleMode) + L(", notify only if found: ", ", уведомлять только если найдено: ") + (S.ScheduleNotifyOnlyIfFound ? L("yes", "да") : L("no", "нет")) : L("Set a schedule so scans run by themselves", "Настройте расписание, чтобы проверки шли сами"), Ui.Accent, () => m.Navigate("schedule", null)));
            int on = m.GuardsOn; int total = 8;
            grid.Children.Add(Tile("pulse", L("Real-time protection", "Защита в реальном времени"), on == 0 ? L("off", "выключена") : on + " / " + total, on == 0 ? L("Turn components on in Protection", "Включите компоненты на странице «Защита»") : L("components are watching while MineHunter runs", "компонентов следят, пока MineHunter запущен"), on == 0 ? Ui.Muted : Ui.Good, () => m.Navigate("protection", null)));

            // Windows health card with the key facts
            var hs = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
            if (m.HealthLoading && health.Count == 0) hs.Children.Add(Ui.Txt(L("Reading…", "Читаю…"), 12, Ui.Muted));
            foreach (var id in new[] { "defender", "firewall", "smartscreen", "uac" })
            {
                var h = health.FirstOrDefault(x => x.Id == id); if (h == null) continue;
                Brush hc = h.State == HealthState.Good ? Ui.Good : h.State == HealthState.Bad ? Ui.Bad : h.State == HealthState.Warn ? Ui.Orange : Ui.Muted;
                hs.Children.Add(Row(h.Title.Replace("Microsoft Defender", "Defender").Replace("Защитник Windows (Microsoft Defender)", "Защитник"), h.State == HealthState.Good ? L("on", "норма") : h.State == HealthState.Bad ? L("problem", "проблема") : h.State == HealthState.Warn ? L("check", "проверить") : "?", hc));
            }
            grid.Children.Add(Tile("pulse", L("Windows health", "Здоровье Windows"), bad.Count + warn.Count == 0 ? (health.Count == 0 ? "…" : L("all right", "в порядке")) : (bad.Count + warn.Count) + L(" to check", " на проверку"), null, bad.Count > 0 ? Ui.Bad : warn.Count > 0 ? Ui.Orange : Ui.Good, () => m.Navigate("health", null), hs));
            root.Children.Add(grid);

            if (bad.Count > 0)
            {
                var wp = new StackPanel(); wp.Children.Add(Ui.Txt(L("Critical warnings", "Критические предупреждения"), 13, Ui.Bad, FontWeights.Bold));
                foreach (var b in bad.Take(5)) wp.Children.Add(Ui.Txt("•  " + b.Text, 12.5, Ui.TextB, null, true, new Thickness(0, 4, 0, 0)));
                var more = Ui.Btn(L("Open Windows health", "Открыть «Здоровье Windows»"), () => m.Navigate("health", null), "BtnSmall"); more.Margin = new Thickness(0, 10, 0, 0); wp.Children.Add(more);
                var card = Ui.Card(wp, 16, Ui.Soft(Ui.Bad, 20), Ui.Soft(Ui.Bad, 70)); card.Margin = new Thickness(0, 0, 0, 12); root.Children.Add(card);
            }
            body.Content = root;
        }

        static string ScheduleModeText(string mode) { return mode == "Full" ? Loc.L("full scan", "полная") : mode == "Custom" ? Loc.L("custom scan", "выборочная") : Loc.L("quick scan", "быстрая"); }

        void StartAndShow(ScanMode mode)
        {
            string err = m.StartScan(mode, "manual");
            if (err != null) { Info(err); return; }
            m.Navigate("scan", "running");
        }

        void InstallNow()
        {
            if (!Ask(L("Install the update now? MineHunter will close, install the new version and start again by itself.", "Установить обновление сейчас? MineHunter закроется, установит новую версию и сам запустится снова."), L("Install", "Установить"))) return;
            string err = m.InstallUpdate();
            if (err != null) Info(L("The update could not be started: ", "Обновление не удалось запустить: ") + err);
        }
    }
}
