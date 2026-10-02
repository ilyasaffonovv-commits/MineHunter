using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>Scheduled scans through the Windows Task Scheduler: every day, every 3 days, weekly, monthly or every N days; quick, full or of chosen folders; run a missed scan at the next
    /// start; only when the PC is idle; not on battery; tell only if something is found. The task appears in taskschd.msc under "MineHunter" and can be removed here.</summary>
    public sealed class SchedulePage : PageBase
    {
        public override string Key { get { return "schedule"; } }
        public override string Title { get { return L("Schedule", "Расписание"); } }
        public override string Icon { get { return "clock"; } }
        readonly StackPanel body = new StackPanel(); readonly TextBlock status = Ui.Txt("", 12.5, Ui.Muted, null, true, new Thickness(0, 10, 0, 0));
        readonly StackPanel stateBox = new StackPanel();

        public SchedulePage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            View = Frame(Header(L("Schedule", "Расписание"), L("Let scans run by themselves. Windows' own Task Scheduler starts them: nothing runs in the background between scans.", "Пусть проверки идут сами. Их запускает планировщик задач Windows: между проверками в фоне ничего не работает.")), Ui.Scroll(body));
        }

        public override void OnShow(object arg) { Build(); }

        void Build()
        {
            var s = m.S; body.Children.Clear();
            var on = Ui.Sw(L("Run scans on a schedule", "Запускать проверки по расписанию"), s.ScheduleEnabled, v => { s.ScheduleEnabled = v; });
            var card = new StackPanel();
            card.Children.Add(on);
            card.Children.Add(Ui.Head(L("What to scan", "Что проверять"), new Thickness(0, 14, 0, 6)));
            card.Children.Add(Ui.Combo(new[] { Ui.Kv("Quick", L("Quick scan (recommended)", "Быстрая проверка (рекомендуется)")), Ui.Kv("Full", L("Full scan of all drives", "Полная проверка всех дисков")), Ui.Kv("Custom", L("Chosen folders and drives", "Выбранные папки и диски")) }, s.ScheduleMode, v => { s.ScheduleMode = v; Build(); }, 320));
            if (s.ScheduleMode == "Custom")
            {
                var paths = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
                foreach (var p in s.ScheduleCustomPaths.ToList()) { var path = p; var row = Ui.Cols(new[] { "*", "Auto" }, Ui.Mono(path, 12, Ui.TextB, false), Ui.Btn(L("Remove", "Убрать"), () => { s.ScheduleCustomPaths.Remove(path); Build(); }, "BtnGhost")); row.Margin = new Thickness(0, 2, 0, 2); paths.Children.Add(row); }
                paths.Children.Add(Ui.Btn(L("Add a folder or drive…", "Добавить папку или диск…"), () => { using (var dlg = new System.Windows.Forms.FolderBrowserDialog { ShowNewFolderButton = false }) if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK && !s.ScheduleCustomPaths.Contains(dlg.SelectedPath, StringComparer.OrdinalIgnoreCase)) { s.ScheduleCustomPaths.Add(dlg.SelectedPath); Build(); } }, "BtnSmall"));
                card.Children.Add(paths);
            }
            card.Children.Add(Ui.Head(L("How often", "Как часто"), new Thickness(0, 14, 0, 6)));
            var every = Ui.Combo(new[] { Ui.Kv("Daily", L("Every day", "Каждый день")), Ui.Kv("Every3Days", L("Every 3 days", "Раз в 3 дня")), Ui.Kv("Weekly", L("Every week", "Раз в неделю")), Ui.Kv("Monthly", L("Every month", "Раз в месяц")), Ui.Kv("CustomDays", L("Every N days…", "Каждые N дней…")) }, s.ScheduleEvery, v => { s.ScheduleEvery = v; Build(); }, 260);
            var line = Ui.H(every);
            if (s.ScheduleEvery == "CustomDays") { var n = Ui.Input(s.ScheduleCustomDays.ToString(), 60, v => { int x; if (int.TryParse(v, out x)) s.ScheduleCustomDays = Math.Max(1, Math.Min(365, x)); }); n.Margin = new Thickness(10, 0, 6, 0); line.Children.Add(n); line.Children.Add(Ui.Txt(L("days", "дн."), 13, Ui.Muted, null, false, new Thickness(0, 7, 0, 0))); }
            card.Children.Add(line);
            if (s.ScheduleEvery == "Weekly") { var d = Ui.Combo(new[] { Ui.Kv("Monday", L("Monday", "Понедельник")), Ui.Kv("Tuesday", L("Tuesday", "Вторник")), Ui.Kv("Wednesday", L("Wednesday", "Среда")), Ui.Kv("Thursday", L("Thursday", "Четверг")), Ui.Kv("Friday", L("Friday", "Пятница")), Ui.Kv("Saturday", L("Saturday", "Суббота")), Ui.Kv("Sunday", L("Sunday", "Воскресенье")) }, s.ScheduleDayOfWeek, v => s.ScheduleDayOfWeek = v, 220); d.Margin = new Thickness(0, 8, 0, 0); card.Children.Add(d); }
            if (s.ScheduleEvery == "Monthly") { var d = Ui.Combo(Enumerable.Range(1, 28).Select(i => Ui.Kv(i.ToString(), L("day ", "число ") + i)).ToList(), s.ScheduleDayOfMonth.ToString(), v => s.ScheduleDayOfMonth = int.Parse(v), 160); d.Margin = new Thickness(0, 8, 0, 0); card.Children.Add(d); }
            var time = Ui.Input(s.ScheduleTime, 80, v => { TimeSpan t; if (TimeSpan.TryParseExact(v.Trim(), @"hh\:mm", null, out t)) s.ScheduleTime = v.Trim(); else Info(L("Time must look like 13:00", "Время должно выглядеть так: 13:00")); }); time.Margin = new Thickness(0, 8, 0, 0);
            card.Children.Add(Ui.H(Ui.Txt(L("At", "В"), 13, Ui.Muted, null, false, new Thickness(0, 14, 10, 0)), time));

            card.Children.Add(Ui.Head(L("Conditions", "Условия"), new Thickness(0, 14, 0, 4)));
            card.Children.Add(Ui.Sw(L("If the PC was off at that time, run the scan at the next start", "Если ПК был выключен в это время, проверить при следующем включении"), s.ScheduleRunMissed, v => s.ScheduleRunMissed = v));
            card.Children.Add(Ui.Sw(L("Only when the PC is idle", "Только когда ПК простаивает"), s.ScheduleOnlyIdle, v => s.ScheduleOnlyIdle = v));
            card.Children.Add(Ui.Sw(L("Do not start on battery", "Не запускать при работе от батареи"), s.ScheduleNotOnBattery, v => s.ScheduleNotOnBattery = v));
            card.Children.Add(Ui.Sw(L("Stop if the PC switches to battery", "Остановить, если ПК перешёл на батарею"), s.ScheduleStopOnBattery, v => s.ScheduleStopOnBattery = v));
            card.Children.Add(Ui.Sw(L("Notify only if something is found", "Уведомлять только если что-то найдено"), s.ScheduleNotifyOnlyIfFound, v => s.ScheduleNotifyOnlyIfFound = v));
            var apply = Ui.Btn(L("Save and apply", "Сохранить и применить"), Apply, "BtnPrimary"); apply.Margin = new Thickness(0, 18, 8, 0);
            var h = Ui.H(apply); if (s.ScheduleEnabled) h.Children.Add(Ui.Btn(L("Run it now", "Запустить сейчас"), () => { var err = m.StartScan(s.ScheduleMode == "Full" ? Scanning.ScanMode.Full : s.ScheduleMode == "Custom" ? Scanning.ScanMode.Custom : Scanning.ScanMode.Quick, "schedule-now", s.ScheduleMode == "Custom" ? s.ScheduleCustomPaths : null); if (err != null) Info(err); else m.Navigate("scan", "running"); }, "Btn"));
            card.Children.Add(h);
            body.Children.Add(Ui.Card(card, 22)); body.Children.Add(status);
            body.Children.Add(Ui.Head(L("In the Windows Task Scheduler", "В планировщике задач Windows"))); body.Children.Add(Ui.Card(stateBox, 16)); RenderState();
        }

        void RenderState()
        {
            stateBox.Children.Clear();
            Ui.Async(m.UiThread, () => new[] { ScheduleManager.Query(ScheduleManager.ScanTaskName), ScheduleManager.Query(ScheduleManager.TrayTaskName) }, (r, ex) =>
            {
                if (ex != null || r == null) return;
                Action<string, TaskStatus> line = (name, t) => stateBox.Children.Add(Ui.Txt(name + ":  " + (t.Exists ? L("created", "создана") + (t.NextRun.HasValue ? L("; next run ", "; следующий запуск ") + t.NextRun.Value.ToString("dd.MM.yyyy HH:mm") : "") + (t.LastRun.HasValue ? L("; last run ", "; последний запуск ") + t.LastRun.Value.ToString("dd.MM.yyyy HH:mm") + (t.LastResult == 0 ? "" : L(" (code ", " (код ") + t.LastResult + ")") : "") : L("not created", "не создана")), 12.5, t.Exists ? Ui.TextB : Ui.Muted, null, true, new Thickness(0, 2, 0, 2)));
                line(L("Scheduled scan", "Плановая проверка"), r[0]); line(L("Tray at sign-in", "Значок в трее при входе"), r[1]);
            });
        }

        void Apply()
        {
            var s = m.S; s.Save();
            string err = ScheduleManager.Apply(s);
            status.Foreground = err == null ? Ui.Good : Ui.Bad;
            status.Text = err == null ? (s.ScheduleEnabled ? L("Saved. Next scan: ", "Сохранено. Следующая проверка: ") + ScheduleManager.NextDue(s, DateTime.Now).ToString("dd.MM.yyyy HH:mm") : L("Saved. The scheduled task was removed.", "Сохранено. Задача в планировщике удалена.")) : L("Windows did not accept the task: ", "Windows не принял задачу: ") + err;
            m.Raise(); RenderState();
        }
    }
}
