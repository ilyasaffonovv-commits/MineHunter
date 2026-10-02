using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Guards;
using MineHunter.Report;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>What happened: finished scans with their reports (open or export as JSON, TXT or HTML) and the journal of changes to the system that the guards noticed ("14:32 SomeSetup.exe added the
    /// service XYZ").</summary>
    public sealed class HistoryPage : PageBase
    {
        public override string Key { get { return "history"; } }
        public override string Title { get { return L("History", "История"); } }
        public override string Icon { get { return "clock"; } }
        readonly StackPanel scans = new StackPanel(), journal = new StackPanel(), alerts = new StackPanel();

        public HistoryPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            var tabs = new TabControl();
            tabs.Items.Add(new TabItem { Header = L("Scans and reports", "Проверки и отчёты"), Content = Ui.Scroll(Ui.V(ScanTools(), scans)) });
            tabs.Items.Add(new TabItem { Header = L("Changes to the system", "Изменения в системе"), Content = Ui.Scroll(Ui.V(Ui.Txt(L("What the guards noticed being added, changed or removed: autostart entries, tasks, services, Defender exclusions, hosts, firewall rules. Windows does not say who did it, so a name is shown only when it can be worked out (and then it says “probably”).", "Что защита заметила добавленным, изменённым или удалённым: записи автозапуска, задачи, службы, исключения Defender, hosts, правила брандмауэра. Windows не говорит, кто это сделал, поэтому имя показывается только когда его можно установить (и тогда пишется «вероятно»)."), 12.5, Ui.Muted, null, true, new Thickness(0, 0, 0, 10)), Ui.Btn(L("Clear the journal", "Очистить журнал"), () => { if (Ask(L("Clear the journal?", "Очистить журнал?"))) { new SystemJournal().Clear(); Render(); } }, "BtnGhost"), journal)) });
            tabs.Items.Add(new TabItem { Header = L("Warnings", "Предупреждения"), Content = Ui.Scroll(alerts) });
            View = Frame(Header(L("History", "История"), L("Past scans, reports and what changed on this PC.", "Прошлые проверки, отчёты и что менялось на этом ПК.")), tabs);
        }

        public override void OnShow(object arg) { Render(); }

        UIElement ScanTools()
        {
            return Ui.Wrap(Ui.Btn(L("Open the reports folder", "Открыть папку отчётов"), () => AppModel.Open(ReportWriter.DefaultDir), "Btn"), Ui.Btn(L("Export the history…", "Экспортировать историю…"), Export, "Btn"), Ui.Btn(L("Clear the history", "Очистить историю"), () => { if (Ask(L("Clear the list of scans? The report files stay.", "Очистить список проверок? Файлы отчётов останутся."))) { History.Clear(); Render(); } }, "BtnGhost"));
        }

        void Render()
        {
            scans.Children.Clear();
            var h = History.List();
            if (h.Count == 0) scans.Children.Add(Ui.Txt(L("No scans yet.", "Проверок ещё не было."), 13, Ui.Muted));
            foreach (var e in h.Take(100))
            {
                var en = e; Brush c = e.Aborted ? Ui.Muted : e.Critical + e.High > 0 ? Ui.Bad : e.Medium > 0 ? Ui.Warn : Ui.Good;
                string res = e.Aborted ? L("stopped", "остановлена") : e.Threats == 0 ? L("no threats", "угроз нет") : (e.Critical > 0 ? e.Critical + L(" critical", " крит.") + "  " : "") + (e.High > 0 ? e.High + L(" high", " выс.") + "  " : "") + (e.Medium > 0 ? e.Medium + L(" medium", " ср.") : "");
                var mid = new StackPanel { Margin = new Thickness(12, 0, 12, 0) };
                mid.Children.Add(Ui.H(Ui.Txt(e.StartedTime.ToString("dd.MM.yyyy HH:mm"), 13.5, null, FontWeights.SemiBold, false), Ui.Txt("  ·  " + ScanProfiles2.ModeName(e.Mode) + "  ·  " + TriggerText(e.Trigger), 12.5, Ui.Muted, null, false)));
                mid.Children.Add(Ui.Txt(Ui.FormatDuration(TimeSpan.FromSeconds(e.Seconds)) + "  ·  " + Ui.FormatNumber(e.Objects) + L(" objects", " объектов") + "  ·  " + L("rules ", "правила ") + e.RulesVersion + (e.Notes > 0 ? "  ·  " + e.Notes + L(" notes", " заметок") : ""), 11.5, Ui.Muted, null, false, new Thickness(0, 2, 0, 0)));
                if (e.Titles.Count > 0) mid.Children.Add(Ui.Txt(string.Join("; ", e.Titles.Take(3)), 11.5, Ui.TextB, null, false, new Thickness(0, 3, 0, 0)));
                var btns = Ui.H();
                if (!string.IsNullOrEmpty(e.ReportHtml) && File.Exists(e.ReportHtml)) btns.Children.Add(Ui.Btn("HTML", () => AppModel.Open(en.ReportHtml), "BtnSmall"));
                if (!string.IsNullOrEmpty(e.ReportTxt) && File.Exists(e.ReportTxt)) { var b = Ui.Btn("TXT", () => AppModel.Open(en.ReportTxt), "BtnSmall"); b.Margin = new Thickness(0, 0, 8, 8); btns.Children.Add(b); }
                if (!string.IsNullOrEmpty(e.ReportJson) && File.Exists(e.ReportJson)) btns.Children.Add(Ui.Btn("JSON", () => AppModel.Open(en.ReportJson), "BtnSmall"));
                var card = Ui.Card(Ui.Cols(new[] { "Auto", "*", "Auto", "Auto" }, Ui.Badge(e.Aborted ? "stop" : e.Threats == 0 ? "check" : "warn", c, 38), mid, Ui.Pill(res, c), btns), 14); ((FrameworkElement)((Grid)card.Child).Children[3]).Margin = new Thickness(12, 0, 0, 0); card.Margin = new Thickness(0, 0, 0, 8); scans.Children.Add(card);
            }
            journal.Children.Clear();
            var j = new SystemJournal().List();
            if (j.Count == 0) journal.Children.Add(Ui.Txt(L("Nothing recorded yet. The journal fills while the real-time protection is on.", "Пока ничего не записано. Журнал наполняется, пока включена защита в реальном времени."), 13, Ui.Muted));
            foreach (var x in j.Take(300))
            {
                var row = Ui.Cols(new[] { "120", "120", "*" }, Ui.Txt(x.Time.ToString("dd.MM HH:mm:ss"), 12, Ui.Muted, null, false), Ui.Pill(KindText(x.Kind), Ui.Accent, 10), Ui.Txt(x.Text, 12.5, Ui.TextB));
                row.Margin = new Thickness(0, 4, 0, 4); journal.Children.Add(row);
            }
            alerts.Children.Clear();
            var al = (m.Guards == null ? new List<GuardAlert>() : m.Guards.Recent).ToList(); if (al.Count == 0) al = GuardHost.LoadAlerts();
            if (al.Count == 0) alerts.Children.Add(Ui.Txt(L("No warnings.", "Предупреждений нет."), 13, Ui.Muted));
            foreach (var a in al.Take(100))
            {
                Brush c = a.Level == AlertLevel.Dangerous ? Ui.Bad : a.Level == AlertLevel.Suspicious ? Ui.Warn : Ui.Accent;
                var card = Ui.Card(Ui.V(Ui.H(Ui.Pill(a.LevelText.ToUpperInvariant(), c, 10), Ui.Txt(a.Time.ToString("dd.MM.yyyy HH:mm") + "  ·  " + a.Title, 13, null, FontWeights.SemiBold, false, new Thickness(10, 0, 0, 0))), Ui.Txt(a.Text, 12, Ui.TextB, null, true, new Thickness(0, 4, 0, 0))), 12); card.Margin = new Thickness(0, 0, 0, 8); alerts.Children.Add(card);
            }
        }

        static string TriggerText(string t) { switch (t) { case "scheduled": return Loc.L("scheduled", "по расписанию"); case "quick-exe": case "full-exe": return Loc.L("own window", "отдельное окно"); case "tray": return Loc.L("from the tray", "из трея"); default: return Loc.L("manual", "вручную"); } }
        static string KindText(string k) { switch (k) { case "run": return "Run"; case "startup": return Loc.L("Startup", "Автозагрузка"); case "tasks": return Loc.L("Task", "Задача"); case "services": return Loc.L("Service", "Служба"); case "exclusions": return Loc.L("Exclusion", "Исключение"); case "hosts": return "hosts"; case "firewall": return Loc.L("Firewall", "Брандмауэр"); case "wmi": return "WMI"; case "profile": return Loc.L("Profile", "Профиль"); case "usb": return "USB"; default: return k ?? ""; } }

        void Export()
        {
            using (var dlg = new System.Windows.Forms.SaveFileDialog { Title = L("Export the scan history", "Экспорт истории проверок"), Filter = "JSON (*.json)|*.json|Text (*.txt)|*.txt|HTML (*.html)|*.html", FileName = "minehunter-history-" + DateTime.Now.ToString("yyyyMMdd") })
            {
                if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
                var h = History.List(); string ext = Path.GetExtension(dlg.FileName).ToLowerInvariant();
                try
                {
                    if (ext == ".json") File.WriteAllText(dlg.FileName, Json.Pretty(Json.Serialize(new Dictionary<string, object> { { "app", "MineHunter" }, { "version", Scanning.AppInfo.Version }, { "exported", DateTime.Now.ToString("o") }, { "scans", h.Select(e => (object)new Dictionary<string, object> { { "started", e.Started }, { "mode", e.Mode }, { "trigger", e.Trigger }, { "seconds", e.Seconds }, { "objects", e.Objects }, { "critical", e.Critical }, { "high", e.High }, { "medium", e.Medium }, { "notes", e.Notes }, { "aborted", e.Aborted }, { "rules", e.RulesVersion }, { "titles", e.Titles.ToArray() } }).ToArray() } })), new UTF8Encoding(false));
                    else if (ext == ".html") File.WriteAllText(dlg.FileName, "<!doctype html><meta charset=\"utf-8\"><title>MineHunter history</title><body style=\"font:14px Segoe UI;background:#0e1220;color:#e8ecf7;padding:24px\"><h2>MineHunter " + Scanning.AppInfo.Version + " - " + System.Net.WebUtility.HtmlEncode(L("scan history", "история проверок")) + "</h2><table cellpadding=6>" + string.Join("", h.Select(e => "<tr><td>" + e.StartedTime.ToString("yyyy-MM-dd HH:mm") + "</td><td>" + e.Mode + "</td><td>" + e.Seconds.ToString("0") + " s</td><td>" + e.Critical + "/" + e.High + "/" + e.Medium + "</td><td>" + System.Net.WebUtility.HtmlEncode(string.Join("; ", e.Titles)) + "</td></tr>")) + "</table>", new UTF8Encoding(true));
                    else File.WriteAllText(dlg.FileName, string.Join("\r\n", h.Select(e => e.StartedTime.ToString("yyyy-MM-dd HH:mm") + "  " + e.Mode + "  " + e.Seconds.ToString("0") + " s  critical " + e.Critical + " high " + e.High + " medium " + e.Medium + "  " + string.Join("; ", e.Titles))), new UTF8Encoding(true));
                    AppModel.Open(Path.GetDirectoryName(dlg.FileName));
                }
                catch (Exception ex) { Info(ex.Message); }
            }
        }
    }

    static class ScanProfiles2 { public static string ModeName(string mode) { return Scanning.ScanProfiles.ModeName(mode); } }
}
