using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>Concrete statements about Windows' own protection, each with what was read. No made-up score: an item is fine, needs a look, or is a problem. A fix button appears only where a
    /// safe real fix exists, and it shows exactly what it will do before it does it.</summary>
    public sealed class HealthPage : PageBase
    {
        public override string Key { get { return "health"; } }
        public override string Title { get { return L("Windows health", "Здоровье Windows"); } }
        public override string Icon { get { return "pulse"; } }
        readonly StackPanel list = new StackPanel(); readonly TextBlock status = Ui.Txt("", 12.5, Ui.Muted, null, true, new Thickness(0, 6, 0, 0));

        public HealthPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            var refresh = Ui.Btn(L("Check again", "Проверить заново"), () => m.RefreshHealth(true), "Btn");
            var top = new StackPanel(); top.Children.Add(Header(L("Windows health", "Здоровье Windows"), L("The state of Defender, firewall, SmartScreen, UAC, updates, boot protection and network settings, as read from this PC.", "Состояние Защитника, брандмауэра, SmartScreen, UAC, обновлений, защиты загрузки и сетевых настроек — как это читается на этом ПК."))); top.Children.Add(Ui.Wrap(refresh)); top.Children.Add(status);
            View = Frame(top, Ui.Scroll(list));
            m.StateChanged += () => { if (View.IsVisible) Render(); };
        }

        public override void OnShow(object arg) { m.RefreshHealth(false); Render(); }

        static Brush Col(HealthState s) { return s == HealthState.Good ? Ui.Good : s == HealthState.Bad ? Ui.Bad : s == HealthState.Warn ? Ui.Orange : s == HealthState.Info ? Ui.Accent : Ui.Muted; }
        static string Ico(HealthState s) { return s == HealthState.Good ? "check" : s == HealthState.Bad ? "cross" : s == HealthState.Warn ? "warn" : s == HealthState.Info ? "info" : "info"; }

        void Render()
        {
            list.Children.Clear();
            var items = m.HealthCache;
            if (items == null) { status.Text = L("Reading the state of Windows…", "Читаю состояние Windows…"); return; }
            int bad = items.Count(i => i.State == HealthState.Bad), warn = items.Count(i => i.State == HealthState.Warn);
            status.Text = (m.HealthLoading ? L("Updating… ", "Обновляю… ") : "") + (bad + warn == 0 ? L("Everything that can be read looks fine.", "Всё, что удалось прочитать, выглядит нормально.") : L("Problems: ", "Проблем: ") + bad + L(", to check: ", ", на проверку: ") + warn) + L("  ·  read ", "  ·  прочитано ") + m.HealthStamp.ToString("HH:mm:ss");
            string group = null;
            foreach (var h in items)
            {
                if (h.Group != group) { group = h.Group; list.Children.Add(Ui.Head(group ?? "")); }
                list.Children.Add(Card(h));
            }
        }

        UIElement Card(HealthItem h)
        {
            var c = Col(h.State);
            var text = new StackPanel { Margin = new Thickness(14, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
            text.Children.Add(Ui.Txt(h.Title, 14, null, FontWeights.Bold)); text.Children.Add(Ui.Txt(h.Text, 12.5, Ui.TextB, null, true, new Thickness(0, 2, 0, 0)));
            var details = new TextBlock { Text = h.Details ?? "", Visibility = Visibility.Collapsed, FontFamily = new FontFamily("Consolas"), FontSize = 11.5, Foreground = Ui.Muted, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) };
            text.Children.Add(details);
            var btns = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            if (!string.IsNullOrEmpty(h.Details)) { var more = Ui.Btn(L("Details", "Подробнее"), null, "BtnSmall"); more.Click += (s, e) => { bool on = details.Visibility != Visibility.Visible; details.Visibility = on ? Visibility.Visible : Visibility.Collapsed; more.Content = on ? L("Hide", "Скрыть") : L("Details", "Подробнее"); }; more.Margin = new Thickness(0, 0, 0, 6); btns.Children.Add(more); }
            if (h.CanFix) { var fix = Ui.Btn(L("Fix…", "Исправить…"), () => Fix(h), "BtnPrimary"); fix.Padding = new Thickness(14, 6, 14, 6); fix.Margin = new Thickness(0, 0, 0, 6); btns.Children.Add(fix); }
            if (!string.IsNullOrEmpty(h.OpenSettings)) { var op = Ui.Btn(L("Open Windows settings", "Открыть настройки Windows"), () => AppModel.Open(h.OpenSettings.Contains(":") ? h.OpenSettings : "ms-settings:" + h.OpenSettings), "BtnGhost"); op.Padding = new Thickness(10, 5, 10, 5); op.FontSize = 11.5; op.Margin = new Thickness(0); btns.Children.Add(op); }
            var card = Ui.Card(Ui.Cols(new[] { "Auto", "*", "Auto" }, Ui.Badge(Ico(h.State), c, 40), text, btns), 14); card.Margin = new Thickness(0, 0, 0, 8);
            if (h.State == HealthState.Bad) card.BorderBrush = Ui.Soft(Ui.Bad, 120);
            return card;
        }

        void Fix(HealthItem h)
        {
            if (!Ask(L("MineHunter will change a Windows setting:\n\n", "MineHunter изменит настройку Windows:\n\n") + h.FixText + L("\n\nThis is the only thing it does. Continue?", "\n\nЭто единственное, что будет сделано. Продолжить?"), L("Fix it", "Исправить"))) return;
            string err = WindowsHealth.ApplyFix(h.FixId);
            Log.Info("Health fix " + h.FixId + ": " + (err ?? "ok"));
            Info(err == null ? L("Done. Checking again…", "Готово. Проверяю заново…") : L("It did not work: ", "Не получилось: ") + err);
            m.RefreshHealth(true);
        }
    }
}
