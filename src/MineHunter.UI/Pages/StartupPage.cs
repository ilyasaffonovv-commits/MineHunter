using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>Everything that starts by itself, in one list: registry autostart, Startup folders, scheduled tasks, services that are not Windows' own. Each item can be switched off and on again;
    /// nothing is deleted, so a mistake is one click from being undone.</summary>
    public sealed class StartupPage : PageBase
    {
        public override string Key { get { return "startup"; } }
        public override string Title { get { return L("Startup", "Автозапуск"); } }
        public override string Icon { get { return "startup"; } }
        readonly StackPanel list = new StackPanel(); readonly TextBlock status = Ui.Txt("", 12.5, Ui.Muted, null, true, new Thickness(0, 6, 0, 0));
        List<StartupItem> items = new List<StartupItem>(); string filter = "all"; bool loading;
        readonly StackPanel chips = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };

        public StartupPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            var head = Header(L("Startup", "Автозапуск"), L("Programs, tasks and services that start by themselves. Switching one off does not delete it: switch it back on any time.", "Программы, задачи и службы, которые запускаются сами. Отключение ничего не удаляет: включить обратно можно в любой момент."));
            var refresh = Ui.Btn(L("Refresh", "Обновить"), () => Load(), "BtnGhost");
            var top = new StackPanel(); top.Children.Add(head); top.Children.Add(chips); chips.Children.Add(refresh);
            View = Frame(top, Ui.Scroll(Ui.V(list, status)));
        }

        public override void OnShow(object arg) { Load(); }

        void Load()
        {
            if (loading) return; loading = true; status.Text = L("Reading…", "Читаю…");
            Ui.Async(m.UiThread, () => StartupManager.List(Rules.RulePack.Load()), (r, ex) => { loading = false; if (ex != null) { status.Text = ex.Message; return; } items = r; Render(); });
        }

        void Chips()
        {
            while (chips.Children.Count > 1) chips.Children.RemoveAt(chips.Children.Count - 1);
            Action<string, string, int> chip = (key, text, n) =>
            {
                var b = Ui.Btn(text + "  " + n, () => { filter = key; Render(); }, filter == key ? "BtnPrimary" : "Btn"); b.Padding = new Thickness(12, 5, 12, 5); b.Margin = new Thickness(8, 0, 0, 0); chips.Children.Add(b);
            };
            chip("all", L("All", "Все"), items.Count); chip("untrusted", L("Not trusted", "Не доверенные"), items.Count(i => !i.Trusted)); chip("off", L("Switched off", "Отключённые"), items.Count(i => !i.Enabled));
        }

        void Render()
        {
            Chips(); list.Children.Clear();
            IEnumerable<StartupItem> q = items;
            if (filter == "untrusted") q = q.Where(i => !i.Trusted); else if (filter == "off") q = q.Where(i => !i.Enabled);
            foreach (var it in q) list.Children.Add(Row(it));
            status.Text = q.Count() + L(" item(s). Green = Microsoft or a trusted publisher; yellow = not signed or unknown; gray = the file is missing.", " пункт(ов). Зелёный = Microsoft или доверенный издатель; жёлтый = без подписи или неизвестно; серый = файла нет.");
        }

        UIElement Row(StartupItem it)
        {
            Brush c = !it.Exists ? Ui.Muted : it.Trusted ? Ui.Good : Ui.Warn;
            var sw = new CheckBox { Style = Ui.S("Switch"), IsChecked = it.Enabled, IsEnabled = it.CanChange, VerticalAlignment = VerticalAlignment.Center, ToolTip = it.CanChange ? L("On / off", "Вкл / выкл") : L("Shown only: cannot be changed from here", "Только показан: отсюда не меняется") };
            sw.Click += (s, e) => Toggle(it, sw);
            var mid = new StackPanel { Margin = new Thickness(12, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center };
            mid.Children.Add(Ui.H(Ui.Dot(c, 9), Ui.Txt(string.IsNullOrWhiteSpace(it.Name) ? L("(default value)", "(значение по умолчанию)") : it.Name, 13.5, null, FontWeights.SemiBold, false, new Thickness(8, 0, 10, 0)), Ui.Pill(it.KindText, Ui.Accent, 10.5)));
            mid.Children.Add(Ui.Mono(Text.Trunc(it.Command ?? "", 160), 11.5, Ui.Muted, false));
            string sub = (it.Publisher != null ? it.Publisher : it.Exists ? L("not signed", "без подписи") : L("the file is missing", "файла нет")) + "  ·  " + it.Source + (string.IsNullOrEmpty(it.Note) ? "" : "  ·  " + it.Note);
            mid.Children.Add(Ui.Txt(sub, 11, Ui.Muted, null, false, new Thickness(0, 2, 0, 0)));
            var btns = Ui.H();
            if (it.Exists && !string.IsNullOrEmpty(it.Target) && File.Exists(it.Target)) { var chk = Ui.Btn(L("Check", "Проверить"), () => m.Navigate("files", it.Target), "BtnSmall"); chk.Margin = new Thickness(0, 0, 6, 0); btns.Children.Add(chk); var fo = Ui.Btn(L("Folder", "Папка"), () => { try { Process.Start("explorer.exe", "/select,\"" + it.Target + "\""); } catch { } }, "BtnGhost"); fo.Margin = new Thickness(0); fo.Padding = new Thickness(10, 5, 10, 5); btns.Children.Add(fo); }
            var card = Ui.Card(Ui.Cols(new[] { "Auto", "*", "Auto" }, sw, mid, btns), 12); card.Margin = new Thickness(0, 0, 0, 8); return card;
        }

        void Toggle(StartupItem it, CheckBox sw)
        {
            bool enable = sw.IsChecked == true;
            if (!enable && it.Kind == "service" && !Ask(L("Switch the service “" + it.Name + "” off? It will not start with Windows (its original setting is remembered, so you can switch it back on).", "Отключить службу «" + it.Name + "»? Она не будет запускаться вместе с Windows (исходная настройка запоминается, включить обратно можно)."), L("Switch off", "Отключить"))) { sw.IsChecked = true; return; }
            string err = StartupManager.SetEnabled(it, enable);
            if (err != null) { sw.IsChecked = !enable; Info(err); return; }
            it.Enabled = enable; Log.Info("Startup " + (enable ? "enabled" : "disabled") + ": " + it.Name);
            status.Text = (enable ? L("Switched on: ", "Включено: ") : L("Switched off: ", "Отключено: ")) + it.Name + L(". Takes effect at the next start of Windows.", ". Вступит в силу при следующем запуске Windows.");
            Chips();
        }
    }
}
