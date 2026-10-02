using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using MineHunter.Guards;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>Live connections: which program talks to which address, with filters. A program can be cut off with a Windows Firewall rule (MineHunter's own rules are listed below and removable).</summary>
    public sealed class NetworkPage : PageBase
    {
        public override string Key { get { return "network"; } }
        public override string Title { get { return L("Network", "Сеть"); } }
        public override string Icon { get { return "network"; } }
        readonly ListBox list = new ListBox { Style = Ui.S("RowList") };
        readonly TextBlock status = Ui.Txt("", 12, Ui.Muted, null, true, new Thickness(0, 8, 0, 0));
        readonly StackPanel blocked = new StackPanel();
        readonly TextBox search = new TextBox { Width = 230, Height = 34, Margin = new Thickness(8, 0, 8, 8), VerticalContentAlignment = VerticalAlignment.Center };
        readonly DispatcherTimer timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        string filter = "external"; List<ConnectionInfo> data = new List<ConnectionInfo>(); bool loading;
        readonly StackPanel chips = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
        readonly Button bCheck, bBlock, bKill;

        public NetworkPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            var head = Header(L("Network", "Сеть"), L("Which programs are talking to which addresses right now (TCP). UDP is not shown.", "Какие программы сейчас с какими адресами разговаривают (TCP). UDP не показывается."));
            search.TextChanged += (s, e) => Render();
            bCheck = Ui.Btn(L("Check the program", "Проверить программу"), () => { var c = Sel(); if (c != null && File.Exists(c.Path)) m.Navigate("files", c.Path); }, "Btn");
            bBlock = Ui.Btn(L("Block this program…", "Заблокировать программу…"), Block, "Btn");
            bKill = Ui.Btn(L("End process…", "Завершить процесс…"), Kill, "BtnDanger");
            var top = new StackPanel(); top.Children.Add(head); top.Children.Add(chips); chips.Children.Add(Ui.Txt(L("Search:", "Поиск:"), 12.5, Ui.Muted, null, false, new Thickness(0, 6, 0, 0))); chips.Children.Add(search);
            var body = new Grid(); body.RowDefinitions.Add(new RowDefinition()); body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var listCard = Ui.Card(list, 8); Grid.SetRow(listCard, 0);
            var bottom = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
            bottom.Children.Add(Ui.Wrap(bCheck, bBlock, bKill)); bottom.Children.Add(status); bottom.Children.Add(Ui.Head(L("Programs blocked by MineHunter", "Программы, заблокированные MineHunter"), new Thickness(0, 12, 0, 6))); bottom.Children.Add(blocked);
            Grid.SetRow(bottom, 1); body.Children.Add(listCard); body.Children.Add(bottom);
            View = Frame(top, body);
            list.SelectionChanged += (s, e) => Buttons();
            timer.Tick += (s, e) => { if (View.IsVisible) Load(); };
        }

        public override void OnShow(object arg) { Load(); RefreshBlocked(); timer.Start(); Buttons(); }
        public override void OnHide() { timer.Stop(); }

        ConnectionInfo Sel() { var it = list.SelectedItem as ListBoxItem; return it == null ? null : it.Tag as ConnectionInfo; }
        void Buttons() { var c = Sel(); bool f = c != null && !string.IsNullOrEmpty(c.Path) && File.Exists(c.Path); bCheck.IsEnabled = f; bBlock.IsEnabled = f; bKill.IsEnabled = c != null && c.Pid > 4; }

        void Load()
        {
            if (loading) return; loading = true;
            Ui.Async(m.UiThread, () => NetworkView.Snapshot(Rules.RulePack.Load(), true), (r, ex) => { loading = false; if (ex == null && r != null) { data = r; Render(); } });
        }

        void Chips()
        {
            while (chips.Children.Count > 2) chips.Children.RemoveAt(2);
            Action<string, string, int> chip = (key, text, n) => { var b = Ui.Btn(text + "  " + n, () => { filter = key; Render(); }, filter == key ? "BtnPrimary" : "Btn"); b.Padding = new Thickness(12, 5, 12, 5); b.Margin = new Thickness(0, 0, 8, 8); chips.Children.Add(b); };
            chip("external", L("External", "Наружу"), data.Count(c => c.External)); chip("unknown", L("Unknown programs", "Неизвестные программы"), data.Count(c => c.External && !c.Trusted)); chip("listen", L("Listening", "Слушают порты"), data.Count(c => c.State == "Listen")); chip("all", L("All", "Все"), data.Count);
        }

        void Render()
        {
            Chips();
            string sel = Sel() == null ? null : Sel().Pid + "|" + Sel().Remote + ":" + Sel().RemotePort + "|" + Sel().LocalPort;
            IEnumerable<ConnectionInfo> q = data;
            if (filter == "external") q = q.Where(c => c.External); else if (filter == "unknown") q = q.Where(c => c.External && !c.Trusted); else if (filter == "listen") q = q.Where(c => c.State == "Listen");
            string s = (search.Text ?? "").Trim().ToLowerInvariant();
            if (s.Length > 0) q = q.Where(c => (c.Process ?? "").ToLowerInvariant().Contains(s) || (c.Remote ?? "").Contains(s) || (c.Path ?? "").ToLowerInvariant().Contains(s) || c.RemotePort.ToString() == s);
            var rows = q.OrderByDescending(c => !c.Trusted && c.External).ThenBy(c => c.Process, StringComparer.OrdinalIgnoreCase).Take(600).ToList();
            list.Items.Clear(); ListBoxItem keep = null;
            list.Items.Add(new ListBoxItem { Content = HeaderRow(), IsEnabled = false, Focusable = false });
            foreach (var c in rows)
            {
                var it = new ListBoxItem { Content = Row(c), Tag = c }; list.Items.Add(it);
                if (sel != null && sel == c.Pid + "|" + c.Remote + ":" + c.RemotePort + "|" + c.LocalPort) keep = it;
            }
            if (keep != null) list.SelectedItem = keep;
            status.Text = rows.Count + L(" connection(s) shown. Green = Microsoft or a trusted publisher; yellow = not trusted.", " соединений показано. Зелёный = Microsoft или доверенный издатель; жёлтый = не доверенный.");
        }

        static readonly double[] W = { 210, 60, 210, 120, 100, 300 };

        UIElement HeaderRow()
        {
            var g = new Grid { Margin = new Thickness(6, 2, 6, 2) };
            string[] h = { L("Program", "Программа"), "PID", L("Remote address", "Удалённый адрес"), L("State", "Состояние"), L("First seen", "Впервые"), L("Publisher / file", "Издатель / файл") };
            for (int i = 0; i < W.Length; i++) { g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(W[i]) }); var t = Ui.Txt(h[i], 11, Ui.Muted, FontWeights.Bold, false); Grid.SetColumn(t, i); g.Children.Add(t); }
            return g;
        }

        UIElement Row(ConnectionInfo c)
        {
            var g = new Grid { Margin = new Thickness(6, 5, 6, 5) };
            for (int i = 0; i < W.Length; i++) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(W[i]) });
            Brush dot = string.IsNullOrEmpty(c.Path) ? Ui.Muted : c.Trusted ? Ui.Good : Ui.Warn;
            var name = Ui.H(Ui.Dot(dot, 9), Ui.Txt(c.Process, 12.5, null, FontWeights.SemiBold, false, new Thickness(8, 0, 0, 0))); name.Width = 200; g.Children.Add(name);
            Action<int, UIElement> put = (i, e) => { Grid.SetColumn(e, i); g.Children.Add(e); };
            put(1, Ui.Txt(c.Pid.ToString(), 12, Ui.Muted, null, false));
            put(2, Ui.Txt(c.State == "Listen" ? L("port ", "порт ") + c.LocalPort : c.Remote + ":" + c.RemotePort, 12, c.External && !c.Trusted ? Ui.Warn : Ui.TextB, null, false));
            put(3, Ui.Txt(c.State, 12, Ui.Muted, null, false));
            put(4, Ui.Txt(c.FirstSeen.HasValue ? (DateTime.Now - c.FirstSeen.Value).TotalMinutes < 1 ? L("just now", "только что") : c.FirstSeen.Value.ToString("HH:mm:ss") : "", 12, Ui.Muted, null, false));
            put(5, Ui.Txt(c.Publisher ?? c.Path ?? "", 11.5, Ui.Muted, null, false));
            return g;
        }

        void RefreshBlocked()
        {
            blocked.Children.Clear();
            var l = FirewallBlock.Blocked();
            if (l.Count == 0) { blocked.Children.Add(Ui.Txt(L("None.", "Нет."), 12.5, Ui.Muted)); return; }
            foreach (var p in l)
            {
                var path = p; var row = Ui.Cols(new[] { "*", "Auto" }, Ui.Mono(path, 12, Ui.TextB, false), Ui.Btn(L("Unblock", "Разблокировать"), () => { string err = FirewallBlock.Unblock(path); if (err != null) Info(err); RefreshBlocked(); }, "BtnSmall"));
                row.Margin = new Thickness(0, 3, 0, 3); blocked.Children.Add(row);
            }
        }

        void Block()
        {
            var c = Sel(); if (c == null || !File.Exists(c.Path)) return;
            if (!Ask(L("Cut “" + Path.GetFileName(c.Path) + "” off from the network? Two Windows Firewall rules (outgoing and incoming) are added for exactly this file; you can remove them below.", "Отрезать «" + Path.GetFileName(c.Path) + "» от сети? В брандмауэр Windows добавятся два правила (исходящее и входящее) именно для этого файла; убрать их можно ниже."), L("Block", "Заблокировать"))) return;
            string err = FirewallBlock.Block(c.Path); if (err != null) Info(err); RefreshBlocked();
        }

        void Kill()
        {
            var c = Sel(); if (c == null) return;
            if (!Ask(L("End “" + c.Process + "” (PID " + c.Pid + ")? Unsaved work in it is lost.", "Завершить «" + c.Process + "» (PID " + c.Pid + ")? Несохранённая работа в ней будет потеряна."), L("End process", "Завершить"), true)) return;
            var ent = new Model.Entity { Kind = Model.EntityKind.Process, Title = c.Process + ".exe", Location = c.Path };
            if (Risk.Decision.IsProtectedProcess(ent)) { Info(L("This is a critical Windows process: MineHunter will not end it.", "Это критический процесс Windows: MineHunter его не завершит.")); return; }
            string err = GuardHost.Terminate(c.Pid); if (err != null) Info(err); Load();
        }
    }
}
