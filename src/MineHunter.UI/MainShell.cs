using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>The main window: a sidebar with the sections and the page of the section on the right.</summary>
    public sealed class MainShell
    {
        public readonly Window W;
        readonly AppModel m;
        readonly Dictionary<string, IPage> pages = new Dictionary<string, IPage>();
        readonly Dictionary<string, RadioButton> nav = new Dictionary<string, RadioButton>();
        readonly ContentControl host = new ContentControl();
        IPage current;
        TextBlock sideProt, sideVer; Border updatePill; TextBlock updateText;

        static string L(string en, string ru) { return Loc.L(en, ru); }

        public MainShell(AppModel model)
        {
            m = model;
            W = new Window
            {
                Title = "MineHunter " + AppInfo.Version, Width = 1280, Height = 840, MinWidth = 1040, MinHeight = 680, WindowStartupLocation = WindowStartupLocation.CenterScreen, Background = Ui.B("Bg"), Foreground = Ui.TextB,
                FontFamily = new FontFamily("Segoe UI"), FontSize = 13, UseLayoutRounding = true, SnapsToDevicePixels = true, Icon = Branding.WpfIcon()
            };
            TextOptions.SetTextFormattingMode(W, TextFormattingMode.Display);
            Dlg.DarkTitle(W);
            m.OwnerWindow = () => W;
            m.Navigate = Go;
            Func<Window> own = () => W;
            foreach (var p in new IPage[] { new HomePage(m, own), new ScanPage(m, own), new ProtectionPage(m, own), new FilesPage(m, own), new ProcessesPage(m, own), new StartupPage(m, own), new NetworkPage(m, own), new QuarantinePage(m, own), new DriversPage(m, own), new HealthPage(m, own), new SchedulePage(m, own), new HistoryPage(m, own), new SettingsPage(m, own) })
                pages[p.Key] = p;

            var root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(236) }); root.ColumnDefinitions.Add(new ColumnDefinition());
            var side = BuildSidebar(); root.Children.Add(side);
            host.Margin = new Thickness(26, 22, 22, 18); Grid.SetColumn(host, 1); root.Children.Add(host);
            W.Content = root;
            m.StateChanged += RefreshSide;
            W.Loaded += (s, e) => RefreshSide();
        }

        UIElement BuildSidebar()
        {
            var side = new Border { Background = Ui.B("Side"), BorderBrush = Ui.B("Line"), BorderThickness = new Thickness(0, 0, 1, 0) };
            var g = new Grid(); g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); g.RowDefinitions.Add(new RowDefinition()); g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var logo = Ui.Cols(new[] { "Auto", "*" }, new Border { Width = 38, Height = 38, CornerRadius = new CornerRadius(10), Background = Ui.Accent, Child = Ui.Icon("shieldcheck", Brushes.White, 22, 2.2) },
                new StackPanel { Margin = new Thickness(12, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Txt("MineHunter", 17, null, FontWeights.Bold, false), Ui.Txt(L("anti-miner", "антимайнер"), 11, Ui.Muted, null, false) } });
            logo.Margin = new Thickness(18, 20, 14, 16); g.Children.Add(logo);
            var navPanel = new StackPanel { Margin = new Thickness(10, 0, 10, 0) };
            string[][] groups = { new[] { "home", "scan", "protection", "files" }, new[] { "processes", "startup", "network", "quarantine" }, new[] { "drivers", "health" }, new[] { "schedule", "history", "settings" } };
            bool first = true;
            foreach (var grp in groups)
            {
                if (!first) navPanel.Children.Add(new Border { Height = 1, Background = Ui.B("Line"), Margin = new Thickness(10, 8, 10, 8) });
                first = false;
                foreach (var key in grp)
                {
                    var p = pages[key]; string k = key;
                    var rb = new RadioButton { GroupName = "nav", Style = Ui.S("NavItem"), Content = Ui.Cols(new[] { "Auto", "*" }, Ui.Icon(p.Icon, null, 19), Ui.Txt(p.Title, 13.5, null, null, false, new Thickness(12, 0, 0, 0))) };
                    rb.Checked += (s, e) => { if (current == null || current.Key != k) Go(k, null); };
                    nav[key] = rb; navPanel.Children.Add(rb);
                }
            }
            var navScroll = new ScrollViewer { Content = navPanel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(0, 0, 0, 8) };
            Grid.SetRow(navScroll, 1); g.Children.Add(navScroll);

            var foot = new StackPanel { Margin = new Thickness(16, 8, 16, 16) };
            sideProt = Ui.Txt("", 12, Ui.Muted, FontWeights.SemiBold); foot.Children.Add(sideProt);
            updateText = Ui.Txt("", 11.5, Ui.Muted, FontWeights.SemiBold, true, new Thickness(0, 6, 0, 0));
            updatePill = new Border { CornerRadius = new CornerRadius(10), Background = Ui.B("Surface2"), Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 8, 0, 0), Cursor = Cursors.Hand, Child = updateText };
            updatePill.MouseLeftButtonUp += (s, e) => Go("settings", "updates");
            foot.Children.Add(updatePill);
            var lang = Ui.Btn("RU", () => SetLang("ru"), "BtnSeg"); var en = Ui.Btn("EN", () => SetLang("en"), "BtnSeg"); lang.Margin = new Thickness(0); en.Margin = new Thickness(0);
            Action paint = () => { lang.Background = Loc.Ru ? Ui.Accent : Brushes.Transparent; lang.Foreground = Loc.Ru ? Brushes.White : Ui.Muted; en.Background = !Loc.Ru ? Ui.Accent : Brushes.Transparent; en.Foreground = !Loc.Ru ? Brushes.White : Ui.Muted; };
            paint(); lang.Click += (s, e) => paint(); en.Click += (s, e) => paint();
            foot.Children.Add(new Border { CornerRadius = new CornerRadius(9), Background = Ui.B("Surface2"), Padding = new Thickness(2), Margin = new Thickness(0, 10, 0, 0), HorizontalAlignment = HorizontalAlignment.Left, Child = Ui.H(lang, en) });
            Grid.SetRow(foot, 2); g.Children.Add(foot);
            side.Child = g; return side;
        }

        void SetLang(string lang)
        {
            Loc.Init(lang); m.Cfg.Language = lang; m.Cfg.SaveUser();
            // the window is rebuilt in the new language: simplest and keeps every string in one place
            var key = current == null ? "home" : current.Key;
            var area = new Rect(W.Left, W.Top, W.ActualWidth, W.ActualHeight);
            var shell = new MainShell(m); shell.W.WindowStartupLocation = WindowStartupLocation.Manual; shell.W.Left = area.Left; shell.W.Top = area.Top; shell.W.Width = area.Width; shell.W.Height = area.Height;
            GuiApp.ReplaceMain(this, shell, key);
        }

        // ------------------------------------------------------------------------------------------------ navigation
        public void Go(string key, object arg = null)
        {
            if (!m.UiThread.CheckAccess()) { m.UiThread.BeginInvoke(new Action(() => Go(key, arg))); return; }
            IPage p; if (!pages.TryGetValue(key, out p)) return;
            if (current != null && current != p) { var pb = current as PageBase; if (pb != null) pb.OnHide(); }
            current = p; host.Content = p.View;
            RadioButton rb; if (nav.TryGetValue(key, out rb) && rb.IsChecked != true) rb.IsChecked = true;
            try { p.OnShow(arg); } catch (Exception ex) { Log.Error("page " + key + ": " + ex); }
            if (!W.IsVisible) { W.Show(); }
            if (W.WindowState == WindowState.Minimized) W.WindowState = WindowState.Normal;
            W.Activate();
        }

        public IPage Page(string key) { IPage p; pages.TryGetValue(key, out p); return p; }
        public string CurrentKey { get { return current == null ? null : current.Key; } }

        void RefreshSide()
        {
            try
            {
                int on = m.GuardsOn;
                sideProt.Text = L("Protection: ", "Защита: ") + (on == 0 ? L("off", "выключена") : on + " " + L("of 8 on", "из 8 включено")); sideProt.Foreground = on == 0 ? Ui.Muted : Ui.Good;
                var up = m.AppUpdate; Brush c = Ui.Muted; string text = L("Version ", "Версия ") + AppInfo.Version;
                if (m.CheckingUpdates) text = "⟳  " + L("Checking for updates…", "Проверяю обновления…");
                else if (up != null && up.State == AppUpdateState.Ready) { text = "⬆  " + L("Update ready: ", "Обновление готово: ") + up.StagedVersion; c = Ui.Warn; }
                else if (up != null && up.State == AppUpdateState.Available) { text = "⬆  " + L("Update available", "Доступно обновление"); c = Ui.Warn; }
                else if (up != null && up.State == AppUpdateState.UpToDate) { text = "✓  " + L("Version " + AppInfo.Version + " — the latest", "Версия " + AppInfo.Version + " — последняя"); c = Ui.Good; }
                else if (up != null && up.State == AppUpdateState.Offline) text = "○  " + L("Version " + AppInfo.Version + " · offline", "Версия " + AppInfo.Version + " · нет сети");
                updateText.Text = text; updateText.Foreground = c;
            }
            catch { }
        }
    }
}
