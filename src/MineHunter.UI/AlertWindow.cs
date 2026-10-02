using System;
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
    /// <summary>The pop-up for a warning from the real-time layer: what happened in plain words, and what can be done about it. It appears in the corner without taking the keyboard focus, so
    /// it never swallows what the user is typing. The wording says "noticed", never "blocked".</summary>
    public sealed class AlertWindow
    {
        public readonly Window W;
        static readonly System.Collections.Generic.List<AlertWindow> Open = new System.Collections.Generic.List<AlertWindow>();
        static string L(string en, string ru) { return Loc.L(en, ru); }

        public AlertWindow(AppModel m, GuardAlert a)
        {
            Brush acc = a.Level == AlertLevel.Dangerous ? Ui.Bad : a.Level == AlertLevel.Suspicious ? Ui.Warn : Ui.Accent;
            string icon = a.Level == AlertLevel.Dangerous ? "cross" : a.Level == AlertLevel.Suspicious ? "warn" : "info";
            var body = new StackPanel();
            body.Children.Add(Ui.Cols(new[] { "Auto", "*", "Auto" }, Ui.Badge(icon, acc, 38), new StackPanel { Margin = new Thickness(12, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Txt(a.LevelText.ToUpperInvariant() + "  ·  " + GuardName(a.Guard), 10.5, acc, FontWeights.Bold, false), Ui.Txt(a.Title, 15, null, FontWeights.Bold, true, new Thickness(0, 2, 0, 0)) } }, CloseBtn()));
            body.Children.Add(Ui.Txt(a.Text, 12.5, Ui.TextB, null, true, new Thickness(0, 10, 0, 0)));
            var btns = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
            bool hasFile = !string.IsNullOrEmpty(a.Path) && File.Exists(a.Path);
            if (hasFile) btns.Children.Add(Ui.Btn(L("Why?", "Почему?"), () => { m.Navigate("files", a.Path); Close(); }, "BtnSmall"));
            if (hasFile && a.Level >= AlertLevel.Suspicious) btns.Children.Add(Ui.Btn(L("Quarantine", "В карантин"), () => { string err = GuardHost.QuarantineFile(a.Path, a.Title, a.Pid); Dlg.Info(W, "MineHunter", err == null ? L("The file was moved to the quarantine. You can restore it from the Quarantine page.", "Файл перемещён в карантин. Его можно вернуть на странице «Карантин».") : err); if (err == null) Close(); }, "BtnSmall"));
            if (a.Pid > 4 && a.Level >= AlertLevel.Suspicious) btns.Children.Add(Ui.Btn(L("Freeze the program", "Заморозить программу"), () => { bool ok = GuardHost.Freeze(a.Pid); Dlg.Info(W, "MineHunter", ok ? L("The program is frozen (suspended). You can stop it from the Processes page or let it go again.", "Программа заморожена (приостановлена). Её можно завершить на странице «Процессы» или отпустить обратно.") : L("Could not freeze it.", "Не удалось заморозить.")); }, "BtnSmall"));
            if (hasFile) btns.Children.Add(Ui.Btn(L("It is fine", "Это безопасно"), () => { if (Dlg.Ask(W, "MineHunter", L("Stop reporting this exact file?", "Больше не сообщать об этом файле?"), L("Yes, it is fine", "Да, он безопасен"))) { string err = GuardHost.Allow(a.Path); if (err == null) Close(); else Dlg.Info(W, "MineHunter", err); } }, "BtnSmall"));
            btns.Children.Add(Ui.Btn(L("Details", "Подробнее"), () => { m.Navigate("protection", null); Close(); }, "BtnGhost"));
            body.Children.Add(btns);
            if (a.Reasons.Count > 0) { var rs = Ui.V(); foreach (var r in a.Reasons.Take(5)) rs.Children.Add(Ui.Txt("•  " + r, 11.5, Ui.Muted, null, true, new Thickness(0, 2, 0, 0))); body.Children.Insert(2, rs); }

            W = new Window
            {
                Width = 430, SizeToContent = SizeToContent.Height, WindowStyle = WindowStyle.None, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false, Topmost = true, ShowActivated = false, AllowsTransparency = true, Background = Brushes.Transparent,
                FontFamily = new FontFamily("Segoe UI"), FontSize = 13
            };
            var card = new Border { Background = Ui.B("Surface"), BorderBrush = acc, BorderThickness = new Thickness(1.2), CornerRadius = new CornerRadius(14), Padding = new Thickness(16), Child = body, Margin = new Thickness(10), Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 18, Opacity = 0.5, ShadowDepth = 3 } };
            W.Content = card;
            W.Loaded += (s, e) => Place();
            W.Closed += (s, e) => Open.Remove(this);
            if (a.Level < AlertLevel.Dangerous) { var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(a.Level == AlertLevel.Suspicious ? 45 : 14) }; t.Tick += (s, e) => { t.Stop(); Close(); }; t.Start(); }
        }

        UIElement CloseBtn() { var b = Ui.Btn("✕", Close, "BtnGhost"); b.Padding = new Thickness(8, 2, 8, 2); b.Margin = new Thickness(0); b.VerticalAlignment = VerticalAlignment.Top; return b; }

        static string GuardName(string g)
        {
            switch (g) { case "file": return L("Files", "Файлы"); case "download": return L("Downloads", "Загрузки"); case "process": return L("Processes", "Процессы"); case "script": return L("Scripts", "Скрипты"); case "persistence": return L("Autostart", "Автозапуск"); case "network": return L("Network", "Сеть"); case "usb": return "USB"; case "ransomware": return L("Ransomware", "Шифровальщики"); default: return g; }
        }

        void Close() { try { W.Close(); } catch { } }

        void Place()
        {
            var wa = SystemParameters.WorkArea;
            double y = wa.Bottom - W.ActualHeight - 8;
            foreach (var o in Open) y -= (o.W.ActualHeight + 4);
            W.Left = wa.Right - W.ActualWidth - 6; W.Top = Math.Max(wa.Top + 6, y);
        }

        public static void Show(AppModel m, GuardAlert a)
        {
            try
            {
                var w = new AlertWindow(m, a); Open.Add(w); w.W.Show();
                if (Open.Count > 4) Open[0].Close();
            }
            catch (Exception ex) { Log.Warn("alert window: " + ex.Message); }
        }
    }
}
