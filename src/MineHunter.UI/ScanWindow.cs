using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Scanning;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>The window of "MineHunter Quick Scan.exe" and "MineHunter Full Scan.exe": it starts the scan at once, shows what is going on, and ends with "No threats found" or the
    /// findings. It is the same scan panel the main program uses, so the same scan gives the same result in both.</summary>
    public sealed class ScanWindow
    {
        public readonly Window W;
        readonly AppModel m; readonly ScanPanel panel; readonly ScanMode mode;

        public ScanWindow(AppModel model, ScanMode scanMode, bool autoStart)
        {
            m = model; mode = scanMode;
            W = new Window
            {
                Title = "MineHunter — " + (mode == ScanMode.Full ? Loc.L("Full scan", "Полная проверка") : Loc.L("Quick scan", "Быстрая проверка")), Width = 1000, Height = 720, MinWidth = 820, MinHeight = 560,
                WindowStartupLocation = WindowStartupLocation.CenterScreen, Background = Ui.B("Bg"), Foreground = Ui.TextB, FontFamily = new FontFamily("Segoe UI"), FontSize = 13, UseLayoutRounding = true, SnapsToDevicePixels = true, Icon = Branding.WpfIcon()
            };
            Dlg.DarkTitle(W);
            m.OwnerWindow = () => W;
            panel = new ScanPanel(m, () => W, true);
            panel.OpenMainRequested = OpenMain;
            panel.RunningChanged += r => { };

            var header = Ui.Cols(new[] { "Auto", "*", "Auto" },
                new Border { Width = 40, Height = 40, CornerRadius = new CornerRadius(11), Background = Ui.Accent, Child = Ui.Icon("shieldcheck", Brushes.White, 24, 2.2) },
                new StackPanel { Margin = new Thickness(14, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Txt("MineHunter", 20, null, FontWeights.Bold), Ui.Txt(mode == ScanMode.Full ? Loc.L("Full scan of all drives", "Полная проверка всех дисков") : Loc.L("Quick scan", "Быстрая проверка"), 12, Ui.Muted) } },
                LangSwitch());
            var root = new Grid { Margin = new Thickness(24, 18, 24, 20) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); root.RowDefinitions.Add(new RowDefinition());
            header.Margin = new Thickness(0, 0, 0, 18);
            Grid.SetRow(panel.Root, 1); root.Children.Add(header); root.Children.Add(panel.Root);
            W.Content = root;
            W.Closing += (s, e) =>
            {
                if (m.Scanner.Running)
                {
                    if (!Dlg.Ask(W, "MineHunter", Loc.L("A scan is running. Stop it and close the window?", "Идёт проверка. Остановить её и закрыть окно?"), Loc.L("Stop and close", "Остановить и закрыть"), Loc.L("Keep scanning", "Продолжить"))) { e.Cancel = true; return; }
                    m.Scanner.Cancel(); try { ScanEngine.ReleaseLock(); } catch { }
                }
            };
            W.Loaded += (s, e) =>
            {
                Log.Info("MineHunter " + AppInfo.Version + " " + mode + " scan window");
                if (autoStart) panel.Start(mode, null, mode == ScanMode.Full ? "full-exe" : "quick-exe"); else panel.ShowCurrent();
                try { m.CheckUpdates(false); } catch { }
            };
        }

        /// <summary>Documentation / automated checks: a picture while the scan runs and one when it is over.</summary>
        public void CaptureSequence(string dir)
        {
            System.IO.Directory.CreateDirectory(dir);
            var started = DateTime.Now; int step = 0; DateTime? finishedAt = null;
            var t = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
            t.Tick += (s, e) =>
            {
                try
                {
                    double sec = (DateTime.Now - started).TotalSeconds;
                    if (step == 0 && m.Scanner.Running && sec >= 7) { GuiApp.Capture(W, System.IO.Path.Combine(dir, mode + "_running_" + Loc.Lang + ".png")); step = 1; if (mode == ScanMode.Full) m.Scanner.Cancel(); }
                    if (step >= 1 && !m.Scanner.Running)
                    {
                        if (finishedAt == null) finishedAt = DateTime.Now;
                        if ((DateTime.Now - finishedAt.Value).TotalSeconds >= 2) { GuiApp.Capture(W, System.IO.Path.Combine(dir, mode + "_done_" + Loc.Lang + ".png")); t.Stop(); W.Close(); }
                    }
                    if (sec > 600) { t.Stop(); W.Close(); }
                }
                catch (Exception ex) { Log.Error("shot: " + ex.Message); }
            };
            t.Start();
        }

        UIElement LangSwitch()
        {
            var ru = Ui.Btn("RU", () => SetLang("ru"), "BtnSeg"); var en = Ui.Btn("EN", () => SetLang("en"), "BtnSeg");
            ru.Margin = new Thickness(0); en.Margin = new Thickness(0);
            Action paint = () => { ru.Background = Loc.Ru ? Ui.Accent : Brushes.Transparent; ru.Foreground = Loc.Ru ? Brushes.White : Ui.Muted; en.Background = !Loc.Ru ? Ui.Accent : Brushes.Transparent; en.Foreground = !Loc.Ru ? Brushes.White : Ui.Muted; };
            paint(); ru.Click += (s, e) => paint(); en.Click += (s, e) => paint();
            return new Border { CornerRadius = new CornerRadius(9), Background = Ui.B("Surface2"), Padding = new Thickness(2), VerticalAlignment = VerticalAlignment.Top, Child = Ui.H(ru, en) };
        }

        void SetLang(string lang)
        {
            Loc.Init(lang); m.Cfg.Language = lang; m.Cfg.SaveUser();
            if (!m.Scanner.Running) panel.ShowCurrent();
        }

        void OpenMain()
        {
            try
            {
                string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MineHunter.exe");
                if (File.Exists(exe)) { Process.Start(new ProcessStartInfo(exe, "--open-last") { UseShellExecute = true }); }
                else Dlg.Info(W, "MineHunter", Loc.L("MineHunter.exe was not found next to this program.", "MineHunter.exe не найден рядом с этой программой."));
            }
            catch (Exception ex) { Log.Warn("open main: " + ex.Message); }
        }
    }
}
