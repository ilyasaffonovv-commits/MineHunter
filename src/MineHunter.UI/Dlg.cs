using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;

namespace MineHunter.Gui
{
    /// <summary>Dark dialogs in the program's own style (the system message box is white and breaks the look).</summary>
    public static class Dlg
    {
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        public static void DarkTitle(Window w)
        {
            w.SourceInitialized += (s, e) => { try { var h = new WindowInteropHelper(w).Handle; int on = 1; if (DwmSetWindowAttribute(h, 20, ref on, 4) != 0) DwmSetWindowAttribute(h, 19, ref on, 4); } catch { } };
        }

        static Window Make(Window owner, string title, double width = 480)
        {
            var w = new Window
            {
                Title = title, Width = width, SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false, Background = Ui.B("Bg"), Foreground = Ui.TextB,
                WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen, FontFamily = new FontFamily("Segoe UI"), FontSize = 13, UseLayoutRounding = true
            };
            if (owner != null) { try { w.Owner = owner; } catch { } }
            DarkTitle(w);
            return w;
        }

        /// <summary>A question with two buttons. <paramref name="danger"/> makes the yes button red.</summary>
        public static bool Ask(Window owner, string title, string text, string yes = null, string no = null, bool danger = false)
        {
            var w = Make(owner, title); bool result = false;
            var panel = new StackPanel { Margin = new Thickness(24, 22, 24, 20) };
            panel.Children.Add(Ui.Txt(text, 13.5));
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
            var b1 = Ui.Btn(yes ?? Loc.L("Yes", "Да"), () => { result = true; w.Close(); }, danger ? "BtnDanger" : "BtnPrimary"); b1.Margin = new Thickness(0, 0, 8, 0);
            var b2 = Ui.Btn(no ?? Loc.L("No", "Нет"), () => { result = false; w.Close(); }, "Btn"); b2.Margin = new Thickness(0);
            buttons.Children.Add(b1); buttons.Children.Add(b2); panel.Children.Add(buttons);
            w.Content = panel; w.ShowDialog(); return result;
        }

        public static void Info(Window owner, string title, string text, string ok = null)
        {
            var w = Make(owner, title);
            var panel = new StackPanel { Margin = new Thickness(24, 22, 24, 20) };
            var body = Ui.Txt(text, 13.5); panel.Children.Add(new ScrollViewer { Content = body, MaxHeight = 360, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
            var b = Ui.Btn(ok ?? "OK", () => w.Close(), "BtnPrimary"); b.HorizontalAlignment = HorizontalAlignment.Right; b.Margin = new Thickness(0, 20, 0, 0);
            panel.Children.Add(b);
            w.Content = panel; w.ShowDialog();
        }

        /// <summary>A one-line input. Returns null when cancelled.</summary>
        public static string Prompt(Window owner, string title, string label, string initial = "", bool multiline = false)
        {
            var w = Make(owner, title, 520); string result = null;
            var panel = new StackPanel { Margin = new Thickness(24, 22, 24, 20) };
            panel.Children.Add(Ui.Txt(label, 13));
            var box = new TextBox { Text = initial ?? "", Margin = new Thickness(0, 10, 0, 0), HorizontalAlignment = HorizontalAlignment.Stretch };
            if (multiline) { box.AcceptsReturn = true; box.TextWrapping = TextWrapping.Wrap; box.Height = 110; box.VerticalScrollBarVisibility = ScrollBarVisibility.Auto; }
            panel.Children.Add(box);
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) };
            var ok = Ui.Btn("OK", () => { result = box.Text; w.Close(); }, "BtnPrimary"); ok.Margin = new Thickness(0, 0, 8, 0);
            var cancel = Ui.Btn(Loc.L("Cancel", "Отмена"), () => w.Close(), "Btn"); cancel.Margin = new Thickness(0);
            buttons.Children.Add(ok); buttons.Children.Add(cancel); panel.Children.Add(buttons);
            w.Content = panel; w.Loaded += (s, e) => { box.Focus(); box.SelectAll(); };
            w.ShowDialog(); return result;
        }

        /// <summary>A dialog with one choice from several buttons. Returns the index, or -1 when closed.</summary>
        public static int Choose(Window owner, string title, string text, params string[] options)
        {
            var w = Make(owner, title, 520); int result = -1;
            var panel = new StackPanel { Margin = new Thickness(24, 22, 24, 20) };
            panel.Children.Add(Ui.Txt(text, 13.5));
            var buttons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
            for (int i = 0; i < options.Length; i++) { if (options[i] == null) continue; int idx = i; var b = Ui.Btn(options[i], () => { result = idx; w.Close(); }, i == 0 ? "BtnPrimary" : "Btn"); buttons.Children.Add(b); }
            panel.Children.Add(buttons);
            w.Content = panel; w.ShowDialog(); return result;
        }
    }
}
