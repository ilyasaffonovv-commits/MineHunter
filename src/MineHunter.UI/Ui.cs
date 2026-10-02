using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Shapes;

namespace MineHunter.Gui
{
    /// <summary>The small kit every page is built from: theme, text, cards, buttons, switches, icons, background work. Pages are written in code with these helpers.</summary>
    public static class Ui
    {
        static ResourceDictionary _theme;
        public static ResourceDictionary Theme
        {
            get
            {
                if (_theme == null)
                    using (var s = typeof(Ui).Assembly.GetManifestResourceStream("ui.Theme.xaml")) _theme = (ResourceDictionary)XamlReader.Load(s);
                return _theme;
            }
        }

        public static Brush B(string key) { return (Brush)Theme[key]; }
        public static Style S(string key) { return (Style)Theme[key]; }
        public static Brush Hex(string hex) { var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex); b.Freeze(); return b; }
        public static Brush Soft(Brush b, byte alpha = 38) { var c = ((SolidColorBrush)b).Color; c.A = alpha; var r = new SolidColorBrush(c); r.Freeze(); return r; }

        public static Brush Good { get { return B("Good"); } }
        public static Brush Warn { get { return B("Warn"); } }
        public static Brush Orange { get { return B("Orange"); } }
        public static Brush Bad { get { return B("Bad"); } }
        public static Brush Accent { get { return B("Accent"); } }
        public static Brush Muted { get { return B("Muted"); } }
        public static Brush TextB { get { return B("Text"); } }

        // ------------------------------------------------------------------------------------------------ text
        public static TextBlock Txt(string text, double size = 13, Brush fg = null, FontWeight? weight = null, bool wrap = true, Thickness? margin = null)
        {
            var t = new TextBlock { Text = text ?? "", FontSize = size, Foreground = fg ?? TextB, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap };
            if (!wrap) t.TextTrimming = TextTrimming.CharacterEllipsis;
            if (weight != null) t.FontWeight = weight.Value;
            if (margin != null) t.Margin = margin.Value;
            return t;
        }

        public static TextBlock Mono(string text, double size = 12, Brush fg = null, bool wrap = true)
        {
            var t = Txt(text, size, fg ?? B("Muted"), null, wrap); t.FontFamily = new FontFamily("Consolas"); return t;
        }

        /// <summary>A small muted heading over a block (upper case).</summary>
        public static TextBlock Head(string text, Thickness? margin = null) { return Txt((text ?? "").ToUpperInvariant(), 11, Muted, FontWeights.Bold, true, margin ?? new Thickness(0, 18, 0, 8)); }

        public static TextBlock Title(string text) { return Txt(text, 22, null, FontWeights.Bold, true, new Thickness(0, 0, 0, 2)); }

        // ------------------------------------------------------------------------------------------------ containers
        public static Border Card(UIElement child, double pad = 18, Brush bg = null, Brush border = null, double radius = 14)
        {
            return new Border { Background = bg ?? B("Surface"), BorderBrush = border ?? B("Line"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(radius), Padding = new Thickness(pad), Child = child };
        }

        public static StackPanel V(params UIElement[] kids) { var p = new StackPanel(); foreach (var k in kids) if (k != null) p.Children.Add(k); return p; }
        public static StackPanel H(params UIElement[] kids) { var p = new StackPanel { Orientation = Orientation.Horizontal }; foreach (var k in kids) if (k != null) p.Children.Add(k); return p; }
        public static WrapPanel Wrap(params UIElement[] kids) { var p = new WrapPanel(); foreach (var k in kids) if (k != null) p.Children.Add(k); return p; }

        /// <summary>A grid with the given column widths ("Auto", "*", "2*", "120") and the elements placed one per column.</summary>
        public static Grid Cols(string[] widths, params UIElement[] kids)
        {
            var g = new Grid();
            foreach (var w in widths) g.ColumnDefinitions.Add(new ColumnDefinition { Width = w == "Auto" ? GridLength.Auto : w.EndsWith("*") ? new GridLength(w.Length == 1 ? 1 : double.Parse(w.TrimEnd('*')), GridUnitType.Star) : new GridLength(double.Parse(w)) });
            for (int i = 0; i < kids.Length && i < widths.Length; i++) { if (kids[i] == null) continue; Grid.SetColumn(kids[i], i); g.Children.Add(kids[i]); }
            return g;
        }

        public static ScrollViewer Scroll(UIElement child, double padRight = 6)
        {
            return new ScrollViewer { Content = child, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Padding = new Thickness(0, 0, padRight, 0) };
        }

        public static FrameworkElement Gap(double h) { return new Border { Height = h }; }
        public static FrameworkElement Line() { return new Border { Height = 1, Background = B("Line"), Margin = new Thickness(0, 10, 0, 10) }; }

        public static Border Pill(string text, Brush accent, double size = 11.5)
        {
            return new Border { CornerRadius = new CornerRadius(12), Background = Soft(accent), Padding = new Thickness(10, 3, 10, 3), HorizontalAlignment = HorizontalAlignment.Left, Child = new TextBlock { Text = text, Foreground = accent, FontWeight = FontWeights.Bold, FontSize = size } };
        }

        public static Ellipse Dot(Brush color, double size = 10) { return new Ellipse { Width = size, Height = size, Fill = color, VerticalAlignment = VerticalAlignment.Center }; }

        // ------------------------------------------------------------------------------------------------ controls
        public static Button Btn(string text, Action click, string style = "Btn", string tip = null)
        {
            var b = new Button { Content = text, Style = S(style), Margin = new Thickness(0, 0, 8, 8) };
            if (click != null) b.Click += (s, e) => click();
            if (tip != null) b.ToolTip = tip;
            return b;
        }

        public static CheckBox Sw(string label, bool value, Action<bool> changed, string tip = null)
        {
            var c = new CheckBox { Content = label, IsChecked = value, Style = S("Switch"), Margin = new Thickness(0, 4, 0, 4) };
            c.Checked += (s, e) => { if (changed != null) changed(true); };
            c.Unchecked += (s, e) => { if (changed != null) changed(false); };
            if (tip != null) c.ToolTip = tip;
            return c;
        }

        public static CheckBox Chk(string label, bool value, Action<bool> changed)
        {
            var c = new CheckBox { Content = label, IsChecked = value, Margin = new Thickness(0, 4, 0, 4) };
            c.Checked += (s, e) => { if (changed != null) changed(true); };
            c.Unchecked += (s, e) => { if (changed != null) changed(false); };
            return c;
        }

        public static ComboBox Combo(IList<KeyValuePair<string, string>> items, string selected, Action<string> changed, double width = 220)
        {
            var c = new ComboBox { Width = width, HorizontalAlignment = HorizontalAlignment.Left };
            foreach (var kv in items) c.Items.Add(new ComboBoxItem { Content = kv.Value, Tag = kv.Key });
            foreach (ComboBoxItem it in c.Items) if ((string)it.Tag == selected) c.SelectedItem = it;
            if (c.SelectedItem == null && c.Items.Count > 0) c.SelectedIndex = 0;
            c.SelectionChanged += (s, e) => { var it = c.SelectedItem as ComboBoxItem; if (it != null && changed != null) changed((string)it.Tag); };
            return c;
        }

        public static KeyValuePair<string, string> Kv(string k, string v) { return new KeyValuePair<string, string>(k, v); }

        public static TextBox Input(string text, double width = 360, Action<string> changed = null)
        {
            var t = new TextBox { Text = text ?? "", Width = width, HorizontalAlignment = HorizontalAlignment.Left };
            if (changed != null) t.LostFocus += (s, e) => changed(t.Text);
            return t;
        }

        // ------------------------------------------------------------------------------------------------ icons (24 x 24, drawn with strokes)
        static readonly Dictionary<string, string> Icons = new Dictionary<string, string>
        {
            { "home", "M3,11 L12,3 L21,11 M5,9.5 L5,21 L19,21 L19,9.5 M10,21 L10,14 L14,14 L14,21" },
            { "shield", "M12,2.5 L20,5.5 L20,12 C20,17 16.5,20.5 12,21.8 C7.5,20.5 4,17 4,12 L4,5.5 Z" },
            { "shieldcheck", "M12,2.5 L20,5.5 L20,12 C20,17 16.5,20.5 12,21.8 C7.5,20.5 4,17 4,12 L4,5.5 Z M8.3,12 L11,14.8 L15.8,9.2" },
            { "scan", "M10.5,4 A6.5,6.5 0 1 1 10.5,17 A6.5,6.5 0 1 1 10.5,4 Z M15.4,15.4 L21,21" },
            { "folder", "M3,6.5 L9.5,6.5 L11.5,8.5 L21,8.5 L21,19 L3,19 Z" },
            { "procs", "M4,5 L20,5 L20,10 L4,10 Z M4,14 L20,14 L20,19 L4,19 Z M7,7.5 L7.2,7.5 M7,16.5 L7.2,16.5" },
            { "startup", "M12,3 L12,12 M6.3,6.8 A8,8 0 1 0 17.7,6.8" },
            { "network", "M12,3 A9,9 0 1 1 12,21 A9,9 0 1 1 12,3 Z M3,12 L21,12 M12,3 C8,7 8,17 12,21 M12,3 C16,7 16,17 12,21" },
            { "box", "M4,8 L12,4 L20,8 L20,16.5 L12,20.5 L4,16.5 Z M4,8 L12,12 L20,8 M12,12 L12,20.5" },
            { "chip", "M7,7 L17,7 L17,17 L7,17 Z M9.5,3.5 L9.5,7 M14.5,3.5 L14.5,7 M9.5,17 L9.5,20.5 M14.5,17 L14.5,20.5 M3.5,9.5 L7,9.5 M3.5,14.5 L7,14.5 M17,9.5 L20.5,9.5 M17,14.5 L20.5,14.5" },
            { "pulse", "M3,12 L7.5,12 L10,6 L14,18 L16.5,12 L21,12" },
            { "clock", "M12,3 A9,9 0 1 1 12,21 A9,9 0 1 1 12,3 Z M12,7 L12,12 L16,14" },
            { "sliders", "M4,7 L20,7 M4,12 L20,12 M4,17 L20,17 M9,4.5 L9,9.5 M15,9.5 L15,14.5 M8,14.5 L8,19.5" },
            { "file", "M6,3 L14,3 L19,8 L19,21 L6,21 Z M14,3 L14,8 L19,8" },
            { "bell", "M6,16 L6,11 A6,6 0 0 1 18,11 L18,16 L20,18 L4,18 Z M10,20.5 A2,2 0 0 0 14,20.5" },
            { "check", "M5,12.5 L10,17.5 L19,7" },
            { "cross", "M6,6 L18,18 M18,6 L6,18" },
            { "warn", "M12,3.5 L21.5,20 L2.5,20 Z M12,10 L12,14.5 M12,17.2 L12,17.4" },
            { "bolt", "M13,3 L5,13.5 L11,13.5 L10,21 L19,10 L13,10 Z" },
            { "play", "M7,4.5 L19,12 L7,19.5 Z" },
            { "stop", "M6,6 L18,6 L18,18 L6,18 Z" },
            { "refresh", "M20,12 A8,8 0 1 1 17.5,6.2 M20,4 L20,9 L15,9" },
            { "download", "M12,4 L12,15 M7,10.5 L12,15.5 L17,10.5 M5,20 L19,20" },
            { "lock", "M6,11 L18,11 L18,20 L6,20 Z M8.5,11 L8.5,8 A3.5,3.5 0 0 1 15.5,8 L15.5,11" },
            { "search", "M10.5,4 A6.5,6.5 0 1 1 10.5,17 A6.5,6.5 0 1 1 10.5,4 Z M15.4,15.4 L21,21" },
            { "info", "M12,3 A9,9 0 1 1 12,21 A9,9 0 1 1 12,3 Z M12,11 L12,16.5 M12,7.7 L12,7.9" },
            { "trash", "M5,7 L19,7 M9,7 L9,4.5 L15,4.5 L15,7 M7,7 L8,20 L16,20 L17,7" },
            { "eye", "M2.5,12 C5,7 8.5,5 12,5 C15.5,5 19,7 21.5,12 C19,17 15.5,19 12,19 C8.5,19 5,17 2.5,12 Z M12,9 A3,3 0 1 1 12,15 A3,3 0 1 1 12,9 Z" },
            { "usb", "M12,3 L12,17 M12,17 A2,2 0 1 1 12,21 A2,2 0 1 1 12,17 Z M12,9 L7,9 L7,12 M12,12 L17,12 L17,9" }
        };

        public static FrameworkElement Icon(string name, Brush color = null, double size = 20, double thickness = 1.8)
        {
            string d; if (!Icons.TryGetValue(name, out d)) d = Icons["info"];
            var path = new Path { Data = Geometry.Parse(d), Stroke = color ?? Muted, StrokeThickness = thickness, StrokeLineJoin = PenLineJoin.Round, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, Fill = Brushes.Transparent };
            var canvas = new Canvas { Width = 24, Height = 24 }; canvas.Children.Add(path);
            return new Viewbox { Width = size, Height = size, Child = canvas, VerticalAlignment = VerticalAlignment.Center };
        }

        /// <summary>A round badge with an icon inside, used as the state mark of a card.</summary>
        public static Border Badge(string icon, Brush accent, double size = 40)
        {
            return new Border { Width = size, Height = size, CornerRadius = new CornerRadius(size / 2), Background = Soft(accent, 40), Child = Icon(icon, accent, size * 0.5), VerticalAlignment = VerticalAlignment.Center };
        }

        // ------------------------------------------------------------------------------------------------ background work
        /// <summary>Runs work on a thread-pool thread and hands the result to the UI thread. A failure is shown as null result + the exception.</summary>
        public static void Async<T>(Dispatcher d, Func<T> work, Action<T, Exception> done)
        {
            Task.Run(() =>
            {
                T r = default(T); Exception err = null;
                try { r = work(); } catch (Exception ex) { err = ex; }
                d.BeginInvoke(new Action(() => done(r, err)));
            });
        }

        public static string FormatDuration(TimeSpan t) { return t.TotalHours >= 1 ? ((int)t.TotalHours).ToString() + ":" + t.Minutes.ToString("00") + ":" + t.Seconds.ToString("00") : t.Minutes.ToString("00") + ":" + t.Seconds.ToString("00"); }

        public static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("0.#") + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / 1048576.0).ToString("0.#") + " MB";
            return (bytes / 1073741824.0).ToString("0.##") + " GB";
        }

        public static string FormatNumber(long n) { return n.ToString("N0", System.Globalization.CultureInfo.GetCultureInfo("ru-RU")).Replace(' ', ' '); }
    }

}
