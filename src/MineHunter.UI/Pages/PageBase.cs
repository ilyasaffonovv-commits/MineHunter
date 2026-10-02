using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using MineHunter.Util;

namespace MineHunter.Gui
{
    public abstract class PageBase : IPage
    {
        protected readonly AppModel m;
        protected readonly Func<Window> owner;
        public abstract string Key { get; }
        public abstract string Title { get; }
        public abstract string Icon { get; }
        public FrameworkElement View { get; protected set; }
        public virtual void OnShow(object arg) { }
        /// <summary>Called when the page is left (stop timers).</summary>
        public virtual void OnHide() { }

        protected PageBase(AppModel model, Func<Window> ownerFn) { m = model; owner = ownerFn; }

        protected static string L(string en, string ru) { return Loc.L(en, ru); }

        protected static StackPanel Header(string title, string subtitle)
        {
            var sp = new StackPanel { Margin = new Thickness(0, 0, 0, 16) };
            sp.Children.Add(Ui.Title(title));
            if (!string.IsNullOrEmpty(subtitle)) sp.Children.Add(Ui.Txt(subtitle, 13, Ui.Muted, null, true, new Thickness(0, 2, 0, 0)));
            return sp;
        }

        /// <summary>The page layout used by most pages: a header on top and the body filling the rest.</summary>
        protected static Grid Frame(UIElement header, UIElement body)
        {
            var g = new Grid(); g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); g.RowDefinitions.Add(new RowDefinition());
            Grid.SetRow(header, 0); Grid.SetRow(body, 1); g.Children.Add(header); g.Children.Add(body); return g;
        }

        protected void Info(string text) { Dlg.Info(owner(), "MineHunter", text); }
        protected bool Ask(string text, string yes = null, bool danger = false) { return Dlg.Ask(owner(), "MineHunter", text, yes, L("Cancel", "Отмена"), danger); }
    }
}
