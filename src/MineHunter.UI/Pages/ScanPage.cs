using System;
using System.Collections.Generic;
using System.Windows;
using MineHunter.Scanning;

namespace MineHunter.Gui
{
    public sealed class ScanPage : PageBase
    {
        public override string Key { get { return "scan"; } }
        public override string Title { get { return L("Scan", "Проверка"); } }
        public override string Icon { get { return "scan"; } }
        readonly ScanPanel panel;

        public ScanPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            panel = new ScanPanel(m, owner, false);
            View = panel.Root;
        }

        public ScanPanel Panel { get { return panel; } }

        public override void OnShow(object arg)
        {
            string a = arg as string;
            var folders = arg as string[];
            if (folders != null) { panel.Start(ScanMode.Custom, folders, "manual"); return; }
            if (a == "choose") { panel.ShowIdle(); return; }
            if (a == "idle") { panel.ShowIdle(); return; }
            panel.ShowCurrent();
        }
    }
}
