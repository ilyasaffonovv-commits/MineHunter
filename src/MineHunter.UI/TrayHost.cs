using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using MineHunter.Guards;
using MineHunter.Scanning;
using MineHunter.Util;
using SD = System.Drawing;

namespace MineHunter.Gui
{
    /// <summary>The notification-area icon: quick actions, the recent findings, and balloon notes for things that do not need a pop-up window.</summary>
    public sealed class TrayHost : IDisposable
    {
        readonly NotifyIcon ni; readonly AppModel m; readonly Action showMain;
        readonly ContextMenuStrip menu = new ContextMenuStrip();
        static string L(string en, string ru) { return Loc.L(en, ru); }

        sealed class DarkColors : ProfessionalColorTable
        {
            public override SD.Color MenuItemSelected { get { return SD.Color.FromArgb(0x23, 0x2C, 0x48); } }
            public override SD.Color MenuItemBorder { get { return SD.Color.FromArgb(0x4C, 0x8D, 0xFF); } }
            public override SD.Color MenuBorder { get { return SD.Color.FromArgb(0x2A, 0x34, 0x54); } }
            public override SD.Color ToolStripDropDownBackground { get { return SD.Color.FromArgb(0x14, 0x1A, 0x2C); } }
            public override SD.Color ImageMarginGradientBegin { get { return SD.Color.FromArgb(0x14, 0x1A, 0x2C); } }
            public override SD.Color ImageMarginGradientMiddle { get { return SD.Color.FromArgb(0x14, 0x1A, 0x2C); } }
            public override SD.Color ImageMarginGradientEnd { get { return SD.Color.FromArgb(0x14, 0x1A, 0x2C); } }
            public override SD.Color SeparatorDark { get { return SD.Color.FromArgb(0x2A, 0x34, 0x54); } }
            public override SD.Color SeparatorLight { get { return SD.Color.FromArgb(0x2A, 0x34, 0x54); } }
            public override SD.Color MenuItemPressedGradientBegin { get { return SD.Color.FromArgb(0x23, 0x2C, 0x48); } }
            public override SD.Color MenuItemPressedGradientEnd { get { return SD.Color.FromArgb(0x23, 0x2C, 0x48); } }
            public override SD.Color MenuItemSelectedGradientBegin { get { return SD.Color.FromArgb(0x23, 0x2C, 0x48); } }
            public override SD.Color MenuItemSelectedGradientEnd { get { return SD.Color.FromArgb(0x23, 0x2C, 0x48); } }
        }

        public TrayHost(AppModel model, Action showMainWindow)
        {
            m = model; showMain = showMainWindow;
            ni = new NotifyIcon { Icon = Branding.TrayIcon(0), Text = "MineHunter", Visible = true, ContextMenuStrip = menu };
            menu.Renderer = new ToolStripProfessionalRenderer(new DarkColors()); menu.ForeColor = SD.Color.FromArgb(0xE8, 0xEC, 0xF7); menu.BackColor = SD.Color.FromArgb(0x14, 0x1A, 0x2C); menu.ShowImageMargin = false;
            menu.Font = new SD.Font("Segoe UI", 9.5f);
            menu.Opening += (s, e) => Rebuild();
            ni.DoubleClick += (s, e) => showMain();
            m.StateChanged += UpdateIcon;
            Rebuild();
        }

        void Add(string text, Action click) { var it = new ToolStripMenuItem(text); it.Click += (s, e) => { try { click(); } catch (Exception ex) { Log.Warn("tray: " + ex.Message); } }; menu.Items.Add(it); }

        void Rebuild()
        {
            menu.Items.Clear();
            Add(L("Open MineHunter", "Открыть MineHunter"), showMain);
            menu.Items.Add(new ToolStripSeparator());
            Add(L("Quick scan", "Быстрая проверка"), () => { m.StartScan(ScanMode.Quick, "tray"); m.Navigate("scan", "running"); });
            Add(L("Full scan", "Полная проверка"), () => { m.StartScan(ScanMode.Full, "tray"); m.Navigate("scan", "running"); });
            Add(L("Check a file…", "Проверить файл…"), () =>
            {
                using (var dlg = new OpenFileDialog { Title = L("Choose a file to check", "Выберите файл для проверки"), CheckFileExists = true })
                    if (dlg.ShowDialog() == DialogResult.OK) m.Navigate("files", dlg.FileName);
            });
            menu.Items.Add(new ToolStripSeparator());
            var recent = new ToolStripMenuItem(L("Recent findings", "Последние находки"));
            var alerts = m.Guards == null ? new List<GuardAlert>() : m.Guards.Recent.Where(a => a.Level >= AlertLevel.Suspicious).Take(5).ToList();
            if (alerts.Count == 0) recent.DropDownItems.Add(new ToolStripMenuItem(L("Nothing new", "Ничего нового")) { Enabled = false });
            foreach (var a in alerts) { var al = a; var it = new ToolStripMenuItem(al.Time.ToString("HH:mm") + "  " + Text.Trunc(al.Title, 44)); it.Click += (s, e) => m.Navigate("protection", null); recent.DropDownItems.Add(it); }
            recent.DropDown.Renderer = menu.Renderer; recent.DropDown.BackColor = menu.BackColor; recent.DropDown.ForeColor = menu.ForeColor;
            menu.Items.Add(recent);
            Add(L("Check for updates", "Проверить обновления"), () => { m.CheckUpdates(true, () => Balloon("MineHunter", m.AppUpdate != null && m.AppUpdate.State == Update.AppUpdateState.Ready ? L("A new version is ready to install.", "Новая версия готова к установке.") : L("You have the latest version.", "У вас последняя версия."))); });
            menu.Items.Add(new ToolStripSeparator());
            Add(L("Exit", "Выход"), () => System.Windows.Application.Current.Shutdown());
        }

        public void Balloon(string title, string text, ToolTipIcon icon = ToolTipIcon.Info)
        {
            try { ni.BalloonTipTitle = title; ni.BalloonTipText = text; ni.BalloonTipIcon = icon; ni.ShowBalloonTip(8000); } catch { }
        }

        public void ClickedBalloon(Action a) { ni.BalloonTipClicked += (s, e) => a(); }

        int shown = -1;
        void UpdateIcon()
        {
            try
            {
                int state = 0;
                if (m.LastResult != null && m.LastResult.Findings.Any(f => f.Verdict >= Model.Verdict.HighRisk)) state = 2;
                else if (m.LastResult != null && m.LastResult.Findings.Count > 0) state = 1;
                else if (m.Guards != null && m.Guards.Recent.Any(a => a.Level == AlertLevel.Dangerous && (DateTime.Now - a.Time).TotalHours < 12)) state = 2;
                if (state == shown) return;
                shown = state; var old = ni.Icon; ni.Icon = Branding.TrayIcon(state);
                ni.Text = state == 2 ? L("MineHunter: dangerous items found", "MineHunter: найдены опасные объекты") : state == 1 ? L("MineHunter: something needs a look", "MineHunter: есть что проверить") : "MineHunter";
                if (old != null) old.Dispose();
            }
            catch { }
        }

        public void Dispose() { try { ni.Visible = false; ni.Dispose(); menu.Dispose(); } catch { } }
    }
}
