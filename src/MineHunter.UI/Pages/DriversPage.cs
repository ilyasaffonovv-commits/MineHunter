using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>A technical driver page, not a driver booster: what is installed (device, maker, Hardware ID, version, date, provider, signature, state) and what Windows Update - Microsoft's own,
    /// signed channel - offers for exactly these devices. BIOS and firmware are never touched; storage and chipset drivers need an explicit confirmation; before an install there is a restore point
    /// and a saved copy of the old driver, and the old driver can be put back.</summary>
    public sealed class DriversPage : PageBase
    {
        public override string Key { get { return "drivers"; } }
        public override string Title { get { return L("Drivers", "Драйверы"); } }
        public override string Icon { get { return "chip"; } }
        readonly StackPanel list = new StackPanel(); readonly StackPanel updates = new StackPanel(); readonly StackPanel backups = new StackPanel();
        readonly TextBlock status = Ui.Txt("", 12.5, Ui.Muted, null, true, new Thickness(0, 6, 0, 0)); readonly TextBox search = new TextBox { Width = 240, Height = 34, Margin = new Thickness(8, 0, 8, 8), VerticalContentAlignment = VerticalAlignment.Center };
        readonly StackPanel chips = new StackPanel { Orientation = Orientation.Horizontal };
        List<DriverInfo> inventory = new List<DriverInfo>(); List<DriverUpdate> found; string category = "*"; bool onlyInteresting = true, loading, searching;
        Button bSearch; CancellationTokenSource cts;

        public DriversPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            bSearch = Ui.Btn(L("Check for driver updates", "Проверить обновления драйверов"), SearchUpdates, "BtnPrimary");
            var note = Ui.Card(Ui.Txt(L("Updates are looked for only through Windows Update (Microsoft's signed channel) for the devices listed here. For graphics cards the vendor's own site is usually newer: MineHunter only opens the official page (NVIDIA, AMD, Intel, the PC maker) and downloads nothing from it. BIOS and firmware are never touched. Before an install MineHunter checks the Hardware ID and the source, makes a restore point and saves the old driver, so it can be put back.", "Обновления ищутся только через Windows Update (подписанный канал Microsoft) для перечисленных здесь устройств. Для видеокарт сайт производителя обычно свежее: MineHunter лишь открывает официальную страницу (NVIDIA, AMD, Intel, производитель ПК) и ничего с неё не скачивает. BIOS и прошивки не трогаются никогда. Перед установкой MineHunter сверяет Hardware ID и источник, делает точку восстановления и сохраняет старый драйвер, чтобы его можно было вернуть."), 12, Ui.Muted), 14, Ui.B("Surface2"));
            note.Margin = new Thickness(0, 0, 0, 12);
            search.TextChanged += (s, e) => Render();
            var onlyBox = Ui.Chk(L("Only drivers that are not Microsoft's own, unsigned or with a problem", "Только не встроенные драйверы Microsoft, без подписи или с проблемой"), true, v => { onlyInteresting = v; Render(); });
            var top = new StackPanel(); top.Children.Add(Header(L("Drivers", "Драйверы"), L("What is installed, and what Windows Update offers for it.", "Что установлено и что для этого предлагает Windows Update."))); top.Children.Add(note);
            top.Children.Add(Ui.Wrap(bSearch, Ui.Btn(L("Refresh the list", "Обновить список"), () => Load(), "BtnGhost"))); top.Children.Add(status);
            var body = new StackPanel();
            body.Children.Add(updates);
            var filterRow = Ui.Wrap(); filterRow.Margin = new Thickness(0, 12, 0, 6); filterRow.Children.Add(Ui.Txt(L("Search:", "Поиск:"), 12.5, Ui.Muted, null, false, new Thickness(0, 6, 0, 0))); filterRow.Children.Add(search); filterRow.Children.Add(onlyBox);
            body.Children.Add(filterRow); body.Children.Add(chips); chips.Margin = new Thickness(0, 0, 0, 10);
            body.Children.Add(list);
            body.Children.Add(Ui.Head(L("Saved copies of old drivers (for roll-back)", "Сохранённые копии старых драйверов (для отката)"))); body.Children.Add(backups);
            View = Frame(top, Ui.Scroll(body));
        }

        public override void OnShow(object arg) { if (inventory.Count == 0) Load(); RenderBackups(); }

        void Load()
        {
            if (loading) return; loading = true; status.Text = L("Reading the installed drivers…", "Читаю установленные драйверы…");
            Ui.Async(m.UiThread, () => Drivers.Inventory(), (r, ex) => { loading = false; if (ex != null) { status.Text = ex.Message; return; } inventory = r; status.Text = r.Count + L(" devices with drivers.", " устройств с драйверами."); Render(); });
        }

        void Render()
        {
            // category chips
            chips.Children.Clear();
            var cats = inventory.Select(d => d.Category).Distinct().ToList();
            Action<string, string, int> chip = (key, text, n) => { var b = Ui.Btn(text + "  " + n, () => { category = key; Render(); }, category == key ? "BtnPrimary" : "Btn"); b.Padding = new Thickness(11, 4, 11, 4); b.Margin = new Thickness(0, 0, 6, 0); chips.Children.Add(b); };
            chip("*", L("All", "Все"), inventory.Count);
            foreach (var c in cats) chip(c, c, inventory.Count(d => d.Category == c));
            list.Children.Clear();
            string s = (search.Text ?? "").Trim().ToLowerInvariant();
            var q = inventory.Where(d => category == "*" || d.Category == category);
            if (onlyInteresting) q = q.Where(Drivers.IsInteresting);
            if (s.Length > 0) q = q.Where(d => (d.Name ?? "").ToLowerInvariant().Contains(s) || (d.Provider ?? "").ToLowerInvariant().Contains(s) || (d.HardwareId ?? "").ToLowerInvariant().Contains(s) || (d.Manufacturer ?? "").ToLowerInvariant().Contains(s));
            foreach (var d in q.Take(300)) list.Children.Add(Row(d));
            if (!q.Any()) list.Children.Add(Ui.Txt(L("Nothing matches.", "Ничего не найдено."), 13, Ui.Muted));
        }

        UIElement Row(DriverInfo d)
        {
            Brush c = d.Problem != null ? Ui.Bad : !d.Signed ? Ui.Warn : Ui.Good;
            var mid = new StackPanel { Margin = new Thickness(12, 0, 12, 0) };
            mid.Children.Add(Ui.Txt(d.Name, 13.5, null, FontWeights.SemiBold, false));
            mid.Children.Add(Ui.Txt((d.Manufacturer ?? "") + (string.IsNullOrEmpty(d.Provider) || d.Provider == d.Manufacturer ? "" : "  ·  " + d.Provider), 11.5, Ui.Muted, null, false));
            mid.Children.Add(Ui.Mono(Text.Trunc(d.HardwareId ?? "", 90), 11, Ui.Muted, false));
            string age = d.AgeDays >= 0 ? (d.AgeDays > 730 ? (d.AgeDays / 365) + L(" y old", " лет назад") : d.Date.Value.ToString("dd.MM.yyyy")) : "";
            var right = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
            right.Children.Add(Ui.Txt(d.Version ?? "", 12.5, Ui.TextB, FontWeights.SemiBold, false)); right.Children.Add(Ui.Txt(age, 11.5, Ui.Muted, null, false));
            right.Children.Add(Ui.Txt(d.Problem ?? (d.Signed ? L("signed", "подписан") + (string.IsNullOrEmpty(d.Signer) ? "" : ": " + Text.Trunc(d.Signer, 28)) : L("NOT signed", "НЕ подписан")), 11, c, FontWeights.SemiBold, false));
            var btns = Ui.H();
            string vendor = Drivers.VendorPage(d);
            if (vendor != null) { var vb = Ui.Btn(L("Official page", "Официальная страница"), () => AppModel.Open(vendor), "BtnSmall"); vb.Margin = new Thickness(10, 0, 0, 0); btns.Children.Add(vb); }
            var save = Ui.Btn(L("Save a copy", "Сохранить копию"), () => SaveCopy(d), "BtnGhost"); save.Padding = new Thickness(10, 5, 10, 5); save.FontSize = 11.5; save.Margin = new Thickness(6, 0, 0, 0); btns.Children.Add(save);
            var card = Ui.Card(Ui.Cols(new[] { "Auto", "*", "Auto", "Auto" }, Ui.Dot(c, 10), mid, right, btns), 12); card.Margin = new Thickness(0, 0, 0, 6); return card;
        }

        void SaveCopy(DriverInfo d)
        {
            Ui.Async(m.UiThread, () => Drivers.Backup(d, null), (dir, ex) => Info(ex == null ? L("Saved: ", "Сохранено: ") + dir : ex.Message));
        }

        // ------------------------------------------------------------------------------------------------ updates
        void SearchUpdates()
        {
            if (searching) { if (cts != null) cts.Cancel(); return; }
            searching = true; cts = new CancellationTokenSource(); var token = cts.Token; bSearch.Content = L("Cancel the search", "Отменить поиск");
            status.Text = L("Asking Windows Update… this can take a minute.", "Спрашиваю Windows Update… это может занять минуту.");
            Ui.Async(m.UiThread, () => Drivers.SearchUpdates(token), (r, ex) =>
            {
                searching = false; bSearch.Content = L("Check for driver updates", "Проверить обновления драйверов");
                if (ex != null) { bool cancelled = ex is OperationCanceledException || ex.GetBaseException() is OperationCanceledException; status.Text = cancelled ? L("Cancelled.", "Отменено.") : L("Could not ask Windows Update: ", "Не удалось спросить Windows Update: ") + ex.GetBaseException().Message + L("  Automatic checking is not available right now.", "  Автоматическая проверка сейчас недоступна."); return; }
                found = r; status.Text = r.Count == 0 ? L("Windows Update offers no new drivers for this PC.", "Windows Update не предлагает новых драйверов для этого ПК.") : r.Count + L(" driver update(s) offered by Windows Update.", " обновлений драйверов предлагает Windows Update.");
                RenderUpdates();
            });
        }

        void RenderUpdates()
        {
            updates.Children.Clear();
            if (found == null) return;
            if (found.Count == 0) { updates.Children.Add(Ui.Card(Ui.Txt(L("Nothing to update through Windows Update. This does not mean the drivers are the newest: for graphics cards check the official page (button “Official page” in the list).", "Через Windows Update обновлять нечего. Это не значит, что драйверы самые новые: для видеокарт загляните на официальную страницу (кнопка «Официальная страница» в списке)."), 12.5, Ui.Muted), 14)); return; }
            updates.Children.Add(Ui.Head(L("Offered by Windows Update", "Предлагает Windows Update"), new Thickness(0, 8, 0, 8)));
            foreach (var u in found)
            {
                var upd = u; Brush rc = u.Risk == DriverRisk.Never ? Ui.Bad : u.Risk == DriverRisk.NeedsConfirmation ? Ui.Orange : Ui.Good;
                var mid = new StackPanel { Margin = new Thickness(12, 0, 12, 0) };
                mid.Children.Add(Ui.Txt(u.Title, 13.5, null, FontWeights.SemiBold));
                string cur = u.Installed == null ? L("no matching installed device", "подходящее установленное устройство не найдено") : u.Installed.Name + ": " + u.Installed.Version + (u.Installed.Date.HasValue ? " (" + u.Installed.Date.Value.ToString("dd.MM.yyyy") + ")" : "") + "  →  " + (u.Version ?? "?") + (u.Date.HasValue ? " (" + u.Date.Value.ToString("dd.MM.yyyy") + ")" : "");
                mid.Children.Add(Ui.Txt(cur, 12, Ui.TextB, null, true, new Thickness(0, 2, 0, 0)));
                mid.Children.Add(Ui.Txt(L("Source: Windows Update (Microsoft)", "Источник: Windows Update (Microsoft)") + (u.SizeBytes > 0 ? "  ·  " + Ui.FormatSize(u.SizeBytes) : "") + (u.Date.HasValue ? "  ·  " + u.Date.Value.ToString("dd.MM.yyyy") : ""), 11.5, Ui.Muted, null, true, new Thickness(0, 2, 0, 0)));
                if (!string.IsNullOrEmpty(u.Reason)) mid.Children.Add(Ui.Txt(u.Reason, 11.5, rc, null, true, new Thickness(0, 4, 0, 0)));
                var b = Ui.Btn(u.Risk == DriverRisk.Never ? L("Not automated", "Не автоматизируется") : L("Download and install…", "Скачать и установить…"), () => Install(upd), u.Risk == DriverRisk.Never ? "BtnGhost" : "BtnPrimary"); b.IsEnabled = u.Risk != DriverRisk.Never && u.Installed != null; b.VerticalAlignment = VerticalAlignment.Center;
                var card = Ui.Card(Ui.Cols(new[] { "Auto", "*", "Auto" }, Ui.Badge("download", rc, 38), mid, b), 14); card.Margin = new Thickness(0, 0, 0, 8); updates.Children.Add(card);
            }
        }

        void Install(DriverUpdate u)
        {
            var installed = inventory;
            string bad = Drivers.CheckInstallable(u, installed);
            if (bad != null) { Info(bad); return; }
            string msg = L("Install “" + u.Title + "”?\n\nBefore installing, MineHunter will:\n  1. check that its Hardware ID matches your device (" + u.Installed.Name + ")\n  2. create a Windows restore point\n  3. save the current driver so it can be put back\n  4. install it through Windows Update (Microsoft's signed channel)\n\nA restart may be needed afterwards.", "Установить «" + u.Title + "»?\n\nПеред установкой MineHunter:\n  1. сверит Hardware ID с вашим устройством (" + u.Installed.Name + ")\n  2. создаст точку восстановления Windows\n  3. сохранит текущий драйвер, чтобы его можно было вернуть\n  4. установит через Windows Update (подписанный канал Microsoft)\n\nПосле этого может понадобиться перезагрузка.");
            if (!Ask(msg, L("Install", "Установить"))) return;
            bool confirmed = false;
            if (u.Risk == DriverRisk.NeedsConfirmation)
            {
                if (!Ask(L("This driver controls storage or the chipset. A bad one can stop Windows from starting. Continue only if you have a backup of your data.\n\nInstall it anyway?", "Этот драйвер управляет накопителями или чипсетом. Неудачный может помешать запуску Windows. Продолжайте, только если у вас есть резервная копия данных.\n\nВсё равно установить?"), L("Yes, install", "Да, установить"), true)) return;
                confirmed = true;
            }
            status.Text = L("Installing… do not turn the PC off.", "Устанавливаю… не выключайте ПК.");
            var log = new List<string>();
            Ui.Async(m.UiThread, () => Drivers.Install(u, confirmed, s => log.Add(s), null, null, installed), (err, ex) =>
            {
                string e = ex != null ? ex.Message : err;
                status.Text = e == null ? L("Installed. If Windows asks, restart the PC.", "Установлено. Если Windows попросит, перезагрузите ПК.") : L("Not installed: ", "Не установлено: ") + e;
                Info(e == null ? L("The driver was installed. The previous one is saved; you can put it back under “Saved copies”.\n\n", "Драйвер установлен. Предыдущий сохранён; вернуть его можно в разделе «Сохранённые копии».\n\n") + string.Join("\n", log) : L("The driver was NOT installed:\n", "Драйвер НЕ установлен:\n") + e);
                RenderBackups(); Load();
            });
        }

        void RenderBackups()
        {
            backups.Children.Clear();
            var l = Drivers.Backups();
            if (l.Count == 0) { backups.Children.Add(Ui.Txt(L("None yet.", "Пока нет."), 12.5, Ui.Muted)); return; }
            foreach (var dir in l.Take(12))
            {
                string d = dir; string name = Path.GetFileName(d); bool hasPkg = Directory.Exists(Path.Combine(d, "package"));
                var row = Ui.Cols(new[] { "*", "Auto" }, Ui.Txt(name + (hasPkg ? "" : L("   (the old driver was a Windows built-in one: use Device Manager > Roll Back Driver)", "   (старый драйвер был встроенным в Windows: используйте Диспетчер устройств > Откатить драйвер)")), 12.5, Ui.TextB, null, true), hasPkg ? Ui.Btn(L("Put this driver back…", "Вернуть этот драйвер…"), () => Rollback(d), "BtnSmall") : null);
                row.Margin = new Thickness(0, 4, 0, 4); backups.Children.Add(row);
            }
        }

        void Rollback(string dir)
        {
            if (!Ask(L("Put the saved driver back? Windows will install the old package over the current one.", "Вернуть сохранённый драйвер? Windows установит старый пакет поверх текущего."), L("Put back", "Вернуть"))) return;
            Ui.Async(m.UiThread, () => Drivers.Rollback(dir), (err, ex) => Info((ex != null ? ex.Message : err) ?? L("Done.", "Готово.")));
        }
    }
}
