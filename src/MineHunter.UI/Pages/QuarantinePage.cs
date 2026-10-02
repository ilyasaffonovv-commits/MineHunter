using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Rules;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>What MineHunter removed is kept here, unable to run, with its SHA-256, the reason and the time. Anything can be restored to its place, re-examined or deleted for good.</summary>
    public sealed class QuarantinePage : PageBase
    {
        public override string Key { get { return "quarantine"; } }
        public override string Title { get { return L("Quarantine", "Карантин"); } }
        public override string Icon { get { return "box"; } }
        readonly ListBox list = new ListBox { Style = Ui.S("FlatList"), SelectionMode = SelectionMode.Extended };
        readonly StackPanel detail = new StackPanel { Margin = new Thickness(20) };
        readonly TextBlock empty = Ui.Txt("", 13.5, Ui.Muted, null, true, new Thickness(4, 8, 0, 0));
        readonly Button bRestore, bDelete, bRescan, bDeleteAll;

        public QuarantinePage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            bRestore = Ui.Btn(L("Restore…", "Восстановить…"), Restore, "BtnPrimary");
            bRescan = Ui.Btn(L("Examine again", "Проверить заново"), Rescan, "Btn");
            bDelete = Ui.Btn(L("Delete for good…", "Удалить навсегда…"), () => Delete(false), "Btn");
            bDeleteAll = Ui.Btn(L("Delete all…", "Удалить всё…"), () => Delete(true), "BtnGhost");
            var refresh = Ui.Btn(L("Refresh", "Обновить"), Load, "BtnGhost");
            var top = new StackPanel(); top.Children.Add(Header(L("Quarantine", "Карантин"), L("Removed files and settings wait here, unable to run. Nothing is lost until you delete it for good.", "Удалённые файлы и настройки ждут здесь и не могут работать. Ничего не потеряно, пока вы не удалите это навсегда."))); top.Children.Add(Ui.Wrap(bRestore, bRescan, bDelete, bDeleteAll, refresh));
            var grid = new Grid(); grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(420) }); grid.ColumnDefinitions.Add(new ColumnDefinition());
            var left = new Grid(); left.Children.Add(list); left.Children.Add(empty);
            var right = Ui.Card(new ScrollViewer { Content = detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }, 0); Grid.SetColumn(right, 1);
            grid.Children.Add(left); grid.Children.Add(right);
            View = Frame(top, grid);
            list.SelectionChanged += (s, e) => ShowDetail();
        }

        public override void OnShow(object arg) { Load(); }

        List<QuarantineItem> Selected() { return list.SelectedItems.Cast<ListBoxItem>().Select(i => i.Tag as QuarantineItem).Where(x => x != null).ToList(); }

        void Load()
        {
            var items = Quarantine.List().OrderByDescending(i => i.Created).ToList();
            list.Items.Clear();
            foreach (var it in items)
            {
                DateTime d; string when = DateTime.TryParse(it.Created, out d) ? d.ToString("dd.MM.yyyy HH:mm") : it.Created;
                string title = string.IsNullOrEmpty(it.Title) ? Path.GetFileName(it.OriginalPath ?? "") : it.Title;
                var sp = new StackPanel { Margin = new Thickness(14, 10, 14, 10) };
                sp.Children.Add(Ui.Cols(new[] { "*", "Auto" }, Ui.Txt(title, 13.5, null, FontWeights.SemiBold, false), Ui.Pill(KindText(it.Type), Ui.Accent, 10.5)));
                sp.Children.Add(Ui.Txt(it.OriginalPath ?? "", 11.5, Ui.Muted, null, false, new Thickness(0, 2, 0, 0)));
                sp.Children.Add(Ui.Txt(when + "  ·  " + Loc.Title(it.FindingTitle ?? "") + (it.Size > 0 ? "  ·  " + Ui.FormatSize(it.Size) : ""), 11, Ui.Muted, null, false, new Thickness(0, 4, 0, 0)));
                list.Items.Add(new ListBoxItem { Content = sp, Tag = it });
            }
            empty.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            empty.Text = L("The quarantine is empty. Whatever MineHunter removes is saved here and can be restored.", "Карантин пуст. То, что удалит MineHunter, сохраняется здесь и может быть восстановлено.");
            ShowDetail();
        }

        static string KindText(string t) { switch (t) { case "File": return L("File", "Файл"); case "Task": return L("Task", "Задача"); case "Service": return L("Service", "Служба"); case "StartupItem": return L("Startup item", "Автозагрузка"); case "RunKey": return L("Run entry", "Запись автозапуска"); case "Stream": return L("Hidden stream", "Скрытый поток"); case "Wmi": return "WMI"; default: return t ?? ""; } }

        UIElement Fact(string label, string value, bool mono = false)
        {
            if (string.IsNullOrEmpty(value)) return null;
            var v = mono ? (FrameworkElement)Ui.Mono(value, 12, Ui.TextB, true) : Ui.Txt(value, 13);
            var g = Ui.Cols(new[] { "140", "*" }, Ui.Txt(label, 12.5, Ui.Muted, FontWeights.SemiBold), v); g.Margin = new Thickness(0, 4, 0, 4); return g;
        }

        void ShowDetail()
        {
            var sel = Selected(); detail.Children.Clear();
            bRestore.IsEnabled = sel.Count > 0 && sel.All(s => s.Restorable); bRescan.IsEnabled = sel.Count == 1 && sel[0].Type == "File"; bDelete.IsEnabled = sel.Count > 0; bDeleteAll.IsEnabled = list.Items.Count > 0;
            if (sel.Count != 1) { detail.Children.Add(Ui.Txt(sel.Count == 0 ? L("Select an item to see its details.", "Выберите объект, чтобы увидеть подробности.") : sel.Count + L(" items selected.", " объектов выбрано."), 13.5, Ui.Muted)); return; }
            var it = sel[0]; DateTime d; string when = DateTime.TryParse(it.Created, out d) ? d.ToString("dd.MM.yyyy HH:mm:ss") : it.Created;
            detail.Children.Add(Ui.Txt(string.IsNullOrEmpty(it.Title) ? Path.GetFileName(it.OriginalPath ?? "") : it.Title, 20, null, FontWeights.Bold));
            detail.Children.Add(Ui.Pill(KindText(it.Type), Ui.Accent));
            detail.Children.Add(Ui.Gap(10));
            detail.Children.Add(Fact(L("Why it is here", "Почему здесь"), Loc.Title(it.FindingTitle ?? "")));
            detail.Children.Add(Fact(L("Reason", "Причина"), it.Reason));
            detail.Children.Add(Fact(L("Original place", "Прежнее место"), it.OriginalPath, true));
            detail.Children.Add(Fact(L("Quarantined", "В карантине с"), when));
            detail.Children.Add(Fact("SHA-256", it.Sha256, true));
            detail.Children.Add(Fact(L("Size", "Размер"), it.Size > 0 ? Ui.FormatSize(it.Size) : null));
            detail.Children.Add(Fact(L("Found by", "Найдено"), "MineHunter " + AppInfo(), false));
            detail.Children.Add(Fact(L("Can be restored", "Можно восстановить"), it.Restorable ? L("yes", "да") : L("no: " + (it.RestoreNote ?? ""), "нет: " + (it.RestoreNote ?? ""))));
            detail.Children.Add(Ui.Txt(L("The stored copy is scrambled with its own key, so it cannot run and is not flagged again. Its SHA-256 is checked when it is restored.", "Сохранённая копия перемешана собственным ключом, поэтому она не может запуститься и не отмечается повторно. При восстановлении проверяется её SHA-256."), 11.5, Ui.Muted, null, true, new Thickness(0, 12, 0, 0)));
        }

        static string AppInfo() { return Scanning.AppInfo.Version; }

        void Restore()
        {
            var sel = Selected(); if (sel.Count == 0) return;
            bool dangerous = sel.Any(s => (s.FindingTitle ?? "").StartsWith("Known malware") || (s.FindingTitle ?? "").StartsWith("Cryptominer") || (s.FindingTitle ?? "").StartsWith("Hijacked") || (s.FindingTitle ?? "").StartsWith("Fake system"));
            string msg = L("Restore " + sel.Count + " item(s) to their original places?", "Восстановить объектов: " + sel.Count + " — на их прежние места?")
                + (dangerous ? L("\n\nWARNING: at least one of them was removed as DANGEROUS (a miner or malware). If you restore it, it becomes active again.", "\n\nВНИМАНИЕ: как минимум один из них был удалён как ОПАСНЫЙ (майнер или вредоносная программа). Если вы его восстановите, он снова станет активным.") : L("\n\nIf an item is malicious, it will become active again.", "\n\nЕсли объект вредоносный, он снова станет активным."));
            if (!Ask(msg, L("Restore", "Восстановить"), dangerous)) return;
            var errors = new List<string>();
            foreach (var q in sel) { string err = RemediationEngine.Restore(q); if (err == null) { Quarantine.Delete(q); Log.Info("Restored " + q.OriginalPath); } else errors.Add((q.Title ?? q.Id) + ": " + err); }
            Load();
            if (errors.Count > 0) Info(L("Some items were not restored:\n", "Часть объектов не восстановлена:\n") + string.Join("\n", errors));
        }

        void Delete(bool all)
        {
            var items = all ? list.Items.Cast<ListBoxItem>().Select(i => i.Tag as QuarantineItem).Where(x => x != null).ToList() : Selected(); if (items.Count == 0) return;
            if (!Ask(L("Delete " + items.Count + " item(s) from the quarantine FOREVER? They cannot be restored afterwards.", "Удалить объектов: " + items.Count + " — из карантина НАВСЕГДА? Потом их нельзя будет восстановить."), L("Delete for good", "Удалить навсегда"), true)) return;
            foreach (var q in items) { try { Quarantine.Delete(q); } catch (Exception ex) { Log.Warn("delete " + q.Id + ": " + ex.Message); } }
            Load();
        }

        void Rescan()
        {
            var sel = Selected(); if (sel.Count != 1) return; var q = sel[0];
            Ui.Async(m.UiThread, () =>
            {
                byte[] data = Quarantine.ReadPayload(q); if (data == null) return null;
                string dir = Path.Combine(RulePack.DataDir, "rescan-" + Guid.NewGuid().ToString("N").Substring(0, 8)); Directory.CreateDirectory(dir);
                string tmp = Path.Combine(dir, Path.GetFileName(q.OriginalPath ?? "item.bin"));
                try { File.WriteAllBytes(tmp, data); return FileAnalyzer.Analyze(tmp, m.S, false); }
                finally { try { Directory.Delete(dir, true); } catch { } }
            }, (r, ex) =>
            {
                if (ex != null || r == null) { Info(L("The stored copy could not be examined: ", "Сохранённую копию не удалось проверить: ") + (ex == null ? "" : ex.Message)); return; }
                Info(L("Verdict now: ", "Вердикт сейчас: ") + r.VerdictText + "\n\n" + r.Explanation + "\n\n" + string.Join("\n", r.Evidence.Where(e => e.Weight > 0).Take(8).Select(e => "+" + e.Weight + "  " + Loc.Ev(e))));
            });
        }
    }
}
