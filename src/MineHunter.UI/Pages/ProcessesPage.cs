using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using MineHunter.Guards;
using MineHunter.Model;
using MineHunter.Native;
using MineHunter.Risk;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>All running programs as a tree (who started whom), coloured by how far each one can be trusted, with the actions that make sense for a program: check its file, open its folder,
    /// stop it, freeze it, cut it off from the network.</summary>
    public sealed class ProcessesPage : PageBase
    {
        public override string Key { get { return "processes"; } }
        public override string Title { get { return L("Processes", "Процессы"); } }
        public override string Icon { get { return "procs"; } }

        sealed class Proc { public int Pid, Parent; public string Name, Path, Cmd, User; public long WorkingSet; public double Cpu; public DateTime Started; public string Trust = "?", Publisher; public List<Proc> Kids = new List<Proc>(); public bool Flagged; }

        readonly TreeView tree = new TreeView();
        readonly TextBlock info = Ui.Txt("", 12, Ui.Muted, null, true, new Thickness(0, 10, 0, 0));
        readonly Dictionary<int, TimeSpan> lastCpu = new Dictionary<int, TimeSpan>(); DateTime lastSample;
        readonly Dictionary<string, Tuple<string, string>> trustCache = new Dictionary<string, Tuple<string, string>>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<int> expanded = new HashSet<int>(); readonly HashSet<string> flaggedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly DispatcherTimer timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        readonly TextBox search = new TextBox { Width = 240, Height = 34, Margin = new Thickness(0, 0, 8, 8), VerticalContentAlignment = VerticalAlignment.Center };
        Proc selected; bool loading; readonly Button bCheck, bFolder, bKill, bFreeze, bBlock;
        List<Proc> all = new List<Proc>();

        public ProcessesPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            var legend = Ui.Wrap();
            Action<Brush, string> leg = (c, t) => { var h = Ui.H(Ui.Dot(c, 9), Ui.Txt(t, 11.5, Ui.Muted, null, false, new Thickness(6, 0, 16, 0))); h.Margin = new Thickness(0, 0, 0, 6); legend.Children.Add(h); };
            leg(Ui.Good, L("Microsoft / trusted publisher", "Microsoft / доверенный издатель")); leg(Ui.Accent, L("signed by someone else", "подписан другим издателем")); leg(Ui.Warn, L("not signed", "без подписи")); leg(Ui.Bad, L("flagged by a scan", "отмечен проверкой")); leg(Ui.Muted, L("unknown (no access)", "неизвестно (нет доступа)"));
            bCheck = Ui.Btn(L("Check file", "Проверить файл"), () => { if (selected != null && File.Exists(selected.Path)) m.Navigate("files", selected.Path); }, "Btn");
            bFolder = Ui.Btn(L("Open folder", "Открыть папку"), () => { if (selected != null && File.Exists(selected.Path)) Process.Start("explorer.exe", "/select,\"" + selected.Path + "\""); }, "BtnGhost");
            bFreeze = Ui.Btn(L("Freeze / unfreeze", "Заморозить / отпустить"), ToggleFreeze, "BtnGhost");
            bBlock = Ui.Btn(L("Block network…", "Заблокировать сеть…"), BlockNetwork, "Btn");
            bKill = Ui.Btn(L("End process…", "Завершить процесс…"), Kill, "BtnDanger");
            var refresh = Ui.Btn(L("Refresh", "Обновить"), () => Load(), "BtnGhost");
            search.TextChanged += (s, e) => Build();
            var bar = Ui.Wrap(Ui.Txt(L("Search:", "Поиск:"), 12.5, Ui.Muted, null, false, new Thickness(0, 6, 8, 0)), search, refresh);
            var actions = Ui.Wrap(bCheck, bFolder, bFreeze, bBlock, bKill);
            var top = new StackPanel(); top.Children.Add(Header(L("Processes", "Процессы"), L("Who started whom, and which of them can be trusted.", "Кто кого запустил и кому из них можно доверять."))); top.Children.Add(legend); top.Children.Add(bar);
            var bottom = new StackPanel(); bottom.Children.Add(actions); bottom.Children.Add(info);
            var g = new Grid(); g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); g.RowDefinitions.Add(new RowDefinition()); g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var treeCard = Ui.Card(new DockPanel { LastChildFill = true, Children = { DockTop(HeaderRow()), tree } }, 8);
            ScrollViewer.SetHorizontalScrollBarVisibility(tree, ScrollBarVisibility.Disabled);
            Grid.SetRow(treeCard, 1); Grid.SetRow(bottom, 2); bottom.Margin = new Thickness(0, 10, 0, 0);
            g.Children.Add(top); g.Children.Add(treeCard); g.Children.Add(bottom);
            View = g;
            tree.SelectedItemChanged += (s, e) => { var it = tree.SelectedItem as TreeViewItem; selected = it == null ? null : it.Tag as Proc; ShowInfo(); Buttons(); };
            timer.Tick += (s, e) => { if (View.IsVisible) Load(); };
            Buttons();
        }

        public override void OnShow(object arg)
        {
            flaggedPaths.Clear();
            if (m.LastResult != null) foreach (var f in m.LastResult.Findings) foreach (var e in f.Entities) if (!string.IsNullOrEmpty(e.Location)) flaggedPaths.Add(e.Location);
            Load(); timer.Start();
        }
        public override void OnHide() { timer.Stop(); }

        static UIElement DockTop(UIElement e) { DockPanel.SetDock(e, Dock.Top); return e; }

        void Buttons()
        {
            bool has = selected != null; bool file = has && !string.IsNullOrEmpty(selected.Path) && File.Exists(selected.Path);
            bCheck.IsEnabled = file; bFolder.IsEnabled = file; bFreeze.IsEnabled = has && selected.Pid > 4; bKill.IsEnabled = has && selected.Pid > 4; bBlock.IsEnabled = file;
        }

        // ------------------------------------------------------------------------------------------------ data
        void Load()
        {
            if (loading) return; loading = true;
            Ui.Async(m.UiThread, () => Snapshot(), (list, ex) =>
            {
                loading = false;
                if (ex != null || list == null) { info.Text = ex == null ? "" : ex.Message; return; }
                all = list; Build();
                // trust is looked up in the background for the files not seen yet, then the tree is coloured again
                var missing = list.Where(p => !string.IsNullOrEmpty(p.Path) && !trustCache.ContainsKey(p.Path)).Select(p => p.Path).Distinct(StringComparer.OrdinalIgnoreCase).Take(400).ToList();
                if (missing.Count > 0)
                    Ui.Async(m.UiThread, () => { var d = new Dictionary<string, Tuple<string, string>>(StringComparer.OrdinalIgnoreCase); var rules = Rules.RulePack.Load(); foreach (var p in missing) { try { var ti = Trust.Check(p); string kind = ti == null || ti.State == TrustState.Error ? "?" : ti.State == TrustState.Unsigned ? "unsigned" : ti.IsValid && (rules.IsTrustedPublisher(ti.Publisher) || (ti.Publisher ?? "").StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)) ? "trusted" : ti.IsValid ? "signed" : "unsigned"; d[p] = Tuple.Create(kind, ti == null ? null : ti.Publisher); } catch { d[p] = Tuple.Create("?", (string)null); } } return d; }, (d, ex2) => { if (d != null) foreach (var kv in d) trustCache[kv.Key] = kv.Value; Build(); });
            });
        }

        List<Proc> Snapshot()
        {
            var list = new List<Proc>();
            var details = new Dictionary<int, Tuple<int, string, string>>();
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, ExecutablePath, CommandLine FROM Win32_Process"))
                    foreach (ManagementObject o in s.Get()) details[Convert.ToInt32(o["ProcessId"])] = Tuple.Create(Convert.ToInt32(o["ParentProcessId"]), Convert.ToString(o["ExecutablePath"]), Convert.ToString(o["CommandLine"]));
            }
            catch { }
            var now = DateTime.Now; double dt = lastSample == default(DateTime) ? 0 : (now - lastSample).TotalSeconds;
            var cpuNow = new Dictionary<int, TimeSpan>();
            foreach (var p in Process.GetProcesses())
                using (p)
                {
                    try
                    {
                        var pr = new Proc { Pid = p.Id, Name = p.ProcessName, WorkingSet = p.WorkingSet64 };
                        Tuple<int, string, string> d; if (details.TryGetValue(p.Id, out d)) { pr.Parent = d.Item1; pr.Path = d.Item2; pr.Cmd = d.Item3; }
                        if (string.IsNullOrEmpty(pr.Path)) { try { pr.Path = p.MainModule.FileName; } catch { } }
                        try { pr.Started = p.StartTime; } catch { }
                        try { var t = p.TotalProcessorTime; cpuNow[p.Id] = t; TimeSpan prev; if (dt > 0 && lastCpu.TryGetValue(p.Id, out prev)) pr.Cpu = Math.Max(0, (t - prev).TotalSeconds / dt / Environment.ProcessorCount * 100); } catch { }
                        list.Add(pr);
                    }
                    catch { }
                }
            lastCpu.Clear(); foreach (var kv in cpuNow) lastCpu[kv.Key] = kv.Value; lastSample = now;
            return list;
        }

        // ------------------------------------------------------------------------------------------------ tree
        void Build()
        {
            int selPid = selected == null ? -1 : selected.Pid;
            foreach (var it in Walk(tree.Items)) { var p = it.Tag as Proc; if (p != null && it.IsExpanded) expanded.Add(p.Pid); else if (p != null) expanded.Remove(p.Pid); }
            var byPid = all.ToDictionary(p => p.Pid, p => p);
            foreach (var p in all) { p.Kids.Clear(); Tuple<string, string> tc; if (!string.IsNullOrEmpty(p.Path) && trustCache.TryGetValue(p.Path, out tc)) { p.Trust = tc.Item1; p.Publisher = tc.Item2; } p.Flagged = !string.IsNullOrEmpty(p.Path) && flaggedPaths.Contains(p.Path); }
            string q = (search.Text ?? "").Trim().ToLowerInvariant();
            var roots = new List<Proc>();
            foreach (var p in all) { Proc par; if (p.Parent != 0 && p.Parent != p.Pid && byPid.TryGetValue(p.Parent, out par) && (par.Started == default(DateTime) || p.Started == default(DateTime) || par.Started <= p.Started.AddSeconds(1))) par.Kids.Add(p); else roots.Add(p); }
            Func<Proc, bool> matches = null;
            matches = p => q.Length == 0 || p.Name.ToLowerInvariant().Contains(q) || (p.Path ?? "").ToLowerInvariant().Contains(q) || p.Pid.ToString() == q || p.Kids.Any(matches);
            tree.Items.Clear();
            TreeViewItem restore = null;
            foreach (var r in roots.Where(matches).OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
            {
                var item = MakeItem(r, matches, q.Length > 0, selPid, ref restore);
                tree.Items.Add(item);
            }
            if (restore != null) restore.IsSelected = true;
            info.Text = all.Count + L(" processes", " процессов");
        }

        IEnumerable<TreeViewItem> Walk(ItemCollection items) { foreach (var o in items) { var it = o as TreeViewItem; if (it == null) continue; yield return it; foreach (var c in Walk(it.Items)) yield return c; } }

        TreeViewItem MakeItem(Proc p, Func<Proc, bool> matches, bool forceOpen, int selPid, ref TreeViewItem restore)
        {
            var item = new TreeViewItem { Header = Row(p), Tag = p, IsExpanded = forceOpen || expanded.Contains(p.Pid) };
            if (p.Pid == selPid) restore = item;
            foreach (var k in p.Kids.Where(matches).OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)) item.Items.Add(MakeItem(k, matches, forceOpen, selPid, ref restore));
            return item;
        }

        static readonly GridLength[] Cols = { new GridLength(200), new GridLength(54), new GridLength(46), new GridLength(74), new GridLength(150), new GridLength(1, GridUnitType.Star) };

        UIElement HeaderRow()
        {
            var g = new Grid { Margin = new Thickness(22, 2, 12, 6) };
            string[] h = { L("Program", "Программа"), "PID", "CPU", L("Memory", "Память"), L("Publisher", "Издатель"), L("File", "Файл") };
            for (int i = 0; i < Cols.Length; i++) { g.ColumnDefinitions.Add(new ColumnDefinition { Width = Cols[i] }); var t = Ui.Txt(h[i], 11, Ui.Muted, FontWeights.Bold, false); Grid.SetColumn(t, i); g.Children.Add(t); }
            return g;
        }

        static Brush TrustBrush(Proc p)
        {
            if (p.Flagged) return Ui.Bad;
            switch (p.Trust) { case "trusted": return Ui.Good; case "signed": return Ui.Accent; case "unsigned": return Ui.Warn; default: return Ui.Muted; }
        }

        UIElement Row(Proc p)
        {
            var g = new Grid { Margin = new Thickness(4, 4, 6, 4) };
            for (int i = 0; i < Cols.Length; i++) g.ColumnDefinitions.Add(new ColumnDefinition { Width = Cols[i] });
            var name = Ui.H(Ui.Dot(TrustBrush(p), 9), Ui.Txt(p.Name, 12.5, null, FontWeights.SemiBold, false, new Thickness(8, 0, 0, 0))); name.Width = 190;
            g.Children.Add(name);
            Action<int, UIElement> put = (c, e) => { Grid.SetColumn(e, c); g.Children.Add(e); };
            put(1, Ui.Txt(p.Pid.ToString(), 12, Ui.Muted, null, false)); put(2, Ui.Txt(p.Cpu >= 0.5 ? p.Cpu.ToString("0") + "%" : "", 12, p.Cpu >= 30 ? Ui.Orange : Ui.Muted, null, false));
            put(3, Ui.Txt(Ui.FormatSize(p.WorkingSet), 12, Ui.Muted, null, false)); put(4, Ui.Txt(p.Publisher ?? (p.Trust == "unsigned" ? L("not signed", "без подписи") : ""), 12, Ui.Muted, null, false)); put(5, Ui.Txt(p.Path ?? "", 11.5, Ui.Muted, null, false));
            return g;
        }

        void ShowInfo()
        {
            if (selected == null) { info.Text = all.Count + L(" processes", " процессов"); return; }
            var p = selected; string parent = all.Where(x => x.Pid == p.Parent).Select(x => x.Name + " (" + x.Pid + ")").FirstOrDefault();
            info.Text = p.Name + "  ·  PID " + p.Pid + (parent != null ? L("  ·  started by ", "  ·  запущен: ") + parent : "") + (p.Started != default(DateTime) ? L("  ·  since ", "  ·  с ") + p.Started.ToString("dd.MM HH:mm") : "") + (p.Flagged ? L("  ·  FLAGGED by the last scan", "  ·  ОТМЕЧЕН последней проверкой") : "") + (string.IsNullOrEmpty(p.Cmd) ? "" : "\n" + Text.Trunc(p.Cmd, 400));
        }

        // ------------------------------------------------------------------------------------------------ actions
        void Kill()
        {
            if (selected == null) return;
            var ent = new Entity { Kind = EntityKind.Process, Title = selected.Name + ".exe", Location = selected.Path };
            if (Decision.IsProtectedProcess(ent)) { Info(L("This is a critical Windows process. Ending it can crash the system, so MineHunter will not do it.", "Это критический процесс Windows. Его завершение может обрушить систему, поэтому MineHunter этого не делает.")); return; }
            if (!Ask(L("End the program “" + selected.Name + "” (PID " + selected.Pid + ")? Unsaved work in it is lost.", "Завершить программу «" + selected.Name + "» (PID " + selected.Pid + ")? Несохранённая работа в ней будет потеряна."), L("End process", "Завершить"), true)) return;
            string err = GuardHost.Terminate(selected.Pid); if (err != null) Info(err); Load();
        }

        readonly HashSet<int> frozen = new HashSet<int>();
        void ToggleFreeze()
        {
            if (selected == null) return;
            if (frozen.Contains(selected.Pid)) { GuardHost.Unfreeze(selected.Pid); frozen.Remove(selected.Pid); info.Text = L("Released: ", "Отпущен: ") + selected.Name; }
            else { if (!Ask(L("Freeze (suspend) “" + selected.Name + "”? It stops working until you release it here.", "Заморозить (приостановить) «" + selected.Name + "»? Она перестанет работать, пока вы не отпустите её здесь."), L("Freeze", "Заморозить"))) return; if (GuardHost.Freeze(selected.Pid)) { frozen.Add(selected.Pid); info.Text = L("Frozen: ", "Заморожен: ") + selected.Name; } else Info(L("Could not freeze it.", "Не удалось заморозить.")); }
        }

        void BlockNetwork()
        {
            if (selected == null || !File.Exists(selected.Path)) return;
            if (!Ask(L("Cut “" + Path.GetFileName(selected.Path) + "” off from the network? MineHunter adds two rules to Windows Firewall (outgoing and incoming) for exactly this file. You can remove them on the Network page.", "Отрезать «" + Path.GetFileName(selected.Path) + "» от сети? MineHunter добавит в брандмауэр Windows два правила (исходящее и входящее) именно для этого файла. Убрать их можно на странице «Сеть»."), L("Block", "Заблокировать"))) return;
            string err = FirewallBlock.Block(selected.Path);
            Info(err == null ? L("Blocked. The program can no longer use the network.", "Заблокировано. Программа больше не может пользоваться сетью.") : err);
        }
    }
}
