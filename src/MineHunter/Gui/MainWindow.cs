using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using MineHunter.Model;
using MineHunter.Remediation;
using MineHunter.Report;
using MineHunter.Risk;
using MineHunter.Rules;
using MineHunter.Scanning;
using MineHunter.Update;
using MineHunter.Util;

namespace MineHunter.Gui
{
    // ---- small view models (public properties so that WPF bindings work) -------------------------------------
    public sealed class ResultItem
    {
        public Finding F; public Entity Note;
        public string Title { get; set; } public string Sub { get; set; } public string VerdictText { get; set; } public string ScoreText { get; set; }
        public Brush Accent { get; set; } public Brush AccentSoft { get; set; }
    }
    public sealed class StepItem
    {
        public RemediationStep Step; public string Text { get; set; } public bool Selected { get; set; } public bool Enabled { get; set; }
    }
    public sealed class QItem
    {
        public QuarantineItem It; public string Title { get; set; } public string Sub { get; set; } public string Meta { get; set; } public string Kind { get; set; }
    }
    sealed class CleanupRow { public Finding F; public FindingOutcome Outcome; }

    sealed class AppState
    {
        public string LastScan, LastMode, Protection; public int Malware, High, Susp, Notes; public List<string> Warnings = new List<string>();
        static string PathFile { get { return Path.Combine(RulePack.DataDir, "state.json"); } }
        public static AppState Load()
        {
            var s = new AppState();
            try
            {
                if (!File.Exists(PathFile)) return s;
                var d = Json.Obj(Json.Parse(File.ReadAllText(PathFile)));
                s.LastScan = Json.Str(d, "lastScan"); s.LastMode = Json.Str(d, "lastMode"); s.Protection = Json.Str(d, "protection");
                s.Malware = Json.Int(d, "malware"); s.High = Json.Int(d, "high"); s.Susp = Json.Int(d, "susp"); s.Notes = Json.Int(d, "notes");
                s.Warnings = Json.Strs(d, "warnings").ToList();
            }
            catch { }
            return s;
        }
        public void Save()
        {
            try
            {
                Directory.CreateDirectory(RulePack.DataDir);
                File.WriteAllText(PathFile, Json.Pretty(Json.Serialize(new Dictionary<string, object>
                { { "lastScan", LastScan }, { "lastMode", LastMode }, { "protection", Protection }, { "malware", Malware }, { "high", High }, { "susp", Susp }, { "notes", Notes }, { "warnings", Warnings.ToArray() } })));
            }
            catch { }
        }
    }

    /// <summary>The main window. The layout lives in MainWindow.xaml (loaded at run time); this class holds the behaviour.</summary>
    public sealed class MainWindow
    {
        enum Mode { Idle, Scanning, Cleaning }

        public readonly Window W;
        readonly AppConfig _cfg;
        readonly AppState _state;
        Mode _mode = Mode.Idle;
        CancellationTokenSource _cts;
        ScanResult _res; ScanOptions _lastOpt;
        UpdateInfo _upd;
        string _lastReportTxt;
        List<CleanupRow> _cleanup;
        List<StepItem> _stepItems = new List<StepItem>();
        bool _autoScanPending = true;
        double _progMax;

        // test hooks (undocumented flags)
        string _shot, _shotsDir, _autoNeutralize, _shotFilter; string _shotTab; int _shotSelect = -1; bool _shotNotes; bool _noScan; bool _shotDone;

        static string L(string en, string ru) { return Loc.L(en, ru); }
        T Q<T>(string name) where T : class { return W.FindName(name) as T; }
        Brush Res(string key) { return (Brush)W.FindResource(key); }
        void Ui(Action a) { W.Dispatcher.BeginInvoke(a); }

        // named elements
        TextBlock PostureToggle, TitleText, TaglineText, UpdateText, HeroGlyph, HeroTitle, HeroSub, ProgText, StProtL, StProtV, StLastL, StLastV, StQuarL, StQuarV, StRulesL, StRulesV, EmptyText, GraphHint, QEmpty, AbPrivacyH, AbPrivacy, AbInfo, AbSettingsH, AbUrlL, AbSaved;
        Border UpdatePill, HeroIcon;
        Button BtnRu, BtnEn, BtnQuick, BtnFull, BtnCustom, BtnCancel, BtnNeutralizeAll, BtnQRestore, BtnQDelete, BtnQDeleteAll, BtnQRefresh, BtnOpenReport, BtnOpenReports, BtnOpenData, BtnSaveSettings, BtnCheckNow, BtnInstallRules;
        ProgressBar Prog; WrapPanel Chips; StackPanel ScanButtons, DetailPanel; ItemsControl PostureList; TabControl Tabs;
        TabItem TabResults, TabGraph, TabQuarantine, TabLog, TabAbout;
        CheckBox CkNotes, CkAutoScan, CkCheckUpdates, CkAutoRules, CkBrowsers, CkMemory;
        ListBox ResultList, QList; ScrollViewer DetailScroll, GraphScroll; Canvas GraphCanvas; TextBox LogBox, TxtUrl;

        public MainWindow(AppConfig cfg, string[] args)
        {
            _cfg = cfg; _state = AppState.Load();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if (a == "--shot" && i + 1 < args.Length) _shot = args[++i];
                else if (a == "--shots" && i + 1 < args.Length) _shotsDir = args[++i];
                else if (a == "--tab" && i + 1 < args.Length) _shotTab = args[++i].ToLowerInvariant();
                else if (a == "--select" && i + 1 < args.Length) int.TryParse(args[++i], out _shotSelect);
                else if (a == "--notes") _shotNotes = true;
                else if (a == "--neutralize" && i + 1 < args.Length) _autoNeutralize = args[++i];
                else if (a == "--filter" && i + 1 < args.Length) _shotFilter = args[++i];
                else if (a == "--no-scan") { _noScan = true; _autoScanPending = false; }
                else if (a == "--lang" && i + 1 < args.Length) Loc.Init(args[++i]);
            }
            using (var s = typeof(MainWindow).Assembly.GetManifestResourceStream("ui.MainWindow.xaml")) W = (Window)XamlReader.Load(s);
            Bind();
            W.Icon = MakeIcon();
            W.SourceInitialized += (s, e) => DarkTitleBar();
            W.Loaded += (s, e) => StartUp();
            W.Closing += OnClosing;
        }

        // ============================================================================================ wiring
        void Bind()
        {
            foreach (var f in typeof(MainWindow).GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic))
            {
                if (f.Name.StartsWith("_") || f.FieldType == typeof(Window)) continue;
                if (!typeof(FrameworkElement).IsAssignableFrom(f.FieldType)) continue;
                var el = W.FindName(f.Name); if (el != null && f.FieldType.IsInstanceOfType(el)) f.SetValue(this, el);
            }
            BtnRu.Click += (s, e) => SetLang("ru"); BtnEn.Click += (s, e) => SetLang("en");
            BtnQuick.Click += (s, e) => StartScan(ScanMode.Quick);
            BtnFull.Click += (s, e) => StartScan(ScanMode.Full);
            BtnCustom.Click += (s, e) => CustomScan();
            BtnCancel.Click += (s, e) => { if (_cts != null) { _cts.Cancel(); BtnCancel.IsEnabled = false; } };
            BtnNeutralizeAll.Click += (s, e) => NeutralizeAll();
            UpdatePill.MouseLeftButtonUp += (s, e) => OnPillClick();
            PostureToggle.MouseLeftButtonUp += (s, e) => { PostureList.Visibility = PostureList.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible; RefreshStatus(); };
            CkNotes.Checked += (s, e) => PopulateResults(); CkNotes.Unchecked += (s, e) => PopulateResults();
            ResultList.SelectionChanged += (s, e) => ShowSelected();
            Tabs.SelectionChanged += (s, e) => { if (e.Source == Tabs) { if (Tabs.SelectedItem == TabGraph) RenderGraph(); if (Tabs.SelectedItem == TabQuarantine) RefreshQuarantine(); if (Tabs.SelectedItem == TabAbout) FillAbout(); } };
            BtnQRefresh.Click += (s, e) => RefreshQuarantine();
            BtnQRestore.Click += (s, e) => QuarantineRestore();
            BtnQDelete.Click += (s, e) => QuarantineDelete(false);
            BtnQDeleteAll.Click += (s, e) => QuarantineDelete(true);
            BtnOpenReport.Click += (s, e) => OpenPath(_lastReportTxt ?? LatestReport());
            BtnOpenReports.Click += (s, e) => OpenPath(ReportWriter.DefaultDir);
            BtnOpenData.Click += (s, e) => OpenPath(RulePack.DataDir);
            BtnSaveSettings.Click += (s, e) => SaveSettings();
            BtnCheckNow.Click += (s, e) => CheckUpdates(false);
            BtnInstallRules.Click += (s, e) => InstallRules();
            Log.Sink = line => Ui(() => AppendLog(line));
        }

        void StartUp()
        {
            ApplyLanguage();
            foreach (var l in Log.Snapshot().Reverse().Take(300).Reverse()) LogBox.AppendText(l + "\n");
            Log.Info("MineHunter " + AppInfo.Version + " started");
            SetHeroIdle();
            RefreshStatus();
            if (_noScan) { CheckUpdates(false); AfterFirstLayout(); return; }
            CheckUpdates(true);
        }

        void OnClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (_mode == Mode.Cleaning) { e.Cancel = true; MessageBox.Show(W, L("Neutralizing is in progress. Please wait until it finishes.", "Идёт обезвреживание. Подождите, пока оно закончится."), "MineHunter", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            if (_cts != null) _cts.Cancel();
        }

        // ============================================================================================ language / static texts
        void SetLang(string lang)
        {
            Loc.Init(lang); _cfg.Language = lang; _cfg.SaveUser();
            ApplyLanguage(); RefreshStatus();
            if (_res != null) { RenderHeroFromResult(); PopulateResults(); }
            else SetHeroIdle();
            RefreshQuarantine(); SetPill(_upd);
        }

        void ApplyLanguage()
        {
            W.Title = "MineHunter " + AppInfo.Version;
            TaglineText.Text = Loc.T("app.tagline");
            BtnQuick.Content = "⚡  " + Loc.T("btn.quick"); BtnFull.Content = Loc.T("btn.full"); BtnCustom.Content = Loc.T("btn.custom"); BtnCancel.Content = Loc.T("btn.cancel");
            BtnNeutralizeAll.Content = Loc.T("btn.neutralize_all");
            TabResults.Header = Loc.T("tab.results"); TabGraph.Header = Loc.T("tab.graph"); TabQuarantine.Header = Loc.T("tab.quarantine"); TabLog.Header = Loc.T("tab.log"); TabAbout.Header = Loc.T("tab.about");
            CkNotes.Content = L("Show minor notes (not threats)", "Показывать мелкие заметки (не угрозы)");
            StProtL.Text = Loc.T("status.protection"); StLastL.Text = Loc.T("status.lastscan"); StQuarL.Text = Loc.T("status.quarantine"); StRulesL.Text = Loc.T("status.rules");
            BtnQRestore.Content = Loc.T("btn.restore"); BtnQDelete.Content = L("Delete selected", "Удалить выбранное"); BtnQDeleteAll.Content = L("Delete all", "Удалить всё"); BtnQRefresh.Content = L("Refresh", "Обновить");
            BtnOpenReport.Content = Loc.T("btn.openreport"); BtnOpenReports.Content = L("Reports folder", "Папка отчётов"); BtnOpenData.Content = L("Data folder", "Папка данных");
            AbPrivacyH.Text = L("Privacy", "Приватность"); AbPrivacy.Text = Loc.T("privacy.text");
            AbSettingsH.Text = L("Settings", "Настройки");
            CkAutoScan.Content = L("Start a quick scan automatically when the program opens", "Запускать быструю проверку автоматически при открытии");
            CkCheckUpdates.Content = L("Check for a newer version when the program opens", "Проверять наличие новой версии при открытии");
            CkAutoRules.Content = L("Install newer detection rules automatically (verified by SHA-256 / signature)", "Устанавливать новые правила детекта автоматически (проверка SHA-256 / подписи)");
            CkBrowsers.Content = L("Scan browsers and their extensions", "Проверять браузеры и их расширения");
            CkMemory.Content = L("Inspect process memory (hollowing, injected code)", "Проверять память процессов (подмена образа, внедрённый код)");
            AbUrlL.Text = L("Update source (address of version.json, https only; leave empty to disable)", "Источник обновлений (адрес version.json, только https; пусто — отключить)");
            BtnSaveSettings.Content = L("Save settings", "Сохранить настройки"); BtnCheckNow.Content = L("Check for updates now", "Проверить обновления сейчас"); BtnInstallRules.Content = Loc.T("upd.install_rules");
            CkAutoScan.IsChecked = _cfg.AutoScanOnStart; CkCheckUpdates.IsChecked = _cfg.CheckUpdatesOnStart; CkAutoRules.IsChecked = _cfg.AutoUpdateRules; CkBrowsers.IsChecked = _cfg.ScanBrowsers; CkMemory.IsChecked = _cfg.ScanMemory;
            TxtUrl.Text = _cfg.UpdateManifestUrl ?? "";
            bool ru = Loc.Ru;
            BtnRu.Background = ru ? Res("Accent") : Brushes.Transparent; BtnRu.Foreground = ru ? Brushes.White : Res("Muted");
            BtnEn.Background = !ru ? Res("Accent") : Brushes.Transparent; BtnEn.Foreground = !ru ? Brushes.White : Res("Muted");
            GraphHint.Text = L("How the pieces of one threat are connected: what starts it, which file it runs, which process it becomes and where it connects. Select a finding in Results to see its graph.", "Как связаны части одной угрозы: что её запускает, какой файл, в какой процесс он превращается и куда подключается. Выберите находку во вкладке «Результаты», чтобы увидеть её граф.");
            FillAbout();
        }

        // ============================================================================================ start-up: updates, then the automatic scan
        void CheckUpdates(bool thenScan)
        {
            SetPillChecking();
            BtnCheckNow.IsEnabled = false;
            Task.Run(() =>
            {
                UpdateInfo u; string rulesNote = null;
                try
                {
                    var rules = RulePack.Load();
                    u = Updater.Check(_cfg, rules.Version);
                    if (u.RulesNewer && _cfg.AutoUpdateRules && !string.IsNullOrEmpty(u.RulesUrl))
                    {
                        string err = Updater.UpdateRules(_cfg, u);
                        if (err == null) { rulesNote = u.RulesVersion; u.LocalRulesVersion = u.RulesVersion; u.RulesNewer = false; Log.Info("Rules updated to " + u.RulesVersion); }
                        else Log.Warn("Rules not updated: " + err);
                    }
                }
                catch (Exception ex) { u = new UpdateInfo { State = UpdateState.Error, Message = ex.Message }; }
                Ui(() =>
                {
                    BtnCheckNow.IsEnabled = true;
                    _upd = u; SetPill(u, rulesNote); RefreshStatus();
                    if (!string.IsNullOrEmpty(rulesNote)) Log.Info(L("Detection rules updated to ", "Правила детекта обновлены до ") + rulesNote);
                    BtnInstallRules.Visibility = u.RulesNewer ? Visibility.Visible : Visibility.Collapsed;
                    if (thenScan && _autoScanPending && _cfg.AutoScanOnStart && _mode == Mode.Idle) StartScan(ScanMode.Quick);
                    _autoScanPending = false;
                    if (_noScan) AfterFirstLayout();
                });
            });
        }

        void SetPillChecking()
        {
            UpdateText.Text = "⟳  " + Loc.T("upd.checking"); UpdateText.Foreground = Res("Muted"); UpdatePill.Cursor = Cursors.Arrow;
        }

        void SetPill(UpdateInfo u, string rulesNote = null)
        {
            if (u == null) { UpdateText.Text = L("Version ", "Версия ") + AppInfo.Version; UpdateText.Foreground = Res("Muted"); return; }
            UpdatePill.Cursor = Cursors.Arrow; UpdatePill.ToolTip = u.Message;
            string v = AppInfo.Version;
            switch (u.State)
            {
                case UpdateState.UpToDate:
                    UpdateText.Text = "✓  " + L("Version " + v + " — the latest", "Версия " + v + " — последняя") + (rulesNote != null ? L("  ·  rules updated", "  ·  правила обновлены") : "");
                    UpdateText.Foreground = Res("Good"); break;
                case UpdateState.UpdateAvailable:
                    UpdateText.Text = "⬆  " + L("New version " + u.Latest + " available — download", "Доступна версия " + u.Latest + " — скачать"); UpdateText.Foreground = Res("Warn"); UpdatePill.Cursor = Cursors.Hand; break;
                case UpdateState.Offline:
                    UpdateText.Text = "○  " + L("Version " + v + "  ·  offline, update check skipped", "Версия " + v + "  ·  нет сети, проверка обновлений пропущена"); UpdateText.Foreground = Res("Muted"); break;
                case UpdateState.NotConfigured:
                    UpdateText.Text = "ⓘ  " + L("Version " + v + "  ·  update source not set yet", "Версия " + v + "  ·  источник обновлений ещё не задан"); UpdateText.Foreground = Res("Muted"); UpdatePill.Cursor = Cursors.Hand; break;
                case UpdateState.Disabled:
                    UpdateText.Text = L("Version " + v + "  ·  update check is off", "Версия " + v + "  ·  проверка обновлений отключена"); UpdateText.Foreground = Res("Muted"); break;
                default:
                    UpdateText.Text = "!  " + L("Version " + v + "  ·  could not check for updates", "Версия " + v + "  ·  не удалось проверить обновления"); UpdateText.Foreground = Res("Warn"); break;
            }
        }

        void OnPillClick()
        {
            if (_upd == null) return;
            if (_upd.State == UpdateState.UpdateAvailable && !string.IsNullOrEmpty(_upd.ReleaseUrl) && _upd.ReleaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) OpenPath(_upd.ReleaseUrl);
            else if (_upd.State == UpdateState.NotConfigured) Tabs.SelectedItem = TabAbout;
        }

        void InstallRules()
        {
            if (_upd == null || !_upd.RulesNewer) return;
            BtnInstallRules.IsEnabled = false;
            var u = _upd;
            Task.Run(() => Updater.UpdateRules(_cfg, u)).ContinueWith(t => Ui(() =>
            {
                BtnInstallRules.IsEnabled = true;
                string err = t.IsFaulted ? t.Exception.GetBaseException().Message : t.Result;
                if (err == null) { u.RulesNewer = false; u.LocalRulesVersion = u.RulesVersion; BtnInstallRules.Visibility = Visibility.Collapsed; AbSaved.Text = L("Rules updated to ", "Правила обновлены до ") + u.RulesVersion; RefreshStatus(); FillAbout(); }
                else { AbSaved.Foreground = Res("Bad"); AbSaved.Text = L("Rules were NOT updated: ", "Правила НЕ обновлены: ") + err; }
            }));
        }

        void SaveSettings()
        {
            _cfg.AutoScanOnStart = CkAutoScan.IsChecked == true; _cfg.CheckUpdatesOnStart = CkCheckUpdates.IsChecked == true; _cfg.AutoUpdateRules = CkAutoRules.IsChecked == true;
            _cfg.ScanBrowsers = CkBrowsers.IsChecked == true; _cfg.ScanMemory = CkMemory.IsChecked == true; _cfg.UpdateManifestUrl = (TxtUrl.Text ?? "").Trim();
            _cfg.SaveUser();
            AbSaved.Foreground = Res("Good"); AbSaved.Text = "✓  " + L("Saved", "Сохранено");
        }

        // ============================================================================================ scanning
        void CustomScan()
        {
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = L("Choose a folder (or a whole drive) to scan", "Выберите папку (или диск) для проверки"), ShowNewFolderButton = false })
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedPath)) StartScan(ScanMode.Custom, dlg.SelectedPath);
        }

        void SetBusy(Mode m)
        {
            _mode = m;
            bool idle = m == Mode.Idle;
            ScanButtons.Visibility = idle ? Visibility.Visible : Visibility.Collapsed;
            BtnCancel.Visibility = m == Mode.Scanning ? Visibility.Visible : Visibility.Collapsed; BtnCancel.IsEnabled = true;
            Prog.Visibility = idle ? Visibility.Collapsed : Visibility.Visible; ProgText.Visibility = idle ? Visibility.Collapsed : Visibility.Visible;
            if (!idle) { Chips.Visibility = Visibility.Collapsed; BtnNeutralizeAll.Visibility = Visibility.Collapsed; }
        }

        void StartScan(ScanMode mode, string path = null)
        {
            if (_mode != Mode.Idle) return;
            SetBusy(Mode.Scanning); _progMax = 0; Prog.Value = 0;
            string what = mode == ScanMode.Quick ? L("Quick scan", "Быстрая проверка") : mode == ScanMode.Full ? L("Full scan", "Полная проверка") : L("Custom scan", "Выборочная проверка");
            SetHero("…", Res("Accent"), Loc.T("scan.running"), what + (path != null ? ": " + path : ""));
            ProgText.Text = Loc.Progress("Preparing...");
            var opt = new ScanOptions { Mode = mode, CustomPath = path, Browsers = _cfg.ScanBrowsers, MemoryInspection = _cfg.ScanMemory };
            _lastOpt = opt; _cts = new CancellationTokenSource(); var ct = _cts.Token;
            Log.Info("Scan started: " + mode + (path != null ? " " + path : ""));
            Task.Run(() => ScanEngine.Run(opt, ct, (s, p) => Ui(() => OnProgress(s, p)))).ContinueWith(t => Ui(() =>
            {
                if (t.IsFaulted) { SetBusy(Mode.Idle); Log.Error(t.Exception.GetBaseException().ToString()); SetHero("!", Res("Bad"), L("The scan failed", "Проверка не удалась"), t.Exception.GetBaseException().Message); return; }
                OnScanDone(t.Result);
            }));
        }

        void OnProgress(string s, int p)
        {
            if (_mode == Mode.Idle) return;
            _progMax = Math.Max(_progMax, p); Prog.Value = _progMax;
            ProgText.Text = Loc.Progress(s);
        }

        void OnScanDone(ScanResult r)
        {
            if (_shotFilter != null)
            {
                // test/demo hook: keep only findings that involve the given text (used to make README screenshots from the benign lab without showing private results)
                string key = _shotFilter;
                Func<Entity, bool> m = e => (e.Location ?? "").IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0 || (e.Title ?? "").IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0;
                r.Findings.RemoveAll(f => !f.Entities.Any(m)); r.Observations.RemoveAll(o => !m(o));
            }
            _res = r; _cleanup = null;
            SetBusy(Mode.Idle);
            try { _lastReportTxt = ReportWriter.Write(r, null, ReportWriter.DefaultDir); } catch (Exception ex) { Log.Warn("report: " + ex.Message); }
            _state.LastScan = DateTime.Now.ToString("o"); _state.LastMode = r.Mode;
            _state.Malware = r.Findings.Count(f => f.Verdict == Verdict.Malware); _state.High = r.Findings.Count(f => f.Verdict == Verdict.HighRisk); _state.Susp = r.Findings.Count(f => f.Verdict == Verdict.Suspicious); _state.Notes = r.Observations.Count;
            _state.Protection = r.Status.DefenderState; _state.Warnings = r.Status.PostureWarnings.ToList();
            if (!r.Aborted) _state.Save();
            Log.Info("Scan finished in " + r.Stats.Seconds + " s: malware " + _state.Malware + ", high risk " + _state.High + ", suspicious " + _state.Susp + ", notes " + _state.Notes);
            RefreshStatus(); RenderHeroFromResult(); PopulateResults();
            if (r.Findings.Count > 0) { Tabs.SelectedItem = TabResults; }
            if (_autoNeutralize != null && !_shotDone)
            {
                // automated GUI test: neutralise the findings that involve the given text (lab objects), without the confirmation box
                string key = _autoNeutralize; _autoNeutralize = null;
                var plan = r.Findings.Where(f => f.Entities.Any(e => (e.Location ?? "").IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0 || (e.Title ?? "").IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0))
                    .Select(f => new KeyValuePair<Finding, List<RemediationStep>>(f, f.Steps.Where(s => s.Type != ActionType.ReviewOnly).ToList())).Where(kv => kv.Value.Count > 0).ToList();
                if (plan.Count > 0) { RunCleanup(plan, false); return; }
            }
            AfterFirstLayout();
        }

        // ============================================================================================ hero / status
        void SetHero(string glyph, Brush color, string title, string sub)
        {
            HeroGlyph.Text = glyph; HeroIcon.Background = color; HeroTitle.Text = title; HeroSub.Text = sub;
        }

        void SetHeroIdle()
        {
            SetBusy(Mode.Idle); Chips.Visibility = Visibility.Collapsed; BtnNeutralizeAll.Visibility = Visibility.Collapsed;
            SetHero("▶", Res("Accent"), L("Ready to scan", "Готов к проверке"), _cfg.AutoScanOnStart ? L("The quick scan starts by itself in a moment.", "Быстрая проверка запустится сама через мгновение.") : Loc.T("scan.idle"));
            HeroGlyph.FontSize = 30;
            HeroSub.Text = Loc.T("scan.idle");
        }

        Border Chip(string text, Brush accent)
        {
            var c = ((SolidColorBrush)accent).Color; c.A = 40;
            return new Border { CornerRadius = new CornerRadius(14), Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(0, 0, 8, 0), Background = new SolidColorBrush(c), Child = new TextBlock { Text = text, Foreground = accent, FontWeight = FontWeights.Bold, FontSize = 12 } };
        }

        void RenderHeroFromResult()
        {
            if (_res == null) return;
            var r = _res; HeroGlyph.FontSize = 36;
            int mal = r.Findings.Count(f => f.Verdict == Verdict.Malware), high = r.Findings.Count(f => f.Verdict == Verdict.HighRisk), susp = r.Findings.Count(f => f.Verdict == Verdict.Suspicious), notes = r.Observations.Count;
            string stats = L("Examined: ", "Проверено: ") + r.Stats.ProcessesScanned + L(" processes, ", " процессов, ") + r.Stats.ModulesChecked + L(" libraries, ", " библиотек, ") + (r.Stats.FilesInspected + r.Stats.FilesSkippedByCache) + L(" files, ", " файлов, ")
                         + r.Stats.ServicesScanned + L(" services, ", " служб, ") + r.Stats.TasksScanned + L(" tasks, ", " задач, ") + r.Stats.BrowserExtensions + L(" extensions", " расширений") + L("  ·  in ", "  ·  за ") + r.Stats.Seconds.ToString("0") + L(" s", " с");
            Chips.Children.Clear();
            if (r.Aborted) SetHero("■", Res("Muted"), L("Scan cancelled", "Проверка отменена"), L("Partial result — only what was checked before you cancelled.", "Частичный результат — только то, что успели проверить."));
            else if (mal > 0) SetHero("✕", Res("Bad"), L("Malware found", "Найдено вредоносное ПО"), stats);
            else if (high > 0) SetHero("!", Res("Orange"), L("Threats found", "Найдены угрозы"), stats);
            else if (susp > 0) SetHero("?", Res("Warn"), L("Something looks suspicious", "Есть подозрительное"), stats);
            else SetHero("✓", Res("Good"), L("No threats found", "Угроз не найдено"), Loc.T("scan.clean") + "  " + stats);
            if (mal > 0) Chips.Children.Add(Chip(Loc.T("sum.malware") + "  " + mal, Res("Bad")));
            if (high > 0) Chips.Children.Add(Chip(Loc.T("sum.high") + "  " + high, Res("Orange")));
            if (susp > 0) Chips.Children.Add(Chip(Loc.T("sum.susp") + "  " + susp, Res("Warn")));
            if (mal + high + susp == 0) Chips.Children.Add(Chip(Loc.T("sum.clean"), Res("Good")));
            if (notes > 0) Chips.Children.Add(Chip(notes + "  " + Loc.T("sum.notes"), (Brush)new SolidColorBrush(Color.FromRgb(0x8E, 0x99, 0xBA))));
            Chips.Visibility = Visibility.Visible;
            BtnNeutralizeAll.Content = Loc.T("btn.neutralize_all");
            BtnNeutralizeAll.Visibility = r.Findings.Any(f => f.Verdict >= Verdict.HighRisk && f.Steps.Any(s => s.RecommendedByDefault && s.Type != ActionType.ReviewOnly)) ? Visibility.Visible : Visibility.Collapsed;
        }

        void RefreshStatus()
        {
            string prot; Brush pc;
            string src = _res != null ? _res.Status.DefenderState : _state.Protection;
            ProtectionView(src, out prot, out pc);
            StProtV.Text = prot; StProtV.Foreground = pc;
            if (_res != null && !_res.Aborted) StLastV.Text = _res.Finished.ToString("dd.MM.yyyy HH:mm") + "  ·  " + (_res.Mode == "Quick" ? L("quick", "быстрая") : _res.Mode == "Full" ? L("full", "полная") : L("custom", "выборочная"));
            else if (!string.IsNullOrEmpty(_state.LastScan)) { DateTime d; StLastV.Text = DateTime.TryParse(_state.LastScan, out d) ? d.ToString("dd.MM.yyyy HH:mm") : _state.LastScan; }
            else StLastV.Text = Loc.T("status.never");
            int q = Quarantine.List().Count; StQuarV.Text = q.ToString() + (q > 0 ? "  " + L("item(s)", "элем.") : "");
            string rv = _upd != null && !string.IsNullOrEmpty(_upd.LocalRulesVersion) ? _upd.LocalRulesVersion : (rulesVersionCache ?? (rulesVersionCache = SafeRulesVersion()));
            StRulesV.Text = rv;
            var warns = (_res != null ? _res.Status.PostureWarnings : _state.Warnings).Select(w => "⚠  " + Loc.Posture(w)).Distinct().ToList();
            PostureList.ItemsSource = warns;
            PostureToggle.Visibility = warns.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (warns.Count == 0) PostureList.Visibility = Visibility.Collapsed;
            PostureToggle.Text = (PostureList.Visibility == Visibility.Visible ? "▾  " : "▸  ") + L("System protection warnings (" + warns.Count + ")", "Предупреждения о защите системы (" + warns.Count + ")");
        }
        string rulesVersionCache;
        static string SafeRulesVersion() { try { return RulePack.Load().Version; } catch { return "?"; } }

        void ProtectionView(string state, out string text, out Brush color)
        {
            color = Res("Muted"); text = "—";
            if (string.IsNullOrEmpty(state)) return;
            if (state.StartsWith("Windows Defender is running")) { text = L("Windows Defender is running", "Защитник Windows работает"); color = Res("Good"); }
            else if (state.StartsWith("No active antivirus")) { text = L("No active antivirus", "Нет работающего антивируса"); color = Res("Bad"); }
            else if (state.StartsWith("Windows Defender is off; other antivirus:")) { text = L("Other antivirus: ", "Другой антивирус: ") + state.Substring(state.IndexOf(':') + 1).Trim(); color = Res("Good"); }
            else text = state;
        }

        // ============================================================================================ results list
        static Brush AccentOf(Verdict v)
        {
            switch (v) { case Verdict.Malware: return GraphView.Bad; case Verdict.HighRisk: return GraphView.Orange; case Verdict.Suspicious: return GraphView.Warn; default: return GraphView.Minor; }
        }
        static Brush Soft(Brush b) { var c = ((SolidColorBrush)b).Color; c.A = 38; var r = new SolidColorBrush(c); r.Freeze(); return r; }

        static string MainLocation(Finding f)
        {
            // show the program's file when there is one (that is what the user recognises); otherwise the most suspicious entity
            var e = f.Entities.Where(x => x.Kind == EntityKind.File).OrderByDescending(x => x.Score).FirstOrDefault()
                    ?? f.Entities.OrderByDescending(x => x.Score).FirstOrDefault();
            if (e == null) return "";
            return e.Kind == EntityKind.Task ? (e.P("taskPath") ?? e.Location) : (e.Location ?? e.Title);
        }

        void PopulateResults()
        {
            var items = new List<ResultItem>();
            if (_res != null)
            {
                foreach (var f in _res.Findings)
                {
                    var acc = AccentOf(f.Verdict);
                    items.Add(new ResultItem { F = f, Title = Loc.Title(f.Title), Sub = MainLocation(f), VerdictText = Loc.Verdict(f.Verdict), ScoreText = f.Score.ToString(), Accent = acc, AccentSoft = Soft(acc) });
                }
                if (CkNotes.IsChecked == true)
                    foreach (var n in _res.Observations)
                        items.Add(new ResultItem { Note = n, Title = n.Title, Sub = n.Kind == EntityKind.Task ? (n.P("taskPath") ?? n.Location) : n.Location, VerdictText = L("NOTE", "ЗАМЕТКА") + "  ·  " + Loc.KindName(n.Kind), ScoreText = n.Score.ToString(), Accent = GraphView.Minor, AccentSoft = Soft(GraphView.Minor) });
            }
            ResultList.ItemsSource = items;
            if (items.Count == 0)
            {
                EmptyText.Visibility = Visibility.Visible;
                EmptyText.Text = _res == null ? L("No scan yet.", "Проверки ещё не было.") : L("Nothing suspicious was found.", "Ничего подозрительного не найдено.") + (_res.Observations.Count > 0 ? "\n\n" + L("There are " + _res.Observations.Count + " minor notes (not threats). Tick the box above to see them.", "Есть " + _res.Observations.Count + " мелких заметок (не угроз). Отметьте галочку выше, чтобы их увидеть.") : "");
                ShowEmptyDetails();
            }
            else { EmptyText.Visibility = Visibility.Collapsed; ResultList.SelectedIndex = 0; }
        }

        void ShowEmptyDetails()
        {
            DetailPanel.Children.Clear();
            if (_cleanup != null && _cleanup.Count > 0) { ShowCleanup(); return; }
            DetailPanel.Children.Add(Tb(_res == null ? L("Press “Quick scan” to check this computer.", "Нажмите «Быстрая проверка», чтобы проверить компьютер.") : Loc.T("scan.clean"), 15, Res("Muted")));
            GraphCanvas.Children.Clear();
        }

        void ShowSelected()
        {
            var it = ResultList.SelectedItem as ResultItem;
            if (it == null) { if (ResultList.Items.Count == 0) ShowEmptyDetails(); return; }
            if (it.F != null) ShowFinding(it.F); else ShowNote(it.Note);
            if (Tabs.SelectedItem == TabGraph) RenderGraph();
        }

        void RenderGraph()
        {
            var it = ResultList.SelectedItem as ResultItem;
            GraphView.Render(GraphCanvas, it != null ? it.F : null);
        }

        // ============================================================================================ details building blocks
        TextBlock Tb(string text, double size = 13, Brush fg = null, FontWeight? weight = null, Thickness? margin = null, string font = null)
        {
            var t = new TextBlock { Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap, Foreground = fg ?? Res("Text") };
            if (weight != null) t.FontWeight = weight.Value; if (margin != null) t.Margin = margin.Value; if (font != null) t.FontFamily = new FontFamily(font);
            return t;
        }
        TextBlock Head(string text) { return Tb(text.ToUpperInvariant(), 11, Res("Muted"), FontWeights.Bold, new Thickness(0, 20, 0, 8)); }
        Border Badge(string text, Brush accent)
        {
            return new Border { CornerRadius = new CornerRadius(12), Background = Soft(accent), Padding = new Thickness(11, 3, 11, 3), HorizontalAlignment = HorizontalAlignment.Left, Child = new TextBlock { Text = text, Foreground = accent, FontWeight = FontWeights.Bold, FontSize = 11.5 } };
        }
        Button Btn(string text, string style, RoutedEventHandler click)
        {
            var b = new Button { Content = text, Style = (Style)W.FindResource(style), Margin = new Thickness(0, 0, 8, 8) }; b.Click += click; return b;
        }

        void ShowFinding(Finding f)
        {
            var P = DetailPanel; P.Children.Clear();
            var acc = AccentOf(f.Verdict);
            var top = new StackPanel { Orientation = Orientation.Horizontal };
            top.Children.Add(Badge(Loc.Verdict(f.Verdict), acc));
            top.Children.Add(new Border { Margin = new Thickness(8, 0, 0, 0), CornerRadius = new CornerRadius(12), Background = Res("Surface2") as Brush, Padding = new Thickness(11, 3, 11, 3), Child = Tb(L("score ", "балл ") + f.Score + " / 100", 11.5, Res("Muted"), FontWeights.SemiBold) });
            P.Children.Add(top);
            P.Children.Add(Tb(Loc.Title(f.Title), 21, null, FontWeights.Bold, new Thickness(0, 10, 0, 0)));
            P.Children.Add(Tb(Loc.VerdictMeaning(f.Verdict), 13, Res("Muted"), null, new Thickness(0, 6, 0, 0)));
            P.Children.Add(ScoreBar(f.Score, acc));

            // what / where
            P.Children.Add(Head(Loc.T("det.what")));
            foreach (var e in f.Entities.OrderBy(EntityOrder).ThenByDescending(x => x.Score).Take(14))
            {
                var row = new Grid { Margin = new Thickness(0, 3, 0, 3) };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(112) }); row.ColumnDefinitions.Add(new ColumnDefinition());
                row.Children.Add(Tb(Loc.KindName(e.Kind), 12, Res("Muted"), FontWeights.SemiBold));
                var sp = new StackPanel(); Grid.SetColumn(sp, 1);
                sp.Children.Add(Tb(e.Title, 13, null, FontWeights.SemiBold));
                string loc = e.Kind == EntityKind.Task ? (e.P("taskPath") ?? e.Location) : e.Location;
                if (!string.IsNullOrEmpty(loc) && loc != e.Title) sp.Children.Add(Tb(loc, 11.5, Res("Muted"), null, new Thickness(0, 1, 0, 0), "Consolas"));
                row.Children.Add(sp); P.Children.Add(row);
            }
            if (f.Entities.Count > 14) P.Children.Add(Tb("… +" + (f.Entities.Count - 14), 12, Res("Muted")));

            // why
            P.Children.Add(Head(Loc.T("det.why")));
            foreach (var ev in f.TopEvidence) P.Children.Add(EvidenceRow(ev));
            P.Children.Add(Tb(L("Each kind of evidence is capped and repeated signals count less, so a single signal cannot raise a program to High Risk.", "Каждый вид улик ограничен, повторяющиеся сигналы весят меньше, поэтому один признак не поднимает программу до высокого риска."), 11, Res("Muted"), null, new Thickness(0, 6, 0, 0)));
            if (!string.IsNullOrEmpty(f.WhyNotHigher)) P.Children.Add(Tb(Loc.T("det.capped") + ": " + Loc.WhyNotHigher(f.WhyNotHigher), 12, Res("Warn"), null, new Thickness(0, 8, 0, 0)));

            // chain
            P.Children.Add(Head(Loc.T("det.chain")));
            var chain = ThreatGraph.Render(f, true);
            P.Children.Add(new Border { Background = new SolidColorBrush(Color.FromRgb(0x10, 0x15, 0x2A)), CornerRadius = new CornerRadius(9), Padding = new Thickness(14, 10, 14, 10), Child = Tb(string.Join("\n", chain), 12, Res("Text"), null, null, "Consolas") });

            // action
            P.Children.Add(Head(Loc.T("det.action")));
            P.Children.Add(Tb(Loc.Recommendation(f), 13));
            _stepItems = f.Steps.Select(s => new StepItem { Step = s, Text = (s.Type == ActionType.ReviewOnly ? "ℹ  " : "") + Loc.Step(s) + (s.Reversible || s.Type == ActionType.ReviewOnly ? "" : L("  (cannot be undone)", "  (необратимо)")), Selected = s.RecommendedByDefault && s.Type != ActionType.ReviewOnly, Enabled = s.Type != ActionType.ReviewOnly }).ToList();
            if (_stepItems.Count > 0)
            {
                P.Children.Add(Tb(Loc.T("det.steps"), 12, Res("Muted"), null, new Thickness(0, 10, 0, 2)));
                var ic = new ItemsControl { ItemsSource = _stepItems, ItemTemplate = (DataTemplate)W.FindResource("StepTpl") }; P.Children.Add(ic);
            }

            var btns = new WrapPanel { Margin = new Thickness(0, 14, 0, 0) };
            if (_stepItems.Any(s => s.Enabled)) btns.Children.Add(Btn(Loc.T("btn.neutralize"), "BtnDanger", (s, e) => NeutralizeSelected(f)));
            btns.Children.Add(Btn(Loc.T("btn.allow"), "Btn", (s, e) => MarkSafe(f.Entities, Loc.Title(f.Title), f)));
            AddFolderButtons(btns, f.Entities);
            P.Children.Add(btns);
            DetailScroll.ScrollToTop();
        }

        void ShowNote(Entity n)
        {
            var P = DetailPanel; P.Children.Clear();
            P.Children.Add(Badge(L("NOTE", "ЗАМЕТКА") + "  ·  " + Loc.KindName(n.Kind), GraphView.Minor));
            P.Children.Add(Tb(n.Title, 21, null, FontWeights.Bold, new Thickness(0, 10, 0, 0)));
            string loc = n.Kind == EntityKind.Task ? (n.P("taskPath") ?? n.Location) : n.Location;
            if (!string.IsNullOrEmpty(loc)) P.Children.Add(Tb(loc, 12, Res("Muted"), null, new Thickness(0, 4, 0, 0), "Consolas"));
            P.Children.Add(Tb(Loc.VerdictMeaning(Verdict.Clean), 13, Res("Muted"), null, new Thickness(0, 8, 0, 0)));
            P.Children.Add(ScoreBar(n.Score, GraphView.Minor));
            P.Children.Add(Head(Loc.T("det.why")));
            foreach (var ev in n.Evidence.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight)) P.Children.Add(EvidenceRow(ev));
            var btns = new WrapPanel { Margin = new Thickness(0, 14, 0, 0) };
            btns.Children.Add(Btn(Loc.T("btn.allow"), "Btn", (s, e) => MarkSafe(new List<Entity> { n }, n.Title, null)));
            AddFolderButtons(btns, new List<Entity> { n });
            P.Children.Add(btns);
            DetailScroll.ScrollToTop();
        }

        static int EntityOrder(Entity e) { switch (e.Kind) { case EntityKind.Task: case EntityKind.Service: case EntityKind.RunKey: case EntityKind.StartupItem: case EntityKind.Wmi: case EntityKind.Driver: return 0; case EntityKind.File: return 1; case EntityKind.Process: return 2; default: return 3; } }

        UIElement ScoreBar(int score, Brush acc)
        {
            var g = new Grid { Height = 8, Margin = new Thickness(0, 12, 0, 0) };
            g.Children.Add(new Border { CornerRadius = new CornerRadius(4), Background = new SolidColorBrush(Color.FromRgb(0x24, 0x2C, 0x4D)) });
            var fill = new Border { CornerRadius = new CornerRadius(4), Background = acc, HorizontalAlignment = HorizontalAlignment.Left };
            g.Children.Add(fill);
            g.SizeChanged += (s, e) => fill.Width = Math.Max(6, g.ActualWidth * Math.Min(100, Math.Max(0, score)) / 100.0);
            var sp = new StackPanel(); sp.Children.Add(g);
            sp.Children.Add(Tb(L("Suspicious ≥ 30   ·   High risk ≥ 60   ·   Malware ≥ 85 (only with corroborating evidence)", "Подозрительное ≥ 30   ·   Высокий риск ≥ 60   ·   Вредоносное ≥ 85 (только при подтверждении разными уликами)"), 10.5, Res("Muted"), null, new Thickness(0, 4, 0, 0)));
            return sp;
        }

        UIElement EvidenceRow(Evidence ev)
        {
            var g = new Grid { Margin = new Thickness(0, 4, 0, 4) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(50) }); g.ColumnDefinitions.Add(new ColumnDefinition());
            Brush wc = ev.Weight >= 40 ? GraphView.Bad : ev.Weight >= 20 ? GraphView.Orange : ev.Weight >= 10 ? GraphView.Warn : GraphView.Muted;
            g.Children.Add(Tb((ev.Weight >= 0 ? "+" : "") + ev.Weight, 13, wc, FontWeights.Bold));
            var sp = new StackPanel(); Grid.SetColumn(sp, 1);
            sp.Children.Add(Tb(Loc.Ev(ev), 13));
            string meta = "[" + Loc.CategoryName(ev.Category) + "]" + (ev.Definitive ? "  " + L("decisive", "решающая") : "") + (string.IsNullOrEmpty(ev.Detail) ? "" : "  " + Text.Trunc(ev.Detail, 120));
            sp.Children.Add(Tb(meta, 11, Res("Muted"), null, new Thickness(0, 1, 0, 0), "Consolas"));
            g.Children.Add(sp); return g;
        }

        void AddFolderButtons(WrapPanel btns, IEnumerable<Entity> ents)
        {
            var path = ents.Select(e => e.Kind == EntityKind.Task || e.Kind == EntityKind.Registry ? null : (e.P("file") ?? e.Location)).FirstOrDefault(p => !string.IsNullOrEmpty(p) && (File.Exists(p) || Directory.Exists(p)));
            var sha = ents.Select(e => e.Sha256).FirstOrDefault(h => !string.IsNullOrEmpty(h));
            if (path != null) btns.Children.Add(Btn(L("Show in folder", "Показать в папке"), "BtnGhost", (s, e) => ShowInFolder(path)));
            if (sha != null) btns.Children.Add(Btn(L("Copy SHA-256", "Копировать SHA-256"), "BtnGhost", (s, e) => { try { Clipboard.SetText(sha); } catch { } }));
        }

        // ============================================================================================ actions
        void MarkSafe(IEnumerable<Entity> ents, string title, Finding f)
        {
            var paths = ents.Where(e => e.Kind == EntityKind.File || e.Kind == EntityKind.StartupItem || e.Kind == EntityKind.Process).Select(e => e.P("file") ?? e.Location).Where(p => !string.IsNullOrEmpty(p) && File.Exists(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (paths.Count == 0) { MessageBox.Show(W, L("This item is not a single file, so it cannot be marked as safe.", "Этот объект — не отдельный файл, поэтому пометить его безопасным нельзя."), "MineHunter", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            string msg = L("Mark as safe and stop reporting these files?\n\n", "Пометить безопасным и больше не сообщать об этих файлах?\n\n") + string.Join("\n", paths.Take(6)) + (paths.Count > 6 ? "\n…" : "") + L("\n\nOnly do this if you are sure you know what the program is.", "\n\nДелайте это, только если точно знаете, что это за программа.");
            if (MessageBox.Show(W, msg, "MineHunter", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            var al = Allowlist.Load();
            foreach (var p in paths) { al.Paths.Add(PathUtil.Normalize(p)); string h = Hashing.Sha256(p); if (h != null) al.Sha256.Add(h); }
            al.Save();
            Log.Info("Marked as safe: " + string.Join("; ", paths));
            if (f != null) { _res.Findings.Remove(f); RenderHeroFromResult(); } else if (_res != null) _res.Observations.RemoveAll(o => ents.Contains(o));
            PopulateResults();
        }

        void NeutralizeSelected(Finding f)
        {
            var chosen = _stepItems.Where(s => s.Selected && s.Enabled).Select(s => s.Step).ToList();
            if (chosen.Count == 0) { MessageBox.Show(W, L("No actions are ticked.", "Не отмечено ни одного действия."), "MineHunter", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            RunCleanup(new List<KeyValuePair<Finding, List<RemediationStep>>> { new KeyValuePair<Finding, List<RemediationStep>>(f, chosen) });
        }

        void NeutralizeAll()
        {
            if (_res == null) return;
            var plan = _res.Findings.Where(f => f.Verdict >= Verdict.HighRisk).Select(f => new KeyValuePair<Finding, List<RemediationStep>>(f, f.Steps.Where(s => s.RecommendedByDefault && s.Type != ActionType.ReviewOnly).ToList())).Where(kv => kv.Value.Count > 0).ToList();
            if (plan.Count == 0) return;
            RunCleanup(plan);
        }

        void RunCleanup(List<KeyValuePair<Finding, List<RemediationStep>>> plan, bool confirm = true)
        {
            if (_mode != Mode.Idle || _res == null) return;
            var sb = new StringBuilder();
            sb.AppendLine(L("The following will be done. Removed files and settings are saved to Quarantine and can be restored; stopped processes are not restarted.", "Будет выполнено следующее. Удаляемые файлы и настройки сохраняются в карантине и могут быть восстановлены; остановленные процессы заново не запускаются."));
            sb.AppendLine();
            foreach (var kv in plan.Take(6)) { sb.AppendLine("■ " + Loc.Title(kv.Key.Title)); foreach (var s in kv.Value.Take(6)) sb.AppendLine("     – " + Loc.Step(s)); if (kv.Value.Count > 6) sb.AppendLine("     …"); }
            if (plan.Count > 6) sb.AppendLine("… +" + (plan.Count - 6));
            sb.AppendLine(); sb.AppendLine(L("Continue?", "Продолжить?"));
            if (confirm && MessageBox.Show(W, sb.ToString(), L("Neutralize", "Обезвредить"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

            var oldRes = _res; var ctx = ScanEngine.LastContext; var opt = _lastOpt ?? new ScanOptions();
            SetBusy(Mode.Cleaning); Prog.Value = 0;
            SetHero("…", Res("Accent"), L("Neutralizing…", "Обезвреживание…"), L("Stopping processes, removing autostart entries and moving files to quarantine.", "Останавливаю процессы, убираю автозапуск и перемещаю файлы в карантин."));
            ProgText.Text = "";
            _cts = new CancellationTokenSource(); var ct = _cts.Token;
            Task.Run(() =>
            {
                var outcomes = new List<FindingOutcome>();
                foreach (var kv in plan)
                {
                    Ui(() => ProgText.Text = Loc.Title(kv.Key.Title));
                    var oc = RemediationEngine.Execute(ctx, kv.Key, kv.Value, m => Log.Info("   " + m));
                    outcomes.Add(new FindingOutcome { FindingId = kv.Key.Id, Outcome = oc });
                }
                Ui(() => { SetHero("⟳", Res("Accent"), L("Checking the result…", "Проверяю результат…"), L("A new quick scan confirms the result.", "Новая быстрая проверка подтверждает результат.")); ProgText.Text = ""; });
                var re = Verifier.Rescan(opt, oldRes.Findings, outcomes, ct, (s, p) => Ui(() => { Prog.Value = p; ProgText.Text = Loc.Progress(s); }));
                string rep = null; try { rep = ReportWriter.Write(oldRes, outcomes, ReportWriter.DefaultDir); } catch { }
                return Tuple.Create(outcomes, re, rep);
            }).ContinueWith(t => Ui(() =>
            {
                SetBusy(Mode.Idle);
                if (t.IsFaulted) { Log.Error(t.Exception.GetBaseException().ToString()); SetHero("!", Res("Bad"), L("Cleanup failed", "Не удалось обезвредить"), t.Exception.GetBaseException().Message); return; }
                var outcomes = t.Result.Item1; _res = t.Result.Item2; if (t.Result.Item3 != null) _lastReportTxt = t.Result.Item3;
                _cleanup = outcomes.Select(o => new CleanupRow { F = oldRes.Findings.First(x => x.Id == o.FindingId), Outcome = o }).ToList();
                foreach (var c in _cleanup) Log.Info("Cleanup " + Loc.Title(c.F.Title) + ": " + c.Outcome.Verdict + " — " + Loc.RescanNote(c.Outcome.RescanNote));
                RefreshStatus(); RenderHeroFromResult(); PopulateResults(); ShowCleanup();
                bool reboot = outcomes.Any(o => o.Outcome != null && o.Outcome.RebootRequired);
                bool allOk = outcomes.All(o => o.Verdict == "Remediated" || o.Verdict == "RebootRequired");
                if (_shot != null || _shotsDir != null) AfterFirstLayout();
                if (allOk && _res.Findings.Count == 0) SetHero("✓", Res("Good"), L("Cleaned and verified", "Очищено и проверено"), reboot ? L("Restart Windows to finish removing locked files.", "Перезагрузите Windows, чтобы завершить удаление занятых файлов.") : L("A new scan confirms nothing dangerous is left.", "Повторная проверка подтверждает: опасного не осталось."));
            }));
        }

        void ShowCleanup()
        {
            var P = DetailPanel; P.Children.Clear();
            ResultList.SelectedIndex = -1;
            P.Children.Add(Tb(L("Cleanup result", "Результат обезвреживания"), 21, null, FontWeights.Bold));
            P.Children.Add(Tb(L("Every item was checked again after the cleanup (a new scan).", "После очистки каждый объект был проверен заново (новая проверка)."), 12.5, Res("Muted"), null, new Thickness(0, 4, 0, 0)));
            bool reboot = _cleanup.Any(c => c.Outcome.Outcome != null && c.Outcome.Outcome.RebootRequired);
            if (reboot) P.Children.Add(new Border { Margin = new Thickness(0, 12, 0, 0), CornerRadius = new CornerRadius(9), Background = Soft(GraphView.Warn), Padding = new Thickness(14, 10, 14, 10), Child = Tb(L("RESTART WINDOWS to finish the cleanup: some files were in use and are scheduled for deletion at the next start.", "ПЕРЕЗАГРУЗИТЕ WINDOWS, чтобы завершить очистку: часть файлов была занята и будет удалена при следующем запуске."), 13, GraphView.Warn, FontWeights.SemiBold) });
            foreach (var c in _cleanup)
            {
                var o = c.Outcome; Brush acc = o.Verdict == "Remediated" ? GraphView.Good : o.Verdict == "RebootRequired" ? GraphView.Warn : o.Verdict == "Partial" ? GraphView.Orange : GraphView.Bad;
                string vt = o.Verdict == "Remediated" ? L("REMOVED AND VERIFIED", "УДАЛЕНО И ПРОВЕРЕНО") : o.Verdict == "RebootRequired" ? L("RESTART REQUIRED", "НУЖНА ПЕРЕЗАГРУЗКА") : o.Verdict == "Partial" ? L("PARTIALLY", "ЧАСТИЧНО") : L("NOT DONE", "НЕ ВЫПОЛНЕНО");
                P.Children.Add(Head(Loc.Title(c.F.Title)));
                P.Children.Add(Badge(vt, acc));
                P.Children.Add(Tb(Loc.RescanNote(o.RescanNote) ?? "", 12.5, Res("Muted"), null, new Thickness(0, 6, 0, 0)));
                foreach (var s in o.StillPresent) P.Children.Add(Tb("• " + s, 12, GraphView.Orange, null, new Thickness(0, 2, 0, 0)));
                if (o.Outcome != null)
                    foreach (var r in o.Outcome.Results)
                        P.Children.Add(Tb((r.Success ? "✓  " : "✗  ") + Loc.Step(r.Step) + (string.IsNullOrEmpty(r.Message) ? "" : "  —  " + Loc.StepMessage(r.Message)), 12, r.Success ? Res("Text") : Res("Bad"), null, new Thickness(0, 3, 0, 0)));
            }
            var btns = new WrapPanel { Margin = new Thickness(0, 16, 0, 0) };
            btns.Children.Add(Btn(Loc.T("btn.openreport"), "Btn", (s, e) => OpenPath(_lastReportTxt)));
            btns.Children.Add(Btn(L("Open Quarantine", "Открыть карантин"), "BtnGhost", (s, e) => Tabs.SelectedItem = TabQuarantine));
            P.Children.Add(btns);
            DetailScroll.ScrollToTop();
        }

        // ============================================================================================ quarantine tab
        void RefreshQuarantine()
        {
            var list = Quarantine.List();
            QList.ItemsSource = list.Select(it =>
            {
                DateTime d; string when = DateTime.TryParse(it.Created, out d) ? d.ToString("dd.MM.yyyy HH:mm") : it.Created;
                return new QItem { It = it, Title = string.IsNullOrEmpty(it.Title) ? Path.GetFileName(it.OriginalPath ?? "") : it.Title, Sub = it.OriginalPath, Meta = when + "  ·  " + Loc.Title(it.FindingTitle ?? "") + (it.Size > 0 ? "  ·  " + (it.Size / 1024) + " KB" : ""), Kind = it.Type };
            }).ToList();
            QEmpty.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            QEmpty.Text = L("Quarantine is empty. Whatever MineHunter removes is saved here and can be restored.", "Карантин пуст. То, что удалит MineHunter, сохраняется здесь и может быть восстановлено.");
            StQuarV.Text = list.Count + (list.Count > 0 ? "  " + L("item(s)", "элем.") : "");
        }

        void QuarantineRestore()
        {
            var sel = QList.SelectedItems.Cast<QItem>().ToList(); if (sel.Count == 0) return;
            if (MessageBox.Show(W, L("Restore the selected items to their original places?\nIf an item is malicious, it will become active again.", "Восстановить выбранное на прежние места?\nЕсли объект вредоносный, он снова станет активным."), "MineHunter", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            var errors = new List<string>();
            foreach (var q in sel) { string err = RemediationEngine.Restore(q.It); if (err == null) { Quarantine.Delete(q.It); Log.Info("Restored " + q.It.OriginalPath); } else errors.Add(q.Title + ": " + err); }
            RefreshQuarantine();
            if (errors.Count > 0) MessageBox.Show(W, string.Join("\n", errors), L("Some items were not restored", "Часть объектов не восстановлена"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        void QuarantineDelete(bool all)
        {
            var items = all ? QList.Items.Cast<QItem>().ToList() : QList.SelectedItems.Cast<QItem>().ToList(); if (items.Count == 0) return;
            if (MessageBox.Show(W, L("Delete " + items.Count + " item(s) from Quarantine FOREVER? They can not be restored afterwards.", "Удалить " + items.Count + " элем. из карантина НАВСЕГДА? Потом их нельзя будет восстановить."), "MineHunter", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            foreach (var q in items) { try { Quarantine.Delete(q.It); } catch (Exception ex) { Log.Warn("delete " + q.It.Id + ": " + ex.Message); } }
            RefreshQuarantine();
        }

        // ============================================================================================ about / log / misc
        void FillAbout()
        {
            var sb = new StringBuilder();
            string exe = ""; try { exe = System.Reflection.Assembly.GetExecutingAssembly().Location; } catch { }
            sb.AppendLine(L("Version: ", "Версия: ") + AppInfo.Version + "     " + L("Rules: ", "Правила: ") + (rulesVersionCache ?? (rulesVersionCache = SafeRulesVersion())));
            sb.AppendLine(L("Program: ", "Программа: ") + exe);
            sb.AppendLine(L("Data folder: ", "Папка данных: ") + RulePack.DataDir);
            sb.AppendLine(L("Reports: ", "Отчёты: ") + ReportWriter.DefaultDir);
            sb.AppendLine(L("Quarantine: ", "Карантин: ") + Quarantine.Root);
            if (!string.IsNullOrEmpty(_cfg.GitHubRepo)) sb.AppendLine(L("Project page: ", "Страница проекта: ") + _cfg.GitHubRepo);
            AbInfo.Text = sb.ToString().TrimEnd();
        }

        void AppendLog(string line)
        {
            LogBox.AppendText(line + "\n"); if (LogBox.LineCount > 3000) { LogBox.Text = string.Join("\n", LogBox.Text.Split('\n').Skip(1000)); }
            LogBox.ScrollToEnd();
        }

        static string LatestReport()
        {
            try { return Directory.GetFiles(ReportWriter.DefaultDir, "report-*.txt").OrderByDescending(f => f).FirstOrDefault(); } catch { return null; }
        }

        static void OpenPath(string p)
        {
            if (string.IsNullOrEmpty(p)) return;
            try
            {
                if (p.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) { Process.Start(new ProcessStartInfo(p) { UseShellExecute = true }); return; }
                if (File.Exists(p) || Directory.Exists(p)) Process.Start(new ProcessStartInfo(p) { UseShellExecute = true });
            }
            catch (Exception ex) { Log.Warn("open " + p + ": " + ex.Message); }
        }

        static void ShowInFolder(string p)
        {
            try { if (File.Exists(p)) Process.Start("explorer.exe", "/select,\"" + p + "\""); else if (Directory.Exists(p)) Process.Start("explorer.exe", "\"" + p + "\""); } catch { }
        }

        // ============================================================================================ window icon + dark title bar
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
        void DarkTitleBar()
        {
            try { var h = new WindowInteropHelper(W).Handle; int on = 1; if (DwmSetWindowAttribute(h, 20, ref on, 4) != 0) DwmSetWindowAttribute(h, 19, ref on, 4); } catch { }
        }

        public static ImageSource MakeIcon()
        {
            var dv = new DrawingVisual();
            using (var dc = dv.RenderOpen())
            {
                dc.DrawRoundedRectangle(new SolidColorBrush(Color.FromRgb(0x4C, 0x8D, 0xFF)), null, new Rect(0, 0, 64, 64), 16, 16);
                var g = Geometry.Parse("M32,10 L50,17 L50,31 C50,43 42,51 32,55 C22,51 14,43 14,31 L14,17 Z");
                dc.DrawGeometry(Brushes.White, null, g);
                dc.DrawGeometry(null, new Pen(new SolidColorBrush(Color.FromRgb(0x4C, 0x8D, 0xFF)), 5) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round }, Geometry.Parse("M23,32 L30,39 L42,25"));
            }
            var rtb = new RenderTargetBitmap(64, 64, 96, 96, PixelFormats.Pbgra32); rtb.Render(dv); rtb.Freeze(); return rtb;
        }

        // ============================================================================================ screenshot hook (used by the automated GUI checks)
        void AfterFirstLayout()
        {
            if ((_shot == null && _shotsDir == null) || _shotDone) return;
            _shotDone = true;
            var steps = new List<KeyValuePair<string, Action>>();
            Action<string> tab = name => { switch (name) { case "graph": Tabs.SelectedItem = TabGraph; RenderGraph(); break; case "quarantine": Tabs.SelectedItem = TabQuarantine; break; case "log": Tabs.SelectedItem = TabLog; break; case "about": Tabs.SelectedItem = TabAbout; break; default: Tabs.SelectedItem = TabResults; break; } };
            if (_shotsDir != null)
            {
                Directory.CreateDirectory(_shotsDir);
                string sfx = "_" + Loc.Lang;
                steps.Add(new KeyValuePair<string, Action>(Path.Combine(_shotsDir, "1_results" + sfx + ".png"), () => { tab("results"); if (ResultList.Items.Count > 0) ResultList.SelectedIndex = 0; }));
                steps.Add(new KeyValuePair<string, Action>(Path.Combine(_shotsDir, "2_results2" + sfx + ".png"), () => { tab("results"); if (ResultList.Items.Count > 1) ResultList.SelectedIndex = 1; }));
                steps.Add(new KeyValuePair<string, Action>(Path.Combine(_shotsDir, "3_notes" + sfx + ".png"), () => { tab("results"); CkNotes.IsChecked = true; if (ResultList.Items.Count > 2) ResultList.SelectedIndex = 2; }));
                steps.Add(new KeyValuePair<string, Action>(Path.Combine(_shotsDir, "4_graph" + sfx + ".png"), () =>
                {
                    CkNotes.IsChecked = false;
                    int best = 0, bestN = -1; for (int i = 0; i < ResultList.Items.Count; i++) { var ri = ResultList.Items[i] as ResultItem; if (ri != null && ri.F != null && ri.F.Entities.Count > bestN) { bestN = ri.F.Entities.Count; best = i; } }
                    if (ResultList.Items.Count > 0) ResultList.SelectedIndex = best; tab("graph");
                }));
                steps.Add(new KeyValuePair<string, Action>(Path.Combine(_shotsDir, "5_quarantine" + sfx + ".png"), () => tab("quarantine")));
                steps.Add(new KeyValuePair<string, Action>(Path.Combine(_shotsDir, "6_log" + sfx + ".png"), () => tab("log")));
                steps.Add(new KeyValuePair<string, Action>(Path.Combine(_shotsDir, "7_about" + sfx + ".png"), () => tab("about")));
            }
            else
                steps.Add(new KeyValuePair<string, Action>(_shot, () => { if (_shotNotes) CkNotes.IsChecked = true; tab(_shotTab ?? "results"); if (_shotSelect >= 0 && _shotSelect < ResultList.Items.Count) ResultList.SelectedIndex = _shotSelect; }));
            int idx = 0;
            var t = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(900) };
            bool prepared = false;
            t.Tick += (s, e) =>
            {
                try
                {
                    if (idx >= steps.Count) { t.Stop(); W.Close(); return; }
                    if (!prepared) { steps[idx].Value(); prepared = true; return; }
                    W.UpdateLayout();
                    var content = (FrameworkElement)System.Windows.Media.VisualTreeHelper.GetChild(W, 0);
                    var rtb = new RenderTargetBitmap((int)content.ActualWidth, (int)content.ActualHeight, 96, 96, PixelFormats.Pbgra32); rtb.Render(content);
                    var enc = new PngBitmapEncoder(); enc.Frames.Add(BitmapFrame.Create(rtb));
                    using (var fs = File.Create(steps[idx].Key)) enc.Save(fs);
                    idx++; prepared = false;
                }
                catch (Exception ex) { Log.Error("shot: " + ex.Message); idx++; prepared = false; }
            };
            t.Start();
        }
    }
}
