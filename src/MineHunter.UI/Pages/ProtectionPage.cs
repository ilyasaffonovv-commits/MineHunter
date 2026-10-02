using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MineHunter.Guards;
using MineHunter.Util;

namespace MineHunter.Gui
{
    /// <summary>The real-time layer, component by component. Each one can be switched on and off on its own and shows its real state (on, off, limited, error). The wording is honest: it watches and
    /// reports; it does not stand in the kernel and it does not claim to stop a program before it starts.</summary>
    public sealed class ProtectionPage : PageBase
    {
        public override string Key { get { return "protection"; } }
        public override string Title { get { return L("Protection", "Защита"); } }
        public override string Icon { get { return "shield"; } }
        readonly StackPanel cards = new StackPanel(); readonly StackPanel alerts = new StackPanel(); readonly TextBlock top = Ui.Txt("", 12.5, Ui.Muted);

        static readonly string[][] Defs = {
            new[] { "file", "folder" }, new[] { "download", "download" }, new[] { "process", "procs" }, new[] { "script", "file" }, new[] { "persistence", "startup" }, new[] { "network", "network" }, new[] { "usb", "usb" }, new[] { "ransomware", "lock" } };

        public ProtectionPage(AppModel model, Func<Window> ownerFn) : base(model, ownerFn)
        {
            var intro = Ui.Card(Ui.V(Ui.Txt(L("How this protection works", "Как работает эта защита"), 14, null, FontWeights.Bold), Ui.Txt(L("These components watch your PC while MineHunter is running (the window or the icon in the tray) and tell you when something looks wrong. They look at files after they appear and at programs as they start: MineHunter does not sit in the Windows kernel and does not block programs before they run. Several independent signs have to agree before it speaks up, so ordinary programs are left alone.", "Эти компоненты следят за ПК, пока запущен MineHunter (окно или значок в трее), и сообщают, когда что-то выглядит неправильно. Они смотрят на файлы после их появления и на программы в момент запуска: MineHunter не сидит в ядре Windows и не блокирует программы до запуска. Чтобы он заговорил, должны совпасть несколько независимых признаков, поэтому обычные программы не трогаются."), 12.5, Ui.Muted, null, true, new Thickness(0, 4, 0, 0))), 16, Ui.B("Surface2"));
            intro.Margin = new Thickness(0, 0, 0, 12);
            var head = new StackPanel(); head.Children.Add(Header(L("Protection", "Защита"), L("Real-time components, one by one.", "Компоненты защиты в реальном времени, по одному."))); head.Children.Add(intro);
            var body = new StackPanel(); body.Children.Add(cards); body.Children.Add(Ui.Head(L("Settings", "Настройки"))); body.Children.Add(Options()); body.Children.Add(Ui.Head(L("Recent warnings", "Последние предупреждения"))); body.Children.Add(alerts);
            View = Frame(head, Ui.Scroll(body));
            m.StateChanged += () => { if (View.IsVisible) RenderCards(); };
        }

        public override void OnShow(object arg) { if (m.Guards == null) m.StartGuards(); RenderCards(); RenderAlerts(); }

        string Describe(string name)
        {
            switch (name)
            {
                case "file": return L("Watches the places where programs land (Temp, AppData, Startup folders, USB drives) and gives every new program or script a quick look: signature, structure, markers.", "Следит за местами, куда попадают программы (Temp, AppData, папки автозагрузки, USB-диски), и быстро проверяет каждую новую программу и скрипт: подпись, структуру, маркеры.");
                case "download": return L("Watches Downloads, the Desktop and the folders your browsers save to. Checks a downloaded file when it is complete: where it came from, signature, structure, reputation.", "Следит за Загрузками, Рабочим столом и папками, куда сохраняют браузеры. Проверяет скачанный файл, когда он докачан: откуда, подпись, структура, репутация.");
                case "process": return L("Looks at every new program and who started it (a document starting PowerShell, an archive starting a program from Temp). One odd thing is not an alarm; independent ones together are.", "Смотрит на каждую новую программу и на то, кто её запустил (документ запускает PowerShell, архив запускает программу из Temp). Одна странность не тревога; несколько независимых вместе — да.");
                case "script": return L("Reads scripts (PowerShell, VBScript, JScript, HTA, batch) when they start or appear, and asks Windows' own antivirus interface (AMSI). A plain download-and-unzip script is left alone.", "Читает скрипты (PowerShell, VBScript, JScript, HTA, bat), когда они запускаются или появляются, и спрашивает собственный антивирусный интерфейс Windows (AMSI). Обычный скрипт «скачать и распаковать» не трогается.");
                case "persistence": return L("Compares the autostart places every few seconds: Run keys, Startup folders, tasks, services, Defender exclusions, hosts, firewall rules, WMI, PowerShell profiles. Says what changed and, when it can tell, which program did it.", "Сверяет места автозапуска каждые несколько секунд: ключи Run, папки автозагрузки, задачи, службы, исключения Defender, hosts, правила брандмауэра, WMI, профили PowerShell. Говорит, что изменилось и, если можно понять, какая программа это сделала.");
                case "network": return L("Notices new outside connections of programs that are not trusted (TCP). Cutting a program off is done with a Windows Firewall rule, on your click.", "Замечает новые внешние соединения программ, которым не доверяют (TCP). Отрезать программу от сети можно правилом брандмауэра Windows — по вашему клику.");
                case "usb": return L("When a drive is plugged in, takes a quick smart look: autorun.inf, shortcuts that replace folders, programs named like folders, hidden programs and scripts.", "При подключении накопителя быстро и осмысленно его просматривает: autorun.inf, ярлыки вместо папок, программы с именами папок, скрытые программы и скрипты.");
                default: return L("Off by default. Places hidden decoy files in Documents, Desktop and Pictures and watches for files being rewritten and renamed in bulk. If it fires, it names the program that writes the most and offers to freeze it; it never does so by itself.", "По умолчанию выключено. Кладёт скрытые файлы-приманки в Документы, Рабочий стол и Изображения и следит за массовой перезаписью и переименованием файлов. Если сработает, назовёт программу, которая пишет больше всех, и предложит заморозить её; сам этого не сделает.");
            }
        }

        string TitleOf(string name)
        {
            switch (name) { case "file": return L("File Guard", "Контроль файлов"); case "download": return L("Download Guard", "Контроль загрузок"); case "process": return L("Process Guard", "Контроль процессов"); case "script": return L("Script Guard", "Контроль скриптов"); case "persistence": return L("Persistence Guard", "Контроль автозапуска"); case "network": return L("Network Guard", "Контроль сети"); case "usb": return L("USB Guard", "Контроль USB"); default: return L("Ransomware Guard", "Защита от шифровальщиков"); }
        }

        bool Get(string n) { var s = m.S; return n == "file" ? s.FileGuard : n == "download" ? s.DownloadGuard : n == "process" ? s.ProcessGuard : n == "script" ? s.ScriptGuard : n == "persistence" ? s.PersistenceGuard : n == "network" ? s.NetworkGuard : n == "usb" ? s.UsbGuard : s.RansomwareGuard; }
        void Set(string n, bool v) { var s = m.S; if (n == "file") s.FileGuard = v; else if (n == "download") s.DownloadGuard = v; else if (n == "process") s.ProcessGuard = v; else if (n == "script") s.ScriptGuard = v; else if (n == "persistence") s.PersistenceGuard = v; else if (n == "network") s.NetworkGuard = v; else if (n == "usb") s.UsbGuard = v; else s.RansomwareGuard = v; }

        void RenderCards()
        {
            cards.Children.Clear();
            var statuses = m.Guards == null ? new List<GuardStatus>() : m.Guards.Statuses();
            foreach (var d in Defs)
            {
                string name = d[0]; var st = statuses.FirstOrDefault(x => x.Name == name);
                bool on = Get(name); var state = st != null ? st.State : (on ? GuardState.Limited : GuardState.Off);
                Brush c = state == GuardState.On ? Ui.Good : state == GuardState.Limited ? Ui.Warn : state == GuardState.Error ? Ui.Bad : state == GuardState.RestartRequired ? Ui.Orange : Ui.Muted;
                var sw = new CheckBox { Style = Ui.S("Switch"), IsChecked = on, VerticalAlignment = VerticalAlignment.Center };
                string nm = name; sw.Click += (s, e) => { Set(nm, sw.IsChecked == true); m.S.Save(); if (nm == "ransomware" && sw.IsChecked == true) Info(L("Ransomware protection places a few hidden decoy files in your Documents, Desktop and Pictures folders. They are removed again when you switch this off.", "Защита от шифровальщиков кладёт несколько скрытых файлов-приманок в папки Документы, Рабочий стол и Изображения. При выключении они убираются.")); m.StartGuards(); };
                var mid = new StackPanel { Margin = new Thickness(14, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
                mid.Children.Add(Ui.H(Ui.Txt(TitleOf(name), 14.5, null, FontWeights.Bold, false), Ui.Pill(st == null ? (on ? L("starting…", "запускается…") : L("Off", "Выключено")) : st.StateText, c, 10.5)));
                ((FrameworkElement)((StackPanel)mid.Children[0]).Children[1]).Margin = new Thickness(10, 0, 0, 0);
                mid.Children.Add(Ui.Txt(Describe(name), 12, Ui.Muted, null, true, new Thickness(0, 4, 0, 0)));
                if (st != null && !string.IsNullOrEmpty(st.Detail) && on) mid.Children.Add(Ui.Txt(st.Detail, 11.5, c, null, true, new Thickness(0, 4, 0, 0)));
                var card = Ui.Card(Ui.Cols(new[] { "Auto", "*", "Auto" }, Ui.Badge(d[1], c, 42), mid, sw), 16); card.Margin = new Thickness(0, 0, 0, 8); cards.Children.Add(card);
            }
        }

        UIElement Options()
        {
            var s = m.S; var p = new StackPanel();
            p.Children.Add(Ui.Sw(L("Game mode: no heavy work and only critical warnings while a full-screen game or presentation is on", "Игровой режим: никакой тяжёлой работы и только критические предупреждения, пока на экране полноэкранная игра или презентация"), s.GameMode, v => { s.GameMode = v; s.Save(); }));
            p.Children.Add(Ui.Sw(L("Check a USB drive automatically when it is plugged in", "Проверять USB-накопитель автоматически при подключении"), s.UsbAutoCheck, v => { s.UsbAutoCheck = v; s.Save(); }));
            p.Children.Add(Ui.Sw(L("Start the tray icon (and with it this protection) when I sign in to Windows", "Запускать значок в трее (а с ним эту защиту) при входе в Windows"), s.StartTrayAtLogon, v => { s.StartTrayAtLogon = v; s.Save(); string err = ScheduleManager.Apply(s); if (err != null) Info(err); }));
            p.Children.Add(Ui.Head(L("Which warnings to show", "Какие предупреждения показывать"), new Thickness(0, 12, 0, 6)));
            p.Children.Add(Ui.Combo(new[] { Ui.Kv("Info", L("Everything, including notes", "Всё, включая заметки")), Ui.Kv("Suspicious", L("Suspicious and dangerous (recommended)", "Подозрительное и опасное (рекомендуется)")), Ui.Kv("Dangerous", L("Only dangerous", "Только опасное")) }, s.NotifyLevel, v => { s.NotifyLevel = v; s.Save(); }, 380));
            return Ui.Card(p, 18);
        }

        void RenderAlerts()
        {
            alerts.Children.Clear();
            var list = (m.Guards == null ? new List<GuardAlert>() : m.Guards.Recent).ToList();
            if (list.Count == 0) list = GuardHost.LoadAlerts();
            if (list.Count == 0) { alerts.Children.Add(Ui.Txt(L("Nothing so far.", "Пока ничего."), 13, Ui.Muted)); return; }
            foreach (var a in list.Take(40))
            {
                Brush c = a.Level == AlertLevel.Dangerous ? Ui.Bad : a.Level == AlertLevel.Suspicious ? Ui.Warn : Ui.Accent;
                var sp = new StackPanel { Margin = new Thickness(12, 0, 0, 0) };
                sp.Children.Add(Ui.H(Ui.Pill(a.LevelText.ToUpperInvariant(), c, 10), Ui.Txt(a.Time.ToString("dd.MM HH:mm") + "  ·  " + a.Title, 13, null, FontWeights.SemiBold, false, new Thickness(10, 0, 0, 0))));
                sp.Children.Add(Ui.Txt(a.Text, 12, Ui.TextB, null, true, new Thickness(0, 4, 0, 0)));
                var btns = Ui.Wrap();
                if (!string.IsNullOrEmpty(a.Path) && File.Exists(a.Path)) { var al = a; btns.Children.Add(Ui.Btn(L("Why?", "Почему?"), () => m.Navigate("files", al.Path), "BtnSmall")); if (a.Level >= AlertLevel.Suspicious) btns.Children.Add(Ui.Btn(L("Quarantine", "В карантин"), () => { string err = GuardHost.QuarantineFile(al.Path, al.Title, al.Pid); Info(err ?? L("Moved to the quarantine.", "Перемещено в карантин.")); }, "BtnSmall")); btns.Children.Add(Ui.Btn(L("It is fine", "Это безопасно"), () => { if (Ask(L("Stop reporting this exact file?", "Больше не сообщать об этом файле?"))) { string err = GuardHost.Allow(al.Path); Info(err ?? L("Done.", "Готово.")); } }, "BtnSmall")); }
                if (btns.Children.Count > 0) { btns.Margin = new Thickness(0, 8, 0, 0); sp.Children.Add(btns); }
                var card = Ui.Card(sp, 14); card.Margin = new Thickness(0, 0, 0, 8); alerts.Children.Add(card);
            }
        }
    }
}
