# Актуальные майнеры/загрузчики (2025–2026) и что из этого попало в MineHunter

Источники — публичные отчёты, найденные 24–25.09.2026 (краткое содержание получено через веб-выборку, детали
проверяйте по первоисточникам):

* Securelist — [SilentCryptoMiner распространяется как «обход блокировок»](https://securelist.com/silentcryptominer-spreads-through-blackmail-on-youtube/115788/)
* The Hacker News — [SilentCryptoMiner заразил ~2000 российских пользователей](https://thehackernews.com/2025/03/silentcryptominer-infects-2000-russian.html)
* The Hacker News (04.2026) — [ISO-приманки: RAT + майнеры, watchdog, WinRing0](https://thehackernews.com/2026/04/researchers-uncover-mining-operation.html)
* Microsoft Security Blog (26.05.2026) — [GPU-майнинг через отравленный поиск, ScreenConnect и .NET-утилиты](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/)
* The Hacker News (09.2026) — [модули REVSTEALER отключают Windows Update и Defender ради майнера](https://thehackernews.com/2026/09/four-revstealer-linked-modules-disable.html)
* Infosecurity Magazine — [вредоносные расширения VS Code для криптоджекинга](https://www.infosecurity-magazine.com/news/microsoft-vs-code-cryptojacking/)
* Microsoft Support — [VulnerableDriver:WinNT/Winring0](https://support.microsoft.com/en-us/windows/microsoft-defender-antivirus-alert-vulnerabledriver-winnt-winring0-eb057830-d77b-41a2-9a34-015a5d203c42)

## Технические приёмы → детекты MineHunter (общие, не привязанные к одному семейству)

| Приём в дикой природе | Как ловит MineHunter |
|---|---|
| Process hollowing в подписанные .NET-утилиты (`InstallUtil`, `RegAsm`, `RegSvcs`, `MSBuild`, `AppLaunch`, `AddInProcess`, `aspnet_compiler`) и в `dwm.exe`, `nslookup.exe`, `svchost.exe` | сверка заголовка образа в памяти с файлом на диске (TimeDateStamp/SizeOfImage/EntryPoint), отсутствие mapped-file, PE в приватной executable-памяти; «LOLBin-цель + внешняя сеть + без аргументов»; `dwm.exe` с внешним соединением |
| Раздутые файлы (680–800 МБ, повторяющиеся блоки) против песочниц | PE > 100 МБ, не подписан, малая энтропия/повторы в трёх выборках |
| Исключения Defender (`AppData`, `ProgramData`, `*.exe`, имена майнеров) | реестр `Exclusions` (local + policy): путь целиком диск/`ProgramData`/Temp/AppData, `.exe`, имена майнеров |
| Отключение Defender/Windows Update, sleep/hibernate | блок «Состояние защиты» (только информирование, вердикт малвари сам по себе не выносится) |
| Постоянство в 3–6 местах сразу (`Windows System Health*` задачи, Run `WinSysCache`, ярлык в Startup) | все механизмы связываются в один граф; `Microsoft`-подобные имена задач с не-Microsoft действием; повторяющийся триггер ≤ 5 мин; Run+Task+Startup на один файл |
| Служба-маскировка (`DrvSvc` с описанием «Windows Image Acquisition») | служба с системным описанием, но образ не подписан/в пользовательской папке |
| Скрытые файлы System+Hidden в `%LocalAppData%\Microsoft\Windows\Caches\<8hex>\` | любой PE внутри `AppData\…\Microsoft\Windows\**` вне известных подпапок; атрибуты Hidden+System |
| DLL side-loading (`autorun.dll` рядом с подписанной утилитой) | подписанный EXE + неподписанная DLL из его же папки, загруженная в процесс |
| Уязвимый драйвер WinRing0 для тюнинга MSR | драйверные службы (`Type=1`) и `WinRing0*.sys`; учитывается законное использование (HWiNFO и т.п.) → слабая улика, сильная в комбинации |
| Watchdog, восстанавливающий удалённое | граф: взаимные ссылки процесс↔задача/служба, повторяющийся триггер, респавн; лечение целой компонентой + rescan |
| Майнер паузится при запуске Task Manager/Process Hacker | CPU — лишь одна из улик; смотрим на статичные признаки и persistence, а не только на нагрузку |
| Конфиг с Pastebin/GitHub, пул-прокси на 443 | строки/аргументы (stratum, wallet-регэксп, `--donate-level`), постоянное соединение неподписанного процесса, DNS-кэш по маскам пулов |
| Вредоносные расширения VS Code и браузеров | сканер расширений (manifest + майнер-строки + force-install политики) |
| Отравленный поиск / LLM-рекомендации → фейковые «утилиты» (CrystalDiskInfo, HWMonitor, DDU, FurMark…) | поддельный бренд: имя/описание известной утилиты у неподписанного файла в пользовательской папке |

Честное ограничение: правила — это эвристики и списки индикаторов. Они не дают гарантии обнаружения любых новых
вредоносных программ, поэтому в MineHunter заложены обновляемые пакеты правил (см. `docs/UPDATES.md`).
