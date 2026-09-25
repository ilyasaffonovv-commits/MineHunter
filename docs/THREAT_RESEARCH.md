# Источники правил

Правила детекта основаны на открытых отчётах о майнерах и загрузчиках 2025 и 2026 годов. Ссылки собраны 24 и 25 сентября 2026 года, краткое содержание получено через веб-выборку, детали стоит проверять по первоисточникам.

- Securelist, [SilentCryptoMiner распространяется как средство обхода блокировок](https://securelist.com/silentcryptominer-spreads-through-blackmail-on-youtube/115788/)
- The Hacker News, [SilentCryptoMiner заразил около 2000 российских пользователей](https://thehackernews.com/2025/03/silentcryptominer-infects-2000-russian.html)
- The Hacker News, апрель 2026, [ISO-приманки, RAT и майнеры, watchdog, WinRing0](https://thehackernews.com/2026/04/researchers-uncover-mining-operation.html)
- Microsoft Security Blog, 26.05.2026, [GPU-майнинг через отравленный поиск, ScreenConnect и .NET-утилиты](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/)
- The Hacker News, сентябрь 2026, [модули REVSTEALER отключают Windows Update и Defender ради майнера](https://thehackernews.com/2026/09/four-revstealer-linked-modules-disable.html)
- Infosecurity Magazine, [вредоносные расширения VS Code для криптоджекинга](https://www.infosecurity-magazine.com/news/microsoft-vs-code-cryptojacking/)
- Microsoft Support, [VulnerableDriver:WinNT/Winring0](https://support.microsoft.com/en-us/windows/microsoft-defender-antivirus-alert-vulnerabledriver-winnt-winring0-eb057830-d77b-41a2-9a34-015a5d203c42)

## Приёмы и соответствующие проверки

Здесь перечислено только то, что есть в коде. Идентификаторы правил описаны в [RULES.md](RULES.md).

| Приём | Проверка |
|---|---|
| Process hollowing в подписанные .NET-утилиты (`InstallUtil`, `RegAsm`, `RegSvcs`, `MSBuild`, `AppLaunch`, `AddInProcess`, `aspnet_compiler`) и в `dwm.exe`, `nslookup.exe`, `svchost.exe` | Заголовок образа в памяти сравнивается с файлом на диске (`SizeOfImage`, `EntryPoint`, `TimeDateStamp`, решающая улика при расхождении в двух и более полях) и проверяется, привязан ли основной образ к файлу. PE-образы в приватной исполняемой памяти. Внешние соединения у процессов из списка `neverExternalNetwork` (`NET.SYSTEM_TOOL_EXTERNAL`). Системные утилиты из списка `hollowTargets`, полностью приостановленные дольше минуты (`PROC.SUSPENDED_LOLBIN`). |
| Раздутые файлы против песочниц | `PE.BLOATED`: файл больше 100 МБ с оверлеем больше 50 МБ, в котором почти все проверенные блоки состоят из повторяющихся данных. |
| Исключения Defender (`AppData`, `ProgramData`, `*.exe`, имена майнеров) | Исключения в реестре, локальные и из политик: целый диск, `ProgramData`, Temp, AppData, расширения, имена майнеров. Правила командной строки для `Add-MpPreference` и изменений реестра. |
| Отключение Defender и его служб | Правила командной строки `CMD.DEFENDER.*`. Состояние защиты (Defender или другой антивирус, UAC, SmartScreen, брандмауэр, обновления Windows) показывается в блоке состояния системы и вердикта сам по себе не выносит. Отключение сна и гибернации учитывается только как слабая улика в командной строке (`CMD.POWERCFG.NEVER`). |
| Закрепление сразу в нескольких местах | Все способы автозапуска связываются в один граф, `PERSIST.MULTI` при нескольких способах для одного файла. Имена, характерные для описанных кампаний (`Windows System Health*`, `WinSysCache`, `DrvSvc`, задачи в `\Microsoft\Windows\WindowsBackup`). Задачи под `\Microsoft\` с недоверенным действием. Задача с интервалом повтора не больше 10 минут (`TASK.REPEAT_SHORT`). |
| Служба под видом компонента Windows | `SVC.FAKE_DESCRIPTION`: описание или имя выдают компонент Windows, а файл службы не подписан. |
| Скрытые файлы в `%LocalAppData%\Microsoft\Windows\Caches\<8hex>\` | `IOC.PATH.RUNTIMEHOST_CACHES`, `LOC.APPDATA_MS_WINDOWS`, атрибуты Hidden и System (`ATTR.HIDDEN_SYSTEM`). |
| Подмена DLL (`autorun.dll` рядом с подписанной утилитой) | `PROC.SIDELOAD_CANDIDATE`: подписанный exe загрузил неподписанную DLL из своей пользовательской папки. Только для загруженных модулей запущенных процессов. |
| Уязвимый драйвер WinRing0 для настройки MSR | `DRV.VULNERABLE_KNOWN`: драйвер из списка имён в правилах. Вес 14, потому что тот же драйвер используют утилиты мониторинга железа. |
| Watchdog, восстанавливающий удалённое | Связи процесс, задача, служба в графе, `WATCHDOG.MULTI_PAYLOAD`, `TASK.REPEAT_SHORT`, `SVC.AUTO_RESTART_UNTRUSTED`. При обезвреживании процессы сначала замораживаются, затем убирается вся находка целиком и запускается повторная проверка. Отдельного признака «воскрес после удаления» нет. |
| Конфигурация майнера и пул-прокси | Строки и параметры в командной строке (`stratum`, шаблоны кошельков Monero и Ethereum, `--donate-level`), домены пулов из DNS-кэша, порты майнинга, долгие внешние соединения неподписанных программ. Прокси на порту 443 отдельно не распознаётся. |
| Вредоносные расширения VS Code и браузеров | Расширения VS Code, Cursor и Windsurf: код майнера и скрипты, отключающие защиту или скачивающие код. Расширения браузеров: код майнера, опасные разрешения, установка по политике. |
| Подмена имён и сведений о версии | Гомоглифы (`ReaItekHD`, заглавная I вместо l), имена системных файлов не в папке Windows, сведения о версии, выдающие компонент Windows у неподписанного файла (вес 22), и сведения известного производителя без его подписи (вес 3, так выглядят и обычные сборки). |

Не реализовано:
- Сопоставление имён известных утилит (CrystalDiskInfo, HWMonitor, DDU, FurMark) с неподписанными файлами из пользовательских папок. Такие файлы попадают под общие правила: расположение, отсутствие подписи, автозапуск, строки майнера.
- Отдельное правило для ScreenConnect и других инструментов удалённого доступа. Есть правила для RDP Wrapper (`CMD.RDP.WRAPPER`, `TAMPER.TERMSERVICE_DLL`).
- Обнаружение майнеров, которые приостанавливаются при запуске диспетчера задач. Загрузка CPU остаётся слабой уликой, вердикт строится на статических признаках и автозапуске.

Правила эвристические и не гарантируют обнаружения новых программ. Поэтому пакеты правил обновляются отдельно от программы ([UPDATES.md](UPDATES.md)).
