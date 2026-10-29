# CHANGELOG

## v0.2.0 (2026-10-29)
- Вкладка **GOOSE Publisher**: симуляція GOOSE за CID / SCD (кілька IED одночасно), значення задаються вручну (у т. ч. аналогові; Quality — validity і всі біти, кнопки для всіх Quality датасету), Simulation ON за замовчуванням (OFF — з підтвердженням), STOP ALL, перевірка конфлікту gocbRef, повтор MinTime → MaxTime.
- Перевірка оновлень на GitHub при запуску (реліз за тегом), смужка «New version … available» з Download; у вікні «?» — галочка і кнопка «Check for updates». Збірка exe і реліз — GitHub Actions за тегом `v*`.
- Програма називається **IEC61850ANALYZER** (вікно, exe `IEC61850ANALYZER_v0.2.0.exe`, налаштування `~/.iec61850analyzer.json`; старі налаштування `~/.iec61850_sniffer.json` підхоплюються).
- Вкладка **PTP** (IEEE 1588 / IEC 61850-9-3, Ethernet і UDP): список повідомлень, Details, TLV (C37.238), панель **Clocks** — GM за BMCA, анонсовані годинники, інтервал Sync, попередження, перевірка 9-3. Retransmission / LOST / фільтри як для GOOSE.
- Фільтр діє окремо для кожної вкладки (правило з Type — лише для неї); над списком «Filter ON: N of M messages hidden».
- SV: **gmIdentity** у Details і порівняння з GM вкладки PTP.
- Кнопка **?**: коротке повідомлення (англійською, кнопка «Українська»), ім'я автора — посилання на LinkedIn (`AUTHOR_URL` у `sniffer.py`), пошта ge.scout@gevernova.com — клік відкриває новий лист (Outlook) з темою «IEC61850ANALYZER v0.2.0 - problem report».
- Панель кнопок компактніша: Files (Load SCD / CID, Open .pcap), View (Columns, Signal).
- GOOSE: стовпець **IEDName** після Time (з SCD / CID, без SCL — частина gocbRef до `/` у дужках).
- Стовпці **LAN** (A / B з PRP-трейлера), **VLAN ID** і **Prio** окремо. LAN входить у ключ потоку.
- SV: панель **Phasors** — RMS, кут, True RMS, частота вибраного потоку.
- **Primary / Secondary**: Secondary лише якщо потік збігається з SV control block SCL (svID, MAC, APPID, confRev, канали); коефіцієнти TCTR / TVTR `Rat.setMag.f`.
- **Filters...**: потоки, що прийшли (галочка Show), свої правила (маски, діапазони APPID / VLAN), фільтр симуляції. За замовчуванням вимкнено.
- Ознака симуляції (GOOSE simulation / Reserved1 S, SV Reserved1 S): помаранчевий фон, `[SIM]`.
- Демо-запис оновлено, додано `tools/demo_mu.scd`.
- IEDName без SCL: назва LD в кінці прибирається (`W1G_D60Master` → `W1G_D60`), без дужок.
- Стовпець Description → **gocbRef** (GOOSE) / **svID** (SV). APPID і VLAN ID — hex і dec.
- Стовпець **Network** (був Net): назва мережі з Adapters... (наприклад PB A / PB B) замість 1 / 2; видно лише під час захоплення з двома мережами.
- **Columns...** / правий клік на заголовку: показати / сховати кожен стовпець (зберігається).
- Правий клік на рядку: правило фільтра з одного поля (лише MAC, лише APPID, VLAN, gocbRef / svID, IEDName, тип) або весь потік.
- Phasors: вибір **Angle reference** (Auto, Ia … Vn), зберігається.
- Data (SV): миттєві значення відліку з урахуванням Primary / Secondary, стовпець RMS (Phasors). Secondary без SCL, що збігається, — `—` (у Phasors і Data). Потік не 9-2LE без SCL — лише raw.

## v0.1.0 (2026-10-29)
- Перша версія: GOOSE / SV, 2 мережі, Retransmission, STREAM LOST, SCL-назви, відкриття pcap.
