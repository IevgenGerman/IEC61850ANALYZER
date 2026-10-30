# CHANGELOG

## v0.4.1 (2026-10-30)
- MMS / Passive: кнопки **Show: Report / Client / Server / Protocol error / TCP / COTP / Session** — показати або сховати групу повідомлень (як в IEDScout), вибір зберігається. Повідомлення з помилкою (наприклад Read з object-non-existent) належить і до Client / Server, і до Protocol error.
- Назви сервісів IEC 61850 (ACSI), як в IEDScout: GetDataValues, SetDataValues, Select, SelectWithValue, Operate, Cancel, Get / SetURCBValues, Get / SetBRCBValues, GetServerDirectory, GetLogicalDeviceDirectory, GetDataSetDirectory, GetDataDirectory ... (сервіс MMS — у Details).
- **CommandTermination (positive / negative)** — InformationReport після Operate; negative з AddCause.

## v0.4.0 (2026-10-29)
- Нова вкладка **MMS** з підрозділами **Passive** / **Active** (Active — пізніше).
- **MMS / Passive** — пасивний розбір MMS (TCP 102) між SCADA та IED (потрібен mirror-порт, TAP або файл захоплення):
  - збирання TCP-потоку (кілька сегментів, повтори, пропуски в захопленні), TPKT, COTP (CR / CC / DT / DR), Session, Presentation, ACSE;
  - список як для GOOSE: час, IEDName (за IP із SCL), Source / Destination IP:port, напрям C→S / S→C, повідомлення, **причина людською мовою**, Invoke ID, інформація;
  - Initiate / Conclude, GetNameList, Read (з назвами запитаних об'єктів у відповіді), Write, GetVariableAccessAttributes, GetNamedVariableListAttributes, Identify, помилки, Reject;
  - **звіти IEC 61850-8-1**: RptID, OptFlds, SeqNum, TimeOfEntry, DatSet, ConfRev, EntryID, BufOvfl, сегментація, Inclusion, значення і причини: data change, quality change, data update, integrity (period), general interrogation, application trigger; назви сигналів — з data reference у звіті або з датасету SCL;
  - **LastApplError** (невдале керування) з AddCause (наприклад Blocked-by-interlocking);
  - помилки червоним, події TCP / COTP / Session сірим; при виборі рядка — повна розшифровка (Details + дерево даних).
- Захоплення: додано TCP 102.

## v0.3.0 (2026-10-29)
- Нова вкладка **GOOSE Publisher** — симуляція GOOSE IED за CID / SCD:
  - CID / IID / ICD — лише власний IED файлу, SCD — усі IED; кілька IED і блоків одночасно (галочки);
  - з SCL: gocbRef, datSet, goID, confRev, MAC, APPID, VLAN, MinTime / MaxTime, типи елементів датасету;
  - значення вручну: BOOLEAN, Dbpos, Enum, числа й аналогові FLOAT32, рядки; редактор внизу завжди видно, подвійний клік — швидке введення;
  - **Quality**: validity і всі біти (overflow … test, operatorBlocked); кнопки «All q of this data set» (good / invalid / questionable / test on / test off / reset) — одна зміна stNum;
  - Simulation ON за замовчуванням (OFF — з підтвердженням), Needs commissioning, підтвердження перед Start, **STOP ALL**, зупинка при закритті;
  - повтор за IEC 61850-8-1: одразу, MinTime, 2×, 4× … MaxTime; TAL = 2 × час до наступного;
  - попередження **CONFLICT**, якщо той самий gocbRef іде з іншого пристрою.

## v0.2.0 (2026-10-29)
- Перевірка оновлень на GitHub при запуску (реліз за тегом), смужка «New version … available» з Download; у вікні «?» — галочка і кнопка «Check for updates». Збірка exe і реліз — GitHub Actions за тегом `v*`.
- Програма називається **IEC61850ANALYZER** (вікно, exe `IEC61850ANALYZER v0.2.0.exe`, налаштування `~/.iec61850analyzer.json`; старі налаштування `~/.iec61850_sniffer.json` підхоплюються).
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
