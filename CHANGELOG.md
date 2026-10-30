# CHANGELOG

## v0.6.1 (2026-10-30)
- Нова вкладка **IED Simulator** — MMS-сервер одного IED з CID / SCD для перевірки сигналів у SCADA без IED (кілька клієнтів одночасно):
  - ISO-стек (COTP / Session / Presentation / ACSE / MMS Initiate), Identify (manufacturer / type / configVersion з CID), GetNameList, Read (змінні і датасети), GetVariableAccessAttributes, GetNamedVariableListAttributes, Write атрибутів RCB;
  - модель з CID: LN / FC / DO / DA, значення DAI / Val, датасети, RCB (екземпляри при indexed), GoCB;
  - **звіти** URCB / BRCB: резервування (Resv / ResvTms / Owner = IP клієнта), TrgOps dchg / qchg / dupd / integrity / GI, BufTm, OptFlds, BRCB буфер (EntryID, BufOvfl, PurgeBuf);
  - значення **вручну**: Set (data change), Toggle / подвійний клік, Update (data update), Quality (validity + біти) → quality change; t оновлюється;
  - пошук сигналу, таблиці Clients / Report control blocks, Log;
  - **Listen IP** з поясненнями: 0.0.0.0 (усі адреси ПК), адреси ПК з назвою адаптера, IP IED з CID («on this PC» / «NOT on this PC»); підказка, до якого IP має підключатися SCADA; за замовчуванням — IP IED, якщо він є на ПК, інакше 0.0.0.0;
  - **IED IP on this PC...** — додати IP IED (маска з CID) другою адресою адаптера (netsh від імені адміністратора) і прибрати після тесту; адаптер з DHCP (інтернет) — попередження, бо фіксований IP вимикає DHCP; **Restore DHCP** повертає автоматичну адресу і DNS (Remove IP робить це сам, якщо адаптер був на DHCP);
  - команди SCADA не приймаються (object-access-denied);
  - звіти, викликані запитом (GI, буфер BRCB), надсилаються після відповіді на запит; внутрішня помилка не розриває з'єднання, а пишеться в Log (з текстом для розбору); опція **Log every MMS PDU**;
  - підказка з адресами ПК, згрупованими за адаптером (Wi-Fi: …; Ethernet 5: …);
  - ReasonCode у звітах — 6 біт (як у IED і libiec61850): з 7 бітами IEDScout розривав з'єднання при першому звіті.
- Перевірено з власним клієнтом (Active: порівняння з CID — без відмінностей) і з клієнтом libiec61850 (звіти GI / data change).
- MMS client: Write (для тестів), закриття з'єднання надсилає FIN одразу.

## v0.6.0 (2026-10-30)
- Нова вкладка **MMS → Active** — власний MMS-клієнт (лише читання, одне з'єднання, нічого не записує в IED):
  - **Connect** за IP (з CID або вручну, останні 10 IP запам'ятовуються): COTP / Session / Presentation / ACSE / MMS Initiate, Identify (виробник, модель, версія), max PDU;
  - **дерево моделі** LD → LN → FC → DO → DA (GetNameList), вибір вузла = читання з назвами атрибутів і типами (GetVariableAccessAttributes + GetDataValues); великий LN читається по FC;
  - **Monitor**: опитування вибраних вузлів кожні 1000 мс (налаштовується), час останньої зміни, кількість змін;
  - **Data sets**: склад усіх датасетів і читання значень датасету; назви передаються вкладкам Passive і GOOSE;
  - **Control blocks**: усі URCB / BRCB / GoCB — free / reserved / IN USE by IP-клієнта (Owner), RptID, DatSet, ConfRev, TrgOps, OptFlds, IntgPd, BufTm; GoEna, GoID, MAC / APPID / VLAN;
  - **Compare with CID**: LD / LN, датасети (склад і порядок), RCB, GoCB — відмінності червоним;
  - **Log** з опцією показу кожного MMS PDU;
  - IED, які в GetNameList віддають лише логічні вузли (без DO / DA), — члени LN беруться з типу LN (GetVariableAccessAttributes) при розкритті вузла, RCB / GoCB — з типу LLN0;
  - значення датасету: читання датасету цілком, а якщо IED відмовляє — по елементах (по 20 у запиті); подвійний клік на датасеті = читання;
  - **Auto refresh every … ms** (за замовчуванням 1000): автоматично оновлюються Monitor, прочитані датасети (вкладка Data sets) і вузол у Values (на місці, дерево не згортається); змінене значення — жовтим;
  - **TRUE / on — зеленим**, FALSE / off — чорним (Values, Monitor, Data sets; для DO — за stVal або general).
- Report test: TrgOps у CID без атрибута `gi` тепер означає gi = true (значення за замовчуванням SCL).

## v0.5.0 (2026-10-30)
- Нова вкладка **MMS → Report test** — перевірка звітів одного IED за його CID (пасивно, з трафіку SCADA або з pcap):
  - **CID check**: RptID ↔ ReportControl, DatSet, ConfRev, кількість елементів датасету, data reference (назви), типи значень (DataTypeTemplates), причини ↔ TrgOps, OptFlds ↔ OptFields, звіти RCB, яких немає в CID;
  - **покриття сигналів**: для кожного елемента датасетів RCB — data change, quality change, data update, integrity, GI (перший час, кількість), останнє значення; можливі причини = TrgOps RCB ∩ тригери атрибута (dchg / qchg / dupd) з DataTypeTemplates, інакше n/a;
  - для BOOLEAN / Dbpos data change вимагає **обидва стани** (TRUE / FALSE, on / off) і показує **мінімальний час між станами**;
  - обов'язкові для «completed» за замовчуванням: data change, GI, integrity; quality change і data update — галочками; покриття — по датасету (будь-який екземпляр RCB);
  - «**RCB test completed - all signals verified - дата час**»;
  - **Save / Open test** (.json, автозбереження кожні 30 с після першого Save), **Export CSV** (Excel);
  - RCB без датасету в CID (GE UR: датасети налаштовані в IED) — звіти тестуються з датасетом, побаченим у трафіку (назви з data reference / GetDataSetDirectory).

## v0.4.1 (2026-10-30)
- MMS / Passive: кнопки **Show: Report / Client / Server / Protocol error / TCP / COTP / Session** — показати або сховати групу повідомлень (як в IEDScout), вибір зберігається. Повідомлення з помилкою (наприклад Read з object-non-existent) належить і до Client / Server, і до Protocol error.
- Назви сервісів IEC 61850 (ACSI), як в IEDScout: GetDataValues, SetDataValues, Select, SelectWithValue, Operate, Cancel, Get / SetURCBValues, Get / SetBRCBValues, GetServerDirectory, GetLogicalDeviceDirectory, GetDataSetDirectory, GetDataDirectory ... (сервіс MMS — у Details).
- **CommandTermination (positive / negative)** — InformationReport після Operate; negative з AddCause.
- **Назви елементів датасету з MMS:** програма запам'ятовує склад датасету з відповідей GetDataSetDirectory і зі звітів із data reference; на вкладці GOOSE (якщо немає SCL) у стовпці Signal з'являються ці назви з позначкою «(from MMS)». Так само назви для звітів без data reference.

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
