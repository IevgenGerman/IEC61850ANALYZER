# IEC61850ANALYZER (GOOSE / SV / PTP / MMS / GOOSE Publisher) — v0.4.1

Програма для перегляду трафіку **GOOSE**, **Sampled Values (9-2 / 9-2LE)** і **PTP (IEEE 1588 / IEC 61850-9-3)** у мережі, за зразком вікна Sniffer в OMICRON IEDScout. Автор: German Ievgen.

MMS у цій версії не розбирається.

## Встановлення (Windows)

1. Встановити **Npcap**: https://npcap.com. Під час встановлення увімкнути «WinPcap API-compatible mode». Це той самий драйвер, що ставить Wireshark.
2. Запуск із вихідного коду (головний файл — `sniffer.py`):
   ```
   pip install -r requirements.txt
   python sniffer.py
   ```
   або зібрати `.exe`: двічі клацнути `build_exe.bat`. Результат: `dist\IEC61850ANALYZER v0.4.1.exe`.
3. Якщо адаптер не відкривається, запустіть програму від імені адміністратора.

## Вікно

| Елемент | Що робить |
|---|---|
| **Adapters...** | вибір адаптера і **назви** мережі **Network 1** і (галочка) **Network 2**, наприклад PB A / PB B або PRP LAN A / LAN B. Вибір запам'ятовується |
| **Start / Pause / Stop / Clear** | захоплення. Pause зупиняє лише оновлення списку, захоплення триває |
| **Auto scroll** | список прокручується до останнього повідомлення |
| **Retransmission** | увімкнено: показуються **всі** повідомлення. Вимкнено: див. нижче |
| **Filter** / **Filters...** | фільтр показу (за замовчуванням вимкнено), див. «Фільтри» |
| **Analog (SV): Primary / Secondary** | одиниці в панелі Phasors, див. «Аналоги» |
| **Files: Load SCD / CID...** | назви сигналів датасетів (можна завантажити кілька файлів) |
| **Columns...** (група View) або **правий клік на заголовку списку** | показати / сховати будь-який стовпець списку поточної вкладки; «Network - always» — показувати Network завжди (інакше лише з двома мережами); «Show all columns». Зберігається окремо для GOOSE і SV |
| **правий клік на рядку** (у списку або в Filters → Streams seen) | додати правило фільтра з **одного поля**: лише Source MAC, лише Destination MAC, лише APPID, VLAN ID, gocbRef / svID, IEDName, тип, або весь потік. Фільтр вмикається |
| **View: Signal (SCL)** | показати / сховати стовпець з назвами сигналів (`Gen/UsrPbIHMI1.Activated.stVal [ST]`) |
| **Files: Open .pcap...** | розбір записаного трафіку (наприклад, з Wireshark) без мережі |
| вкладки **GOOSE** / **Sampled Values** | список повідомлень (Time, **IEDName** — лише GOOSE, Relative time, **Network**, **LAN**, Source, Destination, APPID, **VLAN ID**, **Prio**, **gocbRef** / **svID**, Event); праворуч **Details** і **Data** |
| **APPID** / **VLAN ID** | hex і dec: `0x4011 (16401)`, `27 (0x01B)` |
| **Event** | чому рядок показано: **first** — перше повідомлення потоку, **change** — змінилися значення / якість (GOOSE) або якість (SV), **lost** — потік зник, **back** — потік повернувся, порожньо — звичайне повторення (лише з Retransmission) |
| **Network** | через яку мережеву карту ПК прийшов кадр — назва, яку ти задаєш в **Adapters...** (наприклад `PB A` / `PB B`, `Station bus` / `Process bus`; за замовчуванням Network 1 / Network 2). Потрібен, коли слухаєш дві мережі: без PRP-трейлера (LAN = `-`) лише він показує, з якої мережі кадр. Стовпець видно лише під час захоплення з двома мережами |
| **LAN** | з PRP-трейлера (RCT) у кінці кадру: **A** / **B**. `-` = трейлера немає: пристрій SAN, не PRP, або RedBox / комутатор його прибрав. Номер послідовності і LSDU size — у Details, рядок PRP LAN |
| **VLAN ID** / **Prio** | VLAN ID і пріоритет з тегу 802.1Q. Порожньо, якщо тегу немає (або мережева карта його вирізала) |
| **IEDName** (GOOSE) | з завантаженого SCD / CID за gocbRef — точна назва (`W1G_D60`). Без SCL — частина gocbRef до `/` без назви LD в кінці (`W1G_D60Master` → `W1G_D60`): прибираються відомі назви LD (Master, System, LD0, CTRL, PROT, MEAS …) і всі LD із завантажених SCL |
| **помаранчевий фон, [SIM]** | повідомлення з ознакою симуляції: GOOSE — поле simulation або біт S у Reserved1, SV — біт S у Reserved1 (Ed2). Ввімкнення / вимкнення симуляції = зміна (рядок change) |
| рядок стану | що захоплюється, адаптери, «показано / захоплено» для GOOSE і SV, стан фільтра, SCL |

### Аналоги (вкладка Sampled Values, панель Phasors)

- Для вибраного потоку: **RMS** основної гармоніки (DFT за один період), **кут** відносно опорного каналу — вибір **Angle reference** (Auto, Ia … Vn; Auto = перша напруга з сигналом, інакше перший струм; опорний — жирним; якщо на вибраному каналі немає сигналу — Auto), **True RMS**, **частота**. Під час захоплення оновлюється кожні 0,5 с; для файлу — стан на кінець запису.
- Відліків на період: smpRate з кадрів → smpRate з SCL → з переходу smpCnt через нуль → 80 (9-2LE).
- **Primary:** 9-2LE — струм 1 мА, напруга 10 мВ на одиницю. Тип каналу (I / U) з SCL (TCTR / TVTR), інакше порядок 9-2LE: 4 струми, 4 напруги.
- **Secondary** = первинне / **Rat** (TCTR / TVTR `Rat.setMag.f` каналу; для Бучі 300 і 1100). Лише коли потік **збігається** з SampledValueControl завантаженого SCD / CID: svID = smvID, MAC призначення, APPID, confRev, кількість каналів (і smpRate, якщо є в кадрах). Різний VLAN — лише попередження (мережева карта може вирізати тег). Якщо не збігається — показується Primary і причина (наприклад `confRev 1, SCL 2`).
- Номінальна частота: `HzRtg` з SCL, інакше 50 Гц.
- **Data** (внизу) — **миттєві** значення одного відліку вибраного кадру (`Instant value, smpCnt N`), а не діюче значення: для 300 A RMS вони змінюються від −424 до +424 A. Поруч — стовпець **RMS (Phasors)** цього каналу.
- Однакові правила для Phasors і Data:

| Режим | SCD / CID збігається з потоком | SCD / CID немає або не збігається |
|---|---|---|
| Primary | A / V первинні | A / V первинні для 9-2LE (8 каналів); інший потік — лише raw |
| Secondary | A / V вторинні (первинні / Rat) | `—`, лише raw і причина червоним |

- Кути рахуються і без масштабу (за raw).
- **In у потоці** — виміряний струм нейтралі MU. Розрахунковий In у D60 / EnerVista = Ia + Ib + Ic, при однофазній подачі через нейтраль вони протилежні за знаком (кут 180°); виміряний канал у D60 — це вхід землі Ig.
- Якщо однаковий smvID є в кількох файлах (наприклад, копія потоку в CID захисту), береться той, що збігається найкраще і має коефіцієнти.

### PTP (вкладка PTP)

- Захоплюються PTP-кадри Ethernet (**0x88F7**, IEC 61850-9-3 / IEEE C37.238) і UDP/IPv4 (порти **319 / 320**, звичайний 1588).
- **Список:** Time, Relative time, Network, LAN, Source, Destination, VLAN ID, Prio, **Message type** (Sync, Follow_Up, Announce, Pdelay_Req / Resp / Resp_Follow_Up, Delay_Req / Resp, Signaling, Management), **Domain**, **Clock identity - port**, **Seq**, **Interval** (logMessageInterval), **Info** (Announce: GM, class, пріоритети, steps, джерело часу; Follow_Up: точний час), Event.
- **Retransmission вимкнено:** перше повідомлення кожного типу від кожного годинника, далі лише **зміни** (Announce: GM, пріоритети, clockClass, accuracy, steps, джерело часу, UTC offset; прапорці; домен). **STREAM LOST** — немає повідомлень довше 3 інтервалів (9-3: 3 с).
- **Details:** заголовок (версія, домен, прапорці twoStep / leap / UTC offset valid / ptpTimescale / time-, frequencyTraceable, correctionField, clock identity, port, sequenceId, інтервал), час повідомлення, requesting port (Pdelay / Delay_Resp), дані Announce. **TLV:** розшифровка C37.238-2011 / 2017 (GM time inaccuracy, network time inaccuracy), PATH_TRACE, ALTERNATE_TIME_OFFSET; інші — hex.
- **Clocks:** усі годинники, що шлють Announce / Sync: Network, LAN, домен, анонсований **Grandmaster**, P1, Class, Accuracy, P2, Steps, Time source, **виміряний інтервал Sync**, two-step, перевірка **IEC 61850-9-3** (домен 0, лише Ethernet, P2P без Delay_Req, інтервали Sync / Announce / Pdelay = 1 с, MAC 01:1B:19:00:00:00 / 01:80:C2:00:00:0E). Над таблицею — **Grandmaster за BMCA** для кожного домену; знизу червоним — попередження: кілька GM в домені, clockClass не 6 (GPS втрачено, holdover, free running), Sync без Announce, Announce без Sync, кілька доменів, годинник зник.
- **SV:** у Details потоку — **gmIdentity** (9-2 Ed2.1) і порівняння з Grandmaster вкладки PTP: «= grandmaster (OK)» або червоним «DIFFERENT».
- Обмеження: Npcap дає програмні мітки часу (~мс) — **точність / offset PTP програма не вимірює**, лише показує, що анонсують годинники, і грубий інтервал Sync. Для вимірювання точності потрібен CMC / вимірювач з апаратними мітками.

### MMS (вкладка MMS → Passive / Active)

- **Passive** — програма лише слухає MMS (TCP **102**) між SCADA та IED, нічого не відправляє.
- Комутатор передає MMS (unicast) лише в порт адресата, тому ноутбук на сусідньому порту MMS **не бачить**. Потрібно: **port mirroring (SPAN)** порту IED / SCADA на порт ноутбука, **TAP** / hub, або захоплення на сервері SCADA (pcap → Open .pcap...).
- Список: Time, Network, IEDName (сервер, за IP з `Communication / Address / IP` у SCL), Source / Destination IP:port, Dir (C→S клієнт → сервер, S→C), **Message**, **Reason**, Invoke ID, Info. Стовпці Relative time і LAN за замовчуванням сховані (Columns...).
- Повідомлення: TCP connect / close / reset, COTP CR / CC / DR, Session / ACSE, **Initiate** (max PDU), **GetNameList**, **Read** (у відповіді — назви запитаних об'єктів, помилки object-non-existent тощо червоним), **Write**, GetVariableAccessAttributes, GetNamedVariableListAttributes, Identify, Confirmed error, Reject, Conclude.
- Кнопки **Show:** над списком — групи повідомлень (як в IEDScout): **Report** (звіти, InformationReport), **Client / Server** (запити / відповіді, Initiate, Operate, CommandTermination), **Protocol error** (помилки, Reject, невдале керування, Read / Write з помилкою, TCP reset, пропуск у захопленні), **TCP / COTP / Session** (з'єднання). Рядок видно, якщо увімкнена хоча б одна його група.
- **Message** — назва сервісу IEC 61850 (ACSI), як в IEDScout: GetDataValues, SetDataValues, Select, SelectWithValue, Operate, Cancel, Get / SetURCBValues, Get / SetBRCBValues, GetServerDirectory, GetLogicalDeviceDirectory, GetDataSetDirectory, GetDataDirectory …; сервіс MMS (Read, Write, GetNameList …) — у Details. **CommandTermination (positive / negative)** — після Operate; negative з AddCause.
- **Report** (IEC 61850-8-1): у списку RptID, SeqNum, кількість елементів і **Reason**: *data change*, *quality change*, *data update*, *integrity (period)*, *general interrogation*, *application trigger*. При виборі: RptID, OptFlds, SeqNum, TimeOfEntry, DatSet, ConfRev, EntryID, BufOvfl, SubSeqNum, Inclusion і кожен елемент: номер у датасеті, причина, значення (структури деревом) і назва сигналу (з data reference звіту або з датасету SCL за DatSet / RptID).
- **LastApplError** — невдале керування: CntrlObj, Error, Origin, ctlNum, **AddCause** людською мовою (Blocked-by-interlocking, Blocked-by-Mode …), червоним.
- TCP збирається з сегментів (довгі звіти / відповіді), повтори ігноруються; пропуск у захопленні — рядок «Capture gap», далі синхронізація.
- Зашифрований MMS (TLS, IEC 62351, порт 3782) прочитати неможливо.
- **Active** (MMS-клієнт лише для читання: модель, значення, звіти через вільний RCB) — пізніше.

### GOOSE Publisher (вкладка GOOSE Publisher) — симуляція GOOSE за CID

- **Load CID / SCD...** — GOOSE control blocks файлу. **CID / IID / ICD: лише власний IED файлу** (інші IED у CID — копії видавців, на яких він підписаний); SCD — усі IED. Можна завантажити кілька файлів (наприклад D60.cid і F60.cid). Один рядок = одна адреса GSE (IED з двома точками доступу має два рядки).
- З SCL береться все: gocbRef, datSet, goID (appID), confRev, MAC, APPID, VLAN ID / priority, MinTime / MaxTime, склад датасету і **тип кожного елемента** (BOOLEAN, Dbpos, Quality, Timestamp, INT, FLOAT32 / 64, Enum, рядки, структури для FCD).
- **Control blocks:** клік у першому стовпці — галочка «публікувати». Стан: stNum / sqNum; червоним — помилка відправки або **CONFLICT** (цей gocbRef у мережі приходить ще з іншого MAC — два видавці збивають підписників).
- **Data set** вибраного блоку: значення задаються вручну (статично): BOOLEAN (галочка або подвійний клік), Dbpos (on / off / intermediate / bad), Quality — validity (good / invalid / questionable / reserved) і **всі біти**: overflow, outOfRange, badReference, oscillatory, failure, oldData, inconsistent, inaccurate, substituted, test, operatorBlocked; кнопки **All q of this data set** — одним кліком good / invalid / questionable / test on / test off / reset для всіх Quality датасету (одна зміна, stNum + 1), Enum (зі списку), числа (у тому числі **аналогові FLOAT32**), рядки. Timestamp — автоматично (час останньої зміни). Зміна значення у блоці, що публікується, відправляється відразу: stNum + 1.
- **Network** — адаптер (Network 1 / 2 з Adapters...). Джерельний MAC — MAC адаптера.
- **Simulation** — за замовчуванням **ON** (поле simulation = TRUE і біт S Reserved1, Ed2): такі GOOSE приймають лише IED у режимі симуляції (LPHD.Sim). Вимкнути — тільки після підтвердження; тоді це звичайні GOOSE і підписники **реагують**. **Needs commissioning** — прапорець ndsCom.
- **Start ticked** — підтвердження (адаптер, список блоків, Simulation) і старт; **STOP ALL** — зупинити все (також при закритті програми).
- Відправка за IEC 61850-8-1: heartbeat кожні MaxTime (sqNum + 1); після зміни — одразу, далі MinTime, 2×, 4× … до MaxTime; TAL = 2 × час до наступного повідомлення. Точність ~1 мс (достатньо для перевірки підписки та логіки, не для вимірювання часів — для цього CMC).
- Свої повідомлення видно на вкладці GOOSE, якщо там іде захоплення на тому ж адаптері.

### Фільтри (кнопка Filters...)

- **Filter enabled** / галочка **Filter** на панелі. Вимкнено — показується все.
- **Streams seen** — усі потоки, що вже прийшли (тип, IEDName, Net, LAN, MAC, APPID, VLAN, gocbRef / svID, кількість кадрів, SIM, стан). Клік у стовпці **Show** — показувати цей потік (точне правило: тип, Net, LAN, MAC, APPID, посилання). **Show all streams** / **Remove stream rules**.
- **Правило з одного поля** — правий клік на рядку (наприклад «APPID = 0x4011» або «Destination MAC = 01:0C:CD:04:01:11»), або в Rules заповнити лише одне поле і Add rule.
- **Rules** — свої правила: Type, Net, LAN, Source, Destination, APPID (hex: `4011`, `4000-4FFF`, `1055,104F`), VLAN (`27`, `27-32`), gocbRef / svID, IEDName (текст; `*` і `?` — шаблони, без них — точний збіг). Порожнє поле = будь-яке. Подвійний клік — увімкнути / вимкнути правило.
- Правила діють **окремо для кожної вкладки**: правило з Type = GOOSE / SV / PTP — лише для своєї вкладки, правило без Type — для всіх. Вкладка, для якої немає жодного активного правила, показує все (тому правило «APPID = 0x4011» для SV не ховає GOOSE і PTP). Правила з правого кліку отримують Type вкладки.
- Повідомлення показується, якщо підходить **хоча б під одне** активне правило своєї вкладки (АБО); у правилі всі заповнені поля (І).
- Над списком червоним: **Filter ON: N of M messages hidden** — скільки рядків сховав фільтр. Панелі Phasors і Clocks фільтр не змінює.
- **Simulation:** all / only simulated / without simulated.
- Фільтр змінює лише показ: захоплення, Retransmission і лічильники не змінюються. Рядок STREAM LOST показується разом зі своїм потоком. Налаштування фільтра зберігаються.

### Retransmission вимкнено

- **GOOSE:** перше повідомлення кожного потоку, далі лише коли **змінилося значення або якість** будь-якого елемента датасету (`Event` = first / change).
- **SV:** перший кадр кожного потоку, далі лише коли **змінилася якість** будь-якого каналу; значення ігноруються.
- Потік = Network + LAN + MAC джерела + MAC призначення + APPID + gocbRef / svID. Тому той самий PRP GOOSE з LAN A і LAN B показується двічі (різний `LAN`), навіть якщо обидві копії прийшли на один адаптер.

### Зникнення потоку

- GOOSE не прийшов довше, ніж **TAL** з останнього повідомлення, або SV довше **1 с**: сірий рядок **STREAM LOST**.
- Коли потік з'являється знову, перше повідомлення показується зеленим (`Event` = back).

### Details / Data

- **GOOSE:** Control Block reference, MAC, APPID, GOOSE ID, DataSet, VLAN, needs commissioning, confRev, simulation, entry time, stNum, sqNum, TAL, кількість елементів.
  - **Data:** Boolean, Dbpos (on / off / intermediate / bad), Quality (розшифровано: good / invalid / questionable, test …), Integer, Unsigned, Float, Timestamp, структури (деревом).
- **SV:** svID, MAC, APPID, DataSet, VLAN, кількість ASDU, smpCnt, confRev, smpSynch, smpRate, smpMod.
  - **Data:** 8 каналів 9-2LE (Ia, Ib, Ic, In — 1 мА; Va, Vb, Vc, Vn — 10 мВ) з якістю кожного.

## Оновлення (GitHub)

- При запуску програма у фоні читає з GitHub останній реліз репозиторію `GITHUB_REPO` (у `sniffer.py`) і порівнює його тег (`v0.2.1`) з `VERSION`. Якщо на GitHub новіша версія — жовта смужка під кнопками: **Download** (exe з релізу), **Release page**, **Hide**.
- Немає мережі / проксі / GitHub недоступний — нічого не показується, програма працює як звичайно (тайм-аут 5 с, окремий потік).
- Вікно **?**: галочка «Check for updates at start» і кнопка «Check for updates».
- Потрібен **публічний** репозиторій (для приватного GitHub API без токена відповідає 404 — перевірка мовчки не спрацює).
- Лише стандартна бібліотека Python (urllib, json) — у `requirements.txt` нічого додавати не треба.

### Як випустити нову версію

Коротко: змінити `VERSION` у `sniffer.py`, `CHANGELOG.md`, `COMMIT_MSG.txt` і двічі клацнути **`release.bat`** (коміт з текстом `COMMIT_MSG.txt`, push, тег = версія, push тегу). Вручну:

1. У `sniffer.py` змінити `VERSION = "v 0.2.1"`, дописати CHANGELOG і переписати `COMMIT_MSG.txt` (текст коміту і релізу). Перше завантаження — `first_push.bat`.
2. ```
   git add -A
   git commit -F COMMIT_MSG.txt
   git push
   git tag -a v0.2.1 -F COMMIT_MSG.txt
   git push origin v0.2.1
   ```
3. GitHub Actions (`.github/workflows/build.yml`) запускає тести, збирає `IEC61850ANALYZER_v0.2.1.exe` і додає його до релізу `v0.2.1`. Після цього всі, хто запускає старішу версію, побачать смужку «New version v0.2.1 is available».

## Файли

| Файл | Що це |
|---|---|
| `sniffer.py` | вікно програми |
| `sniff_core.py` | розбір GOOSE / SV, потоки, Retransmission, зникнення потоку |
| `scl_names.py` | назви сигналів, IEDName, SV control blocks (адреса, confRev, Rat / HzRtg каналів) з SCD / CID / ICD / IID |
| `analog.py` | RMS / кут / частота SV, перевірка збігу з SCL, Primary / Secondary |
| `filters.py` | правила фільтра |
| `capture.py` | адаптери і захоплення (Npcap / libpcap через Scapy). Захоплюються лише кадри 0x88B8, 0x88BA, 0x88F7, UDP 319 / 320 і TCP 102, з VLAN і без |
| `tools/make_frames.py`, `tools/make_demo.py`, `tools/demo_goose_sv.pcap` | побудова тестових кадрів і демо-запис: GOOSE D60 (PRP LAN A + B) / F60 зі змінами і зникненням потоку, симульований GOOSE, 3 потоки SV (200 A / 63,5 кВ, PRP LAN A; один зі зміною якості, один симульований, 49,8 Гц; gmIdentity), PTP: GM з GPS (clockClass 6 → 7 на 7 с, TLV C37.238), Pdelay комутатора, другий майстер з 9 с (class 248, інтервал 2 с) |
| `tools/demo_mu.scd` | демо-SCL до запису: MU01_QW1G збігається (300/1, 110 кВ / 100 В — є Secondary), MU02_QW1G має confRev 2 (Secondary немає, видно причину) |
| `ptp.py` | розбір PTP, годинники, BMCA, перевірка 9-3 |
| `updater.py` | перевірка нової версії на GitHub |
| `mms.py` | пасивний розбір MMS: TCP, ISO-стек, MMS, звіти 61850 |
| `goose_pub.py`, `pub_tab.py` | GOOSE Publisher: SCL → кадри, відправка, вкладка |
| `tools/demo_ied.cid` | демо-CID для тестів публікатора і MMS (синтетичний: IP 192.168.1.20, ReportControl urcbA) |
| `.github/workflows/build.yml` | збірка exe і реліз на GitHub за тегом `v*` |
| `tests/test_core.py` | перевірка розбору, фільтра, аналогів, PTP |
| `build_exe.bat`, `exe_name.py` | збірка `.exe` з версією в назві |

## Обмеження v0.2.0

- MMS, Subscribe GOOSE, експорт (CSV / pcap) — пізніше.
- Деякі мережеві карти на Windows вирізають VLAN-тег до того, як кадр дійде до Npcap. Тоді стовпець VLAN порожній.
- Secondary для MU320e з поточних ICD / SCD Бучі не буде: там шаблонні Rat 200 / 1000, smvID `IEDNameMU0101`, APPID 0x4000. Потрібен реальний CID MU.
- Retransmission для SV показує тисячі кадрів на секунду. У списку зберігаються останні 50 000 рядків кожної вкладки.
