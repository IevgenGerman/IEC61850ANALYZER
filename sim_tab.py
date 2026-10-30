# -*- coding: utf-8 -*-
"""
sim_tab.py - tab IED Simulator of IEC61850ANALYZER: the PC answers as one IED of a CID (MMS server),
so that SCADA (Zenon, IEDScout, ...) can be tested without the IED.

  Load CID / SCD...    the IED to simulate (CID: its own IED; SCD: choose the IED)
  Listen IP / Port     the IP of the IED must be an address of this PC (Windows: network adapter /
                       IPv4 / Advanced / IP addresses: Add) - or point SCADA to the IP of the PC
  Start / Stop         MMS server on TCP 102; several clients at the same time
  Model tree           every signal with its value; select a node -> editor:
                       value (TRUE / FALSE, on / off, enum, number, text) -> Set: data change report
                       Update: same value again (data update), quality (validity + detail bits)
                       double-click a BOOLEAN / Dbpos signal: toggle
  Clients / RCBs / Log who is connected, which report control block is enabled by whom, reports sent

Commands from SCADA (Select / Operate) are refused (object-access-denied) in this version; only the
attributes of the report control blocks can be written by the clients.
"""
import queue
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import goose_pub as gp
import ied_model as im
import mms_server as ms
import sim_goose as sg

GREEN = "#1a6e1a"
RED = "#b00020"
ORANGE = "#b35900"
GREY = "#8a8a8a"
ON = "#00a000"
DUMMY = "#dummy"
ALL_TEXT = "0.0.0.0   - all addresses of this PC"
VALUE_PATHS = (["stVal"], ["general"], ["mag", "f"], ["mag", "i"], ["cVal", "mag", "f"], ["instMag", "f"],
               ["setVal"], ["setMag", "f"], ["ctlVal"])


def iid_of(dom, item=""):
    return "%s|%s" % (dom, item)


def split_iid(iid):
    d, _, i = iid.partition("|")
    return d, i


def child(n, path):
    for p in path:
        n = next((k for k in n["kids"] if k["name"] == p), None)
        if n is None:
            return None
    return n


class SimTab(ttk.Frame):
    def __init__(self, master, app, settings=None, save=None):
        super().__init__(master)
        self.app = app
        self.settings = settings or {}
        self.save = save
        self.model = None
        self.server = None
        self.events = queue.Queue()
        self.kids = {}
        self.path = None
        self.gcbs = []                     # GOOSE of the simulated IED (sim_goose)
        self.pub = None
        self.listen = ""
        self.summary = ""
        self.pc = []
        self.target = None                 # node edited (value)
        self.qnode = None                  # node edited (quality)
        self._build()
        self.after(200, self._tick)
        self.after(1000, self._refresh)

    # ------------------------------------------------------------ GUI
    def _build(self):
        bg = "#f3f3f3"
        bar = tk.Frame(self, bg=bg, pady=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Load CID / SCD...", command=self.load).pack(side="left", padx=(4, 2))
        tk.Label(bar, text="IED:", bg=bg).pack(side="left", padx=(6, 2))
        self.v_ied = tk.StringVar()
        self.c_ied = ttk.Combobox(bar, textvariable=self.v_ied, state="readonly", width=16)
        self.c_ied.pack(side="left")
        self.c_ied.bind("<<ComboboxSelected>>", lambda e: self._load_ied(self.v_ied.get()))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        tk.Label(bar, text="Listen IP:", bg=bg).pack(side="left", padx=(0, 2))
        self.v_ip = tk.StringVar(value=ALL_TEXT)
        self.c_ip = ttk.Combobox(bar, textvariable=self.v_ip, width=46, values=[ALL_TEXT])
        self.c_ip.pack(side="left")
        self.c_ip.bind("<<ComboboxSelected>>", lambda e: self._ip_hint())
        ttk.Button(bar, text="IED IP on this PC...", command=self.ip_dialog).pack(side="left", padx=(4, 0))
        tk.Label(bar, text="Port:", bg=bg).pack(side="left", padx=(6, 2))
        self.v_port = tk.StringVar(value=str(self.settings.get("sim_port", 102)))
        ttk.Entry(bar, textvariable=self.v_port, width=6).pack(side="left")
        self.b_start = tk.Button(bar, text="▶ Start server", command=self.start, bg="#2e7d32", fg="white",
                                 activebackground="#1b5e20", activeforeground="white", relief="flat", padx=10)
        self.b_start.pack(side="left", padx=(8, 2))
        ttk.Button(bar, text="■ Stop", command=self.stop).pack(side="left", padx=2)
        self.st_lbl = tk.Label(bar, text="stopped", bg=bg, fg=GREY, padx=8)
        self.st_lbl.pack(side="left")
        self.info = tk.Label(self, text="Load the CID of the IED to simulate.", anchor="w", justify="left", padx=8,
                             pady=2)
        self.info.pack(fill="x")

        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True)
        self.pw = pw
        # ---- model tree
        lf = ttk.Frame(pw)
        hf = tk.Frame(lf, bg="#4a5566")
        hf.pack(fill="x")
        tk.Label(hf, text="Data model (values of the simulated IED)", bg="#4a5566", fg="white", anchor="w",
                 padx=6).pack(side="left")
        ff = tk.Frame(lf)
        ff.pack(fill="x")
        tk.Label(ff, text="Find:").pack(side="left", padx=(4, 2))
        self.v_find = tk.StringVar()
        e = ttk.Entry(ff, textvariable=self.v_find, width=24)
        e.pack(side="left", fill="x", expand=True)
        e.bind("<Return>", lambda ev: self.find_next())
        ttk.Button(ff, text="Next", command=self.find_next).pack(side="left", padx=2)
        tf = ttk.Frame(lf)
        tf.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tf, columns=("value", "type"), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Name", anchor="w")
        self.tree.heading("value", text="Value", anchor="w")
        self.tree.heading("type", text="Type", anchor="w")
        self.tree.column("#0", width=300)
        self.tree.column("value", width=230)
        self.tree.column("type", width=90, stretch=False)
        vs = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="left", fill="y")
        self.tree.tag_configure("ld", font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("on", foreground=ON)
        self.tree.tag_configure("bad", foreground=RED)
        self.tree.bind("<<TreeviewOpen>>", self._on_open)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", self._on_double)
        pw.add(lf, weight=1)
        # ---- right side
        rf = ttk.Frame(pw)
        pw.add(rf, weight=1)
        ed = ttk.LabelFrame(rf, text=" Signal ")
        ed.pack(fill="x", padx=4, pady=4)
        self.ed_ref = tk.Label(ed, text="select a signal in the tree", anchor="w", font=("Segoe UI", 9, "bold"))
        self.ed_ref.grid(row=0, column=0, columnspan=6, sticky="w", padx=6, pady=(2, 4))
        tk.Label(ed, text="Value:").grid(row=1, column=0, sticky="w", padx=6)
        self.v_val = tk.StringVar()
        self.c_val = ttk.Combobox(ed, textvariable=self.v_val, width=28)
        self.c_val.grid(row=1, column=1, sticky="w")
        self.c_val.bind("<Return>", lambda e: self.set_value())
        ttk.Button(ed, text="Set", command=self.set_value).grid(row=1, column=2, padx=2)
        ttk.Button(ed, text="Toggle", command=self.toggle).grid(row=1, column=3, padx=2)
        ttk.Button(ed, text="Update (same value)", command=self.update_same).grid(row=1, column=4, padx=2)
        self.val_type = tk.Label(ed, text="", fg="#666")
        self.val_type.grid(row=1, column=5, sticky="w", padx=4)
        tk.Label(ed, text="Quality:").grid(row=2, column=0, sticky="w", padx=6, pady=(6, 0))
        self.v_valid = tk.StringVar(value="good")
        ttk.Combobox(ed, textvariable=self.v_valid, values=list(gp.QUAL_VALIDITY), state="readonly",
                     width=12).grid(row=2, column=1, sticky="w", pady=(6, 0))
        ttk.Button(ed, text="Set quality", command=self.set_quality).grid(row=2, column=2, padx=2, pady=(6, 0))
        self.q_lbl = tk.Label(ed, text="", fg="#666")
        self.q_lbl.grid(row=2, column=3, columnspan=3, sticky="w", padx=4, pady=(6, 0))
        qf = tk.Frame(ed)
        qf.grid(row=3, column=0, columnspan=6, sticky="w", padx=6, pady=(2, 4))
        self.v_flags = {}
        for i, (_, nm) in enumerate(gp.QUAL_FLAGS):
            v = tk.BooleanVar(value=False)
            self.v_flags[nm] = v
            ttk.Checkbutton(qf, text=nm, variable=v).grid(row=i // 6, column=i % 6, sticky="w", padx=(0, 8))
        tk.Label(ed, text="Set: data change report (dchg)   Update: data update (dupd)   Set quality: quality "
                          "change (qchg)   double-click in the tree: toggle", fg="#666").grid(
            row=4, column=0, columnspan=6, sticky="w", padx=6, pady=(0, 4))

        self.nb = ttk.Notebook(rf)
        self.nb.pack(fill="both", expand=True, padx=4)
        self.cl = self._tv(self.nb, "  Clients  ", ("since", "req", "rpt"),
                           {"#0": ("Client", 200), "since": ("Connected since", 140), "req": ("Requests", 80),
                            "rpt": ("Reports", 80)})
        self.rc = self._tv(self.nb, "  Report control blocks  ", ("state", "rptid", "datset", "trg", "intg", "sq",
                                                                   "sent"),
                           {"#0": ("RCB", 280), "state": ("State", 170), "rptid": ("RptID", 130),
                            "datset": ("DatSet", 230), "trg": ("TrgOps", 150), "intg": ("IntgPd", 60),
                            "sq": ("SqNum", 55), "sent": ("Reports", 60)})
        self.rc.tag_configure("used", foreground=ORANGE)
        self.rc.tag_configure("free", foreground=GREEN)
        lgf = ttk.Frame(self.nb)
        lb = tk.Frame(lgf)
        lb.pack(fill="x")
        self.v_rptlog = tk.BooleanVar(value=True)
        ttk.Checkbutton(lb, text="Log every report", variable=self.v_rptlog).pack(side="left", padx=4)
        self.v_pdulog = tk.BooleanVar(value=False)
        ttk.Checkbutton(lb, text="Log every MMS PDU", variable=self.v_pdulog,
                        command=lambda: setattr(self.server, "log_pdus", self.v_pdulog.get()) if self.server else None
                        ).pack(side="left", padx=4)
        ttk.Button(lb, text="Clear", command=lambda: self.log.delete("1.0", "end")).pack(side="left", padx=4)
        self.log = tk.Text(lgf, height=10, font=("Consolas", 9), wrap="none")
        ls = ttk.Scrollbar(lgf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=ls.set)
        self.log.pack(side="left", fill="both", expand=True)
        ls.pack(side="left", fill="y")
        self.log.tag_configure("err", foreground=RED)
        self.nb.add(lgf, text="  Log  ")
        # ---- GOOSE of the simulated IED
        gf = ttk.Frame(self.nb)
        gb = tk.Frame(gf)
        gb.pack(fill="x")
        tk.Label(gb, text="Network:").pack(side="left", padx=(4, 2))
        self.v_gnet = tk.StringVar()
        self.c_gnet = ttk.Combobox(gb, textvariable=self.v_gnet, state="readonly", width=34)
        self.c_gnet.pack(side="left")
        self.c_gnet.bind("<Button-1>", lambda e: self._fill_gnets())
        self.b_gstart = tk.Button(gb, text="▶ Publish GOOSE", command=self.goose_start, bg="#2e7d32", fg="white",
                                  activebackground="#1b5e20", activeforeground="white", relief="flat", padx=8)
        self.b_gstart.pack(side="left", padx=(8, 2), pady=2)
        ttk.Button(gb, text="■ Stop GOOSE", command=self.goose_stop).pack(side="left", padx=2)
        ttk.Button(gb, text="stNum + 1", command=self.goose_bump).pack(side="left", padx=(8, 2))
        self.g_lbl = tk.Label(gb, text="", fg="#666")
        self.g_lbl.pack(side="left", padx=6)
        tk.Label(gf, text="Same values and quality as the MMS reports.  Click the columns Publish / Simulation / "
                          "NdsCom to switch.  The REAL IED must be disconnected: same MAC / APPID / GoID.",
                 fg=ORANGE, anchor="w").pack(fill="x", padx=4)
        self.gt = self._tv(self.nb, None, ("pub", "sim", "nds", "goid", "datset", "dst", "times", "st", "sent"),
                           {"#0": ("GOOSE control block", 260), "pub": ("Publish", 60), "sim": ("Simulation", 75),
                            "nds": ("NdsCom", 60), "goid": ("GoID", 130), "datset": ("DatSet", 230),
                            "dst": ("MAC / APPID / VLAN / prio", 230), "times": ("Min / Max ms", 90),
                            "st": ("stNum / sqNum", 95), "sent": ("Frames", 70)}, parent_frame=gf)
        self.gt.tag_configure("on", foreground=GREEN)
        self.gt.tag_configure("off", foreground=GREY)
        self.gt.tag_configure("err", foreground=RED)
        self.gt.bind("<Button-1>", self._g_click)
        self.nb.add(gf, text="  GOOSE  ")
        self.nb.select(2)
        pw.bind("<Map>", lambda e: self.after(50, self._sash), add="+")

    def _sash(self):
        try:
            w = self.pw.winfo_width()
            if w > 400 and self.pw.sashpos(0) < 300:
                self.pw.sashpos(0, int(w * 0.45))
        except tk.TclError:
            pass

    def _tv(self, parent, title, cols, heads, parent_frame=None):
        f = ttk.Frame(parent_frame if parent_frame is not None else parent)
        tv = ttk.Treeview(f, columns=cols, show="tree headings")
        for c, (t, w) in heads.items():
            tv.heading(c, text=t, anchor="w")
            tv.column(c, width=w, anchor="w", stretch=(c == "#0"))
        vs = ttk.Scrollbar(f, orient="vertical", command=tv.yview)
        hs = ttk.Scrollbar(f, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tv.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)
        if parent_frame is not None:
            f.pack(fill="both", expand=True)
        else:
            parent.add(f, text=title)
        return tv

    def write_log(self, text, err=False):
        self.log.insert("end", "%s  %s\n" % (time.strftime("%H:%M:%S"), text), "err" if err else "")
        if int(self.log.index("end-1c").split(".")[0]) > 5000:
            self.log.delete("1.0", "1000.0")
        self.log.see("end")

    # ------------------------------------------------------------ CID
    def load(self):
        p = filedialog.askopenfilename(title="CID / SCD of the IED to simulate",
                                       filetypes=[("SCL", "*.cid *.scd *.icd *.iid *.xml"), ("All", "*.*")])
        if not p:
            return
        try:
            ieds = im.list_ieds(p)
        except Exception as ex:                 # noqa: BLE001
            messagebox.showerror("IED Simulator", str(ex), parent=self)
            return
        self.path = p
        self.c_ied["values"] = ieds
        self._load_ied(ieds[0] if ieds else "")

    def _load_ied(self, name):
        if self.server:
            if not messagebox.askyesno("IED Simulator", "The server is running. Stop it and load %s?" % name,
                                       parent=self):
                return
            self.stop()
        self.goose_stop(quiet=True)
        try:
            self.model = im.load(self.path, name or None)
        except Exception as ex:                 # noqa: BLE001
            messagebox.showerror("IED Simulator", str(ex), parent=self)
            return
        M = self.model
        self.v_ied.set(M["ied"])
        nvar = sum(len(v) for v in M["index"].values())
        self.summary = "%s (%s): %s %s %s - %d logical devices, %d variables, %d data sets, %d RCB, %d GoCB." % (
            M["ied"], M["file"], M["vendor"], M["model"], M["revision"], len(M["lds"]), nvar,
            sum(len(v) for v in M["datasets"].values()), len(M["rcbs"]), len(M["gocbs"]))
        self._fill_ips(choose=True)
        self._fill_tree()
        self._fill_rcbs()
        self.gcbs = sg.gocbs(M)
        self._fill_goose()
        self.write_log("loaded %s / %s" % (M["file"], M["ied"]))

    # ------------------------------------------------------------ listen IP
    def _fill_ips(self, choose=False):
        """Listen IP list with plain words: all addresses, this PC (adapter), IED of the CID"""
        self.pc = ms.pc_addresses()
        pc_ips = [x[0] for x in self.pc]
        vals = [ALL_TEXT]
        ied_ips = self.model["ips"] if self.model else []
        for ip in ied_ips:
            vals.append("%s   - IED %s, %s" % (ip, self.model["ied"], "on this PC (OK)" if ip in pc_ips
                                                else "NOT on this PC"))
        for ip, name, desc in self.pc:
            if ip in ied_ips:
                continue
            vals.append("%s   - this PC%s" % (ip, (": " + (name or desc)) if (name or desc) else ""))
        self.c_ip["values"] = vals
        if choose:
            on_pc = [ip for ip in ied_ips if ip in pc_ips]
            self.v_ip.set(next(v for v in vals if v.startswith(on_pc[0] + " ")) if on_pc else ALL_TEXT)
        self._ip_hint()

    def listen_ip(self):
        t = self.v_ip.get().strip()
        return (t.split()[0] if t else "0.0.0.0")

    def _ip_hint(self):
        if not self.model:
            return
        ip = self.listen_ip()
        pc_ips = [x[0] for x in getattr(self, "pc", [])]
        ied = self.model["ips"]
        if ip == "0.0.0.0":
            if any(i in pc_ips for i in ied):
                h = "SCADA connects to the IED IP %s - it is on this PC: OK." % ", ".join(i for i in ied if i in pc_ips)
                col = GREEN
            else:
                h = ("SCADA must connect to an IP of this PC in its network - %s. To keep the SCADA project "
                     "unchanged (IED IP %s) click 'IED IP on this PC...'." % (self._by_adapter() or "-",
                                                                             ", ".join(ied) or "-"))
                col = ORANGE
        elif ip in pc_ips:
            h = "SCADA must connect to %s%s." % (ip, " (IED IP of the CID): OK" if ip in ied else "")
            col = GREEN if ip in ied else "black"
        else:
            h = ("%s is not an address of this PC: Start would fail. Click 'IED IP on this PC...' to add it to "
                 "the network adapter, or choose 0.0.0.0." % ip)
            col = RED
        self.info.config(text=self.summary + "\n" + h, fg=col if col != "black" else "black", wraplength=1400)

    def _by_adapter(self):
        """'Wi-Fi: 192.168.1.150;  Ethernet 5: 10.0.0.122, ...'"""
        groups = {}
        for ip, name, desc in getattr(self, "pc", []):
            if ip.startswith("127."):
                continue
            groups.setdefault(name or desc or "?", []).append(ip)
        return ";   ".join("%s: %s" % (k, ", ".join(v)) for k, v in groups.items())

    def ip_dialog(self):
        IpDialog(self, self.model["ips"] if self.model else [], (self.model or {}).get("masks", {}),
                 getattr(self, "pc", []) or ms.pc_addresses(), on_done=lambda: self._fill_ips(choose=True))

    # ------------------------------------------------------------ server
    def start(self):
        if not self.model:
            messagebox.showinfo("IED Simulator", "Load the CID of the IED first.", parent=self)
            return
        if self.server:
            return
        ip = self.listen_ip()
        try:
            port = int(self.v_port.get())
        except ValueError:
            port = 102
        srv = ms.Server(self.model, on_event=lambda k, c, t: self.events.put((k, c, t)))
        try:
            srv.start(ip, port)
        except OSError as ex:
            msg = str(ex)
            if ip not in [x[0] for x in ms.pc_addresses()] + ["0.0.0.0"]:
                msg += ("\n\n%s is not an address of this PC.\nClick 'IED IP on this PC...' to add it to the "
                        "network adapter, or choose 0.0.0.0 - all addresses of this PC." % ip)
            elif port == 102:
                msg += "\n\nPort 102 is used by another program (another IEC 61850 / S7 server?)."
            messagebox.showerror("IED Simulator", "Cannot listen on %s:%d\n%s" % (ip, port, msg), parent=self)
            return
        self.server = srv
        srv.log_pdus = self.v_pdulog.get()
        if self.save:
            self.save({"sim_ip": ip, "sim_port": port})
        self.listen = "%s on %s:%d" % (self.model["ied"], ip, port)
        self.st_lbl.config(text="RUNNING  " + self.listen, fg=GREEN)
        self.write_log("server started: %s on %s:%d" % (self.model["ied"], ip, port))

    def stop(self):
        if self.server:
            self.server.stop()
            self.server = None
            self.write_log("server stopped")
        self.st_lbl.config(text="stopped", fg=GREY)

    def shutdown(self):
        if self.server:
            self.server.stop()
        if self.pub:
            self.pub.stop()

    def _tick(self):
        try:
            for _ in range(300):
                kind, cl, text = self.events.get_nowait()
                if kind == "report" and not self.v_rptlog.get():
                    continue
                who = cl.name if cl is not None else ""
                self.write_log("%s  %s" % (who, text), err=kind == "log" and ("refused" in text or "ERROR" in text))
        except queue.Empty:
            pass
        self.after(200, self._tick)

    # ------------------------------------------------------------ tree
    def _fill_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.kids = {}
        self.target = self.qnode = None
        for dom in self.model["lds"]:
            iid = iid_of(dom)
            self.tree.insert("", "end", iid=iid, text=dom, values=("", ""), tags=("ld",))
            self.tree.insert(iid, "end", iid=iid + DUMMY, text="")

    def _node(self, iid):
        dom, item = split_iid(iid)
        if not item:
            return None
        return im.find(self.model, dom, item)

    def _insert_kids(self, iid):
        if self.tree.exists(iid + DUMMY):
            self.tree.delete(iid + DUMMY)
        dom, item = split_iid(iid)
        if not item:
            lst = [(ln, n) for ln, n in self.model["lds"][dom].items()]
        else:
            n = im.find(self.model, dom, item)
            lst = [(item + "$" + k["name"], k) for k in n["kids"]] if n else []
        for it, n in lst:
            c = iid_of(dom, it)
            if self.tree.exists(c):
                continue
            label = n["name"]
            self.tree.insert(iid, "end", iid=c, text=label, values=self._vals(n), tags=self._tags(n))
            if n["kids"]:
                self.tree.insert(c, "end", iid=c + DUMMY, text="")

    def _vals(self, n):
        if n["kids"]:
            st = self._summary(n)
            return (st, "") if st else ("", "")
        return (im.value_text(n), n["btype"])

    def _summary(self, n):
        """value shown on a DO line: stVal / general / mag.f"""
        for p in VALUE_PATHS:
            c = child(n, p)
            if c is not None and not c["kids"]:
                return im.value_text(c)
        return ""

    def _tags(self, n):
        node = n
        if n["kids"]:
            node = next((child(n, p) for p in VALUE_PATHS if child(n, p) is not None), None)
            if node is None:
                return ()
        v = node["value"]
        if node["btype"] == "BOOLEAN" and v:
            return ("on",)
        if node["btype"] in ("Dbpos", "Tcmd") and v == "on":
            return ("on",)
        if node["btype"] == "Quality" and isinstance(v, dict) and v.get("validity", "good") != "good":
            return ("bad",)
        return ()

    def _on_open(self, e=None):
        iid = self.tree.focus()
        if self.tree.exists(iid + DUMMY):
            self._insert_kids(iid)

    def _refresh_items(self, iids=None):
        for iid in (iids or self._all_items()):
            if not self.tree.exists(iid):
                continue
            n = self._node(iid)
            if n is not None:
                self.tree.item(iid, values=self._vals(n), tags=self._tags(n))

    def _all_items(self, parent=""):
        out = []
        for c in self.tree.get_children(parent):
            if c.endswith(DUMMY):
                continue
            out.append(c)
            if self.tree.item(c, "open"):
                out += self._all_items(c)
        return out

    def _refresh(self):
        try:
            if self.model:
                self._refresh_items()
                self._fill_clients()
                self._fill_rcbs()
                self._fill_goose()
        except tk.TclError:
            pass
        self.after(1000, self._refresh)

    def find_next(self):
        if not self.model:
            return
        text = self.v_find.get().strip().lower().replace(".", "$")
        if not text:
            return
        cur = self.tree.selection()
        allrefs = [(dom, it) for dom, idx in self.model["index"].items() for it in idx]
        start = 0
        if cur:
            d, i = split_iid(cur[0])
            try:
                start = allrefs.index((d, i)) + 1
            except ValueError:
                start = 0
        for k in list(range(start, len(allrefs))) + list(range(0, start)):
            dom, it = allrefs[k]
            if text in it.lower():
                self._reveal(dom, it)
                return
        messagebox.showinfo("Find", "'%s' not found." % self.v_find.get(), parent=self)

    def _reveal(self, dom, item):
        parts = item.split("$")
        iid = iid_of(dom)
        self.tree.item(iid, open=True)
        self._insert_kids(iid)
        for i in range(len(parts)):
            iid = iid_of(dom, "$".join(parts[:i + 1]))
            if i < len(parts) - 1:
                self.tree.item(iid, open=True)
                if self.tree.exists(iid + DUMMY):
                    self._insert_kids(iid)
        self.tree.selection_set(iid)
        self.tree.see(iid)

    # ------------------------------------------------------------ editor
    def _on_select(self, e=None):
        s = self.tree.selection()
        if not s:
            return
        n = self._node(s[0])
        if n is None:
            return
        tgt, q = self._targets(n)
        self.target, self.qnode = tgt, q
        self.ed_ref.config(text=im.ref(n).replace("$", "."))
        if tgt is not None:
            self.c_val.configure(values=self._choices(tgt), state="normal")
            self.v_val.set(self._text_of(tgt))
            self.val_type.config(text="%s  (%s)" % (tgt["btype"], tgt["name"]))
        else:
            self.c_val.configure(values=[])
            self.v_val.set("")
            self.val_type.config(text="no value to set here" if q is None else "")
        if q is not None:
            v = q["value"] if isinstance(q["value"], dict) else {"validity": "good", "flags": []}
            self.v_valid.set(v.get("validity", "good"))
            for nm, var in self.v_flags.items():
                var.set(nm in v.get("flags", ()) or (nm == "test" and v.get("test", False)))
            self.q_lbl.config(text="now: %s" % gp.quality_text(v))
        else:
            self.q_lbl.config(text="(no quality)")

    def _targets(self, n):
        """selected node -> (value node, quality node)"""
        if n.get("rcb") or n["fc"] in ("BR", "RP", "GO"):
            return None, None
        if not n["kids"]:
            if n["btype"] == "Quality":
                return None, n
            if n["btype"] == "Timestamp":
                return None, None
            p = n["parent"]
            q = None
            while p is not None and q is None:
                q = next((k for k in p["kids"] if k["name"] == "q" and k["btype"] == "Quality"), None)
                p = p["parent"] if q is None else p
            return n, q
        tgt = next((child(n, p) for p in VALUE_PATHS if child(n, p) is not None and not child(n, p)["kids"]), None)
        q = next((k for k in n["kids"] if k["name"] == "q" and k["btype"] == "Quality"), None)
        return tgt, q

    @staticmethod
    def _choices(n):
        bt = n["btype"]
        if bt == "BOOLEAN":
            return ["TRUE", "FALSE"]
        if bt in ("Dbpos", "Tcmd"):
            return ["on", "off", "intermediate", "bad"]
        if bt == "Enum" and n.get("enum"):
            return ["%s (%d)" % (v, k) for k, v in sorted(n["enum"].items())]
        return []

    @staticmethod
    def _text_of(n):
        bt, v = n["btype"], n["value"]
        if bt == "BOOLEAN":
            return "TRUE" if v else "FALSE"
        if bt == "Enum" and n.get("enum"):
            return "%s (%d)" % (n["enum"].get(int(v), "?"), int(v))
        return str(v)

    def _parse(self, n, text):
        bt = n["btype"]
        text = text.strip()
        if bt == "BOOLEAN":
            if text.upper() not in ("TRUE", "FALSE", "1", "0"):
                raise ValueError("TRUE or FALSE")
            return text.upper() in ("TRUE", "1")
        if bt in ("Dbpos", "Tcmd"):
            if text not in gp.DBPOS:
                raise ValueError("on, off, intermediate or bad")
            return text
        if bt == "Enum":
            if text.endswith(")") and "(" in text:
                return int(text[text.rindex("(") + 1:-1])
            rev = {v: k for k, v in (n.get("enum") or {}).items()}
            return rev[text] if text in rev else int(text)
        if bt in im.INT_BITS:
            return int(text)
        if bt in ("FLOAT32", "FLOAT64"):
            return float(text.replace(",", "."))
        return text

    def _changed(self, n):
        iids = [iid_of(*n["path"])]
        p = n["parent"]
        while p is not None:
            iids.append(iid_of(*p["path"]))
            for k in p["kids"]:
                if k["btype"] in ("Timestamp", "Quality"):
                    iids.append(iid_of(*k["path"]))
            p = p["parent"]
        self._refresh_items(iids)

    def set_value(self, same=False):
        n = self.target
        if n is None or not self.model:
            return
        try:
            v = n["value"] if same else self._parse(n, self.v_val.get())
        except (ValueError, KeyError) as ex:
            messagebox.showwarning("Value", "%s: %s" % (n["name"], ex), parent=self)
            return
        self._apply(n, v, "dupd" if same else None)

    def _apply(self, n, v, kind=None):
        old = im.value_text(n)
        if self.server:
            self.server.set_value(n, v, kind)
        else:
            n["value"] = v
        self.v_val.set(self._text_of(n))
        self._changed(n)
        self._goose_changed(n)
        self.write_log("%s: %s -> %s%s" % (im.ref(n).replace("$", "."), old, im.value_text(n),
                                           "" if self.server else "   (server stopped: no report)"))

    def update_same(self):
        self.set_value(same=True)

    def toggle(self):
        n = self.target
        if n is None:
            return
        if n["btype"] == "BOOLEAN":
            self._apply(n, not n["value"])
        elif n["btype"] in ("Dbpos", "Tcmd"):
            self._apply(n, "off" if n["value"] == "on" else "on")

    def _on_double(self, e):
        iid = self.tree.identify_row(e.y)
        if not iid:
            return
        n = self._node(iid)
        if n is None:
            return
        tgt, q = self._targets(n)
        if tgt is not None and tgt["btype"] in ("BOOLEAN", "Dbpos", "Tcmd"):
            self.target = tgt
            self.toggle()
            return "break"

    def set_quality(self):
        q = self.qnode
        if q is None:
            return
        flags = [nm for nm, var in self.v_flags.items() if var.get() and nm != "test"]
        v = {"validity": self.v_valid.get(), "test": self.v_flags["test"].get(), "flags": flags}
        old = gp.quality_text(q["value"]) if isinstance(q["value"], dict) else ""
        if self.server:
            self.server.set_value(q, v, "qchg")
        else:
            q["value"] = v
        self.q_lbl.config(text="now: %s" % gp.quality_text(v))
        self._changed(q)
        self._goose_changed(q)
        self.write_log("%s: quality %s -> %s" % (im.ref(q).replace("$", "."), old, gp.quality_text(v)))

    # ------------------------------------------------------------ clients / RCBs
    def _fill_clients(self):
        srv = self.server
        self.cl.delete(*self.cl.get_children())
        n = 0
        if srv:
            for c in list(srv.clients):
                n += 1
                self.cl.insert("", "end", text=c.name, values=(time.strftime("%H:%M:%S", time.localtime(c.since)),
                                                              c.n_req, c.n_rpt))
            self.st_lbl.config(text="RUNNING  %s   %d client(s), %d reports sent" % (self.listen, n, srv.n_reports),
                               fg=GREEN)
            self.nb.tab(0, text="  Clients (%d)  " % n)

    def _fill_rcbs(self):
        if not self.model:
            return
        A = ms.Server._attr
        sel = self.rc.selection()
        self.rc.delete(*self.rc.get_children())
        for rn in self.model["rcbs"]:
            st = rn["rcb"]
            owner = st.get("owner")
            if A(rn, "RptEna"):
                state = "enabled by %s" % (owner.ip if owner else "?")
            elif owner is not None:
                state = "reserved by %s" % owner.ip
            else:
                state = "free" + (" (buffer %d)" % len(st.get("buffer") or []) if st.get("buffer") else "")
            iid = im.ref(rn)
            self.rc.insert("", "end", iid=iid, text=iid, values=(
                state, A(rn, "RptID"), A(rn, "DatSet") or "(none)", ", ".join(
                    x for x in im.TRG_BITS if x in (A(rn, "TrgOps") or ())), A(rn, "IntgPd"), A(rn, "SqNum"),
                st.get("sent", 0)), tags=("used" if state != "free" and not state.startswith("free") else "free",))
        for s in sel:
            if self.rc.exists(s):
                self.rc.selection_set(s)


# ---------------------------------------------------------------- add the IED IP to an adapter
class IpDialog(tk.Toplevel):
    """the IP of the IED as a second address of a network adapter: the netsh commands are shown and copied,
    the user runs them in cmd as administrator (the program itself never asks for administrator rights)"""

    def __init__(self, master, ied_ips, masks, pc, on_done=None):
        super().__init__(master)
        self.title("IED IP on this PC")
        self.transient(master.winfo_toplevel())
        self.on_done = on_done
        self.resizable(True, False)
        pad = dict(padx=10, pady=3)
        tk.Label(self, text="SCADA connects to the IP of the IED written in its project (from the CID).\n"
                            "So that SCADA finds the simulator without changing the project, this PC needs the "
                            "same IP address\nas a second address of the network adapter connected to SCADA.\n"
                            "Disconnect the real IED first - two devices with one IP do not work.",
                 justify="left", anchor="w").pack(fill="x", **pad)
        f = tk.Frame(self)
        f.pack(fill="x", **pad)
        tk.Label(f, text="IED IP:").grid(row=0, column=0, sticky="w")
        self.v_ip = tk.StringVar(value=ied_ips[0] if ied_ips else "")
        c = ttk.Combobox(f, textvariable=self.v_ip, values=ied_ips, width=18)
        c.grid(row=0, column=1, sticky="w")
        c.bind("<<ComboboxSelected>>", lambda e: self.v_mask.set(masks.get(self.v_ip.get(), "255.255.255.0")))
        tk.Label(f, text="Mask:").grid(row=0, column=2, sticky="w", padx=(10, 2))
        self.v_mask = tk.StringVar(value=masks.get(self.v_ip.get(), "255.255.255.0"))
        ttk.Entry(f, textvariable=self.v_mask, width=16).grid(row=0, column=3, sticky="w")
        tk.Label(f, text="Adapter:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        names = []
        for ip, name, desc in pc:
            if name and not ip.startswith("127.") and not any(n.startswith(name + "   (") for n in names):
                names.append("%s   (now %s%s)" % (name, ip, ", " + desc if desc and desc != name else ""))
        self.v_ad = tk.StringVar(value=names[0] if names else "Ethernet")
        ttk.Combobox(f, textvariable=self.v_ad, values=names, width=60).grid(row=1, column=1, columnspan=3,
                                                                           sticky="w", pady=(6, 0))
        tk.Label(f, text="the adapter that is connected to the SCADA network (its name as in Network Connections)",
                 fg="#666").grid(row=2, column=1, columnspan=3, sticky="w")
        self.dhcp_lbl = tk.Label(self, text="", fg=RED, justify="left", anchor="w", font=("Segoe UI", 9, "bold"))
        self.dhcp_lbl.pack(fill="x", **pad)
        tk.Label(self, text="Run the command in cmd as administrator (Start / cmd / right-click / Run as "
                            "administrator), then click Refresh:", anchor="w").pack(fill="x", **pad)
        self.cmd = tk.Text(self, height=3, font=("Consolas", 9), wrap="word")
        self.cmd.pack(fill="x", **pad)
        b = tk.Frame(self)
        b.pack(fill="x", **pad)
        ttk.Button(b, text="Copy: add IP", command=lambda: self.copy("add")).pack(side="left")
        ttk.Button(b, text="Copy: remove IP", command=lambda: self.copy("delete")).pack(side="left", padx=6)
        ttk.Button(b, text="Copy: restore DHCP", command=lambda: self.copy("dhcp")).pack(side="left")
        ttk.Button(b, text="Refresh", command=self._done).pack(side="left", padx=6)
        ttk.Button(b, text="Close", command=self.close).pack(side="right")
        self.copied = tk.Label(self, text="", fg=GREEN, anchor="w")
        self.copied.pack(fill="x", **pad)
        tk.Label(self, text="An adapter with DHCP (office / internet network) must NOT be used: a fixed IP switches its "
                            "DHCP off and the internet is lost.\nUse the adapter of the substation network (fixed IP) "
                            "or Listen IP 0.0.0.0. 'restore DHCP' gives the adapter back its automatic address and DNS.",
                 justify="left", fg=RED).pack(fill="x", **pad)
        tk.Label(self, text="By hand: Control Panel / Network and Sharing Center / Change adapter settings / adapter / "
                            "Properties /\nInternet Protocol Version 4 / Properties / Advanced / IP addresses: Add. "
                            "Remove it the same way after the test.", justify="left", fg="#666").pack(fill="x", **pad)
        for v in (self.v_ip, self.v_mask, self.v_ad):
            v.trace_add("write", lambda *a: self.show())
        self.show()
        self.grab_set()

    def adapter(self):
        return self.v_ad.get().split("   (")[0].strip()

    def command(self, what="add"):
        if what == "dhcp":
            return ('netsh interface ipv4 set address name="%s" source=dhcp & '
                    'netsh interface ipv4 set dnsservers name="%s" source=dhcp' % (self.adapter(), self.adapter()))
        if what == "add":
            return 'netsh interface ipv4 add address name="%s" address=%s mask=%s' % (
                self.adapter(), self.v_ip.get().strip(), self.v_mask.get().strip())
        return 'netsh interface ipv4 delete address name="%s" address=%s' % (self.adapter(), self.v_ip.get().strip())

    def show(self):
        self.cmd.delete("1.0", "end")
        self.cmd.insert("end", "add:     " + self.command("add") + "\nremove:  " + self.command("delete") +
                        "\nDHCP:    " + self.command("dhcp"))
        d = ms.adapter_dhcp(self.adapter())
        if d is True:
            self.dhcp_lbl.config(text="⚠ '%s' gets its address from DHCP (office / internet): adding a fixed IP "
                                      "switches DHCP off and the internet is lost. Choose another adapter." %
                                 self.adapter())
        elif d is False:
            self.dhcp_lbl.config(text="'%s' has fixed addresses: OK to add the IED IP." % self.adapter(), fg=GREEN)
            return
        else:
            self.dhcp_lbl.config(text="")
        self.dhcp_lbl.config(fg=RED)

    def copy(self, what):
        if what == "add" and ms.adapter_dhcp(self.adapter()) is True:
            if not messagebox.askyesno(
                    "IED IP", "The adapter '%s' gets its address from DHCP (office / internet network).\n\n"
                    "A fixed IP switches DHCP off: the adapter loses its automatic address, gateway and DNS - "
                    "the internet is lost until 'restore DHCP'.\n\nCopy the command anyway?" % self.adapter(),
                    icon="warning", default="no", parent=self):
                return
        self.clipboard_clear()
        self.clipboard_append(self.command(what))
        self.copied.config(text="copied: %s - paste it in cmd (administrator) with right-click / Ctrl+V" %
                           self.command(what))

    def _done(self):
        if self.on_done:
            self.on_done()
        self.show()

    def close(self):
        if self.on_done:
            self.on_done()
        self.destroy()


# ---------------------------------------------------------------- GOOSE of the simulator (methods)
def _fill_gnets(self):
    app = self.app
    vals = []
    for i, iface in enumerate(getattr(app, "nets", []), 1):
        if iface:
            vals.append("%s  -  %s" % (app.net_name(i), (app.net_labels[i - 1] or iface)[:60]))
    self.c_gnet["values"] = vals
    if vals and self.v_gnet.get() not in vals:
        self.v_gnet.set(vals[0])


def _giface(self):
    self._fill_gnets()
    vals = list(self.c_gnet["values"])
    if not vals:
        return None
    i = vals.index(self.v_gnet.get()) if self.v_gnet.get() in vals else 0
    ifaces = [x for x in self.app.nets if x]
    return ifaces[i] if i < len(ifaces) else None


def _fill_goose(self):
    sel = self.gt.selection()
    self.gt.delete(*self.gt.get_children())
    for k, g in enumerate(self.gcbs):
        ok = bool(g["members"])
        vals = ("☑" if g["use"] else "☐", "☑" if g["simulation"] else "☐", "☑" if g["ndscom"] else "☐",
                g["goid"], g["datset"] or "(no data set)",
                "%s / 0x%04X / %s / %s" % (g["mac"], g["appid"], g["vlan"] if g["vlan"] is not None else "-", g["prio"]),
                "%d / %d" % (g["min_ms"], g["max_ms"]),
                ("%d / %d" % (g["stnum"], g["sqnum"])) if g["active"] else "", g["sent"] if g["sent"] else "")
        tag = "err" if g.get("error") else ("on" if g["active"] else ("off" if not ok else ""))
        self.gt.insert("", "end", iid="g%d" % k, text=g["ref"], values=vals, tags=(tag,) if tag else ())
    for x in sel:
        if self.gt.exists(x):
            self.gt.selection_set(x)
    n = sum(1 for g in self.gcbs if g["active"])
    self.g_lbl.config(text=("publishing %d GoCB" % n) if n else "not publishing",
                      fg=GREEN if n else "#666")


def _g_click(self, e):
    iid = self.gt.identify_row(e.y)
    col = self.gt.identify_column(e.x)
    if not iid or not iid.startswith("g"):
        return
    g = self.gcbs[int(iid[1:])]
    key = {"#1": "use", "#2": "simulation", "#3": "ndscom"}.get(col)
    if not key:
        return
    if key == "use" and not g["members"]:
        return "break"
    if key == "simulation" and g["simulation"] and g["active"]:
        if not messagebox.askyesno("GOOSE", "Switch the Simulation flag OFF for %s?\n\nSubscribing IEDs then take "
                                   "these GOOSE as the real ones and WILL react." % g["ref"], icon="warning",
                                   default="no", parent=self):
            return "break"
    g[key] = not g[key]
    if key == "use" and g["active"] and not g["use"]:
        self.pub.remove(g)
        sg.set_goena(g, False)
        g["active"] = False
    elif key == "use" and g["use"] and self.pub and any(x["active"] for x in self.gcbs):
        self._goose_add([g])
    elif key in ("simulation", "ndscom") and g["active"] and self.pub:
        self.pub.change(g)
    self._fill_goose()
    return "break"


def goose_start(self):
    if not self.gcbs:
        messagebox.showinfo("GOOSE", "Load the CID of the IED first.", parent=self)
        return
    todo = [g for g in self.gcbs if g["use"] and not g["active"] and g["members"]]
    if not todo:
        messagebox.showinfo("GOOSE", "Tick the GoCBs to publish (column Publish).", parent=self)
        return
    iface = self._giface()
    if not iface:
        self.app.choose_nets()
        iface = self._giface()
        if not iface:
            return
    sim_off = [g["ref"] for g in todo if not g["simulation"]]
    text = ("Publish %d GOOSE control block(s) of %s on\n  %s\n\n%s\n\nThe REAL IED must be disconnected from "
            "this network (same MAC / APPID / GoID).\n\n%s\n\nStart?" % (
                len(todo), self.model["ied"], self.v_gnet.get(),
                "\n".join("  %s  %s  APPID 0x%04X  %s" % (g["ref"], g["mac"], g["appid"],
                                                         "SIMULATION" if g["simulation"] else "NORMAL")
                          for g in todo[:10]),
                ("Simulation OFF for %d GoCB: subscribers WILL react!" % len(sim_off)) if sim_off else
                "Simulation ON: only IEDs in simulation mode (LPHD.Sim) take these messages."))
    if not messagebox.askyesno("GOOSE", text, icon="warning", default="no", parent=self):
        return
    try:
        if self.pub is None or not self.pub.is_alive():
            self.pub = gp.Publisher(gp.scapy_sender(), on_error=lambda g, t: g.update(error=t))
            self.pub.on_sent = lambda g: g.update(sent=g["sent"] + 1)
            self.pub.start()
    except Exception as ex:                     # noqa: BLE001
        messagebox.showerror("GOOSE", "Can not send (Npcap / Scapy):\n%s" % ex, parent=self)
        return
    self._goose_iface = iface
    self._goose_add(todo)
    self.write_log("GOOSE: publishing %d GoCB on %s" % (len(todo), self.v_gnet.get()))
    self._fill_goose()


def _goose_add(self, lst):
    iface = getattr(self, "_goose_iface", None)
    if not iface or not self.pub:
        return
    src = gp.adapter_mac(iface)
    for g in lst:
        g.pop("error", None)
        sg.set_goena(g, True)
        self.pub.add(g, iface, src)


def goose_stop(self, quiet=False):
    if self.pub:
        for g in self.gcbs:
            if g["active"]:
                self.pub.remove(g)
                sg.set_goena(g, False)
        if not quiet:
            self.write_log("GOOSE stopped")
    for g in self.gcbs:
        g["active"] = False
    if hasattr(self, "gt"):
        self._fill_goose()


def goose_bump(self):
    s = self.gt.selection()
    if not s or not self.pub:
        return
    g = self.gcbs[int(s[0][1:])]
    if g["active"]:
        self.pub.change(g)
        self.write_log("GOOSE %s: stNum + 1 (%d)" % (g["ref"], g["stnum"]))


def _goose_changed(self, node):
    if not self.pub:
        return
    for g in self.gcbs:
        if g["active"] and sg.hits(g, node):
            self.pub.change(g)


for _f in (_fill_gnets, _giface, _fill_goose, _g_click, goose_start, _goose_add, goose_stop, goose_bump,
           _goose_changed):
    setattr(SimTab, _f.__name__, _f)
