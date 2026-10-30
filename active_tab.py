# -*- coding: utf-8 -*-
"""
active_tab.py - tab MMS / Active of IEC61850ANALYZER: our own MMS client (read only, one connection).

  Load CID / SCD...    optional - IP addresses of the IED and the model for "Compare with CID"
  IP / Connect         association to the IED (TCP 102); the data model is browsed at once
  Model tree           LD / LN / FC / DO / DA; selecting a node reads it (GetDataValues)
  Add to monitor       the selected node is read again every polling interval (1000 ms default)
  Data sets            members of every data set (the names are also given to the Passive tab and
                       to GOOSE: data set member names "(from MMS)"), Read values of a data set
  Control blocks       every URCB / BRCB / GoCB of the IED: free / reserved / IN USE by <client IP>,
                       RptID, DatSet, TrgOps, OptFlds, IntgPd, ConfRev, GoID, MAC, APPID, VLAN
  Compare with CID     logical devices / nodes, data sets (members, order), RCBs, GoCBs
  Log                  what was done, errors; optional every MMS PDU we send / receive

  Control (commands)   off by default; switched on with a warning: right-click a DO (or Control...) ->
                       window Control (ctl_dialog.py): Select / Operate / Cancel, CommandTermination
Only commands are written to the IED (no settings, no SetRCBValues).
"""
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import mms
import mms_client as mc
import mms_active as ma


def ctl_pc_name():
    import socket
    try:
        return socket.gethostname()
    except OSError:
        return ""

GREEN = "#1a6e1a"
RED = "#b00020"
ORANGE = "#b35900"
GREY = "#8a8a8a"
ON = "#00a000"                  # TRUE / on
DUMMY = "#dummy"


def iid_of(domain, item=""):
    return "%s|%s" % (domain, item)


def split_iid(iid):
    d, _, i = iid.partition("|")
    return d, i


class ActiveTab(ttk.Frame):
    def __init__(self, master, app, settings=None, save=None):
        super().__init__(master)
        self.app = app
        self.settings = settings or {}
        self.save = save
        self.client = None
        self.om = ma.new_model()
        self.cid = None
        self.cid_path = None
        self.jobs = queue.Queue()
        self.results = queue.Queue()
        self.kids = {}
        self.monitor = {}                 # iid -> dict(value, changed, n)
        self.poll_busy = False
        self.sel_token = 0
        self.controls = []                # open Control windows (CommandTermination / LastApplError)
        self.my_rcbs = {}                 # ref -> cb enabled by this program
        self.rpt_last = {}                # (rid, k) -> (value, changes)
        self.n_reports = 0
        self.ds_live = {}                 # data sets shown with values -> {index: last value}
        self.val_key = None               # node shown in Values (refreshed in place)
        self.val_ids = {}
        self.worker = threading.Thread(target=self._work, daemon=True)
        self.worker.start()
        self._build()
        self.after(100, self._tick)
        self.after(1000, self._poll_monitor)

    # ------------------------------------------------------------ GUI
    def _build(self):
        bg = "#f3f3f3"
        bar = tk.Frame(self, bg=bg, pady=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Load CID / SCD...", command=self.load_cid).pack(side="left", padx=(4, 2))
        tk.Label(bar, text="IED:", bg=bg).pack(side="left", padx=(6, 2))
        self.v_ied = tk.StringVar()
        self.c_ied = ttk.Combobox(bar, textvariable=self.v_ied, state="readonly", width=16)
        self.c_ied.pack(side="left")
        self.c_ied.bind("<<ComboboxSelected>>", lambda e: self._cid_ied(self.v_ied.get()))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        tk.Label(bar, text="IP:", bg=bg).pack(side="left", padx=(0, 2))
        self.v_ip = tk.StringVar(value=(self.settings.get("active_ips") or [""])[0])
        self.c_ip = ttk.Combobox(bar, textvariable=self.v_ip, width=16, values=self.settings.get("active_ips") or [])
        self.c_ip.pack(side="left")
        tk.Label(bar, text="Port:", bg=bg).pack(side="left", padx=(6, 2))
        self.v_port = tk.StringVar(value="102")
        ttk.Entry(bar, textvariable=self.v_port, width=6).pack(side="left")
        self.b_conn = tk.Button(bar, text="Connect", command=self.connect, bg="#2e7d32", fg="white",
                                activebackground="#1b5e20", activeforeground="white", relief="flat", padx=10)
        self.b_conn.pack(side="left", padx=(8, 2))
        ttk.Button(bar, text="Disconnect", command=self.disconnect).pack(side="left", padx=2)
        self.conn_lbl = tk.Label(bar, text="not connected", bg=bg, fg=GREY, padx=8)
        self.conn_lbl.pack(side="left")
        bar2 = tk.Frame(self, bg=bg, pady=2)
        bar2.pack(fill="x")
        ttk.Button(bar2, text="Read", command=self.read_selected).pack(side="left", padx=(4, 2))
        ttk.Button(bar2, text="Add to monitor", command=self.add_monitor).pack(side="left", padx=2)
        self.v_poll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar2, text="Auto refresh every", variable=self.v_poll).pack(side="left", padx=(8, 2))
        self.v_ms = tk.StringVar(value=str(self.settings.get("active_poll_ms", 1000)))
        ttk.Spinbox(bar2, from_=200, to=60000, increment=100, textvariable=self.v_ms, width=7).pack(side="left")
        tk.Label(bar2, text="ms", bg=bg).pack(side="left", padx=(2, 8))
        ttk.Separator(bar2, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(bar2, text="Read data sets", command=self.read_datasets).pack(side="left", padx=2)
        ttk.Button(bar2, text="Read control blocks", command=self.read_cbs).pack(side="left", padx=2)
        ttk.Button(bar2, text="Compare with CID", command=self.compare).pack(side="left", padx=2)
        ttk.Button(bar2, text="Export to Excel...", command=self.export_excel).pack(side="left", padx=2)
        ttk.Separator(bar2, orient="vertical").pack(side="left", fill="y", padx=6)
        self.v_ctl = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar2, text="Control (commands)", variable=self.v_ctl, command=self._ctl_toggle).pack(
            side="left", padx=2)
        self.b_ctl = ttk.Button(bar2, text="Control...", command=self.control_selected, state="disabled")
        self.b_ctl.pack(side="left", padx=2)
        self.ro_lbl = tk.Label(bar2, text="   read only", bg=bg, fg="#666")
        self.ro_lbl.pack(side="left")
        self.busy_lbl = tk.Label(self, text="", anchor="w", padx=8, fg="#555")
        self.busy_lbl.pack(fill="x")

        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True)
        self.pw = pw
        pw.bind("<Map>", lambda e: self.after(50, lambda: self._sash(pw)), add="+")
        # ---- model tree
        lf = ttk.Frame(pw)
        tk.Label(lf, text="Data model of the IED", bg="#4a5566", fg="white", anchor="w", padx=6).pack(fill="x")
        tf = ttk.Frame(lf)
        tf.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tf, show="tree", selectmode="browse")
        self.tree.column("#0", width=320)
        vs = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewOpen>>", self._on_open)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self.add_monitor())
        self.tree.bind("<Button-3>", self._tree_menu)
        self.tree.tag_configure("ld", font=("Segoe UI", 9, "bold"))
        pw.add(lf, weight=1)
        # ---- right side
        self.nb = ttk.Notebook(pw)
        pw.add(self.nb, weight=3)
        self.val = self._tv(self.nb, "  Values  ", ("value", "type"), {"#0": ("Name", 300), "value": ("Value", 420),
                                                                       "type": ("Type", 110)})
        mf = ttk.Frame(self.nb)
        mb = tk.Frame(mf)
        mb.pack(fill="x")
        ttk.Button(mb, text="Remove", command=self.mon_remove).pack(side="left", padx=2, pady=2)
        ttk.Button(mb, text="Clear", command=self.mon_clear).pack(side="left", padx=2, pady=2)
        tk.Label(mb, text="  double-click a node of the model tree to add it", fg="#666").pack(side="left")
        self.mon = self._tv(mf, None, ("value", "changed", "n"),
                            {"#0": ("Reference", 330), "value": ("Value", 680), "changed": ("Last change", 110),
                             "n": ("Changes", 70)})
        self.mon.tag_configure("chg", background="#fff3b0")
        self.mon.tag_configure("on", foreground=ON)
        self.val.tag_configure("on", foreground=ON)
        self.val.tag_configure("err", foreground=RED)
        self.val.tag_configure("chg", background="#fff3b0")
        self.mon.tag_configure("err", foreground=RED)
        self.nb.add(mf, text="  Monitor  ")
        df = ttk.Frame(self.nb)
        db = tk.Frame(df)
        db.pack(fill="x")
        ttk.Button(db, text="Read values of the selected data set", command=self.read_ds_values).pack(
            side="left", padx=2, pady=2)
        tk.Label(db, text="  or double-click the data set - then it is refreshed automatically (Auto refresh)",
                 fg="#666").pack(side="left")
        self.ds = self._tv(df, None, ("value", "type"), {"#0": ("Data set / member", 420), "value": ("Value", 420),
                                                        "type": ("Type", 100)})
        self.ds.tag_configure("ds", font=("Segoe UI", 9, "bold"))
        self.ds.bind("<Double-1>", lambda e: self.read_ds_values())
        self.ds.tag_configure("err", foreground=RED)
        self.ds.tag_configure("on", foreground=ON)
        self.ds.tag_configure("chg", background="#fff3b0")
        self.nb.add(df, text="  Data sets  ")
        cols = ("state", "id", "datset", "confrev", "trg", "opt", "intg", "buf", "dst")
        cbf = ttk.Frame(self.nb)
        cbb = tk.Frame(cbf)
        cbb.pack(fill="x")
        tk.Button(cbb, text="▶ Enable reports", command=self.enable_reports, bg="#2e7d32", fg="white",
                  activebackground="#1b5e20", activeforeground="white", relief="flat", padx=8).pack(
            side="left", padx=2, pady=2)
        ttk.Button(cbb, text="Disable reports", command=self.disable_reports).pack(side="left", padx=2, pady=2)
        self.v_nods = tk.BooleanVar(value=False)
        ttk.Checkbutton(cbb, text="Show RCBs without data set", variable=self.v_nods,
                        command=lambda: self._show_cbs(self.om, None, then=lambda: None)).pack(side="left", padx=8)
        tk.Label(cbb, text="  select a free RCB -> Enable reports (or double-click it); RCBs used by SCADA are not "
                           "touched; only Resv / RptEna / GI are written", fg="#666").pack(side="left")
        self.cb = self._tv(cbf, None, cols, {
            "#0": ("Control block", 430), "state": ("State", 190), "id": ("RptID / GoID", 160),
            "datset": ("DatSet", 260), "confrev": ("ConfRev", 60), "trg": ("TrgOps", 170),
            "opt": ("OptFlds", 300), "intg": ("IntgPd ms", 70), "buf": ("BufTm ms", 65),
            "dst": ("MAC / APPID / VLAN", 260)})
        self.cb.tag_configure("free", foreground=GREEN)
        self.cb.tag_configure("used", foreground=ORANGE)
        self.cb.tag_configure("err", foreground=RED)
        self.cb.tag_configure("grp", font=("Segoe UI", 9, "bold"))
        self.cb.tag_configure("mine", foreground="#0050b3", font=("Segoe UI", 9, "bold"))
        self.cb.tag_configure("nods", foreground=GREY)
        self.cb.bind("<Double-1>", self._cb_double)
        self.nb.add(cbf, text="  Control blocks  ")
        self.nb.bind("<<NotebookTabChanged>>", self._tab_changed, add="+")
        cf = ttk.Frame(self.nb)
        self.cmp_lbl = tk.Label(cf, text="Load the CID, connect, then Compare with CID.", anchor="w", padx=6,
                                font=("Segoe UI", 10, "bold"))
        self.cmp_lbl.pack(fill="x")
        self.cmp = self._tv(cf, None, (), {"#0": ("Finding", 1100)})
        self.cmp.tag_configure("ok", foreground=GREEN)
        self.cmp.tag_configure("bad", foreground=RED)
        self.cmp.tag_configure("info", foreground="#555")
        self.cmp.tag_configure("grp", font=("Segoe UI", 9, "bold"))
        self.nb.add(cf, text="  Compare with CID  ")
        lgf = ttk.Frame(self.nb)
        lb = tk.Frame(lgf)
        lb.pack(fill="x")
        self.v_pdus = tk.BooleanVar(value=False)
        ttk.Checkbutton(lb, text="Show every MMS PDU", variable=self.v_pdus).pack(side="left", padx=4)
        ttk.Button(lb, text="Clear", command=lambda: self.log.delete("1.0", "end")).pack(side="left", padx=4)
        self.log = tk.Text(lgf, height=10, font=("Consolas", 9), wrap="none")
        ls = ttk.Scrollbar(lgf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=ls.set)
        self.log.pack(side="left", fill="both", expand=True)
        ls.pack(side="left", fill="y")
        self.log.tag_configure("err", foreground=RED)
        self.nb.add(lgf, text="  Log  ")
        rf = ttk.Frame(self.nb)
        rb = tk.Frame(rf)
        rb.pack(fill="x")
        self.v_rt = tk.BooleanVar(value=True)
        ttk.Checkbutton(rb, text="Give the reports to Report test", variable=self.v_rt).pack(side="left", padx=4)
        ttk.Button(rb, text="Clear", command=self.rpt_clear).pack(side="left", padx=4)
        self.rpt_lbl = tk.Label(rb, text="no RCB enabled - Control blocks: select a free RCB -> Enable reports",
                                fg="#666")
        self.rpt_lbl.pack(side="left", padx=8)
        self.rpt = self._tv(rf, None, ("value", "reason", "time", "rpt", "n"), {
            "#0": ("Signal", 380), "value": ("Value", 420), "reason": ("Reason", 170), "time": ("Received", 95),
            "rpt": ("RptID / SqNum", 150), "n": ("Changes", 60)})
        self.rpt.tag_configure("on", foreground=ON)
        self.rpt.tag_configure("chg", background="#fff3b0")
        self.rpt.tag_configure("ds", font=("Segoe UI", 9, "bold"))
        self.nb.add(rf, text="  Reports  ")

    def _sash(self, pw):
        try:
            if pw.sashpos(0) < 300:
                pw.sashpos(0, 340)
        except tk.TclError:
            pass

    def _tv(self, parent, title, cols, heads):
        f = ttk.Frame(parent)
        tv = ttk.Treeview(f, columns=cols, show="tree headings")
        for c, (t, w) in heads.items():
            tv.heading(c, text=t, anchor="w")
            tv.column(c, width=w, anchor="w", stretch=(c == cols[-1]) if cols else True)
        vs = ttk.Scrollbar(f, orient="vertical", command=tv.yview)
        hs = ttk.Scrollbar(f, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tv.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)
        if title:
            parent.add(f, text=title)
        else:
            f.pack(fill="both", expand=True)
        return tv

    # ------------------------------------------------------------ worker
    def _work(self):
        while True:
            fn, args, done = self.jobs.get()
            try:
                res, err = fn(*args), None
            except Exception as ex:             # noqa: BLE001 - shown to the user
                res, err = None, ex
            self.results.put((done, res, err))

    def run(self, fn, *args, done=None, busy=""):
        if busy:
            self.busy_lbl.config(text=busy + " ...")
        self.jobs.put((fn, args, done))

    def _post(self, fn, *args):
        """from other threads: run fn(*args) in the GUI thread"""
        self.results.put((lambda r, e: fn(*args), None, None))

    def _tick(self):
        try:
            for _ in range(200):
                done, res, err = self.results.get_nowait()
                if done:
                    try:
                        done(res, err)
                    except tk.TclError:
                        pass
                    except Exception as ex:     # noqa: BLE001 - never stop the loop
                        self.write_log("internal error: %r" % ex, True)
        except queue.Empty:
            pass
        self.after(100, self._tick)

    def write_log(self, text, err=False):
        line = "%s  %s\n" % (time.strftime("%H:%M:%S"), text)
        self.log.insert("end", line, "err" if err else "")
        if int(self.log.index("end-1c").split(".")[0]) > 3000:
            self.log.delete("1.0", "500.0")
        self.log.see("end")

    def _progress(self, text):
        self._post(lambda: self.busy_lbl.config(text=text + " ..."))

    def _done_busy(self):
        self.busy_lbl.config(text="")

    # ------------------------------------------------------------ CID
    def load_cid(self):
        p = filedialog.askopenfilename(title="CID / SCD of the IED",
                                       filetypes=[("SCL", "*.cid *.scd *.icd *.iid *.xml"), ("All", "*.*")])
        if not p:
            return
        try:
            ieds = ma.list_ieds(p)
        except Exception as ex:                 # noqa: BLE001
            messagebox.showerror("CID", str(ex), parent=self)
            return
        self.cid_path = p
        self.c_ied["values"] = ieds
        self._cid_ied(ieds[0] if ieds else "")

    def _cid_ied(self, name):
        try:
            self.cid = ma.cid_model(self.cid_path, name or None)
        except Exception as ex:                 # noqa: BLE001
            messagebox.showerror("CID", str(ex), parent=self)
            return
        self.v_ied.set(self.cid["ied"])
        ips = self.cid["ips"] + [x for x in (self.settings.get("active_ips") or []) if x not in self.cid["ips"]]
        self.c_ip["values"] = ips
        if self.cid["ips"]:
            self.v_ip.set(self.cid["ips"][0])
        self.write_log("CID %s, IED %s: %d LD, %d data sets, %d RCB, %d GoCB, IP %s" % (
            self.cid["file"], self.cid["ied"], len(self.cid["lds"]), len(self.cid["datasets"]),
            len(self.cid["rcbs"]), len(self.cid["gocbs"]), ", ".join(self.cid["ips"]) or "-"))

    # ------------------------------------------------------------ connect
    def connect(self):
        if self.client and self.client.connected:
            messagebox.showinfo("Active", "Already connected to %s - Disconnect first." % self.client.peer, parent=self)
            return
        ip = self.v_ip.get().strip()
        try:
            port = int(self.v_port.get())
        except ValueError:
            port = 102
        if not ip:
            messagebox.showwarning("Active", "Enter the IP address of the IED.", parent=self)
            return
        ips = [ip] + [x for x in (self.settings.get("active_ips") or []) if x != ip]
        self.settings["active_ips"] = ips[:10]
        self.app_save({"active_ips": ips[:10]})
        self.c_ip["values"] = ips[:10]
        self.client = mc.MmsClient(on_pdu=self._on_pdu, on_unconfirmed=self._on_unconfirmed,
                                   on_closed=self._on_closed)
        self.conn_lbl.config(text="connecting to %s:%d ..." % (ip, port), fg=ORANGE)
        self.write_log("connect %s:%d" % (ip, port))
        cl = self.client

        def job():
            cl.connect(ip, port)
            om = ma.new_model()
            om["peer"] = cl.peer
            return ma.browse(cl, om, self._progress)
        self.run(job, done=self._connected, busy="connecting")

    def _connected(self, om, err):
        self._done_busy()
        if err:
            self.conn_lbl.config(text="not connected", fg=GREY)
            self.write_log("connect failed: %s" % err, True)
            messagebox.showerror("Active", "Connect failed:\n%s" % err, parent=self)
            if self.client:
                self.client.close()
            return
        self.om = om
        ident = " / ".join(x for x in om["ident"] if x)
        self.conn_lbl.config(text="connected to %s   %s   max PDU %d" % (self.client.peer, ident, self.client.max_pdu),
                             fg=GREEN)
        self.write_log("connected %s, %s, %d logical devices, %d variables" % (
            self.client.peer, ident or "no identity", len(om["lds"]), sum(len(v) for v in om["names"].values())))
        self._fill_tree()
        self.read_datasets()

    def disconnect(self):
        cl = self.client
        if not cl:
            return
        mine = list(self.my_rcbs.values())
        self.my_rcbs = {}

        def job():
            for cb in mine:                            # give the RCBs back first
                try:
                    ma.disable_rcb(cl, cb)
                except Exception:                      # noqa: BLE001
                    pass
            cl.close()
        self.run(job, done=lambda r, e: self._rpt_label())

    def _on_closed(self, why):
        self._post(self._closed, why)

    def _closed(self, why):
        self.my_rcbs = {}
        self.conn_lbl.config(text="not connected (%s)" % why, fg=GREY)
        self.write_log("connection closed: %s" % why)

    def _on_pdu(self, direction, pdu):
        if not self.v_pdus.get():
            return
        try:
            r = mms.parse_pdu(pdu)
            text = "%s  %s  %s" % (direction, r["mtype"], r["info"])
        except Exception:                       # noqa: BLE001
            text = "%s  %d bytes" % (direction, len(pdu))
        self._post(self.write_log, text)

    def _on_unconfirmed(self, pdu):
        for c in list(self.controls):                 # CommandTermination / LastApplError of a command
            c.feed(pdu)
        try:
            learned = getattr(getattr(self.app, "mms", None), "learned", None)
            r = mms.parse_pdu(pdu, learned=learned)
            if r.get("report"):
                self._post(self._got_report, r["report"])
                return
            text = "%s  %s  %s" % (r["mtype"], r["info"], r.get("reason", ""))
        except Exception:                             # noqa: BLE001
            text = "unconfirmed PDU, %d bytes" % len(pdu)
        self._post(self.write_log, "S→C " + text)

    # ------------------------------------------------------------ control
    def _ctl_toggle(self):
        if self.v_ctl.get():
            ok = messagebox.askyesno(
                "Control (commands)",
                "Commands (Select / Operate / Cancel) switch REAL equipment: breakers, disconnectors, "
                "protection functions.\n\nUse it only with the permission of the person in charge of the "
                "installation and when the consequences are known.\nEvery command must be confirmed and is "
                "written to the log file.\n\nSwitch control on?", icon="warning", default="no", parent=self)
            if not ok:
                self.v_ctl.set(False)
                return
            self.b_ctl.configure(state="normal")
            self.ro_lbl.configure(text="   CONTROL ON - commands possible", fg=RED)
            self.write_log("control switched on")
        else:
            self.b_ctl.configure(state="disabled")
            self.ro_lbl.configure(text="   read only", fg="#666")
            self.write_log("control switched off")

    def _ctl_object(self, ld, item):
        """tree node -> (ld, ln, do) of a controllable data object, or None"""
        parts = item.split("$") if item else []
        if len(parts) < 3:
            return None
        return ld, parts[0], parts[2]

    def control_selected(self):
        ld, item = self._selected()
        obj = self._ctl_object(ld, item) if ld else None
        if not obj:
            messagebox.showinfo("Control", "Select a data object in the tree, e.g. LN / CO / Pos or LN / ST / Pos.",
                                parent=self)
            return
        self.open_control(*obj)

    def open_control(self, ld, ln, do):
        if not self.v_ctl.get():
            messagebox.showinfo("Control", "Switch 'Control (commands)' on first.", parent=self)
            return
        if not self.connected():
            messagebox.showinfo("Control", "Not connected.", parent=self)
            return
        import ctl_dialog
        ctl_dialog.ControlDialog(self, ld, ln, do)

    def connected(self):
        return bool(self.client and self.client.connected)

    def app_save(self, d):
        if self.save:
            self.save(d)

    def shutdown(self):
        cl = self.client
        if cl and cl.connected:
            mine = list(self.my_rcbs.values())

            def go():
                for cb in mine:                        # give the RCBs back
                    try:
                        ma.disable_rcb(cl, cb)
                    except Exception:                  # noqa: BLE001
                        pass
                cl.close()
            threading.Thread(target=go, daemon=True).start()

    # ------------------------------------------------------------ own reports
    def _tab_changed(self, e=None):
        try:
            cur = self.nb.index("current")
        except tk.TclError:
            return
        if cur == 3 and self.connected() and not self.om.get("cbs_read") and not getattr(self, "_cb_reading", False):
            self._cb_reading = True
            self.read_cbs(then=lambda: setattr(self, "_cb_reading", False))

    def _cb_double(self, e):
        iid = self.cb.identify_row(e.y)
        if not iid.startswith("cb|"):
            return
        self.cb.selection_set(iid)
        cb = self._cb_selected()
        if iid[3:] in self.my_rcbs or (cb and cb.get("rptena") == "TRUE" and
                                       ma.mine(cb, self.client.local_ip if self.client else "")):
            self.disable_reports()
        else:
            self.enable_reports()

    def _cb_selected(self):
        s = self.cb.selection()
        if not s or not s[0].startswith("cb|"):
            return None
        ref = s[0][3:]
        return next((c for c in self.om["rcbs"] if c["ref"] == ref), None)

    def enable_reports(self):
        cb = self._cb_selected()
        if not cb:
            messagebox.showinfo("Reports", "Select a report control block in the list.", parent=self)
            return
        if not self.connected():
            return
        ok, why = ma.can_enable(cb, self.client.local_ip)
        if not ok:
            messagebox.showinfo("Reports", "%s cannot be used: %s." % (cb["ref"], why), parent=self)
            return
        cl, om = self.client, self.om
        cand = ma.cid_cb_names(self.cid)

        def job():
            r = ma.enable_rcb(cl, cb)
            ma.read_cbs(cl, om, None, cand)
            return r
        self.run(job, done=lambda r, e: self._enabled(cb, r, e), busy="enabling %s" % cb["ref"])

    def _enabled(self, cb, res, err):
        self._done_busy()
        ok, text = (False, str(err)) if err else res
        self.write_log("reports %s: %s" % (cb["ref"], text), not ok)
        if ok:
            self.my_rcbs[cb["ref"]] = cb
            self.nb.select(6)
        else:
            messagebox.showwarning("Reports", "%s: %s" % (cb["ref"], text), parent=self)
        self._show_cbs(self.om, None, then=lambda: None)
        self._rpt_label()

    def disable_reports(self):
        cb = self._cb_selected()
        if not cb or not (cb["ref"] in self.my_rcbs or ma.mine(cb, self.client.local_ip if self.client else "")):
            messagebox.showinfo("Reports", "Select a report control block enabled or reserved by this PC (blue).\n"
                                "RCBs of other clients (SCADA) are not touched.", parent=self)
            return
        if cb["ref"] not in self.my_rcbs:
            self.my_rcbs[cb["ref"]] = cb
        cl, om = self.client, self.om
        cand = ma.cid_cb_names(self.cid)

        def job():
            r = ma.disable_rcb(cl, self.my_rcbs[cb["ref"]])
            ma.read_cbs(cl, om, None, cand)
            return r
        self.run(job, done=lambda r, e: self._disabled(cb, r, e), busy="disabling %s" % cb["ref"])

    def _disabled(self, cb, res, err):
        self._done_busy()
        ok, text = (False, str(err)) if err else res
        self.write_log("reports %s: %s" % (cb["ref"], text), not ok)
        self.my_rcbs.pop(cb["ref"], None)
        self._show_cbs(self.om, None, then=lambda: None)
        self._rpt_label()

    def _rpt_label(self):
        if self.my_rcbs:
            self.rpt_lbl.config(text="enabled: %s   -   %d reports received" % (
                ", ".join(c["rptid"] or c["ref"] for c in self.my_rcbs.values()), self.n_reports), fg=GREEN)
        else:
            self.rpt_lbl.config(text="no RCB enabled - Control blocks: select a free RCB -> Enable reports",
                                fg="#666")

    def rpt_clear(self):
        self.rpt.delete(*self.rpt.get_children())
        self.rpt_last = {}

    def _got_report(self, rep):
        self.n_reports += 1
        rid = rep.get("rid") or "?"
        now = time.strftime("%H:%M:%S")
        dsref = rep.get("dset") or ""
        mem = self.om["datasets"].get(dsref) if dsref else None
        pid = "rp|" + rid
        if not self.rpt.exists(pid):
            self.rpt.insert("", "end", iid=pid, text="%s   (%s)" % (rid, dsref or "data set ?"), open=True,
                            tags=("ds",), values=("", "", "", "", ""))
        for x in self.rpt.get_children(pid):
            tags = [t for t in self.rpt.item(x, "tags") if t != "chg"]
            self.rpt.item(x, tags=tags)
        for en in rep.get("entries") or []:
            k = en.get("k")
            name = en.get("ref") or (mms.ref61850(mem[k]) if isinstance(mem, list) and k is not None
                                     and k < len(mem) else "#%s" % k)
            iid = "re|%s|%s" % (rid, k)
            val = str(en.get("value", ""))
            old = self.rpt_last.get((rid, k))
            n = (old[1] + (1 if old[0] != val else 0)) if old else 0
            self.rpt_last[(rid, k)] = (val, n)
            reasons = ", ".join(en.get("reasons") or [])
            vals = (val, reasons, now, "%s #%s" % (rid, rep.get("seq")), n)
            st = str(en.get("state") or val)
            tags = ["on"] if st == "TRUE" or st.startswith("on") else []
            if old and old[0] != val:
                tags.append("chg")
            if self.rpt.exists(iid):
                self.rpt.item(iid, text="%2s  %s" % (k, name), values=vals, tags=tags)
            else:
                kids = self.rpt.get_children(pid)
                pos = next((i for i, c in enumerate(kids) if int(c.rsplit("|", 1)[1]) > int(k)), "end")
                self.rpt.insert(pid, pos, iid=iid, text="%2s  %s" % (k, name), values=vals, tags=tags)
        self._rpt_label()
        if self.v_rt.get():
            try:
                m = {"kind": "MMS", "ts": time.time(), "server": (self.client.peer or "").split(":")[0],
                     "report": rep}
                self.app.rpt_tab.feed([m])
            except Exception:                         # noqa: BLE001
                pass

    # ------------------------------------------------------------ model tree
    def _fill_tree(self):
        self.val_key = None
        self.tree.delete(*self.tree.get_children())
        self.kids = {}
        for ld, names in self.om["names"].items():
            ch = {"": []}
            for n in names:
                parent = n.rsplit("$", 1)[0] if "$" in n else ""
                ch.setdefault(parent, []).append(n)
            self.kids[ld] = ch
            iid = iid_of(ld)
            self.tree.insert("", "end", iid=iid, text=ld, open=False, tags=("ld",))
            if ch[""]:
                self.tree.insert(iid, "end", iid=iid + DUMMY, text="")

    def _rebuild_kids(self, ld):
        ch = {"": []}
        for n in self.om["names"].get(ld, []):
            parent = n.rsplit("$", 1)[0] if "$" in n else ""
            ch.setdefault(parent, []).append(n)
        self.kids[ld] = ch

    def _label(self, item):
        last = item.rsplit("$", 1)[-1]
        if item.count("$") == 1 and last in ma.FC_TEXT:
            return "%s   (%s)" % (last, ma.FC_TEXT[last])
        return last

    def _on_open(self, e=None):
        iid = self.tree.focus()
        if not self.tree.exists(iid + DUMMY):
            return
        ld, item = split_iid(iid)
        ch = self.kids.get(ld, {})
        if item and "$" not in item and not ch.get(item):     # LN without member names: read its type
            if not self.connected():
                return
            cl, om = self.client, self.om
            self.tree.item(iid + DUMMY, text="reading ...")
            self.run(ma.expand_ln, cl, om, ld, item, done=lambda r, e: self._expanded(iid, ld, item, e),
                     busy="reading the type of %s/%s" % (ld, item))
            return
        self._populate(iid)

    def _expanded(self, iid, ld, item, err):
        self._done_busy()
        if err:
            self.write_log("type of %s/%s: %s" % (ld, item, err), True)
            if self.tree.exists(iid + DUMMY):
                self.tree.item(iid + DUMMY, text="error: %s" % err)
            return
        self._rebuild_kids(ld)
        if self.tree.exists(iid):
            self._populate(iid)

    def _populate(self, iid):
        if self.tree.exists(iid + DUMMY):
            self.tree.delete(iid + DUMMY)
        ld, item = split_iid(iid)
        ch = self.kids.get(ld, {})
        flat = self.om.get("flat", {}).get(ld)
        for n in ch.get(item, []):
            c = iid_of(ld, n)
            if self.tree.exists(c):
                continue
            self.tree.insert(iid, "end", iid=c, text=self._label(n))
            if ch.get(n) or (flat and "$" not in n):
                self.tree.insert(c, "end", iid=c + DUMMY, text="")

    def _selected(self):
        s = self.tree.selection()
        if not s or s[0].endswith(DUMMY):
            return None, None
        return split_iid(s[0])

    def _on_select(self, e=None):
        ld, item = self._selected()
        if ld and item and self.connected():
            self.read_selected()

    def _tree_menu(self, e):
        iid = self.tree.identify_row(e.y)
        if not iid or iid.endswith(DUMMY):
            return
        self.tree.selection_set(iid)
        ld, item = split_iid(iid)
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Read", command=self.read_selected)
        m.add_command(label="Add to monitor", command=self.add_monitor)
        obj = self._ctl_object(ld, item)
        if obj:
            m.add_command(label="Control...  %s.%s" % (obj[1], obj[2]), command=lambda: self.open_control(*obj),
                          state="normal" if self.v_ctl.get() else "disabled")
        m.add_separator()
        m.add_command(label="Copy reference (MMS)  %s/%s" % (ld, item),
                      command=lambda: self._copy("%s/%s" % (ld, item) if item else ld))
        if item:
            r = mms.ref61850("%s/%s" % (ld, item))
            m.add_command(label="Copy reference (61850)  %s" % r, command=lambda: self._copy(r))
        m.tk_popup(e.x_root, e.y_root)

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    # ------------------------------------------------------------ read
    def read_selected(self):
        ld, item = self._selected()
        if not ld:
            return
        if not item:
            self.val.delete(*self.val.get_children())
            self.val.insert("", "end", text=ld, values=("%d logical nodes - select a logical node" %
                                                        len(self.om["lds"].get(ld, [])), ""))
            return
        if not self.connected():
            return
        self.sel_token += 1
        tok = self.sel_token
        cl, om = self.client, self.om
        self.run(ma.read_item, cl, om, ld, item, done=lambda r, e: self._show_values(tok, ld, item, r, e),
                 busy="reading %s/%s" % (ld, item))

    def _show_values(self, tok, ld, item, rows, err):
        self._done_busy()
        if tok != self.sel_token:
            return
        self.val.delete(*self.val.get_children())
        if err:
            self.val_key = None
            self.val.insert("", "end", text="%s/%s" % (ld, item), values=("error: %s" % err, ""))
            self.write_log("read %s/%s: %s" % (ld, item, err), True)
            return
        self._fill_values(ld, item, rows)
        if self.nb.index("current") != 1:            # keep the Monitor in front
            self.nb.select(0)

    def _val_tags(self, typ, text):
        if typ == "error":
            return ("err",)
        return ("on",) if ma.leaf_state(typ, text) else ()

    def _fill_values(self, ld, item, rows):
        self.val.delete(*self.val.get_children())
        self.val_key = (ld, item)
        self.val_ids = {}
        for path, typ, text, raw in rows:
            parent = self.val_ids.get(path.rsplit(".", 1)[0], "") if "." in path else ""
            label = path if not parent else path.rsplit(".", 1)[1]
            self.val_ids[path] = self.val.insert(parent, "end", text=label, values=(text, typ), open=True,
                                                 tags=self._val_tags(typ, text))

    def _refresh_values(self, key, rows):
        """auto refresh: values of the shown node changed in place (tree stays open / scrolled)"""
        if key != self.val_key or not rows:
            return
        if [r[0] for r in rows] != list(self.val_ids):
            self._fill_values(key[0], key[1], rows)
            return
        for path, typ, text, raw in rows:
            iid = self.val_ids[path]
            old = self.val.item(iid, "values")
            tags = self._val_tags(typ, text)
            if old and old[0] != text and typ not in ("Structure", "Array"):
                tags = tags + ("chg",)
            self.val.item(iid, values=(text, typ), tags=tags)

    # ------------------------------------------------------------ monitor
    def add_monitor(self):
        ld, item = self._selected()
        if not ld or not item:
            return
        iid = iid_of(ld, item)
        if iid not in self.monitor:
            self.monitor[iid] = dict(value=None, changed="", n=0)
            self.mon.insert("", "end", iid=iid, text=mms.ref61850("%s/%s" % (ld, item)), values=("", "", 0))
        self.nb.select(1)

    def mon_remove(self):
        for iid in self.mon.selection():
            self.monitor.pop(iid, None)
            self.mon.delete(iid)

    def mon_clear(self):
        self.monitor.clear()
        self.mon.delete(*self.mon.get_children())

    def _poll_monitor(self):
        try:
            ms = max(200, int(float(self.v_ms.get())))
        except ValueError:
            ms = 1000
        if self.settings.get("active_poll_ms") != ms:
            self.settings["active_poll_ms"] = ms
            self.app_save({"active_poll_ms": ms})
        cur = self.nb.index("current")
        ds_refs = [r for r in self.ds_live if isinstance(self.om["datasets"].get(r), list)] if cur == 2 else []
        val_key = self.val_key if cur == 0 and self.val_key and self.val_key[1] else None
        if self.v_poll.get() and self.connected() and not self.poll_busy and (self.monitor or ds_refs or val_key):
            groups = {}
            for iid in self.monitor:
                ld, item = split_iid(iid)
                groups.setdefault(ld, []).append(item)
            cl, om = self.client, self.om
            self.poll_busy = True

            def job():
                out = {}
                for ld, items in groups.items():
                    for it, rows in ma.read_many(cl, om, ld, items).items():
                        out[iid_of(ld, it)] = rows
                ds = {r: ma.read_dataset_values(cl, om, r, om["datasets"][r]) for r in ds_refs}
                val = ma.read_item(cl, om, val_key[0], val_key[1]) if val_key else None
                return out, ds, val
            self.run(job, done=lambda r, e: self._polled(r, e, val_key))
        self.after(ms, self._poll_monitor)

    def _polled(self, res, err, val_key):
        if err:
            self.poll_busy = False
            self.write_log("auto refresh: %s" % err, True)
            return
        mon, ds, val = res
        self._monitor_values(mon, None)
        for ref, vals in ds.items():
            self._ds_values(ref, self.om["datasets"].get(ref) or [], vals, None, auto=True)
        if val is not None:
            self._refresh_values(val_key, val)

    def _monitor_values(self, res, err):
        self.poll_busy = False
        if err:
            self.write_log("monitor: %s" % err, True)
            return
        now = time.strftime("%H:%M:%S")
        for iid, rows in res.items():
            st = self.monitor.get(iid)
            if st is None or not self.mon.exists(iid):
                continue
            bad = rows and rows[0][1] == "error"
            v = ("error: " + rows[0][2]) if bad else ma.compact(rows)
            tags = ("err",) if bad else ()
            if st["value"] is not None and v != st["value"]:
                st["n"] += 1
                st["changed"] = now
                tags = tags + ("chg",)
            elif st["value"] is None:
                st["changed"] = now
            st["value"] = v
            if not bad and ma.state_of(rows):
                tags = tags + ("on",)
            self.mon.item(iid, values=(v, st["changed"], st["n"]), tags=tags)

    # ------------------------------------------------------------ data sets
    def read_datasets(self):
        if not self.connected():
            return
        cl, om = self.client, self.om
        self.run(ma.read_datasets, cl, om, self._progress, done=self._show_datasets, busy="reading data sets")

    def _show_datasets(self, om, err):
        self._done_busy()
        if err:
            self.write_log("data sets: %s" % err, True)
            return
        self.ds.delete(*self.ds.get_children())
        self.ds_live = {}
        for ref, mem in sorted(self.om["datasets"].items()):
            if isinstance(mem, str):
                self.ds.insert("", "end", iid="ds|" + ref, text=mms.ref61850(ref), values=(mem, ""), tags=("ds", "err"))
                continue
            p = self.ds.insert("", "end", iid="ds|" + ref, text="%s   (%d)" % (ref, len(mem)), values=("", ""),
                               tags=("ds",), open=False)
            for i, m in enumerate(mem):
                self.ds.insert(p, "end", iid="dm|%s|%d" % (ref, i), text="%2d  %s" % (i + 1, mms.ref61850(m)),
                               values=("", ""))
        learned = ma.learned_names(self.om)
        try:
            with self.app.lock:
                self.app.mms.learned.update(learned)
        except AttributeError:
            pass
        self.write_log("%d data sets read (names given to the Passive tab and GOOSE)" % len(learned))

    def read_ds_values(self):
        s = self.ds.selection()
        if not s or not self.connected():
            return
        iid = s[0]
        if iid.startswith("dm|"):
            iid = self.ds.parent(iid)
        ref = iid[3:]
        mem = self.om["datasets"].get(ref)
        if not isinstance(mem, list):
            return
        cl, om = self.client, self.om

        def job():
            return ma.read_dataset_values(cl, om, ref, mem)
        self.run(job, done=lambda r, e: self._ds_values(ref, mem, r, e), busy="reading data set %s" % ref)

    def _ds_values(self, ref, mem, res, err, auto=False):
        if not auto:
            self._done_busy()
        if err:
            self.write_log("read data set %s: %s" % (ref, err), True)
            return
        if not auto:
            self.ds.item("ds|" + ref, open=True)
        last = self.ds_live.setdefault(ref, {})        # this data set is now refreshed automatically
        for i, (v, typ, state) in enumerate(res):
            iid = "dm|%s|%d" % (ref, i)
            if not self.ds.exists(iid):
                continue
            tags = ("err",) if v.startswith("error") else (("on",) if state else ())
            if i in last and last[i] != v:
                tags = tags + ("chg",)
            last[i] = v
            self.ds.item(iid, values=(v, typ), tags=tags)

    # ------------------------------------------------------------ control blocks
    def read_cbs(self, then=None):
        if not self.connected():
            return
        cl, om = self.client, self.om
        cand = ma.cid_cb_names(self.cid)
        self.run(ma.read_cbs, cl, om, self._progress, cand, done=lambda r, e: self._show_cbs(r, e, then),
                 busy="reading control blocks")

    def _show_cbs(self, om, err, then=None):
        self._done_busy()
        self._cb_reading = False
        if err:
            self.write_log("control blocks: %s" % err, True)
            return
        for ld in self.om["names"]:
            self._rebuild_kids(ld)
        for line in self.om.get("cb_log") or []:
            self.write_log("control blocks: " + line)
        self.om["cb_log"] = []
        self.cb.delete(*self.cb.get_children())
        if not self.om.get("cbs_read"):
            self.cb.insert("", "end", text="not read yet - click 'Read control blocks' (or open this tab while "
                                           "connected)", tags=("nods",), values=("",) * 9)
            return
        for title, lst in (("Report control blocks", self.om["rcbs"]), ("GOOSE control blocks", self.om["gocbs"])):
            myip = self.client.local_ip if self.client else ""
            used = sum(1 for c in lst if ma.in_use(c).startswith(("IN USE", "reserved", "publishing")))
            nods = [c for c in lst if c["kind"] != "GoCB" and not c.get("datset") and not c.get("error")]
            p = self.cb.insert("", "end", text="%s (%d, %d in use%s)" % (
                title, len(lst), used, (", %d without data set%s" % (len(nods), "" if self.v_nods.get() else
                                                                    " - hidden")) if nods else ""),
                open=True, tags=("grp",), values=("",) * 9)
            for c in lst:
                if c in nods and not self.v_nods.get():
                    continue
                st = ma.in_use(c, myip)
                tag = "err" if c.get("error") else ("used" if st.startswith(("IN USE", "reserved", "publishing"))
                                                     else "free")
                if c["kind"] == "GoCB":
                    vals = (st, c.get("goid", ""), c.get("datset", ""), c.get("confrev", ""), "", "", "", "",
                            "%s / %s / %s" % (c.get("mac", ""), c.get("appid", ""), c.get("vlan", "")))
                else:
                    vals = (st, c.get("rptid", ""), c.get("datset", ""), c.get("confrev", ""),
                            ", ".join(c.get("trgops") or []), ", ".join(c.get("optflds") or []),
                            c.get("intgpd", ""), c.get("buftm", ""), "")
                if c["ref"] in self.my_rcbs:
                    tag = "mine"
                    vals = ("ENABLED BY THIS PROGRAM",) + tuple(vals[1:])
                elif c["kind"] != "GoCB" and ma.mine(c, myip):
                    tag = "mine"
                elif c["kind"] != "GoCB" and not c.get("datset"):
                    tag = "err" if c.get("error") else "nods"
                    vals = ("no data set",) + tuple(vals[1:])
                self.cb.insert(p, "end", iid="cb|" + c["ref"], text="%s  %s" % (c["kind"], c["ref"]), values=vals,
                               tags=(tag,))
        self.write_log("%d RCB, %d GoCB read" % (len(self.om["rcbs"]), len(self.om["gocbs"])))
        if then:
            then()
        else:
            self.nb.select(3)

    # ------------------------------------------------------------ Excel
    def export_excel(self):
        if not self.connected():
            messagebox.showinfo("Export", "Connect to the IED first.", parent=self)
            return
        ied = (self.cid["ied"] if self.cid else "") or (list(self.om["lds"])[0] if self.om["lds"] else "IED")
        path = filedialog.asksaveasfilename(
            title="Export the IED to Excel", defaultextension=".xlsx", parent=self,
            initialfile="%s_%s_model_%s.xlsx" % (ied, self.client.peer.split(":")[0], time.strftime("%Y-%m-%d")),
            filetypes=[("Excel", "*.xlsx")])
        if not path:
            return
        cl, om, cid = self.client, self.om, self.cid
        cand = ma.cid_cb_names(cid)
        info = [["Exported", time.strftime("%Y-%m-%d %H:%M:%S")], ["PC", ctl_pc_name()],
                ["Program", "IEC61850ANALYZER %s" % getattr(__import__("sys").modules.get("__main__"), "VERSION", "")]]

        def job():
            import xlsx_lite
            sheets = ma.export_sheets(cl, om, cid, cand, self._progress, info)
            xlsx_lite.write(path, sheets)
            return path, [(n, len(r)) for n, h, r, *x in sheets]
        self.run(job, done=self._exported, busy="exporting to Excel")

    def _exported(self, res, err):
        self._done_busy()
        if err:
            self.write_log("Excel export failed: %s" % err, True)
            messagebox.showerror("Export", str(err), parent=self)
            return
        path, counts = res
        self.write_log("Excel: %s  (%s)" % (path, ", ".join("%s %d" % c for c in counts)))
        if messagebox.askyesno("Export", "Saved:\n%s\n\n%s\n\nOpen it?" % (
                path, "\n".join("%s: %d rows" % c for c in counts)), parent=self):
            try:
                import os
                os.startfile(path)
            except Exception:                         # noqa: BLE001
                pass

    # ------------------------------------------------------------ compare
    def compare(self):
        if not self.cid:
            messagebox.showinfo("Compare", "Load the CID / SCD of the IED first.", parent=self)
            return
        if not self.connected() and not self.om["lds"]:
            messagebox.showinfo("Compare", "Connect to the IED first.", parent=self)
            return
        if self.connected() and not self.om.get("cbs_read"):
            self.read_cbs(then=self._compare)
            return
        self._compare()

    def _compare(self):
        if self.om["ident"] or self.om["lds"]:
            F = ma.compare(self.cid, self.om)
        else:
            F = []
        self.cmp.delete(*self.cmp.get_children())
        groups = {}
        for sec, lvl, text in F:
            if sec not in groups:
                groups[sec] = self.cmp.insert("", "end", text=sec, open=True, tags=("grp",))
            self.cmp.insert(groups[sec], "end", text=text, tags=(lvl,))
        nbad = sum(1 for x in F if x[1] == "bad")
        ied_names = {d for d in self.om["lds"]}
        hint = ""
        if not any(d in ied_names for d in self.cid["lds"]):
            hint = "   - no logical device of the CID found: is this the CID of this IED?"
        self.cmp_lbl.config(text=("IED and CID %s: the same" % self.cid["ied"]) if not nbad else
                            "%d difference(s) between the IED and the CID %s%s" % (nbad, self.cid["file"], hint),
                            fg=GREEN if not nbad else RED)
        self.write_log("compare with %s: %d difference(s)" % (self.cid["file"], nbad))
        self.nb.select(4)
