# -*- coding: utf-8 -*-
"""
pub_tab.py - tab "GOOSE Publisher" of IEC61850ANALYZER: simulation of GOOSE of IEDs from their
CID / SCD files (see goose_pub.py).

  Load CID / SCD...      control blocks of the file (CID: only its own IED; SCD: all IEDs)
  table Control blocks   tick = publish this one; state, stNum / sqNum, conflicts
  table Data set         values of the selected control block; editor below: BOOLEAN, Dbpos,
                         Quality (validity + test), Enum, numbers (also analog FLOAT32), strings
  Network                adapter (Network 1 / 2 of Adapters...)
  Simulation             ON by default (Ed2: field simulation + Reserved1 S bit); OFF only after
                         a confirmation - subscribers in normal mode then react to the messages
  Start / STOP ALL       start the ticked control blocks / stop everything
A changed value of a running control block is sent at once as a new state (stNum + 1).
"""
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import goose_pub as gp

CHK, UNCHK = "☑", "☐"
TYPES_NUM = ("INT8", "INT16", "INT24", "INT32", "INT64", "INT128", "INT8U", "INT16U", "INT24U", "INT32U",
             "FLOAT32", "FLOAT64")


class PublisherTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.gcbs = []               # publisher entries (goose_pub.load_gcbs)
        self.pub = None              # goose_pub.Publisher
        self.sel = None              # selected control block
        self.node_iid = {}
        self.confirmed = False
        # ---- top bar
        top = tk.Frame(self, bg="#f3f3f3", pady=4)
        top.pack(fill="x")
        ttk.Button(top, text="▶ Start ticked", command=self.start).pack(side="left", padx=(4, 2))
        tk.Button(top, text="■ STOP ALL", command=self.stop_all, bg="#c62828", fg="white",
                  activebackground="#8e0000", activeforeground="white", relief="flat", padx=10).pack(side="left", padx=6)
        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(top, text="Load CID / SCD...", command=self.load).pack(side="left", padx=4)
        ttk.Button(top, text="Remove all", command=self.remove_all).pack(side="left", padx=2)
        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=6)
        tk.Label(top, text="Network:", bg="#f3f3f3").pack(side="left")
        self.v_net = tk.StringVar()
        self.c_net = ttk.Combobox(top, textvariable=self.v_net, state="readonly", width=34)
        self.c_net.pack(side="left", padx=4)
        self.c_net.bind("<Button-1>", lambda e: self.fill_nets())
        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=6)
        self.v_sim = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Simulation", variable=self.v_sim, command=self.on_sim).pack(side="left", padx=4)
        self.v_nds = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Needs commissioning", variable=self.v_nds, command=self.on_flags).pack(side="left", padx=4)
        self.state = tk.Label(top, text="Stopped", bg="#f3f3f3", fg="#555")
        self.state.pack(side="left", padx=10)
        # ---- warning line
        self.warn = tk.Label(self, text="", fg="#b00020", anchor="w", padx=6, justify="left")
        self.warn.pack(fill="x")
        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True)
        # ---- control blocks
        left = ttk.Frame(pw)
        tk.Label(left, text="Control blocks (click ☐ = publish this one)", bg="#4a5566", fg="white",
                 anchor="w", padx=6).pack(fill="x")
        cols = ("use", "ied", "cb", "subnet", "mac", "appid", "vlan", "times", "state")
        heads = {"use": ("", 30), "ied": ("IED", 110), "cb": ("GoCB", 70), "subnet": ("SubNetwork / AP", 110),
                 "mac": ("Destination MAC", 130), "appid": ("APPID", 105), "vlan": ("VLAN / prio", 90),
                 "times": ("Min / Max ms", 90), "state": ("State", 230)}
        f = ttk.Frame(left)
        f.pack(fill="both", expand=True)
        self.t = ttk.Treeview(f, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            self.t.heading(c, text=heads[c][0], anchor="w")
            self.t.column(c, width=heads[c][1], anchor="w", stretch=(c == "state"))
        vs = ttk.Scrollbar(f, orient="vertical", command=self.t.yview)
        self.t.configure(yscrollcommand=vs.set)
        self.t.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.t.tag_configure("run", foreground="#1a6e1a")
        self.t.tag_configure("bad", foreground="#b00020")
        self.t.bind("<Button-1>", self.on_click)
        self.t.bind("<<TreeviewSelect>>", self.on_select)
        pw.add(left, weight=1)
        # ---- data set
        right = ttk.Frame(pw)
        self.ds_title = tk.Label(right, text="Data set", bg="#4a5566", fg="white", anchor="w", padx=6)
        self.ds_title.pack(fill="x")
        qb = tk.Frame(right, bg="#e6e9ee", pady=2)
        qb.pack(fill="x")
        tk.Label(qb, text="All q of this data set:", bg="#e6e9ee").pack(side="left", padx=4)
        for txt, kw in (("good", dict(validity="good")), ("invalid", dict(validity="invalid")),
                        ("questionable", dict(validity="questionable")), ("test on", dict(test=True)),
                        ("test off", dict(test=False)), ("reset", dict(clear=True))):
            tk.Button(qb, text=txt, command=lambda kw=kw: self.all_quality(**kw), relief="groove", padx=5, pady=0,
                      bg="#f7f7f7").pack(side="left", padx=1)
        # editor first at the bottom: always visible, also in a small window
        self.ed = tk.Frame(right, pady=6, padx=6, bg="#e6e9ee")
        self.ed.pack(side="bottom", fill="x")
        f2 = ttk.Frame(right)
        f2.pack(fill="both", expand=True)
        self.d = ttk.Treeview(f2, columns=("value", "type"), show="tree headings", selectmode="browse")
        self.d.heading("#0", text="Signal", anchor="w")
        self.d.heading("type", text="Type", anchor="w")
        self.d.heading("value", text="Value", anchor="w")
        self.d.column("#0", width=300, anchor="w")
        self.d.column("type", width=80, anchor="w", stretch=False)
        self.d.column("value", width=170, anchor="w", stretch=False)
        vs2 = ttk.Scrollbar(f2, orient="vertical", command=self.d.yview)
        self.d.configure(yscrollcommand=vs2.set)
        self.d.pack(side="left", fill="both", expand=True)
        vs2.pack(side="right", fill="y")
        self.d.bind("<<TreeviewSelect>>", self.on_node)
        self.d.bind("<Double-1>", self.on_double)
        self._clear_editor()
        pw.add(right, weight=1)
        self._pw = pw
        self._pw_w = 0
        pw.bind("<Configure>", self._place_sash)
        self.after(500, self.refresh_state)

    def _place_sash(self, _e=None):
        """data set = half of the width (set again only when the window width changes)"""
        w = self._pw.winfo_width()
        if w > 100 and abs(w - self._pw_w) > 2:
            self._pw_w = w
            self.after_idle(lambda: self._pw.sashpos(0, int(w * 0.5)))

    # ------------------------------------------------------------ networks
    def fill_nets(self):
        app = self.app
        vals = []
        for i, iface in enumerate(app.nets, 1):
            if iface:
                vals.append("%s  -  %s" % (app.net_name(i), (app.net_labels[i - 1] or iface)[:60]))
        self.c_net["values"] = vals
        if vals and self.v_net.get() not in vals:
            self.v_net.set(vals[0])

    def iface(self):
        self.fill_nets()
        vals = list(self.c_net["values"])
        if not vals:
            return None
        i = vals.index(self.v_net.get()) if self.v_net.get() in vals else 0
        ifaces = [x for x in self.app.nets if x]
        return ifaces[i] if i < len(ifaces) else None

    # ------------------------------------------------------------ load
    def load(self):
        files = filedialog.askopenfilenames(title="CID / SCD of the IEDs to simulate",
                                            filetypes=[("SCL", "*.cid *.scd *.iid *.icd *.CID *.SCD *.IID *.ICD"), ("All", "*.*")])
        if not files:
            return
        errs, n = [], 0
        known = {(g["ref"], g["mac"], g["appid"]) for g in self.gcbs}
        for p in files:
            try:
                for g in gp.load_gcbs(p):
                    k = (g["ref"], g["mac"], g["appid"])
                    if k in known:
                        continue
                    known.add(k)
                    g.update(use=False, active=False, stnum=0, sqnum=0, t_change=time.time(), simulation=True, ndscom=False)
                    self.gcbs.append(g)
                    n += 1
            except Exception as ex:
                errs.append("%s: %s" % (p, ex))
        self.fill_table()
        msg = "%d GOOSE control block(s) loaded." % n
        if errs:
            msg += "\n\nNot read:\n" + "\n".join(errs)
        messagebox.showinfo("GOOSE Publisher", msg, parent=self)

    def remove_all(self):
        if any(g.get("active") for g in self.gcbs):
            messagebox.showinfo("GOOSE Publisher", "Stop the publishing first (STOP ALL).", parent=self)
            return
        self.gcbs = []
        self.sel = None
        self.fill_table()
        self.d.delete(*self.d.get_children())

    def fill_table(self):
        self.t.delete(*self.t.get_children())
        for i, g in enumerate(self.gcbs):
            self.t.insert("", "end", iid="g%d" % i, values=self._row(g), tags=self._tags(g))

    def _row(self, g):
        vlan = "-" if g.get("vlan") is None else "%d / %d" % (g["vlan"], g.get("prio") or 0)
        return ((CHK if g.get("use") else UNCHK), g["ied"], g["cb"], ("%s / %s" % (g.get("subnet", ""), g.get("ap", ""))).strip(" /"),
                g.get("mac") or "(no address)", "0x%04X (%d)" % (g["appid"], g["appid"]), vlan,
                "%g / %g" % (g["min_ms"], g["max_ms"]), self._state(g))

    def _state(self, g):
        s = ("sending  stNum %d  sqNum %d" % (g["stnum"], g["sqnum"])) if g.get("active") else ("error: " + g["error"] if g.get("error") else "stopped")
        if g.get("conflict"):
            s += "   CONFLICT: also from " + g["conflict"]
        return s

    def _tags(self, g):
        if g.get("error") or g.get("conflict"):
            return ("bad",)
        return ("run",) if g.get("active") else ()

    def on_click(self, e):
        iid = self.t.identify_row(e.y)
        if not iid or self.t.identify_column(e.x) != "#1":
            return
        g = self.gcbs[int(iid[1:])]
        if not g.get("mac"):
            messagebox.showinfo("GOOSE Publisher", "This control block has no GSE address (MAC / APPID) in the file.", parent=self)
            return "break"
        g["use"] = not g.get("use")
        if not g["use"] and g.get("active") and self.pub:
            self.pub.remove(g)
        self.t.item(iid, values=self._row(g), tags=self._tags(g))
        return "break"

    # ------------------------------------------------------------ data set
    def on_select(self, _e=None):
        s = self.t.selection()
        if not s:
            return
        self.sel = self.gcbs[int(s[0][1:])]
        g = self.sel
        self.ds_title.configure(text="Data set  %s   (%s, confRev %d, goID %s)" % (g["datset"], g["file"], g["confrev"], g["goid"]))
        self.d.delete(*self.d.get_children())
        self.node_iid = {}
        self._fill_nodes("", g["entries"], "")
        self._clear_editor()

    def _fill_nodes(self, parent, nodes, idx):
        for i, n in enumerate(nodes, 1):
            k = "%s%d" % (idx, i)
            nm = n["name"] if not parent else n["name"].rsplit(".", 1)[-1]
            iid = self.d.insert(parent, "end", text="%s  %s" % (k, nm), open=True,
                                values=(gp.value_text(n), n["btype"] + (" ?" if n.get("unknown") else "")))
            self.node_iid[iid] = n
            if n.get("children"):
                self._fill_nodes(iid, n["children"], k + ".")

    def _clear_editor(self, hint=True):
        for w in self.ed.winfo_children():
            w.destroy()
        if hint:
            tk.Label(self.ed, text="Select a signal to change its value here, or double click it: BOOLEAN toggles, "
                                   "a number / analog value opens an input window. A running control block sends "
                                   "the change at once (stNum + 1).",
                     bg="#e6e9ee", wraplength=520, justify="left").pack(anchor="w")

    def on_double(self, e):
        """double click: BOOLEAN toggles; numbers / analogs / strings: small input window"""
        iid = self.d.identify_row(e.y)
        n = self.node_iid.get(iid)
        if not n or n.get("children"):
            return
        bt = n["btype"]
        if bt == "BOOLEAN":
            self._set(iid, n, not n["value"])
        elif bt in TYPES_NUM or bt.startswith(("VisString", "Unicode")) or (bt == "Enum" and not n.get("enum")):
            from tkinter import simpledialog
            txt = simpledialog.askstring("GOOSE Publisher", "%s\n\nNew value (%s):" % (n["name"], bt),
                                         initialvalue=str(n["value"]), parent=self)
            if txt is None:
                return
            try:
                if bt.startswith("FLOAT"):
                    val = float(txt.replace(",", "."))
                elif bt in TYPES_NUM or bt == "Enum":
                    val = int(float(txt.replace(",", ".")))
                else:
                    val = txt
            except ValueError:
                messagebox.showinfo("GOOSE Publisher", "Not a number: %s" % txt, parent=self)
                return
            self._set(iid, n, val)
            self.on_node()

    def on_node(self, _e=None):
        s = self.d.selection()
        if not s:
            return
        iid = s[0]
        n = self.node_iid.get(iid)
        self._clear_editor(hint=n is None)
        if n is None:
            return
        bg = "#e6e9ee"
        tk.Label(self.ed, text=n["name"], bg=bg, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        row = tk.Frame(self.ed, bg=bg)
        row.pack(anchor="w", pady=4)
        bt = n["btype"]
        if n.get("children"):
            tk.Label(row, text="Structure - select one of its members.", bg=bg).pack(side="left")
            return
        if bt == "BOOLEAN":
            v = tk.BooleanVar(value=bool(n["value"]))
            ttk.Checkbutton(row, text="TRUE", variable=v, command=lambda: self._set(iid, n, v.get())).pack(side="left")
        elif bt in ("Dbpos", "Tcmd"):
            v = tk.StringVar(value=n["value"])
            cb = ttk.Combobox(row, textvariable=v, values=("off", "on", "intermediate", "bad"), state="readonly", width=14)
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>", lambda e: self._set(iid, n, v.get()))
        elif bt == "Quality":
            q = n["value"]
            v = tk.StringVar(value=q.get("validity", "good"))
            tk.Label(row, text="validity", bg=bg).pack(side="left")
            cb = ttk.Combobox(row, textvariable=v, values=("good", "invalid", "questionable", "reserved"),
                              state="readonly", width=13)
            cb.pack(side="left", padx=4)
            fl = tk.Frame(self.ed, bg=bg)
            fl.pack(anchor="w")
            fv = {}
            have = set(q.get("flags", ())) | ({"test"} if q.get("test") else set())

            def apply_q(_e=None):
                on = [nm for nm, var in fv.items() if var.get()]
                self._set(iid, n, {"validity": v.get(), "test": "test" in on, "flags": [x for x in on if x != "test"]})
            for k, (_bit, nm) in enumerate(gp.QUAL_FLAGS):
                fv[nm] = tk.BooleanVar(value=nm in have)
                ttk.Checkbutton(fl, text=nm, variable=fv[nm], command=apply_q).grid(row=k // 4, column=k % 4, sticky="w", padx=4)
            cb.bind("<<ComboboxSelected>>", apply_q)
        elif bt == "Enum" and n.get("enum"):
            opts = ["%s (%d)" % (nm, o) for o, nm in sorted(n["enum"].items())]
            cur = next((x for x in opts if x.endswith("(%d)" % int(n["value"]))), "")
            v = tk.StringVar(value=cur)
            cb = ttk.Combobox(row, textvariable=v, values=opts, state="readonly", width=30)
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>", lambda e: self._set(iid, n, int(v.get().rsplit("(", 1)[1].rstrip(")"))))
        elif bt == "Timestamp":
            tk.Label(row, text="automatic: time of the last change", bg=bg).pack(side="left")
        else:
            v = tk.StringVar(value=str(n["value"]))
            en = ttk.Entry(row, textvariable=v, width=20)
            en.pack(side="left")

            def apply(_e=None):
                try:
                    if bt in TYPES_NUM or bt == "Enum":
                        val = float(v.get().replace(",", ".")) if bt.startswith("FLOAT") else int(float(v.get()))
                    else:
                        val = v.get()
                except ValueError:
                    messagebox.showinfo("GOOSE Publisher", "Not a number: %s" % v.get(), parent=self)
                    return
                self._set(iid, n, val)
            ttk.Button(row, text="Set", command=apply).pack(side="left", padx=6)
            en.bind("<Return>", apply)
            if bt.startswith("FLOAT"):
                tk.Label(row, text="analog value", bg=bg, fg="#555").pack(side="left", padx=6)

    def all_quality(self, validity=None, test=None, clear=False):
        """the same quality for every Quality of the selected data set (one change, stNum + 1)"""
        g = self.sel
        if not g:
            messagebox.showinfo("GOOSE Publisher", "Select a control block first.", parent=self)
            return
        n_q = 0
        for n in gp.all_nodes(g["entries"]):
            if n["btype"] != "Quality" or n.get("children"):
                continue
            q = dict(n["value"])
            if validity is not None:
                q["validity"] = validity
            if test is not None:
                q["test"] = test
            if clear:
                q.update(validity="good", test=False, flags=[])
            n["value"] = q
            n_q += 1
        for iid, n in self.node_iid.items():
            if n["btype"] == "Quality":
                self.d.set(iid, "value", gp.value_text(n))
        if n_q and g.get("active") and self.pub:
            self.pub.change(g)
        self.on_node()

    def _set(self, iid, n, val):
        n["value"] = val
        self.d.set(iid, "value", gp.value_text(n))
        g = self.sel
        if g and g.get("active") and self.pub:
            self.pub.change(g)

    # ------------------------------------------------------------ flags
    def on_sim(self):
        if not self.v_sim.get():
            ok = messagebox.askyesno(
                "GOOSE Publisher - Simulation OFF",
                "Without the simulation flag the messages are NORMAL GOOSE.\n\n"
                "Subscribing IEDs in normal mode WILL react (trip, interlocking, blocking ...).\n\n"
                "Switch Simulation OFF?", icon="warning", parent=self)
            if not ok:
                self.v_sim.set(True)
                return
        self.on_flags()

    def on_flags(self):
        for g in self.gcbs:
            g["simulation"] = self.v_sim.get()
            g["ndscom"] = self.v_nds.get()
            if g.get("active") and self.pub:
                self.pub.change(g)

    # ------------------------------------------------------------ start / stop
    def _publisher(self):
        if self.pub is None or not self.pub.is_alive():
            send = gp.scapy_sender()
            self.pub = gp.Publisher(send, on_error=self._on_error)
            self.pub.start()
        return self.pub

    def _on_error(self, g, text):
        g["error"] = text

    def start(self):
        todo = [g for g in self.gcbs if g.get("use") and not g.get("active")]
        if not todo:
            messagebox.showinfo("GOOSE Publisher", "Tick the control blocks to publish (column ☐).", parent=self)
            return
        iface = self.iface()
        if not iface:
            self.app.choose_nets()
            iface = self.iface()
            if not iface:
                return
        src = gp.adapter_mac(iface)
        lines = "\n".join("  %s  %s  APPID 0x%04X" % (g["ref"], g["mac"], g["appid"]) for g in todo[:12])
        if len(todo) > 12:
            lines += "\n  ... %d more" % (len(todo) - 12)
        sim = self.v_sim.get()
        text = ("Publish %d GOOSE control block(s) on\n  %s\n  (source MAC %s)\n\n%s\n\nSimulation: %s\n\n%s\n\nStart?"
                % (len(todo), self.v_net.get(), src, lines, "ON" if sim else "OFF",
                   "Only IEDs in simulation mode (LPHD.Sim) take these messages." if sim else
                   "NORMAL GOOSE - subscribers WILL react!"))
        if not messagebox.askyesno("GOOSE Publisher", text, icon="warning" if not sim else "question", parent=self):
            return
        try:
            pub = self._publisher()
        except Exception as ex:
            messagebox.showerror("GOOSE Publisher", "Can not send (Npcap / Scapy):\n%s" % ex, parent=self)
            return
        for g in todo:
            g.pop("error", None)
            g["simulation"], g["ndscom"] = sim, self.v_nds.get()
            pub.add(g, iface, src)
        self.refresh_state()

    def stop_all(self):
        if self.pub:
            self.pub.stop()
            self.pub = None
        for g in self.gcbs:
            g["active"] = False
        self.refresh_state()

    # ------------------------------------------------------------ state
    def refresh_state(self):
        try:
            own = {}
            act = [g for g in self.gcbs if g.get("active")]
            for g in act:
                own[g["ref"]] = g.get("src", "")
            # conflict: the same gocbRef seen in the network from another MAC
            seen = {}
            with self.app.lock:
                for st in self.app.tracker.streams.values():
                    m = st["m"]
                    if st["kind"] == "GOOSE" and not st["lost"] and m["ref"] in own:
                        seen.setdefault(m["ref"], set()).add(m["src"])
            for g in self.gcbs:
                other = sorted(s for s in seen.get(g["ref"], set()) if s != g.get("src")) if g.get("active") else []
                g["conflict"] = ", ".join(other)
            for i, g in enumerate(self.gcbs):
                iid = "g%d" % i
                if self.t.exists(iid):
                    self.t.item(iid, values=self._row(g), tags=self._tags(g))
            n = len(act)
            sent = self.pub.count if self.pub else 0
            self.state.configure(text=("SENDING %d control block(s), %d messages, Simulation %s" % (
                n, sent, "ON" if self.v_sim.get() else "OFF")) if n else "Stopped",
                fg=("#b00020" if n and not self.v_sim.get() else ("#1a6e1a" if n else "#555")))
            warn = []
            if n and not self.v_sim.get():
                warn.append("Simulation OFF: normal GOOSE - subscribers react to these messages.")
            if any(g.get("conflict") for g in self.gcbs):
                warn.append("CONFLICT: a published gocbRef also comes from another device - two publishers confuse "
                            "the subscribers (different stNum).")
            if any(g.get("error") for g in self.gcbs):
                warn.append("Sending error - see column State.")
            self.warn.configure(text="\n".join(warn))
        finally:
            self.after(500, self.refresh_state)
