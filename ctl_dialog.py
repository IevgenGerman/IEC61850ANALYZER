# -*- coding: utf-8 -*-
"""
ctl_dialog.py - window Control of the tab MMS / Active (like the Control window of IEDScout).

Before a command the object is read: ctlModel, sboTimeout, stVal / q, Loc, Mod / Beh -> warnings.
ctlVal, originator (orCat station-control, orIdent = name of the PC), Synchrocheck / Interlock-check
(set), Test (not set). Select / Operate / Cancel - each one is confirmed; with enhanced security the
CommandTermination is awaited (timeout). Every command is written to the CSV log file.
"""
import time
import tkinter as tk
from tkinter import ttk, messagebox

import mms_control as ctl

GREEN = "#1a6e1a"
RED = "#b00020"
ORANGE = "#b35900"


class ControlDialog(tk.Toplevel):
    def __init__(self, tab, dom, ln, do):
        super().__init__(tab)
        self.tab = tab
        self.dom, self.ln, self.do = dom, ln, do
        self.I = None
        self.C = None
        self.busy = False
        self.resuggest = False
        self.title("Control - %s/%s.%s" % (dom, ln, do))
        self.transient(tab.winfo_toplevel())
        self.geometry("760x620")
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()

    # ------------------------------------------------------------ GUI
    def _build(self):
        top = tk.Label(self, text="%s/%s.%s" % (self.dom, self.ln, self.do), font=("Segoe UI", 11, "bold"),
                       anchor="w", padx=8, pady=4)
        top.pack(fill="x")
        tk.Label(self, text="IED %s   -   commands operate real equipment" % self.tab.client.peer, fg=RED,
                 anchor="w", padx=8).pack(fill="x")
        inf = ttk.LabelFrame(self, text=" Object (read from the IED) ")
        inf.pack(fill="x", padx=8, pady=4)
        self.lbl = {}
        rows = [("ctl", "ctlModel"), ("sbo", "sboTimeout"), ("st", "stVal / q"), ("loc", "Loc (local / remote)"),
                ("mod", "Mod / Beh of the LN")]
        for i, (k, t) in enumerate(rows):
            tk.Label(inf, text=t + ":", anchor="w").grid(row=i, column=0, sticky="w", padx=6)
            self.lbl[k] = tk.Label(inf, text="...", anchor="w", font=("Segoe UI", 9, "bold"))
            self.lbl[k].grid(row=i, column=1, sticky="w")
        ttk.Button(inf, text="Refresh", command=self.refresh).grid(row=0, column=2, rowspan=2, padx=10)
        self.warn = tk.Label(inf, text="", fg=RED, anchor="w", justify="left", wraplength=700)
        self.warn.grid(row=len(rows), column=0, columnspan=3, sticky="w", padx=6, pady=(2, 4))

        cf = ttk.LabelFrame(self, text=" Command ")
        cf.pack(fill="x", padx=8, pady=4)
        tk.Label(cf, text="ctlVal:").grid(row=0, column=0, sticky="w", padx=6, pady=2)
        self.v_val = tk.StringVar()
        self.c_val = ttk.Combobox(cf, textvariable=self.v_val, width=26)
        self.c_val.grid(row=0, column=1, sticky="w")
        self.val_type = tk.Label(cf, text="", fg="#666")
        self.val_type.grid(row=0, column=2, columnspan=2, sticky="w", padx=6)
        tk.Label(cf, text="Originator category:").grid(row=1, column=0, sticky="w", padx=6, pady=2)
        self.v_cat = tk.StringVar(value="station-control")
        ttk.Combobox(cf, textvariable=self.v_cat, values=ctl.OR_CAT, state="readonly", width=24).grid(
            row=1, column=1, sticky="w")
        tk.Label(cf, text="Originator identification:").grid(row=2, column=0, sticky="w", padx=6, pady=2)
        self.v_ident = tk.StringVar(value=ctl.pc_name())
        ttk.Entry(cf, textvariable=self.v_ident, width=28).grid(row=2, column=1, sticky="w")
        self.v_sync = tk.BooleanVar(value=True)
        self.v_ilk = tk.BooleanVar(value=True)
        self.v_test = tk.BooleanVar(value=False)
        ck = tk.Frame(cf)
        ck.grid(row=3, column=0, columnspan=4, sticky="w", padx=6, pady=2)
        ttk.Checkbutton(ck, text="Synchrocheck", variable=self.v_sync).pack(side="left")
        ttk.Checkbutton(ck, text="Interlock-check", variable=self.v_ilk).pack(side="left", padx=12)
        ttk.Checkbutton(ck, text="Test", variable=self.v_test).pack(side="left")
        tk.Label(cf, text="Wait for CommandTermination:").grid(row=4, column=0, sticky="w", padx=6, pady=2)
        tf = tk.Frame(cf)
        tf.grid(row=4, column=1, sticky="w")
        self.v_tmo = tk.StringVar(value="10")
        ttk.Spinbox(tf, from_=1, to=120, textvariable=self.v_tmo, width=5).pack(side="left")
        tk.Label(tf, text="s").pack(side="left", padx=2)

        bf = tk.Frame(self)
        bf.pack(fill="x", padx=8, pady=6)
        self.b_sel = ttk.Button(bf, text="Select", command=lambda: self.action("Select"))
        self.b_sel.pack(side="left")
        self.b_op = tk.Button(bf, text="Operate", command=lambda: self.action("Operate"), bg="#b00020", fg="white",
                              activebackground="#7a0016", activeforeground="white", relief="flat", padx=16)
        self.b_op.pack(side="left", padx=8)
        self.b_cancel = ttk.Button(bf, text="Cancel (command)", command=lambda: self.action("Cancel"))
        self.b_cancel.pack(side="left")
        ttk.Button(bf, text="Close", command=self.close).pack(side="right")
        self.state_lbl = tk.Label(bf, text="", fg="#555")
        self.state_lbl.pack(side="left", padx=10)

        lf = ttk.LabelFrame(self, text=" Result ")
        lf.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.out = tk.Text(lf, height=8, font=("Consolas", 9), wrap="word")
        self.out.pack(fill="both", expand=True)
        self.out.tag_configure("ok", foreground=GREEN)
        self.out.tag_configure("bad", foreground=RED)
        self.out.tag_configure("info", foreground="#555")
        tk.Label(self, text="Log file: %s" % ctl.LOG_FILE, fg="#666", anchor="w", padx=8).pack(fill="x")

    def say(self, text, tag="info"):
        self.out.insert("end", "%s  %s\n" % (time.strftime("%H:%M:%S"), text), tag)
        self.out.see("end")

    # ------------------------------------------------------------ object
    def refresh(self):
        if not self.tab.connected():
            self.say("not connected", "bad")
            return
        cl, om = self.tab.client, self.tab.om
        self.state_lbl.config(text="reading the object ...")
        self.tab.run(ctl.info, cl, om, self.dom, self.ln, self.do, done=self._info)

    def _info(self, I, err):
        if not self.winfo_exists():
            return
        self.state_lbl.config(text="")
        if err:
            self.say("read failed: %s" % err, "bad")
            return
        first = self.I is None
        self.I = I
        if self.C is None:
            self.C = ctl.Control(self.tab.client, self.tab.om, I)
            self.tab.controls.append(self.C)
        else:
            self.C.I = I
        self.lbl["ctl"].config(text=I["ctl_model_text"])
        self.lbl["sbo"].config(text=(I["sbo_timeout"] + " ms") if I["sbo_timeout"] else "-")
        self.lbl["st"].config(text="%s   %s" % (I["st_val"] or "-", I["q"]),
                              fg=GREEN if I["st_val"] in ("TRUE",) or I["st_val"].startswith("on") else "black")
        self.lbl["loc"].config(text=I["loc"] or "-", fg=RED if I["loc"] == "local" else "black")
        self.lbl["mod"].config(text="%s / %s" % (I["mod"] or "-", I["beh"] or "-"))
        w = ctl.warnings(I)
        self.warn.config(text="\n".join("⚠ " + x for x in w))
        t = ctl.ctl_val_type(I)
        k = ctl.ctl_kind(t)
        self.val_type.config(text="(%s)" % {"bool": "BOOLEAN: TRUE = on / close, FALSE = off / open",
                                            "tcmd": "Tcmd", "int": "INTEGER", "uint": "UNSIGNED",
                                            "float": "FLOAT", "analog": "AnalogueValue"}.get(k, k))
        if first or self.resuggest:
            self.resuggest = False
            if k == "bool":
                self.c_val.configure(values=["TRUE", "FALSE"], state="readonly")
                cur = I["st_val"] in ("TRUE",) or I["st_val"].startswith("on")
                self.v_val.set("FALSE" if cur else "TRUE")
            elif k == "tcmd":
                self.c_val.configure(values=["lower", "higher", "stop"], state="readonly")
                self.v_val.set("higher")
            else:
                self.c_val.configure(values=[], state="normal")
                self.v_val.set("0")
        m = I["ctl_model"]
        sbo = m in (2, 4)
        self.b_sel.configure(state="normal" if sbo else "disabled")
        self.b_cancel.configure(state="normal" if (I["has_cancel"] and m not in (0, 1)) else "disabled")
        self.b_op.configure(state="disabled" if (m == 0 or I["oper_type"] is None) else "normal")
        self.say("%s: ctlModel %s, stVal %s %s, Loc %s, Mod/Beh %s / %s" % (
            I["ref"], I["ctl_model_text"], I["st_val"] or "-", I["q"], I["loc"] or "-", I["mod"] or "-",
            I["beh"] or "-"))

    # ------------------------------------------------------------ commands
    def _value(self):
        k = ctl.ctl_kind(ctl.ctl_val_type(self.I))
        t = self.v_val.get().strip()
        if k == "bool":
            return t.upper() == "TRUE"
        if k == "tcmd":
            return t
        if k in ("int", "uint"):
            return int(t)
        return float(t.replace(",", "."))

    def action(self, what):
        if self.busy or self.I is None:
            return
        if not self.tab.connected():
            self.say("not connected", "bad")
            return
        try:
            val = self._value()
        except ValueError:
            messagebox.showwarning("Control", "ctlVal '%s' is not valid." % self.v_val.get(), parent=self)
            return
        I = self.I
        cat = ctl.OR_CAT.index(self.v_cat.get())
        ident = self.v_ident.get()
        test, sync, ilk = self.v_test.get(), self.v_sync.get(), self.v_ilk.get()
        if what == "Operate" and I["ctl_model"] in (2, 4) and not self.C.selected:
            if not messagebox.askyesno("Control", "%s uses %s: Select first.\n\nOperate without Select anyway "
                                       "(the IED will refuse it)?" % (I["ref"], I["ctl_model_text"]),
                                       parent=self, icon="warning", default="no"):
                return
        warn = ctl.warnings(I)
        msg = "%s\n\n%s   ctlVal = %s\nIED %s\n%s, %s%s%s%s\n\n%sContinue?" % (
            I["ref"], what.upper(), self.v_val.get(), self.tab.client.peer, self.v_cat.get(), ident,
            ", Synchrocheck" if sync else "", ", Interlock-check" if ilk else "", ", TEST" if test else "",
            ("Warnings:\n" + "\n".join(warn) + "\n\n") if warn else "")
        if not messagebox.askyesno("Confirm %s" % what, msg, parent=self, icon="warning", default="no"):
            self.say("%s not sent (not confirmed)" % what)
            return
        self.busy = True
        self.state_lbl.config(text="%s ..." % what)
        self.say("%s ctlVal %s ..." % (what, self.v_val.get()))
        C = self.C
        try:
            tmo = max(1.0, float(self.v_tmo.get()))
        except ValueError:
            tmo = 10.0

        def job():
            if what == "Select":
                return C.select(val, cat, ident, test, sync, ilk)
            if what == "Operate":
                return C.operate(val, cat, ident, test, sync, ilk, timeout=tmo)
            return C.cancel(val, cat, ident, test)
        self.tab.run(job, done=lambda r, e: self._done(what, r, e, val, cat, ident, test, sync, ilk))

    def _done(self, what, res, err, val, cat, ident, test, sync, ilk):
        self.busy = False
        if not self.winfo_exists():
            return
        self.state_lbl.config(text="")
        ok, text = (False, "error: %s" % err) if err else res
        self.say("%s: %s" % (what, text), "ok" if ok else "bad")
        path = ctl.log_command(self.tab.client.peer, " / ".join(self.tab.om.get("ident") or []), self.I, what,
                               self.v_val.get(), cat, ident, self.C.ctl_num, test, sync, ilk, ok, text)
        self.tab.write_log("CONTROL %s %s ctlVal %s: %s%s" % (what, self.I["ref"], self.v_val.get(), text,
                                                              "" if path else "  (log file not writable)"),
                           not ok)
        if what == "Operate":
            self.resuggest = ok
            self.after(500, self.refresh)

    def close(self):
        if self.C in self.tab.controls:
            self.tab.controls.remove(self.C)
        self.destroy()
