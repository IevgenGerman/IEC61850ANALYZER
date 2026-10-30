# -*- coding: utf-8 -*-
"""
rpt_tab.py - tab MMS / Report test of IEC61850ANALYZER (see rpt_test.py).

  Load CID / SCD...   the IED to test (CID: its own IED; SCD: choose the IED)
  Start test / Stop   only reports received while the test runs are counted (live or Open .pcap)
  Reset               start again (all results cleared)
  Required            reasons needed for "completed" (data change, GI, integrity by default)
  Open / Save test    .json - continue another day; the test is saved again automatically every
                      30 s after the first Save
  Export CSV          result for the commissioning documents (opens in Excel)
"""
import os
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import rpt_test as rt

GREEN = "#1a6e1a"
RED = "#b00020"
GREY = "#9a9a9a"


class ReportTestTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.test = None
        self.running = False
        self.dirty = False
        self.save_path = None
        self.last_save = 0
        self.cid_path = None
        # ---- bar 1
        bar = tk.Frame(self, bg="#f3f3f3", pady=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Load CID / SCD...", command=self.load).pack(side="left", padx=(4, 2))
        tk.Label(bar, text="IED:", bg="#f3f3f3").pack(side="left", padx=(6, 2))
        self.v_ied = tk.StringVar()
        self.c_ied = ttk.Combobox(bar, textvariable=self.v_ied, state="readonly", width=18)
        self.c_ied.pack(side="left")
        self.c_ied.bind("<<ComboboxSelected>>", lambda e: self.new_test(self.cid_path, self.v_ied.get()))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        self.b_start = tk.Button(bar, text="▶ Start test", command=self.start, bg="#2e7d32", fg="white",
                                 activebackground="#1b5e20", activeforeground="white", relief="flat", padx=10)
        self.b_start.pack(side="left", padx=2)
        ttk.Button(bar, text="■ Stop", command=self.stop).pack(side="left", padx=2)
        ttk.Button(bar, text="Reset", command=self.reset).pack(side="left", padx=2)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(bar, text="Open test...", command=self.open_test).pack(side="left", padx=2)
        ttk.Button(bar, text="Save test...", command=self.save_test).pack(side="left", padx=2)
        ttk.Button(bar, text="Export CSV...", command=self.export).pack(side="left", padx=2)
        # ---- bar 2: required reasons
        bar2 = tk.Frame(self, bg="#f3f3f3", pady=2)
        bar2.pack(fill="x")
        tk.Label(bar2, text="Required for 'completed':", bg="#f3f3f3").pack(side="left", padx=(6, 4))
        self.v_req = {}
        for k in rt.REASONS:
            v = tk.BooleanVar(value=k in rt.DEFAULT_REQUIRED)
            self.v_req[k] = v
            ttk.Checkbutton(bar2, text=rt.REASON_TEXT[k], variable=v, command=self.on_required).pack(side="left", padx=4)
        tk.Label(bar2, text="   data change of BOOLEAN / Dbpos needs both states", bg="#f3f3f3", fg="#666").pack(side="left")
        # ---- info + status
        self.info = tk.Label(self, text="Load the CID of the IED to test.", anchor="w", justify="left", padx=8, pady=2)
        self.info.pack(fill="x")
        self.status = tk.Label(self, text="", anchor="w", padx=8, pady=4, font=("Segoe UI", 11, "bold"))
        self.status.pack(fill="x")
        pw = ttk.PanedWindow(self, orient="vertical")
        pw.pack(fill="both", expand=True)
        # ---- CID check
        f1 = ttk.Frame(pw)
        tk.Label(f1, text="CID check (reports of the IED compared with the CID)", bg="#4a5566", fg="white",
                 anchor="w", padx=6).pack(fill="x")
        self.iss = ttk.Treeview(f1, columns=("count", "first", "last"), show="tree headings", height=5)
        self.iss.heading("#0", text="Finding", anchor="w")
        self.iss.heading("count", text="Count", anchor="w")
        self.iss.heading("first", text="First", anchor="w")
        self.iss.heading("last", text="Last", anchor="w")
        self.iss.column("#0", width=900, anchor="w")
        for c, w in (("count", 60), ("first", 140), ("last", 140)):
            self.iss.column(c, width=w, anchor="w", stretch=False)
        self.iss.tag_configure("ok", foreground=GREEN)
        self.iss.tag_configure("bad", foreground=RED)
        self.iss.pack(fill="both", expand=True)
        pw.add(f1, weight=1)
        # ---- coverage
        f2 = ttk.Frame(pw)
        tk.Label(f2, text="Signals of the report data sets (click the data set line to include / exclude it)",
                 bg="#4a5566", fg="white", anchor="w", padx=6).pack(fill="x")
        cols = ("type",) + tuple(rt.REASONS) + ("states", "mindt", "last", "status")
        head = {"type": ("Type", 70), "dchg": ("data change", 135), "qchg": ("quality change", 135),
                "dupd": ("data update", 110), "integrity": ("integrity", 135), "gi": ("GI", 135),
                "states": ("States", 90), "mindt": ("Min Δt states, ms", 110), "last": ("Last value", 140),
                "status": ("Status", 260)}
        tf = ttk.Frame(f2)
        tf.pack(fill="both", expand=True)
        self.cov = ttk.Treeview(tf, columns=cols, show="tree headings")
        self.cov.heading("#0", text="Data set / signal", anchor="w")
        self.cov.column("#0", width=330, anchor="w")
        for c in cols:
            self.cov.heading(c, text=head[c][0], anchor="w")
            self.cov.column(c, width=head[c][1], anchor="w", stretch=(c == "status"))
        vs = ttk.Scrollbar(tf, orient="vertical", command=self.cov.yview)
        hs = ttk.Scrollbar(tf, orient="horizontal", command=self.cov.xview)
        self.cov.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.cov.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)
        self.cov.tag_configure("ok", foreground=GREEN)
        self.cov.tag_configure("ds", font=("Segoe UI", 9, "bold"))
        self.cov.tag_configure("off", foreground=GREY)
        self.cov.bind("<Button-1>", self.on_click)
        pw.add(f2, weight=4)
        self.after(500, self.tick)

    # ------------------------------------------------------------ CID
    def load(self):
        path = filedialog.askopenfilename(title="CID / SCD of the IED to test",
                                          filetypes=[("SCL", "*.cid *.scd *.iid *.icd *.CID *.SCD *.IID *.ICD"), ("All", "*.*")])
        if not path:
            return
        try:
            ieds = rt.list_ieds(path)
        except Exception as ex:
            messagebox.showerror("Report test", str(ex), parent=self)
            return
        own = os.path.splitext(path)[1].lower() != ".scd"
        self.cid_path = path
        self.c_ied["values"] = ieds[:1] if own else ieds
        self.v_ied.set(ieds[0] if ieds else "")
        if ieds:
            self.new_test(path, ieds[0])

    def new_test(self, path, ied):
        if self.test and self.test.reports and not messagebox.askyesno(
                "Report test", "Start a new test for %s? The results of the current test are cleared "
                               "(save it first if needed)." % ied, parent=self):
            return
        try:
            info = rt.load_ied(path, ied)
        except Exception as ex:
            messagebox.showerror("Report test", str(ex), parent=self)
            return
        self.test = rt.ReportTest(info, [k for k, v in self.v_req.items() if v.get()])
        self.save_path = None
        self.running = False
        self.refresh()

    # ------------------------------------------------------------ run
    def start(self):
        if not self.test:
            messagebox.showinfo("Report test", "Load the CID of the IED first.", parent=self)
            return
        self.running = True
        if not self.app.running and not messagebox.askyesno(
                "Report test", "The test counts the reports that arrive while it runs.\n\n"
                               "Start the capture now (button Start)?\n(No = use Open .pcap later)", parent=self):
            self.refresh()
            return
        if not self.app.running:
            self.app.start()
        self.refresh()

    def stop(self):
        self.running = False
        self.refresh()

    def reset(self):
        if not self.test:
            return
        if not messagebox.askyesno("Report test", "Clear all results of the test?", parent=self):
            return
        self.test = rt.ReportTest(self.test.info if not self.test.dyn else rt.load_ied(self.test.info["path"], self.test.info["ied"]),
                                  [k for k, v in self.v_req.items() if v.get()])
        self.refresh()

    def on_required(self):
        if self.test:
            self.test.required = {k for k, v in self.v_req.items() if v.get()}
            if self.test.completed and self.test.progress()[0] != self.test.progress()[1]:
                self.test.completed = None
            self.dirty = True
            self.refresh()

    def feed(self, msgs):
        """MMS messages from the capture / file (GUI thread)"""
        if not (self.running and self.test):
            return
        learned = self.app.mms.learned
        for m in msgs:
            if m.get("report") and self.test.feed(m, learned):
                self.dirty = True

    # ------------------------------------------------------------ files
    def save_test(self):
        if not self.test:
            return
        name = "RCB_test_%s_%s.json" % (self.test.info["ied"], time.strftime("%Y-%m-%d"))
        path = filedialog.asksaveasfilename(title="Save the test", defaultextension=".json", initialfile=name,
                                            filetypes=[("Test", "*.json")], parent=self)
        if not path:
            return
        self.test.save(path)
        self.save_path = path
        self.last_save = time.time()
        self.dirty = False
        self.refresh()

    def open_test(self):
        path = filedialog.askopenfilename(title="Open a test", filetypes=[("Test", "*.json")], parent=self)
        if not path:
            return
        try:
            t = rt.ReportTest.open(path)
        except FileNotFoundError:
            cid = filedialog.askopenfilename(title="CID / SCD of the test (not found at its old place)",
                                             filetypes=[("SCL", "*.cid *.scd *.iid *.icd"), ("All", "*.*")], parent=self)
            if not cid:
                return
            t = rt.ReportTest.open(path, cid)
        except Exception as ex:
            messagebox.showerror("Report test", str(ex), parent=self)
            return
        self.test = t
        self.cid_path = t.info["path"]
        self.c_ied["values"] = [t.info["ied"]]
        self.v_ied.set(t.info["ied"])
        for k, v in self.v_req.items():
            v.set(k in t.required)
        self.save_path = path
        self.running = False
        self.refresh()

    def export(self):
        if not self.test:
            return
        name = "RCB_test_%s_%s.csv" % (self.test.info["ied"], time.strftime("%Y-%m-%d_%H%M"))
        path = filedialog.asksaveasfilename(title="Export the result", defaultextension=".csv", initialfile=name,
                                            filetypes=[("CSV (Excel)", "*.csv")], parent=self)
        if path:
            self.test.export_csv(path)
            messagebox.showinfo("Report test", "Saved:\n%s" % path, parent=self)

    # ------------------------------------------------------------ view
    def tick(self):
        try:
            if self.dirty and self.test:
                self.refresh()
                if self.save_path and time.time() - self.last_save > 30:
                    self.test.save(self.save_path)
                    self.last_save = time.time()
                self.dirty = False
        finally:
            self.after(500, self.tick)

    def on_click(self, e):
        iid = self.cov.identify_row(e.y)
        if iid.startswith("ds|") and self.test and self.cov.identify_column(e.x) == "#0" and e.x > 18:
            ds = iid[3:]
            self.test.include[ds] = not self.test.include.get(ds, True)
            self.dirty = True
            self.refresh()

    def refresh(self):
        T = self.test
        self.iss.delete(*self.iss.get_children())
        if not T:
            self.info.configure(text="Load the CID of the IED to test.")
            self.status.configure(text="", fg="black")
            self.cov.delete(*self.cov.get_children())
            return
        i = T.info
        extra = ""
        if i.get("rcbs_no_ds"):
            extra = "   |   %d RCB(s) in the CID without data set (configured in the IED) - their reports are tested " \
                    "with the data set seen in the traffic" % len(i["rcbs_no_ds"])
        self.info.configure(text="IED %s   |   IP %s   |   %s   |   %d RCB(s), %d data set(s)   |   reports received: %d   |   "
                                 "test started %s   |   %s%s" % (
                                     i["ied"], ", ".join(i.get("ips") or ["-"]), i["file"], len(i["rcbs"]),
                                     len(i["datasets"]), T.reports, T.started,
                                     "RUNNING" if self.running else "stopped",
                                     (" - auto save: " + os.path.basename(self.save_path)) if self.save_path else "") + extra)
        done, total = T.progress()
        if T.completed:
            self.status.configure(text=T.status_text(), fg=GREEN)
        else:
            self.status.configure(text="%s%s" % (T.status_text(), "" if self.running else "   (press Start test)"),
                                  fg=RED if T.issues else "black")
        if not T.issues:
            self.iss.insert("", "end", text="OK - no difference between the reports and the CID" if T.reports
                            else "no report of this IED yet", tags=("ok",) if T.reports else ())
        for txt, x in T.issues.items():
            self.iss.insert("", "end", text=txt, values=(x["count"], x["first"], x["last"]), tags=("bad",))
        # coverage
        open_ds = {iid for iid in self.cov.get_children() if self.cov.item(iid, "open")}
        first = not self.cov.get_children()
        y = self.cov.yview()
        self.cov.delete(*self.cov.get_children())
        rcb_of = {}
        for r in i["rcbs"]:
            rcb_of.setdefault(r["dataset"], []).append(r["name"])
        for ds, x in T.dyn.items():
            rcb_of.setdefault(ds, []).append("%s - not in CID" % x["rid"])
        for ds, ents in i["datasets"].items():
            inc = T.include.get(ds, True)
            d_done = d_tot = 0
            for n in range(len(ents)):
                for k in T.checks(ds, n):
                    d_tot += 1
                    d_done += 1 if T.check_ok(ds, n, k) else 0
            iid = "ds|" + ds
            self.cov.insert("", "end", iid=iid, open=(first or iid in open_ds),
                            text="%s %s   (%s)" % ("☑" if inc else "☐", ds, ", ".join(rcb_of.get(ds, []))),
                            values=("", "", "", "", "", "", "", "", "", "%d of %d checks" % (d_done, d_tot) if inc else "excluded"),
                            tags=("ds",) + (("ok",) if inc and d_tot and d_done == d_tot else ()) + (() if inc else ("off",)))
            for n, ce in enumerate(ents):
                c = T.cov[ds][n]
                poss = T.possible(ds, n)
                cells = []
                for k in rt.REASONS:
                    s = c["seen"].get(k)
                    if k not in poss:
                        cells.append("n/a" if not s else "(%d×)" % s["count"])
                    elif s:
                        mark = "✔" if (k not in T.required or T.check_ok(ds, n, k)) else "…"
                        cells.append("%s %s (%d×)" % (mark, rt.now_text(s["first"])[11:], s["count"]))
                    else:
                        cells.append("—")
                miss = T.missing(ds, n)
                st = "/".join(sorted(c["states"]))
                self.cov.insert(iid, "end", text="%d  %s" % (n + 1, ce["name"]),
                                values=(ce["btype"],) + tuple(cells) + (
                                    st, "" if c["min_dt"] is None else "%.0f" % (c["min_dt"] * 1000), c["last_value"],
                                    "OK" if not miss else "missing: " + ", ".join(miss)),
                                tags=(("ok",) if not miss and T.checks(ds, n) else ()) + (() if inc else ("off",)))
        if y:
            self.cov.yview_moveto(y[0])
