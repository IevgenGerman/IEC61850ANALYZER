# -*- coding: utf-8 -*-
"""
IEC61850ANALYZER - GOOSE, Sampled Values and PTP (like the Sniffer of IEDScout).
Author: German Ievgen.

  python sniffer.py                       GUI
  python sniffer.py --file capture.pcapng opens a capture file at start (analysis without network)

Networks: 1 or 2 adapters (e.g. PB A / PB B, PRP LAN A / LAN B) - column "Net";
column "LAN" = A / B from the PRP trailer of the frame.
Tabs GOOSE / SV: message list (left), Details + Data (right), column "Signal (SCL)" (names
from SCD / CID files, can be hidden).
Retransmission ON  - every message; OFF - GOOSE: first message of a stream + changes of values
or qualities; SV: first frame + changes of qualities. A stream that stops (GOOSE: longer than TAL,
SV: 1 s) gives a grey line "STREAM LOST"; when it comes back it is shown again.
Messages with the simulation flag: orange background, [SIM] in the description.
Tab PTP: IEEE 1588 / IEC 61850-9-3 messages (Ethernet 0x88F7 and UDP 319 / 320), panel Clocks:
grandmaster by BMCA, announced clocks, warnings, check against IEC 61850-9-3.
SV tab, panel Phasors: RMS / angle / frequency of the selected stream (primary; secondary when
the stream matches an SV control block of the loaded SCD / CID). Filters...: display filter.
Needs: Python 3, scapy (pip install scapy), on Windows Npcap (https://npcap.com).
"""
import os
import sys
import json
import time
import queue
import threading
import datetime
import argparse
import webbrowser
import traceback

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sniff_core as sc          # noqa: E402
import scl_names as sn           # noqa: E402
import capture as cp             # noqa: E402
import analog as an              # noqa: E402
import filters as fl             # noqa: E402
import ptp                       # noqa: E402
import updater                   # noqa: E402

APP = "IEC61850ANALYZER"
VERSION = "v 0.2.0"
MAX_ROWS = 50000                 # per tab; older rows are dropped
DRAIN_PER_TICK = 4000            # messages moved from the capture queue to the view per 100 ms
GREY = "#9a9a9a"
SIM_BG = "#ffd9a8"               # background of messages with the simulation flag
SETTINGS = os.path.join(os.path.expanduser("~"), ".iec61850analyzer.json")
SETTINGS_OLD = os.path.join(os.path.expanduser("~"), ".iec61850_sniffer.json")   # v0.1 / first v0.2 builds
AUTHOR = {"en": "German Ievgen", "uk": "German Ievgen"}
AUTHOR_URL = "https://www.linkedin.com/in/ievgen-german-945b16b6/"
                 # LinkedIn profile of the author (click on the name); empty = no link
GITHUB_REPO = ""                 # "<owner>/<repository>" on GitHub: update check at start (empty = no check)
AUTHOR_MAIL = "german.kbrza@gmailgit init.com"   # click -> new e-mail in the default mail program (Outlook)
ABOUT = {
    "en": dict(title="About", text="This is a test program meant to make commissioning work easier.\n\n"
                                   "If you find that the program works incorrectly, please send a description "
                                   "of the problem.", author="Author:", lang="Українська", ok="OK",
               upd_auto="Check for updates at start", upd_btn="Check for updates", upd_new="New version %s is available.",
               upd_cur="You have the newest version (%s).", upd_err="Can not reach GitHub (no network or proxy).",
               banner="New version %s is available (you have %s).", download="Download", page="Release page",
               hide="Hide"),
    "uk": dict(title="Про програму", text="Це тестова програма для спроби спростити роботу під час наладки.\n\n"
                                          "Якщо ви виявили некоректну роботу програми, будь ласка, надішліть опис "
                                          "проблеми.", author="Автор:", lang="English", ok="OK",
               upd_auto="Перевіряти оновлення при запуску", upd_btn="Перевірити оновлення",
               upd_new="Доступна нова версія %s.", upd_cur="У вас найновіша версія (%s).",
               upd_err="Немає зв'язку з GitHub (мережа або проксі).",
               banner="Доступна нова версія %s (у вас %s).", download="Завантажити", page="Сторінка релізу",
               hide="Сховати"),
}


def load_settings():
    try:
        with open(SETTINGS if os.path.exists(SETTINGS) or not os.path.exists(SETTINGS_OLD) else SETTINGS_OLD,
                  encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(d):
    try:
        s = load_settings()
        s.update(d)
        with open(SETTINGS, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=1)
    except Exception:
        pass


def tstr(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")


# ---------------------------------------------------------------- one tab (GOOSE, SV or PTP)
class StreamTab(ttk.Frame):
    COLS = ("time", "rel", "net", "lan", "src", "dst", "appid", "vlan", "prio", "desc", "event")
    COLS_GOOSE = ("time", "ied", "rel", "net", "lan", "src", "dst", "appid", "vlan", "prio", "desc", "event")
    COLS_PTP = ("time", "rel", "net", "lan", "src", "dst", "vlan", "prio", "mtype", "domain", "clock", "seq",
                "intv", "info", "event")
    HEAD = {"time": ("Time", 128), "ied": ("IEDName", 120), "rel": ("Relative time", 95), "net": ("Network", 85),
            "lan": ("LAN", 40), "src": ("Source", 140), "dst": ("Destination", 140), "appid": ("APPID", 118),
            "vlan": ("VLAN ID", 85), "prio": ("Prio", 40), "desc": ("gocbRef", 330), "event": ("Event", 60),
            "mtype": ("Message type", 140), "domain": ("Domain", 55), "clock": ("Clock identity - port", 215),
            "seq": ("Seq", 55), "intv": ("Interval", 65), "info": ("Info", 330)}
    # LD inst names glued to the IED name in gocbRef (<IED><LD>/LLN0$GO$..): removed for the IEDName
    # column when no SCL is loaded (GE UR: "Master"); the LD names of loaded SCL files are added
    LD_SUFFIX = ("Master", "System", "LD0", "LD1", "LD2", "CTRL", "Ctrl", "PROT", "Prot", "MEAS", "Meas",
                 "Application", "GOOSE", "Goose")

    def __init__(self, master, app, kind):
        super().__init__(master)
        self.app, self.kind = app, kind
        self.cols = {"GOOSE": self.COLS_GOOSE, "PTP": self.COLS_PTP}.get(kind, self.COLS)   # IEDName: GOOSE only
        self.rows = []                 # messages of the model (newest last)
        self.iid = {}                  # tree iid -> message
        self.n = 0
        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True)
        # ---- messages
        left = ttk.Frame(pw)
        tk.Label(left, text="Messages", bg="#4a5566", fg="white", anchor="w", padx=6).pack(fill="x")
        sf = ttk.Frame(left)
        sf.pack(fill="x", pady=3)
        self.search = tk.StringVar()
        ttk.Entry(sf, textvariable=self.search, width=40).pack(side="left", padx=(2, 4))
        ttk.Button(sf, text="Find", command=self.rebuild).pack(side="left")
        ttk.Button(sf, text="x", width=2, command=lambda: (self.search.set(""), self.rebuild())).pack(side="left", padx=2)
        self.flabel = tk.Label(sf, text="", fg="#b00020", anchor="w")      # "Filter ON: n hidden"
        self.flabel.pack(side="left", padx=8)
        self.hidden_n = 0
        tf = ttk.Frame(left)
        tf.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tf, columns=self.cols, show="headings", selectmode="browse")
        for c in self.cols:
            self.tree.heading(c, text=self.col_title(c), anchor="w")
            self.tree.column(c, width=self.HEAD[c][1], anchor="w", stretch=(c in ("desc", "info")))
        vs = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)
        self.tree.tag_configure("lost", foreground=GREY)
        self.tree.tag_configure("back", foreground="#1a6e1a")
        self.tree.tag_configure("change", foreground="#000000")
        self.tree.tag_configure("err", foreground="#b00020")
        self.tree.tag_configure("sim", background=SIM_BG)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Button-3>", self.on_right_click)
        self.tree.bind("<Button-2>", self.on_right_click)       # macOS
        st = load_settings()
        self.hidden = set(st.get("hidden_cols_" + kind, []))       # columns hidden by the user
        self.net_always = bool(st.get("net_always_" + kind, False))
        self.net_auto = True
        pw.add(left, weight=3)
        # ---- details
        right = ttk.Frame(pw)
        tk.Label(right, text="Details", bg="#4a5566", fg="white", anchor="w", padx=6).pack(fill="x")
        self.title = tk.Label(right, text="", anchor="w", font=("Segoe UI", 10, "bold"), padx=6, pady=4)
        self.title.pack(fill="x")
        self.head = ttk.Treeview(right, columns=("f", "v"), show="headings", height={"GOOSE": 18, "SV": 10}.get(kind, 12))
        self.head.heading("f", text="Details", anchor="w")
        self.head.heading("v", text="", anchor="w")
        self.head.column("f", width=205, anchor="w", stretch=False)
        self.head.column("v", width=330, anchor="w")
        self.head.pack(fill="x", padx=2)
        self.sel_key = None
        if kind == "SV":
            self._phasor_panel(right)
        if kind == "PTP":
            self._clocks_panel(right)
        tk.Label(right, text="TLV (extensions)" if kind == "PTP" else "Data", anchor="w", padx=6, pady=2,
                 bg="#e6e9ee").pack(fill="x", pady=(6, 0))
        df = ttk.Frame(right)
        df.pack(fill="both", expand=True)
        self.data = ttk.Treeview(df, columns=("value", "rms", "type", "sig"), show="tree headings")
        self.data_ch = {}              # SV: channel -> iid of its value row (column RMS from Phasors)
        self.data.heading("#0", text="Name", anchor="w")
        self.data.heading("value", text="Value", anchor="w")
        self.data.heading("rms", text="RMS (Phasors)", anchor="w")
        self.data.column("rms", width=105, anchor="e", stretch=False)
        self.data.heading("type", text="Type", anchor="w")
        self.data.heading("sig", text="Signal (SCL)", anchor="w")
        self.data.column("#0", width=110, anchor="w", stretch=False)
        self.data.column("value", width=230, anchor="w")
        self.data.column("type", width=80, anchor="w", stretch=False)
        self.data.column("sig", width=280, anchor="w")
        dv = ttk.Scrollbar(df, orient="vertical", command=self.data.yview)
        self.data.configure(yscrollcommand=dv.set)
        self.data.pack(side="left", fill="both", expand=True)
        dv.pack(side="right", fill="y")
        pw.add(right, weight=2)
        self.show_sig(app.var_sig.get())

    # ------------------------------------------------------------ phasors (SV)
    def _phasor_panel(self, right):
        hf = tk.Frame(right, bg="#e6e9ee")
        hf.pack(fill="x", pady=(6, 0))
        tk.Label(hf, text="Phasors (selected stream)", anchor="w", padx=6, pady=2, bg="#e6e9ee").pack(side="left")
        self.ph_mode = tk.Label(hf, text="", anchor="e", padx=6, bg="#e6e9ee", font=("Segoe UI", 9, "bold"))
        self.ph_mode.pack(side="right")
        self.ph_ref = ttk.Combobox(hf, textvariable=self.app.var_ref, state="readonly", width=7,
                                   values=("Auto", "Ia", "Ib", "Ic", "In", "Va", "Vb", "Vc", "Vn"))
        self.ph_ref.pack(side="right")
        self.ph_ref.bind("<<ComboboxSelected>>", lambda e: self.app.on_ref())
        tk.Label(hf, text="Angle reference:", bg="#e6e9ee").pack(side="right")
        self.ph_info = tk.Label(right, text="Select a SV message.", anchor="w", justify="left", padx=6,
                                wraplength=560, fg="#333")
        self.ph_info.pack(fill="x")
        self.ph = ttk.Treeview(right, columns=("rms", "ang", "true", "rat", "sig"), show="tree headings", height=8)
        self.ph.heading("#0", text="Channel", anchor="w")
        self.ph.heading("rms", text="RMS (50 Hz)", anchor="w")
        self.ph.heading("ang", text="Angle", anchor="w")
        self.ph.heading("true", text="True RMS", anchor="w")
        self.ph.heading("rat", text="Rat (SCL)", anchor="w")
        self.ph.heading("sig", text="Signal (SCL)", anchor="w")
        self.ph.column("#0", width=70, anchor="w", stretch=False)
        self.ph.column("rms", width=110, anchor="e", stretch=False)
        self.ph.column("ang", width=75, anchor="e", stretch=False)
        self.ph.column("true", width=110, anchor="e", stretch=False)
        self.ph.column("rat", width=70, anchor="e", stretch=False)
        self.ph.column("sig", width=170, anchor="w")
        self.ph.tag_configure("ref", font=("Segoe UI", 9, "bold"))
        self.ph.pack(fill="x", padx=2)

    def ref_index(self):
        """channel number of the angle reference (None = Auto). 8 channels (9-2LE): Ia..Vn = 0..7;
        other streams: Ch 1 .. Ch n"""
        v = self.app.var_ref.get()
        names = list(self.ph_ref["values"])
        return names.index(v) - 1 if v in names and v != "Auto" else None

    def _ref_list(self, nch):
        L = ["Auto"] + (["Ia", "Ib", "Ic", "In", "Va", "Vb", "Vc", "Vn"] if nch == 8 else ["Ch %d" % (i + 1) for i in range(nch)])
        if list(self.ph_ref["values"]) != L:
            self.ph_ref["values"] = L
            if self.app.var_ref.get() not in L:
                self.app.var_ref.set("Auto")

    def show_phasors(self):
        if self.kind != "SV":
            return
        app = self.app
        sec = app.var_units.get() == "secondary"
        if self.sel_key is None:
            return
        with app.lock:
            r = app.phasors.compute(self.sel_key, app.scl, sec, ref=self.ref_index())
        self.ph.delete(*self.ph.get_children())
        if r is None:
            self.ph_info.configure(text="No samples of this stream.")
            self.ph_mode.configure(text="")
            return
        self._ref_list(len(r["rows"]) or 8)
        lines = []
        if r.get("ref_note"):
            lines.append("Angle reference %s: no signal - Auto is used" % app.var_ref.get())
        if r["cb"]:
            cb = r["cb"]
            lines.append("SCL: %s / %s  (%s)  - matches the stream" % (cb["ied"], cb["cb"], cb["file"]))
        else:
            lines.append("SCL: not matched - only primary values. " + "; ".join(r["problems"]))
        if r["warnings"]:
            lines.append("Warning: " + "; ".join(r["warnings"]))
        f = ("%.3f Hz" % r["freq"]) if r.get("freq") else "-"
        lines.append("Frequency %s   |   nominal %g Hz   |   %d samples / period (%s)   |   %s" % (
            f, r["fnom"], r["spp"], r["spp_how"], "live" if app.running and app.live else "end of the capture"))
        if not r["ok"]:
            lines.append(r["text"])
        self.ph_info.configure(text="\n".join(lines))
        if sec and not r["cb"]:
            self.ph_mode.configure(text="SECONDARY: no values - needs a matching SCD / CID", fg="#b00020")
        else:
            self.ph_mode.configure(text="SECONDARY" if sec else "PRIMARY", fg="#1a4f9c")
        self.ph.heading("rms", text="RMS (%g Hz)" % r["fnom"])
        for x in r["rows"]:
            if x["kind"] == "I":
                lab = ("Ia", "Ib", "Ic", "In")[x["ch"]] if r["rows"] and len(r["rows"]) == 8 and x["ch"] < 4 else "I%d" % (x["ch"] + 1)
            elif x["kind"] == "U":
                lab = ("Va", "Vb", "Vc", "Vn")[x["ch"] - 4] if len(r["rows"]) == 8 and x["ch"] >= 4 else "U%d" % (x["ch"] + 1)
            else:
                lab = "Ch %d" % (x["ch"] + 1)
            ang = "" if x["ang"] is None else "%.1f°" % x["ang"]
            rat = "" if not x.get("rat") else "%g" % x["rat"]
            self.ph.insert("", "end", text=lab, values=(an.fmt(x["rms"], x["unit"]), ang, an.fmt(x["tr"], x["unit"]), rat, x["name"]),
                           tags=("ref",) if x["ch"] == r.get("ref") else ())
            iid = self.data_ch.get(x["ch"])
            if iid and self.data.exists(iid):
                self.data.set(iid, "rms", an.fmt(x["rms"], x["unit"]))

    # ------------------------------------------------------------ model / view
    def show_net(self, on):
        self.net_auto = on
        self.apply_columns()

    def col_title(self, c):
        return ("gocbRef" if self.kind == "GOOSE" else "svID") if c == "desc" else self.HEAD[c][0]

    # ------------------------------------------------------------ PTP: clocks panel
    def _clocks_panel(self, right):
        hf = tk.Frame(right, bg="#e6e9ee")
        hf.pack(fill="x", pady=(6, 0))
        tk.Label(hf, text="Clocks (Announce / Sync senders)", anchor="w", padx=6, pady=2, bg="#e6e9ee").pack(side="left")
        self.ck_best = tk.Label(right, text="", anchor="w", justify="left", padx=6, wraplength=600,
                                font=("Segoe UI", 9, "bold"), fg="#1a4f9c")
        self.ck_best.pack(fill="x")
        cols = ("net", "lan", "dom", "gm", "p1", "cls", "acc", "p2", "steps", "src", "sync", "two", "chk")
        heads = {"net": ("Network", 70), "lan": ("LAN", 35), "dom": ("Dom", 40), "gm": ("Grandmaster (announced)", 190),
                 "p1": ("P1", 40), "cls": ("Class", 45), "acc": ("Accuracy", 65), "p2": ("P2", 40), "steps": ("Steps", 45),
                 "src": ("Time source", 95), "sync": ("Sync every", 75), "two": ("2-step", 50), "chk": ("IEC 61850-9-3", 260)}
        f = ttk.Frame(right)
        f.pack(fill="x", padx=2)
        self.ck = ttk.Treeview(f, columns=cols, show="tree headings", height=5)
        self.ck.heading("#0", text="Clock identity - port", anchor="w")
        self.ck.column("#0", width=200, anchor="w", stretch=False)
        for c in cols:
            self.ck.heading(c, text=heads[c][0], anchor="w")
            self.ck.column(c, width=heads[c][1], anchor="w", stretch=(c == "chk"))
        hs = ttk.Scrollbar(f, orient="horizontal", command=self.ck.xview)
        self.ck.configure(xscrollcommand=hs.set)
        self.ck.pack(fill="x")
        hs.pack(fill="x")
        self.ck.tag_configure("best", font=("Segoe UI", 9, "bold"))
        self.ck.tag_configure("lost", foreground=GREY)
        self.ck.tag_configure("bad", foreground="#b00020")
        self.ck_warn = tk.Label(right, text="", anchor="w", justify="left", padx=6, wraplength=600, fg="#b00020")
        self.ck_warn.pack(fill="x")

    def show_clocks(self):
        if self.kind != "PTP":
            return
        app = self.app
        now = time.time() if (app.running and app.live) else (app.last_ts or time.time())
        with app.lock:
            rows, best, warn = app.ptp_state.summary(now)
        self.ck.delete(*self.ck.get_children())
        best_gm = {b["gm"] for b in best.values()}
        for r in sorted(rows, key=lambda r: (r["c"]["clock"], r["c"]["net"], r["c"]["lan"])):
            c, a = r["c"], r["a"]
            chk = "OK" if not r["check"] else "; ".join(r["check"])
            tags = ("lost",) if not r["alive"] else (("bad",) if r["check"] else ()) + (("best",) if a and a["gm"] in best_gm else ())
            self.ck.insert("", "end", text="%s-%d" % (c["clock"], c["port"]), tags=tags, values=(
                app.net_name(c["net"]), c["lan"] or "-", ",".join(str(d) for d in sorted(c["domains"])),
                a["gm"] if a else "", a["p1"] if a else "", a["cls"] if a else "",
                ptp.ACCURACY.get(a["acc"], "0x%02X" % a["acc"]) if a else "", a["p2"] if a else "", a["steps"] if a else "",
                ptp.TIME_SOURCE.get(a["src"], "0x%02X" % a["src"]) if a else "",
                ("%.3f s" % r["sync_iv"]) if r["sync_iv"] else "", "yes" if c["two_step"] else "no", chk))
        if best:
            self.ck_best.configure(text="   ".join(
                "Grandmaster (BMCA) domain %d: %s  class %s, prio %d/%d, %s, UTC offset %d s" % (
                    d, b["gm"], b["cls"], b["p1"], b["p2"], ptp.TIME_SOURCE.get(b["src"], "0x%02X" % b["src"]), b["utc"])
                for d, b in sorted(best.items())))
        else:
            self.ck_best.configure(text=("No active grandmaster: Announce lost or never received." if rows else "No PTP messages."))
        self.ck_warn.configure(text="\n".join("! " + w for w in warn[:8]) +
                               ("\n... %d more" % (len(warn) - 8) if len(warn) > 8 else ""))

    def apply_columns(self):
        """visible columns: not hidden by the user; Network only with two networks or 'always'"""
        vis = [c for c in self.cols if c not in self.hidden and (c != "net" or self.net_auto or self.net_always)]
        self.tree.configure(displaycolumns=vis or [self.cols[0]])

    def columns_menu(self):
        """menu: one check per column (right click on the header or button Columns...)"""
        mn = tk.Menu(self, tearoff=0)
        self._menu_vars = []                             # keep the variables alive while the menu is open
        for c in self.cols:
            if c == "net":
                v = tk.BooleanVar(value=self.net_always)
                self._menu_vars.append(v)
                mn.add_checkbutton(label="Network - always (else only with 2 networks)", variable=v,
                                   command=lambda v=v: self._set_net(v.get()))
                continue
            v = tk.BooleanVar(value=c not in self.hidden)
            self._menu_vars.append(v)
            mn.add_checkbutton(label=self.col_title(c), variable=v, command=lambda c=c, v=v: self._set_col(c, v.get()))
        mn.add_separator()
        mn.add_command(label="Show all columns", command=self._all_cols)
        return mn

    def _save_cols(self):
        save_settings({"hidden_cols_" + self.kind: sorted(self.hidden), "net_always_" + self.kind: self.net_always})
        self.apply_columns()

    def _set_col(self, c, on):
        if on:
            self.hidden.discard(c)
        elif len([x for x in self.cols if x not in self.hidden and x != "net"]) > 1:
            self.hidden.add(c)
        self._save_cols()

    def _set_net(self, on):
        self.net_always = on
        self._save_cols()

    def _all_cols(self):
        self.hidden.clear()
        self._save_cols()

    def on_right_click(self, e):
        region = self.tree.identify_region(e.x, e.y)
        if region == "heading":
            self.columns_menu().tk_popup(e.x_root, e.y_root)
            return "break"
        iid = self.tree.identify_row(e.y)
        m = self.iid.get(iid) if iid else None
        if m is not None:
            self.app.rule_menu(m, self).tk_popup(e.x_root, e.y_root)
            return "break"

    def show_sig(self, on):
        if self.kind == "PTP":
            self.data.configure(displaycolumns=("value", "type"))
            return
        cols = ("value", "rms", "type") if self.kind == "SV" else ("value", "type")
        self.data.configure(displaycolumns=cols + ("sig",) if on else cols)

    def clear(self):
        self.rows.clear()
        self.iid.clear()
        self.tree.delete(*self.tree.get_children())
        self.head.delete(*self.head.get_children())
        self.data.delete(*self.data.get_children())
        self.title.configure(text="")
        self.sel_key = None
        if self.kind == "SV":
            self.ph.delete(*self.ph.get_children())
            self.ph_info.configure(text="Select a SV message.")
            self.ph_mode.configure(text="")

    def _values_ptp(self, m):
        t0 = self.app.t0 or m["ts"]
        if m["kind"] == "LOST":
            info, ev = "STREAM LOST", "lost"
        else:
            info = m.get("info", "")
            ev = {"first": "first", "change": "change", "back": "back", "all": ""}.get(m.get("reason"), "")
            if m.get("error"):
                info += "   [%s]" % m["error"]
        vlan = "" if m["vlan"] is None else "%d (0x%03X)" % (m["vlan"], m["vlan"])
        prio = "" if m["prio"] is None else m["prio"]
        lmi = m.get("lmi")
        iv = "" if lmi is None or lmi == 127 else ("%g s" % (2.0 ** lmi))
        return (tstr(m["ts"]), "%.6f" % (m["ts"] - t0), self.app.net_name(m["net"]), m.get("lan") or "-", m["src"],
                m["dst"], vlan, prio, m.get("mname", ""), m.get("domain", ""), m.get("ref", ""), m.get("seq", ""),
                iv, info, ev)

    def _values(self, m):
        if self.kind == "PTP":
            return self._values_ptp(m)
        t0 = self.app.t0 or m["ts"]
        if m["kind"] == "LOST":
            desc = "STREAM LOST   %s" % m["ref"]
            ev = "lost"
        else:
            desc = m["ref"] or "(no reference)"
            ev = {"first": "first", "change": "change", "back": "back", "all": ""}.get(m.get("reason"), "")
            if m.get("error"):
                desc += "   [%s]" % m["error"]
        if m.get("sim"):
            desc = "[SIM] " + desc
        vlan = "" if m["vlan"] is None else "%d (0x%03X)" % (m["vlan"], m["vlan"])
        prio = "" if m["prio"] is None else m["prio"]
        v = (tstr(m["ts"]), "%.6f" % (m["ts"] - t0), self.app.net_name(m["net"]), m.get("lan") or "-", m["src"], m["dst"],
             "0x%04X (%d)" % (m["appid"], m["appid"]), vlan, prio, desc, ev)
        if self.kind == "GOOSE":
            v = v[:1] + (self.ied_name(m.get("ref") or ""),) + v[1:]
        return v

    def ied_name(self, ref):
        """IED name of a GOOSE: from the loaded SCL (exact). Without SCL: the part of gocbRef before
        '/' = IED name + LD inst glued together; a known LD name at the end is removed
        (W1G_D60Master -> W1G_D60)."""
        scl = self.app.scl
        if scl:
            n = scl.ied_of(ref)
            if n:
                return n
        if "/" not in ref:
            return ""
        head = ref.split("/")[0]
        lds = sorted(set(self.LD_SUFFIX) | (scl.ld_names if scl else set()), key=len, reverse=True)
        for ld in lds:
            if ld and head.endswith(ld) and len(head) > len(ld):
                return head[:-len(ld)]
        return head

    def _tag(self, m):
        sim = ("sim",) if m.get("sim") else ()
        if m["kind"] == "LOST":
            return ("lost",) + sim
        if m.get("error"):
            return ("err",) + sim
        return (m.get("reason", ""),) + sim

    def _match(self, m, s, filt=True):
        if filt and not self.app.filt.passes(m, self.app.ied_of(m)):
            return False
        if not s:
            return True
        s = s.lower()
        return any(s in str(v).lower() for v in self._values(m))

    def add(self, msgs, view=True):
        self.rows.extend(msgs)
        drop = len(self.rows) - MAX_ROWS
        if drop > 0:                                         # keep the newest MAX_ROWS - 10 %
            del self.rows[:drop + MAX_ROWS // 10]
            if view:
                self.rebuild()
                return
        if not view:
            return
        s = self.search.get().strip()
        last = None
        for m in msgs:
            if not self._shown_by_filter(m) or not self._match(m, s, False):
                continue
            self.n += 1
            iid = "m%d" % self.n
            self.iid[iid] = m
            self.tree.insert("", "end", iid=iid, values=self._values(m), tags=self._tag(m))
            last = iid
        if last and self.app.var_scroll.get():
            self.tree.see(last)
        self._filter_label()

    def _filter_label(self):
        if not self.app.filt.enabled:
            self.flabel.configure(text="")
            return
        self.flabel.configure(text="Filter ON: %d of %d messages hidden" % (self.hidden_n, len(self.rows)))

    def _shown_by_filter(self, m):
        ok = self.app.filt.passes(m, self.app.ied_of(m))
        if not ok:
            self.hidden_n += 1
        return ok

    def rebuild(self):
        self.tree.delete(*self.tree.get_children())
        self.iid.clear()
        s = self.search.get().strip()
        last = None
        self.hidden_n = 0
        for m in self.rows:
            if not self._shown_by_filter(m) or not self._match(m, s, False):
                continue
            self.n += 1
            iid = "m%d" % self.n
            self.iid[iid] = m
            self.tree.insert("", "end", iid=iid, values=self._values(m), tags=self._tag(m))
            last = iid
        if last and self.app.var_scroll.get():
            self.tree.see(last)
        self._filter_label()

    # ------------------------------------------------------------ details
    def on_select(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        m = self.iid.get(sel[0])
        if m is None:
            return
        self.sel_key = m["key"]
        if m["kind"] != "LOST" and m.get("raw") is not None and not m.get("full"):
            full = sc.decode(m["raw"], m["ts"], m["net"], full=True)
            if full:
                for k in ("header", "data", "error"):
                    m[k] = full[k]
            m["full"] = True
        ttl = ("%s   %s" % (m.get("mname", ""), m["ref"])) if self.kind == "PTP" else (m["ref"] or "")
        self.title.configure(text=("STREAM LOST   " if m["kind"] == "LOST" else "") + ttl,
                             fg=GREY if m["kind"] == "LOST" else "black")
        self.head.delete(*self.head.get_children())
        self.head.insert("", "end", values=("Network", "%s  (adapter %d)" % (self.app.net_name(m["net"]), m["net"])))
        for f, v in m["header"]:
            self.head.insert("", "end", values=(f, v))
        if m["kind"] == "SV" and m.get("gmIdentity"):
            with self.app.lock:
                best = self.app.ptp_state.summary(m["ts"])[1]
            gms = {b["gm"] for b in best.values()}
            if not gms:
                txt = "no PTP Announce captured - can not compare"
            elif m["gmIdentity"] in gms:
                txt = "= grandmaster of the PTP tab (OK)"
            else:
                txt = "DIFFERENT from the PTP grandmaster %s" % ", ".join(sorted(gms))
            self.head.insert("", "end", values=("gmIdentity vs PTP", txt), tags=("gmbad",) if "DIFFERENT" in txt else ())
            self.head.tag_configure("gmbad", foreground="#b00020")
        self.data.delete(*self.data.get_children())
        self.data_ch = {}
        names = self.app.scl
        parents = {}
        scal = None
        if m["kind"] == "SV":
            sec = self.app.var_units.get() == "secondary"
            cb = an.Phasors.match(an.stream_info(m), names)[0]
            scal = an.scales(len(m["data"]) // 2, cb, sec)
            self.data.heading("value", text="Instant value, smpCnt %s" % m.get("smpCnt", ""))
        for i, (nm, typ, val, _raw) in enumerate(m["data"]):
            if self.kind == "PTP":
                self.data.insert("", "end", text=nm, values=(val, "", typ, ""))
                continue
            if m["kind"] == "GOOSE":
                sig = names.goose_name(m["ref"], nm) if names else ""
                parent = parents.get(nm.rsplit(".", 1)[0], "") if "." in nm else ""
                label = "%s %s" % (typ, nm.rsplit(".", 1)[-1]) if typ != "Structure" else "Structure %s" % nm.rsplit(".", 1)[-1]
            else:
                ch = i // 2
                sig = names.sv_name(m["ref"], ch) if names else ""
                if nm.endswith(".q"):
                    sig = (sig + ".q") if sig else ""
                elif scal and ch < len(scal) and len(_raw) >= 4:
                    raw = sc.sint(_raw[0:4])
                    kind, fac, unit = scal[ch]
                    val = "%s   (raw %d)" % ("\u2014" if fac is None else ("%.3f %s" % (raw * fac, unit)), raw)
                parent, label = "", nm
            iid = self.data.insert(parent, "end", text=label, values=(val, "", typ, sig), open=True)
            parents[nm] = iid
            if m["kind"] == "SV" and not nm.endswith(".q"):
                self.data_ch[i // 2] = iid
        if self.kind == "SV":
            self.show_phasors()
        if self.kind == "PTP":
            self.show_clocks()


# ---------------------------------------------------------------- networks dialog
class NetDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Configuration - Network adapters")
        self.transient(app)
        self.resizable(True, False)
        self.result = None
        try:
            self.ads = cp.adapters()
        except Exception as ex:
            self.ads = []
            messagebox.showerror(APP, str(ex), parent=self)
        labels = [l for _, l in self.ads]
        st = load_settings()
        pad = dict(padx=10, pady=4)
        self.n1 = tk.StringVar(value=st.get("net1_name") or "Network 1")
        self.n2 = tk.StringVar(value=st.get("net2_name") or "Network 2")
        f1 = ttk.Frame(self)
        f1.pack(fill="x", **pad)
        tk.Label(f1, text="Network 1 - name (column Network):").pack(side="left")
        ttk.Entry(f1, textvariable=self.n1, width=16).pack(side="left", padx=6)
        tk.Label(f1, text="e.g. PB A, LAN A, Station bus", fg="#777").pack(side="left")
        tk.Label(self, text="Network 1 - adapter:", anchor="w").pack(fill="x", **pad)
        self.c1 = ttk.Combobox(self, values=labels, state="readonly", width=95)
        self.c1.pack(fill="x", **pad)
        self.use2 = tk.BooleanVar(value=bool(st.get("net2")))
        ttk.Checkbutton(self, text="Use a second network (Network 2), e.g. PB B / PRP LAN B",
                        variable=self.use2, command=self._toggle).pack(fill="x", **pad)
        f2 = ttk.Frame(self)
        f2.pack(fill="x", **pad)
        tk.Label(f2, text="Network 2 - name (column Network):").pack(side="left")
        self.e2 = ttk.Entry(f2, textvariable=self.n2, width=16)
        self.e2.pack(side="left", padx=6)
        tk.Label(f2, text="e.g. PB B, LAN B, Process bus", fg="#777").pack(side="left")
        self.c2 = ttk.Combobox(self, values=labels, state="readonly", width=95)
        self.c2.pack(fill="x", **pad)
        ids = [i for i, _ in self.ads]
        for cb, key in ((self.c1, "net1"), (self.c2, "net2")):
            if st.get(key) in ids:
                cb.current(ids.index(st[key]))
        if not self.c1.get() and labels:
            self.c1.current(0)
        tk.Label(self, text="Only GOOSE and SV frames are captured. On Windows Npcap must be installed "
                            "(npcap.com, option 'WinPcap API-compatible mode').",
                 fg="#555", anchor="w", wraplength=700, justify="left").pack(fill="x", **pad)
        bf = ttk.Frame(self)
        bf.pack(fill="x", padx=10, pady=10)
        ttk.Button(bf, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(bf, text="OK", command=self.ok).pack(side="right", padx=6)
        self._toggle()
        self.grab_set()

    def _toggle(self):
        self.c2.configure(state="readonly" if self.use2.get() else "disabled")
        self.e2.configure(state="normal" if self.use2.get() else "disabled")

    def ok(self):
        if self.c1.current() < 0:
            messagebox.showinfo(APP, "Choose the adapter of Network 1.", parent=self)
            return
        n1 = self.ads[self.c1.current()][0]
        n2 = self.ads[self.c2.current()][0] if self.use2.get() and self.c2.current() >= 0 else None
        if n2 == n1:
            messagebox.showinfo(APP, "Network 2 must be another adapter.", parent=self)
            return
        nm1 = self.n1.get().strip() or "Network 1"
        nm2 = self.n2.get().strip() or "Network 2"
        if n2 and nm1 == nm2:
            messagebox.showinfo(APP, "Give the two networks different names.", parent=self)
            return
        self.result = (n1, n2, self.ads[self.c1.current()][1],
                       self.ads[self.c2.current()][1] if n2 else "", nm1, nm2)
        save_settings({"net1": n1, "net2": n2, "net1_name": nm1, "net2_name": nm2})
        self.destroy()


# ---------------------------------------------------------------- about
class AboutDialog(tk.Toplevel):
    """short note about the program: English by default, button for Ukrainian, author -> LinkedIn"""

    def __init__(self, app):
        super().__init__(app)
        self.transient(app)
        self.resizable(False, False)
        self.lang = load_settings().get("about_lang", "en")
        if self.lang not in ABOUT:
            self.lang = "en"
        tk.Label(self, text="%s   %s" % (APP, VERSION), font=("Segoe UI", 11, "bold"), padx=16, pady=10).pack(anchor="w")
        self.txt = tk.Label(self, justify="left", anchor="w", wraplength=440, padx=16)
        self.txt.pack(fill="x")
        af = tk.Frame(self, padx=16, pady=10)
        af.pack(fill="x")
        self.alab = tk.Label(af, text="")
        self.alab.pack(side="left")
        self.name = tk.Label(af, text="", fg="#1a4f9c" if AUTHOR_URL else "black",
                             cursor="hand2" if AUTHOR_URL else "", font=("Segoe UI", 9, "underline" if AUTHOR_URL else "normal"))
        self.name.pack(side="left", padx=4)
        if AUTHOR_URL:
            self.name.bind("<Button-1>", lambda e: webbrowser.open(AUTHOR_URL))
        if AUTHOR_MAIL:
            mail = tk.Label(af, text=AUTHOR_MAIL, fg="#1a4f9c", cursor="hand2", font=("Segoe UI", 9, "underline"))
            mail.pack(side="left", padx=8)
            mail.bind("<Button-1>", lambda e: self.send_mail())
        uf = tk.Frame(self, padx=12)
        uf.pack(fill="x")
        self.v_auto = tk.BooleanVar(value=load_settings().get("check_updates", True))
        self.c_auto = ttk.Checkbutton(uf, variable=self.v_auto,
                                      command=lambda: save_settings({"check_updates": self.v_auto.get()}))
        self.c_auto.pack(side="left")
        self.b_upd = ttk.Button(uf, command=self.check_updates)
        self.b_upd.pack(side="right")
        self.upd = tk.Label(self, text="", anchor="w", padx=16, fg="#1a4f9c")
        self.upd.pack(fill="x")
        self.upd_info = None
        if not GITHUB_REPO:
            self.b_upd.configure(state="disabled")
        bf = tk.Frame(self, padx=12, pady=10)
        bf.pack(fill="x")
        self.b_ok = ttk.Button(bf, text="OK", command=self.destroy)
        self.b_ok.pack(side="right")
        self.b_lang = ttk.Button(bf, text="", command=self.switch)
        self.b_lang.pack(side="left")
        self.show()
        self.grab_set()

    def show(self):
        t = ABOUT[self.lang]
        self.title(t["title"])
        self.txt.configure(text=t["text"])
        self.alab.configure(text=t["author"])
        self.name.configure(text=AUTHOR[self.lang])
        self.b_lang.configure(text=t["lang"])
        self.c_auto.configure(text=t["upd_auto"])
        self.b_upd.configure(text=t["upd_btn"])

    def check_updates(self):
        t = ABOUT[self.lang]
        self.config(cursor="watch")
        self.update()
        try:
            state, info = updater.check_now(GITHUB_REPO, VERSION)
        finally:
            self.config(cursor="")
        if state == "newer":
            self.upd.configure(text=t["upd_new"] % info["tag"] + "  >>", cursor="hand2", font=("Segoe UI", 9, "underline"))
            self.upd.bind("<Button-1>", lambda e: webbrowser.open(info["url"]))
        elif state == "current":
            self.upd.configure(text=t["upd_cur"] % info["tag"], cursor="", font=("Segoe UI", 9))
        else:
            self.upd.configure(text=t["upd_err"], cursor="", font=("Segoe UI", 9))

    def send_mail(self):
        """new e-mail in the default mail program (Outlook) with the program name and version in the subject"""
        from urllib.parse import quote
        url = "mailto:%s?subject=%s" % (AUTHOR_MAIL, quote("%s %s - problem report" % (APP, VERSION.replace("v ", "v"))))
        try:
            if hasattr(os, "startfile"):
                os.startfile(url)                       # Windows: default mail program
            else:
                webbrowser.open(url)
        except Exception as ex:
            messagebox.showinfo(APP, "%s\n\n%s" % (AUTHOR_MAIL, ex), parent=self)

    def switch(self):
        self.lang = "uk" if self.lang == "en" else "en"
        save_settings({"about_lang": self.lang})
        self.show()


# ---------------------------------------------------------------- filters window
class FilterDialog(tk.Toplevel):
    """display filter: streams seen (tick = show this stream) + manual rules"""
    SCOLS = ("use", "kind", "ied", "net", "lan", "src", "dst", "appid", "vlan", "ref", "frames", "sim", "state")
    SHEAD = {"use": ("Show", 45), "kind": ("Type", 55), "ied": ("IEDName", 110), "net": ("Network", 85), "lan": ("LAN", 35),
             "src": ("Source", 130), "dst": ("Destination", 130), "appid": ("APPID", 100), "vlan": ("VLAN", 45),
             "ref": ("gocbRef / svID", 260), "frames": ("Frames", 70), "sim": ("SIM", 40), "state": ("State", 55)}
    RCOLS = ("on",) + fl.FIELDS
    RHEAD = {"on": ("On", 35), "kind": ("Type", 55), "net": ("Network", 85), "lan": ("LAN", 35), "src": ("Source", 130),
             "dst": ("Destination", 130), "appid": ("APPID", 90), "vlan": ("VLAN", 60), "ref": ("gocbRef / svID", 220),
             "ied": ("IEDName", 100)}

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Filters")
        self.geometry("1250x720")
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=6)
        self.v_on = tk.BooleanVar(value=app.filt.enabled)
        ttk.Checkbutton(top, text="Filter enabled (off = everything is shown)", variable=self.v_on,
                        command=self.apply).pack(side="left")
        ttk.Label(top, text="     Simulation:").pack(side="left")
        self.v_sim = tk.StringVar(value=app.filt.sim)
        cb = ttk.Combobox(top, textvariable=self.v_sim, values=fl.SIM_MODES, state="readonly", width=18)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.apply())
        ttk.Label(top, text="   Rules per tab (Type); a tab without a rule shows all. At least one rule (OR); "
                            "inside a rule all filled fields (AND).", foreground="#555").pack(side="left", padx=8)
        # ---- streams seen
        lf = ttk.LabelFrame(self, text="Streams seen (click 'Show' = show / hide this stream;  right click = rule from one "
                                       "field: only MAC, only APPID, only svID ...)")
        lf.pack(fill="both", expand=True, padx=8, pady=4)
        bf = ttk.Frame(lf)
        bf.pack(fill="x")
        ttk.Button(bf, text="Refresh", command=self.refresh_streams).pack(side="left", padx=2, pady=2)
        ttk.Button(bf, text="Show all streams", command=lambda: self.tick_all(True)).pack(side="left", padx=2)
        ttk.Button(bf, text="Remove stream rules", command=lambda: self.tick_all(False)).pack(side="left", padx=2)
        self.st = self._tree(lf, self.SCOLS, self.SHEAD, 9)
        self.st.bind("<Button-1>", self.on_stream_click)
        self.st.bind("<Button-3>", self.on_stream_menu)
        self.st.bind("<Button-2>", self.on_stream_menu)
        self.st.tag_configure("sim", background=SIM_BG)
        self.st.tag_configure("lost", foreground=GREY)
        # ---- rules
        rf = ttk.LabelFrame(self, text="Rules (double click = on / off). APPID hex: 4011, 4000-4FFF, 1055,104F;  "
                                       "VLAN: 27, 27-32;  text: * and ? wildcards")
        rf.pack(fill="both", expand=True, padx=8, pady=4)
        self.rt = self._tree(rf, self.RCOLS, self.RHEAD, 6)
        self.rt.bind("<Double-1>", self.on_rule_toggle)
        self.rt.bind("<<TreeviewSelect>>", self.on_rule_select)
        ef = ttk.Frame(rf)
        ef.pack(fill="x", pady=4)
        self.ev = {}
        for i, k in enumerate(fl.FIELDS):
            ttk.Label(ef, text=self.RHEAD[k][0]).grid(row=0, column=i, sticky="w", padx=2)
            if k == "kind":
                w = ttk.Combobox(ef, values=("", "GOOSE", "SV", "PTP"), width=7, state="readonly")
            elif k == "net":
                w = ttk.Combobox(ef, values=("", app.net_name(1), app.net_name(2)), width=9, state="readonly")
            elif k == "lan":
                w = ttk.Combobox(ef, values=("", "A", "B", "-"), width=3, state="readonly")
            else:
                w = ttk.Entry(ef, width={"src": 18, "dst": 18, "appid": 12, "vlan": 8, "ref": 30, "ied": 14}[k])
            w.grid(row=1, column=i, sticky="w", padx=2)
            self.ev[k] = w
        b2 = ttk.Frame(rf)
        b2.pack(fill="x")
        ttk.Button(b2, text="Add rule", command=self.add_rule).pack(side="left", padx=2)
        ttk.Button(b2, text="Update selected", command=self.update_rule).pack(side="left", padx=2)
        ttk.Button(b2, text="Delete selected", command=self.delete_rule).pack(side="left", padx=2)
        ttk.Button(b2, text="Delete all rules", command=self.delete_all).pack(side="left", padx=2)
        ttk.Button(b2, text="Close", command=self.destroy).pack(side="right", padx=2)
        self.load_from_app()

    @staticmethod
    def _tree(parent, cols, head, h):
        f = ttk.Frame(parent)
        f.pack(fill="both", expand=True)
        t = ttk.Treeview(f, columns=cols, show="headings", height=h, selectmode="browse")
        for c in cols:
            t.heading(c, text=head[c][0], anchor="w")
            t.column(c, width=head[c][1], anchor="w", stretch=(c == "ref"))
        vs = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=vs.set)
        t.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        return t

    # ---- state
    def load_from_app(self):
        f = self.app.filt
        self.v_on.set(f.enabled)
        self.v_sim.set(f.sim)
        self.refresh_rules()
        self.refresh_streams()

    def apply(self):
        self.app.filt.enabled = self.v_on.get()
        self.app.filt.sim = self.v_sim.get()
        self.app.filters_changed()

    # ---- streams
    def refresh_streams(self):
        app = self.app
        self.st.delete(*self.st.get_children())
        self.smap = {}
        with app.lock:
            items = [(k, dict(st)) for k, st in app.tracker.streams.items()]
        items.sort(key=lambda x: (x[1]["kind"], x[1]["m"]["ref"], x[1]["m"]["net"], x[1]["m"].get("lan", "")))
        for i, (k, st) in enumerate(items):
            m = st["m"]
            use = "\u2611" if app.filt.find_stream_rule(m) else "\u2610"
            iid = "s%d" % i
            self.smap[iid] = m
            tags = (("sim",) if m.get("sim") else ()) + (("lost",) if st["lost"] else ())
            self.st.insert("", "end", iid=iid, tags=tags, values=(
                use, st["kind"], app.ied_of(m), app.net_name(m["net"]), m.get("lan") or "-", m["src"], m["dst"], "" if m.get("appid") is None else "0x%04X (%d)" % (m["appid"], m["appid"]),
                "" if m["vlan"] is None else m["vlan"], m["ref"], st["n"], "yes" if m.get("sim") else "",
                "lost" if st["lost"] else "active"))

    def on_stream_click(self, e):
        iid = self.st.identify_row(e.y)
        if not iid or self.st.identify_column(e.x) != "#1":
            return
        m = self.smap.get(iid)
        f = self.app.filt
        r = f.find_stream_rule(m)
        if r:
            f.rules.remove(r)
        else:
            f.rules.append(f.stream_rule(m))
            if not f.enabled:
                f.enabled = True                       # ticking a stream = the user wants the filter
        self.app.filters_changed()
        return "break"

    def on_stream_menu(self, e):
        iid = self.st.identify_row(e.y)
        m = self.smap.get(iid) if iid else None
        if m is not None:
            self.app.rule_menu(m, self).tk_popup(e.x_root, e.y_root)
        return "break"

    def tick_all(self, on):
        f = self.app.filt
        if on:
            for m in self.smap.values():
                if not f.find_stream_rule(m):
                    f.rules.append(f.stream_rule(m))
        else:
            f.rules = [r for r in f.rules if not r.auto]
        self.app.filters_changed()

    # ---- rules
    def refresh_rules(self):
        self.rt.delete(*self.rt.get_children())
        for i, r in enumerate(self.app.filt.rules):
            self.rt.insert("", "end", iid="r%d" % i, values=("\u2611" if r.on else "\u2610",) + tuple(
                self.app.net_name(int(r.f[k])) if k == "net" and r.f[k] in ("1", "2") else r.f[k] for k in fl.FIELDS))

    def _sel(self):
        s = self.rt.selection()
        return int(s[0][1:]) if s else None

    def _editor(self):
        d = {k: self.ev[k].get().strip() for k in fl.FIELDS}
        d["net"] = {self.app.net_name(1): "1", self.app.net_name(2): "2"}.get(d["net"], d["net"])
        if not any(d.values()):
            raise ValueError("Fill at least one field.")
        return fl.Rule(d)

    def on_rule_select(self, _e=None):
        i = self._sel()
        if i is None:
            return
        r = self.app.filt.rules[i]
        for k, w in self.ev.items():
            if isinstance(w, ttk.Combobox):
                w.set(self.app.net_name(int(r.f[k])) if k == "net" and r.f[k] in ("1", "2") else r.f[k])
            else:
                w.delete(0, "end")
                w.insert(0, r.f[k])

    def add_rule(self):
        try:
            r = self._editor()
        except ValueError as ex:
            messagebox.showinfo(APP, str(ex), parent=self)
            return
        self.app.filt.rules.append(r)
        self.app.filt.enabled = True
        self.app.filters_changed()

    def update_rule(self):
        i = self._sel()
        if i is None:
            return
        try:
            r = self._editor()
        except ValueError as ex:
            messagebox.showinfo(APP, str(ex), parent=self)
            return
        r.on = self.app.filt.rules[i].on
        self.app.filt.rules[i] = r
        self.app.filters_changed()

    def delete_rule(self):
        i = self._sel()
        if i is not None:
            del self.app.filt.rules[i]
            self.app.filters_changed()

    def delete_all(self):
        if self.app.filt.rules and messagebox.askyesno(APP, "Delete all rules?", parent=self):
            self.app.filt.rules = []
            self.app.filters_changed()

    def on_rule_toggle(self, e):
        iid = self.rt.identify_row(e.y)
        if not iid:
            return
        r = self.app.filt.rules[int(iid[1:])]
        r.on = not r.on
        self.app.filters_changed()


# ---------------------------------------------------------------- main window
class App(tk.Tk):
    def __init__(self, open_file=None):
        super().__init__()
        self.title("%s  %s" % (APP, VERSION))
        self.geometry("1500x860")
        self.minsize(1000, 600)
        self.q = queue.Queue()
        self.lock = threading.RLock()
        self.tracker = sc.Tracker()
        self.phasors = an.Phasors()
        self.ptp_state = ptp.PtpState()
        self.last_ts = None
        self.caps = []
        self.running = False
        self.paused = False
        self.t0 = None
        self.scl = None
        self.live = False
        st = load_settings()
        self.nets = (st.get("net1"), st.get("net2"))
        self.net_names = (st.get("net1_name") or "Network 1", st.get("net2_name") or "Network 2")
        self.net_labels = ("", "")
        self.var_scroll = tk.BooleanVar(value=True)
        self.var_retrans = tk.BooleanVar(value=False)
        self.var_sig = tk.BooleanVar(value=True)
        self.var_units = tk.StringVar(value=st.get("units", "primary"))
        self.var_ref = tk.StringVar(value=st.get("angle_ref", "Auto"))
        self.filt = fl.FilterSet(st.get("filter"))
        self.var_filt = tk.BooleanVar(value=self.filt.enabled)
        self.filt_win = None
        self._toolbar()
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=4, pady=2)
        self.tabs = {"GOOSE": StreamTab(self.nb, self, "GOOSE"), "SV": StreamTab(self.nb, self, "SV"),
                     "PTP": StreamTab(self.nb, self, "PTP")}
        self.nb.add(self.tabs["GOOSE"], text="  GOOSE  ")
        self.nb.add(self.tabs["SV"], text="  Sampled Values  ")
        self.nb.add(self.tabs["PTP"], text="  PTP  ")
        self.status = tk.StringVar()
        tk.Label(self, textvariable=self.status, anchor="w", bg="#2b2f36", fg="white", padx=8).pack(fill="x", side="bottom")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100, self.poll)
        self.after(500, self.check_lost)
        self.after(500, self.tick_phasors)
        self.update_net_col()
        self._status()
        if open_file:
            self.after(200, lambda: self.open_file(open_file))
        if GITHUB_REPO and st.get("check_updates", True):
            self.after(1500, lambda: updater.check(GITHUB_REPO, VERSION, lambda info: self.after(0, self.show_update, info)))

    def show_update(self, info):
        """yellow bar under the toolbar: new version on GitHub"""
        lang = load_settings().get("about_lang", "en")
        t = ABOUT.get(lang, ABOUT["en"])
        bar = tk.Frame(self, bg="#fff3c4", padx=8, pady=3)
        bar.pack(fill="x", before=self.nb)
        tk.Label(bar, text=t["banner"] % (info["tag"], VERSION.replace("v ", "v")), bg="#fff3c4",
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        if info.get("exe"):
            ttk.Button(bar, text=t["download"], command=lambda: webbrowser.open(info["exe"])).pack(side="left", padx=6)
        ttk.Button(bar, text=t["page"], command=lambda: webbrowser.open(info["url"])).pack(side="left", padx=2)
        ttk.Button(bar, text=t["hide"], command=bar.destroy).pack(side="right")

    # ------------------------------------------------------------ toolbar
    def _toolbar(self):
        bar = tk.Frame(self, bg="#f3f3f3", pady=4)
        bar.pack(fill="x")

        def grp(title):
            f = tk.Frame(bar, bg="#f3f3f3", padx=6)
            f.pack(side="left", fill="y")
            inner = tk.Frame(f, bg="#f3f3f3")
            inner.pack(side="top")
            tk.Label(f, text=title, bg="#f3f3f3", fg="#777").pack(side="bottom")
            ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=2)
            return inner
        g = grp("Capture")
        self.b_start = ttk.Button(g, text="▶ Start", command=self.start)
        self.b_pause = ttk.Button(g, text="❚❚ Pause", command=self.pause)
        self.b_stop = ttk.Button(g, text="■ Stop", command=self.stop)
        for b in (self.b_start, self.b_pause, self.b_stop):
            b.pack(side="left", padx=2)
        ttk.Button(g, text="Clear", command=self.clear).pack(side="left", padx=2)
        ttk.Checkbutton(g, text="Auto scroll", variable=self.var_scroll).pack(side="left", padx=4)
        g = grp("Filter")
        ttk.Checkbutton(g, text="Retransmission", variable=self.var_retrans,
                        command=self.on_retrans).pack(side="left", padx=4)
        ttk.Checkbutton(g, text="Filter", variable=self.var_filt, command=self.on_filter_toggle).pack(side="left", padx=(8, 2))
        ttk.Button(g, text="Filters...", command=self.open_filters).pack(side="left", padx=2)
        g = grp("Analog (SV)")
        for v, t in (("primary", "Primary"), ("secondary", "Secondary")):
            ttk.Radiobutton(g, text=t, value=v, variable=self.var_units, command=self.on_units).pack(side="left", padx=3)
        g = grp("Networks")
        ttk.Button(g, text="Adapters...", command=self.choose_nets).pack(side="left", padx=2)
        g = grp("Files")
        ttk.Button(g, text="Load SCD / CID...", command=self.load_scl).pack(side="left", padx=2)
        ttk.Button(g, text="Open .pcap...", command=self.open_file).pack(side="left", padx=2)
        g = grp("View")
        self.b_cols = ttk.Button(g, text="Columns...", command=self.cols_button)
        self.b_cols.pack(side="left", padx=2)
        ttk.Checkbutton(g, text="Signal (SCL)", variable=self.var_sig,
                        command=lambda: [t.show_sig(self.var_sig.get()) for t in self.tabs.values()]).pack(side="left", padx=4)
        ttk.Button(bar, text="?", width=3, command=self.about).pack(side="right", padx=8)

    # ------------------------------------------------------------ actions
    def about(self):
        AboutDialog(self)

    def ied_of(self, m):
        """IED name of a message for the filter: GOOSE from gocbRef / SCL, SV from the SCL control block"""
        kind = m["stream"] if m["kind"] == "LOST" else m["kind"]
        if kind == "GOOSE":
            return self.tabs["GOOSE"].ied_name(m.get("ref") or "").strip("()")
        if kind == "PTP":
            return ""
        if self.scl:
            inf = dict(svid=m.get("ref"), dst=m["dst"], appid=m["appid"], vlan=m["vlan"],
                       confRev=m.get("confRev"), nch=m.get("nch"), smpRate=m.get("smpRate"))
            cb = an.Phasors.best(inf, self.scl)[0]
            if cb:
                return cb["ied"]
        return ""

    def net_name(self, n):
        """name of the network / adapter n (1, 2) given in Adapters..."""
        try:
            return self.net_names[int(n) - 1]
        except (ValueError, IndexError, TypeError):
            return str(n)

    def on_ref(self):
        save_settings({"angle_ref": self.var_ref.get()})
        self.tabs["SV"].show_phasors()

    def cur_tab(self):
        return [self.tabs["GOOSE"], self.tabs["SV"], self.tabs["PTP"]][self.nb.index("current")]

    def cols_button(self):
        b = self.b_cols
        self.cur_tab().columns_menu().tk_popup(b.winfo_rootx(), b.winfo_rooty() + b.winfo_height())

    def rule_menu(self, m, parent):
        """right click on a message / stream: add a filter rule from one field"""
        kind = m["stream"] if m["kind"] == "LOST" else m["kind"]
        ied = self.ied_of(m)
        mn = tk.Menu(parent, tearoff=0)
        items = [("Source MAC = %s" % m["src"], dict(src=m["src"])),
                 ("Destination MAC = %s" % m["dst"], dict(dst=m["dst"]))]
        if m.get("appid") is not None:
            items.append(("APPID = 0x%04X (%d)" % (m["appid"], m["appid"]), dict(appid="%04X" % m["appid"])))
        if m.get("vlan") is not None:
            items.append(("VLAN ID = %d" % m["vlan"], dict(vlan=str(m["vlan"]))))
        if m.get("ref"):
            items.append(("%s = %s" % ({"GOOSE": "gocbRef", "SV": "svID"}.get(kind, "Clock identity - port"), m["ref"]),
                          dict(ref=m["ref"])))
        if ied:
            items.append(("IEDName = %s" % ied, dict(ied=ied)))
        items.append(("Type = %s" % kind, dict(kind=kind)))
        mn.add_command(label="Add filter rule - show only:", state="disabled")
        for lab, d in items:
            if "kind" not in d:
                d = dict(d, kind=kind)                   # rule only for this tab (type)
            mn.add_command(label="    " + lab, command=lambda d=d: self.add_rule(d))
        mn.add_separator()
        mn.add_command(label="    this stream (exact)", command=lambda: self.add_rule(self.filt.stream_rule(m).to_dict()))
        mn.add_separator()
        mn.add_command(label="Filters...", command=self.open_filters)
        return mn

    def add_rule(self, d):
        r = fl.Rule(d)
        if any(x.f == r.f for x in self.filt.rules):
            for x in self.filt.rules:
                if x.f == r.f:
                    x.on = True
        else:
            self.filt.rules.append(r)
        self.filt.enabled = True
        self.filters_changed()

    def update_net_col(self):
        """column Net only when two networks are used (live capture with Network 2)"""
        on = bool(self.live and self.nets[1])
        for t in self.tabs.values():
            t.show_net(on)

    def on_units(self):
        save_settings({"units": self.var_units.get()})
        self.tabs["SV"].on_select()                # Data (instant values) + Phasors

    def tick_phasors(self):
        try:
            if self.running and self.live and not self.paused:
                i = self.nb.index("current")
                if i == 1:
                    self.tabs["SV"].show_phasors()
                elif i == 2:
                    self.ptp_tick = (getattr(self, "ptp_tick", 0) + 1) % 2
                    if self.ptp_tick == 0:                 # clocks every 1 s
                        self.tabs["PTP"].show_clocks()
        finally:
            self.after(500, self.tick_phasors)

    def on_filter_toggle(self):
        self.filt.enabled = self.var_filt.get()
        self.filters_changed()

    def filters_changed(self):
        self.var_filt.set(self.filt.enabled)
        save_settings({"filter": self.filt.to_dict()})
        for t in self.tabs.values():
            t.rebuild()
        if self.filt_win is not None and self.filt_win.winfo_exists():
            self.filt_win.load_from_app()
        self._status()

    def open_filters(self):
        if self.filt_win is not None and self.filt_win.winfo_exists():
            self.filt_win.lift()
            self.filt_win.refresh_streams()
            return
        self.filt_win = FilterDialog(self)

    def on_retrans(self):
        with self.lock:
            self.tracker.retrans = {k: self.var_retrans.get() for k in ("GOOSE", "SV", "PTP")}

    def choose_nets(self):
        if self.running:
            messagebox.showinfo(APP, "Stop the capture first.")
            return
        d = NetDialog(self)
        self.wait_window(d)
        if d.result:
            self.nets = d.result[:2]
            self.net_labels = d.result[2:4]
            self.net_names = d.result[4:6]
            for t in self.tabs.values():
                t.rebuild()
            self._status()

    def load_scl(self):
        files = filedialog.askopenfilenames(title="SCL files (SCD / CID / ICD / IID)",
                                            filetypes=[("SCL", "*.scd *.cid *.icd *.iid *.SCD *.CID *.ICD *.IID"), ("All", "*.*")])
        if not files:
            return
        self.config(cursor="watch")
        self.update()
        try:
            names = self.scl or sn.SclNames()
            names.load(files)
            self.scl = names
        finally:
            self.config(cursor="")
        msg = names.summary()
        if names.errors:
            msg += "\n\nNot read:\n" + "\n".join(names.errors)
        messagebox.showinfo(APP, msg)
        self.tabs["GOOSE"].rebuild()          # IEDName column from the new SCL
        if self.filt.enabled:
            self.tabs["SV"].rebuild()
        for t in self.tabs.values():
            t.on_select()
        self._status()

    def start(self):
        if self.running:
            if self.paused:
                self.pause()
            return
        if not self.nets[0]:
            self.choose_nets()
            if not self.nets[0]:
                return
        self.on_retrans()
        self.live = True
        self.caps = []
        for i, iface in enumerate(self.nets, 1):
            if iface:
                c = cp.Capture(i, iface, self.on_frame, self.on_cap_error)
                c.start()
                self.caps.append(c)
        self.running = True
        self.paused = False
        self.update_net_col()
        self._status()

    def pause(self):
        if not self.running:
            return
        self.paused = not self.paused
        if not self.paused:
            for t in self.tabs.values():
                t.rebuild()
        self._status()

    def stop(self):
        for c in self.caps:
            c.stop()
        self.caps = []
        self.running = False
        self.paused = False
        self._status()

    def clear(self):
        with self.lock:
            self.tracker.reset()
            self.phasors.reset()
            self.ptp_state.reset()
            self.last_ts = None
            self.on_retrans()
        while not self.q.empty():
            try:
                self.q.get_nowait()
            except queue.Empty:
                break
        self.t0 = None
        for t in self.tabs.values():
            t.clear()
        self._status()

    def on_close(self):
        self.stop()
        self.destroy()

    # ------------------------------------------------------------ capture -> queue
    def on_frame(self, net, frame, ts):
        """capture thread: decode (fast), filter, queue what must be shown"""
        m = sc.decode(frame, ts, net, full=False)
        if m is None:
            return
        with self.lock:
            out = self.tracker.feed(m)
            if m["kind"] == "SV":
                self.phasors.feed(m)
            elif m["kind"] == "PTP":
                self.ptp_state.feed(m)
        for x in out:
            x["raw"] = frame
            self.q.put(x)

    def on_cap_error(self, net, text):
        self.q.put({"kind": "ERROR", "net": net, "text": text})

    def check_lost(self):
        if self.running and self.live:
            with self.lock:
                out = self.tracker.check(time.time())
            for x in out:
                self.q.put(x)
        self.after(250, self.check_lost)

    def poll(self):
        """GUI thread: queue -> tabs"""
        batch = {"GOOSE": [], "SV": [], "PTP": []}
        n = 0
        try:
            while n < DRAIN_PER_TICK:
                m = self.q.get_nowait()
                n += 1
                if m["kind"] == "ERROR":
                    self.stop()
                    messagebox.showerror(APP, "Network %s:\n%s" % (self.net_name(m["net"]), m["text"]))
                    continue
                if self.t0 is None:
                    self.t0 = m["ts"]
                kind = m["stream"] if m["kind"] == "LOST" else m["kind"]
                batch[kind].append(m)
        except queue.Empty:
            pass
        for k, L in batch.items():
            if L:
                self.tabs[k].add(L, view=not self.paused)
        if n:
            self._status()
        self.after(100, self.poll)

    def _status(self):
        tr = self.tracker
        state = "Capturing" if self.running and not self.paused else ("Paused" if self.paused else "Stopped")
        n1 = self.net_labels[0] or (self.nets[0] or "-")
        n2 = self.net_labels[1] or (self.nets[1] or "-")
        scl = self.scl.summary() if self.scl else "no SCL"
        self.status.set("%s   |   %s: %s   |   %s: %s   |   GOOSE %d / %d   SV %d / %d   PTP %d / %d  shown / captured   |   %s   |   %s"
                        % (state, self.net_name(1), n1[:30], self.net_name(2), n2[:30], tr.shown["GOOSE"], tr.captured["GOOSE"],
                           tr.shown["SV"], tr.captured["SV"], tr.shown["PTP"], tr.captured["PTP"], self.filt.summary(), scl))

    # ------------------------------------------------------------ file
    def open_file(self, path=None):
        if self.running:
            messagebox.showinfo(APP, "Stop the capture first.")
            return
        path = path or filedialog.askopenfilename(title="Capture file",
                                                  filetypes=[("Capture", "*.pcap *.pcapng *.cap"), ("All", "*.*")])
        if not path:
            return
        self.clear()
        self.on_retrans()
        self.live = False
        self.config(cursor="watch")
        self.update()
        msgs = {"GOOSE": [], "SV": [], "PTP": []}
        last = None
        try:
            for frame, ts in cp.read_file(path):
                with self.lock:
                    lost = self.tracker.check(ts)
                    m = sc.decode(frame, ts, 1, full=False)
                    out = self.tracker.feed(m) if m else []
                    if m and m["kind"] == "SV":
                        self.phasors.feed(m)
                    elif m and m["kind"] == "PTP":
                        self.ptp_state.feed(m)
                for x in lost:
                    msgs[x["stream"]].append(x)
                for x in out:
                    x["raw"] = frame
                    msgs[x["kind"]].append(x)
                if self.t0 is None and (lost or out):
                    self.t0 = ts
                last = ts
                self.last_ts = ts
        except Exception as ex:
            messagebox.showerror(APP, "%s\n\n%s" % (path, ex))
        finally:
            self.config(cursor="")
        for k in msgs:
            msgs[k].sort(key=lambda m: m["ts"])
            self.tabs[k].add(msgs[k])
        self._status()
        self.title("%s  %s  -  %s" % (APP, VERSION, os.path.basename(path)))
        self.update_net_col()


def main():
    ap = argparse.ArgumentParser(description=APP)
    ap.add_argument("--file", help="capture file to open at start (.pcap / .pcapng)")
    a = ap.parse_args()
    try:
        App(a.file).mainloop()
    except Exception:
        traceback.print_exc()
        try:
            messagebox.showerror(APP, traceback.format_exc())
        except Exception:
            pass


if __name__ == "__main__":
    main()
