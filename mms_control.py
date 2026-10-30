# -*- coding: utf-8 -*-
"""
mms_control.py - IEC 61850 control (commands) of the tab MMS / Active (v0.6.2), no GUI.

  info(client, om, dom, ln, do)   ctlModel, sboTimeout, stVal / q, Loc / LocSta, Mod / Beh of the LN, type of
                                  Oper (ctlVal), SBOw / Cancel present
  Control(client, om, ...)         select() / operate() / cancel() for every control model:
      status-only                  no command
      direct-with-normal-security  Write Oper
      sbo-with-normal-security     Read SBO (select), Write Oper
      direct-with-enhanced-sec.    Write Oper, wait CommandTermination
      sbo-with-enhanced-security   Write SBOw (select), Write Oper, wait CommandTermination
  Failed commands: LastApplError (AddCause) sent by the IED before the negative response / termination.
  log_command(...)                 every command -> CSV file (IEC61850ANALYZER_commands.csv in the home folder)

Settings (SP / SG / SE) are never written.
"""
import csv
import os
import queue
import socket
import struct
import time

import goose_pub as gp
import mms
import mms_active as ma
import mms_client as mc

CTL_MODELS = {0: "status-only", 1: "direct-with-normal-security", 2: "sbo-with-normal-security",
              3: "direct-with-enhanced-security", 4: "sbo-with-enhanced-security"}
OR_CAT = ["not-supported", "bay-control", "station-control", "remote-control", "automatic-bay",
          "automatic-station", "automatic-remote", "maintenance", "process"]
TCMD = {"stop": 0, "lower": 1, "higher": 2, "reserved": 3}
LOG_FILE = os.path.join(os.path.expanduser("~"), "IEC61850ANALYZER_commands.csv")
tlv = mc.tlv


def pc_name():
    try:
        return socket.gethostname()
    except OSError:
        return "IEC61850ANALYZER"


def _sint(v):
    n = 1
    while True:
        try:
            return int(v).to_bytes(n, "big", signed=True)
        except OverflowError:
            n += 1


def _leaf_text(rows):
    for p, t, v, r in rows:
        if t not in ("Structure", "Array"):
            return v, t
    return "", ""


# ---------------------------------------------------------------- object information
def info(client, om, dom, ln, do):
    """-> dict with what must be known before a command"""
    base = "%s$%%s$%s" % (ln, do)
    I = dict(dom=dom, ln=ln, do=do, ref="%s/%s.%s" % (dom, ln, do), ctl_model=None, ctl_model_text="?",
             sbo_timeout="", st_val="", st_type="", q="", loc="", mod="", beh="", oper_type=None,
             has_sbo=False, has_sbow=False, has_cancel=False, errors=[])
    co = ma.item_type(client, om, dom, base % "CO")
    if co and co.get("kind") == "struct":
        names = [n for n, t in co["comps"]]
        I["has_sbo"] = "SBO" in names
        I["has_sbow"] = "SBOw" in names
        I["has_cancel"] = "Cancel" in names
        I["oper_type"] = dict(co["comps"]).get("Oper")
        I["sbow_type"] = dict(co["comps"]).get("SBOw")
        I["cancel_type"] = dict(co["comps"]).get("Cancel")
    items = [base % "CF" + "$ctlModel", base % "CF" + "$sboTimeout", base % "ST" + "$stVal", base % "ST" + "$q",
             "%s$ST$Mod$stVal" % ln, "%s$ST$Beh$stVal" % ln, "%s$ST$Loc$stVal" % ln, "LLN0$ST$Loc$stVal",
             "LLN0$ST$Mod$stVal"]
    res = ma.read_many(client, om, dom, items)
    val = {it: (None if rows and rows[0][1] == "error" else _leaf_text(rows)) for it, rows in res.items()}
    cm = val.get(items[0])
    if cm:
        try:
            I["ctl_model"] = int(cm[0])
            I["ctl_model_text"] = CTL_MODELS.get(I["ctl_model"], cm[0])
        except ValueError:
            I["ctl_model_text"] = cm[0]
    else:
        I["errors"].append("ctlModel not readable")
    if val.get(items[1]):
        I["sbo_timeout"] = val[items[1]][0]
    if val.get(items[2]):
        I["st_val"], I["st_type"] = val[items[2]]
    if val.get(items[3]):
        q = val[items[3]][0]
        I["q"] = q[q.index("(") + 1:q.rindex(")")] if "(" in q else q
    I["mod"] = _enum_text(val.get(items[4]) or val.get(items[8]))
    I["beh"] = _enum_text(val.get(items[5]))
    loc = val.get(items[6]) or val.get(items[7])
    I["loc"] = ("local" if loc[0] == "TRUE" else "remote") if loc else ""
    return I


BEH = {1: "on", 2: "on-blocked", 3: "test", 4: "test/blocked", 5: "off"}


def _enum_text(v):
    if not v:
        return ""
    try:
        if int(v[0]) not in BEH:
            return ""
        return "%s (%s)" % (BEH[int(v[0])], v[0])
    except ValueError:
        return v[0]


def warnings(I):
    w = []
    if I["ctl_model"] == 0:
        w.append("ctlModel status-only: the object cannot be controlled")
    if I["loc"] == "local":
        w.append("Loc = TRUE (local): remote commands are refused (Blocked-by-switching-hierarchy)")
    for k in ("mod", "beh"):
        if I[k] and not I[k].startswith(("on ", "? ")):
            w.append("%s %s: commands may be blocked or only accepted with Test" % (k.capitalize(), I[k]))
    if I["oper_type"] is None:
        w.append("no Oper in the data model (CO) - not a controllable object")
    return w


# ---------------------------------------------------------------- encoding
def ctl_kind(typ):
    """type of ctlVal -> 'bool' / 'int' / 'uint' / 'float' / 'tcmd' / 'analog' / 'other'"""
    if not typ:
        return "other"
    k = typ.get("kind")
    if k == "BOOLEAN":
        return "bool"
    if k == "INTEGER":
        return "int"
    if k == "UNSIGNED":
        return "uint"
    if k == "FLOAT":
        return "float"
    if k == "BIT STRING":
        return "tcmd"
    if k == "struct" and typ["comps"] and typ["comps"][0][0] in ("f", "i"):
        return "analog"
    return "other"


def ctl_val_type(I):
    t = I.get("oper_type")
    if t and t.get("kind") == "struct":
        return dict(t["comps"]).get("ctlVal")
    return None


def enc_ctl_val(typ, value):
    k = ctl_kind(typ)
    if k == "bool":
        return b"\x83\x01" + (b"\xff" if value else b"\x00")
    if k in ("int", "uint"):
        return tlv(0x85 if k == "int" else 0x86, _sint(int(value)))
    if k == "float":
        return tlv(0x87, b"\x08" + struct.pack(">f", float(value)))
    if k == "tcmd":
        return tlv(0x84, b"\x06" + bytes([(TCMD.get(value, int(value) if str(value).isdigit() else 0) & 3) << 6]))
    if k == "analog":
        name, sub = typ["comps"][0]
        inner = tlv(0x87, b"\x08" + struct.pack(">f", float(value))) if name == "f" else tlv(0x85, _sint(int(value)))
        return tlv(0xA2, inner)
    raise ValueError("ctlVal type not supported: %s" % (typ.get("kind") if typ else "?"))


def enc_struct(typ, value, or_cat, or_ident, ctl_num, test, sync, interlock, now=None):
    """Oper / SBOw / Cancel structure following the component names of its type"""
    now = now or time.time()
    out = b""
    for name, t in typ["comps"]:
        if name == "ctlVal":
            out += enc_ctl_val(t, value)
        elif name == "operTm":
            out += tlv(0x91, gp.utc_bytes(now))
        elif name == "origin":
            parts = b""
            for n2, t2 in (t or {}).get("comps", []):
                if n2 == "orCat":
                    parts += tlv(0x85, _sint(or_cat))
                elif n2 == "orIdent":
                    parts += tlv(0x89, or_ident.encode("utf-8")[:64])
            out += tlv(0xA2, parts)
        elif name == "ctlNum":
            out += tlv(0x86, _sint(ctl_num & 0xFF))
        elif name == "T":
            out += tlv(0x91, gp.utc_bytes(now))
        elif name == "Test":
            out += b"\x83\x01" + (b"\xff" if test else b"\x00")
        elif name == "Check":
            out += tlv(0x84, b"\x06" + bytes([(0x80 if sync else 0) | (0x40 if interlock else 0)]))
        else:
            raise ValueError("unknown component %s in %s" % (name, "control structure"))
    return tlv(0xA2, out)


# ---------------------------------------------------------------- command sequences
class Control:
    """one controllable object; the unconfirmed PDUs of the association must be given to feed()"""

    def __init__(self, client, om, I, ctl_num=0):
        self.client, self.om, self.I = client, om, I
        self.events = queue.Queue()
        self.ctl_num = ctl_num
        self.selected = False

    def feed(self, pdu):
        """unconfirmed PDU (reader thread) -> LastApplError / CommandTermination of this object"""
        try:
            r = mms.parse_pdu(pdu)
        except Exception:                               # noqa: BLE001
            return
        t = r.get("mtype", "")
        if not (t.startswith("CommandTermination") or t.startswith("LastApplError")):
            return
        obj = "%s/%s" % (self.I["dom"], self.I["ln"])
        text = " ".join(str(x[3]) for x in r["tree"].rows) + " " + r.get("info", "")
        if self.I["do"] not in text and obj not in text and "." + self.I["do"] not in r.get("info", ""):
            return
        self.events.put(dict(kind="term" if t.startswith("CommandTermination") else "lae",
                             positive="positive" in t, cause=(r.get("reason") or "").replace("AddCause: ", ""),
                             text=t, info=r.get("info", ""), t=time.time()))

    def _clear(self):
        while True:
            try:
                self.events.get_nowait()
            except queue.Empty:
                return

    def _lae(self, wait=0.3):
        """LastApplError received for the last request?"""
        end = time.time() + wait
        while True:
            try:
                ev = self.events.get(timeout=max(0.0, end - time.time()))
                if ev["kind"] == "lae":
                    return ev
            except queue.Empty:
                return None

    def _item(self, attr):
        return "%s$CO$%s$%s" % (self.I["ln"], self.I["do"], attr)

    def select(self, value, or_cat, or_ident, test, sync, interlock):
        """-> (ok, text)"""
        m = self.I["ctl_model"]
        self._clear()
        if m == 2:
            res = self.client.read(self.I["dom"], [self._item("SBO")])
            ok, b, t, e = res[0]
            if not ok:
                return False, "Select (read SBO) failed: %s" % b
            rows = []
            mc.typed_rows(b, t, e, None, "SBO", rows)
            name = rows[0][2] if rows else ""
            self.selected = bool(name)
            return self.selected, ("Selected (SBO = %s)" % name) if name else "Select refused (SBO empty)"
        if m == 4:
            self.ctl_num = (self.ctl_num + 1) & 0xFF
            typ = self.I.get("sbow_type") or self.I["oper_type"]
            data = enc_struct(typ, value, or_cat, or_ident, self.ctl_num, test, sync, interlock)
            err = self.client.write(self.I["dom"], self._item("SBOw"), data)
            if err is None:
                self.selected = True
                return True, "Selected (SBOw, ctlNum %d)" % self.ctl_num
            lae = self._lae()
            return False, "SelectWithValue refused: %s%s" % (err, (" - AddCause: %s" % lae["cause"]) if lae else "")
        return False, "Select is not used with %s" % CTL_MODELS.get(m, m)

    def operate(self, value, or_cat, or_ident, test, sync, interlock, timeout=10.0):
        """-> (ok, text); waits for CommandTermination with enhanced security"""
        m = self.I["ctl_model"]
        if m == 0:
            return False, "status-only: no command"
        if m != 4:
            self.ctl_num = (self.ctl_num + 1) & 0xFF
        self._clear() if m != 4 else None
        data = enc_struct(self.I["oper_type"], value, or_cat, or_ident, self.ctl_num, test, sync, interlock)
        t0 = time.time()
        err = self.client.write(self.I["dom"], self._item("Oper"), data)
        self.selected = False
        if err is not None:
            lae = self._lae()
            return False, "Operate refused: %s%s" % (err, (" - AddCause: %s" % lae["cause"]) if lae else "")
        if m in (1, 2):
            return True, "Operate accepted (%d ms)" % ((time.time() - t0) * 1000)
        end = t0 + timeout                               # enhanced security: CommandTermination
        while True:
            try:
                ev = self.events.get(timeout=max(0.0, end - time.time()))
            except queue.Empty:
                return False, "Operate accepted, but no CommandTermination within %g s" % timeout
            if ev["kind"] == "term":
                ms = (ev["t"] - t0) * 1000
                if ev["positive"]:
                    return True, "CommandTermination positive after %d ms" % ms
                return False, "CommandTermination NEGATIVE after %d ms - AddCause: %s" % (ms, ev["cause"] or "?")
            if ev["kind"] == "lae":
                continue                                  # negative termination follows

    def cancel(self, value, or_cat, or_ident, test):
        typ = self.I.get("cancel_type")
        if not typ:
            return False, "no Cancel in the data model"
        self._clear()
        data = enc_struct(typ, value, or_cat, or_ident, self.ctl_num, test, False, False)
        err = self.client.write(self.I["dom"], self._item("Cancel"), data)
        self.selected = False
        if err is None:
            return True, "Cancel accepted"
        lae = self._lae()
        return False, "Cancel refused: %s%s" % (err, (" - AddCause: %s" % lae["cause"]) if lae else "")


# ---------------------------------------------------------------- log file
def log_command(peer, ident, I, action, value, or_cat, or_ident, ctl_num, test, sync, interlock, ok, text,
                path=None):
    path = path or LOG_FILE
    new = not os.path.exists(path)
    try:
        with open(path, "a", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            if new:
                w.writerow(["Date time", "IED IP", "IED", "Object", "ctlModel", "Action", "ctlVal", "orCat",
                            "orIdent", "ctlNum", "Test", "Synchrocheck", "Interlock-check", "Result", "Details"])
            w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), peer, ident, I["ref"], I["ctl_model_text"], action,
                        value, OR_CAT[or_cat] if 0 <= or_cat < len(OR_CAT) else or_cat, or_ident, ctl_num,
                        test, sync, interlock, "OK" if ok else "FAILED", text])
        return path
    except OSError:
        return None
