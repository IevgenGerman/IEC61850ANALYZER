# -*- coding: utf-8 -*-
"""
goose_pub.py - GOOSE publisher (simulation of an IED from its CID / SCD).

From the SCL:
  GSEControl (name, datSet, appID = goID, confRev) of LN0, its DataSet with the type of every
  FCDA (DataTypeTemplates: DOType / DA / DAType / BDA -> BOOLEAN, Dbpos, Quality, Timestamp,
  INT*, FLOAT*, Enum, strings, structures for FCD entries) and the address of the control block
  in Communication / ConnectedAP / GSE (MAC, APPID, VLAN ID, priority, MinTime, MaxTime).
  One GSE address = one publisher entry (an IED with two access points has two entries).

Sending (IEC 61850-8-1):
  every MaxTime the same message (heartbeat, sqNum + 1); a change of a value -> stNum + 1,
  sqNum 0, sent at once, then after MinTime, 2 x, 4 x ... MinTime up to MaxTime.
  TAL = 2 x the time to the next message. t = time of the last change.
  Simulation (Ed2): goosePdu field simulation = TRUE and bit S of Reserved1 - ON by default.
  Frames are sent with Scapy (Npcap on Windows) from the MAC of the chosen adapter.
"""
import os
import struct
import threading
import time
import xml.etree.ElementTree as ET

DEF_MIN_MS = 4
DEF_MAX_MS = 1000


# ---------------------------------------------------------------- BER / MMS encoding
def tlv(tag, val):
    n = len(val)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b"\x81" + bytes([n])
    else:
        ln = b"\x82" + n.to_bytes(2, "big")
    return bytes([tag]) + ln + val


def ber_int(v, signed=True):
    v = int(v)
    if not signed and v < 0:
        v = 0
    n = 1
    while True:
        try:
            b = v.to_bytes(n, "big", signed=True)
            return b
        except OverflowError:
            n += 1


def utc_bytes(t, q=0x0A):
    sec = int(t)
    frac = int((t - sec) * (1 << 24)) & 0xFFFFFF
    return sec.to_bytes(4, "big") + frac.to_bytes(3, "big") + bytes([q])


QUAL_VALIDITY = {"good": 0, "invalid": 1, "reserved": 2, "questionable": 3}
DBPOS = {"intermediate": 0, "off": 1, "on": 2, "bad": 3}


# detail bits of the quality (IEC 61850-8-1, bit number from the MSB of the 13 bit string)
QUAL_FLAGS = [(2, "overflow"), (3, "outOfRange"), (4, "badReference"), (5, "oscillatory"), (6, "failure"),
              (7, "oldData"), (8, "inconsistent"), (9, "inaccurate"), (10, "substituted"), (11, "test"),
              (12, "operatorBlocked")]


def quality_bits(validity="good", test=False, extra=0, flags=()):
    """13 bit quality -> int (MSB first: validity 2 bits, overflow ... test = bit 11, operatorBlocked)"""
    v = QUAL_VALIDITY.get(validity, 0) << 11
    names = set(flags) | ({"test"} if test else set())
    for bit, nm in QUAL_FLAGS:
        if nm in names:
            v |= 1 << (12 - bit)
    return v | extra


def quality_text(v):
    on = [nm for _, nm in QUAL_FLAGS if nm in v.get("flags", ()) or (nm == "test" and v.get("test"))]
    return v.get("validity", "good") + (", " + ", ".join(on) if on else "")


def encode(node, now):
    """MMS Data of one data set entry (node) -> bytes"""
    bt = node["btype"]
    val = node["value"]
    if node.get("children"):
        return tlv(0xA2, b"".join(encode(c, now) for c in node["children"]))
    if bt == "BOOLEAN":
        return tlv(0x83, b"\x01" if val else b"\x00")
    if bt in ("Dbpos", "Tcmd"):
        return tlv(0x84, b"\x06" + bytes([(DBPOS.get(val, 0) & 3) << 6]))
    if bt == "Check":
        return tlv(0x84, b"\x06" + bytes([(int(val) & 3) << 6]))
    if bt == "Quality":
        q = quality_bits(val.get("validity", "good"), val.get("test", False), flags=val.get("flags", ())) \
            if isinstance(val, dict) else int(val)
        return tlv(0x84, b"\x03" + (q << 3).to_bytes(2, "big"))
    if bt == "Timestamp":
        return tlv(0x91, utc_bytes(now if val in (None, "", "auto") else float(val)))
    if bt in ("INT8", "INT16", "INT24", "INT32", "INT64", "INT128", "Enum"):
        return tlv(0x85, ber_int(val))
    if bt in ("INT8U", "INT16U", "INT24U", "INT32U"):
        b = ber_int(val, signed=False)
        return tlv(0x86, b)
    if bt == "FLOAT32":
        return tlv(0x87, b"\x08" + struct.pack(">f", float(val)))
    if bt == "FLOAT64":
        return tlv(0x87, b"\x0b" + struct.pack(">d", float(val)))
    if bt.startswith("VisString") or bt == "Currency":
        return tlv(0x8A, str(val).encode("latin1", "replace"))
    if bt.startswith("Unicode"):
        return tlv(0x90, str(val).encode("utf-8"))
    if bt.startswith("Octet"):
        try:
            return tlv(0x89, bytes.fromhex(str(val)))
        except ValueError:
            return tlv(0x89, b"")
    if bt == "EntryTime":
        return tlv(0x8C, b"\x00" * 6)
    return tlv(0x83, b"\x00")                             # unknown: boolean FALSE


def default_value(bt):
    if bt == "BOOLEAN":
        return False
    if bt in ("Dbpos", "Tcmd"):
        return "off"
    if bt == "Quality":
        return {"validity": "good", "test": False, "flags": []}
    if bt == "Timestamp":
        return "auto"
    if bt in ("FLOAT32", "FLOAT64"):
        return 0.0
    if bt.startswith(("VisString", "Unicode", "Octet")):
        return ""
    return 0


def value_text(node):
    v, bt = node["value"], node["btype"]
    if node.get("children"):
        return ""
    if bt == "BOOLEAN":
        return "TRUE" if v else "FALSE"
    if bt == "Quality":
        return quality_text(v)
    if bt == "Timestamp":
        return "auto (time of the last change)"
    if bt == "Enum" and node.get("enum"):
        return "%s (%s)" % (node["enum"].get(int(v), "?"), v)
    return str(v)


# ---------------------------------------------------------------- SCL
def _q(root):
    ns = root.tag.split("}")[0][1:] if root.tag.startswith("{") else ""
    return (lambda t: "{%s}%s" % (ns, t)) if ns else (lambda t: t)


def _ms(el, default):
    if el is None or not (el.text or "").strip():
        return default
    try:
        v = float(el.text.strip())
    except ValueError:
        return default
    mult = el.get("multiplier", "m")
    return v * {"m": 1.0, "": 1000.0, "u": 0.001}.get(mult, 1.0)


def load_gcbs(path, own_only=None):
    """-> list of publisher entries (one per GSE address) from one SCL file.
    CID / IID / ICD: only the IED of the file (the first IED - the other IEDs in it are copies of
    the publishers it subscribes to); SCD: all IEDs."""
    if own_only is None:
        own_only = os.path.splitext(path)[1].lower() in (".cid", ".iid", ".icd")
    root = ET.parse(path).getroot()
    q = _q(root)
    dtt = root.find(q("DataTypeTemplates"))
    T = dict(lnt={}, dot={}, dat={}, enum={})
    if dtt is not None:
        T["lnt"] = {e.get("id"): e for e in dtt.findall(q("LNodeType"))}
        T["dot"] = {e.get("id"): e for e in dtt.findall(q("DOType"))}
        T["dat"] = {e.get("id"): e for e in dtt.findall(q("DAType"))}
        for e in dtt.findall(q("EnumType")):
            T["enum"][e.get("id")] = {int(v.get("ord")): (v.text or "").strip() for v in e.findall(q("EnumVal"))
                                      if v.get("ord") is not None}
    # addresses
    addr = {}
    com = root.find(q("Communication"))
    if com is not None:
        for sn in com.findall(q("SubNetwork")):
            for cap in sn.findall(q("ConnectedAP")):
                for g in cap.findall(q("GSE")):
                    P = {p.get("type"): (p.text or "").strip() for p in g.iter(q("P"))}
                    addr.setdefault((cap.get("iedName"), g.get("ldInst"), g.get("cbName")), []).append(dict(
                        subnet=sn.get("name", ""), ap=cap.get("apName", ""),
                        mac=(P.get("MAC-Address") or "").replace("-", ":").upper(),
                        appid=int(P["APPID"], 16) if P.get("APPID") else 0,
                        vlan=int(P["VLAN-ID"], 16) if P.get("VLAN-ID") else None,
                        prio=int(P["VLAN-PRIORITY"]) if P.get("VLAN-PRIORITY") else 4,
                        min_ms=_ms(g.find(q("MinTime")), DEF_MIN_MS), max_ms=_ms(g.find(q("MaxTime")), DEF_MAX_MS)))
    out = []
    ieds = root.findall(q("IED"))
    for ied in (ieds[:1] if own_only else ieds):
        iname = ied.get("name", "")
        lns = {}                                         # (ld, lnname) -> lnType
        for ld in ied.iter(q("LDevice")):
            for ln in ld:
                tag = ln.tag.split("}")[-1]
                if tag in ("LN0", "LN"):
                    key = (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or "")
                    lns[(ld.get("inst", ""), key)] = ln.get("lnType")
        for ld in ied.iter(q("LDevice")):
            ldi = ld.get("inst", "")
            ln0 = ld.find(q("LN0"))
            if ln0 is None:
                continue
            dsets = {d.get("name"): d for d in ln0.findall(q("DataSet"))}
            for gc in ln0.findall(q("GSEControl")):
                ds = dsets.get(gc.get("datSet"))
                if ds is None:
                    continue
                entries = []
                for f in ds.findall(q("FCDA")):
                    entries.append(_fcda_node(f, ldi, lns, T, q))
                base = dict(ied=iname, ld=ldi, cb=gc.get("name", ""), file=os.path.basename(path),
                            ref="%s%s/LLN0$GO$%s" % (iname, ldi, gc.get("name", "")),
                            datset="%s%s/LLN0$%s" % (iname, ldi, gc.get("datSet", "")),
                            goid=gc.get("appID") or "%s%s/LLN0$GO$%s" % (iname, ldi, gc.get("name", "")),
                            confrev=int(gc.get("confRev") or 1), entries=entries)
                adrs = addr.get((iname, ldi, gc.get("name"))) or [None]
                for a in adrs:
                    e = dict(base)
                    e["entries"] = _copy(entries)
                    if a:
                        e.update(a)
                    else:
                        e.update(subnet="", ap="", mac="", appid=0, vlan=None, prio=4,
                                 min_ms=DEF_MIN_MS, max_ms=DEF_MAX_MS)
                    out.append(e)
    return out


def _copy(nodes):
    return [dict(n, children=_copy(n.get("children") or []), value=_val_copy(n["value"]),
                 trg=set(n.get("trg") or ())) for n in nodes]


def _val_copy(v):
    if isinstance(v, dict):
        d = dict(v)
        if "flags" in d:
            d["flags"] = list(d["flags"])
        return d
    return v


def all_nodes(nodes):
    for n in nodes:
        yield n
        yield from all_nodes(n.get("children") or [])


def _fcda_node(f, ldi, lns, T, q):
    ln = (f.get("prefix", "") or "") + f.get("lnClass", "") + (f.get("lnInst", "") or "")
    name = "%s/%s.%s" % (f.get("ldInst", ""), ln, f.get("doName", ""))
    fc = f.get("fc", "")
    if f.get("daName"):
        name += "." + f.get("daName")
    lnt = T["lnt"].get(lns.get((f.get("ldInst") or ldi, ln)))
    dot = None
    if lnt is not None:
        parts = f.get("doName", "").split(".")
        do = next((d for d in lnt.findall(q("DO")) if d.get("name") == parts[0]), None)
        dot = T["dot"].get(do.get("type")) if do is not None else None
        for p in parts[1:]:
            if dot is None:
                break
            sdo = next((s for s in dot.findall(q("SDO")) if s.get("name") == p), None)
            dot = T["dot"].get(sdo.get("type")) if sdo is not None else None
    label = "%s [%s]" % (name, fc)
    if dot is None:                                       # type unknown: treat as BOOLEAN
        return dict(name=label, btype="BOOLEAN", value=False, children=[], unknown=True)
    if f.get("daName"):
        parts = f.get("daName").split(".")
        da = next((d for d in dot.findall(q("DA")) if d.get("name") == parts[0]), None)
        if da is None:
            return dict(name=label, btype="BOOLEAN", value=False, children=[], unknown=True)
        el = da
        for p in parts[1:]:
            dat = T["dat"].get(el.get("type"))
            el = next((b for b in dat.findall(q("BDA")) if b.get("name") == p), None) if dat is not None else None
            if el is None:
                return dict(name=label, btype="BOOLEAN", value=False, children=[], unknown=True)
        return _da_node(label, el, T, q, inherit=_trg(da))
    kids = _dot_members(dot, fc, T, q, name)
    return dict(name=label, btype="Struct", value=None, children=kids,
                trg=set().union(*[k.get("trg", set()) for k in kids]) if kids else set())


def _trg(el, inherit=()):
    """trigger options of a DA (dchg / qchg / dupd); a BDA inherits those of its DA"""
    t = {k for k in ("dchg", "qchg", "dupd") if el.get(k) == "true"}
    return t or set(inherit)


def _da_node(name, el, T, q, depth=0, inherit=()):
    bt = el.get("bType", "")
    trg = _trg(el, inherit)
    if bt == "Struct" and depth < 6:
        dat = T["dat"].get(el.get("type"))
        kids = [_da_node(name + "." + b.get("name"), b, T, q, depth + 1, trg) for b in dat.findall(q("BDA"))] if dat is not None else []
        return dict(name=name, btype="Struct", value=None, children=kids, trg=trg)
    n = dict(name=name, btype=bt, value=default_value(bt), children=[], trg=trg)
    if bt == "Enum":
        n["enum"] = T["enum"].get(el.get("type"), {})
        if n["enum"]:
            n["value"] = min(n["enum"])
    return n


def _dot_members(dot, fc, T, q, base, depth=0):
    out = []
    if depth > 6:
        return out
    for el in dot:
        tag = el.tag.split("}")[-1]
        if tag == "DA" and el.get("fc") == fc:
            out.append(_da_node(base + "." + el.get("name"), el, T, q))
        elif tag == "SDO":
            sd = T["dot"].get(el.get("type"))
            if sd is not None:
                kids = _dot_members(sd, fc, T, q, base + "." + el.get("name"), depth + 1)
                if kids:
                    out.append(dict(name=base + "." + el.get("name"), btype="Struct", value=None, children=kids,
                                    trg=set().union(*[k.get("trg", set()) for k in kids])))
    return out


# ---------------------------------------------------------------- frame
def macb(s):
    return bytes(int(x, 16) for x in s.replace("-", ":").split(":"))


def build_frame(g, src_mac, now, tal_ms):
    alld = b"".join(encode(n, g["t_change"]) for n in g["entries"])
    sim = g.get("simulation", True)
    pdu = (tlv(0x80, g["ref"].encode()) + tlv(0x81, ber_int(int(tal_ms))) + tlv(0x82, g["datset"].encode()) +
           tlv(0x83, g["goid"].encode()) + tlv(0x84, utc_bytes(g["t_change"])) +
           tlv(0x85, ber_int(g["stnum"])) + tlv(0x86, ber_int(g["sqnum"])) +
           tlv(0x87, b"\x01" if sim else b"\x00") + tlv(0x88, ber_int(g["confrev"])) +
           tlv(0x89, b"\x01" if g.get("ndscom") else b"\x00") + tlv(0x8A, ber_int(len(g["entries"]))) +
           tlv(0xAB, alld))
    apdu = tlv(0x61, pdu)
    res1 = b"\x80\x00" if sim else b"\x00\x00"
    payload = g["appid"].to_bytes(2, "big") + (8 + len(apdu)).to_bytes(2, "big") + res1 + b"\x00\x00" + apdu
    h = macb(g["mac"]) + macb(src_mac)
    if g.get("vlan") is not None:
        h += b"\x81\x00" + (((g.get("prio") or 0) << 13) | (g["vlan"] & 0x0FFF)).to_bytes(2, "big")
    fr = h + b"\x88\xb8" + payload
    if len(fr) < 60:
        fr += b"\x00" * (60 - len(fr))
    return fr


# ---------------------------------------------------------------- sender
class Publisher(threading.Thread):
    """sends all active control blocks; send(iface, frame) is given (Scapy socket per adapter)"""

    def __init__(self, sender, on_sent=None, on_error=None):
        super().__init__(daemon=True)
        self.sender, self.on_sent, self.on_error = sender, on_sent, on_error
        self.gcbs = []
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self._halt = threading.Event()
        self.count = 0

    def add(self, g, iface, src_mac):
        with self.lock:
            now = time.time()
            g.update(iface=iface, src=src_mac, stnum=g.get("stnum", 0) + 1, sqnum=0, t_change=now,
                     interval=g["min_ms"], next=time.monotonic(), active=True)
            if g not in self.gcbs:
                self.gcbs.append(g)
        self.wake.set()

    def remove(self, g):
        with self.lock:
            g["active"] = False
            if g in self.gcbs:
                self.gcbs.remove(g)

    def change(self, g):
        """a value of g changed -> new state (stNum + 1), fast retransmission"""
        with self.lock:
            if not g.get("active"):
                return
            g.update(stnum=g["stnum"] + 1, sqnum=0, t_change=time.time(), interval=g["min_ms"], next=time.monotonic())
        self.wake.set()

    def stop(self):
        with self.lock:
            for g in self.gcbs:
                g["active"] = False
            self.gcbs = []
        self._halt.set()
        self.wake.set()

    def run(self):
        while not self._halt.is_set():
            with self.lock:
                now_m = time.monotonic()
                due = [g for g in self.gcbs if g["active"] and g["next"] <= now_m + 0.0002]
                for g in due:
                    # interval to the next message: after a change MinTime, then 2x, 4x ... MaxTime
                    nxt_ms = g["min_ms"] if g["sqnum"] == 0 else min(g["interval"] * 2, g["max_ms"])
                    tal = 2 * nxt_ms                      # TAL = 2 x time to the next message
                    try:
                        fr = build_frame(g, g["src"], time.time(), tal)
                        self.sender(g["iface"], fr)
                        self.count += 1
                        if self.on_sent:
                            self.on_sent(g)
                    except Exception as ex:
                        g["active"] = False
                        if self.on_error:
                            self.on_error(g, str(ex))
                        continue
                    g["interval"] = nxt_ms
                    g["sqnum"] = (g["sqnum"] + 1) & 0xFFFFFFFF
                    g["next"] = now_m + nxt_ms / 1000.0
                wait = min([g["next"] for g in self.gcbs if g["active"]] or [now_m + 0.5]) - time.monotonic()
            self.wake.wait(max(0.0005, min(wait, 0.5)))
            self.wake.clear()


def scapy_sender():
    """-> function send(iface, frame) with one Scapy L2 socket per adapter"""
    import scapy.all  # noqa: F401  (loads Npcap / libpcap)
    from scapy.config import conf
    socks = {}

    def send(iface, frame):
        s = socks.get(iface)
        if s is None:
            s = socks[iface] = conf.L2socket(iface=iface)
        s.send(frame)
    return send


def adapter_mac(iface):
    try:
        from scapy.arch import get_if_hwaddr
        return get_if_hwaddr(iface).upper()
    except Exception:
        return "00:00:00:00:00:00"
