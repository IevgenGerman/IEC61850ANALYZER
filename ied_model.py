# -*- coding: utf-8 -*-
"""
ied_model.py - data model of one IED from its CID / SCD for the IED simulator (MMS server).

  load(path, ied_name)  -> Model: logical devices (MMS domains), logical nodes as MMS structures
                           LN $ FC $ DO $ DA (IEC 61850-8-1), values from DAI / Val of the CID,
                           data sets (named variable lists), report control blocks (URCB / BRCB
                           instances name01.. when indexed) and GOOSE control blocks.
  encode(node, now)     -> MMS Data of a node (value)
  type_desc(node)       -> MMS TypeDescription (GetVariableAccessAttributes)
  decode(tag, bytes)    -> python value of a written MMS Data element

A node is a dict: name, btype, value, kids [nodes], trg (dchg / qchg / dupd), enum, fc, path
(domain, item), parent. The values of the RCB attributes are kept in their nodes too.
"""
import os
import struct
import time
import xml.etree.ElementTree as ET

import goose_pub as gp

FC_ORDER = ["MX", "ST", "CO", "CF", "DC", "SP", "SG", "SE", "SV", "SR", "OR", "BL", "EX",
            "BR", "RP", "LG", "GO", "GS", "MS", "US"]
TRG_BITS = ["reserved", "dchg", "qchg", "dupd", "period", "gi"]
OPT_BITS = ["reserved", "seq-num", "time-stamp", "reason", "data-set", "data-ref", "buffer-ovfl", "entryID",
            "conf-rev", "segmentation"]
SCL_OPT = {"seqNum": "seq-num", "timeStamp": "time-stamp", "reasonCode": "reason", "dataSet": "data-set",
           "dataRef": "data-ref", "bufOvfl": "buffer-ovfl", "entryID": "entryID", "configRef": "conf-rev",
           "segmentation": "segmentation"}
INT_BITS = {"INT8": 8, "INT16": 16, "INT24": 24, "INT32": 32, "INT64": 64, "INT128": 128, "Enum": 8,
            "INT8U": 8, "INT16U": 16, "INT24U": 24, "INT32U": 32}
EPOCH_1984 = 441763200                                   # 1984-01-01 UTC


def tlv(tag, val):
    n = len(val)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b"\x81" + bytes([n])
    elif n < 0x10000:
        ln = b"\x82" + n.to_bytes(2, "big")
    else:
        ln = b"\x83" + n.to_bytes(3, "big")
    return bytes([tag]) + ln + val


def sint_bytes(v):
    n = 1
    while True:
        try:
            return int(v).to_bytes(n, "big", signed=True)
        except OverflowError:
            n += 1


def bits_bytes(names, table):
    """set of names -> MMS bit string content (unused-bits byte + bits, MSB first)"""
    n = len(table)
    nbytes = (n + 7) // 8
    v = 0
    for i, nm in enumerate(table):
        if nm in names:
            v |= 1 << (nbytes * 8 - 1 - i)
    return bytes([nbytes * 8 - n]) + v.to_bytes(nbytes, "big")


def binary_time(t):
    """BinaryTime 6 bytes: ms of the day, days since 1984-01-01"""
    days = int((t - EPOCH_1984) // 86400)
    ms = int(round((t - EPOCH_1984 - days * 86400) * 1000))
    return ms.to_bytes(4, "big") + days.to_bytes(2, "big")


# ---------------------------------------------------------------- nodes
def node(name, btype, value=None, kids=None, **kw):
    n = dict(name=name, btype=btype, value=value, kids=kids or [], trg=set(), parent=None)
    n.update(kw)
    for k in n["kids"]:
        k["parent"] = n
    return n


def _q(root):
    return gp._q(root)


def _da(name, el, T, q, fc, inherit=(), depth=0):
    bt = el.get("bType", "")
    trg = {k for k in ("dchg", "qchg", "dupd") if el.get(k) == "true"} or set(inherit)
    if bt == "Struct" and depth < 8:
        dat = T["dat"].get(el.get("type"))
        kids = [_da(b.get("name"), b, T, q, fc, trg, depth + 1) for b in dat.findall(q("BDA"))] if dat is not None else []
        n = node(name, "Struct", None, kids, fc=fc)
    else:
        n = node(name, bt, gp.default_value(bt), fc=fc)
        if bt == "Enum":
            n["enum"] = T["enum"].get(el.get("type"), {})
            if n["enum"]:
                n["value"] = min(n["enum"])
        if bt == "Timestamp":
            n["value"] = time.time()
        if el.get("count") and int(el.get("count") or 0) > 0:      # array of a basic type
            cnt = int(el.get("count"))
            n = node(name, "Array", None, [node(str(i), bt, gp.default_value(bt), fc=fc) for i in range(cnt)], fc=fc)
    n["trg"] = trg
    for v in el.findall(q("Val")):                        # value in the type (DA / BDA)
        set_text(n, (v.text or "").strip())
        break
    return n


def _do(name, dot, fc, T, q, depth=0):
    """DO (or SDO) of the type dot with only the DAs of the functional constraint fc"""
    kids = []
    if dot is None or depth > 8:
        return None
    for el in dot:
        tag = el.tag.split("}")[-1]
        if tag == "DA" and el.get("fc") == fc:
            kids.append(_da(el.get("name"), el, T, q, fc))
        elif tag == "SDO":
            k = _do(el.get("name"), T["dot"].get(el.get("type")), fc, T, q, depth + 1)
            if k:
                kids.append(k)
    return node(name, "Struct", None, kids, fc=fc) if kids else None


def set_text(n, text):
    """value from the CID (Val) / editor text -> node value"""
    bt = n["btype"]
    try:
        if bt == "BOOLEAN":
            n["value"] = text.strip().lower() in ("true", "1", "on")
        elif bt == "Enum":
            rev = {v: k for k, v in (n.get("enum") or {}).items()}
            n["value"] = rev[text] if text in rev else int(text)
        elif bt in INT_BITS:
            n["value"] = int(text)
        elif bt in ("FLOAT32", "FLOAT64"):
            n["value"] = float(text)
        elif bt in ("Dbpos", "Tcmd"):
            n["value"] = text if text in gp.DBPOS else "off"
        elif bt in ("Quality", "Timestamp", "Struct", "Array"):
            pass
        else:
            n["value"] = text
    except (ValueError, KeyError):
        pass


def walk(n):
    yield n
    for k in n["kids"]:
        yield from walk(k)


def leaves(n):
    return [x for x in walk(n) if not x["kids"]]


# ---------------------------------------------------------------- RCB / GoCB nodes
def _rcb_node(inst, rc, buffered, dom, lnn, dsref, ed2, q):
    tr = rc.find(q("TrgOps"))
    of = rc.find(q("OptFields"))
    trg = {k for k in TRG_BITS[1:] if tr is not None and tr.get(k, "true" if k == "gi" else "false") == "true"}
    opt = {v for k, v in SCL_OPT.items() if of is not None and of.get(k) == "true"}
    rid = rc.get("rptID") or "%s/%s$%s$%s" % (dom, lnn, "BR" if buffered else "RP", inst)
    k = [node("RptID", "VisString129", rid), node("RptEna", "BOOLEAN", False)]
    if not buffered:
        k.append(node("Resv", "BOOLEAN", False))
    k += [node("DatSet", "VisString129", dsref), node("ConfRev", "INT32U", int(rc.get("confRev") or 1)),
          node("OptFlds", "OptFlds", opt), node("BufTm", "INT32U", int(rc.get("bufTime") or 0)),
          node("SqNum", "INT16U" if buffered else "INT8U", 0), node("TrgOps", "TrgOps", trg),
          node("IntgPd", "INT32U", int(rc.get("intgPd") or 0)), node("GI", "BOOLEAN", False)]
    if buffered:
        k += [node("PurgeBuf", "BOOLEAN", False), node("EntryID", "Octet8", "0000000000000000"),
              node("TimeOfEntry", "EntryTime", 0.0)]
        if ed2:
            k.append(node("ResvTms", "INT16", 0))
    if ed2:
        k.append(node("Owner", "Octet64", ""))
    n = node(inst, "Struct", None, k, fc="BR" if buffered else "RP")
    for x in walk(n):
        x["fc"] = n["fc"]
    n["rcb"] = dict(buffered=buffered, name=inst, cbname=rc.get("name"), ln=lnn, domain=dom)
    return n


def _gocb_node(gc, dom, dsref, addr):
    a = addr or {}
    k = [node("GoEna", "BOOLEAN", False), node("GoID", "VisString129", gc.get("appID") or ""),
         node("DatSet", "VisString129", dsref), node("ConfRev", "INT32U", int(gc.get("confRev") or 1)),
         node("NdsCom", "BOOLEAN", False),
         node("DstAddress", "Struct", None, [
             node("Addr", "Octet6", a.get("mac", "010CCD010000").replace(":", "").replace("-", "")),
             node("PRIORITY", "INT8U", a.get("prio", 4)), node("VID", "INT16U", a.get("vlan") or 0),
             node("APPID", "INT16U", a.get("appid") or 0)]),
         node("MinTime", "INT32U", a.get("min", 0)), node("MaxTime", "INT32U", a.get("max", 0)),
         node("FixedOffs", "BOOLEAN", False)]
    n = node(gc.get("name", ""), "Struct", None, k, fc="GO")
    for x in walk(n):
        x["fc"] = "GO"
    return n


# ---------------------------------------------------------------- SCL
def list_ieds(path):
    root = ET.parse(path).getroot()
    q = _q(root)
    return [i.get("name", "") for i in root.findall(q("IED"))]


def load(path, ied_name=None):
    root = ET.parse(path).getroot()
    q = _q(root)
    ed2 = (root.get("version") or "") >= "2007"
    dtt = root.find(q("DataTypeTemplates"))
    T = dict(lnt={}, dot={}, dat={}, enum={})
    if dtt is not None:
        T["lnt"] = {e.get("id"): e for e in dtt.findall(q("LNodeType"))}
        T["dot"] = {e.get("id"): e for e in dtt.findall(q("DOType"))}
        T["dat"] = {e.get("id"): e for e in dtt.findall(q("DAType"))}
        for e in dtt.findall(q("EnumType")):
            T["enum"][e.get("id")] = {int(v.get("ord")): (v.text or "").strip() for v in e.findall(q("EnumVal"))
                                      if v.get("ord") is not None}
    ieds = root.findall(q("IED"))
    if not ieds:
        raise ValueError("no IED in the file")
    ied = next((i for i in ieds if i.get("name") == ied_name), None) if ied_name else ieds[0]
    if ied is None:
        raise ValueError("IED %s is not in the file" % ied_name)
    iname = ied.get("name", "")
    ips, gse, masks = [], {}, {}
    com = root.find(q("Communication"))
    if com is not None:
        for cap in com.iter(q("ConnectedAP")):
            if cap.get("iedName") != iname:
                continue
            for a in cap.findall(q("Address")):
                P = {p.get("type"): (p.text or "").strip() for p in a.findall(q("P"))}
                if P.get("IP"):
                    ips.append(P["IP"])
                    masks[P["IP"]] = P.get("IP-SUBNET") or "255.255.255.0"
            for g in cap.findall(q("GSE")):
                P = {p.get("type"): (p.text or "").strip() for p in g.iter(q("P"))}
                gse[(g.get("ldInst"), g.get("cbName"))] = dict(
                    mac=P.get("MAC-Address") or "", appid=int(P["APPID"], 16) if P.get("APPID") else 0,
                    vlan=int(P["VLAN-ID"], 16) if P.get("VLAN-ID") else 0,
                    prio=int(P["VLAN-PRIORITY"]) if (P.get("VLAN-PRIORITY") or "").isdigit() else 4,
                    min=gp._ms(g.find(q("MinTime")), 0), max=gp._ms(g.find(q("MaxTime")), 0))
    M = dict(ied=iname, file=os.path.basename(path), path=path, ips=ips, masks=masks, ed2=ed2,
             vendor=ied.get("manufacturer") or "", model=ied.get("type") or "", revision=ied.get("configVersion") or "",
             lds={}, index={}, datasets={}, rcbs=[], gocbs=[])
    lddom = {ld.get("inst", ""): (ld.get("ldName") or iname + ld.get("inst", "")) for ld in ied.iter(q("LDevice"))}
    for ld in ied.iter(q("LDevice")):
        ldi = ld.get("inst", "")
        dom = lddom[ldi]
        lns = {}
        for ln in ld:
            tag = ln.tag.split("}")[-1]
            if tag not in ("LN0", "LN"):
                continue
            lnn = "LLN0" if tag == "LN0" else (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or "")
            lnt = T["lnt"].get(ln.get("lnType"))
            fcs = {}
            if lnt is not None:
                for fc in FC_ORDER[:13]:
                    dos = []
                    for do in lnt.findall(q("DO")):
                        d = _do(do.get("name"), T["dot"].get(do.get("type")), fc, T, q)
                        if d:
                            dos.append(d)
                    if dos:
                        fcs[fc] = node(fc, "Struct", None, dos, fc=fc)
            ln_node = node(lnn, "Struct", None, [], ln_el=ln)
            # instance values (DOI / SDI / DAI / Val)
            for doi in ln.findall(q("DOI")):
                _doi_values(doi, [doi.get("name")], fcs, q)
            # data sets
            for ds in ln.findall(q("DataSet")):
                mem = []
                for f in ds.findall(q("FCDA")):
                    fl = "LLN0" if f.get("lnClass") == "LLN0" else \
                        (f.get("prefix", "") or "") + f.get("lnClass", "") + (f.get("lnInst", "") or "")
                    item = fl + "$" + (f.get("fc") or "")
                    if f.get("doName"):
                        item += "$" + f.get("doName").replace(".", "$")
                    if f.get("daName"):
                        item += "$" + f.get("daName").replace(".", "$")
                    mem.append((lddom.get(f.get("ldInst") or ldi, iname + (f.get("ldInst") or ldi)), item))
                M["datasets"].setdefault(dom, {})["%s$%s" % (lnn, ds.get("name"))] = mem
            # control blocks
            for rc in ln.findall(q("ReportControl")):
                buffered = rc.get("buffered") == "true"
                re_ = rc.find(q("RptEnabled"))
                mx = int(re_.get("max") or 1) if re_ is not None else 1
                indexed = rc.get("indexed", "true") != "false"
                dsref = ("%s/%s$%s" % (dom, lnn, rc.get("datSet"))) if rc.get("datSet") else ""
                names = ["%s%02d" % (rc.get("name"), i + 1) for i in range(mx)] if indexed else [rc.get("name")]
                fc = "BR" if buffered else "RP"
                for inst in names:
                    n = _rcb_node(inst, rc, buffered, dom, lnn, dsref, ed2, q)
                    fcs.setdefault(fc, node(fc, "Struct", None, [], fc=fc))["kids"].append(n)
                    M["rcbs"].append(n)
            for gc in ln.findall(q("GSEControl")):
                dsref = ("%s/%s$%s" % (dom, lnn, gc.get("datSet"))) if gc.get("datSet") else ""
                n = _gocb_node(gc, dom, dsref, gse.get((ldi, gc.get("name"))))
                fcs.setdefault("GO", node("GO", "Struct", None, [], fc="GO"))["kids"].append(n)
                M["gocbs"].append(n)
            ln_node["kids"] = [fcs[f] for f in FC_ORDER if f in fcs]
            lns[lnn] = ln_node
        M["lds"][dom] = {k: lns[k] for k in sorted(lns)}
    # parents, paths, index
    for dom, lns in M["lds"].items():
        idx = {}
        M["index"][dom] = idx
        for lnn, ln in lns.items():
            _link(ln, None, lnn, dom, idx)
    return M


def _link(n, parent, item, dom, idx):
    n["parent"] = parent
    n["path"] = (dom, item)
    idx[item] = n
    for k in n["kids"]:
        _link(k, n, item + "$" + k["name"], dom, idx)


def _doi_values(el, path, fcs, q):
    for c in el:
        tag = c.tag.split("}")[-1]
        if tag in ("SDI", "DOI"):
            _doi_values(c, path + [c.get("name")], fcs, q)
        elif tag == "DAI":
            val = c.find(q("Val"))
            if val is None or val.text is None:
                continue
            names = path + [c.get("name")]
            for fcn in fcs.values():
                n = fcn
                for p in names:
                    n = next((k for k in n["kids"] if k["name"] == p), None)
                    if n is None:
                        break
                if n is not None and not n["kids"]:
                    set_text(n, val.text.strip())
                    break


# ---------------------------------------------------------------- model access
def names(M, dom):
    """variable names of a domain (depth first, LN alphabetical)"""
    return list(M["index"].get(dom, {}).keys())


def find(M, dom, item):
    return M["index"].get(dom, {}).get(item)


def ref(n):
    return "%s/%s" % n["path"]


# ---------------------------------------------------------------- MMS encoding
def encode(n, now=None):
    now = now or time.time()
    if n["kids"]:
        return tlv(0xA1 if n["btype"] == "Array" else 0xA2, b"".join(encode(k, now) for k in n["kids"]))
    bt, v = n["btype"], n["value"]
    if bt == "TrgOps":
        return tlv(0x84, bits_bytes(v or set(), TRG_BITS))
    if bt == "OptFlds":
        return tlv(0x84, bits_bytes(v or set(), OPT_BITS))
    if bt == "EntryTime":
        return tlv(0x8C, binary_time(v or now))
    if bt == "Timestamp":
        return tlv(0x91, gp.utc_bytes(float(v) if isinstance(v, (int, float)) else now))
    if bt == "Struct":                                   # empty structure
        return tlv(0xA2, b"")
    if bt in ("INT64", "INT128") or (bt in INT_BITS and not bt.endswith("U")):
        return tlv(0x85, sint_bytes(int(v or 0)))
    if bt in INT_BITS:                                   # unsigned: no leading sign problem
        b = sint_bytes(max(0, int(v or 0)))
        return tlv(0x86, b)
    return gp.encode(dict(n, children=[]), now)


def type_desc(n):
    if n["kids"] and n["btype"] == "Array":
        return tlv(0xA1, tlv(0x81, sint_bytes(len(n["kids"]))) + tlv(0xA2, type_desc(n["kids"][0])))
    if n["kids"] or n["btype"] == "Struct":
        comps = b"".join(tlv(0x30, tlv(0x80, k["name"].encode()) + tlv(0xA1, type_desc(k))) for k in n["kids"])
        return tlv(0xA2, tlv(0xA1, comps))
    bt = n["btype"]
    if bt == "BOOLEAN":
        return b"\x83\x00"
    if bt in INT_BITS:
        return tlv(0x86 if bt.endswith("U") else 0x85, bytes([INT_BITS[bt]]))
    if bt == "FLOAT32":
        return tlv(0xA7, b"\x02\x01\x20\x02\x01\x08")
    if bt == "FLOAT64":
        return tlv(0xA7, b"\x02\x01\x40\x02\x01\x0b")
    if bt == "Quality":
        return b"\x84\x01\x0d"
    if bt in ("Dbpos", "Tcmd", "Check"):
        return b"\x84\x01\x02"
    if bt == "TrgOps":
        return b"\x84\x01\x06"
    if bt == "OptFlds":
        return b"\x84\x01\x0a"
    if bt == "Timestamp":
        return b"\x91\x00"
    if bt == "EntryTime":
        return b"\x8c\x01\xff"
    if bt.startswith("VisString") or bt in ("ObjRef", "Currency"):
        size = int("".join(c for c in bt if c.isdigit()) or 129)
        return tlv(0x8A, sint_bytes(-size))
    if bt.startswith("Unicode"):
        return tlv(0x90, sint_bytes(-int("".join(c for c in bt if c.isdigit()) or 255)))
    if bt.startswith("Octet"):
        size = int("".join(c for c in bt if c.isdigit()) or 64)
        return tlv(0x89, sint_bytes(size if bt in ("Octet8", "Octet6") else -size))
    return b"\x83\x00"


def decode(tag, b):
    """written MMS Data (simple types) -> python value"""
    if tag == 0x83:
        return bool(b and b[0])
    if tag == 0x85:
        return int.from_bytes(b, "big", signed=True) if b else 0
    if tag == 0x86:
        return int.from_bytes(b, "big") if b else 0
    if tag in (0x8A, 0x90):
        return b.decode("latin1" if tag == 0x8A else "utf-8", "replace")
    if tag == 0x89:
        return b.hex()
    if tag == 0x84:
        unused = b[0] if b else 0
        raw = b[1:]
        n = len(raw) * 8 - unused
        return [(raw[i // 8] >> (7 - i % 8)) & 1 for i in range(max(n, 0))]
    if tag == 0x87 and len(b) == 5:
        return struct.unpack(">f", b[1:])[0]
    return None


def value_text(n):
    if n["kids"]:
        return ""
    bt, v = n["btype"], n["value"]
    if bt in ("TrgOps", "OptFlds"):
        return ", ".join(x for x in (TRG_BITS if bt == "TrgOps" else OPT_BITS) if x in (v or ()))
    if bt == "Timestamp":
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(v))) + " UTC" if isinstance(v, (int, float)) else ""
    if bt == "EntryTime":
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(v))) + " UTC" if v else ""
    if bt in ("Dbpos", "Tcmd"):
        return str(v)
    return gp.value_text(dict(n, children=[]))
