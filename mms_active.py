# -*- coding: utf-8 -*-
"""
mms_active.py - logic of the tab MMS / Active (no GUI): model of the IED read online with the MMS
client, control blocks (RCB / GoCB) in plain words, the same model taken from the CID, and the
comparison online <-> CID.

  browse(client)              -> Online model: logical devices, variable names, data set names
  read_datasets(client, om)   -> members of every data set
  read_cbs(client, om)        -> RCBs (URCB / BRCB) and GoCBs with their attributes
  cid_model(path, ied)        -> the same from the CID / SCD
  compare(cid, om)            -> findings [(section, "ok" | "bad" | "info", text)]
"""
import os
import xml.etree.ElementTree as ET

import mms
import mms_client as mc
import sniff_core as sc
import goose_pub as gp

TRG_BITS = ["reserved", "dchg", "qchg", "dupd", "period", "gi"]
OPT_BITS = ["reserved", "seq-num", "time-stamp", "reason", "data-set", "data-ref", "buffer-ovfl", "entryID",
            "conf-rev", "segmentation"]
# SCL OptFields attribute -> name of the bit above
SCL_OPT = {"seqNum": "seq-num", "timeStamp": "time-stamp", "reasonCode": "reason", "dataSet": "data-set",
           "dataRef": "data-ref", "bufOvfl": "buffer-ovfl", "entryID": "entryID", "configRef": "conf-rev",
           "segmentation": "segmentation"}
FC_TEXT = {"ST": "status", "MX": "measurands", "CO": "control", "CF": "configuration", "DC": "description",
           "SP": "setting", "SG": "setting group", "SE": "setting group edit", "SV": "substitution",
           "EX": "extended definition", "BR": "buffered report", "RP": "unbuffered report", "LG": "log",
           "GO": "GOOSE control", "GS": "GSSE control", "MS": "multicast SV", "US": "unicast SV",
           "SR": "service response", "OR": "operate received", "BL": "blocking"}


# ---------------------------------------------------------------- helpers
def bit_names(raw, names):
    bits, n = sc.bitstring(raw or b"")
    return [names[i] for i, x in enumerate(bits) if x and i < len(names) and names[i] != "reserved"]


def owner_text(raw):
    if not raw or not any(raw):
        return ""
    if len(raw) == 4:
        return ".".join(str(x) for x in raw)
    return raw.hex()


def leaf_map(rows, root):
    """typed rows of a structure -> {component path below root ('DatSet', 'DstAddress.Addr'): (type, text, raw)}"""
    out = {}
    for path, typ, text, raw in rows:
        if path.startswith(root + "."):
            out[path[len(root) + 1:]] = (typ, text, raw)
    return out


def compact(rows):
    """typed rows -> one line 'stVal=TRUE   q=good   t=...' (monitor)"""
    if not rows:
        return ""
    root = rows[0][0]
    leaves = [(p, t, v) for p, t, v, r in rows if t not in ("Structure", "Array")]
    if len(leaves) == 1 and leaves[0][0] == root:
        return leaves[0][2]
    out = []
    for p, t, v in leaves:
        nm = p[len(root) + 1:] if p.startswith(root + ".") else p
        if t == "Quality" and "(" in v:
            v = v[v.index("(") + 1:v.rindex(")")]
        out.append("%s=%s" % (nm, v))
    return "   ".join(out)


def leaf_state(typ, text):
    """Boolean TRUE / Dbpos on -> True, FALSE / off -> False, else None"""
    if typ == "Boolean":
        return text == "TRUE"
    if typ == "Dbpos":
        return True if text.startswith("on") else (False if text.startswith("off") else None)
    return None


def state_of(rows):
    """state of a signal (value of a DO / DA): stVal or general, or the value itself"""
    leaves = [(p, t, v) for p, t, v, r in rows if t not in ("Structure", "Array")]
    if len(leaves) == 1:
        return leaf_state(leaves[0][1], leaves[0][2])
    for name in ("stVal", "general"):
        for p, t, v in leaves:
            if p.rsplit(".", 1)[-1] == name:
                return leaf_state(t, v)
    return None


def ln_of(item):
    return item.split("$", 1)[0]


def is_cb(item):
    p = item.split("$")
    return len(p) == 3 and p[1] in ("RP", "BR", "GO")


def find_type(typ, item):
    """type of the LN + 'LN$FC$DO$DA' -> type of that member (None if unknown)"""
    parts = item.split("$")[1:]
    t = typ
    for p in parts:
        if not t or t.get("kind") != "struct":
            return None
        t = next((ct for cn, ct in t["comps"] if cn == p), None)
    return t


# ---------------------------------------------------------------- online model
def new_model():
    return dict(ident=[], lds={}, names={}, flat={}, dsnames={}, datasets={}, rcbs=[], gocbs=[], types={}, peer="",
                cbs_read=False, ds_read=False)


def browse(client, om=None, progress=None):
    om = om or new_model()
    try:
        om["ident"] = client.identify()
    except mc.MmsError:
        om["ident"] = []
    lds = client.name_list(9)
    for ld in lds:
        if progress:
            progress("reading names of %s" % ld)
        names = client.name_list(0, ld)
        om["names"][ld] = names
        om["lds"][ld] = sorted({n for n in names if "$" not in n})
        # some IEDs list only the logical nodes: the members are then taken from the type of the LN
        om["flat"][ld] = not any("$" in n for n in names)
        try:
            om["dsnames"][ld] = client.name_list(2, ld)
        except mc.MmsError:
            om["dsnames"][ld] = []
    return om


def expand_ln(client, om, domain, ln):
    """names of all members of a LN from its type (GetVariableAccessAttributes) -> added to om["names"]"""
    out = []
    try:
        typ = ln_type(client, om, domain, ln)
    except mc.MmsError:                               # too big: functional constraint by functional constraint
        typ = None
        comps = []
        for fc in FC_TEXT:
            t = item_type(client, om, domain, ln + "$" + fc)
            if t is not None:
                comps.append((fc, t))
        if comps:
            typ = dict(kind="struct", comps=comps)

    def walk(t, path):
        if t and t.get("kind") == "struct":
            for cn, ct in t["comps"]:
                p = path + "$" + cn
                out.append(p)
                walk(ct, p)
    walk(typ, ln)
    have = set(om["names"].setdefault(domain, []))
    om["names"][domain] += [n for n in out if n not in have]
    return out


def read_dataset_values(client, om, ref, members):
    """values of a data set -> [(text, type)]; read as named variable list, else member by member"""
    ld, item = ref.split("/", 1)
    res = None
    try:
        res = client.read_list(ld, item)
        if not res or all(not r[0] for r in res) or len(res) != len(members):
            res = None
    except mc.MmsError:
        res = None
    if res is None:                                   # member by member (grouped by LD, 20 per request)
        res = [None] * len(members)
        groups = {}
        for i, m in enumerate(members):
            md, mi = m.split("/", 1)
            groups.setdefault(md, []).append((i, mi))
        for md, lst in groups.items():
            for k in range(0, len(lst), 20):
                part = lst[k:k + 20]
                try:
                    r = client.read(md, [mi for _, mi in part])
                except mc.MmsError as ex:
                    r = [(False, str(ex), None, None)] * len(part)
                for (i, _), x in zip(part, r):
                    res[i] = x
    out = []
    for m, x in zip(members, res):
        ok, b, t, e = x or (False, "no result", None, None)
        if not ok:
            out.append(("error: " + str(b), "", None))
            continue
        md, mi = m.split("/", 1)
        typ = item_type(client, om, md, mi)
        rows = []
        mc.typed_rows(b, t, e, typ, mi.replace("$", "."), rows)
        out.append((compact(rows), rows[0][1] if rows else "", state_of(rows)))
    return out


def ln_type(client, om, domain, ln):
    key = (domain, ln)
    if key not in om["types"]:
        om["types"][key] = client.type_of(domain, ln)
    return om["types"][key]


def item_type(client, om, domain, item):
    """type of any variable; a LN whose type does not fit into one PDU (big GGIO of GE UR: service error
    pdu-size) is asked level by level: LN$FC, LN$FC$DO ... -> type or None"""
    parts = item.split("$")
    for k in range(1, len(parts) + 1):
        pref = "$".join(parts[:k])
        key = (domain, pref)
        if key not in om["types"]:
            try:
                om["types"][key] = client.type_of(domain, pref)
            except mc.MmsError:
                om["types"][key] = None
                if not client.connected:
                    return None
        t = om["types"][key]
        if t is None:
            continue
        return t if k == len(parts) else find_type(t, "_$" + "$".join(parts[k:]))
    return None


def read_item(client, om, domain, item):
    """-> list of typed rows (path, type, text, raw) of one variable; what does not fit into one PDU (big LN,
    big FC) is read level by level (FC, DO) using the variable names"""
    typ = item_type(client, om, domain, item)
    err = None
    try:
        res = client.read(domain, [item])
    except mc.MmsError as ex:
        res, err = None, ex
    if res and res[0][0]:
        ok, b, t, e = res[0]
        rows = []
        mc.typed_rows(b, t, e, typ, item.replace("$", "."), rows)
        return rows
    kids = [n for n in om["names"].get(domain, []) if n.startswith(item + "$") and n.count("$") == item.count("$") + 1]
    if not kids and typ and typ.get("kind") == "struct":
        kids = [item + "$" + c for c, _ in typ["comps"]]
    if kids and client.connected:
        rows = [(item.replace("$", "."), "Structure", "", None)]
        for k in kids:
            rows += read_item(client, om, domain, k)
        return rows
    if err is not None:
        raise err
    return [(item.replace("$", "."), "error", res[0][1] if res else "no result", None)]


def read_many(client, om, domain, items, chunk=40):
    """monitor: several variables of one LD -> {item: rows}"""
    out = {}
    for i in range(0, len(items), chunk):
        part = items[i:i + chunk]
        try:
            res = client.read(domain, part)
        except mc.MmsError as ex:
            for it in part:
                out[it] = [(it, "error", str(ex), None)]
            continue
        for it, (ok, b, t, e) in zip(part, res):
            if not ok:
                out[it] = [(it, "error", b, None)]
                continue
            typ = item_type(client, om, domain, it)
            rows = []
            mc.typed_rows(b, t, e, typ, it.replace("$", "."), rows)
            out[it] = rows
    return out


def read_datasets(client, om, progress=None):
    for ld, names in om["dsnames"].items():
        for n in names:
            ref = "%s/%s" % (ld, n)
            if progress:
                progress("reading data set %s" % ref)
            try:
                om["datasets"][ref] = client.dataset(ld, n)
            except mc.MmsError as ex:
                om["datasets"][ref] = "error: %s" % ex
    om["ds_read"] = True
    return om


def learned_names(om):
    """data set members -> MmsDecoder.learned format {dsref: {index: 61850 name}}"""
    return {ref: {i: mms.ref61850(x) for i, x in enumerate(mem)} for ref, mem in om["datasets"].items()
            if isinstance(mem, list)}


def read_cb(client, om, domain, item):
    rows = read_item(client, om, domain, item)
    lm = leaf_map(rows, item.replace("$", "."))
    kind = item.split("$")[1]

    def txt(k, default=""):
        return lm[k][1] if k in lm else default

    def raw(k):
        return lm[k][2] if k in lm else None

    base = dict(ref="%s/%s" % (domain, item), domain=domain, item=item, ln=ln_of(item), name=item.split("$")[2],
                datset=txt("DatSet"), confrev=txt("ConfRev"), error="")
    if rows and rows[0][1] == "error":
        base["error"] = rows[0][2]
    if kind == "GO":
        base.update(kind="GoCB", goena=txt("GoEna"), goid=txt("GoID"), ndscom=txt("NdsCom"),
                    mac=":".join("%02X" % x for x in (raw("DstAddress.Addr") or b"")),
                    appid=txt("DstAddress.APPID"), vlan=txt("DstAddress.VLAN-ID"),
                    prio=txt("DstAddress.VLAN-PRIORITY"))
        return base
    base.update(kind="BRCB" if kind == "BR" else "URCB", rptid=txt("RptID"), rptena=txt("RptEna"),
                resv=txt("Resv") if "Resv" in lm else txt("ResvTms"), owner=owner_text(raw("Owner")),
                trgops=bit_names(raw("TrgOps"), TRG_BITS), optflds=bit_names(raw("OptFlds"), OPT_BITS),
                intgpd=txt("IntgPd"), buftm=txt("BufTm"), sqnum=txt("SqNum"), entryid=txt("EntryID"))
    return base


def in_use(cb, my_ip=""):
    """who uses the control block - plain words (my_ip: Owner = this PC)"""
    if cb.get("error"):
        return "read error: " + cb["error"]
    if cb["kind"] == "GoCB":
        return "publishing" if cb.get("goena") == "TRUE" else "disabled"
    ena = cb.get("rptena") == "TRUE"
    resv = cb.get("resv") not in ("", "FALSE", "0")
    who = (" by " + cb["owner"]) if cb.get("owner") else ""
    if my_ip and cb.get("owner") == my_ip:
        who = " by this PC (%s)" % my_ip
    if ena:
        return "IN USE - enabled" + who
    if resv:
        return "reserved" + who
    return "free"


def cid_cb_names(cid):
    """control blocks of the CID -> [(domain, item)] (instance names with and without index)"""
    out = []
    if not cid:
        return out
    for c in cid.get("rcbs", []):
        fc = "BR" if c["kind"] == "BRCB" else "RP"
        names = [c["name"]] + ["%s%02d" % (c["name"], i + 1) for i in range(max(1, int(c.get("max") or 1)))]
        for n in names:
            out.append((c["domain"], "%s$%s$%s" % (c["ln"], fc, n)))
    for c in cid.get("gocbs", []):
        out.append((c["domain"], "%s$GO$%s" % (c["ln"], c["name"])))
    return out


def read_cbs(client, om, progress=None, candidates=None):
    """all URCB / BRCB / GoCB: from the variable names, else from the type of LLN0, else the names of the CID
    (candidates) are tried directly. om["cb_log"]: what was done (for the Log)"""
    om["rcbs"], om["gocbs"] = [], []
    log = om["cb_log"] = []
    for ld in list(om["names"]):                      # LN-only name list: control blocks from the type of LLN0
        if not any(is_cb(n) for n in om["names"][ld]) and "LLN0" in om["lds"].get(ld, []):
            if progress:
                progress("reading the type of %s/LLN0" % ld)
            try:
                new = expand_ln(client, om, ld, "LLN0")
                n = sum(1 for x in new if is_cb(x))
                if n:
                    log.append("%s: %d control blocks found in the type of LLN0" % (ld, n))
            except mc.MmsError as ex:
                log.append("%s: type of LLN0 not readable (%s)" % (ld, ex))
    found = {(ld, it) for ld, names in om["names"].items() for it in names if is_cb(it)}
    if candidates:                                    # names from the CID, tried directly
        tried = 0
        for ld, it in candidates:
            if (ld, it) in found or ld not in om["lds"]:
                continue
            tried += 1
            try:
                res = client.read(ld, [it + "$" + ("GoEna" if "$GO$" in it else "RptID")])
            except mc.MmsError:
                continue
            if res and res[0][0]:
                found.add((ld, it))
                om["names"].setdefault(ld, []).append(it)
        if tried:
            log.append("names of the CID tried: %d, found in the IED: %d" % (
                tried, sum(1 for c in candidates if c in found)))
    for ld, it in sorted(found):
        if progress:
            progress("reading %s/%s" % (ld, it))
        try:
            cb = read_cb(client, om, ld, it)
        except mc.MmsError as ex:
            kind = it.split("$")[1]
            cb = dict(ref="%s/%s" % (ld, it), domain=ld, item=it, ln=ln_of(it), name=it.split("$")[2],
                      kind="GoCB" if kind == "GO" else ("BRCB" if kind == "BR" else "URCB"), error=str(ex),
                      datset="", confrev="")
        (om["gocbs"] if cb["kind"] == "GoCB" else om["rcbs"]).append(cb)
    if not found:
        log.append("no control block found - load the CID of the IED (Load CID / SCD...) and read again")
    om["cbs_read"] = True
    return om


# ---------------------------------------------------------------- CID model
def list_ieds(path):
    root = ET.parse(path).getroot()
    q = gp._q(root)
    return [i.get("name", "") for i in root.findall(q("IED"))]


def cid_model(path, ied_name=None):
    root = ET.parse(path).getroot()
    q = gp._q(root)
    ieds = root.findall(q("IED"))
    if not ieds:
        raise ValueError("no IED in the file")
    ied = next((i for i in ieds if i.get("name") == ied_name), None) if ied_name else ieds[0]
    if ied is None:
        raise ValueError("IED %s is not in the file" % ied_name)
    iname = ied.get("name", "")
    ips, gse = [], {}
    com = root.find(q("Communication"))
    if com is not None:
        for cap in com.iter(q("ConnectedAP")):
            if cap.get("iedName") != iname:
                continue
            for a in cap.findall(q("Address")):
                for p in a.findall(q("P")):
                    if p.get("type") == "IP" and (p.text or "").strip():
                        ips.append(p.text.strip())
            for g in cap.findall(q("GSE")):
                P = {p.get("type"): (p.text or "").strip() for p in g.iter(q("P"))}
                gse[(g.get("ldInst"), g.get("cbName"))] = dict(
                    mac=(P.get("MAC-Address") or "").replace("-", ":").upper(),
                    appid=int(P["APPID"], 16) if P.get("APPID") else None,
                    vlan=int(P["VLAN-ID"], 16) if P.get("VLAN-ID") else None)
    lds, datasets, rcbs, gocbs = {}, {}, [], []
    for ld in ied.iter(q("LDevice")):
        ldi = ld.get("inst", "")
        dom = iname + ldi
        lns = []
        for ln in ld:
            tag = ln.tag.split("}")[-1]
            if tag not in ("LN0", "LN"):
                continue
            lnn = "LLN0" if tag == "LN0" else (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or "")
            lns.append(lnn)
            for ds in ln.findall(q("DataSet")):
                mem = []
                for f in ds.findall(q("FCDA")):
                    fl = (f.get("prefix", "") or "") + f.get("lnClass", "") + (f.get("lnInst", "") or "")
                    if f.get("lnClass") == "LLN0":
                        fl = "LLN0"
                    item = fl + "$" + (f.get("fc") or "")
                    if f.get("doName"):
                        item += "$" + f.get("doName").replace(".", "$")
                    if f.get("daName"):
                        item += "$" + f.get("daName").replace(".", "$")
                    mem.append("%s%s/%s" % (iname, f.get("ldInst", ldi), item))
                datasets["%s/%s$%s" % (dom, lnn, ds.get("name"))] = mem
            for rc in ln.findall(q("ReportControl")):
                tr = rc.find(q("TrgOps"))
                of = rc.find(q("OptFields"))
                re_ = rc.find(q("RptEnabled"))
                buffered = rc.get("buffered") == "true"
                rcbs.append(dict(
                    name=rc.get("name", ""), domain=dom, ln=lnn, kind="BRCB" if buffered else "URCB",
                    rptid=rc.get("rptID") or "", datset=("%s/%s$%s" % (dom, lnn, rc.get("datSet"))) if rc.get("datSet") else "",
                    confrev=rc.get("confRev") or "", intgpd=rc.get("intgPd") or "",
                    trgops=[k for k in TRG_BITS if tr is not None and tr.get(k, "true" if k == "gi" else "false") == "true"],
                    optflds=[v for k, v in SCL_OPT.items() if of is not None and of.get(k) == "true"],
                    max=int(re_.get("max") or 1) if re_ is not None else 1))
            for gc in ln.findall(q("GSEControl")):
                a = gse.get((ldi, gc.get("name"))) or {}
                gocbs.append(dict(name=gc.get("name", ""), domain=dom, ln=lnn, kind="GoCB",
                                  goid=gc.get("appID") or "",
                                  datset=("%s/%s$%s" % (dom, lnn, gc.get("datSet"))) if gc.get("datSet") else "",
                                  confrev=gc.get("confRev") or "", mac=a.get("mac", ""), appid=a.get("appid"),
                                  vlan=a.get("vlan")))
        lds[dom] = sorted(lns)
    return dict(ied=iname, file=os.path.basename(path), path=path, ips=ips, lds=lds, datasets=datasets,
                rcbs=rcbs, gocbs=gocbs)


# ---------------------------------------------------------------- compare
def _match_cb(cid_cb, online, kind):
    """online CB instances of a CID control block: same name, or name + 2 digits (indexed RCB)"""
    out = []
    for o in online:
        if o["domain"] != cid_cb["domain"] or o.get("ln") != cid_cb["ln"]:
            continue
        if kind != "GoCB" and o["kind"] != cid_cb["kind"]:
            continue
        n = o["name"]
        if n == cid_cb["name"] or (n.startswith(cid_cb["name"]) and n[len(cid_cb["name"]):].isdigit()):
            out.append(o)
    return out


def _int(s):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def compare(cid, om):
    """-> [(section, level, text)]  level ok / bad / info"""
    F = []
    # ---- logical devices / logical nodes
    for dom in sorted(set(cid["lds"]) | set(om["lds"])):
        if dom not in om["lds"]:
            F.append(("Logical devices", "bad", "%s: in the CID, not in the IED" % dom))
            continue
        if dom not in cid["lds"]:
            F.append(("Logical devices", "bad", "%s: in the IED, not in the CID" % dom))
            continue
        a, b = set(cid["lds"][dom]), set(om["lds"][dom])
        if a == b:
            F.append(("Logical devices", "ok", "%s: %d logical nodes - same" % (dom, len(a))))
        for x in sorted(a - b):
            F.append(("Logical devices", "bad", "%s/%s: in the CID, not in the IED" % (dom, x)))
        for x in sorted(b - a):
            F.append(("Logical devices", "bad", "%s/%s: in the IED, not in the CID" % (dom, x)))
    # ---- data sets
    online_ds = {}
    for ld, names in om["dsnames"].items():
        for n in names:
            online_ds["%s/%s" % (ld, n)] = om["datasets"].get("%s/%s" % (ld, n))
    for ref in sorted(set(cid["datasets"]) | set(online_ds)):
        if ref not in online_ds:
            F.append(("Data sets", "bad", "%s: in the CID, not in the IED" % ref))
            continue
        if ref not in cid["datasets"]:
            F.append(("Data sets", "info", "%s: in the IED, not in the CID (configured in the IED or dynamic)" % ref))
            continue
        a, b = cid["datasets"][ref], online_ds[ref]
        if b is None:
            F.append(("Data sets", "info", "%s: members not read" % ref))
        elif isinstance(b, str):
            F.append(("Data sets", "bad", "%s: %s" % (ref, b)))
        elif a == b:
            F.append(("Data sets", "ok", "%s: %d members - same" % (ref, len(a))))
        else:
            F.append(("Data sets", "bad", "%s: members differ - CID %d, IED %d" % (ref, len(a), len(b))))
            for i in range(max(len(a), len(b))):
                x = a[i] if i < len(a) else "-"
                y = b[i] if i < len(b) else "-"
                if x != y:
                    F.append(("Data sets", "bad", "    #%d  CID %s   IED %s" % (i + 1, mms.ref61850(x), mms.ref61850(y))))
    # ---- control blocks
    if not om.get("cbs_read"):
        F.append(("Report control blocks", "info", "control blocks not read"))
        return F
    seen = set()
    for c in cid["rcbs"]:
        inst = _match_cb(c, om["rcbs"], c["kind"])
        nm = "%s/%s$%s$%s" % (c["domain"], c["ln"], "BR" if c["kind"] == "BRCB" else "RP", c["name"])
        if not inst:
            F.append(("Report control blocks", "bad", "%s: in the CID, not in the IED" % nm))
            continue
        bad = []
        for o in inst:
            seen.add(o["ref"])
            if o.get("error"):
                bad.append("%s: read error %s" % (o["name"], o["error"]))
                continue
            if c["rptid"] and o.get("rptid") not in (c["rptid"], "") and not o.get("rptid", "").startswith(c["rptid"]):
                bad.append("%s: RptID IED %s, CID %s" % (o["name"], o.get("rptid"), c["rptid"]))
            if c["datset"] and o.get("datset") != c["datset"]:
                bad.append("%s: DatSet IED %s, CID %s" % (o["name"], o.get("datset") or "(none)", c["datset"]))
            if c["datset"] and _int(c["confrev"]) is not None and _int(o.get("confrev")) != _int(c["confrev"]):
                bad.append("%s: ConfRev IED %s, CID %s" % (o["name"], o.get("confrev"), c["confrev"]))
            if c["datset"] and set(o.get("trgops") or []) != set(c["trgops"]):
                bad.append("%s: TrgOps IED %s, CID %s" % (o["name"], ",".join(o.get("trgops") or []) or "-",
                                                         ",".join(c["trgops"]) or "-"))
            if c["datset"] and "period" in c["trgops"] and _int(c["intgpd"]) and _int(o.get("intgpd")) != _int(c["intgpd"]):
                bad.append("%s: IntgPd IED %s ms, CID %s ms" % (o["name"], o.get("intgpd"), c["intgpd"]))
        if bad:
            for x in bad:
                F.append(("Report control blocks", "bad", "%s/%s$%s" % (c["domain"], c["ln"], x)))
        else:
            extra = "" if c["datset"] else " (no data set in the CID - data set of the IED: %s)" % (
                ", ".join(sorted({o.get("datset") or "none" for o in inst})))
            F.append(("Report control blocks", "ok", "%s: %d instance(s) - same%s" % (nm, len(inst), extra)))
    for o in om["rcbs"]:
        if o["ref"] not in seen:
            F.append(("Report control blocks", "bad", "%s: in the IED, not in the CID" % o["ref"]))
    seen = set()
    for c in cid["gocbs"]:
        inst = _match_cb(c, om["gocbs"], "GoCB")
        nm = "%s/%s$GO$%s" % (c["domain"], c["ln"], c["name"])
        if not inst:
            F.append(("GOOSE control blocks", "bad", "%s: in the CID, not in the IED" % nm))
            continue
        o = inst[0]
        seen.add(o["ref"])
        bad = []
        if o.get("error"):
            bad.append("read error %s" % o["error"])
        else:
            if c["goid"] and o.get("goid") != c["goid"]:
                bad.append("GoID IED %s, CID %s" % (o.get("goid"), c["goid"]))
            if c["datset"] and o.get("datset") != c["datset"]:
                bad.append("DatSet IED %s, CID %s" % (o.get("datset") or "(none)", c["datset"]))
            if _int(c["confrev"]) is not None and _int(o.get("confrev")) != _int(c["confrev"]):
                bad.append("ConfRev IED %s, CID %s" % (o.get("confrev"), c["confrev"]))
            if c["mac"] and o.get("mac") and o["mac"] != c["mac"]:
                bad.append("MAC IED %s, CID %s" % (o["mac"], c["mac"]))
            if c["appid"] is not None and _int(o.get("appid")) is not None and _int(o["appid"]) != c["appid"]:
                bad.append("APPID IED 0x%04X, CID 0x%04X" % (_int(o["appid"]), c["appid"]))
            if c["vlan"] is not None and _int(o.get("vlan")) is not None and _int(o["vlan"]) != c["vlan"]:
                bad.append("VLAN IED %s, CID %s" % (o["vlan"], c["vlan"]))
        if bad:
            for x in bad:
                F.append(("GOOSE control blocks", "bad", "%s: %s" % (nm, x)))
        else:
            F.append(("GOOSE control blocks", "ok", "%s: same (%s)" % (nm, "publishing" if o.get("goena") == "TRUE" else "disabled")))
    for o in om["gocbs"]:
        if o["ref"] not in seen:
            F.append(("GOOSE control blocks", "bad", "%s: in the IED, not in the CID" % o["ref"]))
    return F


# ---------------------------------------------------------------- own reports (v0.6.3)
def mine(cb, my_ip):
    """reserved / enabled by this PC (Owner = own IP, e.g. left from an earlier connection)"""
    return bool(my_ip) and cb.get("owner") == my_ip


def can_enable(cb, my_ip=""):
    """only report control blocks with a data set and not used by another client"""
    if cb.get("kind") not in ("URCB", "BRCB") or cb.get("error"):
        return False, "not a report control block"
    if not cb.get("datset"):
        return False, "no data set"
    st = in_use(cb, my_ip)
    if st != "free" and not mine(cb, my_ip):
        return False, st
    return True, ""


def enable_rcb(client, cb):
    """Resv (URCB) -> RptEna -> GI; DatSet / TrgOps / OptFlds / IntgPd are not changed. -> (ok, text)"""
    d, i = cb["domain"], cb["item"]
    done = []
    if cb["kind"] == "URCB":
        err = client.write(d, i + "$Resv", b"\x83\x01\xff")
        if err and err != "object-non-existent":
            return False, "Resv refused: %s" % err
        done.append("Resv")
    err = client.write(d, i + "$RptEna", b"\x83\x01\xff")
    if err:
        if "Resv" in done:
            client.write(d, i + "$Resv", b"\x83\x01\x00")
        hint = ""
        if err == "temporarily-unavailable":
            hint = (" - the RCB is reserved by another connection; if it is this PC from an earlier connection: "
                    "Disconnect / Connect, or wait until the IED releases it (reservation time ResvTms)")
        return False, "RptEna refused: %s%s" % (err, hint)
    done.append("RptEna")
    if "gi" in (cb.get("trgops") or []):
        err = client.write(d, i + "$GI", b"\x83\x01\xff")
        done.append("GI" if not err else "GI refused: %s" % err)
    return True, "enabled (%s)" % ", ".join(done)


def disable_rcb(client, cb):
    """RptEna FALSE, reservation off (Resv FALSE / ResvTms 0) -> (ok, text)"""
    d, i = cb["domain"], cb["item"]
    err = client.write(d, i + "$RptEna", b"\x83\x01\x00")
    if cb["kind"] == "URCB":
        e2 = client.write(d, i + "$Resv", b"\x83\x01\x00")
    else:
        e2 = client.write(d, i + "$ResvTms", b"\x85\x01\x00")
        if e2 == "object-non-existent":
            e2 = None
    if err is None and e2 is None:
        return True, "disabled, reservation released"
    if err is None:
        return True, "disabled (reservation: %s)" % e2
    return False, "RptEna FALSE refused: %s%s" % (err, "" if e2 is None else ", reservation: %s" % e2)


# ---------------------------------------------------------------- Excel export (v0.6.4)
def export_sheets(client, om, cid=None, cid_candidates=None, progress=None, info=None):
    """IED read online -> sheets for xlsx_lite.write: Info, Model (all attributes with type and value),
    Data sets, Control blocks, Compare with CID"""
    if not om.get("ds_read"):
        read_datasets(client, om, progress)
    if not om.get("cbs_read"):
        read_cbs(client, om, progress, cid_candidates)
    model = []
    for ld in sorted(om["lds"]):
        for ln in om["lds"][ld]:
            if progress:
                progress("reading %s/%s" % (ld, ln))
            try:
                rows = read_item(client, om, ld, ln)
            except mc.MmsError as ex:
                model.append([ld, ln, "", "", "error", str(ex), ""])
                continue
            for path, typ, text, raw in rows:
                parts = path.split(".")
                if typ in ("Structure", "Array") and len(parts) > 3:
                    continue                           # leaves only (and LN / FC / DO lines)
                fc = parts[1] if len(parts) > 1 else ""
                rest = ".".join(parts[2:])
                ref = "%s/%s%s%s" % (ld, parts[0], ("." + rest) if rest else "", (" [%s]" % fc) if fc else "")
                model.append([ld, parts[0], fc, rest, "" if typ in ("Structure", "Array") else typ,
                              text if typ not in ("Structure", "Array") else "", ref])
    dsr = []
    for ref, mem in sorted(om["datasets"].items()):
        if isinstance(mem, str):
            dsr.append([ref, "", mem, "", ""])
            continue
        for i, m in enumerate(mem):
            dom, item = m.split("/", 1) if "/" in m else ("", m)
            p = item.split("$")
            dsr.append([ref, i + 1, mms.ref61850(m), m, p[1] if len(p) > 1 else ""])
    cbr = []
    for c in om["rcbs"]:
        cbr.append([c["ref"], c["kind"], in_use(c, getattr(client, "local_ip", "")), c.get("rptid", ""),
                    c.get("datset", ""), c.get("confrev", ""), ", ".join(c.get("trgops") or []),
                    ", ".join(c.get("optflds") or []), c.get("intgpd", ""), c.get("buftm", ""), c.get("owner", ""),
                    "", "", "", c.get("error", "")])
    for c in om["gocbs"]:
        cbr.append([c["ref"], c["kind"], in_use(c), c.get("goid", ""), c.get("datset", ""), c.get("confrev", ""),
                    "", "", "", "", "", c.get("mac", ""), c.get("appid", ""), c.get("vlan", ""), c.get("error", "")])
    sheets = []
    inf = [["IED (online)", client.peer], ["Identity", " / ".join(om.get("ident") or [])],
           ["Logical devices", len(om["lds"])], ["Variables (Model sheet rows)", len(model)],
           ["Data sets", len(om["datasets"])], ["Report control blocks", len(om["rcbs"])],
           ["GOOSE control blocks", len(om["gocbs"])]]
    if cid:
        inf.append(["CID", "%s (IED %s)" % (cid["file"], cid["ied"])])
    inf += [[k, v] for k, v in (info or [])]
    sheets.append(("Info", ["Item", "Value"], inf, [30, 90]))
    sheets.append(("Model", ["LD", "LN", "FC", "DO / DA", "Type", "Value", "Reference (61850)"], model,
                   [22, 18, 5, 40, 12, 40, 70]))
    sheets.append(("Data sets", ["Data set", "#", "Member (61850)", "Member (MMS)", "FC"], dsr, [45, 5, 60, 60, 5]))
    sheets.append(("Control blocks", ["Control block", "Type", "State", "RptID / GoID", "DatSet", "ConfRev", "TrgOps",
                                      "OptFlds", "IntgPd ms", "BufTm ms", "Owner", "MAC", "APPID", "VLAN", "Error"],
                   cbr, None))
    if cid:
        F = compare(cid, om)
        sheets.append(("Compare with CID", ["Section", "Result", "Finding"],
                       [[s, {"ok": "OK", "bad": "DIFFERENT", "info": "info"}.get(l, l), t] for s, l, t in F],
                       [25, 12, 120]))
    return sheets
