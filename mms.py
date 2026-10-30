# -*- coding: utf-8 -*-
"""
mms.py - passive decoding of IEC 61850 MMS (TCP port 102) for the tab MMS / Passive.

The analyzer only listens: SCADA <-> IED traffic is visible with a mirror (SPAN) port, a TAP /
hub or a capture file. Nothing is sent.

Stack: Ethernet / IPv4 / TCP (reassembly per direction) -> TPKT (RFC 1006) -> COTP (ISO 8073,
CR / CC / DT / DR, DT segments joined until EOT) -> Session (ISO 8327: CN, AC, DT, FN, DN, AB ...)
-> Presentation (ISO 8823) -> ACSE (AARQ / AARE / RLRQ / RLRE) -> MMS (ISO 9506).

MMS PDUs: Initiate, Conclude, Confirmed request / response / error (Read, Write, GetNameList,
GetVariableAccessAttributes, GetNamedVariableListAttributes, Identify, File...), Reject,
Unconfirmed InformationReport:
  - IEC 61850-8-1 report (variableListName "RPT"): RptID, OptFlds, SeqNum, TimeOfEntry, DatSet,
    BufOvfl, EntryID, ConfRev, SubSeqNum, MoreSegmentsFollow, Inclusion, data references,
    values, reason codes (data change, quality change, data update, integrity, general
    interrogation, application trigger)
  - LastApplError (negative control response: AddCause)
Signal names of report entries: data reference in the report, else the data set of the SCL
(DatSet of the report or the ReportControl with this RptID).

MmsDecoder.feed(frame, ts, net) -> list of message dicts (kind 'MMS') like the GOOSE messages:
  src / dst  'IP:port', ip_src / ip_dst, server (IP of the port 102 side), dir ('C->S' / 'S->C'),
  mtype (text), invoke, info, reason, header [(field, value)], tree [(key, parent, label, value,
  type, signal)], ref (RptID / object name for the filter)
"""
import datetime

import sniff_core as sc

MMS_PORT = 102

CONF_SERVICES = {0: "Status", 1: "GetNameList", 2: "Identify", 3: "Rename", 4: "Read", 5: "Write",
                 6: "GetVariableAccessAttributes", 7: "DefineNamedVariable", 11: "DefineNamedVariableList",
                 12: "GetNamedVariableListAttributes", 13: "DeleteNamedVariableList", 46: "ObtainFile",
                 72: "FileOpen", 73: "FileRead", 74: "FileClose", 75: "FileRename", 76: "FileDelete",
                 77: "FileDirectory"}
REASONS = ["reserved", "data change", "quality change", "data update", "integrity (period)",
           "general interrogation", "application trigger"]
OPTFLDS = ["reserved", "sequence-number", "report-time-stamp", "reason-for-inclusion", "data-set-name",
           "data-reference", "buffer-overflow", "entryID", "conf-revision", "segmentation"]
DATA_ACCESS_ERROR = {0: "object-invalidated", 1: "hardware-fault", 2: "temporarily-unavailable",
                     3: "object-access-denied", 4: "object-undefined", 5: "invalid-address",
                     6: "type-unsupported", 7: "type-inconsistent", 8: "object-attribute-inconsistent",
                     9: "object-access-unsupported", 10: "object-non-existent", 11: "object-value-invalid"}
ADD_CAUSE = {0: "Unknown", 1: "Not-supported", 2: "Blocked-by-switching-hierarchy", 3: "Select-failed",
             4: "Invalid-position", 5: "Position-reached", 6: "Parameter-change-in-execution",
             7: "Step-limit", 8: "Blocked-by-Mode", 9: "Blocked-by-process", 10: "Blocked-by-interlocking",
             11: "Blocked-by-synchrocheck", 12: "Command-already-in-execution", 13: "Blocked-by-health",
             14: "1-of-n-control", 15: "Abortion-by-cancel", 16: "Time-limit-over",
             17: "Abortion-by-trip", 18: "Object-not-selected", 19: "Object-already-selected",
             20: "No-access-authority", 21: "Ended-with-overshoot", 22: "Abortion-due-to-deviation",
             23: "Abortion-by-communication-loss", 24: "Blocked-by-command", 25: "None",
             26: "Inconsistent-parameters", 27: "Locked-by-other-client"}
OBJ_CLASS = {0: "namedVariable", 1: "scatteredAccess", 2: "namedVariableList", 3: "namedType",
             4: "semaphore", 5: "eventCondition", 6: "eventAction", 7: "eventEnrollment", 8: "journal",
             9: "domain", 10: "programInvocation", 11: "operatorStation"}
SESSION = {0x01: "Data transfer", 0x0D: "Session connect (CN)", 0x0E: "Session accept (AC)",
           0x0C: "Session refuse (RF)", 0x09: "Session finish (FN)", 0x0A: "Session disconnect (DN)",
           0x19: "Session abort (AB)", 0x1A: "Session abort accept (AA)", 0x08: "Session not finished (NF)"}


# ---------------------------------------------------------------- BER (multi-byte tags)
def ber(b, p, end):
    """yields (cls, constructed, number, value start, value end, tag start)"""
    while p < end:
        t0 = p
        first = b[p]
        cls, cons, num = first >> 6, bool(first & 0x20), first & 0x1F
        p += 1
        if num == 0x1F:
            num = 0
            while p < end:
                x = b[p]
                p += 1
                num = (num << 7) | (x & 0x7F)
                if not x & 0x80:
                    break
        if p >= end:
            raise ValueError("BER: no length")
        ln, v = sc.ber_len(b, p)
        e = v + ln
        if e > end:
            raise ValueError("BER overrun")
        yield cls, cons, num, v, e, t0
        p = e


def kids(b, p, end):
    return list(ber(b, p, end))


def vis(b):
    return b.decode("latin1", "replace")


def obj_name(b, p, end):
    """MMS ObjectName -> text: vmd-specific / domain-specific (domain/item) / aa-specific"""
    for cls, cons, num, v, e, _ in ber(b, p, end):
        if num == 0:
            return vis(b[v:e])
        if num == 1:
            ids = [vis(b[v2:e2]) for _, _, _, v2, e2, _ in ber(b, v, e)]
            return "/".join(ids)
        if num == 2:
            return "@" + vis(b[v:e])
    return "?"


def ref61850(name):
    """'IEDLD/LLN0$ST$Mod$stVal' -> 'IEDLD/LLN0.Mod.stVal [ST]'"""
    if "/" not in name or "$" not in name:
        return name
    dom, item = name.split("/", 1)
    parts = item.split("$")
    if len(parts) >= 2 and len(parts[1]) == 2 and parts[1].isupper():
        return "%s/%s [%s]" % (dom, ".".join([parts[0]] + parts[2:]), parts[1])
    return "%s/%s" % (dom, ".".join(parts))


def binary_time(v):
    """MMS TimeOfDay / BinaryTime (6 bytes: ms of the day + days since 1984-01-01)"""
    if len(v) == 6:
        ms = int.from_bytes(v[0:4], "big")
        days = int.from_bytes(v[4:6], "big")
        t = datetime.datetime(1984, 1, 1) + datetime.timedelta(days=days, milliseconds=ms)
        return t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    if len(v) == 4:
        ms = int.from_bytes(v, "big")
        return str(datetime.timedelta(milliseconds=ms))
    return v.hex()


def binary_time_epoch(v):
    """BinaryTime (6 bytes) -> seconds since 1970 (UTC) or None"""
    if len(v) != 6:
        return None
    ms = int.from_bytes(v[0:4], "big")
    days = int.from_bytes(v[4:6], "big")
    return 441763200.0 + days * 86400 + ms / 1000.0          # 1984-01-01 = 441763200


def entry_info(b, t, e):
    """report / data value -> (top type, number of members, state text (Boolean / Dbpos), value text)"""
    out = []
    sc.mms_data(b, t, e, out)
    if not out:
        return "", 0, None, ""
    top = out[0][1]
    nmem = sum(1 for x in out if x[0].count(".") == 1)
    state = next((x[2] for x in out if x[1] in ("Boolean", "Dbpos")), None)
    val = next((x[2] for x in out if x[1] not in ("Structure", "Array", "Quality", "Timestamp")), "")
    if not val:
        val = out[0][2]
    return top, nmem, state, val


def bits_of(raw):
    bits, n = sc.bitstring(raw)
    return bits


# ---------------------------------------------------------------- data values -> tree rows
class Tree:
    def __init__(self):
        self.rows = []
        self.n = 0

    def add(self, parent, label, value="", typ="", sig=""):
        self.n += 1
        k = "n%d" % self.n
        self.rows.append((k, parent, label, value, typ, sig))
        return k


def data_rows(tree, parent, b, v, e, label, sig=""):
    """one MMS Data element (TLV in b[v:e] incl. tag) -> rows; returns (short value text, type)"""
    out = []
    sc.mms_data(b, v, e, out)
    if not out:
        return "", ""
    keys = {}
    first_txt = first_typ = ""
    for i, (nm, typ, val, raw) in enumerate(out):
        par = keys.get(nm.rsplit(".", 1)[0], parent) if "." in nm else parent
        if typ == "BinaryTime":
            val = binary_time(raw)
        lab = label if "." not in nm else "%s %s" % (typ, nm.rsplit(".", 1)[-1])
        k = tree.add(par, lab, val, typ, sig if "." not in nm else "")
        keys[nm] = k
        if i == 0:
            first_txt, first_typ = val, typ
    return first_txt, first_typ


# ---------------------------------------------------------------- MMS PDU
def parse_pdu(b, names=None, pending=None, conn=None, learned=None):
    """MMS PDU (bytes) -> dict(mtype, invoke, info, reason, tree rows, header extra, ref)"""
    r = dict(mtype="MMS", invoke=None, info="", reason="", ref="", hdr=[], tree=Tree())
    T = r["tree"]
    if not b:
        return r
    try:
        items = kids(b, 0, len(b))
    except ValueError as ex:
        r.update(mtype="MMS (bad BER: %s)" % ex)
        return r
    if not items:
        return r
    cls, cons, num, v, e, _ = items[0]
    if num == 0 and cons:
        _confirmed(b, v, e, r, "request", names, pending, conn)
    elif num == 1 and cons:
        _confirmed(b, v, e, r, "response", names, pending, conn)
    elif num == 2:
        r["mtype"] = "Confirmed error"
        for c2, cn2, n2, v2, e2, _ in ber(b, v, e):
            if n2 == 0:
                r["invoke"] = sc.uint(b[v2:e2])
            elif n2 == 2:
                for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                    if n3 == 0:
                        for c4, cn4, n4, v4, e4, _ in ber(b, v3, e3):
                            r["info"] = "error class %d, code %d" % (n4, sc.uint(b[v4:e4]))
        T.add("", "Error", r["info"])
    elif num == 3:
        _unconfirmed(b, v, e, r, names, learned)
    elif num == 4:
        r["mtype"] = "Reject"
        for c2, cn2, n2, v2, e2, _ in ber(b, v, e):
            if n2 == 0:
                r["invoke"] = sc.uint(b[v2:e2])
            else:
                r["info"] = "reject reason [%d] = %d" % (n2, sc.uint(b[v2:e2]))
        T.add("", "Reject", r["info"])
    elif num == 5:
        r.update(mtype="Cancel request", invoke=sc.uint(b[v:e]))
    elif num == 6:
        r.update(mtype="Cancel response", invoke=sc.uint(b[v:e]))
    elif num in (8, 9):
        r["mtype"] = "Initiate " + ("request" if num == 8 else "response")
        lbl = {0: "Local detail (max PDU size)", 1: "Max services outstanding (calling)",
               2: "Max services outstanding (called)", 3: "Data structure nesting level"}
        for c2, cn2, n2, v2, e2, _ in ber(b, v, e):
            if n2 in lbl:
                T.add("", lbl[n2], str(sc.uint(b[v2:e2])))
                if n2 == 0:
                    r["info"] = "max PDU %d bytes" % sc.uint(b[v2:e2])
            elif n2 == 4 and cn2:
                for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                    if n3 == 0:
                        T.add("", "MMS version", str(sc.uint(b[v3:e3])))
                    elif n3 == 1:
                        T.add("", "Parameter CBB", "".join(map(str, bits_of(b[v3:e3]))))
                    elif n3 == 2:
                        bits = bits_of(b[v3:e3])
                        T.add("", "Services supported", "%d of %d" % (sum(bits), len(bits)))
    elif num == 10:
        r["mtype"] = "Initiate error"
    elif num == 11:
        r["mtype"] = "Conclude request"
    elif num == 12:
        r["mtype"] = "Conclude response"
    elif num == 13:
        r["mtype"] = "Conclude error"
    else:
        r["mtype"] = "MMS PDU [%d]" % num
    return r


def _var_spec(b, v, e):
    """VariableAccessSpecification -> list of object names (listOfVariable) or ['list: name']"""
    out = []
    for c2, cn2, n2, v2, e2, _ in ber(b, v, e):
        if n2 == 0:                                       # listOfVariable
            for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):  # SEQUENCE
                for c4, cn4, n4, v4, e4, _ in ber(b, v3, e3):
                    if n4 == 0:                           # variableSpecification name
                        out.append(obj_name(b, v4, e4))
        elif n2 == 1:                                     # variableListName
            out.append("list " + obj_name(b, v2, e2))
    return out


def acsi_name(svc, objs, extra=None):
    """IEC 61850 (ACSI) name of an MMS service, like IEDScout: Read of $CO$..$SBO -> Select,
    Write of $CO$..$SBOw -> SelectWithValue, $Oper -> Operate, $Cancel -> Cancel, RCB -> Get/SetURCBValues ..."""
    first = objs[0] if objs else ""
    item = first.split("/", 1)[-1]
    parts = item.split("$")
    fc = parts[1] if len(parts) > 1 else ""
    if svc == 4:
        if fc == "CO" and parts[-1] == "SBO":
            return "Select"
        if fc in ("RP", "BR"):
            return "Get%sValues" % ("URCB" if fc == "RP" else "BRCB")
        if fc == "GO":
            return "GetGoCBValues"
        if fc == "LG":
            return "GetLCBValues"
        return "GetDataValues"
    if svc == 5:
        if fc == "CO":
            return {"SBOw": "SelectWithValue", "Oper": "Operate", "Cancel": "Cancel"}.get(parts[-1], "Control")
        if fc in ("RP", "BR"):
            return "Set%sValues" % ("URCB" if fc == "RP" else "BRCB")
        if fc == "GO":
            return "SetGoCBValues"
        if fc in ("SP", "SE", "SG"):
            return "SetSettingValues" if fc != "SG" else "SelectActiveSG"
        return "SetDataValues"
    if svc == 1:
        return {9: "GetServerDirectory", 0: "GetLogicalDeviceDirectory", 2: "GetDataSetDirectory (list)"}.get(extra, "GetNameList")
    if svc == 6:
        return "GetDataDirectory"
    if svc == 12:
        return "GetDataSetDirectory"
    if svc == 11:
        return "CreateDataSet"
    if svc == 13:
        return "DeleteDataSet"
    if svc == 2:
        return "GetServerIdentity"
    if svc in (72, 73, 74, 77, 76, 46):
        return {72: "GetFile (open)", 73: "GetFile (read)", 74: "GetFile (close)", 77: "GetFileDirectory",
                76: "DeleteFile", 46: "SetFile"}[svc]
    return None


def _confirmed(b, v, e, r, kind, names, pending, conn):
    T = r["tree"]
    svc = None
    for c2, cn2, n2, v2, e2, _ in ber(b, v, e):
        if svc is None and c2 == 0 and n2 == 2:          # UNIVERSAL INTEGER invokeID
            r["invoke"] = sc.uint(b[v2:e2])
            continue
        if c2 == 2 and svc is None:
            svc = n2
            sname = CONF_SERVICES.get(n2, "service %d" % n2)
            r["mtype"] = "%s %s" % (sname, kind)
            r["svc"] = sname
            key = (conn, r["invoke"])
            if kind == "response" and pending is not None:
                r["acsi"] = pending.pop(("acsi", key), None)
            if n2 == 4:                                   # Read
                if kind == "request":
                    vs = []
                    for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                        if n3 == 1:
                            vs = _var_spec(b, v3, e3)
                        elif n3 == 0:
                            T.add("", "specificationWithResult", "TRUE" if b[v3:e3] != b"\x00" else "FALSE")
                    for nm in vs:
                        T.add("", ref61850(nm), "", "read", "")
                    r["info"] = ", ".join(ref61850(x) for x in vs[:3]) + (" ..." if len(vs) > 3 else "")
                    r["ref"] = vs[0] if vs else ""
                    r["acsi"] = acsi_name(4, vs)
                    if pending is not None:
                        pending[key] = vs
                else:
                    req = (pending or {}).pop(key, None) or []
                    i = 0
                    for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                        if n3 == 1:                       # listOfAccessResult
                            for c4, cn4, n4, v4, e4, t4 in ber(b, v3, e3):
                                lab = ref61850(req[i]) if i < len(req) else "Result %d" % (i + 1)
                                if c4 == 2 and n4 == 0 and not cn4:
                                    T.add("", lab, "FAILURE: " + DATA_ACCESS_ERROR.get(sc.uint(b[v4:e4]), str(sc.uint(b[v4:e4]))))
                                else:
                                    data_rows(T, "", b, t4, e4, lab)
                                i += 1
                    r["info"] = ", ".join(ref61850(x) for x in req[:3]) if req else "%d result(s)" % i
                    r["ref"] = req[0] if req else ""
            elif n2 == 5:                                 # Write
                if kind == "request":
                    vs = []
                    vals = []
                    # VariableAccessSpecification is the first element, listOfData [0] the second
                    els = kids(b, v2, e2)
                    if els:
                        c3, cn3, n3, v3, e3, t3 = els[0]
                        vs = _var_spec(b, t3, e3)
                    if len(els) > 1:
                        c3, cn3, n3, v3, e3, t3 = els[1]
                        for c4, cn4, n4, v4, e4, t4 in ber(b, v3, e3):
                            vals.append((t4, e4))
                    for i, (t4, e4) in enumerate(vals):
                        lab = ref61850(vs[i]) if i < len(vs) else "Value %d" % (i + 1)
                        data_rows(T, "", b, t4, e4, lab)
                    r["info"] = ", ".join(ref61850(x) for x in vs[:3])
                    r["ref"] = vs[0] if vs else ""
                    r["acsi"] = acsi_name(5, vs)
                    if pending is not None:
                        pending[key] = vs
                else:
                    req = (pending or {}).pop(key, None) or []
                    res = []
                    for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                        res.append("success" if n3 == 1 else "FAILURE: " + DATA_ACCESS_ERROR.get(sc.uint(b[v3:e3]), str(sc.uint(b[v3:e3]))))
                    for i, x in enumerate(res):
                        T.add("", ref61850(req[i]) if i < len(req) else "Result %d" % (i + 1), x)
                    r["info"] = ", ".join(res)
            elif n2 == 1:                                 # GetNameList
                if kind == "request":
                    txt = []
                    for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                        if n3 == 0:
                            for c4, cn4, n4, v4, e4, _ in ber(b, v3, e3):
                                txt.append("class " + OBJ_CLASS.get(sc.uint(b[v4:e4]), str(sc.uint(b[v4:e4]))))
                                r["acsi"] = acsi_name(1, [], sc.uint(b[v4:e4]))
                        elif n3 == 1:
                            for c4, cn4, n4, v4, e4, _ in ber(b, v3, e3):
                                txt.append({0: "scope VMD", 1: "domain " + vis(b[v4:e4]), 2: "scope association"}.get(n4, "scope"))
                        elif n3 == 2:
                            txt.append("after " + vis(b[v3:e3]))
                    r["info"] = ", ".join(txt)
                    for t in txt:
                        T.add("", t)
                else:
                    ids, more = [], False
                    for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                        if n3 == 0:
                            ids = [vis(b[v4:e4]) for _, _, _, v4, e4, _ in ber(b, v3, e3)]
                        elif n3 == 1:
                            more = b[v3:e3] != b"\x00"
                    p = T.add("", "Identifiers (%d)%s" % (len(ids), ", more follows" if more else ""))
                    for x in ids:
                        T.add(p, x)
                    r["info"] = "%d name(s)%s" % (len(ids), ", more follows" if more else "")
            elif n2 == 2 and kind == "response":          # Identify
                lab = {0: "Vendor", 1: "Model", 2: "Revision"}
                txt = []
                for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                    T.add("", lab.get(n3, str(n3)), vis(b[v3:e3]))
                    txt.append(vis(b[v3:e3]))
                r["info"] = " / ".join(txt)
            elif n2 in (6, 12, 13, 11):                   # attributes / named variable list
                if kind == "request":
                    nm = obj_name(b, v2, e2) if n2 != 6 else ""
                    if n2 == 6:
                        for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                            if n3 == 0:
                                nm = obj_name(b, v3, e3)
                    r["info"] = ref61850(nm)
                    r["ref"] = nm
                    T.add("", "Object", ref61850(nm))
                    if n2 == 12 and pending is not None:
                        pending[key] = [nm]
                else:
                    if n2 == 12:
                        vs = []
                        for c3, cn3, n3, v3, e3, _ in ber(b, v2, e2):
                            if n3 == 1:
                                for c4, cn4, n4, v4, e4, _ in ber(b, v3, e3):
                                    for c5, cn5, n5, v5, e5, _ in ber(b, v4, e4):
                                        if n5 == 0:
                                            vs.append(obj_name(b, v5, e5))
                        req = (pending or {}).pop(key, None) or []
                        p = T.add("", "Data set members (%d)" % len(vs))
                        for x in vs:
                            T.add(p, ref61850(x))
                        r["info"] = "%s%d member(s)" % ((ref61850(req[0]) + ": ") if req else "", len(vs))
                        if req:                           # whole data set learned
                            r["learn"] = (req[0], {i: ref61850(x) for i, x in enumerate(vs)}, None)
                    else:
                        r["info"] = "%d bytes" % (e2 - v2)
            else:
                r["info"] = "%d bytes" % (e2 - v2)
    if svc is None and r["mtype"] == "MMS":
        r["mtype"] = "Confirmed " + kind
    if svc is not None and kind == "request" and not r.get("acsi"):
        r["acsi"] = acsi_name(svc, [])
    if svc is not None and kind == "request" and pending is not None and r.get("acsi"):
        pending[("acsi", (conn, r["invoke"]))] = r["acsi"]
    if r.get("acsi"):
        r["mtype"] = "%s %s" % (r["acsi"], kind)


def _unconfirmed(b, v, e, r, names, learned=None):
    T = r["tree"]
    for c2, cn2, n2, v2, e2, _ in ber(b, v, e):
        if n2 != 0:                                       # only informationReport
            r["mtype"] = "Unconfirmed [%d]" % n2
            continue
        els = kids(b, v2, e2)
        vnames = []
        if els:
            c3, cn3, n3, v3, e3, t3 = els[0]
            if n3 == 1:
                vnames = [obj_name(b, v3, e3)]
            elif n3 == 0:
                vnames = _var_spec(b, t3, e3)
        results = []
        if len(els) > 1:
            c3, cn3, n3, v3, e3, t3 = els[1]
            results = [x for x in ber(b, v3, e3)]
        if vnames == ["RPT"]:
            _report(b, results, r, names, learned)
            return
        lae = [i for i, n in enumerate(vnames) if n.endswith("LastApplError")]
        ctl = [i for i, n in enumerate(vnames) if "$CO$" in n or n.endswith(("$Oper", "$SBOw", "$Cancel"))]
        cause = ""
        for i, nm in enumerate(vnames):
            if i >= len(results):
                break
            c4, cn4, n4, v4, e4, t4 = results[i]
            if i in lae:
                out = []
                sc.mms_data(b, t4, e4, out)
                vals = [x[2] for x in out[1:] if x[0].count(".") == 1]       # top level members only
                lab = ["CntrlObj", "Error", "Origin", "ctlNum", "AddCause"]
                p = T.add("", "LastApplError")
                for k, val in enumerate(vals[:6]):
                    txt = val
                    if k == 4 and val.lstrip("-").isdigit():
                        txt = "%s (%s)" % (val, ADD_CAUSE.get(int(val), "?"))
                        cause = ADD_CAUSE.get(int(val), val)
                    T.add(p, lab[k] if k < len(lab) else "item %d" % (k + 1), txt)
                if not r["info"] and vals:
                    r["info"] = ref61850(vals[0])
            else:
                data_rows(T, "", b, t4, e4, ref61850(nm))
        if ctl:
            r["mtype"] = "CommandTermination" + (" (negative)" if lae else " (positive)")
            r["info"] = ref61850(vnames[ctl[0]])
            r["acsi"] = "CommandTermination"
        elif lae:
            r["mtype"] = "LastApplError (control failed)"
        else:
            r["mtype"] = "InformationReport"
            r["info"] = ", ".join(ref61850(x) for x in vnames[:3])
        if cause:
            r["reason"] = "AddCause: " + cause
            r["neg"] = True


def _report(b, res, r, names, learned=None):
    """IEC 61850-8-1 report"""
    T = r["tree"]
    r["mtype"] = "Report"
    vals = [(b[v:e], t, e, n, cons) for (c, cons, n, v, e, t) in res]
    i = 0

    def take():
        nonlocal i
        if i >= len(vals):
            raise IndexError
        x = vals[i]
        i += 1
        return x
    try:
        rid = vis(take()[0])
        opt = bits_of(take()[0]) + [0] * 10
        r["ref"] = rid
        T.add("", "RptID", rid, "VisibleString")
        T.add("", "OptFlds", ", ".join(OPTFLDS[k] for k in range(1, 10) if opt[k]) or "-", "BitString")
        seq = tme = dset = tsec = confrev = None
        if opt[1]:
            seq = sc.uint(take()[0])
            T.add("", "SeqNum", str(seq), "Unsigned")
        if opt[2]:
            raw = take()[0]
            tme = binary_time(raw)
            tsec = binary_time_epoch(raw)
            T.add("", "TimeOfEntry", tme, "BinaryTime")
        if opt[4]:
            dset = vis(take()[0])
            T.add("", "DatSet", dset, "VisibleString")
        if opt[6]:
            T.add("", "BufOvfl", "TRUE" if take()[0] != b"\x00" else "FALSE", "Boolean")
        if opt[7]:
            T.add("", "EntryID", take()[0].hex(), "OctetString")
        if opt[8]:
            confrev = sc.uint(take()[0])
            T.add("", "ConfRev", str(confrev), "Unsigned")
        if opt[9]:
            T.add("", "SubSeqNum", str(sc.uint(take()[0])), "Unsigned")
            T.add("", "MoreSegmentsFollow", "TRUE" if take()[0] != b"\x00" else "FALSE", "Boolean")
        incl = bits_of(take()[0])
        idx = [k for k, x in enumerate(incl) if x]
        T.add("", "Inclusion", "".join(map(str, incl)) + "  (%d of %d entries)" % (len(idx), len(incl)), "BitString")
        refs = []
        if opt[5]:
            refs = [vis(take()[0]) for _ in idx]
        values = [take() for _ in idx]
        reasons = []
        if opt[3]:
            for _ in idx:
                rb = bits_of(take()[0])
                reasons.append([REASONS[k] for k in range(1, min(len(rb), 7)) if rb[k]])
        ds_names = names.report_names(rid, dset) if names else []
        learn = {}
        if refs and dset:                                 # names of the data set learned from the report
            learn = {k: ref61850(refs[j]) for j, k in enumerate(idx)}
            r["learn"] = (dset, learn, rid)
        known = (learned or {}).get(dset or (learned or {}).get(("rpt", rid), ""), {})
        allr = []
        for j, k in enumerate(idx):
            nm = ref61850(refs[j]) if j < len(refs) else (ds_names[k] if k < len(ds_names) else known.get(k, ""))
            why = ", ".join(reasons[j]) if j < len(reasons) else ""
            allr += reasons[j] if j < len(reasons) else []
            raw, t, e, n, cons = values[j]
            lab = "Entry %d%s" % (k + 1, ("  [" + why + "]") if why else "")
            data_rows(T, "", b, t, e, lab, nm)
        r["reason"] = ", ".join(dict.fromkeys(allr))
        ents = []
        for j, k in enumerate(idx):
            raw, t, e, n, cons = values[j]
            top, nmem, state, val = entry_info(b, t, e)
            ents.append(dict(k=k, type=top, nmem=nmem, state=state, value=val,
                             ref=ref61850(refs[j]) if j < len(refs) else None,
                             reasons=reasons[j] if j < len(reasons) else None))
        r["report"] = dict(rid=rid, seq=seq, time=tsec, dset=dset, confrev=confrev, n=len(incl),
                           opt=[OPTFLDS[k] for k in range(1, 10) if opt[k]], entries=ents)
        r["info"] = "%s%s  %d entr%s" % (rid, (" #%d" % seq) if seq is not None else "", len(idx), "y" if len(idx) == 1 else "ies")
    except (IndexError, ValueError) as ex:
        r["info"] = (r.get("ref") or "") + "  (report not complete: %s)" % ex


# ---------------------------------------------------------------- session / presentation / ACSE
def find_mms(b, p, end, depth=0):
    """Presentation / ACSE wrappers -> (MMS PDU bytes or None, ACSE text)"""
    acse = ""
    try:
        items = kids(b, p, end)
    except ValueError:
        return None, acse
    for cls, cons, num, v, e, t in items:
        tag = b[t]
        if tag == 0x61 and e > v and b[v] == 0x30:      # fully-encoded-data (PDV-list)
            for c2, cn2, n2, v2, e2, t2 in ber(b, v, e):  # PDV-list
                for c3, cn3, n3, v3, e3, t3 in ber(b, v2, e2):
                    if c3 == 2 and n3 == 0:                # (presentation-context-id is ignored)             # single-ASN1-type
                        inner = b[v3:e3]
                        if inner and inner[0] in (0x60, 0x61, 0x62, 0x63, 0x64):   # ACSE
                            m, a = _acse(inner)
                            return m, a
                        return inner, acse
        if cons and depth < 8:
            m, a = find_mms(b, v, e, depth + 1)
            if m is not None or a:
                return m, a
    return None, acse


def _acse(b):
    names = {0x60: "ACSE associate request (AARQ)", 0x61: "ACSE associate response (AARE)",
             0x62: "ACSE release request (RLRQ)", 0x63: "ACSE release response (RLRE)", 0x64: "ACSE abort (ABRT)"}
    a = names.get(b[0], "ACSE")
    try:
        for cls, cons, num, v, e, t in ber(b, 0, len(b)):
            for c2, cn2, n2, v2, e2, t2 in ber(b, v, e):
                if c2 == 2 and n2 == 30:                  # user-information
                    for c3, cn3, n3, v3, e3, t3 in ber(b, v2, e2):      # EXTERNAL
                        for c4, cn4, n4, v4, e4, t4 in ber(b, v3, e3):
                            if c4 == 2 and n4 == 0:       # single-ASN1-type
                                return b[v4:e4], a
                if c2 == 2 and n2 == 2 and b[0] == 0x61:  # AARE result
                    for c3, cn3, n3, v3, e3, t3 in ber(b, v2, e2):
                        if sc.uint(b[v3:e3]) != 0:
                            a += " - REJECTED"
    except ValueError:
        pass
    return None, a


def session(spdu):
    """SPDU -> (session text, presentation bytes or b'')"""
    if not spdu:
        return "", b""
    si = spdu[0]
    if si == 0x01 and len(spdu) >= 4 and spdu[2] == 0x01:      # GT + DT
        return "Data transfer", spdu[4:]
    name = SESSION.get(si, "SPDU 0x%02X" % si)
    if len(spdu) < 2:
        return name, b""
    ln = spdu[1]
    p = 2
    if ln == 0xFF:
        ln = int.from_bytes(spdu[2:4], "big")
        p = 4
    end = min(len(spdu), p + ln)
    user = b""
    while p + 2 <= end:
        code = spdu[p]
        l2 = spdu[p + 1]
        q = p + 2
        if l2 == 0xFF:
            l2 = int.from_bytes(spdu[p + 2:p + 4], "big")
            q = p + 4
        if code in (0xC1, 0xC2):                          # user data / extended user data
            user = spdu[q:q + l2]
        p = q + l2
    if not user and end < len(spdu):
        user = spdu[end:]
    return name, user


# ---------------------------------------------------------------- TCP reassembly + decoder
class Conn:
    def __init__(self):
        self.next = None
        self.buf = bytearray()
        self.cotp = bytearray()
        self.pending = {}
        self.gap = False
        self.fin = None


class MmsDecoder:
    def __init__(self, names=None):
        self.names = names
        self.dirs = {}              # (src ip, sport, dst ip, dport) -> Conn
        self.pending = {}           # (connection id, invoke) -> requested names
        self.learned = {}           # data set reference -> {entry index (0..): name} learned from MMS
                                    # (GetDataSetDirectory responses, reports with data references)
        self.count = 0

    def reset(self):
        self.dirs.clear()
        self.pending.clear()

    def feed(self, frame, ts, net=1):
        e = sc.ether(frame)
        if not e:
            return []
        dst, src, vlan, prio, et, p = e
        if et != 0x0800 or len(frame) < p + 40:
            return []
        ihl = (frame[p] & 0x0F) * 4
        if frame[p + 9] != 6:
            return []
        tot = int.from_bytes(frame[p + 2:p + 4], "big")
        ip_end = min(len(frame), p + tot) if tot else len(frame)
        ips = ".".join(str(x) for x in frame[p + 12:p + 16])
        ipd = ".".join(str(x) for x in frame[p + 16:p + 20])
        t = p + ihl
        sport = int.from_bytes(frame[t:t + 2], "big")
        dport = int.from_bytes(frame[t + 2:t + 4], "big")
        if MMS_PORT not in (sport, dport):
            return []
        seq = int.from_bytes(frame[t + 4:t + 8], "big")
        doff = (frame[t + 12] >> 4) * 4
        flags = frame[t + 13]
        data = bytes(frame[t + doff:ip_end])
        base = dict(kind="MMS", net=net, ts=ts, src="%s:%d" % (ips, sport), dst="%s:%d" % (ipd, dport),
                    ip_src=ips, ip_dst=ipd, mac_src=sc.mac(src), mac_dst=sc.mac(dst), appid=None, vlan=vlan,
                    prio=prio, sim=False, error="", data=[], sig=b"", full=True,
                    server=ipd if dport == MMS_PORT else ips, dir="C→S" if dport == MMS_PORT else "S→C")
        base["lan"] = sc.prp_lan(frame)
        cid = tuple(sorted([(ips, sport), (ipd, dport)]))
        base["conn"] = "%s:%d ↔ %s:%d" % (cid[0][0], cid[0][1], cid[1][0], cid[1][1])
        base["key"] = (net, base["lan"], "MMS", cid)
        out = []
        k = (ips, sport, ipd, dport)
        c = self.dirs.get(k)
        if flags & 0x04:                                  # RST
            out.append(self._msg(base, "TCP reset", "connection aborted", []))
            self.dirs.pop(k, None)
            self.dirs.pop((ipd, dport, ips, sport), None)
            return out
        if flags & 0x02:                                  # SYN
            if c is not None and c.next == (seq + 1) & 0xFFFFFFFF:
                return out                                # the same SYN again (retransmission / loopback)
            self.dirs[k] = c = Conn()
            c.next = (seq + 1) & 0xFFFFFFFF
            out.append(self._msg(base, "TCP connect" + (" accept" if flags & 0x10 else " request"),
                                 "SYN" + ("-ACK" if flags & 0x10 else ""), []))
            return out
        if c is None:
            c = self.dirs[k] = Conn()
        if data:
            if c.next is None:
                c.next = seq
            diff = (seq - c.next) & 0xFFFFFFFF
            if diff == 0:
                c.buf += data
                c.next = (seq + len(data)) & 0xFFFFFFFF
            elif diff > 0x7FFFFFFF:                       # old data (retransmission / overlap)
                over = ((c.next - seq) & 0xFFFFFFFF)
                if over < len(data):
                    c.buf += data[over:]
                    c.next = (seq + len(data)) & 0xFFFFFFFF
            else:                                         # gap: data lost in the capture -> resync
                c.buf = bytearray(data)
                c.cotp = bytearray()
                c.next = (seq + len(data)) & 0xFFFFFFFF
                out.append(self._msg(base, "Capture gap", "%d bytes missing - resync" % diff, []))
            out += self._tpkts(c, base, k)
        if flags & 0x01 and c.fin != seq:                 # FIN (once)
            c.fin = seq
            out.append(self._msg(base, "TCP close", "FIN", []))
        return out

    def _tpkts(self, c, base, k):
        out = []
        while len(c.buf) >= 4:
            if c.buf[0] != 3 or c.buf[1] != 0:
                i = c.buf.find(b"\x03\x00", 1)
                if i < 0:
                    c.buf = bytearray()
                    break
                del c.buf[:i]
                continue
            ln = int.from_bytes(c.buf[2:4], "big")
            if ln < 7:
                del c.buf[:2]
                continue
            if len(c.buf) < ln:
                break
            tp = bytes(c.buf[:ln])
            del c.buf[:ln]
            out += self._cotp(c, tp, base, k)
        return out

    def _cotp(self, c, tp, base, k):
        li = tp[4]
        code = tp[5] & 0xF0
        payload = tp[5 + li:]
        if code == 0xF0:                                  # DT
            eot = bool(tp[6] & 0x80)
            c.cotp += payload
            if not eot:
                return []
            spdu = bytes(c.cotp)
            c.cotp = bytearray()
            return [self._spdu(spdu, base, k)]
        name = {0xE0: "COTP connect request (CR)", 0xD0: "COTP connect confirm (CC)",
                0x80: "COTP disconnect request (DR)", 0xC0: "COTP disconnect confirm (DC)",
                0x70: "COTP error (ER)"}.get(code, "COTP 0x%02X" % code)
        hdr = [("COTP", name)]
        if code in (0xE0, 0xD0):                          # parameters: TSAPs, TPDU size
            p = 7 + 4
            while p + 2 <= 5 + li:
                pc, pl = tp[p], tp[p + 1]
                pv = tp[p + 2:p + 2 + pl]
                if pc == 0xC1:
                    hdr.append(("Calling TSAP", pv.hex()))
                elif pc == 0xC2:
                    hdr.append(("Called TSAP", pv.hex()))
                elif pc == 0xC0 and pv:
                    hdr.append(("TPDU size", str(1 << pv[0])))
                p += 2 + pl
        return [self._msg(base, name, "", [], hdr)]

    def _spdu(self, spdu, base, k):
        stext, pres = session(spdu)
        hdr = [("COTP", "Data (DT), %d bytes" % len(spdu)), ("Session", stext)]
        mms, acse = find_mms(pres, 0, len(pres)) if pres else (None, "")
        if acse:
            hdr.append(("ACSE", acse))
        if mms is None:
            t = acse or stext or "Session"
            return self._msg(base, t, "", [], hdr)
        conn = base["conn"]
        r = parse_pdu(mms, self.names, self.pending, conn, self.learned)
        if r.get("learn"):
            ds, mp, rid = r["learn"]
            self.learned.setdefault(ds, {}).update(mp)
            if rid:
                self.learned[("rpt", rid)] = ds
        hdr.append(("MMS PDU", "%s, %d bytes" % (r["mtype"], len(mms))))
        if r["invoke"] is not None:
            hdr.append(("Invoke ID", str(r["invoke"])))
        m = self._msg(base, r["mtype"], r["info"], r["tree"].rows, hdr)
        bad = any(str(x[3]).startswith("FAILURE") for x in r["tree"].rows) or bool(r.get("neg"))
        t = r["mtype"]
        cats = {"report"} if t in ("Report", "InformationReport") else {"cs"}
        if bad or t.startswith(("Confirmed error", "Reject", "LastApplError", "Initiate error", "Conclude error",
                                "Cancel")) or "bad BER" in t:
            cats.add("error")
        if r.get("svc"):
            hdr.append(("MMS service", r["svc"]))
        m.update(invoke=r["invoke"], reason=r["reason"], ref=r["ref"] or m["ref"], bad=bad, cats=cats,
                 report=r.get("report"))
        return m

    def _msg(self, base, mtype, info, tree, hdr=None):
        self.count += 1
        m = dict(base)
        cats = {"error"} if mtype.startswith(("TCP reset", "Capture gap")) or "REJECTED" in mtype else {"transport"}
        m.update(mtype=mtype, info=info, tree=tree, invoke=None, reason="", ref=base["conn"], cats=cats,
                 header=[("Connection", base["conn"]), ("Direction", "client → server" if base["dir"] == "C→S" else "server → client"),
                         ("Source", "%s  (%s)" % (base["src"], base["mac_src"])),
                         ("Destination", "%s  (%s)" % (base["dst"], base["mac_dst"])),
                         ("VLAN ID", "" if base["vlan"] is None else "%d (0x%03X)" % (base["vlan"], base["vlan"])),
                         ("VLAN priority", "" if base["prio"] is None else str(base["prio"]))] + (hdr or []))
        return m
