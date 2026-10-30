# -*- coding: utf-8 -*-
"""
rpt_test.py - test of the reports (RCB) of one IED against its CID, from the MMS traffic that
the analyzer hears (tab MMS / Report test). Passive: the reports are enabled by SCADA (or later by
the active MMS client); the analyzer only checks what arrives.

1. CID check - every report of the IED (server IP from the CID) is compared with the CID:
   RptID -> ReportControl, DatSet, ConfRev, number of data set entries, data references (names),
   types of the values (DataTypeTemplates), reasons allowed by TrgOps, OptFlds <-> OptFields.
2. Coverage - for every entry of every data set used by a ReportControl of the IED:
   which reasons arrived (data change, quality change, data update, integrity, general
   interrogation), first / last time, count, last value; for BOOLEAN / Dbpos data change needs
   BOTH states (TRUE and FALSE, on and off) and the minimum time between two opposite states is kept.
   Possible reasons of an entry = TrgOps of its RCB(s) AND the trigger options of the attribute
   in the DataTypeTemplates (dchg / qchg / dupd); GI and integrity from TrgOps gi / period.
   Required for "completed" (default): data change, GI, integrity; quality change and data update
   on request. Coverage is counted per data set (any RCB instance using it).
3. Save / open the test (.json) to continue later, export the result (.csv, opens in Excel).
"""
import csv
import datetime
import json
import os
import re
import xml.etree.ElementTree as ET

import goose_pub as gp

REASONS = ["dchg", "qchg", "dupd", "integrity", "gi"]
REASON_TEXT = {"dchg": "data change", "qchg": "quality change", "dupd": "data update",
               "integrity": "integrity (period)", "gi": "general interrogation"}
TEXT_REASON = {v: k for k, v in REASON_TEXT.items()}
DEFAULT_REQUIRED = ("dchg", "integrity", "gi")
OPT_MAP = {"seqNum": "sequence-number", "timeStamp": "report-time-stamp", "reasonCode": "reason-for-inclusion",
           "dataSet": "data-set-name", "dataRef": "data-reference", "bufOvfl": "buffer-overflow",
           "entryID": "entryID", "configRef": "conf-revision", "segmentation": "segmentation"}
BT_MMS = {"BOOLEAN": "Boolean", "Dbpos": "Dbpos", "Tcmd": "Dbpos", "Check": "Bitstring", "Quality": "Quality",
          "FLOAT32": "Float", "FLOAT64": "Double", "Enum": "Integer", "Timestamp": "Timestamp",
          "Struct": "Structure", "EntryTime": "BinaryTime"}
STATE_TYPES = ("BOOLEAN", "Dbpos", "Tcmd")


def now_text(t=None):
    return datetime.datetime.fromtimestamp(t if t is not None else datetime.datetime.now().timestamp()).strftime("%Y-%m-%d %H:%M:%S")


def mms_type(bt):
    if bt in BT_MMS:
        return BT_MMS[bt]
    if bt.startswith("INT") and bt.endswith("U"):
        return "Unsigned"
    if bt.startswith("INT"):
        return "Integer"
    if bt.startswith("VisString"):
        return "VisibleString"
    if bt.startswith("Unicode"):
        return "MMSString"
    if bt.startswith("Octet"):
        return "OctetString"
    return bt


def infer_trg(node):
    """trigger options from the attribute names when the CID has none (stVal / mag -> dchg, q -> qchg ...)"""
    if node.get("trg"):
        return set(node["trg"])
    names = [node["name"]] + [c["name"] for c in gp.all_nodes(node.get("children") or [])]
    t = set()
    for n in names:
        leaf = n.split(" [")[0].rsplit(".", 1)[-1]
        if leaf in ("stVal", "mag", "cVal", "instMag", "f", "i", "general", "phsA", "phsB", "phsC", "neut", "setVal",
                    "setMag", "ctlVal"):
            t.add("dchg")
        if leaf == "q":
            t.add("qchg")
        if leaf in ("actVal", "cnt", "frVal"):
            t.add("dupd")
    return t


# ---------------------------------------------------------------- CID
def list_ieds(path):
    root = ET.parse(path).getroot()
    q = gp._q(root)
    return [i.get("name", "") for i in root.findall(q("IED"))]


def load_ied(path, ied_name=None):
    """IED of a CID (its own = first IED) or of a SCD (by name) -> dict(ied, file, ips, rcbs, datasets)"""
    root = ET.parse(path).getroot()
    q = gp._q(root)
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
    ips = []
    com = root.find(q("Communication"))
    if com is not None:
        for cap in com.iter(q("ConnectedAP")):
            if cap.get("iedName") == iname:
                for p in cap.iter(q("P")):
                    if p.get("type") == "IP" and (p.text or "").strip():
                        ips.append(p.text.strip())
    lns = {}
    for ld in ied.iter(q("LDevice")):
        for ln in ld:
            tag = ln.tag.split("}")[-1]
            if tag in ("LN0", "LN"):
                key = (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or "")
                lns[(ld.get("inst", ""), key)] = ln.get("lnType")
    datasets, rcbs, no_ds = {}, [], []
    for ld in ied.iter(q("LDevice")):
        ldi = ld.get("inst", "")
        ln0 = ld.find(q("LN0"))
        if ln0 is None:
            continue
        dsets = {d.get("name"): d for d in ln0.findall(q("DataSet"))}
        for ln in [ln0] + ld.findall(q("LN")):
            lnn = (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or "")
            for rc in ln.findall(q("ReportControl")):
                ds = dsets.get(rc.get("datSet"))
                if ds is None:                            # RCB without data set (configured in the IED, e.g. GE UR)
                    no_ds.append(rc.get("name", ""))
                    continue
                dsref = "%s%s/LLN0$%s" % (iname, ldi, rc.get("datSet"))
                if dsref not in datasets:
                    datasets[dsref] = [_entry(gp._fcda_node(f, ldi, lns, T, q)) for f in ds.findall(q("FCDA"))]
                tr = rc.find(q("TrgOps"))
                of = rc.find(q("OptFields"))
                re_ = rc.find(q("RptEnabled"))
                buffered = rc.get("buffered") == "true"
                trg = {k for k in ("dchg", "qchg", "dupd", "period", "gi")      # SCL: gi default true
                       if tr is not None and tr.get(k, "true" if k == "gi" else "false") == "true"}
                rcbs.append(dict(
                    name=rc.get("name", ""), ld=ldi, ln=lnn, dataset=dsref, buffered=buffered,
                    rptid=rc.get("rptID") or "", confrev=int(rc.get("confRev") or 0),
                    intgpd=int(rc.get("intgPd") or 0), trgops=sorted(trg),
                    optfields=sorted(k for k in OPT_MAP if of is not None and of.get(k) == "true"),
                    max=int(re_.get("max") or 1) if re_ is not None else 1,
                    ref="%s%s/%s$%s$%s" % (iname, ldi, lnn, "BR" if buffered else "RP", rc.get("name", ""))))
    return dict(ied=iname, file=os.path.basename(path), path=path, ips=ips, rcbs=rcbs, datasets=datasets,
                rcbs_no_ds=no_ds)


def _entry(node):
    return dict(name=node["name"], btype=node["btype"], trg=sorted(infer_trg(node)),
                nmem=len(node.get("children") or []),
                state=node["btype"] in STATE_TYPES or bool(node.get("children") and next(
                    (c for c in gp.all_nodes(node["children"]) if c["btype"] in STATE_TYPES), None)))


# ---------------------------------------------------------------- test
class ReportTest:
    def __init__(self, info, required=DEFAULT_REQUIRED):
        self.info = info
        self.required = set(required)
        self.started = now_text()
        self.completed = None
        self.issues = {}            # text -> dict(count, first, last)
        self.unknown = {}           # RptID not in the CID -> count
        self.reports = 0
        self.include = {ds: True for ds in info["datasets"]}
        self.dyn = {}               # data sets not in the CID, learned from the traffic: ds -> dict(rid, seen)
        self.cov = {ds: [self._new_cov() for _ in ents] for ds, ents in info["datasets"].items()}
        # possible reasons per data set: union of the TrgOps of the RCBs that use it
        self.ds_trg = {}
        for r in info["rcbs"]:
            t = set(r["trgops"])
            if r["intgpd"] <= 0:
                t.discard("period")
            self.ds_trg.setdefault(r["dataset"], set()).update(t)

    @staticmethod
    def _new_cov():
        return dict(seen={}, states={}, last_state=None, last_change=None, min_dt=None, last_value="", n=0)

    # ---- possible / required reasons of an entry
    def possible(self, ds, i):
        ent = self.info["datasets"][ds][i]
        if ds in self.dyn:                                # not in the CID: data change + what was seen
            seen = self.dyn[ds]["seen"]
            return {"dchg"} | (seen & {"gi", "integrity"}) | (set(self.cov[ds][i]["seen"]) & {"qchg", "dupd"})
        t = self.ds_trg.get(ds, set())
        out = set()
        for k in ("dchg", "qchg", "dupd"):
            if k in t and k in ent["trg"]:
                out.add(k)
        if "period" in t:
            out.add("integrity")
        if "gi" in t:
            out.add("gi")
        return out

    def checks(self, ds, i):
        return [k for k in REASONS if k in self.possible(ds, i) and k in self.required]

    def check_ok(self, ds, i, k):
        c = self.cov[ds][i]
        if k not in c["seen"]:
            return False
        if k == "dchg" and self.info["datasets"][ds][i]["state"]:
            st = set(c["states"])
            if self.info["datasets"][ds][i]["btype"] in ("Dbpos", "Tcmd") or any(s in ("on", "off", "intermediate", "bad") for s in st):
                return {"on", "off"} <= st
            return len(st) >= 2
        return True

    def progress(self):
        total = done = 0
        for ds, ents in self.info["datasets"].items():
            if not self.include.get(ds, True):
                continue
            for i in range(len(ents)):
                for k in self.checks(ds, i):
                    total += 1
                    done += 1 if self.check_ok(ds, i, k) else 0
        return done, total

    def missing(self, ds, i):
        out = []
        for k in self.checks(ds, i):
            if not self.check_ok(ds, i, k):
                if k == "dchg" and k in self.cov[ds][i]["seen"] and self.info["datasets"][ds][i]["state"]:
                    out.append("data change: only state " + "/".join(sorted(self.cov[ds][i]["states"])))
                else:
                    out.append(REASON_TEXT[k])
        return out

    # ---- feed
    def _issue(self, text, t):
        x = self.issues.get(text)
        if x is None:
            self.issues[text] = dict(count=1, first=now_text(t), last=now_text(t))
        else:
            x["count"] += 1
            x["last"] = now_text(t)

    def find_rcb(self, rid, dset):
        def base(s):
            return re.sub(r"\d{1,2}$", "", s)
        for r in self.info["rcbs"]:
            if r["rptid"] and (rid == r["rptid"] or base(rid) == base(r["rptid"])):
                return r
        for r in self.info["rcbs"]:                       # default RptID = reference of the RCB (instance)
            if rid == r["ref"] or base(rid) == r["ref"] or rid.startswith(r["ref"]):
                return r
        if dset:
            for r in self.info["rcbs"]:
                if r["dataset"] == dset:
                    return r
        return None

    def mine(self, m):
        ips = self.info.get("ips") or []
        if ips:
            return m.get("server") in ips
        rep = m.get("report") or {}
        return (rep.get("dset") or rep.get("rid") or "").startswith(self.info["ied"])

    def _dyn_dataset(self, ds, rid, rep, learned):
        """data set that is not in the CID: entries from the report (names learned from MMS / data references)"""
        names = (learned or {}).get(ds, {})
        n = rep.get("n") or 0
        ents = []
        for k in range(n):
            e = next((x for x in rep.get("entries", []) if x["k"] == k), None)
            nm = names.get(k) or (e.get("ref") if e else None) or "entry %d" % (k + 1)
            ents.append(dict(name=nm, btype="?", trg=["dchg"], nmem=0, state=False))
        self.info["datasets"][ds] = ents
        self.cov[ds] = [self._new_cov() for _ in ents]
        self.include[ds] = True
        self.dyn[ds] = dict(rid=rid, seen=set())
        return ents

    def feed(self, m, learned=None):
        """one MMS message; True when it was a report of this IED"""
        rep = m.get("report")
        if not rep or not self.mine(m):
            return False
        self.reports += 1
        t = rep.get("time") or m["ts"]
        rid, dset = rep.get("rid", ""), rep.get("dset")
        rcb = self.find_rcb(rid, dset)
        if rcb is None:
            self.unknown[rid] = self.unknown.get(rid, 0) + 1
            if not dset:
                self._issue("RptID %s: not in the CID and the report has no DatSet - can not be tested" % rid, t)
                return True
            self._issue("RptID %s / %s: not in the CID (RCB and data set configured in the IED) - tested with "
                        "the data set seen in the traffic" % (rid, dset), t)
            rcb = dict(name=rid, dataset=dset, confrev=0, buffered="entryID" in (rep.get("opt") or []),
                       optfields=[], trgops=["dchg", "qchg", "dupd", "period", "gi"], dyn=True)
        ds = dset or rcb["dataset"]
        if dset and dset != rcb["dataset"]:
            self._issue("%s: DatSet %s, CID %s" % (rcb["name"], dset, rcb["dataset"]), t)
            if dset not in self.info["datasets"]:
                return True
        ents = self.info["datasets"].get(ds)
        if ents is None:
            ents = self._dyn_dataset(ds, rid, rep, learned)
        if ds in self.dyn:                                # names learned later (GetDataSetDirectory)
            names = (learned or {}).get(ds, {})
            for k, ce in enumerate(ents):
                if ce["name"].startswith("entry ") and names.get(k):
                    ce["name"] = names[k]
        if rep.get("confrev") is not None and rcb["confrev"] and rep["confrev"] != rcb["confrev"]:
            self._issue("%s: ConfRev %s, CID %s" % (rcb["name"], rep["confrev"], rcb["confrev"]), t)
        if rep.get("n") and rep["n"] != len(ents):
            self._issue("%s: %d data set entries in the report, %d in the CID" % (rcb["name"], rep["n"], len(ents)), t)
        exp = {OPT_MAP[k] for k in rcb["optfields"]}
        got = set(rep.get("opt") or [])
        if rcb.get("dyn"):
            exp = set(got)
        if not rcb["buffered"]:
            exp -= {"buffer-overflow", "entryID"}
            got -= {"buffer-overflow", "entryID"}
        exp.discard("segmentation")
        got.discard("segmentation")
        if exp != got:
            d = sorted(got - exp)
            mi = sorted(exp - got)
            self._issue("%s: OptFlds differ from the CID OptFields%s%s" % (
                rcb["name"], (" - sent, not in CID: " + ", ".join(d)) if d else "",
                (" - in CID, not sent: " + ", ".join(mi)) if mi else ""), t)
        if "reason-for-inclusion" not in got:
            self._issue("%s: reason codes not sent (OptFlds reason-for-inclusion off) - reasons can not be checked" % rcb["name"], t)
        allowed = set(rcb["trgops"]) | ({"integrity"} if "period" in rcb["trgops"] else set())
        for e in rep.get("entries", []):
            k = e["k"]
            if k >= len(ents):
                self._issue("%s: entry %d does not exist in the CID data set (%d entries)" % (rcb["name"], k + 1, len(ents)), t)
                continue
            ce = ents[k]
            if ds in self.dyn:                            # type / state from the first value
                if ce["btype"] == "?":
                    ce["btype"] = e["type"] or "?"
                if e.get("state") is not None:
                    ce["state"] = True
                if e.get("ref") and ce["name"].startswith("entry "):
                    ce["name"] = e["ref"]
            want = mms_type(ce["btype"])
            if e["type"] and want != e["type"] and not (want == "Integer" and e["type"] == "Unsigned"):
                self._issue("%s entry %d %s: type %s, CID %s (%s)" % (rcb["name"], k + 1, ce["name"], e["type"], want, ce["btype"]), t)
            elif ce["btype"] == "Struct" and e["nmem"] != ce["nmem"]:
                self._issue("%s entry %d %s: %d members, CID %d" % (rcb["name"], k + 1, ce["name"], e["nmem"], ce["nmem"]), t)
            if e.get("ref"):
                a = e["ref"].split(" [")[0]
                b = ce["name"].split(" [")[0]
                if not (a.endswith(b) or b.endswith(a.split("/", 1)[-1])):
                    self._issue("%s entry %d: data reference %s, CID %s" % (rcb["name"], k + 1, e["ref"], ce["name"]), t)
            c = self.cov[ds][k]
            c["n"] += 1
            c["last_value"] = e.get("value", "")
            keys = []
            for rtxt in (e.get("reasons") or []):
                key = TEXT_REASON.get(rtxt)
                if key is None:
                    continue
                keys.append(key)
                base_key = "period" if key == "integrity" else key
                if base_key not in allowed and key in ("dchg", "qchg", "dupd", "gi", "integrity"):
                    self._issue("%s entry %d: reason '%s' but TrgOps of the RCB does not enable it" % (rcb["name"], k + 1, rtxt), t)
            if not e.get("reasons"):
                keys.append("unknown")
            if ds in self.dyn:
                self.dyn[ds]["seen"].update(x for x in keys if x in ("gi", "integrity"))
            for key in keys:
                s = c["seen"].get(key)
                if s is None:
                    c["seen"][key] = dict(first=t, last=t, count=1)
                else:
                    s["last"] = t
                    s["count"] += 1
            if "dchg" in keys and e.get("state") is not None:
                st = e["state"].split(" ")[0]              # TRUE / FALSE, on / off / intermediate / bad
                c["states"].setdefault(st, t)
                if c["last_state"] is not None and st != c["last_state"] and c["last_change"] is not None:
                    dt = t - c["last_change"]
                    if dt >= 0 and (c["min_dt"] is None or dt < c["min_dt"]):
                        c["min_dt"] = dt
                if st != c["last_state"]:
                    c["last_change"] = t
                c["last_state"] = st
        done, total = self.progress()
        if total and done == total and not self.completed:
            self.completed = now_text(t)                  # time of the report that completed the test
        return True

    def status_text(self):
        done, total = self.progress()
        if self.completed:
            return "RCB test completed - all signals verified - %s" % self.completed
        return "%d of %d checks passed" % (done, total)

    # ---- save / open
    def to_json(self):
        return dict(version=1, cid=self.info["path"], ied=self.info["ied"], required=sorted(self.required),
                    dyn={ds: dict(rid=x["rid"], seen=sorted(x["seen"]), entries=self.info["datasets"][ds])
                         for ds, x in self.dyn.items()},
                    started=self.started, completed=self.completed, issues=self.issues, unknown=self.unknown,
                    reports=self.reports, include=self.include,
                    cov={ds: [dict(c) for c in L] for ds, L in self.cov.items()})

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_json(), f, indent=1)

    @classmethod
    def open(cls, path, cid_path=None):
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        cid = cid_path or d["cid"]
        if not os.path.exists(cid):
            raise FileNotFoundError("CID of the test not found: %s" % cid)
        t = cls(load_ied(cid, d.get("ied")), d.get("required", DEFAULT_REQUIRED))
        t.started, t.completed = d.get("started", t.started), d.get("completed")
        t.issues, t.unknown, t.reports = d.get("issues", {}), d.get("unknown", {}), d.get("reports", 0)
        for ds, x in d.get("dyn", {}).items():
            t.info["datasets"][ds] = x["entries"]
            t.cov[ds] = [t._new_cov() for _ in x["entries"]]
            t.dyn[ds] = dict(rid=x["rid"], seen=set(x["seen"]))
        t.include.update(d.get("include", {}))
        for ds, L in d.get("cov", {}).items():
            if ds in t.cov:
                for i, c in enumerate(L[:len(t.cov[ds])]):
                    t.cov[ds][i].update(c)
        return t

    # ---- export
    def export_csv(self, path):
        done, total = self.progress()
        rcb_of = {}
        for r in self.info["rcbs"]:
            rcb_of.setdefault(r["dataset"], []).append(r["name"])
        for ds, x in self.dyn.items():
            rcb_of.setdefault(ds, []).append("%s (not in CID)" % x["rid"])
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["IEC61850ANALYZER - RCB test"])
            w.writerow(["IED", self.info["ied"]])
            w.writerow(["CID", self.info["path"]])
            w.writerow(["IP", ", ".join(self.info.get("ips") or [])])
            w.writerow(["Started", self.started])
            w.writerow(["Result", self.status_text()])
            w.writerow(["Checks passed", "%d of %d" % (done, total)])
            w.writerow(["Required reasons", ", ".join(REASON_TEXT[k] for k in REASONS if k in self.required)])
            w.writerow(["Reports received", self.reports])
            w.writerow([])
            w.writerow(["CID check"])
            if not self.issues:
                w.writerow(["", "OK - the reports match the CID"])
            for txt, x in self.issues.items():
                w.writerow(["", txt, "count %d" % x["count"], "first %s" % x["first"], "last %s" % x["last"]])
            w.writerow([])
            hdr = ["Data set", "RCB", "#", "Signal", "Type", "Possible reasons"] + \
                  [REASON_TEXT[k] for k in REASONS] + ["States (data change)", "Min time between states (ms)",
                                                       "Last value", "Status"]
            w.writerow(hdr)
            for ds, ents in self.info["datasets"].items():
                if not self.include.get(ds, True):
                    continue
                for i, ce in enumerate(ents):
                    c = self.cov[ds][i]
                    poss = self.possible(ds, i)
                    cells = []
                    for k in REASONS:
                        s = c["seen"].get(k)
                        if k not in poss:
                            cells.append("n/a")
                        elif s:
                            cells.append("%s (%dx)" % (now_text(s["first"]), s["count"]))
                        else:
                            cells.append("-")
                    miss = self.missing(ds, i)
                    w.writerow([ds, ", ".join(rcb_of.get(ds, [])), i + 1, ce["name"], ce["btype"],
                                ", ".join(REASON_TEXT[k] for k in REASONS if k in poss)] + cells +
                               ["/".join(sorted(c["states"])), "" if c["min_dt"] is None else "%.0f" % (c["min_dt"] * 1000),
                                c["last_value"], "OK" if not miss else "missing: " + ", ".join(miss)])
            w.writerow([])
            if self.completed:
                w.writerow(["RCB test completed - all signals verified - %s" % self.completed])
            else:
                w.writerow(["RCB test not completed - %d of %d checks passed" % (done, total)])
