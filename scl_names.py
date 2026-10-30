# -*- coding: utf-8 -*-
"""
scl_names.py - names of the data set entries of GOOSE / SV control blocks from SCL files
(SCD, CID, ICD, IID), for the column "Signal (SCL)" of the sniffer.

  GOOSE: gocbRef  <IED><LD>/LLN0$GO$<GSEControl name>  -> {"1": "LD/LN.DO.DA [FC]", "1.2": ...}
  SV   : svID     <SampledValueControl smvID>          -> {channel no (1..): "LD/LN.DO", ...}
A data set entry on DO level (FCD) is a structure: its members get the names of the DA / SDO of
the DO type (in the order of the type), so "3.1", "3.2" ... are named too.
"""
import os
import xml.etree.ElementTree as ET


def _int(s, base=10):
    try:
        return int(str(s).strip(), base)
    except (TypeError, ValueError):
        return None


class SclNames:
    def __init__(self):
        self.goose = {}       # gocbRef -> {index path: name}
        self.goose_ds = {}    # gocbRef -> data set reference
        self.goose_ied = {}   # gocbRef -> IED name
        self.ds_names = {}    # "IEDLD/LLN0$DS" -> [entry names] (MMS reports)
        self.rpt = {}         # RptID -> data set reference
        self.ip_ied = {}      # IP address -> IED name
        self.ld_names = set() # LD inst names (to split <IED><LD> of gocbRef without SCL entry)
        self.sv = {}          # svID -> [channel names]
        self.sv_cb = {}       # svID -> [SV control blocks with this smvID]: IED, LD, name, confRev, smpRate, address, channels
        self.files = []
        self.errors = []

    # ------------------------------------------------------------ loading
    def load(self, paths):
        for p in paths:
            if os.path.isdir(p):
                for fn in sorted(os.listdir(p)):
                    if os.path.splitext(fn)[1].lower() in (".scd", ".cid", ".icd", ".iid", ".ssd", ".sed"):
                        self._load_file(os.path.join(p, fn))
            else:
                self._load_file(p)
        return self

    def _load_file(self, path):
        try:
            root = ET.parse(path).getroot()
        except Exception as ex:
            self.errors.append("%s: %s" % (os.path.basename(path), ex))
            return
        ns = root.tag.split("}")[0][1:] if root.tag.startswith("{") else ""
        q = (lambda t: "{%s}%s" % (ns, t)) if ns else (lambda t: t)
        dtt = root.find(q("DataTypeTemplates"))
        types = dict(lnt={}, dot={}, dat={})
        if dtt is not None:
            types["lnt"] = {e.get("id"): e for e in dtt.findall(q("LNodeType"))}
            types["dot"] = {e.get("id"): e for e in dtt.findall(q("DOType"))}
            types["dat"] = {e.get("id"): e for e in dtt.findall(q("DAType"))}
        n0 = len(self.goose) + len(self.sv)
        addr = self._smv_addresses(root, q)
        com = root.find(q("Communication"))
        if com is not None:
            for cap in com.iter(q("ConnectedAP")):
                for pp in cap.iter(q("P")):
                    if pp.get("type") == "IP" and (pp.text or "").strip():
                        self.ip_ied[pp.text.strip()] = cap.get("iedName", "")
        for ied in root.findall(q("IED")):
            iname = ied.get("name", "")
            lnvals = self._ln_values(ied, q)
            for ld in ied.iter(q("LDevice")):
                ldi = ld.get("inst", "")
                if ldi:
                    self.ld_names.add(ldi)
                ln0 = ld.find(q("LN0"))
                if ln0 is None:
                    continue
                lns = {}
                for ln in [ln0] + ld.findall(q("LN")):
                    key = (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or "")
                    lns[key] = ln.get("lnType")
                dsets = {d.get("name"): d for d in ln0.findall(q("DataSet"))}
                for dn, d in dsets.items():                # data sets for MMS reports
                    ent = self._entries(d, lns, types, q)
                    self.ds_names["%s%s/LLN0$%s" % (iname, ldi, dn)] = [ent[k] for k in sorted(
                        (k for k in ent if "." not in k), key=int)]
                for ln in [ln0] + ld.findall(q("LN")):
                    lnn = (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or "")
                    for rc in ln.findall(q("ReportControl")):
                        dsr = "%s%s/LLN0$%s" % (iname, ldi, rc.get("datSet") or "")
                        br = "BR" if rc.get("buffered") == "true" else "RP"
                        rid = rc.get("rptID") or "%s%s/%s$%s$%s" % (iname, ldi, lnn, br, rc.get("name"))
                        self.rpt[rid] = dsr
                for gc in ln0.findall(q("GSEControl")):
                    ds = dsets.get(gc.get("datSet"))
                    ref = "%s%s/LLN0$GO$%s" % (iname, ldi, gc.get("name"))
                    self.goose_ied[ref] = iname
                    self.goose_ds[ref] ="%s%s/LLN0$%s" % (iname, ldi, gc.get("datSet") or "")
                    self.goose[ref] = self._entries(ds, lns, types, q) if ds is not None else {}
                for sc in ln0.findall(q("SampledValueControl")):
                    ds = dsets.get(sc.get("datSet"))
                    svid = sc.get("smvID") or ""
                    if ds is not None and svid:
                        self.sv[svid] = self._channels(ds, q)
                        a = addr.get((iname, ldi, sc.get("name"))) or {}
                        self.sv_cb.setdefault(svid, []).append(dict(
                            ied=iname, ld=ldi, cb=sc.get("name", ""), datSet=sc.get("datSet", ""),
                            confRev=_int(sc.get("confRev")), smpRate=_int(sc.get("smpRate")),
                            nofASDU=_int(sc.get("nofASDU")), mac=a.get("mac"), appid=a.get("appid"),
                            vlan=a.get("vlan"), prio=a.get("prio"), file=os.path.basename(path),
                            chans=self._channel_info(ds, ldi, lnvals, q)))
        self.files.append("%s (%d control blocks)" % (os.path.basename(path), len(self.goose) + len(self.sv) - n0))

    # ------------------------------------------------------------ SV: addresses, CT / VT ratios
    @staticmethod
    def _smv_addresses(root, q):
        """(IED, LD inst, cbName) -> {mac, appid, vlan, prio} from Communication / ConnectedAP / SMV"""
        out = {}
        com = root.find(q("Communication"))
        if com is None:
            return out
        for cap in com.iter(q("ConnectedAP")):
            for smv in cap.findall(q("SMV")):
                P = {p.get("type"): (p.text or "").strip() for p in smv.iter(q("P"))}
                mac = P.get("MAC-Address", "").replace("-", ":").upper() or None
                out[(cap.get("iedName"), smv.get("ldInst"), smv.get("cbName"))] = dict(
                    mac=mac, appid=_int(P.get("APPID"), 16), vlan=_int(P.get("VLAN-ID"), 16),
                    prio=_int(P.get("VLAN-PRIORITY")))
        return out

    @staticmethod
    def _ln_values(ied, q):
        """(LD inst, LN name) -> {"Rat": 300.0, "ARtg": 1, "VRtg": .., "HzRtg": 50} (instance values
        DOI / SDI setMag / DAI f or i)"""
        out = {}
        for ld in ied.iter(q("LDevice")):
            for ln in ld.findall(q("LN")):
                if ln.get("lnClass") not in ("TCTR", "TVTR"):
                    continue
                key = (ld.get("inst", ""), (ln.get("prefix", "") or "") + ln.get("lnClass", "") + (ln.get("inst", "") or ""))
                v = {}
                for doi in ln.findall(q("DOI")):
                    if doi.get("name") not in ("Rat", "ARtg", "VRtg", "HzRtg"):
                        continue
                    sdi = next((x for x in doi.findall(q("SDI")) if x.get("name") == "setMag"), None)
                    if sdi is None:
                        continue
                    for dai in sdi.findall(q("DAI")):
                        val = dai.find(q("Val"))
                        if val is not None and (val.text or "").strip():
                            try:
                                v[doi.get("name")] = float(val.text.strip())
                            except ValueError:
                                pass
                out[key] = v
        return out

    def _channel_info(self, ds, ldi, lnvals, q):
        """per SV channel: {name, kind 'I' / 'U' / '', rat, rtg, hz, ln}"""
        fl = ds.findall(q("FCDA"))
        if len(fl) >= 2 and all((f.get("daName") or "") == "q" for f in fl[1::2]):
            fl = fl[0::2]
        out = []
        for f in fl:
            lnc = f.get("lnClass", "")
            ln = (f.get("prefix", "") or "") + lnc + (f.get("lnInst", "") or "")
            v = lnvals.get((f.get("ldInst") or ldi, ln), {})
            do = f.get("doName", "")
            kind = "I" if lnc == "TCTR" or do.startswith("Amp") else ("U" if lnc == "TVTR" or do.startswith("Vol") else "")
            out.append(dict(name=self._fcda_name(f)[0].replace(".instMag.i", ""), kind=kind, ln=ln,
                            rat=v.get("Rat"), rtg=v.get("ARtg") if kind == "I" else v.get("VRtg"),
                            hz=v.get("HzRtg")))
        return out

    # ------------------------------------------------------------ names
    @staticmethod
    def _fcda_name(f):
        ln = (f.get("prefix", "") or "") + f.get("lnClass", "") + (f.get("lnInst", "") or "")
        n = "%s/%s.%s" % (f.get("ldInst", ""), ln, f.get("doName", ""))
        if f.get("daName"):
            n += "." + f.get("daName")
        return n, f.get("fc", "")

    def _entries(self, ds, lns, types, q):
        out = {}
        for i, f in enumerate(ds.findall(q("FCDA")), 1):
            name, fc = self._fcda_name(f)
            out[str(i)] = "%s [%s]" % (name, fc)
            if not f.get("daName"):                       # DO level: members of the DO type
                ln = (f.get("prefix", "") or "") + f.get("lnClass", "") + (f.get("lnInst", "") or "")
                members = self._do_members(types, lns.get(ln), f.get("doName", ""), fc, q)
                self._name_members(out, str(i), name, members)
        return out

    def _name_members(self, out, idx, base, members):
        for j, (nm, sub) in enumerate(members, 1):
            k = "%s.%d" % (idx, j)
            out[k] = base + "." + nm
            if sub:
                self._name_members(out, k, base + "." + nm, sub)

    def _do_members(self, types, lntype, doname, fc, q):
        """[(name, [sub members])] of a DO (dots = SDO path) for the functional constraint fc"""
        lnt = types["lnt"].get(lntype)
        if lnt is None:
            return []
        parts = doname.split(".")
        do = next((d for d in lnt.findall(q("DO")) if d.get("name") == parts[0]), None)
        if do is None:
            return []
        dot = types["dot"].get(do.get("type"))
        for p in parts[1:]:
            if dot is None:
                return []
            sdo = next((s for s in dot.findall(q("SDO")) if s.get("name") == p), None)
            dot = types["dot"].get(sdo.get("type")) if sdo is not None else None
        return self._dot_members(types, dot, fc, q) if dot is not None else []

    def _dot_members(self, types, dot, fc, q, depth=0):
        out = []
        if depth > 6:
            return out
        for el in dot:
            tag = el.tag.split("}")[-1]
            if tag == "DA" and el.get("fc") == fc:
                sub = self._dat_members(types, el.get("type"), q) if el.get("bType") == "Struct" else []
                out.append((el.get("name"), sub))
            elif tag == "SDO":
                sd = types["dot"].get(el.get("type"))
                sub = self._dot_members(types, sd, fc, q, depth + 1) if sd is not None else []
                if sub:
                    out.append((el.get("name"), sub))
        return out

    def _dat_members(self, types, typ, q, depth=0):
        dat = types["dat"].get(typ)
        if dat is None or depth > 6:
            return []
        out = []
        for b in dat.findall(q("BDA")):
            sub = self._dat_members(types, b.get("type"), q, depth + 1) if b.get("bType") == "Struct" else []
            out.append((b.get("name"), sub))
        return out

    def _channels(self, ds, q):
        """SV channel names: 9-2LE data set = value + quality per channel (FCDA pairs) or one
        FCD per channel (DO level)"""
        names = [self._fcda_name(f)[0] for f in ds.findall(q("FCDA"))]
        if len(names) >= 2 and all(n.endswith(".q") for n in names[1::2]):
            return [n.rsplit(".instMag.i", 1)[0] if ".instMag.i" in n else n for n in names[0::2]]
        return names

    # ------------------------------------------------------------ lookup
    def goose_name(self, ref, index):
        return self.goose.get(ref, {}).get(index, "")

    def ied_of(self, ref):
        return self.goose_ied.get(ref, "")

    def sv_name(self, svid, ch):
        L = self.sv.get(svid)
        return L[ch] if L and ch < len(L) else ""

    def report_names(self, rptid, datset=None):
        """names of the data set entries of a report (by DatSet of the report, else by RptID)"""
        if datset:
            L = self.ds_names.get(datset.replace(".", "$")) or self.ds_names.get(datset)
            if L:
                return L
        return self.ds_names.get(self.rpt.get(rptid, ""), [])

    def summary(self):
        return "%d GOOSE + %d SV control blocks from %d file(s)" % (len(self.goose), len(self.sv), len(self.files))
