# -*- coding: utf-8 -*-
"""
filters.py - display filter of the sniffer (window "Filters").

Default: OFF (everything is shown). Rules work per message type (tab): a rule with Type
GOOSE / SV / PTP only for that tab, a rule without Type for all tabs; a tab without an active rule
for its type shows everything. When ON a message is shown when it matches at least one active
rule of its type (OR between rules); inside a rule every filled field must match (AND), an empty
field matches everything. With no active rule only the simulation choice works.

Fields of a rule:
  kind   GOOSE / SV / PTP / (empty = all)
  net    1 / 2           lan  A / B / - (no PRP trailer)
  src, dst, ref, ied     text, case does not matter; * and ? are wildcards
                         (without a wildcard the text must be equal)
  appid  hex: 4011, 0x4011, 4000-4FFF, 1055,104F     (list and ranges)
  vlan   decimal: 27, 27-32, 101
Rules made by ticking a stream in the table "Streams seen" are exact (kind, net, LAN, src, dst, appid, ref).
Simulation: all / only simulated / without simulated messages.
The filter only changes what is shown: the capture, Retransmission and the counters stay.
A "STREAM LOST" line follows the filter of its stream.
"""
import fnmatch

FIELDS = ("kind", "net", "lan", "src", "dst", "appid", "vlan", "ref", "ied")
SIM_MODES = ("all", "only simulated", "without simulated")


def _ranges(spec, base):
    out = []
    for tok in str(spec).replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        a, _, b = tok.partition("-")
        try:
            lo = int(a.strip(), base)
            hi = int(b.strip(), base) if b.strip() else lo
        except ValueError:
            raise ValueError("bad number: %s" % tok)
        out.append((min(lo, hi), max(lo, hi)))
    return out


def _text(pat, val):
    pat = (pat or "").strip().lower()
    val = (val or "").lower()
    if any(c in pat for c in "*?["):
        return fnmatch.fnmatchcase(val, pat)
    return val == pat


class Rule:
    def __init__(self, d=None):
        d = d or {}
        self.on = bool(d.get("on", True))
        self.auto = bool(d.get("auto", False))
        self.f = {k: str(d.get(k, "") or "").strip() for k in FIELDS}
        self._appid = _ranges(self.f["appid"], 16) if self.f["appid"] else None
        self._vlan = _ranges(self.f["vlan"], 10) if self.f["vlan"] else None

    def to_dict(self):
        d = dict(self.f)
        d.update(on=self.on, auto=self.auto)
        return d

    def match(self, m, ied):
        f = self.f
        kind = m["stream"] if m["kind"] == "LOST" else m["kind"]
        if f["kind"] and f["kind"].upper() != kind:
            return False
        if f["net"] and f["net"] != str(m["net"]):
            return False
        if f["lan"] and f["lan"].upper() != ((m.get("lan") or "-").upper()):
            return False
        if f["src"] and not _text(f["src"], m["src"]):
            return False
        if f["dst"] and not _text(f["dst"], m["dst"]):
            return False
        if f["ref"] and not _text(f["ref"], m["ref"]):
            return False
        if f["ied"] and not _text(f["ied"], ied):
            return False
        if self._appid is not None and (m.get("appid") is None or not any(lo <= m["appid"] <= hi for lo, hi in self._appid)):
            return False
        if self._vlan is not None:
            if m["vlan"] is None or not any(lo <= m["vlan"] <= hi for lo, hi in self._vlan):
                return False
        return True

    def text(self):
        return "  ".join("%s=%s" % (k, v) for k, v in self.f.items() if v) or "(everything)"


class FilterSet:
    def __init__(self, d=None):
        d = d or {}
        self.enabled = bool(d.get("enabled", False))
        self.sim = d.get("sim", "all") if d.get("sim") in SIM_MODES else "all"
        self.rules = []
        for r in d.get("rules", []):
            try:
                self.rules.append(Rule(r))
            except ValueError:
                pass

    def to_dict(self):
        return dict(enabled=self.enabled, sim=self.sim, rules=[r.to_dict() for r in self.rules])

    def passes(self, m, ied=""):
        if not self.enabled:
            return True
        sim = bool(m.get("sim"))
        if self.sim == "only simulated" and not sim:
            return False
        if self.sim == "without simulated" and sim:
            return False
        kind = m["stream"] if m["kind"] == "LOST" else m["kind"]
        act = [r for r in self.rules if r.on and r.f["kind"] in ("", kind)]
        if not act:                                       # no rule for this type (tab): show everything
            return True
        return any(r.match(m, ied) for r in act)

    # ---- exact rule of one stream (table "Streams seen")
    @staticmethod
    def stream_rule(m):
        kind = m["stream"] if m["kind"] == "LOST" else m["kind"]
        return Rule(dict(kind=kind, net=str(m["net"]), lan=m.get("lan") or "-", src=m["src"], dst=m["dst"],
                         appid="" if m.get("appid") is None else "%04X" % m["appid"], ref=m["ref"], auto=True))

    def find_stream_rule(self, m):
        want = self.stream_rule(m).f
        for r in self.rules:
            if r.auto and r.f == want:
                return r
        return None

    def summary(self):
        if not self.enabled:
            return "Filter OFF"
        n = sum(1 for r in self.rules if r.on)
        s = "Filter ON: %d rule(s)" % n
        if self.sim != "all":
            s += ", " + self.sim
        return s
