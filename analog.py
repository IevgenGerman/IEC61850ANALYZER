# -*- coding: utf-8 -*-
"""
analog.py - RMS, angle and frequency of Sampled Values streams (panel "Phasors").

Every SV frame gives its samples (smpCnt + one INT32 per channel) to a ring buffer of its
stream. On request (every 0.5 s for the selected stream) a one-period DFT is calculated:

  N   = samples per period (smpRate of the frame, else of the SCL control block, else from the
        smpCnt wrap: (max smpCnt + 1) / f nominal, else 80 = 9-2LE protection stream)
  X   = 2/N * sum x[n] * e^(-j 2 pi n / N)            fundamental phasor, last N samples
  RMS = |X| / sqrt 2,  True RMS = sqrt(mean x^2)
  angle relative to the reference channel: chosen in the panel (Angle reference), or Auto = first
  voltage with signal, else first current
  f   = f nom * (1 + d phi / 2 pi), d phi = angle change of the reference channel between the
        two last periods

Units (primary, 9-2LE): current 1 mA, voltage 10 mV per bit. Channel kind (I / U) from the SCL
(TCTR / TVTR), else 9-2LE order: 4 currents, 4 voltages.
Secondary values = primary / Rat (TCTR / TVTR Rat.setMag.f of the channel). No value (dash)
without a matching SCL. Only when the stream matches an SCL SampledValueControl: svID = smvID, destination MAC, APPID, confRev and
number of channels (VLAN only gives a warning: some network cards remove the VLAN tag).
"""
import math
from collections import deque

BUF = 2048                 # samples kept per stream (>= 2 periods of 256 samples per period)
F_DEFAULT = 50.0
SCALE = {"I": 0.001, "U": 0.01}
UNIT = {"I": "A", "U": "V"}


def scales(nch, cb, secondary):
    """per channel (kind, factor, unit) for raw -> A / V. factor None = no value (only raw):
       primary  : SCL control block matches -> kind from SCL; else 9-2LE (8 channels) -> 4 I + 4 U;
                  other streams without a matching SCL -> None (scale unknown)
       secondary: only with a matching SCL control block and its Rat: primary / Rat; else None"""
    out = []
    for ch in range(nch):
        c = cb["chans"][ch] if cb and ch < len(cb["chans"]) else None
        if c is not None:
            kind = c["kind"]
        elif nch == 8 and not cb:
            kind = "I" if ch < 4 else "U"
        else:
            kind = ""
        f = SCALE.get(kind)
        if f is not None and secondary:
            f = (f / c["rat"]) if (cb and c and c.get("rat")) else None
        out.append((kind, f, UNIT.get(kind, "")))
    return out


def stream_info(m):
    """stream data of one SV message (for match() without a buffer)"""
    return dict(svid=m.get("ref"), dst=m["dst"], appid=m["appid"], vlan=m["vlan"], confRev=m.get("confRev"),
                nch=m.get("nch"), smpRate=m.get("smpRate"))


class Phasors:
    def __init__(self):
        self.buf = {}       # stream key -> deque of (smpCnt, values)
        self.info = {}      # stream key -> dict(svid, dst, appid, vlan, confRev, smpRate, nch, maxcnt, wrap, frames, last ts)
        self._tab = {}      # N -> (cos, sin)

    def reset(self):
        self.buf.clear()
        self.info.clear()

    # ------------------------------------------------------------ feed (capture thread, under the app lock)
    def feed(self, m):
        smp = m.get("samples")
        if not smp:
            return
        k = m["key"]
        d = self.buf.get(k)
        if d is None:
            d = self.buf[k] = deque(maxlen=BUF)
            self.info[k] = dict(maxcnt=0, wrap=False, frames=0)
        inf = self.info[k]
        last = d[-1][0] if d else None
        for cnt, vals in smp:
            if cnt == last:                               # the same sample twice (loopback, mirror port)
                continue
            if last is not None and cnt < last:
                inf["wrap"] = inf["wrap"] or (last > 100 and cnt < 5)
            if cnt > inf["maxcnt"]:
                inf["maxcnt"] = cnt
            last = cnt
            d.append((cnt, vals))
        inf.update(svid=m["ref"], dst=m["dst"], appid=m["appid"], vlan=m["vlan"], confRev=m.get("confRev"),
                   smpRate=m.get("smpRate"), nch=m.get("nch") or len(smp[0][1]), ts=m["ts"])
        inf["frames"] += 1

    # ------------------------------------------------------------ SCL match
    @staticmethod
    def match(inf, scl):
        """-> (control block or None, problems [text], warnings [text]); problems = no secondary"""
        cb, p, w = Phasors.best(inf, scl)
        if cb is None:
            return None, p, w
        return (cb if not p else None), (["%s/%s (%s): %s" % (cb["ied"], cb["cb"], cb["file"], x) for x in p]), w

    @staticmethod
    def best(inf, scl):
        """best SCL control block for the stream (also when it does not match) -> (cb, problems, warnings).
        Several SCL can have the same smvID (e.g. the subscriber copy in a protection CID): the one
        with the fewest differences, then with CT / VT ratios, wins."""
        cands = (scl.sv_cb.get(inf.get("svid")) if scl else None) or []
        if not scl:
            return None, ["no SCD / CID loaded"], []
        if not cands:
            return None, ["svID %s is not in the loaded SCL (smvID)" % inf.get("svid")], []
        best = None
        for cb in cands:
            p, w = [], []
            if not cb.get("mac"):
                p.append("no SMV address (MAC / APPID) for %s/%s in the SCL" % (cb["ied"], cb["cb"]))
            else:
                if (inf.get("dst") or "").upper() != cb["mac"]:
                    p.append("MAC %s, SCL %s" % (inf.get("dst"), cb["mac"]))
                if cb.get("appid") is not None and inf.get("appid") != cb["appid"]:
                    p.append("APPID 0x%04X, SCL 0x%04X" % (inf.get("appid"), cb["appid"]))
            if cb.get("confRev") is not None and inf.get("confRev") is not None and inf["confRev"] != cb["confRev"]:
                p.append("confRev %s, SCL %s" % (inf["confRev"], cb["confRev"]))
            if inf.get("nch") and len(cb["chans"]) != inf["nch"]:
                p.append("%d channels, SCL data set %d" % (inf["nch"], len(cb["chans"])))
            if inf.get("smpRate") and cb.get("smpRate") and inf["smpRate"] != cb["smpRate"]:
                p.append("smpRate %s, SCL %s" % (inf["smpRate"], cb["smpRate"]))
            if cb.get("vlan") is not None and inf.get("vlan") is not None and inf["vlan"] != cb["vlan"]:
                w.append("VLAN %s, SCL %s" % (inf["vlan"], cb["vlan"]))
            if cb.get("vlan") and inf.get("vlan") is None:
                w.append("no VLAN tag in the frames (SCL VLAN %s) - removed by the network card?" % cb["vlan"])
            if not p:
                miss = [c["name"] for c in cb["chans"] if c["kind"] and not c.get("rat")]
                if miss:
                    w.append("no Rat.setMag.f for: " + ", ".join(miss))
            score = (len(p), -sum(1 for c in cb["chans"] if c.get("rat")))
            if best is None or score < best[0]:
                best = (score, cb, p, w)
        return best[1], best[2], best[3]

    # ------------------------------------------------------------ calculation
    def _cs(self, n):
        t = self._tab.get(n)
        if t is None:
            t = self._tab[n] = ([math.cos(2 * math.pi * i / n) for i in range(n)],
                                [math.sin(2 * math.pi * i / n) for i in range(n)])
        return t

    @staticmethod
    def _contiguous(d, wrap):
        """newest part of the buffer with consecutive smpCnt"""
        out = [d[-1]]
        for i in range(len(d) - 2, -1, -1):
            c, nxt = d[i][0], out[-1][0]
            if c + 1 == nxt or (nxt == 0 and wrap and c >= 1):
                out.append(d[i])
            else:
                break
        out.reverse()
        return out

    def compute(self, key, scl=None, secondary=False, ref=None):
        """-> dict(ok, text, rows [(ch, name, kind, rms, angle, true rms, unit text, ratio)], freq, spp,
        match, problems, warnings) or None if the stream has no samples"""
        d = self.buf.get(key)
        inf = self.info.get(key)
        if not d or not inf:
            return None
        cb, problems, warnings = self.match(inf, scl)
        chans = cb["chans"] if cb else None
        # samples per period
        fnom = None
        if cb:
            fnom = next((c["hz"] for c in cb["chans"] if c.get("hz")), None)
        fnom = fnom or F_DEFAULT
        if inf.get("smpRate"):
            spp, how = int(inf["smpRate"]), "smpRate of the frames"
        elif cb and cb.get("smpRate"):
            spp, how = int(cb["smpRate"]), "smpRate of the SCL control block"
        elif inf.get("wrap") and inf["maxcnt"] > 0:
            spp, how = int(round((inf["maxcnt"] + 1) / fnom)), "smpCnt wraps at %d" % (inf["maxcnt"] + 1)
        else:
            spp, how = 80, "assumed (9-2LE)"
        try:
            snap = list(d)
        except RuntimeError:
            return None
        part = self._contiguous(snap, inf.get("wrap"))
        nch = len(part[-1][1])
        res = dict(ok=False, rows=[], freq=None, spp=spp, spp_how=how, fnom=fnom, cb=cb, problems=problems,
                   warnings=warnings, secondary=bool(secondary), frames=inf["frames"], text="")
        if spp < 4 or len(part) < spp:
            res["text"] = "collecting samples: %d of %d (one period)" % (len(part), spp)
            return res
        cos, sin = self._cs(spp)
        win2 = part[-spp:]
        win1 = part[-2 * spp:-spp] if len(part) >= 2 * spp else None
        ph = []
        for ch in range(nch):
            x = [s[1][ch] for s in win2]
            re = sum(a * c for a, c in zip(x, cos)) * 2.0 / spp
            im = -sum(a * s for a, s in zip(x, sin)) * 2.0 / spp
            tr = math.sqrt(sum(a * a for a in x) / spp)
            ph.append((complex(re, im), tr))
        # kinds and scaling (factor None -> no value, see scales())
        rows = []
        for ch, (kind, fac, unit) in enumerate(scales(nch, cb, secondary)):
            c = chans[ch] if chans and ch < len(chans) else None
            if not c and scl:                             # names only (stream not matched)
                nm = scl.sv_name(inf.get("svid"), ch)
            else:
                nm = c["name"] if c else ""
            rows.append(dict(ch=ch, name=nm, kind=kind, X=ph[ch][0], raw=abs(ph[ch][0]), fac=fac,
                             tr=None if fac is None else ph[ch][1] * fac, unit=unit,
                             rat=c.get("rat") if c else None))
        # reference channel for the angles + frequency
        def first(kind):                                 # first channel with >= 1 % of the biggest of its kind
            big = max([r["raw"] for r in rows if r["kind"] == kind] or [0.0])
            return next((r for r in rows if r["kind"] == kind and big > 10 and r["raw"] >= 0.01 * big), None)
        auto = first("U") or first("I") or first("")
        if ref is not None and 0 <= ref < len(rows):
            if rows[ref]["raw"] > 10:
                auto = rows[ref]
            else:
                res["ref_note"] = "Angle reference: channel %d has no signal - Auto is used" % (ref + 1)
        ref = auto
        a0 = math.atan2(ref["X"].imag, ref["X"].real) if ref else 0.0
        for r in rows:
            mag = None if r["fac"] is None else abs(r["X"]) * r["fac"] / math.sqrt(2)
            ang = None
            if ref and r["raw"] > 10:
                ang = math.degrees(math.atan2(r["X"].imag, r["X"].real) - a0)
                ang = (ang + 180.0) % 360.0 - 180.0
            r.update(rms=mag, ang=ang)
        res["ref"] = ref["ch"] if ref else None
        if ref and win1:
            x = [s[1][ref["ch"]] for s in win1]
            re = sum(a * c for a, c in zip(x, cos))
            im = -sum(a * s for a, s in zip(x, sin))
            p1 = math.atan2(im, re)
            p2 = math.atan2(ph[ref["ch"]][0].imag, ph[ref["ch"]][0].real)
            dphi = (p2 - p1 + math.pi) % (2 * math.pi) - math.pi
            f = fnom * (1.0 + dphi / (2 * math.pi))
            res["freq"] = f
        res["rows"] = rows
        res["ok"] = True
        return res


def fmt(v, unit):
    """value with k prefix: 63508.5 V -> 63.509 kV"""
    if v is None:
        return "\u2014"
    if abs(v) < 1e-9:
        v = 0.0
    if unit in ("A", "V") and abs(v) >= 1000:
        return "%.3f k%s" % (v / 1000.0, unit)
    if unit in ("A", "V"):
        return ("%.4f %s" % (v, unit)) if abs(v) < 1 else "%.3f %s" % (v, unit)
    return "%.0f" % v
