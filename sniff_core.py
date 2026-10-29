# -*- coding: utf-8 -*-
"""
sniff_core.py - decoding of IEC 61850 GOOSE (EtherType 0x88B8) and Sampled Values
(9-2 / 9-2LE, EtherType 0x88BA) frames, streams, the Retransmission filter and the
"stream lost" events. No GUI here (author: German Ievgen).

Message = dict:
  kind      'GOOSE' | 'SV' | 'LOST'
  net       1 | 2 (network = adapter of the PC that received the frame)
  lan       'A' | 'B' from the PRP trailer (RCT) of the frame, '' = no PRP trailer
  ts        time stamp (s, float)
  src, dst  MAC 'AA:BB:CC:DD:EE:FF'
  appid     int,  vlan (VID or None), prio (int or None)
  ref       GOOSE: gocbRef,  SV: svID
  header    [(field, value text)]       - panel Details
  data      [(name, type, value text)]  - panel Data (GOOSE: data set entries, SV: channels)
  key       stream key (net, lan, src, dst, appid, ref)
  PTP       kind 'PTP' (see ptp.py): mtype, mname, domain, clock, port, seq, lmi, info; appid None
  sim       simulation: GOOSE simulation field or Reserved1 S bit, SV Reserved1 S bit
  samples   SV: [(smpCnt, (value ch1, ch2 ...))] of all ASDU of the frame (for the phasors)
  reason    why it is shown: 'first' | 'change' | 'all' | 'lost' | 'back'

Retransmission ON  : every frame is shown.
Retransmission OFF : GOOSE - the first frame of a stream, then only when a value or a quality
                     of the data set changed; SV - the first frame, then only when a quality
                     changed (values are ignored).
A stream is lost when nothing came for longer than TAL (GOOSE) / SV_LOST_S (SV): message
'LOST' (shown grey); the next frame of that stream is shown again ('back').
"""
import struct

import ptp

ETH_GOOSE = 0x88B8
ETH_SV = 0x88BA
ETH_VLAN = (0x8100, 0x88A8, 0x9100)
SV_LOST_S = 1.0          # SV stream lost after 1 s without frames
GOOSE_LOST_MIN_S = 0.0   # extra margin added to TAL (0 = exactly TAL)


# ---------------------------------------------------------------- helpers
def mac(b):
    return ":".join("%02X" % x for x in b)


def ber_len(b, p):
    """length of a BER TLV at p (p = first length byte) -> (length, position of the value)"""
    n = b[p]
    if n < 0x80:
        return n, p + 1
    k = n & 0x7F
    if k == 0 or k > 4:
        raise ValueError("BER length")
    return int.from_bytes(b[p + 1:p + 1 + k], "big"), p + 1 + k


def tlvs(b, p, end):
    """yields (tag, value start, value end) of the TLVs between p and end"""
    while p < end:
        tag = b[p]
        ln, v = ber_len(b, p + 1)
        e = v + ln
        if e > end:
            raise ValueError("BER overrun")
        yield tag, v, e
        p = e


def uint(b):
    return int.from_bytes(b, "big", signed=False) if b else 0


def sint(b):
    return int.from_bytes(b, "big", signed=True) if b else 0


def utc_time(b):
    """IEC 61850 UtcTime (8 bytes) -> 'YYYY-MM-DD hh:mm:ss.ffffff' + quality flags"""
    import datetime
    if len(b) != 8:
        return b.hex()
    sec = int.from_bytes(b[0:4], "big")
    frac = int.from_bytes(b[4:7], "big") / float(1 << 24)
    q = b[7]
    try:
        t = datetime.datetime.fromtimestamp(sec + frac, datetime.timezone.utc)
        s = t.strftime("%Y-%m-%d %H:%M:%S.%f")
    except (OverflowError, OSError, ValueError):
        s = "%d.%06d" % (sec, int(frac * 1e6))
    flags = []
    if q & 0x80:
        flags.append("LeapSecondsKnown")
    if q & 0x40:
        flags.append("ClockFailure")
    if q & 0x20:
        flags.append("ClockNotSynchronized")
    acc = q & 0x1F
    return s + " UTC" + (" [" + ", ".join(flags) + "]" if flags else "") + ("  acc %d" % acc if acc != 0x1F else "")


QUALITY_BITS = ["validity", "validity", "overflow", "outOfRange", "badReference", "oscillatory",
                "failure", "oldData", "inconsistent", "inaccurate", "substituted", "test",
                "operatorBlocked", "derived"]


def quality_text(bits, nbits=13):
    """IEC 61850 quality from a bit list (MSB first) -> 'good' / 'invalid, test' ..."""
    bits = list(bits) + [0] * 14
    v = (bits[0] << 1) | bits[1]
    out = {0: "good", 1: "invalid", 2: "reserved", 3: "questionable"}[v]
    extra = [QUALITY_BITS[i] for i in range(2, min(nbits, 14)) if bits[i]]
    return out + (", " + ", ".join(extra) if extra else "")


def bitstring(b):
    """MMS bit-string value (first byte = unused bits) -> (bits list, nbits)"""
    if not b:
        return [], 0
    unused = b[0]
    raw = b[1:]
    n = len(raw) * 8 - unused
    bits = [(raw[i // 8] >> (7 - i % 8)) & 1 for i in range(max(n, 0))]
    return bits, n


DBPOS = {"00": "intermediate (00)", "01": "off (01)", "10": "on (10)", "11": "bad (11)"}


# ---------------------------------------------------------------- MMS Data (GOOSE allData)
def mms_data(b, p, end, out, prefix=""):
    """decodes the MMS Data elements between p and end into out [(index name, type, value, raw)]"""
    i = 0
    for tag, v, e in tlvs(b, p, end):
        i += 1
        nm = "%s%d" % (prefix, i)
        val = b[v:e]
        if tag in (0xA2, 0xA1):                       # structure / array
            out.append((nm, "Structure" if tag == 0xA2 else "Array", "", val))
            mms_data(b, v, e, out, nm + ".")
            continue
        if tag == 0x83:
            out.append((nm, "Boolean", "TRUE" if (val and val[0]) else "FALSE", val))
        elif tag == 0x84:
            bits, n = bitstring(val)
            s = "".join(str(x) for x in bits)
            if n == 2:
                out.append((nm, "Dbpos", DBPOS.get(s, s), val))
            elif n == 13:
                out.append((nm, "Quality", "%s  (%s)" % (s, quality_text(bits)), val))
            else:
                out.append((nm, "Bitstring", s, val))
        elif tag == 0x85:
            out.append((nm, "Integer", str(sint(val)), val))
        elif tag == 0x86:
            out.append((nm, "Unsigned", str(uint(val)), val))
        elif tag == 0x87:
            if len(val) == 5:
                out.append((nm, "Float", "%g" % struct.unpack(">f", val[1:5])[0], val))
            elif len(val) == 9:
                out.append((nm, "Double", "%.10g" % struct.unpack(">d", val[1:9])[0], val))
            else:
                out.append((nm, "Float", val.hex(), val))
        elif tag == 0x89:
            out.append((nm, "OctetString", val.hex(), val))
        elif tag == 0x8A:
            out.append((nm, "VisibleString", val.decode("latin1", "replace"), val))
        elif tag == 0x90:
            out.append((nm, "MMSString", val.decode("utf-8", "replace"), val))
        elif tag == 0x91:
            out.append((nm, "Timestamp", utc_time(val), val))
        elif tag == 0x8C:
            out.append((nm, "BinaryTime", val.hex(), val))
        else:
            out.append((nm, "tag 0x%02X" % tag, val.hex(), val))
    return out


# ---------------------------------------------------------------- frame
def ether(frame):
    """-> (dst, src, vlan, prio, ethertype, payload offset) or None"""
    if len(frame) < 14:
        return None
    dst, src = frame[0:6], frame[6:12]
    et = int.from_bytes(frame[12:14], "big")
    p = 14
    vlan = prio = None
    while et in ETH_VLAN and len(frame) >= p + 4:
        tci = int.from_bytes(frame[p:p + 2], "big")
        if vlan is None:
            vlan, prio = tci & 0x0FFF, tci >> 13
        et = int.from_bytes(frame[p + 2:p + 4], "big")
        p += 4
    return dst, src, vlan, prio, et, p


def decode(frame, ts=0.0, net=1, full=True):
    """raw Ethernet frame -> message dict (or None if not GOOSE / SV).
    full=False: SV only header + qualities (fast path for the filter)"""
    e = ether(frame)
    if not e:
        return None
    dst, src, vlan, prio, et, p = e
    if et not in (ETH_GOOSE, ETH_SV):
        pp = ptp.find_ptp(frame, et, p)
        if pp is None:
            return None
        m = dict(kind="PTP", net=net, ts=ts, src=mac(src), dst=mac(dst), appid=None, vlan=vlan, prio=prio,
                 ref="", header=[], data=[], sig=b"", error="", sim=False)
        try:
            ptp.decode_ptp(frame, pp[0], pp[1], m, full)
        except Exception as ex:
            m["error"] = "decode error: %s" % ex
            m["header"].append(("Error", m["error"]))
            m.setdefault("mtype", -1)
            m.setdefault("mname", "?")
            m.setdefault("lost_s", 3.0)
            for k, v in (("clock", ""), ("port", 0), ("domain", 0), ("seq", 0), ("lmi", 0), ("flags", (0, 0)),
                         ("transport", pp[1]), ("info", "")):
                m.setdefault(k, v)
        m["lan"] = prp_lan(frame, m)
        m["key"] = (net, m["lan"], m["src"], m["dst"], "PTP", m["mtype"], m["ref"], m["domain"])
        return m
    if len(frame) < p + 8:
        return None
    appid = int.from_bytes(frame[p:p + 2], "big")
    length = int.from_bytes(frame[p + 2:p + 4], "big")
    end = min(len(frame), p + length) if length >= 8 else len(frame)
    res1 = int.from_bytes(frame[p + 4:p + 6], "big")
    m = dict(kind="GOOSE" if et == ETH_GOOSE else "SV", net=net, ts=ts, src=mac(src), dst=mac(dst),
             appid=appid, vlan=vlan, prio=prio, ref="", header=[], data=[], sig=None, error="",
             sim=bool(res1 & 0x8000), sim_bit=bool(res1 & 0x8000))   # Ed2: Reserved1 bit 15 = Simulate
    try:
        if et == ETH_GOOSE:
            _goose(frame, p + 8, end, m)
        else:
            _sv(frame, p + 8, end, m, full)
    except Exception as ex:                               # malformed frame: still shown
        m["error"] = "decode error: %s" % ex
        m["header"].append(("Error", m["error"]))
    if m["sig"] is not None and m["sim"]:
        m["sig"] = m["sig"] + b"|SIM"                     # simulation on / off = a change
    m["lan"] = prp_lan(frame, m)
    m["key"] = (net, m["lan"], m["src"], m["dst"], appid, m["ref"])
    return m


def prp_lan(frame, m=None):
    """PRP (IEC 62439-3) redundancy control trailer at the end of the frame:
    SeqNr (2) | LanId (4 bit: 0xA / 0xB) + LSDU size (12 bit) | suffix 0x88FB.
    -> 'A' / 'B', or '' when the frame has no RCT (SAN, not PRP, or the RedBox removed it)"""
    if len(frame) < 30 or frame[-2:] != b"\x88\xfb":
        return ""
    w = int.from_bytes(frame[-4:-2], "big")
    lid, size = w >> 12, w & 0x0FFF
    if lid not in (0xA, 0xB):
        return ""
    lan = "A" if lid == 0xA else "B"
    if m is not None:
        seq = int.from_bytes(frame[-6:-4], "big")
        # LSDU size = bytes after the source MAC up to the end (with RCT); with or without VLAN tag
        ok = size in (len(frame) - 12, len(frame) - 16)
        m["header"].append(("PRP LAN", "%s   (sequence %d, LSDU size %d%s)" % (lan, seq, size, "" if ok else " - does not match the frame")))
    return lan


def _goose(b, p, end, m):
    if b[p] != 0x61:
        raise ValueError("no goosePdu")
    ln, v = ber_len(b, p + 1)
    H = m["header"]
    f = {}
    for tag, s, e in tlvs(b, v, min(v + ln, end)):
        val = b[s:e]
        if tag == 0x80:
            f["gocbRef"] = val.decode("latin1", "replace")
        elif tag == 0x81:
            f["tal"] = uint(val)
        elif tag == 0x82:
            f["datSet"] = val.decode("latin1", "replace")
        elif tag == 0x83:
            f["goID"] = val.decode("latin1", "replace")
        elif tag == 0x84:
            f["t"] = utc_time(val)
        elif tag == 0x85:
            f["stNum"] = uint(val)
        elif tag == 0x86:
            f["sqNum"] = uint(val)
        elif tag == 0x87:
            f["simulation"] = bool(val and val[0])
        elif tag == 0x88:
            f["confRev"] = uint(val)
        elif tag == 0x89:
            f["ndsCom"] = bool(val and val[0])
        elif tag == 0x8A:
            f["num"] = uint(val)
        elif tag == 0xAB:
            data = []
            mms_data(b, s, e, data)
            m["data"] = data
            # signature of the values + qualities (top level entries and structures)
            m["sig"] = b[s:e]
    m["ref"] = f.get("gocbRef", "")
    m["tal"] = f.get("tal", 0)
    m["confRev"] = f.get("confRev")
    m["sim"] = m["sim"] or bool(f.get("simulation"))
    m["stNum"], m["sqNum"] = f.get("stNum"), f.get("sqNum")
    H += [("Control Block reference", f.get("gocbRef", "")),
          ("Destination MAC address", m["dst"]), ("Source MAC address", m["src"]),
          ("Application ID", "%d (0x%04X)" % (m["appid"], m["appid"])),
          ("GOOSE ID", f.get("goID", "")), ("DataSet reference", f.get("datSet", "")),
          ("VLAN ID", "" if m["vlan"] is None else "%d (0x%03X)" % (m["vlan"], m["vlan"])),
          ("VLAN priority", "" if m["prio"] is None else str(m["prio"])),
          ("Needs commissioning", str(f.get("ndsCom", "")).lower()),
          ("Configuration revision", str(f.get("confRev", ""))),
          ("Simulation/Test", str(f.get("simulation", "")).lower()),
          ("Simulate bit (Reserved1)", "true" if m["sim_bit"] else "false"),
          ("Entry time", f.get("t", "")),
          ("Status number", str(f.get("stNum", ""))),
          ("Sequence number", str(f.get("sqNum", ""))),
          ("Time allowed to live (ms)", str(f.get("tal", ""))),
          ("Number of DataSet entries", str(f.get("num", "")))]


def _sv(b, p, end, m, full):
    if b[p] != 0x60:
        raise ValueError("no savPdu")
    ln, v = ber_len(b, p + 1)
    asdus = []
    for tag, s, e in tlvs(b, v, min(v + ln, end)):
        if tag == 0xA2:                                    # seqASDU
            for t2, s2, e2 in tlvs(b, s, e):
                if t2 == 0x30:
                    asdus.append((s2, e2))
    H = m["header"]
    qsig = []
    m["samples"] = []                                      # [(smpCnt, (value ch1, ch2 ...))] of all ASDU
    for k, (s, e) in enumerate(asdus):
        f = {}
        for tag, a, z in tlvs(b, s, e):
            val = b[a:z]
            if tag == 0x80:
                f["svID"] = val.decode("latin1", "replace")
            elif tag == 0x81:
                f["datSet"] = val.decode("latin1", "replace")
            elif tag == 0x82:
                f["smpCnt"] = uint(val)
            elif tag == 0x83:
                f["confRev"] = uint(val)
            elif tag == 0x84:
                f["refrTm"] = utc_time(val)
            elif tag == 0x85:
                f["smpSynch"] = uint(val)
            elif tag == 0x86:
                f["smpRate"] = uint(val)
            elif tag == 0x87:
                f["seq"] = val
            elif tag == 0x88:
                f["smpMod"] = uint(val)
            elif tag == 0x89:
                f["gmIdentity"] = ptp.clock_id(val)
        seq = f.get("seq", b"")
        qsig.append(b"".join(seq[i + 4:i + 8] for i in range(0, len(seq) - 7, 8)))   # qualities
        nch = len(seq) // 8
        if nch and f.get("smpCnt") is not None:
            m["samples"].append((f["smpCnt"], struct.unpack_from(">" + "iI" * nch, seq)[0::2]))
        if k == 0:
            m["ref"] = f.get("svID", "")
            m["smpCnt"] = f.get("smpCnt")
            m["confRev"], m["smpRate"], m["nch"] = f.get("confRev"), f.get("smpRate"), len(seq) // 8
            m["gmIdentity"] = f.get("gmIdentity")
            synch = f.get("smpSynch")
            H += [("svID", f.get("svID", "")),
                  ("Destination MAC address", m["dst"]), ("Source MAC address", m["src"]),
                  ("Application ID", "%d (0x%04X)" % (m["appid"], m["appid"])),
                  ("DataSet reference", f.get("datSet", "")),
                  ("VLAN ID", "" if m["vlan"] is None else "%d (0x%03X)" % (m["vlan"], m["vlan"])),
                  ("VLAN priority", "" if m["prio"] is None else str(m["prio"])),
                  ("Number of ASDU", str(len(asdus))),
                  ("Sample count", str(f.get("smpCnt", ""))),
                  ("Configuration revision", str(f.get("confRev", ""))),
                  ("Synchronization (smpSynch)", {0: "0 - none", 1: "1 - local", 2: "2 - global"}.get(synch, str(synch) if synch is not None else "")),
                  ("Sample rate (smpRate)", str(f.get("smpRate", ""))),
                  ("Sample mode (smpMod)", str(f.get("smpMod", ""))),
                  ("Refresh time", f.get("refrTm", "")),
                  ("Grandmaster identity (gmIdentity)", f.get("gmIdentity") or "- (not in the frame)"),
                  ("Simulate bit (Reserved1)", "true" if m["sim_bit"] else "false")]
            if full:
                n = len(seq) // 8
                for i in range(n):
                    raw = seq[i * 8:i * 8 + 8]
                    val = sint(raw[0:4])
                    qv = int.from_bytes(raw[4:8], "big")
                    bits = [(qv >> (31 - j)) & 1 for j in range(14)]
                    # 9-2LE: 4 currents (1 mA) then 4 voltages (10 mV)
                    if n == 8:
                        unit = ("%.3f A" % (val * 0.001)) if i < 4 else ("%.2f V" % (val * 0.01))
                        nm = ("Ia", "Ib", "Ic", "In", "Va", "Vb", "Vc", "Vn")[i]
                    else:
                        unit, nm = str(val), "Ch %d" % (i + 1)
                    m["data"].append((nm, "INT32 + q", "%s   (raw %d)" % (unit, val), raw))
                    m["data"].append((nm + ".q", "Quality", "0x%08X  (%s)" % (qv, quality_text(bits, 14)), raw[4:8]))
    m["sig"] = b"|".join(qsig)                             # qualities only


# ---------------------------------------------------------------- streams + filter
class Tracker:
    """streams, Retransmission filter and lost streams"""

    def __init__(self):
        self.retrans = {"GOOSE": False, "SV": False, "PTP": False}
        self.streams = {}            # key -> dict(kind, last ts, sig, tal, lost, ref ...)
        self.captured = {"GOOSE": 0, "SV": 0, "PTP": 0}
        self.shown = {"GOOSE": 0, "SV": 0, "PTP": 0}

    def reset(self):
        self.streams.clear()
        self.captured = {"GOOSE": 0, "SV": 0, "PTP": 0}
        self.shown = {"GOOSE": 0, "SV": 0, "PTP": 0}

    def feed(self, m):
        """a decoded message -> list of messages to show (lost events of other streams are
        produced by check(); a lost stream that comes back gives 'back')"""
        k = m["key"]
        kind = m["kind"]
        self.captured[kind] += 1
        st = self.streams.get(k)
        out = []
        if st is None:
            st = self.streams[k] = dict(kind=kind, last=m["ts"], sig=m["sig"], lost=False,
                                        tal=m.get("tal", 0), m=m, n=1, first=m["ts"], lost_s=m.get("lost_s"))
            m["reason"] = "first"
            out.append(m)
        else:
            changed = m["sig"] != st["sig"]
            if st["lost"]:
                m["reason"] = "back"
                out.append(m)
            elif self.retrans[kind]:
                m["reason"] = "change" if changed else "all"
                out.append(m)
            elif changed:
                m["reason"] = "change"
                out.append(m)
            st.update(last=m["ts"], sig=m["sig"], lost=False, tal=m.get("tal", st["tal"]), m=m,
                      lost_s=m.get("lost_s", st.get("lost_s")))
            st["n"] += 1
        self.shown[kind] += len(out)
        return out

    def check(self, now):
        """lost streams at the time now -> list of 'LOST' messages (once per loss)"""
        out = []
        for k, st in self.streams.items():
            if st["lost"]:
                continue
            if st["kind"] == "GOOSE":
                limit = (st["tal"] or 0) / 1000.0 + GOOSE_LOST_MIN_S
                if limit <= 0:
                    limit = 2.0
            elif st["kind"] == "PTP":
                limit = st.get("lost_s") or 3.0
            else:
                limit = SV_LOST_S
            gap = now - st["last"]
            if gap > limit:
                st["lost"] = True
                last = st["m"]
                lm = dict(kind="LOST", stream=st["kind"], net=last["net"], lan=last.get("lan", ""), sim=last.get("sim", False), ts=st["last"] + limit,
                          src=last["src"], dst=last["dst"], appid=last["appid"], vlan=last["vlan"],
                          prio=last["prio"], ref=last["ref"], key=k, reason="lost", data=[], error="",
                          header=[("Event", "STREAM LOST"),
                                  ("Stream", "%s  %s" % (st["kind"], last["ref"])),
                                  ("PRP LAN", last.get("lan") or "-"),
                                  ("Last message", "%.6f" % st["last"]),
                                  ("Limit", ("TAL %d ms" % st["tal"]) if st["kind"] == "GOOSE" else "%.1f s without frames" % limit)])
                if st["kind"] == "PTP":
                    for k2 in ("mtype", "mname", "domain", "clock", "port", "seq", "lmi", "flags", "info", "transport"):
                        lm[k2] = last.get(k2)
                    lm["info"] = ""
                self.shown[st["kind"]] += 1
                out.append(lm)
        return out
