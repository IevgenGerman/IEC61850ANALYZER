# -*- coding: utf-8 -*-
"""
ptp.py - IEEE 1588 / PTPv2 (IEC 61850-9-3 power utility profile, IEEE C37.238) for the sniffer.

Transport: Ethernet (EtherType 0x88F7, 9-3 / C37.238) and UDP over IPv4 (ports 319 event /
320 general, default 1588 profile - not 9-3).
  01:1B:19:00:00:00   Sync, Follow_Up, Announce, Delay_Req ... (forwarded by switches)
  01:80:C2:00:00:0E   Pdelay_Req / Pdelay_Resp / Pdelay_Resp_Follow_Up (only between neighbours)

decode_ptp() fills a message dict like the GOOSE / SV messages (kind 'PTP'):
  mtype, mname, domain, version, flags, corr (ns), clock (clockIdentity), port, seq, lmi
  (logMessageInterval), ref ('<clockIdentity>-<port>'), header [(field, value)],
  data = TLVs, sig (for the Retransmission filter: Announce data set + flags), lost_s (stream lost
  after 3 message intervals), ann (Announce data set), gm_text ...
PtpState collects per clock (sourcePortIdentity) what was seen: Announce data set, message types
and intervals, domains, transport, destination MAC -> panel "Clocks": best master (BMCA),
warnings and a check against IEC 61850-9-3.

The time stamps of the PC (Npcap) are software time stamps (~ms): the sniffer can not measure the
offset / accuracy of PTP, only show what the clocks announce.
"""
import struct
from collections import deque

ETH_PTP = 0x88F7
MAC_PTP = "01:1B:19:00:00:00"
MAC_PDELAY = "01:80:C2:00:00:0E"

MTYPES = {0x0: "Sync", 0x1: "Delay_Req", 0x2: "Pdelay_Req", 0x3: "Pdelay_Resp", 0x8: "Follow_Up",
          0x9: "Delay_Resp", 0xA: "Pdelay_Resp_Follow_Up", 0xB: "Announce", 0xC: "Signaling",
          0xD: "Management"}
PDELAY = (0x2, 0x3, 0xA)

CLOCK_CLASS = {6: "6 - locked to primary reference (GPS)", 7: "7 - holdover (was locked, in spec)",
               13: "13 - locked to app. specific time", 14: "14 - holdover (app. specific)",
               52: "52 - degraded A", 58: "58 - degraded A (app. specific)",
               135: "135 - holdover (C37.238 / 9-3)", 140: "140 - holdover, degraded",
               150: "150 - holdover, degraded", 160: "160 - holdover, degraded",
               165: "165 - not locked (app. specific)", 187: "187 - degraded B",
               193: "193 - degraded B (app. specific)", 248: "248 - default (free running)",
               255: "255 - slave only"}
TIME_SOURCE = {0x10: "ATOMIC_CLOCK", 0x20: "GPS (GNSS)", 0x30: "TERRESTRIAL_RADIO", 0x39: "SERIAL_TIME_CODE",
               0x40: "PTP", 0x50: "NTP", 0x60: "HAND_SET", 0x90: "OTHER", 0xA0: "INTERNAL_OSCILLATOR"}
ACCURACY = {0x17: "1 ps", 0x18: "2.5 ps", 0x19: "10 ps", 0x1A: "25 ps", 0x1B: "100 ps", 0x1C: "250 ps",
            0x1D: "1 ns", 0x1E: "2.5 ns", 0x1F: "10 ns", 0x20: "25 ns", 0x21: "100 ns", 0x22: "250 ns",
            0x23: "1 us", 0x24: "2.5 us", 0x25: "10 us", 0x26: "25 us", 0x27: "100 us", 0x28: "250 us",
            0x29: "1 ms", 0x2A: "2.5 ms", 0x2B: "10 ms", 0x2C: "25 ms", 0x2D: "100 ms", 0x2E: "250 ms",
            0x2F: "1 s", 0x30: "10 s", 0x31: "> 10 s", 0xFE: "unknown"}
TLV_TYPES = {0x0001: "MANAGEMENT", 0x0002: "MANAGEMENT_ERROR_STATUS", 0x0003: "ORGANIZATION_EXTENSION",
             0x0004: "REQUEST_UNICAST_TRANSMISSION", 0x0008: "PATH_TRACE", 0x0009: "ALTERNATE_TIME_OFFSET_INDICATOR"}
FLAGS0 = [(0x01, "alternateMaster"), (0x02, "twoStep"), (0x04, "unicast"), (0x20, "profileSpecific1"),
          (0x40, "profileSpecific2"), (0x80, "security")]
FLAGS1 = [(0x01, "leap61"), (0x02, "leap59"), (0x04, "currentUtcOffsetValid"), (0x08, "ptpTimescale"),
          (0x10, "timeTraceable"), (0x20, "frequencyTraceable"), (0x40, "synchronizationUncertain")]


def clock_id(b):
    return ":".join("%02X" % x for x in b)


def ts10(b):
    """PTP Timestamp (48 bit s + 32 bit ns) -> text"""
    import datetime
    sec = int.from_bytes(b[0:6], "big")
    ns = int.from_bytes(b[6:10], "big")
    try:
        t = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        t = str(sec)
    return "%s.%09d (PTP / TAI s %d)" % (t, ns, sec), sec + ns * 1e-9


def interval_text(lmi):
    if lmi == 0x7F or lmi == 127:
        return "127 (not used)"
    return "%d (%g s)" % (lmi, 2.0 ** lmi)


def flags_text(f0, f1):
    on = [n for b, n in FLAGS0 if f0 & b] + [n for b, n in FLAGS1 if f1 & b]
    return ", ".join(on) if on else "-"


def mac_to_clock(mac):
    """EUI-64 clock identity usually = MAC with FF:FE in the middle"""
    p = mac.split(":")
    return ":".join(p[:3] + ["FF", "FE"] + p[3:]) if len(p) == 6 else ""


# ---------------------------------------------------------------- frame
def find_ptp(frame, et, p):
    """-> (payload offset, transport text) of a PTP message or None. Ethernet 0x88F7 or IPv4/UDP 319/320"""
    if et == ETH_PTP:
        return p, "Ethernet (L2)"
    if et == 0x0800 and len(frame) >= p + 28:
        ihl = (frame[p] & 0x0F) * 4
        if frame[p + 9] != 17:
            return None
        u = p + ihl
        if len(frame) < u + 8:
            return None
        dport = int.from_bytes(frame[u + 2:u + 4], "big")
        if dport in (319, 320):
            src = ".".join(str(x) for x in frame[p + 12:p + 16])
            dst = ".".join(str(x) for x in frame[p + 16:p + 20])
            return u + 8, "UDP/IPv4 %s -> %s port %d" % (src, dst, dport)
    return None


def decode_ptp(frame, p, transport, m, full=True):
    b = frame
    if len(b) < p + 34:
        raise ValueError("PTP header too short")
    mt = b[p] & 0x0F
    tsp = b[p] >> 4
    ver = b[p + 1] & 0x0F
    mlen = int.from_bytes(b[p + 2:p + 4], "big")
    dom = b[p + 4]
    f0, f1 = b[p + 6], b[p + 7]
    corr = int.from_bytes(b[p + 8:p + 16], "big", signed=True) / 65536.0
    cid = clock_id(b[p + 20:p + 28])
    port = int.from_bytes(b[p + 28:p + 30], "big")
    seq = int.from_bytes(b[p + 30:p + 32], "big")
    lmi = struct.unpack(">b", b[p + 33:p + 34])[0]
    end = min(len(b), p + mlen) if mlen >= 34 else len(b)
    name = MTYPES.get(mt, "type 0x%X" % mt)
    m.update(mtype=mt, mname=name, domain=dom, version=ver, flags=(f0, f1), corr=corr, clock=cid, port=port,
             seq=seq, lmi=lmi, transport=transport, ref="%s-%d" % (cid, port), appid=None)
    H = m["header"]
    H += [("Message type", "%s (0x%X)" % (name, mt)),
          ("Transport", transport),
          ("Destination MAC address", m["dst"]), ("Source MAC address", m["src"]),
          ("VLAN ID", "" if m["vlan"] is None else "%d (0x%03X)" % (m["vlan"], m["vlan"])),
          ("VLAN priority", "" if m["prio"] is None else str(m["prio"])),
          ("PTP version", str(ver)), ("transportSpecific / majorSdoId", str(tsp)),
          ("Message length", str(mlen)), ("Domain", str(dom)),
          ("Flags", "0x%02X%02X  %s" % (f0, f1, flags_text(f0, f1))),
          ("Correction field", "%.3f ns" % corr),
          ("Source clock identity", cid), ("Source port", str(port)),
          ("Sequence ID", str(seq)), ("Log message interval", interval_text(lmi))]
    info = ""
    sig = bytes([f0, f1, dom])
    q = p + 34
    if mt in (0x0, 0x1, 0x2, 0x8, 0x9, 0x3, 0xA, 0xB) and len(b) >= q + 10:
        tname = {0x0: "Origin timestamp", 0x1: "Origin timestamp", 0x2: "Origin timestamp",
                 0x8: "Precise origin timestamp", 0x9: "Receive timestamp", 0x3: "Request receipt timestamp",
                 0xA: "Response origin timestamp", 0xB: "Origin timestamp"}[mt]
        txt, secs = ts10(b[q:q + 10])
        H.append((tname, txt))
        m["ptp_time"] = secs
        if mt == 0x0 and f0 & 0x02:
            info = "two-step: time in Follow_Up"
        elif mt in (0x0, 0x8):
            info = txt.split(" (")[0]
    if mt in (0x9, 0x3, 0xA) and len(b) >= q + 20:
        rp = "%s-%d" % (clock_id(b[q + 10:q + 18]), int.from_bytes(b[q + 18:q + 20], "big"))
        H.append(("Requesting port identity", rp))
        info = "for " + rp
    tlv_from = None
    if mt == 0xB and len(b) >= q + 30:
        a = dict(utc=struct.unpack(">h", b[q + 10:q + 12])[0], p1=b[q + 13], cls=b[q + 14], acc=b[q + 15],
                 var=int.from_bytes(b[q + 16:q + 18], "big"), p2=b[q + 18], gm=clock_id(b[q + 19:q + 27]),
                 steps=int.from_bytes(b[q + 27:q + 29], "big"), src=b[q + 29], domain=dom, flags=(f0, f1))
        m["ann"] = a
        H += [("Current UTC offset", "%d s%s" % (a["utc"], "" if f1 & 0x04 else "  (not valid)")),
              ("Grandmaster priority 1", str(a["p1"])),
              ("Grandmaster clock class", CLOCK_CLASS.get(a["cls"], str(a["cls"]))),
              ("Grandmaster clock accuracy", "0x%02X  %s" % (a["acc"], ACCURACY.get(a["acc"], ""))),
              ("Grandmaster offsetScaledLogVariance", "0x%04X" % a["var"]),
              ("Grandmaster priority 2", str(a["p2"])),
              ("Grandmaster identity", a["gm"]),
              ("Steps removed", str(a["steps"])),
              ("Time source", "0x%02X  %s" % (a["src"], TIME_SOURCE.get(a["src"], "")))]
        sig = b[q + 10:q + 30] + bytes([f0, f1, dom])
        info = "GM %s  class %d  prio %d/%d  steps %d  %s" % (a["gm"], a["cls"], a["p1"], a["p2"], a["steps"],
                                                               TIME_SOURCE.get(a["src"], "0x%02X" % a["src"]))
        tlv_from = q + 30
    elif mt in (0x9, 0x3, 0xA):
        tlv_from = q + 20
    elif mt in (0x0, 0x1, 0x2, 0x8):
        tlv_from = q + (20 if mt == 0x2 else 10)
    elif mt in (0xC, 0xD):
        tlv_from = q + 10 if mt == 0xC else q + 14
    if tlv_from is not None and full:
        tlvs(b, tlv_from, end, m)
    m["sig"] = sig
    m["info"] = info
    # stream lost after 3 intervals (9-3: 1 s -> 3 s); Follow_Up / Resp with 0x7F -> 3 s
    iv = 2.0 ** lmi if -7 <= lmi <= 6 else 1.0
    m["lost_s"] = max(1.5, min(60.0, 3.0 * iv))


def tlvs(b, p, end, m):
    i = 0
    while p + 4 <= end:
        t = int.from_bytes(b[p:p + 2], "big")
        ln = int.from_bytes(b[p + 2:p + 4], "big")
        v = b[p + 4:p + 4 + ln]
        if len(v) < ln:
            break
        i += 1
        name = TLV_TYPES.get(t, "TLV 0x%04X" % t)
        text = v.hex()
        if t == 0x0003 and ln >= 6:
            org, sub = v[0:3].hex().upper(), v[3:6].hex().upper()
            text = "organization %s  subtype %s" % (org, sub)
            if org == "1C129D":                           # IEEE C37.238
                if sub == "000001" and ln >= 16:
                    text += "  C37.238-2011: grandmasterID %d, GM time inaccuracy %d ns, network time inaccuracy %d ns" % (
                        int.from_bytes(v[6:8], "big"), int.from_bytes(v[8:12], "big"), int.from_bytes(v[12:16], "big"))
                elif sub == "000002" and ln >= 14:
                    text += "  C37.238-2017: GM time inaccuracy %d ns, network time inaccuracy %d ns" % (
                        int.from_bytes(v[6:10], "big"), int.from_bytes(v[10:14], "big"))
            elif org == "0080C2":
                text += "  (IEEE 802.1)"
        elif t == 0x0008:
            text = "  ".join(clock_id(v[k:k + 8]) for k in range(0, len(v) - 7, 8))
        elif t == 0x0009 and ln >= 11:
            text = "key %d, offset %d s, jump %d s" % (v[0], struct.unpack(">i", v[1:5])[0], struct.unpack(">i", v[5:9])[0])
        m["data"].append(("TLV %d" % i, name, text, v))
        p += 4 + ln


# ---------------------------------------------------------------- clocks seen + BMCA + 9-3 check
def bmca_key(a):
    """IEEE 1588 data set comparison (smaller = better)"""
    return (a["p1"], a["cls"], a["acc"], a["var"], a["p2"], a["gm"])


class PtpState:
    def __init__(self):
        self.clocks = {}      # (net, lan, clock, port) -> dict

    def reset(self):
        self.clocks.clear()

    def feed(self, m):
        k = (m["net"], m.get("lan") or "", m["clock"], m["port"])
        c = self.clocks.get(k)
        if c is None:
            c = self.clocks[k] = dict(net=m["net"], lan=m.get("lan") or "", clock=m["clock"], port=m["port"],
                                      src=m["src"], types={}, lmi={}, domains=set(), transports=set(), dsts={},
                                      sync=deque(maxlen=20), ann=None, first=m["ts"], last=m["ts"], vlan=set(),
                                      ann_ts=None, sync_ts=None, two_step=False)
        c["last"] = m["ts"]
        mt = m["mtype"]
        c["types"][mt] = c["types"].get(mt, 0) + 1
        if mt in (0x0, 0x2, 0x1, 0xB):
            c["lmi"][mt] = m["lmi"]
        c["domains"].add(m["domain"])
        c["transports"].add("UDP" if m["transport"].startswith("UDP") else "L2")
        c["dsts"].setdefault(mt, set()).add(m["dst"])
        c["vlan"].add(m["vlan"])
        if mt == 0x0:
            c["sync"].append(m["ts"])
            c["sync_ts"] = m["ts"]
            c["two_step"] = bool(m["flags"][0] & 0x02)
        if mt == 0xB:
            c["ann"] = m.get("ann")
            c["ann_ts"] = m["ts"]

    def summary(self, now):
        """-> (rows, best, warnings). rows: one per clock that sent Announce or Sync"""
        rows, warn = [], []
        masters = [c for c in self.clocks.values() if 0xB in c["types"] or 0x0 in c["types"]]
        by_dom = {}
        for c in masters:
            a = c["ann"]
            iv = None
            if len(c["sync"]) >= 3:
                L = list(c["sync"])
                iv = (L[-1] - L[0]) / (len(L) - 1)
            alive = (now - c["last"]) < 3.5 * max(1.0, 2.0 ** (c["lmi"].get(0xB, 0) if -7 <= c["lmi"].get(0xB, 0) <= 6 else 0))
            row = dict(c=c, a=a, sync_iv=iv, alive=alive, check=self.check93(c))
            rows.append(row)
            if a and alive:
                by_dom.setdefault(a["domain"], []).append(a)
            if alive and 0x0 in c["types"] and not a:
                warn.append("%s: Sync without Announce" % c["clock"])
            if alive and a and 0x0 not in c["types"]:
                warn.append("%s: Announce without Sync" % c["clock"])
            if a and a["cls"] not in (6, 13) and alive:
                warn.append("GM %s: clock class %s" % (a["gm"], CLOCK_CLASS.get(a["cls"], a["cls"])))
            if not alive:
                warn.append("%s: no messages for %.1f s (lost)" % (c["clock"], now - c["last"]))
        best = {}
        for dom, L in by_dom.items():
            gms = {}
            for a in L:
                gms[a["gm"]] = a
            b = min(gms.values(), key=bmca_key)
            best[dom] = b
            if len(gms) > 1:
                warn.append("domain %d: %d different grandmasters announced (%s) - best by BMCA: %s"
                            % (dom, len(gms), ", ".join(sorted(gms)), b["gm"]))
        if len(by_dom) > 1:
            warn.append("several PTP domains: %s" % ", ".join(str(d) for d in sorted(by_dom)))
        warn = list(dict.fromkeys(warn))
        return rows, best, warn

    @staticmethod
    def check93(c):
        """differences to IEC 61850-9-3 (power utility profile) for one clock -> [text]"""
        p = []
        if "UDP" in c["transports"]:
            p.append("UDP transport (9-3: Ethernet L2)")
        if c["domains"] - {0}:
            p.append("domain %s (9-3 default 0)" % ",".join(str(d) for d in sorted(c["domains"])))
        if 0x1 in c["types"] or 0x9 in c["types"]:
            p.append("Delay_Req / Delay_Resp = E2E (9-3: peer-to-peer)")
        for mt, nm in ((0x0, "Sync"), (0xB, "Announce"), (0x2, "Pdelay_Req")):
            if mt in c["lmi"] and c["lmi"][mt] != 0:
                p.append("%s interval 2^%d s (9-3: 1 s)" % (nm, c["lmi"][mt]))
        for mt, dsts in c["dsts"].items():
            want = MAC_PDELAY if mt in PDELAY else MAC_PTP
            if "L2" in c["transports"] and any(d != want for d in dsts):
                p.append("%s to %s (expected %s)" % (MTYPES.get(mt, mt), ",".join(sorted(dsts)), want))
        return p
