# -*- coding: utf-8 -*-
"""Builds GOOSE / SV frames (for tests and the demo capture demo_goose_sv.pcap)."""
import struct


def tlv(tag, val):
    n = len(val)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b"\x81" + bytes([n])
    else:
        ln = b"\x82" + n.to_bytes(2, "big")
    return bytes([tag]) + ln + val


def macb(s):
    return bytes(int(x, 16) for x in s.replace("-", ":").split(":"))


def eth(dst, src, et, payload, vlan=None, prio=4):
    h = macb(dst) + macb(src)
    if vlan is not None:
        h += b"\x81\x00" + ((prio << 13) | vlan).to_bytes(2, "big")
    return h + et.to_bytes(2, "big") + payload


def boolean(v):
    return tlv(0x83, b"\x01" if v else b"\x00")


def quality(validity=0, test=False):
    # 13 bits, 3 unused: validity in the 2 MSB, test = bit 11
    bits = (validity << 14) | ((1 << (15 - 11)) if test else 0)
    return tlv(0x84, b"\x03" + bits.to_bytes(2, "big"))


def dbpos(v):
    return tlv(0x84, b"\x06" + bytes([v << 6]))


def utc(sec):
    return tlv(0x91, int(sec).to_bytes(4, "big") + b"\x00\x00\x00\x0a")


def goose(dst, src, appid, gocb, datset, goid, st, sq, data, tal=2000, vlan=101, prio=6, conf=1, t=1793300000, sim=False):
    alld = b"".join(data)
    pdu = (tlv(0x80, gocb.encode()) + tlv(0x81, tal.to_bytes(2, "big")) + tlv(0x82, datset.encode()) +
           tlv(0x83, goid.encode()) + tlv(0x84, int(t).to_bytes(4, "big") + b"\x00\x00\x00\x0a") +
           tlv(0x85, st.to_bytes(4, "big")) + tlv(0x86, sq.to_bytes(4, "big")) + tlv(0x87, b"\x01" if sim else b"\x00") +
           tlv(0x88, conf.to_bytes(1, "big")) + tlv(0x89, b"\x00") + tlv(0x8A, bytes([len(data)])) +
           tlv(0xAB, alld))
    apdu = tlv(0x61, pdu)
    res1 = b"\x80\x00" if sim else b"\x00\x00"           # Reserved1 bit 15 = Simulate
    payload = appid.to_bytes(2, "big") + (8 + len(apdu)).to_bytes(2, "big") + res1 + b"\x00" * 2 + apdu
    return eth(dst, src, 0x88B8, payload, vlan, prio)


def prp(fr, lan="A", seq=0, vlan=True):
    """adds the PRP redundancy control trailer (LAN A / B)"""
    size = len(fr) + 6 - 12 - (4 if vlan else 0)
    return fr + (seq & 0xFFFF).to_bytes(2, "big") + (((0xA if lan == "A" else 0xB) << 12) | size).to_bytes(2, "big") + b"\x88\xfb"


def sv(dst, src, appid, svid, smpcnt, values, qual=None, vlan=27, prio=4, conf=1, synch=2, rct=False, sim=False, gm=None):
    qual = qual or [0] * len(values)
    seq = b"".join(struct.pack(">iI", v, q) for v, q in zip(values, qual))
    asdu = (tlv(0x80, svid.encode()) + tlv(0x82, smpcnt.to_bytes(2, "big")) + tlv(0x83, conf.to_bytes(4, "big")) +
            tlv(0x85, bytes([synch])) + tlv(0x87, seq) + (tlv(0x89, macb(gm)) if gm else b""))
    pdu = tlv(0x60, tlv(0x80, b"\x01") + tlv(0xA2, tlv(0x30, asdu)))
    res1 = b"\x80\x00" if sim else b"\x00\x00"
    payload = appid.to_bytes(2, "big") + (8 + len(pdu)).to_bytes(2, "big") + res1 + b"\x00" * 2 + pdu
    fr = eth(dst, src, 0x88BA, payload, vlan, prio)
    if rct:                                              # PRP trailer, LAN A
        fr = prp(fr, "A", smpcnt, vlan is not None)
    return fr


# ---------------------------------------------------------------- PTP (IEEE 1588 v2, Ethernet 0x88F7)
PTP_MAC = "01:1B:19:00:00:00"
PDELAY_MAC = "01:80:C2:00:00:0E"


def ptp_hdr(mtype, length, clock, port, seq, domain=0, flags=(0x02, 0x3C), lmi=0, corr=0, ctrl=5):
    return (bytes([mtype & 0x0F, 2]) + length.to_bytes(2, "big") + bytes([domain, 0]) + bytes(flags) +
            int(corr * 65536).to_bytes(8, "big", signed=True) + b"\x00" * 4 + macb(clock) + port.to_bytes(2, "big") +
            seq.to_bytes(2, "big") + bytes([ctrl]) + lmi.to_bytes(1, "big", signed=True))


def ptp_ts(t):
    sec = int(t)
    return sec.to_bytes(6, "big") + int(round((t - sec) * 1e9)).to_bytes(4, "big")


def ptp_frame(dst, src, body, vlan=None, prio=4):
    return eth(dst, src, 0x88F7, body, vlan, prio)


def ptp_sync(src, clock, seq, t, domain=0, two_step=True, lmi=0, vlan=None):
    b = ptp_hdr(0x0, 44, clock, 1, seq, domain, (0x02 if two_step else 0x00, 0x3C), lmi, ctrl=0) + ptp_ts(0 if two_step else t)
    return ptp_frame(PTP_MAC, src, b, vlan)


def ptp_follow_up(src, clock, seq, t, domain=0, vlan=None):
    b = ptp_hdr(0x8, 44, clock, 1, seq, domain, (0x00, 0x3C), 0, ctrl=2) + ptp_ts(t)
    return ptp_frame(PTP_MAC, src, b, vlan)


def ptp_announce(src, clock, seq, t, gm=None, p1=128, cls=6, acc=0x21, var=0x4E5D, p2=128, steps=0, tsrc=0x20,
                 utc=37, domain=0, flags1=0x3C, lmi=0, tlv=b"", vlan=None):
    body = (ptp_ts(t) + utc.to_bytes(2, "big", signed=True) + b"\x00" + bytes([p1, cls, acc]) + var.to_bytes(2, "big") +
            bytes([p2]) + macb(gm or clock) + steps.to_bytes(2, "big") + bytes([tsrc]) + tlv)
    b = ptp_hdr(0xB, 34 + len(body), clock, 1, seq, domain, (0x00, flags1), lmi, ctrl=5) + body
    return ptp_frame(PTP_MAC, src, b, vlan)


def c37238_tlv(gm_inacc=50, net_inacc=200):
    """IEEE C37.238-2017 organization extension TLV"""
    v = bytes.fromhex("1C129D") + bytes.fromhex("000002") + gm_inacc.to_bytes(4, "big") + net_inacc.to_bytes(4, "big") + b"\x00\x00"
    return (0x0003).to_bytes(2, "big") + len(v).to_bytes(2, "big") + v


def ptp_pdelay_req(src, clock, seq, domain=0):
    b = ptp_hdr(0x2, 54, clock, 1, seq, domain, (0x00, 0x00), 0, ctrl=5) + b"\x00" * 20
    return ptp_frame(PDELAY_MAC, src, b)


def ptp_pdelay_resp(src, clock, seq, req_clock, t, domain=0):
    b = ptp_hdr(0x3, 54, clock, 1, seq, domain, (0x02, 0x00), 0x7F, ctrl=5) + ptp_ts(t) + macb(req_clock) + (1).to_bytes(2, "big")
    return ptp_frame(PDELAY_MAC, src, b)


# ---------------------------------------------------------------- MMS over TCP (IEC 61850-8-1)
def ipv4_tcp(dst_mac, src_mac, sip, dip, sport, dport, seq, ack, flags, payload=b"", vlan=None):
    tcp = (sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + (seq & 0xFFFFFFFF).to_bytes(4, "big") +
           (ack & 0xFFFFFFFF).to_bytes(4, "big") + bytes([5 << 4, flags]) + (8192).to_bytes(2, "big") + b"\x00" * 4)
    ip = (b"\x45\x00" + (20 + len(tcp) + len(payload)).to_bytes(2, "big") + b"\x00\x01\x40\x00\x40\x06\x00\x00" +
          bytes(int(x) for x in sip.split(".")) + bytes(int(x) for x in dip.split(".")))
    return eth(dst_mac, src_mac, 0x0800, ip + tcp + payload, vlan)


def tpkt(cotp):
    return b"\x03\x00" + (4 + len(cotp)).to_bytes(2, "big") + cotp


def cotp_dt(spdu, eot=True):
    return tpkt(b"\x02\xf0" + (b"\x80" if eot else b"\x00") + spdu)


def cotp_cr(cc=False):
    return tpkt(bytes([0x11, 0xD0 if cc else 0xE0]) + b"\x00\x01\x00\x01\x00" +
                b"\xc0\x01\x0a\xc1\x02\x00\x01\xc2\x02\x00\x01")


def pres_data(mms, ctx=3):
    return tlv(0x61, tlv(0x30, tlv(0x02, bytes([ctx])) + tlv(0xA0, mms)))


def mms_dt(mms):
    return cotp_dt(b"\x01\x00\x01\x00" + pres_data(mms))


def mms_connect(mms, accept=False):
    """Session CN / AC + presentation CP / CPA + ACSE AARQ / AARE + MMS initiate"""
    user = tlv(0xBE, tlv(0x28, tlv(0x02, b"\x03") + tlv(0xA0, mms)))
    acse = tlv(0x61 if accept else 0x60, tlv(0xA1, tlv(0x06, bytes.fromhex("28ca220203"))) +
               ((tlv(0xA2, tlv(0x02, b"\x00"))) if accept else b"") + user)
    pres = tlv(0x31, tlv(0xA0, tlv(0x80, b"\x00\x01")) + tlv(0xA2, tlv(0x61, tlv(0x30, tlv(0x02, b"\x01") + tlv(0xA0, acse)))))
    ud = bytes([0xC1]) + (bytes([len(pres)]) if len(pres) < 255 else b"\xff" + len(pres).to_bytes(2, "big")) + pres
    spdu = bytes([0x0E if accept else 0x0D]) + (bytes([len(ud)]) if len(ud) < 255 else b"\xff" + len(ud).to_bytes(2, "big")) + ud
    return cotp_dt(spdu)


def initiate(resp=False):
    detail = tlv(0xA4, tlv(0x80, b"\x01") + tlv(0x81, b"\x05\xf1\x00") + tlv(0x82, b"\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18"))
    return tlv(0xA9 if resp else 0xA8, tlv(0x80, (65000).to_bytes(4, "big")[1:]) + tlv(0x81, b"\x05") +
               tlv(0x82, b"\x05") + tlv(0x83, b"\x0a") + detail)


def obj(domain, item):
    return tlv(0xA1, tlv(0x1A, domain.encode()) + tlv(0x1A, item.encode()))


def read_req(invoke, names):
    lst = b"".join(tlv(0x30, tlv(0xA0, obj(d, i))) for d, i in names)
    return tlv(0xA0, tlv(0x02, bytes([invoke])) + tlv(0xA4, tlv(0xA1, tlv(0xA0, lst))))


def read_resp(invoke, datas):
    return tlv(0xA1, tlv(0x02, bytes([invoke])) + tlv(0xA4, tlv(0xA1, b"".join(datas))))


def write_req(invoke, names, datas):
    lst = b"".join(tlv(0x30, tlv(0xA0, obj(d, i))) for d, i in names)
    return tlv(0xA0, tlv(0x02, bytes([invoke])) + tlv(0xA5, tlv(0xA0, lst) + tlv(0xA0, b"".join(datas))))


def write_resp(invoke, n=1):
    return tlv(0xA1, tlv(0x02, bytes([invoke])) + tlv(0xA5, b"\x81\x00" * n))


def getnamelist_req(invoke, domain):
    return tlv(0xA0, tlv(0x02, bytes([invoke])) + tlv(0xA1, tlv(0xA0, tlv(0x80, b"\x00")) + tlv(0xA1, tlv(0x81, domain.encode()))))


def getnamelist_resp(invoke, ids):
    return tlv(0xA1, tlv(0x02, bytes([invoke])) + tlv(0xA1, tlv(0xA0, b"".join(tlv(0x1A, x.encode()) for x in ids)) + tlv(0x81, b"\x00")))


def bits(lst, nbits=None):
    n = nbits or len(lst)
    nb = (n + 7) // 8
    v = 0
    for i, x in enumerate(lst):
        if x:
            v |= 1 << (nb * 8 - 1 - i)
    return bytes([nb * 8 - n]) + v.to_bytes(nb, "big")


def btime(t):
    import datetime as _dt
    d = _dt.datetime.utcfromtimestamp(t)
    days = (d.date() - _dt.date(1984, 1, 1)).days
    ms = (d.hour * 3600 + d.minute * 60 + d.second) * 1000 + d.microsecond // 1000
    return ms.to_bytes(4, "big") + days.to_bytes(2, "big")


def report(rptid, seq, t, datset, incl, values, reasons, confrev=1):
    """IEC 61850-8-1 report: OptFlds sequence-number, report-time-stamp, reason, data-set-name, conf-revision"""
    opt = bits([0, 1, 1, 1, 1, 0, 0, 0, 1, 0])
    items = (tlv(0x8A, rptid.encode()) + tlv(0x84, opt) + tlv(0x86, bytes([seq])) + tlv(0x8C, btime(t)) +
             tlv(0x8A, datset.encode()) + tlv(0x86, bytes([confrev])) + tlv(0x84, bits(incl)) + b"".join(values) +
             b"".join(tlv(0x84, bits([0] + [1 if k in r else 0 for k in range(1, 7)], 7)) for r in reasons))
    return tlv(0xA3, tlv(0xA0, tlv(0xA1, tlv(0x80, b"RPT")) + tlv(0xA0, items)))


def last_appl_error(cntrl, add_cause):
    st = (tlv(0x8A, cntrl.encode()) + tlv(0x85, b"\x00") + tlv(0xA2, tlv(0x85, b"\x03") + tlv(0x89, b"SCADA")) +
          tlv(0x86, b"\x07") + tlv(0x85, bytes([add_cause])))
    return tlv(0xA3, tlv(0xA0, tlv(0xA0, tlv(0x30, tlv(0xA0, tlv(0x80, b"LastApplError")))) + tlv(0xA0, tlv(0xA2, st))))


def command_termination(domain, item, add_cause=None):
    """InformationReport after Operate: [LastApplError,] <obj>$CO$<DO>$Oper (negative when add_cause is given)"""
    oper = tlv(0xA2, tlv(0x83, b"\x01") + tlv(0xA2, tlv(0x85, b"\x03") + tlv(0x89, b"SCADA")) + tlv(0x86, b"\x07") +
               tlv(0x91, b"\x00" * 8) + tlv(0x83, b"\x00") + tlv(0x84, b"\x06\x00"))
    names = b""
    res = b""
    if add_cause is not None:
        names += tlv(0x30, tlv(0xA0, tlv(0x80, b"LastApplError")))
        res += tlv(0xA2, tlv(0x8A, (domain + "/" + item).encode()) + tlv(0x85, b"\x01") +
                   tlv(0xA2, tlv(0x85, b"\x03") + tlv(0x89, b"SCADA")) + tlv(0x86, b"\x07") + tlv(0x85, bytes([add_cause])))
    names += tlv(0x30, tlv(0xA0, tlv(0xA1, tlv(0x1A, domain.encode()) + tlv(0x1A, item.encode()))))
    res += oper
    return tlv(0xA3, tlv(0xA0, tlv(0xA0, names) + tlv(0xA0, res)))
