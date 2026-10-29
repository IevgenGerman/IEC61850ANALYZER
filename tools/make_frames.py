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
