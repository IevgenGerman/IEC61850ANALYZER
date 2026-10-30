import sys, os
import os; R=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0,R); sys.path.insert(0,R+'/tools')
import sniff_core as sc, make_frames as mf
D60='01:0C:CD:01:00:4F'; SRC='20:B7:C0:01:27:BA'
def g(st,sq,b1,b2,q=0, ts=0):
    fr=mf.goose(D60,SRC,0x104F,'W1G_D60Master/LLN0$GO$BAY','W1G_D60Master/LLN0$TT6DataSet1','W1G_D60_GCB1',st,sq,
                [mf.boolean(b1),mf.quality(q),mf.boolean(b2),mf.quality(0),mf.dbpos(2),mf.utc(1793300000)],tal=2000)
    return sc.decode(fr,ts,1)
m=g(1,0,False,False)
assert m['kind']=='GOOSE' and m['ref']=='W1G_D60Master/LLN0$GO$BAY' and m['vlan']==101 and m['prio']==6, m
print(m['header']); print([d[:3] for d in m['data']])
assert m['data'][0][1:3]==('Boolean','FALSE') and m['data'][1][1]=='Quality' and 'good' in m['data'][1][2]
assert m['data'][4][1:3]==('Dbpos','on (10)')
t=sc.Tracker()
seq=[(0.0,g(1,0,0,0)),(1.0,g(1,1,0,0)),(2.0,g(1,2,0,0)),(2.5,g(2,0,1,0)),(2.6,g(2,1,1,0)),(3.0,g(2,2,1,0,q=1)),(4.0,g(2,3,1,0,q=1))]
shown=[]
for ts,mm in seq:
    mm['ts']=ts; mm2=dict(mm); shown+= [ (ts,x['reason']) for x in t.feed(mm2)]
print('OFF:',shown); assert shown==[(0.0,'first'),(2.5,'change'),(3.0,'change')]
lost=t.check(6.5); print('lost',[(x['kind'],x['ts']) for x in lost]); assert len(lost)==1 and abs(lost[0]['ts']-6.0)<1e-9
assert t.check(7)==[]
b=g(2,4,1,0,q=1); b['ts']=8.0; r=t.feed(b); assert r and r[0]['reason']=='back'
t2=sc.Tracker(); t2.retrans['GOOSE']=True
assert sum(len(t2.feed(dict(mm,ts=ts))) for ts,mm in seq)==7
# SV
def s(cnt,q=0,ts=0,val=1000):
    fr=mf.sv('01:0C:CD:04:01:11','F8:02:78:10:EC:94',0x4011,'MU01_QW1G_01',cnt,[val,val,val,0,5774,5774,5774,0],[q]+[0]*7, rct=True)
    return sc.decode(fr,ts,2)
m=s(5); print(m['header'][:9]); print(m['data'][:4])
assert m['kind']=='SV' and m['ref']=='MU01_QW1G_01' and m['net']==2 and m['vlan']==27
assert m['data'][0][2].startswith('1.000 A') and m['data'][8][2].startswith('57.74 V')
t=sc.Tracker(); out=[]
for i in range(4000):
    q = 0x40000000 if 2000<=i<2100 else 0
    out+=[(i,x['reason']) for x in t.feed(s(i%4000,q=q,ts=i/4000.0,val=1000+i))]
print('SV OFF', out); assert out==[(0,'first'),(2000,'change'),(2100,'change')]
assert 'invalid' in s(1,q=0x40000000)['data'][1][2]
print('captured',t.captured,'shown',t.shown)
# speed
import time
fr=mf.sv('01:0C:CD:04:01:11','F8:02:78:10:EC:94',0x4011,'MU01_QW1G_01',1,[1]*8)
t0=time.time(); n=20000
tt=sc.Tracker()
for i in range(n): tt.feed(sc.decode(fr,i/4000,1,full=False))
dt=time.time()-t0; print('SV fast path: %.0f frames/s'%(n/dt))
t0=time.time()
for i in range(n): sc.decode(fr,i/4000,1,full=True)
print('SV full decode: %.0f frames/s'%(n/(time.time()-t0)))
print('ALL OK')


# ---- PRP LAN A / B from the redundancy control trailer
def _rct(fr, lan, seq=7, vlan=True):
    size = len(fr) + 6 - 12 - (4 if vlan else 0)
    return fr + seq.to_bytes(2, "big") + (((0xA if lan == "A" else 0xB) << 12) | size).to_bytes(2, "big") + b"\x88\xfb"


_g = mf.goose("01:0C:CD:01:00:4F", "20:B7:C0:01:27:BA", 0x104F, "W1G_D60Master/LLN0$GO$BAY",
              "W1G_D60Master/LLN0$DS", "ID", 1, 0, [mf.boolean(True)])
_a, _b, _n = sc.decode(_rct(_g, "A")), sc.decode(_rct(_g, "B")), sc.decode(_g)
assert _a["lan"] == "A" and _b["lan"] == "B" and _n["lan"] == "", (_a["lan"], _b["lan"], _n["lan"])
assert _a["key"] != _b["key"]
assert any(f == "PRP LAN" and "does not match" not in v for f, v in _a["header"]), _a["header"][-1]
assert _a["data"] == _n["data"] and _a["ref"] == _n["ref"]
print("PRP LAN OK")


# ---- v0.2.0: simulation flag, phasors (primary / secondary with SCL match), filters
import math
import analog as an, filters as fl, scl_names as sn
_s = sc.decode(mf.goose("01:0C:CD:01:00:99", "00:0A:DC:01:02:03", 0x1099, "X/LLN0$GO$S", "X/LLN0$DS", "S", 1, 0, [mf.boolean(True)], sim=True))
assert _s["sim"] and ("Simulate bit (Reserved1)", "true") in _s["header"]
assert not sc.decode(_g)["sim"]

_scl = sn.SclNames().load([os.path.join(R, "tools", "demo_mu.scd")])
for svid, dst, app, conf, ok in (("MU01_QW1G_01", "01:0C:CD:04:01:11", 0x4011, 1, True),
                                 ("MU02_QW1G_01", "01:0C:CD:04:01:13", 0x4013, 1, False)):   # SCL confRev 2
    P = an.Phasors()
    for i in range(200):
        w = 2 * math.pi * 50 * i / 4000
        I = [int(200000 * math.sqrt(2) * math.sin(w - p * 2.0944)) for p in range(3)] + [0]
        U = [int(6350850 * math.sqrt(2) * math.sin(w - p * 2.0944)) for p in range(3)] + [0]
        m = sc.decode(mf.sv(dst, "F8:02:78:10:EC:94", app, svid, i, I + U, conf=conf))
        P.feed(m)
    pr = P.compute(m["key"], _scl, secondary=False)
    se = P.compute(m["key"], _scl, secondary=True)
    assert abs(pr["rows"][0]["rms"] - 200.0) < 0.01 and abs(pr["rows"][4]["rms"] - 63508.5) < 1, pr["rows"][0]
    assert abs(pr["freq"] - 50.0) < 0.01 and abs(pr["rows"][5]["ang"] + 120) < 0.1
    if ok:
        assert se["secondary"] and abs(se["rows"][0]["rms"] - 200 / 300.0) < 1e-3 and abs(se["rows"][4]["rms"] - 57.735) < 0.01, se["rows"][4]
    else:
        assert se["cb"] is None and se["rows"][0]["rms"] is None and "confRev" in se["problems"][0], se["problems"]
        assert se["rows"][5]["ang"] is not None                 # angles also without scale
# scales: 9-2LE primary without SCL, secondary only with SCL, other streams without SCL -> raw only
assert an.scales(8, None, False)[0] == ("I", 0.001, "A") and an.scales(8, None, False)[4] == ("U", 0.01, "V")
assert an.scales(8, None, True)[0][1] is None and an.scales(6, None, False)[0][1] is None
cb = _scl.sv_cb["MU01_QW1G_01"][0]
assert abs(an.scales(8, cb, True)[0][1] - 0.001 / 300) < 1e-12 and abs(an.scales(8, cb, True)[4][1] - 0.01 / 1100) < 1e-12
print("PHASORS OK")

F = fl.FilterSet()
assert F.passes(_s)                                   # off
F.enabled = True
F.sim = "without simulated"
assert not F.passes(_s) and F.passes(sc.decode(_g))
F.sim = "all"
F.rules = [fl.Rule(dict(kind="SV", appid="4000-40FF"))]
assert F.passes(m) and F.passes(sc.decode(_g))          # SV rule: GOOSE tab not filtered
F.rules.append(fl.Rule(dict(ref="w1g_d60*")))             # rule without type: all tabs
assert F.passes(sc.decode(_g)) and F.passes(m)
F.rules = [fl.Rule(dict(ref="xyz*"))]
assert not F.passes(sc.decode(_g)) and not F.passes(m)
F.rules = [F.stream_rule(sc.decode(_g)), fl.Rule(dict(kind="SV", appid="4011"))]   # m = MU02 0x4013
assert F.passes(sc.decode(_g)) and not F.passes(m) and F.find_stream_rule(sc.decode(_g))
assert fl.FilterSet(F.to_dict()).passes(sc.decode(_g))
print("FILTERS OK")


# ---- PTP: decode, Announce change, BMCA, 9-3 check, UDP, SV gmIdentity
import ptp
GMC = "EC:46:70:FF:FE:00:11:22"
a1 = sc.decode(mf.ptp_announce("EC:46:70:00:11:22", GMC, 1, 1793300000.0, tlv=mf.c37238_tlv()))
assert a1["kind"] == "PTP" and a1["mname"] == "Announce" and a1["ann"]["cls"] == 6 and a1["ann"]["gm"] == GMC
assert a1["ann"]["utc"] == 37 and a1["data"] and "C37.238-2017" in a1["data"][0][2]
a2 = sc.decode(mf.ptp_announce("EC:46:70:00:11:22", GMC, 2, 1793300001.0, cls=7))
a1b = sc.decode(mf.ptp_announce("EC:46:70:00:11:22", GMC, 2, 1793300001.0, tlv=mf.c37238_tlv()))
assert a1["key"] == a2["key"] and a1["sig"] != a2["sig"] and a1["sig"] == a1b["sig"]     # seq / time ignored
fu = sc.decode(mf.ptp_follow_up("EC:46:70:00:11:22", GMC, 1, 1793300000.5))
assert fu["mname"] == "Follow_Up" and "2026-" in fu["info"]
pd = sc.decode(mf.ptp_pdelay_req("00:1B:1E:00:00:05", "00:1B:1E:FF:FE:00:00:05", 3))
assert pd["mname"] == "Pdelay_Req" and pd["dst"] == ptp.MAC_PDELAY
T2 = sc.Tracker()
assert len(T2.feed(a1)) == 1 and len(T2.feed(a1b)) == 0 and T2.feed(a2)[0]["reason"] == "change"
S = ptp.PtpState()
rogue = sc.decode(mf.ptp_announce("00:0A:DC:AA:BB:CC", "00:0A:DC:FF:FE:AA:BB:CC", 1, 1793300000.0, cls=248, lmi=1))
for x in (a1, rogue):
    S.feed(x)
rows, best, warn = S.summary(a1["ts"] + 1)
assert best[0]["gm"] == GMC and any("2 different grandmasters" in w for w in warn), warn
assert any("Announce interval" in p for r in rows for p in r["check"])
# UDP / IPv4 port 320 -> not 9-3
ip = bytes.fromhex("4500") + (20 + 8 + 64).to_bytes(2, "big") + b"\x00" * 4 + bytes([64, 17]) + b"\x00\x00" + bytes([10, 0, 0, 1, 224, 0, 1, 129])
body = mf.ptp_announce("EC:46:70:00:11:22", GMC, 1, 1793300000.0)[14:]
udp = (320).to_bytes(2, "big") + (320).to_bytes(2, "big") + (8 + len(body)).to_bytes(2, "big") + b"\x00\x00"
u = sc.decode(mf.eth("01:00:5E:00:01:81", "EC:46:70:00:11:22", 0x0800, ip + udp + body))
assert u and u["kind"] == "PTP" and u["transport"].startswith("UDP")
S2 = ptp.PtpState(); S2.feed(u)
assert any("UDP" in p for p in S2.summary(u["ts"])[0][0]["check"])
g = sc.decode(mf.sv("01:0C:CD:04:01:11", "F8:02:78:10:EC:94", 0x4011, "MU01_QW1G_01", 0, [0] * 8, gm=GMC), full=True)
assert g["gmIdentity"] == GMC
print("PTP OK")


# ---- GOOSE publisher: SCL -> frame -> decoder of the sniffer, retransmission MinTime ... MaxTime
import goose_pub as gp
G = gp.load_gcbs(os.path.join(R, "tools", "demo_ied.cid"))
assert len(G) == 1
g = G[0]
assert (g["ref"], g["mac"], g["appid"], g["vlan"], g["prio"], g["min_ms"], g["max_ms"], g["confrev"]) == \
    ("DEMO_IEDLD0/LLN0$GO$GCB1", "01:0C:CD:01:0F:01", 0x0F01, 101, 4, 4.0, 1000.0, 3)
assert [e["btype"] for e in g["entries"]] == ["BOOLEAN", "Quality", "Dbpos", "FLOAT32", "Enum", "Struct"]
assert [c["btype"] for c in g["entries"][5]["children"]] == ["BOOLEAN", "Quality", "Timestamp"]
assert g["entries"][4]["value"] == 1 and g["entries"][4]["enum"][5] == "off"
g["entries"][0]["value"] = True
g["entries"][1]["value"] = {"validity": "questionable", "test": True}
g["entries"][2]["value"] = "on"
g["entries"][3]["value"] = 123.5
g["entries"][4]["value"] = 3
g.update(stnum=7, sqnum=0, t_change=1793300000.25, simulation=True, ndscom=False)
d = sc.decode(gp.build_frame(g, "02:00:00:00:00:01", 1793300000.3, 8), full=True)
vals = [x[2] for x in d["data"]]
assert d["ref"] == g["ref"] and d["sim"] and d["vlan"] == 101 and d["prio"] == 4 and d["stNum"] == 7, d["header"]
assert vals[0] == "TRUE" and "questionable, test" in vals[1] and vals[2].startswith("on") and vals[3] == "123.5" and vals[4] == "3", vals
assert d["data"][5][1] == "Structure" and d["data"][6][2] == "FALSE"
g["simulation"] = False
assert not sc.decode(gp.build_frame(g, "02:00:00:00:00:01", 1793300000.3, 8))["sim"]
sent = []
pub = gp.Publisher(lambda iface, fr: sent.append((time.monotonic(), sc.decode(fr))))
pub.start()
g2 = gp.load_gcbs(os.path.join(R, "tools", "demo_ied.cid"))[0]
g2["min_ms"], g2["max_ms"] = 10, 160
pub.add(g2, "x", "02:00:00:00:00:01")
time.sleep(0.5)
pub.stop()
st = [m["stNum"] for t, m in sent]
iv = [round((b[0] - a[0]) * 1000) for a, b in zip(sent, sent[1:])][:5]
assert st[0] == 1 and [m["sqNum"] for t, m in sent][:4] == [0, 1, 2, 3], st
assert all(abs(a - b) <= 25 for a, b in zip(iv, [10, 20, 40, 80, 160])), iv   # loose: CI timers
assert sent[0][1]["tal"] == 20
print("PUBLISHER OK", iv)
g3 = gp.load_gcbs(os.path.join(R, "tools", "demo_ied.cid"))[0]
g3.update(stnum=1, sqnum=0, t_change=1793300000.0, simulation=True)
g3["entries"][1]["value"] = {"validity": "invalid", "test": True, "flags": ["oldData", "failure", "operatorBlocked"]}
q = sc.decode(gp.build_frame(g3, "02:00:00:00:00:01", 1793300000.0, 8), full=True)["data"][1][2]
assert q.startswith("0100001100011") and "oldData" in q and "operatorBlocked" in q, q
print("QUALITY OK")


# ---- MMS passive: TCP reassembly, initiate, read, write, reports (reasons, names from SCL), LastApplError
import mms
import struct as _st
names = sn.SclNames().load([os.path.join(R, "tools", "demo_ied.cid")])
D = mms.MmsDecoder(names)
CL, SV_ = ("00:50:56:00:00:10", "192.168.1.10", 50001), ("00:0A:DC:00:00:20", "192.168.1.20", 102)
sq = {"c": 1000, "s": 5000}


def tsend(fromc, payload=b"", flags=0x18):
    a, b = (CL, SV_) if fromc else (SV_, CL)
    k = "c" if fromc else "s"
    fr = mf.ipv4_tcp(b[0], a[0], a[1], b[1], a[2], b[2], sq[k], 0, flags, payload)
    sq[k] += len(payload) + (1 if flags & 0x03 else 0)
    return D.feed(fr, 1793300000.0)


o = tsend(True, flags=0x02) + tsend(False, flags=0x12) + tsend(True, mf.cotp_cr()) + tsend(False, mf.cotp_cr(True))
o += tsend(True, mf.mms_connect(mf.initiate())) + tsend(False, mf.mms_connect(mf.initiate(True), True))
o += tsend(True, mf.mms_dt(mf.read_req(2, [("DEMO_IEDLD0", "GGIO1$ST$Ind1$stVal"), ("DEMO_IEDLD0", "MMXU1$MX$TotW$mag$f")])))
o += tsend(False, mf.mms_dt(mf.read_resp(2, [mf.boolean(True), mf.tlv(0x80, b"\x0a")])))
vals = [mf.boolean(True), mf.quality(0), mf.tlv(0x87, b"\x08" + _st.pack(">f", 12.5))]
rep = mf.mms_dt(mf.report("DEMO_IED_urcbA", 3, 1793300002, "DEMO_IEDLD0/LLN0$DS1", [1, 1, 0, 1, 0, 0], vals, [[1], [2], [4]]))
o += tsend(False, rep[:30]) + tsend(False, rep[30:])                    # report in two TCP segments
o += tsend(False, mf.mms_dt(mf.last_appl_error("DEMO_IEDLD0/Q0XCBR1$CO$Pos", 10)))
o += tsend(True, flags=0x11)
types = [m["mtype"] for m in o]
assert types == ["TCP connect request", "TCP connect accept", "COTP connect request (CR)", "COTP connect confirm (CC)",
                 "Initiate request", "Initiate response", "GetDataValues request", "GetDataValues response", "Report",
                 "LastApplError (control failed)", "TCP close"], types
rd = o[7]
assert rd["invoke"] == 2 and rd["bad"] and rd["tree"][0][2] == "DEMO_IEDLD0/GGIO1.Ind1.stVal [ST]" and rd["tree"][0][3] == "TRUE"
rp = o[8]
assert rp["reason"] == "data change, quality change, integrity (period)" and rp["ref"] == "DEMO_IED_urcbA", rp["reason"]
ent = [x for x in rp["tree"] if x[2].startswith("Entry")]
assert [x[2] for x in ent] == ["Entry 1  [data change]", "Entry 2  [quality change]", "Entry 4  [integrity (period)]"]
assert ent[2][3] == "12.5" and ent[2][5] == "LD0/MMXU1.TotW.mag.f [MX]", ent
assert o[9]["reason"] == "AddCause: Blocked-by-interlocking" and o[4]["info"] == "max PDU 65000 bytes"
o = tsend(True, flags=0x02)
o += tsend(True, mf.mms_dt(mf.write_req(9, [("DEMO_IEDLD0", "Q0XCBR1$CO$Pos$Oper")], [mf.tlv(0xA2, mf.boolean(True))])))
o += tsend(False, mf.mms_dt(mf.write_resp(9)))
o += tsend(False, mf.mms_dt(mf.command_termination("DEMO_IEDLD0", "Q0XCBR1$CO$Pos$Oper")))
o += tsend(False, mf.mms_dt(mf.command_termination("DEMO_IEDLD0", "Q0XCBR1$CO$Pos$Oper", 10)))
t = [(m["mtype"], m["reason"], sorted(m["cats"])) for m in o]
assert t[1][0] == "Operate request" and t[2][0] == "Operate response", t
assert t[3] == ("CommandTermination (positive)", "", ["cs"]), t[3]
assert t[4] == ("CommandTermination (negative)", "AddCause: Blocked-by-interlocking", ["cs", "error"]), t[4]
assert rp["cats"] == {"report"} and rd["cats"] == {"cs", "error"} and o[0]["cats"] == {"transport"}
# names of a data set learned from MMS (GOOSE data set without SCL)
o = tsend(True, mf.mms_dt(mf.dataset_dir_req(11, "W1G_D60Master", "LLN0$TT6DataSet1")))
o += tsend(False, mf.mms_dt(mf.dataset_dir_resp(11, [("W1G_D60Master", "Gen$ST$UsrPbIHMI1$Activated$stVal"),
                                                     ("W1G_D60Master", "Gen$ST$UsrPbIHMI1$Activated$q")])))
assert o[0]["mtype"] == "GetDataSetDirectory request" and "2 member(s)" in o[1]["info"], o[1]["info"]
assert D.learned["W1G_D60Master/LLN0$TT6DataSet1"] == {0: "W1G_D60Master/Gen.UsrPbIHMI1.Activated.stVal [ST]",
                                                        1: "W1G_D60Master/Gen.UsrPbIHMI1.Activated.q [ST]"}
o = tsend(False, mf.mms_dt(mf.report("BIN_INPUT", 26, 1793300002, "W1G_F60Master/LLN0$TT3DataSet01", [0, 0, 0, 1],
                                      [mf.tlv(0xA2, mf.boolean(False) + mf.quality(0))], [[1]],
                                      refs=["W1G_F60Gen/UsrPbIHMI3$ST$Activated"])))
assert D.learned["W1G_F60Master/LLN0$TT3DataSet01"] == {3: "W1G_F60Gen/UsrPbIHMI3.Activated [ST]"}
print("MMS OK")


# ---- MMS report test: demo traffic completes, CID differences, data set not in the CID
import rpt_test as rtm
import capture as cpm
RT = rtm.ReportTest(rtm.load_ied(os.path.join(R, "tools", "demo_ied.cid")))
DD = mms.MmsDecoder()
for fr, ts in cpm.read_file(os.path.join(R, "tools", "demo_goose_sv.pcap")):
    for m in DD.feed(fr, ts):
        RT.feed(m, DD.learned)
dsn = "DEMO_IEDLD0/LLN0$DS1"
assert RT.completed and RT.status_text().startswith("RCB test completed - all signals verified"), RT.status_text()
assert not RT.issues, RT.issues
assert sorted(RT.cov[dsn][0]["states"]) == ["FALSE", "TRUE"] and abs(RT.cov[dsn][0]["min_dt"] - 0.3) < 0.01
assert RT.possible(dsn, 1) == {"qchg", "gi", "integrity"} and RT.checks(dsn, 1) == ["integrity", "gi"]
# differences: ConfRev 2, 5 entries, quality change not in TrgOps of a modified CID
RT2 = rtm.ReportTest(rtm.load_ied(os.path.join(R, "tools", "demo_ied.cid")))
RT2.info["rcbs"][0]["trgops"] = ["dchg", "gi", "period"]
bad = {"kind": "MMS", "ts": 1.0, "server": "192.168.1.20", "report": dict(
    rid="DEMO_IED_urcbA", seq=1, time=1793300000.0, dset=dsn, confrev=2, n=5,
    opt=["sequence-number", "report-time-stamp", "reason-for-inclusion", "data-set-name", "conf-revision"],
    entries=[dict(k=1, type="Boolean", nmem=0, state="TRUE", value="TRUE", ref=None, reasons=["quality change"])])}
RT2.feed(bad)
txt = " | ".join(RT2.issues)
assert "ConfRev 2, CID 3" in txt or "ConfRev 2, CID 1" in txt, txt
assert "5 data set entries in the report, 6 in the CID" in txt and "type Boolean, CID Quality" in txt
assert "reason 'quality change' but TrgOps" in txt, txt
# report of an RCB / data set that is not in the CID (GE UR: data sets configured in the IED)
RT3 = rtm.ReportTest(rtm.load_ied(os.path.join(R, "tools", "demo_ied.cid")))
dyn = {"kind": "MMS", "ts": 2.0, "server": "192.168.1.20", "report": dict(
    rid="BIN_INPUT", seq=26, time=1793300000.0, dset="DEMO_IEDLD0/LLN0$TT3DataSet01", confrev=1, n=4,
    opt=["sequence-number", "reason-for-inclusion", "data-set-name", "data-reference"],
    entries=[dict(k=3, type="Structure", nmem=3, state="FALSE", value="FALSE", ref="DEMO_IEDGen/UsrPbIHMI3.Activated [ST]",
                  reasons=["data change"])])}
RT3.feed(dyn)
assert "DEMO_IEDLD0/LLN0$TT3DataSet01" in RT3.dyn and RT3.info["datasets"]["DEMO_IEDLD0/LLN0$TT3DataSet01"][3]["name"].endswith("UsrPbIHMI3.Activated [ST]")
assert any("not in the CID" in x for x in RT3.issues)
print("REPORT TEST OK")


# ---- MMS Active: CID model, control block decoding, compare (offline) + live client if a server runs
import mms_active as ma
import mms_client as mcl
cid = ma.cid_model(os.path.join(R, "tools", "demo_ied.cid"))
assert cid["ied"] == "DEMO_IED" and cid["ips"] == ["192.168.1.20"] and "DEMO_IEDLD0" in cid["lds"]
assert cid["rcbs"][0]["trgops"] == ["dchg", "qchg", "period", "gi"] and cid["gocbs"][0]["appid"] == 0x0F01
assert len(cid["datasets"]["DEMO_IEDLD0/LLN0$DS1"]) == 6
om = ma.new_model()
om["lds"] = {d: list(v) for d, v in cid["lds"].items()}
om["dsnames"] = {"DEMO_IEDLD0": ["LLN0$DS1"]}
om["datasets"] = {"DEMO_IEDLD0/LLN0$DS1": list(cid["datasets"]["DEMO_IEDLD0/LLN0$DS1"])}
r0 = dict(cid["rcbs"][0], ref="DEMO_IEDLD0/LLN0$RP$urcbA01", name="urcbA01", rptena="TRUE", resv="FALSE",
          owner="192.168.1.10", optflds=[], intgpd="5000", confrev="1")
g0 = dict(cid["gocbs"][0], ref="DEMO_IEDLD0/LLN0$GO$GCB1", goena="TRUE", appid="3841", vlan="101", confrev="3")
om.update(rcbs=[r0], gocbs=[g0], cbs_read=True)
F = ma.compare(cid, om)
assert not [f for f in F if f[1] == "bad"], F
assert ma.in_use(r0) == "IN USE - enabled by 192.168.1.10"
om["datasets"]["DEMO_IEDLD0/LLN0$DS1"].pop()
om["rcbs"][0] = dict(r0, intgpd="2000", datset="DEMO_IEDLD0/LLN0$DSX")
om["gocbs"][0] = dict(g0, appid="3842")
bad = [f[2] for f in ma.compare(cid, om) if f[1] == "bad"]
assert any("members differ - CID 6, IED 5" in x for x in bad) and any("IntgPd IED 2000" in x for x in bad)
assert any("DatSet IED DEMO_IEDLD0/LLN0$DSX" in x for x in bad) and any("APPID IED 0x0F02" in x for x in bad), bad
assert ma.bit_names(b"\x02\x7c", ma.TRG_BITS) == ["dchg", "qchg", "dupd", "period", "gi"]
assert ma.owner_text(b"\x0a\x00\x00\x05") == "10.0.0.5" and ma.owner_text(b"\x00" * 4) == ""
assert ma.compact([("X.ST.Ind1", "Structure", "", None), ("X.ST.Ind1.stVal", "Boolean", "TRUE", b"\x01"),
                   ("X.ST.Ind1.q", "Quality", "0000000000000  (good)", b"")]) == "stVal=TRUE   q=good"
assert ma.state_of([("X.ST.Ind1", "Structure", "", None), ("X.ST.Ind1.stVal", "Boolean", "TRUE", b"")]) is True
assert ma.state_of([("X.ST.Pos.stVal", "Dbpos", "off (01)", b"")]) is False
assert ma.state_of([("X.ST.Op", "Structure", "", None), ("X.ST.Op.general", "Boolean", "TRUE", b""),
                    ("X.ST.Op.phsA", "Boolean", "FALSE", b"")]) is True
assert ma.state_of([("X.MX.A.mag.f", "Float", "1.0", b"")]) is None
import socket as _s
try:
    _s.create_connection(("127.0.0.1", 102), timeout=0.3).close()
    live = True
except OSError:
    live = False
if live:                                    # e.g. libiec61850 server_example_basic_io
    c = mcl.MmsClient()
    c.connect("127.0.0.1")
    om = ma.browse(c)
    ma.read_datasets(c, om)
    ma.read_cbs(c, om)
    assert om["lds"] and om["rcbs"]
    c.close()
    print("MMS ACTIVE OK (live: %s, %d variables, %d RCB)" % (" / ".join(om["ident"]),
                                                             sum(len(v) for v in om["names"].values()), len(om["rcbs"])))
else:
    print("MMS ACTIVE OK (no local server on port 102 - live part skipped)")


# ---- IED simulator (MMS server) <-> own MMS client: model, compare with CID, RCB, reports
import time as _t
import ied_model as imd
import mms_server as msv
_cid = os.path.join(R, "tools", "demo_ied.cid")
SM = imd.load(_cid)
SRV = msv.Server(SM)
_sk = _s.socket()
_sk.bind(("127.0.0.1", 0))
_port = _sk.getsockname()[1]
_sk.close()
SRV.start("127.0.0.1", _port)
_rep = []
cl = mcl.MmsClient(on_unconfirmed=_rep.append)
cl.connect("127.0.0.1", _port)
om = ma.browse(cl)
ma.read_datasets(cl, om)
ma.read_cbs(cl, om)
assert om["ident"][0] == SM["vendor"] or om["ident"][0] == "IEC61850ANALYZER"
assert not [f for f in ma.compare(ma.cid_model(_cid), om) if f[1] == "bad"], ma.compare(ma.cid_model(_cid), om)
rcb = om["rcbs"][0]
D, I = rcb["domain"], rcb["item"]
assert cl.write(D, "LLN0$ST$Mod$stVal", b"\x85\x01\x01") == "object-access-denied"
assert cl.write(D, I + "$RptEna", b"\x83\x01\xff") is None
assert cl.write(D, I + "$IntgPd", b"\x86\x01\x05") == "temporarily-unavailable"
assert cl.write(D, I + "$GI", b"\x83\x01\xff") is None
_t.sleep(0.2)
ds_dom, ds_item = SM["datasets"][D][rcb["datset"].split("/", 1)[1]][0]
leaf = imd.find(SM, ds_dom, ds_item)
leaf = leaf if not leaf["kids"] else next(k for k in imd.walk(leaf) if not k["kids"] and k["btype"] == "BOOLEAN")
SRV.set_value(leaf, True)
_t.sleep(0.3)
reps = [mms.parse_pdu(p).get("report") for p in _rep]
assert reps[0]["entries"][0]["reasons"] == ["general interrogation"]
assert any(r and r["entries"][0]["reasons"] == ["data change"] for r in reps), reps
cl2 = mcl.MmsClient()
cl2.connect("127.0.0.1", _port)
assert cl2.write(D, I + "$RptEna", b"\x83\x01\xff") == "temporarily-unavailable"
cl.close()
_t.sleep(0.3)
assert cl2.write(D, I + "$RptEna", b"\x83\x01\xff") is None
cl2.close()
SRV.stop()
print("IED SIMULATOR OK (%d variables, %d reports)" % (sum(len(v) for v in SM["index"].values()), len(reps)))


# ---- Control: Oper structure following the type of the IED
import mms_control as mct
_oper = dict(kind="struct", comps=[("ctlVal", dict(kind="BOOLEAN")), ("origin", dict(kind="struct", comps=[
    ("orCat", dict(kind="INTEGER")), ("orIdent", dict(kind="OCTET STRING"))])), ("ctlNum", dict(kind="UNSIGNED")),
    ("T", dict(kind="UTC TIME")), ("Test", dict(kind="BOOLEAN")), ("Check", dict(kind="BIT STRING"))])
_b = mct.enc_struct(_oper, True, 2, "PC1", 7, False, True, True, now=1793300000.0)
assert _b.startswith(bytes.fromhex("a2")) and bytes.fromhex("8301ff") in _b and bytes.fromhex("a2088501028903504331") in _b
assert _b.endswith(bytes.fromhex("830100840206c0")) and bytes.fromhex("860107") in _b, _b.hex()
assert mct.ctl_kind(dict(kind="BIT STRING")) == "tcmd" and mct.enc_ctl_val(dict(kind="BIT STRING"), "higher") == bytes.fromhex("84020680")
_I = dict(ctl_model=4, loc="local", mod="on (1)", beh="test (3)", oper_type=_oper)
_w = " | ".join(mct.warnings(_I))
assert "Blocked-by-switching-hierarchy" in _w and "Beh test" in _w
print("CONTROL OK")
