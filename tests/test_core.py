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
