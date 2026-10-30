# builds demo_goose_sv.pcap: GOOSE D60/F60 with changes + quality change + a lost stream, SV 3 streams with a quality change
import sys
import os; sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import make_frames as mf
from scapy.utils import PcapWriter
from scapy.layers.l2 import Ether
out=[]
T=1793300000.0
def G(dev,dst,src,appid,st,sq,b1,b2,q1=0,tal=2000):
    return mf.goose(dst,src,appid,'%sMaster/LLN0$GO$BAY'%dev,'%sMaster/LLN0$TT6DataSet1'%dev,'%s_GCB1'%dev,st,sq,
        [mf.boolean(b1),mf.quality(q1),mf.boolean(b2),mf.quality(0)],tal=tal)
# D60: heartbeat 1 s, change at 3.0 s (b1 -> TRUE, burst), quality invalid at 6 s, stops at 8 s (lost), back at 12 s
st=1; sq=0; val=0; q=0
t=0.0
events=[]
while t<14:
    if 8<=t<12: t+=1; continue
    if abs(t-3.0)<1e-9: st+=1; sq=0; val=1
    if abs(t-6.0)<1e-9: st+=1; sq=0; q=1
    fr=G('W1G_D60','01:0C:CD:01:00:4F','20:B7:C0:01:27:BA',0x104F,st,sq,val,0,q1=q)
    out.append((T+t, mf.prp(fr,'A',int(t))))           # D60 = PRP node: the same frame on LAN A and LAN B
    out.append((T+t+0.00005, mf.prp(fr,'B',int(t))))
    sq+=1; t+=1.0
# F60 heartbeat every 1 s, no changes (SAN, no PRP trailer)
for i in range(14): out.append((T+i+0.3, G('W1G_F60','01:0C:CD:01:00:55','DC:37:52:0F:35:41',0x1055,1,i,0,0)))
# SV 3 streams (Bucha: CT 300/1, VT 110 kV / 100 V), 4000 samples/s; written 400 frames/s of 1.2 s
# (smpCnt 0..1199 consecutive -> the phasors work); quality invalid on MU02 at smpCnt 400..599.
# MU01_QW1G_01: 200 A, 63.5 kV;  MU02_QW1G_01: 150 A;  MU01_QC1G_01: simulated (Reserved1 S bit), 49.8 Hz
import math
for k,(svid,dst,app,vl,amp,f,sim) in enumerate([('MU01_QW1G_01','01:0C:CD:04:01:11',0x4011,27,200.0,50.0,False),
                                             ('MU02_QW1G_01','01:0C:CD:04:01:13',0x4013,29,150.0,50.0,False),
                                             ('MU01_QC1G_01','01:0C:CD:04:01:15',0x4015,31,80.0,49.8,True)]):
    gm = {0: 'EC:46:70:FF:FE:00:11:22', 1: '00:0A:DC:FF:FE:AA:BB:CC'}.get(k)   # MU02: other GM -> warning
    for i in range(1200):
        ts=i/400.0
        qq=0x40000000 if (k==1 and 400<=i<600) else 0
        w=2*math.pi*f*i/4000.0
        I=[int(amp*1000*math.sqrt(2)*math.sin(w-0.4-p*2*math.pi/3)) for p in range(3)]+[0]
        U=[int(63508.5*100*math.sqrt(2)*math.sin(w-p*2*math.pi/3)) for p in range(3)]+[0]
        out.append((T+ts+0.01*k, mf.sv(dst,'F8:02:78:10:EC:%02X'%(0x94+k),app,svid,i%4000,I+U,[qq]+[0]*7,vlan=vl,rct=True,sim=sim,gm=gm)))   # PRP LAN A
# simulated GOOSE (test set): W1G_TEST from 5 s
for i in range(5):
    out.append((T+5+i+0.6, mf.goose('01:0C:CD:01:00:99','00:0A:DC:01:02:03',0x1099,'W1G_TESTLD0/LLN0$GO$SIM','W1G_TESTLD0/LLN0$DS1','SIM1',1,i,
                                    [mf.boolean(True),mf.quality(0,test=True)],sim=True)))
# PTP (IEC 61850-9-3): GM EC:46:70:00:11:22 (GPS, class 6; GPS lost at 7 s -> class 7), switch port Pdelay,
# second master 00:0A:DC:AA:BB:CC from 9 s (free running, class 248, Announce every 2 s -> 9-3 check)
GMC = 'EC:46:70:FF:FE:00:11:22'
for i in range(14):
    t = T + i + 0.1
    cls, fl1 = (6, 0x3C) if i < 7 else (7, 0x2C)
    out.append((t, mf.ptp_announce('EC:46:70:00:11:22', GMC, i, t, cls=cls, flags1=fl1, tlv=mf.c37238_tlv())))
    out.append((t + 0.002, mf.ptp_sync('EC:46:70:00:11:22', GMC, i, t)))
    out.append((t + 0.0025, mf.ptp_follow_up('EC:46:70:00:11:22', GMC, i, t + 0.000000123)))
    out.append((t + 0.3, mf.ptp_pdelay_req('00:1B:1E:00:00:05', '00:1B:1E:FF:FE:00:00:05', i)))
for j, i in enumerate(range(9, 14, 2)):
    t = T + i + 0.6
    out.append((t, mf.ptp_announce('00:0A:DC:AA:BB:CC', '00:0A:DC:FF:FE:AA:BB:CC', j, t, cls=248, acc=0xFE, tsrc=0xA0, flags1=0x00, lmi=1)))
    out.append((t + 0.001, mf.ptp_sync('00:0A:DC:AA:BB:CC', '00:0A:DC:FF:FE:AA:BB:CC', j, t, two_step=False, lmi=1)))
# MMS (TCP 102): SCADA 192.168.1.10 <-> DEMO_IED 192.168.1.20 (names from tools/demo_ied.cid):
# connect, initiate, GetNameList, Read, reports (GI, data change, quality change, integrity - split in two
# TCP segments), Write RptEna, failed control (LastApplError), close
import struct as _st
CM, SM = "00:50:56:00:00:10", "00:0A:DC:00:00:20"
seqs = {"c": 1000, "s": 5000}
def tcp(t, fromc, payload=b"", flags=0x18):
    a = (CM, "192.168.1.10", 50001) if fromc else (SM, "192.168.1.20", 102)
    b = (SM, "192.168.1.20", 102) if fromc else (CM, "192.168.1.10", 50001)
    k = "c" if fromc else "s"
    out.append((T + t, mf.ipv4_tcp(b[0], a[0], a[1], b[1], a[2], b[2], seqs[k], 0, flags, payload)))
    seqs[k] += len(payload) + (1 if flags & 0x03 else 0)
def vals(b1, q1, pos, w, mod, b2):
    return [mf.boolean(b1), mf.quality(q1), mf.dbpos(pos), mf.tlv(0x87, b"\x08" + _st.pack(">f", w)), mf.tlv(0x85, bytes([mod])),
            mf.tlv(0xA2, mf.boolean(b2) + mf.quality(0) + mf.utc(T + 1))]
tcp(0.50, True, flags=0x02); tcp(0.501, False, flags=0x12)
tcp(0.502, True, mf.cotp_cr()); tcp(0.503, False, mf.cotp_cr(True))
tcp(0.51, True, mf.mms_connect(mf.initiate())); tcp(0.52, False, mf.mms_connect(mf.initiate(True), True))
tcp(0.60, True, mf.mms_dt(mf.getnamelist_req(1, "DEMO_IEDLD0")))
tcp(0.61, False, mf.mms_dt(mf.getnamelist_resp(1, ["GGIO1", "GGIO1$ST", "GGIO1$ST$Ind1", "LLN0", "MMXU1", "Q0XCBR1"])))
tcp(0.70, True, mf.mms_dt(mf.read_req(2, [("DEMO_IEDLD0", "GGIO1$ST$Ind1$stVal"), ("DEMO_IEDLD0", "LLN0$ST$Mod$stVal"), ("DEMO_IEDLD0", "MMXU1$MX$TotW$mag$f")])))
tcp(0.71, False, mf.mms_dt(mf.read_resp(2, [mf.boolean(False), mf.tlv(0x85, b"\x01"), mf.tlv(0x80, b"\x0a")])))
tcp(0.80, True, mf.mms_dt(mf.write_req(3, [("DEMO_IEDLD0", "LLN0$RP$urcbA01$RptEna")], [mf.boolean(True)])))
tcp(0.81, False, mf.mms_dt(mf.write_resp(3)))
v = vals(False, 0, 1, 1250.5, 1, False)
tcp(0.82, False, mf.mms_dt(mf.report("DEMO_IED_urcbA", 0, T + 0.82, "DEMO_IEDLD0/LLN0$DS1", [1] * 6, v, [[5]] * 6)))
v = vals(True, 0, 1, 1250.5, 1, False)
tcp(3.10, False, mf.mms_dt(mf.report("DEMO_IED_urcbA", 1, T + 3.1, "DEMO_IEDLD0/LLN0$DS1", [1, 0, 0, 0, 0, 0], v[:1], [[1]])))
v = vals(True, 1, 2, 980.0, 1, False)
tcp(4.20, False, mf.mms_dt(mf.report("DEMO_IED_urcbA", 2, T + 4.2, "DEMO_IEDLD0/LLN0$DS1", [0, 1, 1, 0, 0, 0], v[1:3], [[2], [1]])))
rep = mf.mms_dt(mf.report("DEMO_IED_urcbA", 3, T + 5.82, "DEMO_IEDLD0/LLN0$DS1", [1] * 6, v, [[4]] * 6))
tcp(5.82, False, rep[:40]); tcp(5.8201, False, rep[40:])
oper = mf.tlv(0xA2, mf.boolean(True) + mf.tlv(0xA2, mf.tlv(0x85, b"\x03") + mf.tlv(0x89, b"SCADA")) + mf.tlv(0x86, b"\x07") +
              mf.utc(T + 6) + mf.boolean(False) + mf.tlv(0x84, b"\x06\x00"))
tcp(6.00, True, mf.mms_dt(mf.write_req(4, [("DEMO_IEDLD0", "Q0XCBR1$CO$Pos$Oper")], [oper])))
tcp(6.01, False, mf.mms_dt(mf.write_resp(4)))
tcp(6.30, False, mf.mms_dt(mf.command_termination("DEMO_IEDLD0", "Q0XCBR1$CO$Pos$Oper")))
tcp(6.80, True, mf.mms_dt(mf.write_req(5, [("DEMO_IEDLD0", "Q0XCBR1$CO$Pos$Oper")], [oper])))
tcp(6.81, False, mf.mms_dt(mf.write_resp(5)))
tcp(7.00, False, mf.mms_dt(mf.command_termination("DEMO_IEDLD0", "Q0XCBR1$CO$Pos$Oper", 10)))
tcp(9.00, True, b"", 0x11); tcp(9.001, False, b"", 0x11)
out.sort(key=lambda x:x[0])
w=PcapWriter('demo_goose_sv.pcap',linktype=1)
for ts,fr in out:
    p=Ether(fr); p.time=ts; w.write(p)
w.close(); print(len(out),'frames')
