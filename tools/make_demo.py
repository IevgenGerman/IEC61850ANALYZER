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
out.sort(key=lambda x:x[0])
w=PcapWriter('demo_goose_sv.pcap',linktype=1)
for ts,fr in out:
    p=Ether(fr); p.time=ts; w.write(p)
w.close(); print(len(out),'frames')
