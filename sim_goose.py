# -*- coding: utf-8 -*-
"""
sim_goose.py - GOOSE of the IED simulator: the GOOSE control blocks of the simulated IED (CID) are
published with the values of its data model - the same values and quality as the MMS reports.

  gocbs(model)          -> publisher entries (goose_pub.Publisher / build_frame), one per GoCB
  hits(g, node)         -> True if the changed node belongs to a member of the data set of g
A value set by hand (Server.set_value) -> Publisher.change(g): stNum + 1, fast retransmission.
Simulation flag ON by default (the real IED must be disconnected anyway: same MAC / APPID).
"""
import time

import goose_pub as gp
import ied_model as im


def _attr(cb, name, default=None):
    n = next((k for k in cb["kids"] if k["name"] == name), None)
    return n if n is not None else default


def _val(cb, name, default=None):
    n = _attr(cb, name)
    return n["value"] if n is not None else default


def gocbs(model):
    out = []
    for cb in model["gocbs"]:
        dom, item = cb["path"]
        ds = str(_val(cb, "DatSet") or "")
        mem = []
        if "/" in ds:
            d2, i2 = ds.split("/", 1)
            mem = model["datasets"].get(d2, {}).get(i2.replace(".", "$")) or []
        dst = _attr(cb, "DstAddress")
        addr = {k["name"]: k["value"] for k in (dst["kids"] if dst else [])}
        mac = str(addr.get("Addr") or "010CCD010000").replace(":", "").replace("-", "")
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2)).upper()
        mn = int(_val(cb, "MinTime") or 0) or gp.DEF_MIN_MS
        mx = int(_val(cb, "MaxTime") or 0) or gp.DEF_MAX_MS
        g = dict(ref="%s/%s" % (dom, item), cb=cb, datset=ds, goid=str(_val(cb, "GoID") or "%s/%s" % (dom, item)),
                 confrev=int(_val(cb, "ConfRev") or 1), mac=mac, appid=int(addr.get("APPID") or 0),
                 vlan=int(addr.get("VID") or 0) if addr.get("VID") is not None else None,
                 prio=int(addr.get("PRIORITY") if addr.get("PRIORITY") is not None else 4),
                 min_ms=mn, max_ms=max(mx, mn), members=mem, entries=mem, simulation=True, ndscom=False,
                 use=bool(mem), active=False, stnum=0, sqnum=0, sent=0)

        def data(t, g=g):
            now = time.time()
            out2 = b""
            for d, i in g["members"]:
                n = im.find(model, d, i)
                out2 += im.encode(n, now) if n is not None else gp.tlv(0x83, b"\x00")
            return out2
        g["data_fn"] = data
        out.append(g)
    return out


def hits(g, node):
    dom, item = node["path"]
    for d, i in g["members"]:
        if d == dom and (item == i or item.startswith(i + "$") or i.startswith(item + "$")):
            return True
    return False


def set_goena(g, on):
    n = _attr(g["cb"], "GoEna")
    if n is not None:
        n["value"] = bool(on)
