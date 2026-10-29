# -*- coding: utf-8 -*-
"""
capture.py - network adapters and capture threads (Npcap + Scapy on Windows, libpcap on Linux).
Only GOOSE (0x88B8), SV (0x88BA) and PTP (0x88F7, UDP 319 / 320) frames are captured (BPF filter,
with and without VLAN tag).
A capture thread gives raw frames to a callback: on_frame(net, frame bytes, time stamp).
"""
import threading
import time

BPF = ("ether proto 0x88b8 or ether proto 0x88ba or ether proto 0x88f7 or "
       "(udp and (port 319 or port 320)) or "
       "(vlan and (ether proto 0x88b8 or ether proto 0x88ba or ether proto 0x88f7 or "
       "(udp and (port 319 or port 320))))")


class CaptureError(Exception):
    pass


def _scapy():
    try:
        import scapy.all  # noqa: F401  (loads the platform part: Npcap / libpcap, interfaces)
        from scapy.config import conf
        return conf
    except Exception as ex:
        raise CaptureError("Scapy is not installed (pip install scapy): %s" % ex)


def adapters():
    """[(id, label)] - id is what the capture needs, label: description / IP / name"""
    conf = _scapy()
    out = []
    try:
        conf.ifaces.reload()
    except Exception:
        pass
    for itf in conf.ifaces.values():
        name = getattr(itf, "network_name", None) or getattr(itf, "name", "")
        desc = getattr(itf, "description", "") or getattr(itf, "name", "")
        ip = getattr(itf, "ip", "") or ""
        mac = getattr(itf, "mac", "") or ""
        if not name:
            continue
        label = "%s   |   IP %s   |   %s" % (desc, ip or "-", mac or name)
        out.append((name, label))
    out.sort(key=lambda x: x[1].lower())
    return out


class Capture(threading.Thread):
    """reads one adapter until stop()"""

    def __init__(self, net, iface, on_frame, on_error):
        super().__init__(daemon=True)
        self.net, self.iface, self.on_frame, self.on_error = net, iface, on_frame, on_error
        self._halt = threading.Event()
        self.sock = None
        self.count = 0

    def run(self):
        try:
            conf = _scapy()
            try:
                self.sock = conf.L2listen(iface=self.iface, filter=BPF, promisc=True)
            except Exception as ex:
                if "filter" not in str(ex).lower():
                    raise CaptureError("Cannot open the adapter (is Npcap installed? run as administrator?): %s" % ex)
                # the BPF filter cannot be compiled here -> capture everything, the decoder drops
                # every frame that is not GOOSE / SV
                try:
                    self.sock = conf.L2listen(iface=self.iface, promisc=True)
                except Exception as ex2:
                    raise CaptureError("Cannot open the adapter (is Npcap installed? run as administrator?): %s" % ex2)
            sel = getattr(type(self.sock), "select", None)
            while not self._halt.is_set():
                try:
                    if sel is not None:                     # wait max 0.3 s -> Stop reacts quickly
                        ready = sel([self.sock], 0.3)
                        if not ready:
                            continue
                    r = self.sock.recv_raw(65535)
                except Exception as ex:
                    if self._halt.is_set():
                        break
                    raise CaptureError("Capture error: %s" % ex)
                if not r:
                    continue
                cls, data, ts = r[0], r[1], (r[2] if len(r) > 2 else None)
                if not data:
                    continue
                self.count += 1
                self.on_frame(self.net, bytes(data), float(ts) if ts else time.time())
        except Exception as ex:
            self.on_error(self.net, str(ex))
        finally:
            try:
                if self.sock:
                    self.sock.close()
            except Exception:
                pass

    def stop(self):
        self._halt.set()


def read_file(path):
    """frames of a .pcap / .pcapng file -> iterator of (frame bytes, time stamp)"""
    _scapy()
    from scapy.utils import PcapReader
    with PcapReader(path) as r:
        for p in r:
            yield bytes(p), float(p.time)
