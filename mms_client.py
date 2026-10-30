# -*- coding: utf-8 -*-
"""
mms_client.py - IEC 61850 / MMS client (tab MMS / Active). Only reading in v0.6.0.

Connection (ISO stack over TCP 102, RFC 1006):
  COTP CR / CC -> Session CN (+ Presentation CP + ACSE AARQ + MMS Initiate) / AC -> data transfer
  The connect PDUs are the ones of the widely used libiec61850 client (called AP title 1.1.1.999.1,
  AE qualifier 12, calling AP title 1.1.1.999, AE qualifier 12, max PDU 65000).
Services:
  identify()                       GetServerIdentity (vendor, model, revision)
  name_list(cls, domain)           GetNameList (all parts, continueAfter): logical devices (cls 9),
                                   variables of an LD (cls 0), data sets of an LD (cls 2)
  read(domain, items)              GetDataValues / Get(U|B)RCBValues / GetGoCBValues (MMS Read)
  type_of(domain, item)            GetVariableAccessAttributes -> type tree (names of the members)
  dataset(domain, item)            GetNamedVariableListAttributes -> members of a data set
  close()                          Conclude + TCP close
Every request waits for its response (invokeID) with a timeout; a reader thread receives the
PDUs (unconfirmed PDUs = reports go to on_unconfirmed). on_pdu(direction, mms bytes) lets the GUI
show the traffic.
"""
import socket
import threading

import mms
import sniff_core as sc

# ---------------------------------------------------------------- connect PDUs (libiec61850 client)
COTP_CR = bytes.fromhex("0300001611e00000000100c0010dc2020001c1020001")
SESSION_CN = bytes.fromhex(
    "0db20506130100160102140200023302000134020001c19c318199a003800101a28191810400000001820400000001a423"
    "300f0201010604520100013004060251013010020103060528ca220201300406025101615e305c020101a0576055a107"
    "060528ca220203a20706052901876701a30302010ca606060429018767a70302010cbe2f282d020103a028a8268003"
    "00fde881010582010583010aa416800101810305f100820c03ee1c00000408000079ef18")
TPDU_SIZE = 8192


class MmsError(Exception):
    pass


def tlv(tag, val):
    n = len(val)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b"\x81" + bytes([n])
    elif n < 0x10000:
        ln = b"\x82" + n.to_bytes(2, "big")
    else:
        ln = b"\x83" + n.to_bytes(3, "big")
    return bytes([tag]) + ln + val


def uint_bytes(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return b


def obj(domain, item):
    """ObjectName domain-specific"""
    return tlv(0xA1, tlv(0x1A, domain.encode()) + tlv(0x1A, item.encode()))


# ---------------------------------------------------------------- type description
def parse_type(b, p, end):
    """TypeSpecification -> dict(kind, comps [(name, type)] / elem / bits)"""
    for cls, cons, num, v, e, t in mms.ber(b, p, end):
        if num == 2:                                      # structure
            comps = []
            for c2, cn2, n2, v2, e2, _ in mms.ber(b, v, e):
                if n2 == 1:                               # components
                    for c3, cn3, n3, v3, e3, _ in mms.ber(b, v2, e2):    # SEQUENCE
                        name, typ = "", None
                        for c4, cn4, n4, v4, e4, _ in mms.ber(b, v3, e3):
                            if n4 == 0:
                                name = b[v4:e4].decode("latin1")
                            elif n4 == 1:
                                typ = parse_type(b, v4, e4)
                        comps.append((name, typ))
            return dict(kind="struct", comps=comps)
        if num == 1:                                      # array
            elem, count = None, 0
            for c2, cn2, n2, v2, e2, _ in mms.ber(b, v, e):
                if n2 == 1:
                    count = sc.uint(b[v2:e2])
                elif n2 == 2:
                    elem = parse_type(b, v2, e2)
            return dict(kind="array", elem=elem, count=count)
        names = {3: "BOOLEAN", 4: "BIT STRING", 5: "INTEGER", 6: "UNSIGNED", 7: "FLOAT", 9: "OCTET STRING",
                 10: "VISIBLE STRING", 11: "GENERALIZED TIME", 12: "BINARY TIME", 13: "BCD", 15: "OBJECT ID",
                 16: "MMS STRING", 17: "UTC TIME"}
        info = sc.sint(b[v:e]) if num in (4, 5, 6, 9, 10, 16) and e > v and not cons else None
        return dict(kind=names.get(num, "type %d" % num), size=info)
    return None


def typed_rows(b, t, e, typ, path, out):
    """value TLV b[t:e] + type -> rows (path, type, value text, raw bytes) with the member names of the type"""
    tag = b[t]
    ln, v = sc.ber_len(b, t + 1)
    if tag in (0xA2, 0xA1):                               # structure / array
        out.append((path, "Structure" if tag == 0xA2 else "Array", "", None))
        kids = list(mms.ber(b, v, v + ln))
        for k, (c, cons, num, v2, e2, t2) in enumerate(kids):
            if typ and typ.get("kind") == "struct" and k < len(typ["comps"]):
                cname, ctype = typ["comps"][k]
            elif typ and typ.get("kind") == "array":
                cname, ctype = "[%d]" % k, typ.get("elem")
            else:
                cname, ctype = str(k + 1), None
            typed_rows(b, t2, e2, ctype, (path + "." + cname) if path else cname, out)
        return
    rows = []
    sc.mms_data(b, t, e, rows)
    if rows:
        out.append((path, rows[0][1], rows[0][2], rows[0][3]))


# ---------------------------------------------------------------- client
class MmsClient:
    def __init__(self, on_pdu=None, on_unconfirmed=None, on_closed=None, timeout=10.0):
        self.sock = None
        self.on_pdu, self.on_unconfirmed, self.on_closed = on_pdu, on_unconfirmed, on_closed
        self.timeout = timeout
        self.invoke = 0
        self.wait = {}               # invoke -> [Event, (kind, bytes)]
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.reader = None
        self.connected = False
        self.max_pdu = 65000
        self.peer = ""
        self.local_ip = ""
        self.conclude_ev = threading.Event()

    # ---- transport
    def _recv_tpkt(self):
        h = self._recv_n(4)
        if h[0] != 3:
            raise MmsError("bad TPKT")
        ln = int.from_bytes(h[2:4], "big")
        return h + self._recv_n(ln - 4)

    def _recv_n(self, n):
        buf = b""
        while len(buf) < n:
            x = self.sock.recv(n - len(buf))
            if not x:
                raise MmsError("connection closed by the IED")
            buf += x
        return buf

    def _recv_spdu(self):
        """COTP DT segments until EOT -> SPDU"""
        data = b""
        while True:
            tp = self._recv_tpkt()
            li = tp[4]
            code = tp[5] & 0xF0
            if code == 0x80:
                raise MmsError("COTP disconnect request from the IED")
            if code != 0xF0:
                continue
            data += tp[5 + li:]
            if tp[6] & 0x80:
                return data

    def _send_spdu(self, spdu):
        chunk = TPDU_SIZE - 7
        with self.send_lock:
            for i in range(0, len(spdu), chunk):
                part = spdu[i:i + chunk]
                eot = i + chunk >= len(spdu)
                cotp = b"\x02\xf0" + (b"\x80" if eot else b"\x00") + part
                self.sock.sendall(b"\x03\x00" + (4 + len(cotp)).to_bytes(2, "big") + cotp)

    def send_pdu(self, pdu):
        pres = tlv(0x61, tlv(0x30, tlv(0x02, b"\x03") + tlv(0xA0, pdu)))
        if self.on_pdu:
            self.on_pdu("C→S", pdu)
        self._send_spdu(b"\x01\x00\x01\x00" + pres)

    # ---- connect
    def connect(self, ip, port=102, timeout=5.0):
        self.peer = "%s:%d" % (ip, port)
        self.sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            self.local_ip = self.sock.getsockname()[0]       # own address (Owner of RCBs reserved by us)
        except OSError:
            self.local_ip = ""
        self.sock.settimeout(timeout)
        self.sock.sendall(COTP_CR)
        cc = self._recv_tpkt()
        if (cc[5] & 0xF0) != 0xD0:
            self.sock.close()
            raise MmsError("COTP connect refused by the IED")
        self._send_spdu(SESSION_CN)
        spdu = self._recv_spdu()
        stext, pres = mms.session(spdu)
        if spdu[0] != 0x0E:
            self.sock.close()
            raise MmsError("session refused by the IED (%s)" % stext)
        pdu, acse = mms.find_mms(pres, 0, len(pres))
        if "REJECTED" in acse:
            self.sock.close()
            raise MmsError("association rejected by the IED (%s)" % acse)
        if not pdu or pdu[0] != 0xA9:
            self.sock.close()
            raise MmsError("no MMS initiate response (%s)" % (pdu[:1].hex() if pdu else acse))
        r = mms.parse_pdu(pdu)
        if self.on_pdu:
            self.on_pdu("S→C", pdu)
        for k, parent, label, val, typ, sig in r["tree"].rows:
            if label.startswith("Local detail"):
                try:
                    self.max_pdu = int(val)
                except ValueError:
                    pass
        self.sock.settimeout(None)
        self.connected = True
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        return r

    def _read_loop(self):
        why = "closed"
        try:
            while True:
                spdu = self._recv_spdu()
                stext, pres = mms.session(spdu)
                if spdu[0] in (0x09, 0x0A, 0x19):         # FN / DN / AB
                    why = stext
                    break
                pdu, acse = mms.find_mms(pres, 0, len(pres)) if pres else (None, "")
                if not pdu:
                    continue
                if self.on_pdu:
                    self.on_pdu("S→C", pdu)
                tag = pdu[0]
                if tag in (0xA1, 0xA2, 0xA4):             # response / error / reject: invokeID first
                    inv = None
                    for cls, cons, num, v, e, t in mms.ber(pdu, 2 if pdu[1] < 0x80 else 2 + (pdu[1] & 0x7F), len(pdu)):
                        inv = sc.uint(pdu[v:e])
                        break
                    with self.lock:
                        w = self.wait.get(inv)
                    if w:
                        w[1] = (tag, pdu)
                        w[0].set()
                elif tag == 0xA3 and self.on_unconfirmed:
                    self.on_unconfirmed(pdu)
                elif tag in (0x8C, 0xAD):                 # conclude response / error
                    self.conclude_ev.set()
        except (OSError, MmsError, ValueError) as ex:
            why = str(ex)
        finally:
            self.connected = False
            with self.lock:
                for w in self.wait.values():
                    w[0].set()
            if self.on_closed:
                self.on_closed(why)

    def request(self, service):
        """confirmed request (service TLV) -> response service content (bytes, start, end)"""
        if not self.connected:
            raise MmsError("not connected")
        with self.lock:
            self.invoke = (self.invoke + 1) & 0x7FFFFFFF
            inv = self.invoke
            ev = threading.Event()
            self.wait[inv] = [ev, None]
        self.send_pdu(tlv(0xA0, tlv(0x02, uint_bytes(inv)) + service))
        ok = ev.wait(self.timeout)
        with self.lock:
            res = self.wait.pop(inv, [None, None])[1]
        if not ok or res is None:
            raise MmsError("no response from the IED (timeout %g s)" % self.timeout if self.connected else "connection lost")
        tag, pdu = res
        if tag == 0xA2:
            r = mms.parse_pdu(pdu)
            raise MmsError("confirmed error: %s" % r["info"])
        if tag == 0xA4:
            r = mms.parse_pdu(pdu)
            raise MmsError("reject: %s" % r["info"])
        # service = second element of the response
        cls, cons, num, v, e, t = list(mms.ber(pdu, 0, len(pdu)))[0]
        items = list(mms.ber(pdu, v, e))
        if len(items) < 2:
            return pdu, 0, 0
        c2, cn2, n2, v2, e2, t2 = items[1]
        return pdu, v2, e2

    # ---- services
    def identify(self):
        b, v, e = self.request(b"\x82\x00")
        out = []
        for cls, cons, num, v2, e2, t in mms.ber(b, v, e):
            out.append(b[v2:e2].decode("latin1", "replace"))
        return out

    def name_list(self, cls, domain=None):
        names, after = [], None
        while True:
            scope = tlv(0x81, domain.encode()) if domain else b"\x80\x00"
            req = tlv(0xA0, tlv(0x80, bytes([cls]))) + tlv(0xA1, scope)
            if after:
                req += tlv(0x82, after.encode())
            b, v, e = self.request(tlv(0xA1, req))
            more = False
            got = []
            for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
                if n2 == 0:
                    got = [b[v3:e3].decode("latin1") for _, _, _, v3, e3, _ in mms.ber(b, v2, e2)]
                elif n2 == 1:
                    more = b[v2:e2] != b"\x00"
            names += got
            if not more or not got:
                return names
            after = got[-1]

    def read(self, domain, items):
        """-> list of (ok, bytes, start, end) per item (ok False: (error text, None, None, None))"""
        lst = b"".join(tlv(0x30, tlv(0xA0, obj(domain, i))) for i in items)
        b, v, e = self.request(tlv(0xA4, tlv(0xA1, tlv(0xA0, lst))))
        out = []
        for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
            if n2 == 1:                                   # listOfAccessResult
                for c3, cn3, n3, v3, e3, t3 in mms.ber(b, v2, e2):
                    if c3 == 2 and n3 == 0 and not cn3:
                        out.append((False, mms.DATA_ACCESS_ERROR.get(sc.uint(b[v3:e3]), str(sc.uint(b[v3:e3]))), None, None))
                    else:
                        out.append((True, b, t3, e3))
        return out

    def read_list(self, domain, item):
        """read a data set (named variable list) -> list of (ok, bytes, start, end) per member"""
        b, v, e = self.request(tlv(0xA4, tlv(0xA1, tlv(0xA1, obj(domain, item)))))
        out = []
        for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
            if n2 == 1:
                for c3, cn3, n3, v3, e3, t3 in mms.ber(b, v2, e2):
                    if c3 == 2 and n3 == 0 and not cn3:
                        out.append((False, mms.DATA_ACCESS_ERROR.get(sc.uint(b[v3:e3]), str(sc.uint(b[v3:e3]))), None, None))
                    else:
                        out.append((True, b, t3, e3))
        return out

    def write(self, domain, item, data):
        """Write one variable (data = encoded MMS Data TLV) -> None if success, else error text"""
        req = tlv(0xA0, tlv(0x30, tlv(0xA0, obj(domain, item)))) + tlv(0xA0, data)
        b, v, e = self.request(tlv(0xA5, req))
        for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
            if n2 == 1:
                return None
            return mms.DATA_ACCESS_ERROR.get(sc.uint(b[v2:e2]), str(sc.uint(b[v2:e2])))
        return "no result"

    def type_of(self, domain, item):
        b, v, e = self.request(tlv(0xA6, tlv(0xA0, obj(domain, item))))
        for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
            if n2 == 2:
                return parse_type(b, v2, e2)
        return None

    def dataset(self, domain, item):
        b, v, e = self.request(tlv(0xAC, obj(domain, item)))
        out = []
        for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
            if n2 == 1:
                for c3, cn3, n3, v3, e3, t3 in mms.ber(b, v2, e2):
                    for c4, cn4, n4, v4, e4, t4 in mms.ber(b, v3, e3):
                        if n4 == 0:
                            out.append(mms.obj_name(b, v4, e4))
        return out

    def close(self):
        if self.connected:
            try:
                self.conclude_ev.clear()
                self.send_pdu(b"\x8b\x00")
                self.conclude_ev.wait(2.0)
            except OSError:
                pass
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)       # FIN also while the reader thread waits
        except OSError:
            pass
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.connected = False


