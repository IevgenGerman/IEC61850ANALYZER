# -*- coding: utf-8 -*-
"""
mms_server.py - IEC 61850 / MMS server of the IED simulator (one IED from a CID, several clients).

ISO stack over TCP 102 (RFC 1006): COTP CR / CC, Session CN / AC, Presentation CP / CPA,
ACSE AARQ / AARE, MMS Initiate. Services:
  Identify, Status, GetNameList (domains, variables, data sets), Read (variables and data sets),
  GetVariableAccessAttributes, GetNamedVariableListAttributes, Write (only the attributes of the
  report control blocks - values, quality and commands of the IED are not writable: access denied),
  Conclude.
Reports (IEC 61850-8-1 InformationReport "RPT"): URCB / BRCB with reservation (Resv / ResvTms /
Owner = IP of the client), TrgOps dchg / qchg / dupd / period (integrity, IntgPd) / gi, BufTm,
OptFlds (seq-num, time-stamp, reason, data-set, data-ref, buffer-ovfl, entryID, conf-rev),
buffering of BRCBs while disabled (EntryID, TimeOfEntry, PurgeBuf, BufOvfl).
Values are changed by hand in the GUI: set_value() / set_quality() -> reports with the reasons.
"""
import socket
import threading
import time
import traceback

import ied_model as im
import mms

TRG_KIND = {"dchg": "dchg", "qchg": "qchg", "dupd": "dupd"}
# ReasonCode as 6 bits (like the IEDs and libiec61850; 7 bits with application-trigger make IEDScout drop
# the association)
REASON_BITS = ["reserved", "dchg", "qchg", "dupd", "integrity", "gi"]
ERR = {"temporarily-unavailable": 2, "object-access-denied": 3, "object-undefined": 4, "type-inconsistent": 7,
       "object-non-existent": 10, "object-value-invalid": 11}
ERR_TEXT = {v: k for k, v in ERR.items()}
BUF_MAX = 1000
ACSE_OID = bytes.fromhex("52010001")                    # 2.2.1.0.1
MMS_OID = bytes.fromhex("28ca220201")                   # 1.0.9506.2.1
MMS_APP_CTX = bytes.fromhex("28ca220203")               # 1.0.9506.2.3
# services supported: status, getNameList, identify, read, write, getVariableAccessAttributes,
# getNamedVariableListAttributes, informationReport, conclude
SERVICES = bytes.fromhex("03ee08000000000000000118")
tlv = im.tlv


def ber_uint(v):
    return im.sint_bytes(max(0, int(v)))


def kids(b, p, e):
    return list(mms.ber(b, p, e))


def obj_name(b, v, e):
    """ObjectName -> (domain, item) or (None, name)"""
    for c, cn, n, v2, e2, t in mms.ber(b, v, e):
        if n == 1:
            ids = [b[v3:e3].decode("latin1") for _, _, _, v3, e3, _ in mms.ber(b, v2, e2)]
            return (ids[0], ids[1]) if len(ids) == 2 else (None, "/".join(ids))
        return None, b[v2:e2].decode("latin1")
    return None, ""


def obj_enc(dom, item):
    return tlv(0xA1, tlv(0x1A, dom.encode()) + tlv(0x1A, item.encode()))


# ---------------------------------------------------------------- client connection
class Client(threading.Thread):
    def __init__(self, server, sock, addr):
        super().__init__(daemon=True)
        self.srv, self.sock, self.addr = server, sock, addr
        self.ip = addr[0]
        self.name = "%s:%d" % addr
        self.send_lock = threading.Lock()
        self.tpdu = 8192
        self.max_pdu = 65000
        self.mms_ctx = 3
        self.acse_ctx = 1
        self.alive = True
        self.since = time.time()
        self.n_req = 0
        self.n_rpt = 0
        self.associated = False
        self.holding = False               # while a request is handled: reports wait for the response
        self.held = []

    # ---- transport
    def _recv_n(self, n):
        buf = b""
        while len(buf) < n:
            x = self.sock.recv(n - len(buf))
            if not x:
                raise ConnectionError("closed by the client")
            buf += x
        return buf

    def _recv_tpkt(self):
        h = self._recv_n(4)
        if h[0] != 3:
            raise ConnectionError("not RFC 1006")
        return h + self._recv_n(int.from_bytes(h[2:4], "big") - 4)

    def _send_cotp_data(self, spdu):
        chunk = self.tpdu - 7
        with self.send_lock:
            for i in range(0, len(spdu), chunk):
                part = spdu[i:i + chunk]
                eot = i + chunk >= len(spdu)
                cotp = b"\x02\xf0" + (b"\x80" if eot else b"\x00") + part
                self.sock.sendall(b"\x03\x00" + (4 + len(cotp)).to_bytes(2, "big") + cotp)

    def send_mms(self, pdu):
        if self.holding and pdu[:1] == b"\xa3" and threading.current_thread() is self:
            self.held.append(pdu)          # report caused by this request: after the response
            return
        if self.srv.log_pdus:
            self.srv._event("pdu", self, "S→C  " + _pdu_text(pdu))
        pres = tlv(0x61, tlv(0x30, tlv(0x02, bytes([self.mms_ctx])) + tlv(0xA0, pdu)))
        self._send_cotp_data(b"\x01\x00\x01\x00" + pres)

    # ---- main loop
    def run(self):
        why = "closed"
        try:
            data = b""
            while self.alive:
                tp = self._recv_tpkt()
                li = tp[4]
                code = tp[5] & 0xF0
                if code == 0xE0:                          # CR -> CC
                    self._cc(tp)
                    continue
                if code == 0x80:                          # DR
                    why = "COTP disconnect"
                    break
                if code != 0xF0:
                    continue
                data += tp[5 + li:]
                if not tp[6] & 0x80:
                    continue
                spdu, data = data, b""
                if not self._spdu(spdu):
                    why = "session finished"
                    break
        except (OSError, ConnectionError, ValueError, IndexError) as ex:
            why = str(ex) or ex.__class__.__name__
        except Exception as ex:                           # noqa: BLE001 - shown in the log
            why = "internal error %s: %s" % (ex.__class__.__name__, ex)
            self.srv._event("log", self, "INTERNAL ERROR (please send this log): " +
                            traceback.format_exc().replace("\n", " | "))
        finally:
            self.alive = False
            try:
                self.sock.close()
            except OSError:
                pass
            self.srv._closed(self, why)

    def _cc(self, cr):
        src_ref = cr[8:10]
        params = b""
        p = 11
        while p + 2 <= len(cr):
            code, ln = cr[p], cr[p + 1]
            val = cr[p + 2:p + 2 + ln]
            if code == 0xC0 and val:                      # TPDU size
                self.tpdu = min(1 << val[0], 8192) if val[0] < 16 else 8192
                params += bytes([0xC0, 1, min(val[0], 13)])
            elif code in (0xC1, 0xC2):
                params += bytes([code, ln]) + val
            p += 2 + ln
        body = b"\xd0" + src_ref + b"\x00\x01" + b"\x00" + params
        cc = bytes([len(body)]) + body
        with self.send_lock:
            self.sock.sendall(b"\x03\x00" + (4 + len(cc)).to_bytes(2, "big") + cc)

    def _spdu(self, spdu):
        si = spdu[0]
        if si == 0x0D:                                    # CONNECT
            self._connect(spdu)
            return True
        if si in (0x09,):                                 # FINISH -> DISCONNECT
            self._send_cotp_data(b"\x0a\x00")
            return False
        if si == 0x19:                                    # ABORT
            return False
        if si == 0x01:
            pdu, acse = mms.find_mms(spdu[4:], 0, len(spdu) - 4)
            if pdu:
                self._mms(pdu)
            return True
        return True

    # ---- association
    def _connect(self, spdu):
        stext, pres = mms.session(spdu)
        called_ssel = b"\x00\x01"
        p = 2 if spdu[1] != 0xFF else 4
        while p + 2 <= len(spdu):
            code, ln = spdu[p], spdu[p + 1]
            q = p + 2
            if ln == 0xFF:
                ln = int.from_bytes(spdu[p + 2:p + 4], "big")
                q = p + 4
            if code == 0x34:
                called_ssel = spdu[q:q + ln]
            if code in (0xC1, 0xC2):
                break
            p = q + ln
        ctxs, psel, aarq_ctx, aarq = self._parse_cp(pres)
        for cid, oid in ctxs:
            if oid == ACSE_OID:
                self.acse_ctx = cid
            elif oid == MMS_OID:
                self.mms_ctx = cid
        mms_ctx, init_req = self._parse_aarq(aarq)
        if mms_ctx is not None:
            self.mms_ctx = mms_ctx
        init_resp = self._initiate(init_req)
        aare = tlv(0x61, tlv(0xA1, tlv(0x06, MMS_APP_CTX)) + tlv(0xA2, b"\x02\x01\x00") +
                   tlv(0xA3, tlv(0xA1, b"\x02\x01\x00")) +
                   tlv(0xBE, tlv(0x28, tlv(0x02, bytes([self.mms_ctx])) + tlv(0xA0, init_resp))))
        results = b"".join(tlv(0x30, b"\x80\x01\x00" + tlv(0x81, b"\x51\x01")) for _ in (ctxs or [(1, 0), (3, 0)]))
        cpa = tlv(0x31, tlv(0xA0, b"\x80\x01\x01") + tlv(0xA2, tlv(0x83, psel or b"\x00\x00\x00\x01") +
                                                       tlv(0xA5, results) +
                                                       tlv(0x61, tlv(0x30, tlv(0x02, bytes([self.acse_ctx])) +
                                                                     tlv(0xA0, aare)))))
        params = b"\x05\x06\x13\x01\x00\x16\x01\x02" + b"\x14\x02\x00\x02" + tlv(0x34, called_ssel)
        ud = (bytes([0xC1, len(cpa)]) if len(cpa) < 255 else b"\xc1\xff" + len(cpa).to_bytes(2, "big")) + cpa
        body = params + ud
        ac = (bytes([0x0E, len(body)]) if len(body) < 255 else b"\x0e\xff" + len(body).to_bytes(2, "big")) + body
        self._send_cotp_data(ac)
        self.associated = True
        self.srv._event("assoc", self, "associated, max PDU %d" % self.max_pdu)

    def _parse_cp(self, b):
        ctxs, psel, actx, aarq = [], None, None, b""
        try:
            for c, cn, n, v, e, t in mms.ber(b, 0, len(b)):            # CP-type SET
                for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
                    if n2 == 2 and c2 == 2:                            # normal-mode-parameters
                        for c3, cn3, n3, v3, e3, t3 in mms.ber(b, v2, e2):
                            if c3 == 2 and n3 == 2:                    # called-presentation-selector
                                psel = b[v3:e3]
                            elif c3 == 2 and n3 == 4:                  # context definition list
                                for _, _, _, v4, e4, _ in mms.ber(b, v3, e3):
                                    cid, oid = None, None
                                    for c5, cn5, n5, v5, e5, t5 in mms.ber(b, v4, e4):
                                        if n5 == 2 and c5 == 0:
                                            cid = b[v5]
                                        elif n5 == 6 and c5 == 0:
                                            oid = b[v5:e5]
                                    if cid is not None:
                                        ctxs.append((cid, oid))
                            elif c3 == 1 and n3 == 1:                  # user data (fully encoded)
                                for _, _, _, v4, e4, _ in mms.ber(b, v3, e3):
                                    for c5, cn5, n5, v5, e5, t5 in mms.ber(b, v4, e4):
                                        if c5 == 0 and n5 == 2:
                                            actx = b[v5]
                                        elif c5 == 2 and n5 == 0:
                                            aarq = b[v5:e5]
        except (ValueError, IndexError):
            pass
        return ctxs, psel, actx, aarq

    def _parse_aarq(self, b):
        ctx, init = None, b""
        try:
            for c, cn, n, v, e, t in mms.ber(b, 0, len(b)):
                for c2, cn2, n2, v2, e2, t2 in mms.ber(b, v, e):
                    if c2 == 2 and n2 == 30:                           # user-information
                        for _, _, _, v3, e3, _ in mms.ber(b, v2, e2):  # EXTERNAL
                            for c4, cn4, n4, v4, e4, t4 in mms.ber(b, v3, e3):
                                if c4 == 0 and n4 == 2:
                                    ctx = b[v4]
                                elif c4 == 2 and n4 == 0:
                                    init = b[v4:e4]
        except (ValueError, IndexError):
            pass
        return ctx, init

    def _initiate(self, req):
        calling, out_calling, out_called, nest = 65000, 5, 5, 10
        try:
            for c, cn, n, v, e, t in mms.ber(req, 0, len(req)):
                for c2, cn2, n2, v2, e2, t2 in mms.ber(req, v, e):
                    x = int.from_bytes(req[v2:e2], "big") if not cn2 and e2 > v2 else None
                    if n2 == 0 and x:
                        calling = x
                    elif n2 == 1 and x:
                        out_calling = x
                    elif n2 == 2 and x:
                        out_called = x
                    elif n2 == 3 and x is not None:
                        nest = x
        except (ValueError, IndexError):
            pass
        self.max_pdu = max(1000, min(calling, 65000))
        detail = tlv(0xA4, b"\x80\x01\x01" + tlv(0x81, b"\x05\xf1\x00") + tlv(0x82, SERVICES))
        return tlv(0xA9, tlv(0x80, ber_uint(self.max_pdu)) + tlv(0x81, ber_uint(min(out_calling, 10))) +
                   tlv(0x82, ber_uint(min(out_called, 10))) + tlv(0x83, ber_uint(min(nest, 10))) + detail)

    # ---- MMS
    def _mms(self, pdu):
        tag = pdu[0]
        if tag == 0x8B:                                   # conclude request
            self.send_mms(b"\x8c\x00")
            self.srv._event("log", self, "Conclude")
            return
        if tag != 0xA0:
            return
        items = kids(pdu, *_content(pdu))
        if not items:
            return
        inv = int.from_bytes(pdu[items[0][3]:items[0][4]], "big")
        if len(items) < 2:
            return
        c, cn, num, v, e, t = items[1]
        self.n_req += 1
        if self.srv.log_pdus:
            self.srv._event("pdu", self, "C→S  " + _pdu_text(pdu))
        self.holding, self.held = True, []
        try:
            try:
                with self.srv.lock:
                    resp = self._service(pdu, num, cn, v, e)
            except _MmsErr as ex:
                self.send_mms(tlv(0xA2, tlv(0x80, ber_uint(inv)) + tlv(0xA2, tlv(0xA0, bytes([0x80 | ex.cls, 1, ex.code])))))
                return
            except (ValueError, IndexError) as ex:
                self.srv._event("log", self, "bad request: %s" % ex)
                resp = None
            except Exception:                             # noqa: BLE001 - keep the association, report it
                self.srv._event("log", self, "INTERNAL ERROR (please send this log): " +
                                traceback.format_exc().replace("\n", " | ") + " request " + pdu[:200].hex())
                resp = None
            if resp is None:                              # reject: unrecognized service
                self.send_mms(tlv(0xA4, tlv(0x80, ber_uint(inv)) + b"\x81\x01\x01"))
                return
            self.send_mms(tlv(0xA1, tlv(0x02, ber_uint(inv)) + resp))
        finally:
            self.holding = False
            held, self.held = self.held, []
            for x in held:                                # reports (GI, buffered) after the response
                self.send_mms(x)

    def _service(self, b, num, cn, v, e):
        M = self.srv.model
        if num == 2 and not cn:                           # identify
            return tlv(0xA2, tlv(0x80, (M["vendor"] or "IEC61850ANALYZER").encode()) +
                       tlv(0x81, (M["model"] or "IED simulator").encode()) +
                       tlv(0x82, (M["revision"] or "1").encode()))
        if num == 0 and not cn:                           # status
            return tlv(0xA0, b"\x80\x01\x00\x81\x01\x00")
        if num == 1:
            return self._name_list(b, v, e)
        if num == 4:
            return self._read(b, v, e)
        if num == 5:
            return self._write(b, v, e)
        if num == 6:
            return self._gvaa(b, v, e)
        if num == 12:
            return self._gnvla(b, v, e)
        if num in (11, 13):                               # define / delete named variable list
            raise _MmsErr(4, 0)                           # service: other
        return None

    def _name_list(self, b, v, e):
        M = self.srv.model
        cls, dom, after = 0, None, None
        for c, cn, n, v2, e2, t in mms.ber(b, v, e):
            if n == 0:
                for _, _, _, v3, e3, _ in mms.ber(b, v2, e2):
                    cls = int.from_bytes(b[v3:e3], "big")
            elif n == 1:
                for c3, cn3, n3, v3, e3, _ in mms.ber(b, v2, e2):
                    if n3 == 1:
                        dom = b[v3:e3].decode("latin1")
            elif n == 2:
                after = b[v2:e2].decode("latin1")
        if cls == 9:
            lst = list(M["lds"])
        elif dom is not None and dom not in M["lds"]:
            raise _MmsErr(2, 1)                           # definition: object-undefined
        elif cls == 0 and dom:
            lst = im.names(M, dom)
        elif cls == 2 and dom:
            lst = list(M["datasets"].get(dom, {}))
        else:
            lst = []
        if after is not None:
            try:
                lst = lst[lst.index(after) + 1:]
            except ValueError:
                lst = [x for x in lst if x > after]
        out, size, more = [], 0, False
        budget = self.max_pdu - 64
        for x in lst:
            enc = tlv(0x1A, x.encode())
            if size + len(enc) > budget:
                more = True
                break
            out.append(enc)
            size += len(enc)
        return tlv(0xA1, tlv(0xA0, b"".join(out)) + (b"\x81\x01\xff" if more else b"\x81\x01\x00"))

    def _var_specs(self, b, v, e):
        """VariableAccessSpecification -> ('list', [(dom, item)]) or ('named', (dom, item))"""
        for c, cn, n, v2, e2, t in mms.ber(b, v, e):
            if n == 0:
                out = []
                for _, _, _, v3, e3, _ in mms.ber(b, v2, e2):
                    for c4, cn4, n4, v4, e4, t4 in mms.ber(b, v3, e3):
                        if n4 == 0:
                            out.append(obj_name(b, v4, e4))
                return "list", out
            if n == 1:
                return "named", obj_name(b, v2, e2)
        return "list", []

    def _read(self, b, v, e):
        M = self.srv.model
        spec, refs = None, []
        for c, cn, n, v2, e2, t in mms.ber(b, v, e):
            if n == 1:
                spec, refs = self._var_specs(b, v2, e2)
        if spec == "named":
            dom, item = refs
            mem = M["datasets"].get(dom, {}).get(item)
            if mem is None:
                raise _MmsErr(2, 1)
            refs = mem
        now = time.time()
        res, size = [], 0
        for dom, item in refs:
            n = im.find(M, dom, item) if dom else None
            if n is None:
                r = b"\x80\x01\x0a"
            else:
                r = im.encode(n, now)
                if size + len(r) > self.max_pdu - 64:
                    r = b"\x80\x01\x03"
            size += len(r)
            res.append(r)
        return tlv(0xA4, tlv(0xA1, b"".join(res)))

    def _gvaa(self, b, v, e):
        for c, cn, n, v2, e2, t in mms.ber(b, v, e):
            if n == 0:
                dom, item = obj_name(b, v2, e2)
                node = im.find(self.srv.model, dom, item) if dom else None
                if node is None:
                    raise _MmsErr(2, 1)
                td = im.type_desc(node)
                if len(td) > self.max_pdu - 64:          # like the IEDs: service error pdu-size
                    raise _MmsErr(4, 3)
                return tlv(0xA6, b"\x80\x01\x00" + tlv(0xA2, td))
        raise _MmsErr(2, 1)

    def _gnvla(self, b, v, e):
        dom, item = obj_name(b, v, e)
        mem = self.srv.model["datasets"].get(dom, {}).get(item) if dom else None
        if mem is None:
            raise _MmsErr(2, 1)
        lst = b"".join(tlv(0x30, tlv(0xA0, obj_enc(d, i))) for d, i in mem)
        return tlv(0xAC, b"\x80\x01\x00" + tlv(0xA1, lst))

    def _write(self, b, v, e):
        items = kids(b, v, e)
        if not items:
            raise _MmsErr(2, 1)
        c, cn, n, v1, e1, t1 = items[0]
        if n == 1:                                        # write to a data set: not supported
            raise _MmsErr(7, 0)
        refs = []
        for _, _, _, v3, e3, _ in mms.ber(b, v1, e1):
            for c4, cn4, n4, v4, e4, t4 in mms.ber(b, v3, e3):
                if n4 == 0:
                    refs.append(obj_name(b, v4, e4))
        data = kids(b, items[1][3], items[1][4]) if len(items) > 1 else []
        res = []
        for i, (dom, item) in enumerate(refs):
            d = data[i] if i < len(data) else None
            code = self.srv.write(self, dom, item, b, d)
            res.append(b"\x81\x00" if code is None else bytes([0x80, 1, code]))
        return tlv(0xA5, b"".join(res))


def _pdu_text(pdu):
    try:
        r = mms.parse_pdu(pdu)
        return ("%s  %s" % (r["mtype"], r["info"]))[:300]
    except Exception:                                     # noqa: BLE001
        return "%d bytes %s" % (len(pdu), pdu[:24].hex())


def _content(pdu):
    ln, v = _len(pdu, 1)
    return v, v + ln


def _len(b, p):
    x = b[p]
    if x < 0x80:
        return x, p + 1
    n = x & 0x7F
    return int.from_bytes(b[p + 1:p + 1 + n], "big"), p + 1 + n


class _MmsErr(Exception):
    def __init__(self, cls, code):
        super().__init__("%d/%d" % (cls, code))
        self.cls, self.code = cls, code


# ---------------------------------------------------------------- server + report engine
class Server:
    def __init__(self, model, on_event=None):
        self.model = model
        self.on_event = on_event
        self.lock = threading.RLock()
        self.clients = []
        self.sock = None
        self.running = False
        self.n_reports = 0
        self.log_pdus = False
        for rn in model["rcbs"]:
            rn["rcb"].update(owner=None, buffer=[], ovfl=False, pending={}, first=None, next_intg=None,
                             entry=0, sent=0)

    # ---- events to the GUI
    def _event(self, kind, client, text):
        if self.on_event:
            try:
                self.on_event(kind, client, text)
            except Exception:                             # noqa: BLE001
                pass

    # ---- listen
    def start(self, ip="0.0.0.0", port=102):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.listen(8)
        self.sock = s
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._engine, daemon=True).start()

    def _accept(self):
        while self.running:
            try:
                c, addr = self.sock.accept()
            except OSError:
                break
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            cl = Client(self, c, addr)
            with self.lock:
                self.clients.append(cl)
            self._event("connect", cl, "connected")
            cl.start()

    def stop(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        for c in list(self.clients):
            c.alive = False
            try:
                c.sock.shutdown(socket.SHUT_RDWR)
                c.sock.close()
            except OSError:
                pass

    def _closed(self, client, why):
        with self.lock:
            if client in self.clients:
                self.clients.remove(client)
            for rn in self.model["rcbs"]:
                st = rn["rcb"]
                if st["owner"] is client:
                    self._attr_set(rn, "RptEna", False)
                    if not st["buffered"]:
                        self._attr_set(rn, "Resv", False)
                    self._attr_set(rn, "Owner", "")
                    st["owner"] = None
                    st["pending"] = {}
                    self._event("rcb", client, "%s released (client gone)" % im.ref(rn))
        self._event("close", client, why)

    # ---- RCB attributes
    @staticmethod
    def _attr(rn, name, default=None):
        n = next((k for k in rn["kids"] if k["name"] == name), None)
        return n["value"] if n is not None else default

    @staticmethod
    def _attr_set(rn, name, value):
        n = next((k for k in rn["kids"] if k["name"] == name), None)
        if n is not None:
            n["value"] = value

    def members(self, rn):
        ds = self._attr(rn, "DatSet") or ""
        if "/" not in ds:
            return []
        dom, item = ds.split("/", 1)
        return self.model["datasets"].get(dom, {}).get(item.replace(".", "$")) or []

    def write(self, client, dom, item, b, d):
        """-> None (success) or DataAccessError code"""
        M = self.model
        node = im.find(M, dom, item) if dom else None
        if node is None:
            return ERR["object-non-existent"]
        if d is None:
            return ERR["type-inconsistent"]
        parts = item.split("$")
        if len(parts) != 4 or parts[1] not in ("RP", "BR"):
            self._event("log", client, "write %s/%s refused (access denied)" % (dom, item))
            return ERR["object-access-denied"]
        rn = node["parent"]
        st = rn["rcb"]
        attr = parts[3]
        c, cn, n, v, e, t = d
        if cn:
            return ERR["type-inconsistent"]
        val = im.decode(b[t], b[v:e])
        other = st["owner"] is not None and st["owner"] is not client
        enabled = bool(self._attr(rn, "RptEna"))
        bt = node["btype"]
        want = {"BOOLEAN": (0x83,), "VisString129": (0x8A,), "INT32U": (0x86, 0x85), "INT16U": (0x86, 0x85),
                "INT8U": (0x86, 0x85), "INT16": (0x85, 0x86), "OptFlds": (0x84,), "TrgOps": (0x84,),
                "Octet8": (0x89,), "Octet64": (0x89,), "EntryTime": (0x8C,)}.get(bt, ())
        if b[t] not in want:
            return ERR["type-inconsistent"]
        if attr in ("SqNum", "ConfRev", "Owner", "TimeOfEntry"):
            return ERR["object-access-denied"]
        if other:
            return ERR["temporarily-unavailable"]
        ref = im.ref(rn)
        if attr == "RptEna":
            if val:
                if not self.members(rn):
                    return ERR["object-value-invalid"]
                st["owner"] = client
                self._attr_set(rn, "Owner", _owner_hex(client.ip))
                self._attr_set(rn, "RptEna", True)
                st["next_intg"] = None
                self._event("rcb", client, "%s enabled by %s" % (ref, client.ip))
                if st["buffered"]:
                    self._send_buffer(rn)
            else:
                self._flush(rn)
                self._attr_set(rn, "RptEna", False)
                keep = (not st["buffered"] and self._attr(rn, "Resv")) or \
                    (st["buffered"] and int(self._attr(rn, "ResvTms") or 0) > 0)
                if not keep:
                    st["owner"] = None
                    self._attr_set(rn, "Owner", "")
                self._event("rcb", client, "%s disabled" % ref)
            return None
        if attr == "Resv":
            self._attr_set(rn, "Resv", bool(val))
            st["owner"] = client if val else (client if enabled else None)
            self._attr_set(rn, "Owner", _owner_hex(client.ip) if val else "")
            self._event("rcb", client, "%s %s" % (ref, "reserved" if val else "reservation released"))
            return None
        if attr == "ResvTms":
            self._attr_set(rn, "ResvTms", int(val))
            if int(val) != 0:
                st["owner"] = client
                self._attr_set(rn, "Owner", _owner_hex(client.ip))
            elif not enabled:
                st["owner"] = None
                self._attr_set(rn, "Owner", "")
            return None
        if attr == "GI":
            if not val:
                return None
            if not enabled:
                return ERR["temporarily-unavailable"]
            st["owner"] = client
            self._flush(rn)
            self._report(rn, {i: {"gi"} for i in range(len(self.members(rn)))})
            self._event("rcb", client, "%s general interrogation" % ref)
            return None
        if enabled:                                       # the other attributes only while disabled
            return ERR["temporarily-unavailable"]
        if not st["buffered"]:
            st["owner"] = client                          # implicit reservation (Ed2)
            self._attr_set(rn, "Owner", _owner_hex(client.ip))
        if attr == "PurgeBuf":
            if val:
                st["buffer"] = []
                st["ovfl"] = False
                self._event("rcb", client, "%s buffer purged" % ref)
            return None
        if attr == "DatSet":
            ds = str(val)
            d2, _, i2 = ds.partition("/")
            if ds and M["datasets"].get(d2, {}).get(i2.replace(".", "$")) is None:
                return ERR["object-value-invalid"]
            if ds != self._attr(rn, "DatSet"):
                self._attr_set(rn, "DatSet", ds)
                self._attr_set(rn, "ConfRev", int(self._attr(rn, "ConfRev") or 0) + 1)
                st["buffer"] = []
            return None
        if bt in ("OptFlds", "TrgOps"):
            table = im.OPT_BITS if bt == "OptFlds" else im.TRG_BITS
            val = {table[i] for i, x in enumerate(val) if x and i < len(table) and table[i] != "reserved"}
        elif bt.startswith("INT"):
            val = int(val)
        self._attr_set(rn, attr, val)
        self._event("rcb", client, "%s %s = %s" % (ref, attr, im.value_text(node)))
        return None

    # ---- values changed by hand
    def set_value(self, node, value, kind=None):
        """leaf value set by hand; kind None: dchg if the value changed, else dupd"""
        with self.lock:
            self._flush_hits(node)                        # a pending entry of this signal goes out first
            old = node["value"]
            node["value"] = value
            if kind is None:
                kind = "qchg" if node["btype"] == "Quality" else ("dchg" if old != value else "dupd")
            self._touch_t(node)
            self.trigger(node, kind)

    def _touch_t(self, node):
        p = node["parent"]
        while p is not None:
            t = next((k for k in p["kids"] if k["name"] == "t" and k["btype"] == "Timestamp"), None)
            if t is not None:
                t["value"] = time.time()
                return
            p = p["parent"]

    def _hits(self, rn, node):
        dom, item = node["path"]
        return [i for i, (md, mi) in enumerate(self.members(rn))
                if md == dom and (mi == item or item.startswith(mi + "$") or mi.startswith(item + "$"))]

    def _flush_hits(self, node):
        for rn in self.model["rcbs"]:
            st = rn["rcb"]
            if st["pending"] and any(i in st["pending"] for i in self._hits(rn, node)):
                self._flush(rn)

    def trigger(self, node, kind):
        if node["trg"] and kind not in node["trg"]:
            return
        for rn in self.model["rcbs"]:
            trg = self._attr(rn, "TrgOps") or set()
            if kind not in trg:
                continue
            st = rn["rcb"]
            enabled = bool(self._attr(rn, "RptEna"))
            if not enabled and not st["buffered"]:
                continue
            hit = self._hits(rn, node)
            if not hit:
                continue
            buftm = int(self._attr(rn, "BufTm") or 0)
            if buftm <= 0:
                self._report(rn, {i: {kind} for i in hit})
                continue
            if any(i in st["pending"] for i in hit):
                self._flush(rn)
            for i in hit:
                st["pending"].setdefault(i, set()).add(kind)
            if st["first"] is None:
                st["first"] = time.time()

    def _flush(self, rn):
        st = rn["rcb"]
        if st["pending"]:
            p, st["pending"], st["first"] = st["pending"], {}, None
            self._report(rn, p)

    def _engine(self):
        while self.running:
            time.sleep(0.02)
            now = time.time()
            with self.lock:
                for rn in self.model["rcbs"]:
                    st = rn["rcb"]
                    if st["first"] is not None and now - st["first"] >= int(self._attr(rn, "BufTm") or 0) / 1000.0:
                        self._flush(rn)
                    if not self._attr(rn, "RptEna"):
                        st["next_intg"] = None
                        continue
                    ip = int(self._attr(rn, "IntgPd") or 0)
                    if "period" not in (self._attr(rn, "TrgOps") or set()) or ip <= 0:
                        continue
                    if st["next_intg"] is None:
                        st["next_intg"] = now + ip / 1000.0
                    elif now >= st["next_intg"]:
                        st["next_intg"] += ip / 1000.0
                        if st["next_intg"] < now:
                            st["next_intg"] = now + ip / 1000.0
                        self._flush(rn)
                        self._report(rn, {i: {"integrity"} for i in range(len(self.members(rn)))})

    # ---- report encoding / sending
    def _report(self, rn, incl):
        st = rn["rcb"]
        mem = self.members(rn)
        if not mem or not incl:
            return
        now = time.time()
        values = {}
        for i in incl:
            if i < len(mem):
                n = im.find(self.model, *mem[i])
                values[i] = im.encode(n, now) if n is not None else b"\x80\x01\x0a"
        st["entry"] += 1
        entry = dict(id=st["entry"].to_bytes(8, "big"), t=now, incl={i: set(r) for i, r in incl.items()},
                     values=values)
        if not self._attr(rn, "RptEna"):
            if st["buffered"]:
                st["buffer"].append(entry)
                if len(st["buffer"]) > BUF_MAX:
                    st["buffer"].pop(0)
                    st["ovfl"] = True
            return
        self._send_entry(rn, entry)

    def _send_buffer(self, rn):
        st = rn["rcb"]
        eid = bytes.fromhex(self._attr(rn, "EntryID") or "00" * 8)
        buf = st["buffer"]
        if any(eid) and any(x["id"] == eid for x in buf):
            k = next(i for i, x in enumerate(buf) if x["id"] == eid)
            buf = buf[k + 1:]
        for x in buf:
            self._send_entry(rn, x)
        st["buffer"] = []
        st["ovfl"] = False

    def _send_entry(self, rn, entry):
        st = rn["rcb"]
        cl = st["owner"]
        if cl is None or not cl.alive:
            return
        mem = self.members(rn)
        opt = self._attr(rn, "OptFlds") or set()
        if not st["buffered"]:
            opt = opt - {"buffer-ovfl", "entryID"}
        opt = opt - {"segmentation"}
        sq = int(self._attr(rn, "SqNum") or 0)
        d = [tlv(0x8A, str(self._attr(rn, "RptID") or "").encode()), tlv(0x84, im.bits_bytes(opt, im.OPT_BITS))]
        if "seq-num" in opt:
            d.append(tlv(0x86, ber_uint(sq)))
        if "time-stamp" in opt:
            d.append(tlv(0x8C, im.binary_time(entry["t"])))
        if "data-set" in opt:
            d.append(tlv(0x8A, str(self._attr(rn, "DatSet") or "").encode()))
        if "buffer-ovfl" in opt:
            d.append(tlv(0x83, b"\x01" if st["ovfl"] else b"\x00"))
        if "entryID" in opt:
            d.append(tlv(0x89, entry["id"]))
        if "conf-rev" in opt:
            d.append(tlv(0x86, ber_uint(int(self._attr(rn, "ConfRev") or 0))))
        idx = sorted(i for i in entry["incl"] if i < len(mem))
        d.append(tlv(0x84, im.bits_bytes({str(i) for i in idx}, [str(i) for i in range(len(mem))])))
        if "data-ref" in opt:
            for i in idx:
                d.append(tlv(0x8A, ("%s/%s" % mem[i]).encode()))
        for i in idx:
            d.append(entry["values"][i])
        if "reason" in opt:
            for i in idx:
                d.append(tlv(0x84, im.bits_bytes(entry["incl"][i], REASON_BITS)))
        pdu = tlv(0xA3, tlv(0xA0, tlv(0xA1, tlv(0x80, b"RPT")) + tlv(0xA0, b"".join(d))))
        self._attr_set(rn, "SqNum", (sq + 1) & (0xFFFF if st["buffered"] else 0xFF))
        if st["buffered"]:
            self._attr_set(rn, "EntryID", entry["id"].hex())
            self._attr_set(rn, "TimeOfEntry", entry["t"])
        try:
            cl.send_mms(pdu)
            cl.n_rpt += 1
            st["sent"] += 1
            self.n_reports += 1
            reasons = sorted({r for x in entry["incl"].values() for r in x})
            self._event("report", cl, "%s -> %s: SqNum %d, %d entr%s, %s" % (
                self._attr(rn, "RptID"), cl.ip, sq, len(idx), "y" if len(idx) == 1 else "ies", ", ".join(reasons)))
        except OSError as ex:
            self._event("log", cl, "report not sent: %s" % ex)


def _owner_hex(ip):
    try:
        return socket.inet_aton(ip).hex()
    except OSError:
        return ""


def pc_addresses():
    """[(ip, adapter name, adapter description)] of this PC (Scapy / Npcap if present)"""
    out = []
    try:
        from scapy.config import conf
        import scapy.all as _sa  # loads the interfaces (Npcap)
        del _sa
        try:
            conf.ifaces.reload()
        except Exception:                               # noqa: BLE001
            pass
        for itf in conf.ifaces.values():
            ips = []
            for x in (getattr(itf, "ips", {}) or {}).get(4, []) or []:
                ips.append(x)
            if not ips and getattr(itf, "ip", ""):
                ips.append(itf.ip)
            for ip in ips:
                if ip and ip != "0.0.0.0" and not ip.startswith("169.254.") and ip not in [o[0] for o in out]:
                    out.append((ip, getattr(itf, "name", "") or "", getattr(itf, "description", "") or ""))
    except Exception:                                   # noqa: BLE001
        pass
    for ip in local_ips():
        if ip not in ("0.0.0.0",) and ip not in [o[0] for o in out]:
            out.append((ip, "", "loopback" if ip.startswith("127.") else ""))
    return out


def adapter_dhcp(name):
    """True / False: DHCP of a Windows adapter (registry, no administrator, no PowerShell); None: unknown"""
    import sys
    if sys.platform != "win32" or not name:
        return None
    try:
        from scapy.config import conf
        guid = None
        for itf in conf.ifaces.values():
            if getattr(itf, "name", "") == name:
                guid = getattr(itf, "guid", None)
                break
        if not guid:
            return None
        import winreg
        key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s" % guid
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            v, _ = winreg.QueryValueEx(k, "EnableDHCP")
            return bool(v)
    except Exception:                                   # noqa: BLE001
        return None


def local_ips():
    out = ["0.0.0.0"]
    try:
        for x in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            if x[4][0] not in out:
                out.append(x[4][0])
    except OSError:
        pass
    if "127.0.0.1" not in out:
        out.append("127.0.0.1")
    return out
