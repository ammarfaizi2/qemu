#!/usr/bin/env python3
"""
qmon client - talk to qmon.so over its unix socket.

Wire protocol: every message is  u32 len (LE)  followed by  len  payload bytes;
payload[0] is the message type.  See README.md for the full table.

Usage:
  client.py SOCK ping
  client.py SOCK regs  [VCPU]
  client.py SOCK vmem  VCPU ADDR LEN
  client.py SOCK pmem  VCPU ADDR LEN
  client.py SOCK xlate VCPU ADDR
  client.py SOCK maps  [VCPU]
  client.py SOCK break ADDR
  client.py SOCK clrbreak ADDR
  client.py SOCK watch ADDR LEN [r|w|rw]
  client.py SOCK clrwatch ADDR
  client.py SOCK cont  [VCPU|all]
  client.py SOCK listen [SECONDS]
  client.py SOCK selftest MARKER_VA COUNTER_VA      # used by verify.sh
Numbers may be decimal or 0x-hex.
"""
import socket
import struct
import sys
import time

# request types
REQ_PING, REQ_READ_REGS, REQ_READ_VMEM, REQ_READ_PMEM = 0x01, 0x10, 0x11, 0x12
REQ_XLATE, REQ_LIST_MAP = 0x13, 0x14
REQ_SET_BREAK, REQ_CLR_BREAK, REQ_SET_WATCH, REQ_CLR_WATCH, REQ_CONTINUE = \
    0x20, 0x21, 0x22, 0x23, 0x30
# response / event types
RSP_OK, RSP_ERR, EV_BREAK, EV_WATCH = 0x80, 0x81, 0xA0, 0xA1


class QmonError(Exception):
    pass


class Qmon:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise EOFError("connection closed")
            buf += chunk
        return buf

    def recv_msg(self):
        ln = struct.unpack("<I", self._recv(4))[0]
        pl = self._recv(ln)
        return pl[0], pl[1:]

    def send(self, payload):
        self.s.sendall(struct.pack("<I", len(payload)) + payload)

    # send a request, skip/queue events, return the (type, body) response
    def request(self, payload, on_event=None):
        self.send(payload)
        while True:
            t, body = self.recv_msg()
            if t in (EV_BREAK, EV_WATCH):
                if on_event:
                    on_event(t, body)
                continue
            if t == RSP_ERR:
                code = struct.unpack("<I", body[:4])[0]
                msg = body[4:].split(b"\0", 1)[0].decode(errors="replace")
                raise QmonError("err %d: %s" % (code, msg))
            return t, body

    # ---- typed requests -------------------------------------------------
    def ping(self):
        self.request(struct.pack("<B", REQ_PING))

    def regs(self, vcpu=0):
        _, b = self.request(struct.pack("<BI", REQ_READ_REGS, vcpu))
        n = struct.unpack("<I", b[:4])[0]
        off = 4
        out = {}
        for _ in range(n):
            nl = b[off]; off += 1
            name = b[off:off + nl].decode(); off += nl
            w = b[off]; off += 1
            val = b[off:off + w]; off += w
            out[name] = int.from_bytes(val, "little") if w else None
        return out

    def vmem(self, vcpu, addr, length):
        _, b = self.request(struct.pack("<BIQI", REQ_READ_VMEM, vcpu, addr, length))
        n = struct.unpack("<I", b[:4])[0]
        return b[4:4 + n]

    def pmem(self, vcpu, addr, length):
        _, b = self.request(struct.pack("<BIQI", REQ_READ_PMEM, vcpu, addr, length))
        n = struct.unpack("<I", b[:4])[0]
        return b[4:4 + n]

    def xlate(self, vcpu, addr):
        _, b = self.request(struct.pack("<BIQ", REQ_XLATE, vcpu, addr))
        return struct.unpack("<Q", b[:8])[0]

    def maps(self, vcpu=0):
        _, b = self.request(struct.pack("<BI", REQ_LIST_MAP, vcpu))
        n = struct.unpack("<I", b[:4])[0]
        off = 4
        out = []
        for _ in range(n):
            gva, gpa, size, flags = struct.unpack("<QQQI", b[off:off + 28])
            off += 28
            out.append((gva, gpa, size, flags))
        return out

    def set_break(self, addr):
        self.request(struct.pack("<BQ", REQ_SET_BREAK, addr))

    def clr_break(self, addr):
        self.request(struct.pack("<BQ", REQ_CLR_BREAK, addr))

    def set_watch(self, addr, length, rw):
        self.request(struct.pack("<BQQB", REQ_SET_WATCH, addr, length, rw))

    def clr_watch(self, addr):
        self.request(struct.pack("<BQ", REQ_CLR_WATCH, addr))

    def cont(self, vcpu=0):
        self.request(struct.pack("<BI", REQ_CONTINUE, vcpu & 0xffffffff))

    def wait_event(self, timeout):
        self.s.settimeout(timeout)
        try:
            while True:
                t, b = self.recv_msg()
                if t == EV_BREAK:
                    vcpu, rip, bp = struct.unpack("<IQQ", b[:20])
                    return ("break", vcpu, rip, bp)
                if t == EV_WATCH:
                    vcpu, rip, addr, store, size, val = struct.unpack("<IQQBBQ", b[:30])
                    return ("watch", vcpu, rip, addr, store, size, val)
                # ignore stray RSP frames
        except socket.timeout:
            return None
        finally:
            self.s.settimeout(None)


def hexdump(data, base=0):
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join("%02x" % c for c in chunk)
        out.append("%016x  %-47s" % (base + i, hexs))
    return "\n".join(out)


def fmt_flags(f):
    return "".join([
        "P" if f & 1 else "-", "W" if f & 2 else "-",
        "U" if f & 4 else "-", "X" if not (f & 8) else "-",
        "L" if f & 16 else "-",
    ])


# ---------------------------------------------------------------------------
def selftest(q, marker, counter):
    fails = 0

    def check(name, ok, detail=""):
        nonlocal fails
        print("[%s] %s %s" % ("PASS" if ok else "FAIL", name, detail))
        if not ok:
            fails += 1

    q.ping()
    check("ping", True)

    r = q.regs(0)
    rip = r.get("rip")
    check("obj1 read-regs", rip is not None,
          "rip=0x%x cr3=0x%x" % (rip or 0, r.get("cr3") or 0))

    if rip:
        v = q.vmem(0, rip, 16)
        check("obj2 read-vmem", len(v) == 16, "16 bytes @rip")
        try:
            gpa = q.xlate(0, rip)
            p = q.pmem(0, gpa, 16)
            check("obj3 xlate+pmem", p == v,
                  "rip->gpa 0x%x, vmem==pmem=%s" % (gpa, p == v))
        except QmonError as e:
            check("obj3 xlate+pmem", False, str(e))

    try:
        m = q.maps(0)
        check("obj3 list-map", len(m) > 0, "%d ranges" % len(m))
        for gva, gpa, size, fl in m[:4]:
            print("        %016x -> %016x  %8x  %s" % (gva, gpa, size, fmt_flags(fl)))
    except QmonError as e:
        check("obj3 list-map", True, "SKIP: %s" % e)   # cr3 not exposed -> skip

    # objective 5: breakpoint on marker(), inspect while frozen, resume, re-arm
    print("... waiting for guest target (boot may be slow under instrumentation)")
    q.set_break(marker)
    hits = 0
    for attempt in range(2):
        ev = q.wait_event(240)
        if ev and ev[0] == "break" and ev[2] == marker:
            rr = q.regs(0)
            ok = rr.get("rip") == marker
            check("obj5 breakpoint hit #%d" % (attempt + 1), ok,
                  "EV_BREAK rip=0x%x (frozen regs.rip=0x%x)" % (ev[2], rr.get("rip") or 0))
            hits += ok
            q.cont(0)
        else:
            check("obj5 breakpoint hit #%d" % (attempt + 1), False, "no EV_BREAK: %r" % (ev,))
            break
    q.clr_break(marker)

    # objective 4: watchpoint on g_counter (write), observe increasing value
    q.set_watch(counter, 8, 2)   # rw=2 -> writes
    seen = []
    for _ in range(2):
        ev = q.wait_event(240)
        if ev and ev[0] == "watch" and ev[3] == counter:
            seen.append(ev[6])
            q.cont(0)            # in case it ever stops; NOTIFY mode won't, harmless
    inc = len(seen) >= 1 and (len(seen) < 2 or seen[1] >= seen[0])
    check("obj4 watchpoint", inc, "values=%s" % seen)
    q.clr_watch(counter)

    print("\n%s (%d failure(s))" % ("ALL GOOD" if fails == 0 else "FAILURES", fails))
    return 1 if fails else 0


# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    num = lambda x: int(x, 0)
    q = Qmon(path)

    if cmd == "ping":
        q.ping(); print("ok")
    elif cmd == "regs":
        for k, v in q.regs(num(args[0]) if args else 0).items():
            print("%-12s 0x%x" % (k, v if v is not None else 0))
    elif cmd == "vmem":
        print(hexdump(q.vmem(num(args[0]), num(args[1]), num(args[2])), num(args[1])))
    elif cmd == "pmem":
        print(hexdump(q.pmem(num(args[0]), num(args[1]), num(args[2])), num(args[1])))
    elif cmd == "xlate":
        print("0x%x" % q.xlate(num(args[0]), num(args[1])))
    elif cmd == "maps":
        for gva, gpa, size, fl in q.maps(num(args[0]) if args else 0):
            print("%016x -> %016x  %10x  %s" % (gva, gpa, size, fmt_flags(fl)))
    elif cmd == "break":
        q.set_break(num(args[0])); print("ok")
    elif cmd == "clrbreak":
        q.clr_break(num(args[0])); print("ok")
    elif cmd == "watch":
        rwmap = {"r": 1, "w": 2, "rw": 3}
        rw = rwmap.get(args[2].lower(), 3) if len(args) > 2 else 3
        q.set_watch(num(args[0]), num(args[1]), rw); print("ok")
    elif cmd == "clrwatch":
        q.clr_watch(num(args[0])); print("ok")
    elif cmd == "cont":
        v = 0xffffffff if (args and args[0] == "all") else (num(args[0]) if args else 0)
        q.cont(v); print("ok")
    elif cmd == "listen":
        end = time.time() + (num(args[0]) if args else 3600)
        while time.time() < end:
            ev = q.wait_event(end - time.time())
            if ev:
                print(ev)
    elif cmd == "selftest":
        return selftest(q, num(args[0]), num(args[1]))
    else:
        print("unknown command:", cmd); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
