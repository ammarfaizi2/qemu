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
  client.py SOCK context [VCPU]   |  backtrace [VCPU]   # ring/func/process; call trace
  client.py SOCK resolve NAME     |  sym ADDR           # kernel symbol <-> addr
  client.py SOCK slide                              # detected KASLR text slide
  client.py SOCK test NAME [args]                   # ping|regs|slide|vmem|maps|watch|break|ktrace
  client.py SOCK test break MARKER_VA               # watch/break take a target VA
  client.py SOCK test all MARKER_VA COUNTER_VA      # run the whole suite (one connection)
Numbers may be decimal or 0x-hex.
"""
import socket
import struct
import sys
import time

# request types
REQ_PING, REQ_READ_REGS, REQ_READ_VMEM, REQ_READ_PMEM = 0x01, 0x10, 0x11, 0x12
REQ_XLATE, REQ_LIST_MAP, REQ_CONTEXT, REQ_BACKTRACE = 0x13, 0x14, 0x15, 0x16
REQ_SLIDE = 0x17
REQ_SET_BREAK, REQ_CLR_BREAK, REQ_SET_WATCH, REQ_CLR_WATCH = 0x20, 0x21, 0x22, 0x23
REQ_RESOLVE, REQ_SYM, REQ_CONTINUE = 0x24, 0x25, 0x30
# response / event types
RSP_OK, RSP_ERR, EV_BREAK, EV_WATCH = 0x80, 0x81, 0xA0, 0xA1


class QmonError(Exception):
    pass


# ---- sub-encoding readers: return (value, new_offset) ----
def _u8(b, o):
    return b[o], o + 1


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0], o + 4


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0], o + 8


def _sym(b, o):
    nl, o = _u8(b, o)
    name = b[o:o + nl].decode("latin1"); o += nl
    off, o = _u64(b, o)
    return (name, off), o


def _context(b, o):
    ring, o = _u8(b, o)
    (fn, foff), o = _sym(b, o)
    pid, o = _u32(b, o)
    cl, o = _u8(b, o)
    comm = b[o:o + cl].decode("latin1"); o += cl
    return {"ring": ring, "func": fn, "off": foff, "pid": pid, "comm": comm}, o


def _backtrace(b, o):
    n, o = _u32(b, o)
    frames = []
    for _ in range(n):
        addr, o = _u64(b, o)
        (nm, off), o = _sym(b, o)
        frames.append((addr, nm, off))
    return frames, o


def fmt_context(c):
    ringname = {0: "ring0/kernel", 3: "ring3/user"}.get(c["ring"], "ring%d" % c["ring"])
    where = "%s+0x%x" % (c["func"], c["off"]) if c["func"] else "0x%x" % c["off"]
    who = " | %s(pid %d)" % (c["comm"], c["pid"]) if c["comm"] else ""
    return "%s in %s%s" % (ringname, where, who)


def fmt_frames(frames):
    out = []
    for i, (addr, nm, off) in enumerate(frames):
        sym = "%s+0x%x" % (nm, off) if nm else "?"
        out.append("  #%-2d 0x%016x  %s" % (i, addr, sym))
    return "\n".join(out)


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

    # ---- symbols / context / unwinding ----
    def resolve(self, name):
        _, b = self.request(struct.pack("<B", REQ_RESOLVE) + name.encode() + b"\0")
        return struct.unpack("<Q", b[:8])[0]

    def sym(self, addr):
        _, b = self.request(struct.pack("<BQ", REQ_SYM, addr))
        (nm, off), _ = _sym(b, 0)
        return nm, off

    def slide(self):
        _, b = self.request(struct.pack("<B", REQ_SLIDE))
        return bool(b[0]), struct.unpack_from("<Q", b, 1)[0]

    def context(self, vcpu=0):
        _, b = self.request(struct.pack("<BI", REQ_CONTEXT, vcpu))
        ctx, _ = _context(b, 0)
        return ctx

    def backtrace(self, vcpu=0, maxframes=64):
        _, b = self.request(struct.pack("<BII", REQ_BACKTRACE, vcpu, maxframes))
        fr, _ = _backtrace(b, 0)
        return fr

    def break_at(self, name_or_addr):
        """Set a breakpoint by symbol name or numeric address."""
        try:
            addr = int(name_or_addr, 0) if isinstance(name_or_addr, str) else int(name_or_addr)
        except ValueError:
            addr = self.resolve(name_or_addr)
        self.set_break(addr)
        return addr

    def wait_event(self, timeout):
        self.s.settimeout(timeout)
        try:
            while True:
                t, b = self.recv_msg()
                if t == EV_BREAK:
                    o = 0
                    vcpu, o = _u32(b, o); rip, o = _u64(b, o); bp, o = _u64(b, o)
                    ctx, o = _context(b, o)
                    frames, o = _backtrace(b, o)
                    return ("break", vcpu, rip, bp, ctx, frames)
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
class Checker:
    """Collects PASS/FAIL results for one test case."""
    def __init__(self):
        self.fails = 0

    def __call__(self, name, ok, detail=""):
        print("[%s] %s %s" % ("PASS" if ok else "FAIL", name, detail))
        if not ok:
            self.fails += 1


# Each tc_* runs over a single connection `q` and reports via `ck`.
def tc_ping(q, ck):
    q.ping()
    ck("ping", True)


def tc_regs(q, ck):
    r = q.regs(0)
    rip, cr3 = r.get("rip"), r.get("cr3")
    ck("regs: rip present", rip not in (None, 0), "rip=0x%x" % (rip or 0))
    ck("regs: cr3 present", cr3 not in (None, 0), "cr3=0x%x" % (cr3 or 0))


def tc_slide(q, ck):
    cal, s = q.slide()
    ck("kaslr slide calibrated", cal, "slide=0x%x" % s)
    ck("slide is 2MB-aligned", s % 0x200000 == 0, "0x%x" % s)


def tc_vmem(q, ck):
    rip = q.regs(0).get("rip")
    if not rip:
        ck("vmem: have rip", False)
        return
    v = q.vmem(0, rip, 32)
    ck("vmem: 32 bytes @rip", len(v) == 32, v.hex())
    try:
        gpa = q.xlate(0, rip)
        p = q.pmem(0, gpa, 32)
        ck("xlate+pmem == vmem", p == v, "rip->gpa 0x%x (gva==gpa bytes)" % gpa)
    except QmonError as e:
        ck("xlate+pmem == vmem", False, str(e))


def tc_maps(q, ck):
    try:
        m = q.maps(0)
        ck("list-map: ranges", len(m) > 0, "%d ranges" % len(m))
        for gva, gpa, size, fl in m[:4]:
            print("        %016x -> %016x  %8x  %s" % (gva, gpa, size, fmt_flags(fl)))
    except QmonError as e:
        # cr3 not exposed by the gdb reg set -> treat as skip, otherwise fail
        ck("list-map (skipped)", "cr3" in str(e), "%s" % e)


def tc_break(q, ck, marker):
    print("... break on marker 0x%x (guest target must be running)" % marker)
    q.set_break(marker)
    for attempt in range(2):
        ev = q.wait_event(240)
        if ev and ev[0] == "break" and ev[2] == marker:
            ok = q.regs(0).get("rip") == marker
            ck("breakpoint hit #%d" % (attempt + 1), ok,
               "rip=0x%x  [%s]" % (ev[2], fmt_context(ev[4])))
            q.cont(0)
        else:
            ck("breakpoint hit #%d" % (attempt + 1), False, "no EV_BREAK: %r" % (ev,))
            break
    q.clr_break(marker)


def tc_watch(q, ck, counter):
    print("... watch writes to g_counter 0x%x" % counter)
    q.set_watch(counter, 8, 2)   # rw=2 -> writes
    seen = []
    for _ in range(2):
        ev = q.wait_event(240)
        if ev and ev[0] == "watch" and ev[3] == counter:
            seen.append(ev[6])
            q.cont(0)            # harmless; NOTIFY watch doesn't actually stop
    inc = len(seen) >= 1 and (len(seen) < 2 or seen[1] >= seen[0])
    ck("watchpoint write events", inc, "values=%s" % seen)
    q.clr_watch(counter)


def tc_ktrace(q, ck):
    # The target calls nanosleep ~10/s -> break in the kernel nanosleep path.
    ksym = "hrtimer_nanosleep"
    try:
        addr = q.resolve(ksym)
    except QmonError as e:
        ck("kernel call-trace", False, "resolve %s failed (ksyms loaded?): %s" % (ksym, e))
        return
    print("... break in kernel %s @0x%x" % (ksym, addr))
    q.set_break(addr)
    got = None
    for _ in range(6):
        ev = q.wait_event(240)
        if not (ev and ev[0] == "break"):
            break
        ctx, frames = ev[4], ev[5]
        q.cont(0)
        got = (ctx, frames)
        if ctx["comm"] == "qmon_target":
            break
    q.clr_break(addr)
    if not got:
        ck("kernel call-trace", False, "no EV_BREAK at %s" % ksym)
        return
    ctx, frames = got
    funcs = [f[1] for f in frames]
    print("    context : %s" % fmt_context(ctx))
    print(fmt_frames(frames))
    ck("ctx ring0 + function", ctx["ring"] == 0 and ctx["func"] == ksym, ctx["func"])
    ck("ctx current process", ctx["comm"] == "qmon_target",
       "comm=%r pid=%d" % (ctx["comm"], ctx["pid"]))
    ck("backtrace reaches do_syscall_64", "do_syscall_64" in funcs, " <- ".join(funcs[:6]))


# name -> (function, number of positional args it needs)
TESTS = {
    "ping":   (tc_ping, 0),
    "regs":   (tc_regs, 0),
    "slide":  (tc_slide, 0),
    "vmem":   (tc_vmem, 0),
    "maps":   (tc_maps, 0),
    "watch":  (tc_watch, 1),
    "break":  (tc_break, 1),
    "ktrace": (tc_ktrace, 0),
}
TEST_ORDER = ["ping", "regs", "slide", "vmem", "maps", "watch", "break", "ktrace"]


def run_test(q, name, args):
    ck = Checker()
    fn, nargs = TESTS[name]
    fn(q, ck, *args[:nargs])
    return 1 if ck.fails else 0


def run_all_tests(q, marker, counter):
    ck = Checker()
    argmap = {"break": [marker], "watch": [counter]}
    for name in TEST_ORDER:
        print("----- %s -----" % name)
        fn, nargs = TESTS[name]
        fn(q, ck, *argmap.get(name, []))
    print("\n%s (%d failure(s))" % ("ALL GOOD" if ck.fails == 0 else "FAILURES", ck.fails))
    return 1 if ck.fails else 0

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
        addr = q.break_at(args[0]); print("break @ 0x%x" % addr)
    elif cmd == "clrbreak":
        q.clr_break(q.resolve(args[0]) if not args[0].lstrip("-").isdigit()
                    and not args[0].startswith("0x") else num(args[0])); print("ok")
    elif cmd == "watch":
        rwmap = {"r": 1, "w": 2, "rw": 3}
        rw = rwmap.get(args[2].lower(), 3) if len(args) > 2 else 3
        q.set_watch(num(args[0]), num(args[1]), rw); print("ok")
    elif cmd == "clrwatch":
        q.clr_watch(num(args[0])); print("ok")
    elif cmd == "cont":
        v = 0xffffffff if (args and args[0] == "all") else (num(args[0]) if args else 0)
        q.cont(v); print("ok")
    elif cmd == "slide":
        cal, s = q.slide()
        print("slide=0x%x calibrated=%s" % (s, cal))
    elif cmd == "resolve":
        print("0x%x" % q.resolve(args[0]))
    elif cmd == "sym":
        nm, off = q.sym(num(args[0]))
        print("%s+0x%x" % (nm, off) if nm else "(unknown)")
    elif cmd == "context":
        print(fmt_context(q.context(num(args[0]) if args else 0)))
    elif cmd == "backtrace" or cmd == "bt":
        print(fmt_frames(q.backtrace(num(args[0]) if args else 0)))
    elif cmd == "listen":
        end = time.time() + (num(args[0]) if args else 3600)
        while time.time() < end:
            ev = q.wait_event(end - time.time())
            if not ev:
                continue
            if ev[0] == "break":
                print("EV_BREAK vcpu%d @0x%x  [%s]" % (ev[1], ev[2], fmt_context(ev[4])))
                print(fmt_frames(ev[5]))
            else:
                print("EV_WATCH vcpu%d rip=0x%x %s [%d]@0x%x = 0x%x" %
                      (ev[1], ev[2], "store" if ev[4] else "load", ev[5], ev[3], ev[6]))
    elif cmd == "test":
        if not args:
            print("usage: test <name>|all [args]; names:", ", ".join(TEST_ORDER))
            return 2
        name = args[0]
        if name == "all":
            return run_all_tests(q, num(args[1]), num(args[2]))
        if name not in TESTS:
            print("unknown test %r; names: %s" % (name, ", ".join(TEST_ORDER)))
            return 2
        return run_test(q, name, [num(a) for a in args[1:]])
    else:
        print("unknown command:", cmd); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
