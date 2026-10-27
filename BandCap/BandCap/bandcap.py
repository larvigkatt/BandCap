#!/usr/bin/env python3
"""
BandCap 2.1 - volatile, system-wide bandwidth limiter for Windows 10/11.

How it works
------------
WinDivert (a signed kernel packet-divert driver) hands every internet-bound
IP packet to this process *instead of* the network stack. We hold packets in
a queue and release them through a token bucket at the configured rate, so the
real traffic that reaches the wire (upload) or your applications (download)
never exceeds the cap. LAN / loopback / multicast traffic is excluded in the
kernel filter, so it is never touched.

Volatility
----------
* No settings, registry values, firewall rules or QoS policies are written.
* The driver is loaded on demand when the first handle opens and unloads when
  the last handle closes. If this process dies for ANY reason (even
  taskkill /f), Windows closes the handles and traffic flows normally again.
* The only side effect while running: the WinDivert driver service is
  registered transiently (it is flagged for deletion at load time) and the
  system timer resolution is raised to 1 ms (restored on exit).

Usage
-----
    python bandcap.py                      # GUI
    python bandcap.py --cli --down 8mbps --up 250kbps [--mode fq|simple]
    python bandcap.py --selftest           # offline packet-logic tests
"""
import argparse
import collections
import ctypes
import math
import os
import re
import struct
import sys
import threading
import time

APP = "BandCap"
HERE = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------------
# Tunables
# ----------------------------------------------------------------------------
DEFAULT_QUEUE_DELAY = 0.200   # simple mode only: seconds of data allowed to sit in a queue
MIN_QUEUE_BYTES = 16 * 1024   # ...but never less than this (absorbs bursts)
PRIO_QUEUE_BYTES = 64 * 1024  # separate queue for ACKs / DNS / small UDP
BURST_SECONDS = 0.020         # token bucket depth
MIN_BURST_BYTES = 3000
SEG_THRESHOLD = 1500          # outbound TCP packets bigger than this are LSO
SEG_PAYLOAD = 1200            # ...and get re-segmented to this payload size
CODEL_TARGET_MIN = 0.025     # seconds; scaled up on slow links (see FqCodel.set_rate)
CODEL_INTERVAL_MIN = 0.200   # seconds
QUANTUM = 1514               # fq_codel: bytes a flow may send per round
MIN_RATE = 1000.0              # bytes/s (8 Kbps): refuse limits that would freeze the line
PRIO_UDP_MAX = 220            # small UDP/ICMP packets are latency-sensitive

# ----------------------------------------------------------------------------
# Rate parsing / formatting
# ----------------------------------------------------------------------------
UNITS = {            # -> bytes per second per unit
    "kbps": 1000 / 8,
    "mbps": 1_000_000 / 8,
    "kb/s": 1000.0,
    "mb/s": 1_000_000.0,
}


def parse_rate(text):
    """'8mbps' / '250 Kbps' / '30KB/s' -> bytes per second."""
    t = text.strip().lower().replace(" ", "")
    for unit in sorted(UNITS, key=len, reverse=True):
        if t.endswith(unit):
            return float(t[: -len(unit)]) * UNITS[unit]
    raise ValueError("rate needs a unit: kbps, mbps, kb/s or mb/s")


def fmt_rate(bps):
    bits = bps * 8
    if bits >= 1_000_000:
        return f"{bits / 1e6:.2f} Mbps"
    return f"{bits / 1e3:.0f} Kbps"


# ----------------------------------------------------------------------------
# Packet inspection (pure functions - unit tested by --selftest)
# ----------------------------------------------------------------------------
def inspect(pkt, outbound):
    """Return None to bypass shaping, otherwise True (priority) / False (bulk)."""
    if len(pkt) < 20:
        return None
    ver = pkt[0] >> 4
    if ver == 6:
        if len(pkt) < 40:
            return None
        peer = pkt[24] if outbound else pkt[8]
        if (peer & 0xE0) != 0x20:          # only shape global unicast 2000::/3
            return None
        proto, l3 = pkt[6], 40
    elif ver == 4:
        l3 = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
    else:
        return None
    if proto == 6:                          # TCP
        if len(pkt) < l3 + 20:
            return False
        thl = (pkt[l3 + 12] >> 4) * 4
        return len(pkt) - l3 - thl <= 0     # pure ACK / SYN / FIN -> priority
    if proto in (17, 1, 58):                # UDP / ICMP / ICMPv6
        return len(pkt) <= PRIO_UDP_MAX
    return False


def segment_tcp(pkt, addr, calc, clone):
    """
    Split an oversized outbound TCP packet (Large Send Offload 'super-packet')
    into wire-sized segments so the shaper can pace them smoothly.
    calc(bytearray, addr) must (re)compute IP/TCP checksums.
    Returns [(bytes, addr), ...]; returns [(pkt, addr)] when not applicable.
    """
    try:
        ver = pkt[0] >> 4
        if ver == 4:
            l3 = (pkt[0] & 0x0F) * 4
            if pkt[9] != 6 or (struct.unpack_from("!H", pkt, 6)[0] & 0x3FFF):
                return [(pkt, addr)]         # not TCP, or fragmented
        elif ver == 6:
            l3 = 40
            if pkt[6] != 6:
                return [(pkt, addr)]
        else:
            return [(pkt, addr)]
        thl = (pkt[l3 + 12] >> 4) * 4
        hdr_len = l3 + thl
        payload = pkt[hdr_len:]
        if len(payload) <= SEG_PAYLOAD:
            return [(pkt, addr)]
        seq0 = struct.unpack_from("!I", pkt, l3 + 4)[0]
        ipid0 = struct.unpack_from("!H", pkt, 4)[0] if ver == 4 else 0
        out = []
        n = (len(payload) + SEG_PAYLOAD - 1) // SEG_PAYLOAD
        for i in range(n):
            chunk = payload[i * SEG_PAYLOAD:(i + 1) * SEG_PAYLOAD]
            seg = bytearray(pkt[:hdr_len]) + chunk
            struct.pack_into("!I", seg, l3 + 4, (seq0 + i * SEG_PAYLOAD) & 0xFFFFFFFF)
            flags = seg[l3 + 13]
            if i != n - 1:
                flags &= ~(0x01 | 0x08)      # FIN, PSH only on the last segment
            if i != 0:
                flags &= ~0x80               # CWR only on the first segment
            seg[l3 + 13] = flags
            if ver == 4:
                struct.pack_into("!H", seg, 2, len(seg))
                struct.pack_into("!H", seg, 4, (ipid0 + i) & 0xFFFF)
            else:
                struct.pack_into("!H", seg, 4, len(seg) - 40)
            a = clone(addr)
            calc(seg, a)
            out.append((bytes(seg), a))
        return out
    except Exception:
        return [(pkt, addr)]


# ----------------------------------------------------------------------------
# WinDivert binding (ctypes, no third-party deps)
# ----------------------------------------------------------------------------
class Addr(ctypes.Structure):
    _fields_ = [("raw", ctypes.c_ubyte * 80)]     # WINDIVERT_ADDRESS is 80 bytes


ERRORS = {
    2: "WinDivert64.sys / WinDivert.dll not found next to bandcap.py.",
    5: "Windows denied access to the WinDivert driver (not elevated, or the driver is blocked).",
    87: "Invalid parameter (bad filter?).",
    577: "Windows refused to load the driver (signature check).",
    654: "Driver is incompatible with this Windows version.",
    1060: "Driver service problem - another WinDivert version may be loaded; "
          "close other tools that use WinDivert and try again.",
    1275: "The driver was blocked by Windows (Smart App Control / "
          "driver blocklist / security software).",
}


class WinDivert:
    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("BandCap only runs on Windows.")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise RuntimeError("64-bit Python is required (bundled driver is x64).")
        dll = os.path.join(HERE, "WinDivert.dll")
        if not os.path.exists(dll):
            raise RuntimeError(ERRORS[2])
        L = ctypes.WinDLL(dll, use_last_error=True)
        c = ctypes
        L.WinDivertOpen.argtypes = [c.c_char_p, c.c_int, c.c_int16, c.c_uint64]
        L.WinDivertOpen.restype = c.c_void_p
        L.WinDivertRecv.argtypes = [c.c_void_p, c.c_void_p, c.c_uint,
                                    c.POINTER(c.c_uint), c.c_void_p]
        L.WinDivertRecv.restype = c.c_int
        L.WinDivertSend.argtypes = [c.c_void_p, c.c_char_p, c.c_uint,
                                    c.POINTER(c.c_uint), c.c_void_p]
        L.WinDivertSend.restype = c.c_int
        L.WinDivertShutdown.argtypes = [c.c_void_p, c.c_int]
        L.WinDivertShutdown.restype = c.c_int
        L.WinDivertClose.argtypes = [c.c_void_p]
        L.WinDivertClose.restype = c.c_int
        L.WinDivertSetParam.argtypes = [c.c_void_p, c.c_int, c.c_uint64]
        L.WinDivertSetParam.restype = c.c_int
        L.WinDivertHelperCalcChecksums.argtypes = [c.c_void_p, c.c_uint, c.c_void_p, c.c_uint64]
        L.WinDivertHelperCalcChecksums.restype = c.c_int
        self.L = L

    def open(self, flt):
        h = self.L.WinDivertOpen(flt.encode(), 0, 0, 0)   # NETWORK layer, prio 0
        if h is None or h == 0xFFFFFFFFFFFFFFFF:
            err = ctypes.get_last_error()
            raise RuntimeError(f"WinDivertOpen failed (error {err}): "
                               f"{ERRORS.get(err, 'see WinDivert docs')}\n\n" + diagnose())
        self.L.WinDivertSetParam(h, 0, 8192)               # queue length (packets)
        self.L.WinDivertSetParam(h, 1, 8000)               # queue time (ms)
        self.L.WinDivertSetParam(h, 2, 16 * 1024 * 1024)   # queue size (bytes)
        return h

    def recv(self, h, buf, n_out, addr):
        return self.L.WinDivertRecv(h, buf, len(buf), ctypes.byref(n_out), ctypes.byref(addr))

    def send(self, h, pkt, addr):
        return self.L.WinDivertSend(h, pkt, len(pkt), None, ctypes.byref(addr))

    def shutdown(self, h):
        self.L.WinDivertShutdown(h, 3)

    def close(self, h):
        self.L.WinDivertClose(h)

    def calc_checksums(self, ba, addr):
        buf = (ctypes.c_ubyte * len(ba)).from_buffer(ba)
        self.L.WinDivertHelperCalcChecksums(ctypes.addressof(buf), len(ba),
                                            ctypes.byref(addr), 0)

    @staticmethod
    def clone(addr):
        return Addr.from_buffer_copy(addr)


def v4_public(field):
    """
    True-expression for 'field is outside all private/special ranges'.
    NOTE: the WinDivert grammar only allows `not` in front of a single test,
    never in front of a parenthesised group (error 87), so we express the
    exclusion positively: (f < lo or f > hi) and (f < lo2 or f > hi2) ...
    """
    rng = [("10.0.0.0", "10.255.255.255"), ("172.16.0.0", "172.31.255.255"),
           ("192.168.0.0", "192.168.255.255"), ("169.254.0.0", "169.254.255.255"),
           ("127.0.0.0", "127.255.255.255"), ("224.0.0.0", "255.255.255.255"),
           ("0.0.0.0", "0.255.255.255"), ("100.64.0.0", "100.127.255.255")]
    return " and ".join(f"({field} < {a} or {field} > {b})" for a, b in rng)


def build_filter(outbound, skip_impostors=True):
    """
    `not impostor`: packets injected by OTHER drivers (antivirus, VPN, hotspot...) are
    flagged 'impostor'. WinDivert documents that it cannot stop those from being
    captured again after we re-inject them, so shaping them can make a packet circulate
    through our queue until its TTL runs out - phantom traffic that pins the cap.
    We simply never touch them.
    """
    side = "outbound" if outbound else "inbound"
    peer = "ip.DstAddr" if outbound else "ip.SrcAddr"
    imp = "not impostor and " if skip_impostors else ""
    return (f"{side} and not loopback and {imp}"
            f"((ip and {v4_public(peer)}) or ipv6)")


def is_impostor(addr):
    """WINDIVERT_ADDRESS bitfield byte 10: bit0 Sniffed, 1 Outbound, 2 Loopback, 3 Impostor."""
    return bool(addr.raw[10] & 0x08)


# ----------------------------------------------------------------------------
# Queue disciplines
# ----------------------------------------------------------------------------
def flow_key(pkt):
    """Connection identity: protocol + addresses + ports (bytes, hashable)."""
    ver = pkt[0] >> 4
    if ver == 4:
        l3, proto, addrs = (pkt[0] & 0x0F) * 4, pkt[9], pkt[12:20]
        frag = (pkt[6] & 0x3F) | pkt[7]
    else:
        l3, proto, addrs, frag = 40, pkt[6], pkt[8:40], 0
    ports = pkt[l3:l3 + 4] if proto in (6, 17) and not frag else b""
    return bytes((proto,)) + addrs + ports


def describe_flow(hdr, outbound):
    """Human-readable 'TCP 1.2.3.4:443 (local port 51234)' from the first bytes of a packet."""
    import socket
    try:
        if hdr[0] >> 4 == 4:
            l3, proto, fam = (hdr[0] & 0x0F) * 4, hdr[9], socket.AF_INET
            src, dst = hdr[12:16], hdr[16:20]
        else:
            l3, proto, fam = 40, hdr[6], socket.AF_INET6
            src, dst = hdr[8:24], hdr[24:40]
        remote = socket.inet_ntop(fam, bytes(dst if outbound else src))
        name = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(proto, f"proto {proto}")
        if proto in (6, 17) and len(hdr) >= l3 + 4:
            sp, dp = struct.unpack_from("!HH", hdr, l3)
            rp, lp = (dp, sp) if outbound else (sp, dp)
            return f"{name:<4} {remote}:{rp}  (local port {lp})"
        return f"{name:<4} {remote}"
    except Exception:
        return "unparseable packet"


class Sched:
    """Common interface: enqueue / dequeue / drain, plus counters."""
    on_drop = None                     # optional hook(pkt, addr) used by simulator

    def __init__(self):
        self.drops = 0
        self.sojourn = 0.0             # queueing delay of the last released packet

    def _drop(self, pkt, addr):
        self.drops += 1
        if self.on_drop:
            self.on_drop(pkt, addr)


class SimpleQueue(Sched):
    """v1 behaviour: two FIFOs (ACK/small-UDP priority + bulk), tail drop."""
    name = "Simple FIFO (tail drop)"

    def __init__(self):
        super().__init__()
        self.hi, self.lo = collections.deque(), collections.deque()
        self.hbytes = self.lbytes = 0
        self.rate = 0.0

    @property
    def bytes(self):
        return self.hbytes + self.lbytes

    def set_rate(self, rate):
        self.rate = rate

    def enqueue(self, pkt, addr, prio, now):
        n = len(pkt)
        if prio:
            if self.hbytes + n > PRIO_QUEUE_BYTES:
                return self._drop(pkt, addr)
            self.hi.append((pkt, addr, now))
            self.hbytes += n
        else:
            limit = max(self.rate * DEFAULT_QUEUE_DELAY, MIN_QUEUE_BYTES)
            if self.lbytes > 0 and self.lbytes + n > limit:
                return self._drop(pkt, addr)
            self.lo.append((pkt, addr, now))
            self.lbytes += n

    def dequeue(self, now):
        if self.hi:
            item = self.hi.popleft()
            self.hbytes -= len(item[0])
        elif self.lo:
            item = self.lo.popleft()
            self.lbytes -= len(item[0])
        else:
            return None
        self.sojourn = now - item[2]
        return item

    def drain(self):
        items = list(self.hi) + list(self.lo)
        self.hi.clear(); self.lo.clear()
        self.hbytes = self.lbytes = 0
        return items


class _Flow:
    __slots__ = ("key", "q", "bytes", "deficit", "active", "first_above",
                 "drop_next", "count", "lastcount", "dropping")

    def __init__(self, key):
        self.key = key
        self.q = collections.deque()
        self.bytes = 0
        self.deficit = 0
        self.active = False
        self.first_above = 0.0
        self.drop_next = 0.0
        self.count = self.lastcount = 0
        self.dropping = False


class FqCodel(Sched):
    """
    Flow queueing + CoDel (RFC 8290 fq_codel, RFC 8289 CoDel).

    * Every connection gets its own sub-queue; a deficit round-robin serves
      them byte-fairly, and flows that were idle go first ("sparse" flows).
    * CoDel watches how long each packet sat in its sub-queue (sojourn time).
      If it stays above `target` for a whole `interval`, it starts dropping
      at the head of that flow, at an accelerating rate (interval/sqrt(n)),
      until the standing queue is gone.  No queue-size tuning is needed.
    * Pure ACKs and small UDP/ICMP use a small strict-priority queue, because
      ACKs for a download are only ~3% of its bytes but gate its speed.
    """
    name = "Fair queue + CoDel"

    def __init__(self):
        super().__init__()
        self.prio = collections.deque()
        self.pbytes = 0
        self.flows = {}
        self.new, self.old = collections.deque(), collections.deque()
        self.fbytes = 0
        self.set_rate(0.0)

    @property
    def bytes(self):
        return self.pbytes + self.fbytes

    def set_rate(self, rate):
        self.rate = rate
        mtu_time = 1500.0 / rate if rate > 0 else 0.0
        # CoDel's target must exceed one packet's serialisation time, otherwise
        # it would punish the queue for merely holding a single packet.
        self.target = max(CODEL_TARGET_MIN, 1.5 * mtu_time)
        self.interval = max(CODEL_INTERVAL_MIN, 8.0 * self.target)
        self.limit = max(rate * 0.5, 32 * 1024)      # hard safety cap (bytes)

    # -- enqueue -----------------------------------------------------------
    def enqueue(self, pkt, addr, prio, now):
        n = len(pkt)
        if prio:
            if self.pbytes + n > PRIO_QUEUE_BYTES:
                return self._drop(pkt, addr)
            self.prio.append((pkt, addr, now))
            self.pbytes += n
            return
        key = flow_key(pkt)
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = _Flow(key)
        f.q.append((pkt, addr, now))
        f.bytes += n
        self.fbytes += n
        if not f.active:
            f.active = True
            f.deficit = QUANTUM
            self.new.append(f)
        while self.fbytes > self.limit:              # overflow: head-drop the fattest flow
            fat = max(self.flows.values(), key=lambda x: x.bytes)
            p, a, _ = fat.q.popleft()
            fat.bytes -= len(p)
            self.fbytes -= len(p)
            self._drop(p, a)

    # -- dequeue -----------------------------------------------------------
    def dequeue(self, now):
        if self.prio:
            item = self.prio.popleft()
            self.pbytes -= len(item[0])
            self.sojourn = now - item[2]
            return item
        while True:
            lst = self.new if self.new else self.old
            if not lst:
                return None
            f = lst[0]
            if f.deficit <= 0:
                f.deficit += QUANTUM
                lst.popleft()
                self.old.append(f)
                continue
            item = self._codel(f, now)
            if item is None:
                lst.popleft()
                if lst is self.new and self.old:
                    self.old.append(f)               # keep: avoids starving old flows
                else:
                    f.active = False
                    self.flows.pop(f.key, None)
                continue
            f.deficit -= len(item[0])
            return item

    def _law(self, t, count):
        return t + self.interval / math.sqrt(count)

    def _dodeq(self, f, now):
        if not f.q:
            f.first_above = 0.0
            return None, False
        item = f.q.popleft()
        n = len(item[0])
        f.bytes -= n
        self.fbytes -= n
        if now - item[2] < self.target or f.bytes <= 1500:
            f.first_above = 0.0
            return item, False
        if f.first_above == 0.0:
            f.first_above = now + self.interval
            return item, False
        return item, now >= f.first_above

    def _codel(self, f, now):
        item, ok = self._dodeq(f, now)
        if item is None:
            f.dropping = False
            return None
        if f.dropping:
            if not ok:
                f.dropping = False
            else:
                while now >= f.drop_next and f.dropping:
                    self._drop(item[0], item[1])
                    f.count += 1
                    item, ok = self._dodeq(f, now)
                    if item is None:
                        f.dropping = False
                        return None
                    if not ok:
                        f.dropping = False
                    else:
                        f.drop_next = self._law(f.drop_next, f.count)
        elif ok:
            self._drop(item[0], item[1])
            item, ok = self._dodeq(f, now)
            f.dropping = True
            delta = f.count - f.lastcount
            if delta > 1 and now - f.drop_next < 16 * self.interval:
                f.count = delta
            else:
                f.count = 1
            f.drop_next = self._law(now, f.count)
            f.lastcount = f.count
            if item is None:
                return None
        self.sojourn = now - item[2]
        return item

    def drain(self):
        items = list(self.prio)
        for f in self.flows.values():
            items.extend(f.q)
            f.q.clear()
            f.bytes = 0
        self.prio.clear()
        self.new.clear(); self.old.clear(); self.flows.clear()
        self.pbytes = self.fbytes = 0
        return items


MODES = {"fq": FqCodel, "simple": SimpleQueue}


# ----------------------------------------------------------------------------
# One direction of shaping
# ----------------------------------------------------------------------------
class Direction:
    def __init__(self, wd, name, outbound, mode="fq"):
        self.wd, self.name, self.outbound = wd, name, outbound
        self.rate = 0.0                       # bytes / s, 0 = unlimited
        self.sched = MODES[mode]()
        self.cond = threading.Condition()
        self.running = False
        self.handle = None
        self.threads = []
        self.sent_bytes = 0
        self.error = None
        self.talk = {}                        # flow_key -> [bytes, first 64 bytes, last seen]

    # -- stats (read by GUI) ----------------------------------------------
    @property
    def queued(self):
        return self.sched.bytes

    @property
    def dropped(self):
        return self.sched.drops

    @property
    def delay_ms(self):
        return self.sched.sojourn * 1000 if self.sched.bytes else 0.0

    def set_rate(self, rate):
        with self.cond:
            self.rate = rate
            self.sched.set_rate(rate)

    def set_mode(self, mode):
        """Swap queue discipline (only while stopped)."""
        if self.running:
            raise RuntimeError("stop before changing queue mode")
        rate = self.rate
        self.sched = MODES[mode]()
        self.sched.set_rate(rate)

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        self.error = None
        try:
            self.handle = self.wd.open(build_filter(self.outbound))
        except RuntimeError as e:
            if "error 87" not in str(e):
                raise
            self.handle = self.wd.open(build_filter(self.outbound, skip_impostors=False))
        self.running = True
        self.threads = [threading.Thread(target=self._guard, args=(self._rx,), daemon=True),
                        threading.Thread(target=self._guard, args=(self._tx,), daemon=True)]
        for t in self.threads:
            t.start()

    def stop(self):
        if not self.running:
            return
        self.running = False
        h = self.handle
        try:
            self.wd.shutdown(h)               # unblocks the blocking Recv
        except Exception:
            pass
        with self.cond:
            self.cond.notify_all()
        for t in self.threads:
            t.join(timeout=2)
        with self.cond:                        # release anything still queued
            leftovers = self.sched.drain()
        for pkt, addr, _ in leftovers:
            try:
                self.wd.send(h, pkt, addr)
            except Exception:
                pass
        self.wd.close(h)
        self.handle = None

    def _guard(self, fn):
        """Run a worker thread; on any unexpected exception stop shaping (the GUI/CLI then
        calls stop(), which releases queued packets) instead of silently stalling traffic."""
        try:
            fn()
        except Exception as e:
            self.error = f"{self.name}: {type(e).__name__}: {e}"
            self.running = False
            with self.cond:
                self.cond.notify_all()

    # -- capture -----------------------------------------------------------
    def _rx(self):
        buf = ctypes.create_string_buffer(65600)
        n = ctypes.c_uint()
        fails = 0
        while self.running:
            addr = Addr()
            if not self.wd.recv(self.handle, buf, n, addr):
                if not self.running:
                    break
                fails += 1
                if fails > 50:
                    self.error = f"{self.name}: capture failed repeatedly"
                    self.running = False
                    break
                time.sleep(0.01)
                continue
            fails = 0
            self._ingest(ctypes.string_at(buf, n.value), addr)

    def _note(self, pkt, now):
        k = flow_key(pkt)
        e = self.talk.get(k)
        if e is None:
            if len(self.talk) > 400:               # forget connections idle for a minute
                for kk in [kk for kk, v in list(self.talk.items()) if now - v[2] > 60]:
                    self.talk.pop(kk, None)
            e = self.talk[k] = [0, pkt[:64], now]
        e[0] += len(pkt)
        e[2] = now

    def _ingest(self, pkt, addr):
        cls = inspect(pkt, self.outbound)
        if cls is not None:
            self._note(pkt, time.perf_counter())
        if cls is None or self.rate <= 0 or is_impostor(addr):
            self._send(pkt, addr)
            return
        items = [(pkt, addr)]
        if self.outbound and len(pkt) > SEG_THRESHOLD:
            items = segment_tcp(pkt, addr, self.wd.calc_checksums, self.wd.clone)
        now = time.perf_counter()
        with self.cond:
            for p, a in items:
                self.sched.enqueue(p, a, cls, now)
            self.cond.notify()

    # -- pacing ------------------------------------------------------------
    def _tx(self):
        tokens, last = 0.0, time.perf_counter()
        while self.running:
            with self.cond:
                while self.running and self.sched.bytes == 0:
                    self.cond.wait(0.5)
                if not self.running:
                    return
            rate = self.rate
            now = time.perf_counter()
            if rate > 0:
                burst = max(rate * BURST_SECONDS, MIN_BURST_BYTES)
                tokens = min(burst, tokens + (now - last) * rate)
                last = now
                if tokens < 0:                # in debt: wait until back to zero
                    time.sleep(min(max(-tokens / rate, 0.0005), 0.05))
                    continue
            else:
                tokens, last = 0.0, now
            with self.cond:
                item = self.sched.dequeue(time.perf_counter())
            if item is None:
                continue
            self._send(item[0], item[1])
            if rate > 0:
                tokens -= len(item[0])

    def _send(self, pkt, addr):
        self.wd.send(self.handle, pkt, addr)
        self.sent_bytes += len(pkt)


# ----------------------------------------------------------------------------
# Elevation / timer helpers
# ----------------------------------------------------------------------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_elevated():
    """True only if THIS process token is elevated (TokenElevation), not merely an admin account."""
    try:
        from ctypes import wintypes
        k32, adv = ctypes.windll.kernel32, ctypes.windll.advapi32
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        adv.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        adv.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        tok = ctypes.c_void_p()
        if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
            return False
        elev, ret = wintypes.DWORD(), wintypes.DWORD()
        ok = adv.GetTokenInformation(tok, 20, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret))
        k32.CloseHandle(ctypes.c_void_p(tok.value))
        return bool(ok and elev.value)
    except Exception:
        return False


def diagnose():
    """Facts that separate 'not elevated' from 'driver blocked' when WinDivertOpen fails."""
    import subprocess
    out = [f"Elevated process token: {'YES' if is_elevated() else 'NO'}",
           f"Python: {sys.executable} ({8 * ctypes.sizeof(ctypes.c_void_p)}-bit)",
           f"Folder: {HERE}"]
    for fn in ("WinDivert.dll", "WinDivert64.sys"):
        p = os.path.join(HERE, fn)
        note = "found" if os.path.exists(p) else "MISSING"
        try:
            open(p + ":Zone.Identifier").close()
            note += ", marked 'downloaded from internet' (right-click > Properties > Unblock)"
        except OSError:
            pass
        out.append(f"{fn}: {note}")
    try:
        r = subprocess.run(["sc", "query", "WinDivert"], capture_output=True, text=True,
                           creationflags=0x08000000, timeout=5).stdout
        m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", r)
        out.append("WinDivert driver service: " + (m.group(1) if m else "not registered"))
    except Exception:
        pass
    return "\n".join(out)


def relaunch_as_admin(gui):
    exe = sys.executable
    if gui:
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(w):
            exe = w
    import subprocess
    params = subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, HERE, 1)


class HiResTimer:
    """timeBeginPeriod(1) for accurate sleeps; undone on exit."""
    def __enter__(self):
        try:
            ctypes.windll.winmm.timeBeginPeriod(1)
        except Exception:
            pass
        return self

    def __exit__(self, *a):
        try:
            ctypes.windll.winmm.timeEndPeriod(1)
        except Exception:
            pass


# ----------------------------------------------------------------------------
# GUI  (deliberately dressed as a 2006-era Windows XP utility)
# ----------------------------------------------------------------------------
XP_FACE = "#ECE9D8"          # classic "Luna" dialog face colour
XP_BLUE = 0xE35400           # COLORREF (0x00BBGGRR) of Luna blue #0054E3
GRAPH_BG, GRAPH_GRID = "#000000", "#1E6B1E"
GRAPH_DOWN, GRAPH_UP, GRAPH_CAP = "#00FF00", "#FFFF00", "#808000"
GRAPH_POINTS = 120           # 120 samples x 0.5 s = one minute
GRAPH_W, GRAPH_H = 244, 62


def style_titlebar(root):
    """Windows 11: tint the caption Luna blue (DWM window attributes 34/35/36)."""
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        for attr, colour in ((35, XP_BLUE), (36, 0xFFFFFF), (34, XP_BLUE)):
            v = ctypes.c_int(colour)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(v), 4)
    except Exception:
        pass


def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    wd = WinDivert()
    dirs = {"down": Direction(wd, "Download", False),
            "up": Direction(wd, "Upload", True)}
    FONT, FONT_B = ("Tahoma", 8), ("Tahoma", 8, "bold")

    root = tk.Tk()
    root.title("BandCap - Bandwidth Limiter" + ("" if is_admin() else " [NOT elevated]"))
    root.configure(bg=XP_FACE)
    root.resizable(False, False)
    ttk.Style().theme_use("winnative")           # classic (non-themed) combobox
    root.option_add("*Font", FONT)
    style_titlebar(root)

    mode = tk.StringVar(value="fq")
    active = {"on": False}
    hist = {k: collections.deque([0.0] * GRAPH_POINTS, maxlen=GRAPH_POINTS) for k in dirs}
    prev = {k: (time.perf_counter(), 0) for k in dirs}
    tick_no = {"n": 0}
    pending = {"id": None}                       # debounce timer for live edits

    # ---- menu bar -----------------------------------------------------------
    menubar = tk.Menu(root)
    m_file = tk.Menu(menubar, tearoff=0)
    m_file.add_command(label="Start / Stop", command=lambda: toggle())
    m_file.add_separator()
    m_file.add_command(label="Exit", command=lambda: on_close())
    menubar.add_cascade(label="File", menu=m_file, underline=0)
    m_opt = tk.Menu(menubar, tearoff=0)
    m_opt.add_radiobutton(label="Fair queue + CoDel (recommended)", variable=mode,
                          value="fq", command=lambda: mode_changed())
    m_opt.add_radiobutton(label="Simple FIFO (tail drop, v1 behaviour)", variable=mode,
                          value="simple", command=lambda: mode_changed())
    menubar.add_cascade(label="Options", menu=m_opt, underline=0)
    m_view = tk.Menu(menubar, tearoff=0)
    m_view.add_command(label="Top connections...", command=lambda: show_talkers())
    menubar.add_cascade(label="View", menu=m_view, underline=0)
    m_help = tk.Menu(menubar, tearoff=0)
    m_help.add_command(label="About BandCap...", command=lambda: messagebox.showinfo(
        "About BandCap",
        "BandCap 2.1\nVolatile system-wide bandwidth limiter.\n\n"
        "Packet diversion: WinDivert 2.2 (LGPL).\n"
        "Queueing: fq_codel (RFC 8290 / RFC 8289).\n\n"
        "Closing this window restores normal networking."))
    menubar.add_cascade(label="Help", menu=m_help, underline=0)
    root.config(menu=menubar)

    outer = tk.Frame(root, bg=XP_FACE, padx=8, pady=8)
    outer.pack()

    vars_ = {}
    graphs = {}
    infos = {}

    def make_group(key, title, val, unit):
        grp = tk.LabelFrame(outer, text=" " + title + " ", font=FONT_B, bg=XP_FACE,
                            fg="#000000", padx=8, pady=6, bd=2, relief="groove")
        grp.pack(fill="x", pady=(0, 6))
        en = tk.BooleanVar(value=True)
        v = tk.StringVar(value=val)
        u = tk.StringVar(value=unit)
        top = tk.Frame(grp, bg=XP_FACE)
        top.pack(fill="x")
        tk.Checkbutton(top, text="Limit to:", variable=en, bg=XP_FACE,
                       activebackground=XP_FACE, font=FONT).pack(side="left")
        tk.Entry(top, textvariable=v, width=8, relief="sunken", bd=2, bg="white",
                 font=FONT).pack(side="left", padx=(4, 4))
        ttk.Combobox(top, textvariable=u, width=6, state="readonly", font=FONT,
                     values=["Kbps", "Mbps", "KB/s", "MB/s"]).pack(side="left")
        c = tk.Canvas(grp, width=GRAPH_W, height=GRAPH_H, bg=GRAPH_BG, bd=2,
                      relief="sunken", highlightthickness=0)
        c.pack(pady=(6, 3))
        info = tk.StringVar(value="Idle")
        tk.Label(grp, textvariable=info, bg=XP_FACE, font=FONT, anchor="w").pack(fill="x")
        vars_[key] = (en, v, u)
        graphs[key] = c
        infos[key] = info

    make_group("down", "Download", "8", "Mbps")
    make_group("up", "Upload", "250", "Kbps")

    bar = tk.Frame(outer, bg=XP_FACE)
    bar.pack(fill="x")
    btn = tk.Button(bar, text="Start", width=10, font=FONT, bg=XP_FACE)
    btn.pack(side="left")
    tk.Label(bar, text="Edits apply live. Closing restores everything.",
             bg=XP_FACE, fg="#444444", font=FONT).pack(side="left", padx=10)

    # ---- status bar (sunken panels, like every 2006 app) ------------------------
    sb = tk.Frame(root, bg=XP_FACE)
    sb.pack(fill="x", side="bottom")
    status = tk.StringVar(value="Stopped - traffic untouched")
    drops = tk.StringVar(value="Drops: 0")
    tk.Label(sb, textvariable=status, bd=1, relief="sunken", anchor="w", bg=XP_FACE,
             font=FONT, width=34).pack(side="left", fill="x", expand=True, padx=(2, 1), pady=2)
    tk.Label(sb, textvariable=drops, bd=1, relief="sunken", anchor="w", bg=XP_FACE,
             font=FONT, width=14).pack(side="left", padx=(1, 2), pady=2)

    # ---- drawing ----------------------------------------------------------
    def draw(key):
        c = graphs[key]
        c.delete("all")
        off = (tick_no["n"] * 2) % 12                 # scrolling grid, Task-Manager style
        for x in range(-off, GRAPH_W + 12, 12):
            c.create_line(x, 0, x, GRAPH_H, fill=GRAPH_GRID)
        for y in range(0, GRAPH_H, 12):
            c.create_line(0, y, GRAPH_W, y, fill=GRAPH_GRID)
        d = dirs[key]
        samples = list(hist[key])
        top = max(d.rate * 1.25, max(samples) * 1.1, 1000.0)
        if d.rate > 0:
            y = GRAPH_H - 1 - d.rate / top * (GRAPH_H - 2)
            c.create_line(0, y, GRAPH_W, y, fill=GRAPH_CAP, dash=(3, 3))
        pts = []
        step = GRAPH_W / (GRAPH_POINTS - 1)
        for i, s in enumerate(samples):
            pts += [i * step, GRAPH_H - 1 - s / top * (GRAPH_H - 2)]
        c.create_line(*pts, fill=GRAPH_DOWN if key == "down" else GRAPH_UP)

    def apply(live=False):
        """live=True: called from edits while running - bad input is ignored, never fatal."""
        rates = {}
        try:
            for key in dirs:
                en, v, u = vars_[key]
                r = parse_rate(f"{float(v.get())}{u.get()}") if en.get() else 0.0
                if en.get() and r < MIN_RATE:
                    raise ValueError("limit too low")
                rates[key] = r
        except ValueError:
            if live:
                status.set("Invalid limit - keeping the previous one")
                return True
            stop()
            messagebox.showerror(APP, "Enter a number for each limit (at least 8 Kbps).")
            return False
        try:
            for key, d in dirs.items():
                d.set_rate(rates[key])
                if vars_[key][0].get() and not d.running:
                    d.start()
                    prev[key] = (time.perf_counter(), d.sent_bytes)
                elif not vars_[key][0].get() and d.running:
                    d.stop()
        except Exception as e:
            stop()
            messagebox.showerror(APP, str(e))
            return False
        if active["on"]:
            status.set("Limiting active - " + dirs["down"].sched.name)
        return True

    def start():
        for d in dirs.values():
            d.set_mode(mode.get())
        active["on"] = True
        btn.config(text="Stop")
        apply()

    def stop():
        active["on"] = False
        if pending["id"]:
            root.after_cancel(pending["id"])
            pending["id"] = None
        btn.config(text="Start")
        for d in dirs.values():
            d.stop()
        status.set("Stopped - traffic untouched")
        for k in dirs:
            infos[k].set("Idle")
            hist[k].extend([0.0] * GRAPH_POINTS)

    def toggle():
        stop() if active["on"] else start()

    def mode_changed():
        if active["on"]:
            stop()
            start()

    def tick():
        tick_no["n"] += 1
        total = 0
        for key, d in dirs.items():
            if active["on"] and d.error:
                err = d.error
                stop()
                messagebox.showerror(APP, err)
                break
            if active["on"] and d.running:
                t0, b0 = prev[key]
                t1, b1 = time.perf_counter(), d.sent_bytes
                rate = (b1 - b0) / max(t1 - t0, 1e-3)
                prev[key] = (t1, b1)
                hist[key].append(rate)
                total += d.dropped
                infos[key].set(f"{fmt_rate(rate)} (limit {fmt_rate(d.rate)})   "
                               f"delay {d.delay_ms:.0f} ms   queued {d.queued // 1024} KB")
            else:
                hist[key].append(0.0)
            draw(key)
        drops.set(f"Drops: {total}")
        root.after(500, tick)

    def show_talkers():
        win = tk.Toplevel(root)
        win.title("Top connections")
        win.configure(bg=XP_FACE)
        win.resizable(False, False)
        txt = tk.Text(win, width=76, height=17, font=("Courier New", 8), bg="white",
                      relief="sunken", bd=2, state="disabled")
        txt.pack(padx=8, pady=(8, 2))
        tk.Label(win, text="Shaped internet traffic only (LAN is excluded). Rates are averaged between refreshes.",
                 bg=XP_FACE, fg="#444444", font=FONT).pack(padx=8, pady=(0, 8))
        snap = {}

        def refresh():
            if not win.winfo_exists():
                return
            now = time.perf_counter()
            out = []
            for key, d in dirs.items():
                out.append(f"== {d.name} " + "=" * 60)
                if not d.running:
                    out.append("   (not running)")
                    continue
                cur = {k: (v[0], v[1]) for k, v in list(d.talk.items())}
                t0, old = snap.get(key, (now, {}))
                dt = max(now - t0, 1e-3)
                rows = sorted(((b - old.get(k, 0)) / dt, h) for k, (b, h) in cur.items())
                rows = [r for r in reversed(rows) if r[0] > 0][:6]
                snap[key] = (now, {k: b for k, (b, _) in cur.items()})
                for rate, hdr in rows:
                    out.append(f"   {fmt_rate(rate):>10}  {describe_flow(hdr, d.outbound)}")
                if not rows:
                    out.append("   (no traffic in the last interval)")
            txt.config(state="normal")
            txt.delete("1.0", "end")
            txt.insert("end", "\n".join(out))
            txt.config(state="disabled")
            win.after(1000, refresh)
        refresh()

    btn.config(command=toggle)
    def live_edit(*_):
        if not active["on"]:
            return
        if pending["id"]:
            root.after_cancel(pending["id"])
        def go():
            pending["id"] = None
            if active["on"]:
                apply(live=True)
        pending["id"] = root.after(600, go)       # wait until typing pauses

    for key in vars_:
        for var in vars_[key]:
            var.trace_add("write", live_edit)

    def on_close():
        stop()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(500, tick)
    with HiResTimer():
        root.mainloop()


def run_cli(args):
    wd = WinDivert()
    ds = []
    for key, name, outb in (("down", "Download", False), ("up", "Upload", True)):
        spec = getattr(args, key)
        if spec:
            d = Direction(wd, name, outb, args.mode)
            d.set_rate(parse_rate(spec))
            ds.append(d)
    if not ds:
        sys.exit("Give --down and/or --up, e.g. --down 8mbps --up 250kbps")
    with HiResTimer():
        for d in ds:
            d.start()
        print(f"Limiting ({ds[0].sched.name})... press Ctrl+C to stop; everything reverts instantly.")
        prev = [d.sent_bytes for d in ds]
        try:
            while True:
                time.sleep(1)
                line = []
                for i, d in enumerate(ds):
                    cur = d.sent_bytes
                    line.append(f"{d.name}: {fmt_rate(cur - prev[i])} (cap {fmt_rate(d.rate)}, "
                                f"delay {d.delay_ms:.0f} ms, queue {d.queued // 1024} KB, drops {d.dropped})")
                    prev[i] = cur
                    if d.error:
                        raise RuntimeError(d.error)
                print(" | ".join(line))
        except KeyboardInterrupt:
            pass
        finally:
            for d in ds:
                d.stop()
    print("Stopped. Network is back to normal.")


# ----------------------------------------------------------------------------
# Self-test (runs anywhere, no driver needed)
# ----------------------------------------------------------------------------
def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _fix(seg, addr):
    """Reference checksum implementation standing in for WinDivertHelperCalcChecksums."""
    ver = seg[0] >> 4
    l3 = (seg[0] & 15) * 4 if ver == 4 else 40
    seg[l3 + 16:l3 + 18] = b"\0\0"
    tcp = bytes(seg[l3:])
    if ver == 4:
        seg[10:12] = b"\0\0"
        seg[10:12] = struct.pack("!H", _csum(bytes(seg[:l3])))
        ph = bytes(seg[12:20]) + struct.pack("!BBH", 0, 6, len(tcp))
    else:
        ph = bytes(seg[8:40]) + struct.pack("!IBBBB", len(tcp), 0, 0, 0, 6)
    seg[l3 + 16:l3 + 18] = struct.pack("!H", _csum(ph + tcp))


def _mk(ver, payload_len, flags=0x18):
    payload = bytes((i * 7) & 0xFF for i in range(payload_len))
    tcp = struct.pack("!HHIIBBHHH", 5555, 443, 1000, 77, 5 << 4, flags, 65535, 0, 0) + payload
    if ver == 4:
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 321, 0x4000, 64, 6, 0,
                         bytes([8, 8, 8, 8]), bytes([1, 2, 3, 4]))
    else:
        ip = struct.pack("!IHBB16s16s", 0x60000000, len(tcp), 6, 64,
                         bytes([0x20, 1] + [0] * 13 + [1]), bytes([0x20, 1] + [0] * 13 + [2]))
    pkt = bytearray(ip + tcp)
    return bytes(pkt)


def _pk(sport, size=1400):
    p = bytearray(_mk(4, size - 40))
    struct.pack_into("!H", p, 20, sport)          # TCP source port -> distinct flow
    return bytes(p)


def run_open_loop(sched, rate, flows, dur, dt=0.0005):
    """Virtual-time bottleneck: flows = [(port, offered_bytes_per_s)]. No real clock."""
    sched.set_rate(rate)
    nxt = [0.0] * len(flows)
    busy, t = 0.0, 0.0
    got = {p: 0 for p, _ in flows}
    soj = {p: [] for p, _ in flows}
    while t < dur:
        for i, (port, off) in enumerate(flows):
            while nxt[i] <= t:
                sched.enqueue(_pk(port), port, False, nxt[i])
                nxt[i] += 1400.0 / off
        if t >= busy:
            it = sched.dequeue(t)
            if it:
                got[it[1]] += len(it[0])
                soj[it[1]].append(sched.sojourn)
                busy = t + len(it[0]) / rate
        t += dt
    return got, soj


def selftest_queues(check):
    R, D = 100_000, 12.0
    for name, cls in (("fq", FqCodel), ("simple", SimpleQueue)):
        got, soj = run_open_loop(cls(), R, [(1111, 400_000), (2222, 30_000)], D)
        light = got[2222] / D / 30_000
        total = sum(got.values()) / D / R
        print(f"     [{name}] light flow got {light:.0%} of what it sent, link use {total:.0%}, "
              f"light-flow delay {1000 * sum(soj[2222]) / max(len(soj[2222]), 1):.0f} ms")
        if name == "fq":
            check(light > 0.95, "fq: light flow isn't crushed by a flood (byte-fair DRR)")
            check(total > 0.95, "fq: link stays full")
    # strict-priority class: pure ACKs overtake queued bulk
    q = FqCodel(); q.set_rate(R)
    for _ in range(10):
        q.enqueue(_pk(1111), "bulk", False, 0.0)
    q.enqueue(_mk(4, 0, 0x10), "ack", True, 0.0)
    check(q.dequeue(0.0)[1] == "ack", "fq: pure ACK is served before queued bulk data")
    # CoDel: a persistent standing queue must trigger drops; a short burst must not
    q = FqCodel(); q.set_rate(R)
    for i in range(300):
        q.enqueue(_pk(1111), i, False, 0.0)       # 420 KB backlog, all stamped t=0
    q.limit = 10 ** 9
    t, d0 = 0.5, q.drops
    while q.bytes and t < 8:
        q.dequeue(t)
        t += 0.014
    check(q.drops > d0, "codel: standing queue (>target for >interval) gets dropped")
    q = FqCodel(); q.set_rate(R)
    for i in range(6):
        q.enqueue(_pk(1111), i, False, 0.0)
    t = 0.0
    while q.bytes:
        q.dequeue(t)
        t += 0.014
    check(q.drops == 0, "codel: a short burst is NOT dropped")
    check(flow_key(_pk(1)) != flow_key(_pk(2)) and flow_key(_pk(1)) == flow_key(_pk(1)),
          "flow_key separates connections by port")


def selftest():
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + msg)
        ok &= bool(cond)

    for ver in (4, 6):
        big = _mk(ver, 8000, flags=0x19)          # PSH|ACK|FIN on a LSO packet
        l3 = 20 if ver == 4 else 40
        if ver == 4:
            big = big[:2] + b"\0\0" + big[4:]      # LSO often leaves IP length = 0
        segs = segment_tcp(big, object(), _fix, lambda a: a)
        check(len(segs) == 7, f"v{ver}: 8000B -> {len(segs)} segments")
        data = b"".join(s[l3 + 20:] for s, _ in segs)
        check(data == big[l3 + 20:], f"v{ver}: payload preserved byte-for-byte")
        seqs = [struct.unpack_from("!I", s, l3 + 4)[0] for s, _ in segs]
        check(seqs == [1000 + i * SEG_PAYLOAD for i in range(7)], f"v{ver}: sequence numbers contiguous")
        fl = [s[l3 + 13] for s, _ in segs]
        check(all(f & 0x09 == 0 for f in fl[:-1]) and fl[-1] & 0x09 == 0x09, f"v{ver}: FIN/PSH only on last")
        good = True
        for s, _ in segs:
            tmp = bytearray(s)
            ref = bytes(tmp[l3 + 16:l3 + 18])
            _fix(tmp, None)
            good &= bytes(tmp[l3 + 16:l3 + 18]) == ref
            good &= (len(s) == struct.unpack_from("!H", s, 2)[0]) if ver == 4 else \
                    (len(s) - 40 == struct.unpack_from("!H", s, 4)[0])
        check(good, f"v{ver}: lengths + checksums valid")
        check(inspect(_mk(ver, 0, 0x10), True) is True, f"v{ver}: pure ACK is priority")
        check(inspect(_mk(ver, 1000, 0x18), True) is False, f"v{ver}: data is bulk")
    lan = bytearray(_mk(6, 10)); lan[24] = 0xFE
    check(inspect(bytes(lan), True) is None, "v6 link-local bypasses shaping")
    check(segment_tcp(_mk(4, 500), None, _fix, lambda a: a)[0][0] == _mk(4, 500), "small packet untouched")
    check(describe_flow(_pk(5555), True) == "TCP  1.2.3.4:443  (local port 5555)",
          "describe_flow: outbound TCP shows remote ip:port and local port")
    for s in ("8mbps", "250 Kbps", "30KB/s", "1.5MB/s"):
        print("     parse", s, "->", fmt_rate(parse_rate(s)))
    selftest_queues(check)
    a = Addr(); a.raw[10] = 0x08
    check(is_impostor(a) and not is_impostor(Addr()), "impostor flag read from the right bit (byte 10, bit 3)")
    for o in (True, False):
        f = build_filter(o)
        check("not impostor" in f, f"filter ({'out' if o else 'in'}): skips packets injected by other drivers")
        check(not re.search(r"\bnot\s*\(|!\s*\(", f), f"filter ({'out' if o else 'in'}): no 'not (' groups (WinDivert grammar)")
        check(f.count("(") == f.count(")"), "filter: balanced parentheses")
    print("example filter:", build_filter(True))
    print("ALL OK" if ok else "FAILURES")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", action="store_true", help="console mode instead of GUI")
    ap.add_argument("--down", help="download cap, e.g. 8mbps")
    ap.add_argument("--up", help="upload cap, e.g. 250kbps")
    ap.add_argument("--mode", choices=sorted(MODES), default="fq",
                    help="fq = fair queue + CoDel (default), simple = FIFO tail drop")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(0 if selftest() else 1)
    if sys.platform != "win32":
        sys.exit("BandCap only runs on Windows (use --selftest elsewhere).")
    if not is_admin():
        relaunch_as_admin(gui=not args.cli)
        return
    try:
        run_cli(args) if args.cli else run_gui()
    except Exception as e:
        if args.cli:
            sys.exit(str(e))
        import tkinter.messagebox as mb
        mb.showerror(APP, str(e))


if __name__ == "__main__":
    main()

