#!/usr/bin/env python3
"""
Virtual-time comparison of BandCap's two queue modes with Reno-style TCP
senders (no Windows, no driver, no real clock).

    python simulate.py

It models N bulk TCP flows (speed-test-like) through a shaper running at the
configured rate, with a 50 ms base RTT, and reports link utilisation and
queueing delay for the 'simple' tail-drop FIFO versus 'fq' (fair queue +
CoDel). It is a simplified model (loss detected one RTT after the drop,
at most one window reduction per RTT, no timeouts) meant to compare the two
disciplines under identical conditions, not to predict absolute numbers.
"""
import heapq
import statistics
import struct
import sys

import bandcap as B

RTT = 0.050
PKT = 1500


def make_pkt(port):
    p = bytearray(B._mk(4, PKT - 40))
    struct.pack_into("!H", p, 20, port)
    return bytes(p)


def simulate(mode, rate, nflows, dur=60.0, warm=15.0):
    sched = B.MODES[mode]()
    sched.set_rate(rate)
    ev, seqno = [], 0

    def push(t, kind, data):
        nonlocal seqno
        seqno += 1
        heapq.heappush(ev, (t, seqno, kind, data))

    flows = [dict(cwnd=10.0, ssthresh=1e9, inflight=0, recover=0.0, port=1000 + i)
             for i in range(nflows)]
    st = dict(busy=0.0, svc=False, got=0, soj=[])

    def drop_hook(pkt, addr):                     # sender learns ~1 RTT later
        push(drop_hook.now + RTT, "loss", addr)
    drop_hook.now = 0.0
    sched.on_drop = drop_hook

    def send(i, t):
        f = flows[i]
        while f["inflight"] < int(f["cwnd"]):
            f["inflight"] += 1
            push(t + RTT / 2, "arrive", i)

    def kick(t):
        if not st["svc"] and sched.bytes:
            st["svc"] = True
            push(max(t, st["busy"]), "service", None)

    for i in range(nflows):
        send(i, 0.0)
    while ev:
        t, _, kind, data = heapq.heappop(ev)
        if t > dur:
            break
        drop_hook.now = t
        if kind == "arrive":
            sched.enqueue(make_pkt(flows[data]["port"]), data, False, t)
            kick(t)
        elif kind == "service":
            st["svc"] = False
            it = sched.dequeue(t)
            if it:
                done = t + len(it[0]) / rate
                st["busy"] = done
                if t >= warm:
                    st["got"] += len(it[0])
                    st["soj"].append(sched.sojourn)
                push(done + RTT / 2, "ack", it[1])
                st["svc"] = True
                push(done, "service", None)
        elif kind == "ack":
            f = flows[data]
            f["inflight"] -= 1
            f["cwnd"] += 1.0 if f["cwnd"] < f["ssthresh"] else 1.0 / f["cwnd"]
            send(data, t)
        elif kind == "loss":
            f = flows[data]
            f["inflight"] -= 1
            if t >= f["recover"]:
                f["ssthresh"] = max(f["cwnd"] / 2, 2.0)
                f["cwnd"] = f["ssthresh"]
                f["recover"] = t + RTT + (statistics.mean(st["soj"][-50:]) if st["soj"] else 0)
            send(data, t)
        if not st["svc"]:
            kick(t)
    soj = sorted(st["soj"]) or [0]
    return dict(util=st["got"] / (dur - warm) / rate,
                mean=1000 * statistics.mean(soj),
                p95=1000 * soj[int(len(soj) * 0.95)],
                drops=sched.drops)


if __name__ == "__main__":
    cases = [("download 8 Mbps", 1_000_000), ("upload 250 Kbps", 31_250)]
    print(f"{'case':<17}{'flows':>5}  {'mode':<7}{'link use':>9}{'mean delay':>12}{'p95 delay':>11}{'drops':>7}")
    for label, rate in cases:
        for n in (1, 4, 16):
            for mode in ("simple", "fq"):
                r = simulate(mode, rate, n)
                print(f"{label:<17}{n:>5}  {mode:<7}{r['util']:>8.0%}{r['mean']:>10.0f} ms{r['p95']:>9.0f} ms{r['drops']:>7}")
