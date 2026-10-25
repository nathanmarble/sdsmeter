"""Check the Npcap capture (npcap.py) against Wireshark's tshark: both capture the
game traffic at the same time, and the game messages each reassembles are compared.
Needs Wireshark installed (only this test does); run with the game running:
    python tools/test_npcap.py [seconds=60]
"""
import collections, os, re, subprocess, sys, threading, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from sds_meter import netif, npcap  # noqa: E402
from sds_meter.meter import DEFAULT_PORTS, IMPACT_MSGS, Stream  # noqa: E402

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
SKIP = ("loopback", "etwdump", "bluetooth", "ciscodump", "randpkt", "sshdump", "udpdump", "wifidump")


class Collector:
    """Per-flow reassembly into game messages, like Meter.feed does."""

    def __init__(self, ports):
        self.ports, self.lock = ports, threading.Lock()
        self.streams = collections.defaultdict(Stream)
        self.msgs = collections.defaultdict(list)            # "S2C"/"C2S" -> [(time, message)]

    def feed(self, t, src, sport, dst, dport, seq, payload):
        d = "S2C" if self.ports[0] <= sport <= self.ports[1] else "C2S"
        with self.lock:
            st = self.streams[(src, sport, dst, dport)]
            st.feed(seq, payload, t)
            self.msgs[d] += [(time.time(), m) for m in st.messages()]


def main():
    secs = int(next((a for a in sys.argv[1:] if a.isdigit()), 60))
    ports = DEFAULT_PORTS
    lo, hi = ports
    ours, ts = Collector(ports), Collector(ports)

    out = subprocess.run([TSHARK, "-D"], capture_output=True, text=True).stdout
    ifaces = [m.group(1) for line in out.splitlines()
              if (m := re.match(r"\d+\.\s+(\S+)", line)) and not any(s in line.lower() for s in SKIP)]
    cmd = [TSHARK, "-l", "-n", "-T", "fields", "-E", "separator=,",
           "-o", "tcp.desegment_tcp_streams:FALSE", "-o", "tcp.analyze_sequence_numbers:FALSE",
           "-f", f"tcp portrange {lo}-{hi}"]
    for f in ("frame.time_epoch", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.seq_raw", "tcp.payload"):
        cmd += ["-e", f]
    for i in ifaces:
        cmd += ["-i", i]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def read_tshark():
        for line in proc.stdout:
            p = line.rstrip("\n").split(",")
            if len(p) == 7 and p[6]:
                ts.feed(float(p[0]), p[1], int(p[2]), p[3], int(p[4]), int(p[5]), bytes.fromhex(p[6]))
    threading.Thread(target=read_tshark, daemon=True).start()

    print("adapters:", netif.adapters(), "| default route:", netif.default_ip())
    errors = []
    devs = [d for d, _, ips in npcap.devices() if ips]
    cap = npcap.Capture(devs, ports, ours.feed, errors.append)
    print(f"capturing {secs}s on ports {lo}-{hi} with npcap ({len(devs)} devices) and tshark ...")
    time.sleep(1)
    t_start = time.time() + 4                                 # compare once both are surely running
    for s in range(secs, 0, -10):
        print(f"  {s:>3}s left | messages npcap { {d: len(v) for d, v in ours.msgs.items()} }"
              f"  tshark { {d: len(v) for d, v in ts.msgs.items()} }")
        time.sleep(min(10, s))
    t_end = time.time() - 2
    cap.stop()
    proc.terminate()
    time.sleep(0.5)

    for e in errors[:10]:
        print("npcap error:", e)
    ok = True
    for d in ("S2C", "C2S"):
        a, b = [m for _, m in ours.msgs[d]], [m for _, m in ts.msgs[d]]
        win_a = collections.Counter(m for t, m in ours.msgs[d] if t_start <= t <= t_end)
        win_b = collections.Counter(m for t, m in ts.msgs[d] if t_start <= t <= t_end)
        only_ts = sum((win_b - collections.Counter(a)).values())     # tshark saw it, npcap never did
        only_ours = sum((win_a - collections.Counter(b)).values())
        hits_a = sum(1 for m in a if int.from_bytes(m[6:8], "big") in IMPACT_MSGS)
        hits_b = sum(1 for m in b if int.from_bytes(m[6:8], "big") in IMPACT_MSGS)
        print(f"{d}: messages npcap {len(a)}  tshark {len(b)} | damage msgs npcap {hits_a}  tshark {hits_b}"
              f" | only in tshark {only_ts}  only in npcap {only_ours}")
        if (d == "S2C" and not b) or only_ts > max(2, sum(win_b.values()) // 200):
            ok = False
    print("PASS: npcap capture matches tshark" if ok else "FAIL (or no game traffic seen)")


if __name__ == "__main__":
    main()
