"""Packet capture through Npcap's wpcap.dll (ctypes), without Wireshark / tshark.

  available()                         True if Npcap is installed
  devices()                           [(device name, description, [ipv4, ...])]
  Capture(devs, ports, on_packet)     live: on_packet(t, src, sport, dst, dport, seq, payload)
                                      for every TCP segment with data to/from the ports
  read_file(path, ports, on_packet)   the same for a .pcap / .pcapng file (replay)
"""
import ctypes, os, socket, threading

from . import netif

PCAP_ERRBUF_SIZE = 256
PCAP_IF_LOOPBACK = 1
DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LOOP, DLT_IPV4 = 0, 1, 12, 108, 228
DLT_RAW_ALT = 101                                       # LINKTYPE_RAW on some builds


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]


class pcap_addr(ctypes.Structure):
    pass


pcap_addr._fields_ = [("next", ctypes.POINTER(pcap_addr)), ("addr", ctypes.POINTER(sockaddr)),
                      ("netmask", ctypes.POINTER(sockaddr)), ("broadaddr", ctypes.POINTER(sockaddr)),
                      ("dstaddr", ctypes.POINTER(sockaddr))]


class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [("next", ctypes.POINTER(pcap_if)), ("name", ctypes.c_char_p),
                    ("description", ctypes.c_char_p), ("addresses", ctypes.POINTER(pcap_addr)),
                    ("flags", ctypes.c_uint)]


class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]   # long is 32-bit on Windows


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


_dll = []


def _lib():
    """wpcap.dll: Npcap puts it in System32\\Npcap (or System32 in WinPcap-compatible mode)."""
    if _dll:
        return _dll[0]
    npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
    if os.path.isdir(npcap_dir):
        os.add_dll_directory(npcap_dir)                  # wpcap.dll loads Packet.dll from there
    for path in (os.path.join(npcap_dir, "wpcap.dll"), "wpcap.dll"):
        try:
            lib = ctypes.CDLL(path)
            break
        except OSError:
            continue
    else:
        return None
    P = ctypes.c_void_p
    lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), ctypes.c_char_p]
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(pcap_if)]
    lib.pcap_create.restype = lib.pcap_open_offline.restype = P
    lib.pcap_create.argtypes = lib.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    for f in ("pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout", "pcap_set_immediate_mode",
              "pcap_set_buffer_size"):
        getattr(lib, f).argtypes = [P, ctypes.c_int]
    lib.pcap_activate.argtypes = lib.pcap_datalink.argtypes = lib.pcap_close.argtypes = [P]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_geterr.argtypes = [P]
    lib.pcap_compile.argtypes = [P, ctypes.POINTER(bpf_program), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]
    lib.pcap_setfilter.argtypes = [P, ctypes.POINTER(bpf_program)]
    lib.pcap_freecode.argtypes = [ctypes.POINTER(bpf_program)]
    lib.pcap_next_ex.argtypes = [P, ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
                                 ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    _dll.append(lib)
    return lib


def available():
    return _lib() is not None


def devices():
    """[(device, description, [ipv4 addresses])], loopback left out."""
    lib, err = _lib(), ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    if lib is None:
        return []
    alldevs = ctypes.POINTER(pcap_if)()
    if lib.pcap_findalldevs(ctypes.byref(alldevs), err) != 0:
        return []
    out, d = [], alldevs
    while d:
        dev = d.contents
        if not dev.flags & PCAP_IF_LOOPBACK:
            ips, a = [], dev.addresses
            while a:
                sa = a.contents.addr
                if sa and sa.contents.sa_family == socket.AF_INET:
                    ips.append(socket.inet_ntoa(bytes(sa.contents.sa_data[2:6])))
                a = a.contents.next
            out.append((dev.name.decode(), (dev.description or b"").decode(errors="replace"), ips))
        d = dev.next
    lib.pcap_freealldevs(alldevs)
    return out


def ip_layer(dlt, data):
    """The IPv4 packet inside a captured frame, or None."""
    if dlt == DLT_EN10MB:
        off, etype = 14, data[12:14]
        while etype in (b"\x81\x00", b"\x88\xa8") and len(data) >= off + 4:   # VLAN tags
            etype, off = data[off + 2:off + 4], off + 4
        return data[off:] if etype == b"\x08\x00" else None
    if dlt in (DLT_NULL, DLT_LOOP):
        return data[4:]
    if dlt in (DLT_RAW, DLT_RAW_ALT, DLT_IPV4):
        return data
    return None


def _set_filter(lib, h, ports):
    prog = bpf_program()
    expr = f"tcp portrange {ports[0]}-{ports[1]}".encode()
    if lib.pcap_compile(h, ctypes.byref(prog), expr, 1, 0xFFFFFFFF) == 0:
        lib.pcap_setfilter(h, ctypes.byref(prog))
        lib.pcap_freecode(ctypes.byref(prog))


def _loop(lib, h, ports, on_packet, running=lambda: True):
    """Read packets until EOF / error / running() is False. Returns pcap_next_ex's last code."""
    dlt = lib.pcap_datalink(h)
    hdr, data = ctypes.POINTER(pcap_pkthdr)(), ctypes.POINTER(ctypes.c_ubyte)()
    lo, hi = ports
    while running():
        r = lib.pcap_next_ex(h, ctypes.byref(hdr), ctypes.byref(data))
        if r == 0:                                       # timeout: check running() again
            continue
        if r < 0:
            return r
        h_ = hdr.contents
        ip = ip_layer(dlt, ctypes.string_at(data, h_.caplen))
        seg = netif.parse(ip, lo, hi) if ip else None
        if seg:
            on_packet(h_.ts.tv_sec + h_.ts.tv_usec / 1e6, *seg)
    return 0


class Capture:
    """One pcap handle and reader thread per device; stop() ends them."""

    def __init__(self, devs, ports, on_packet, on_error=None):
        self.lib, self.ports, self.on_packet = _lib(), ports, on_packet
        self.on_error = on_error or (lambda msg: None)
        self.running = True
        for dev in devs:
            threading.Thread(target=self._run, args=(dev,), daemon=True).start()

    def _run(self, dev):
        lib, err = self.lib, ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        h = lib.pcap_create(dev.encode(), err)
        if not h:
            self.on_error(f"{dev}: {err.value.decode(errors='replace')}")
            return
        lib.pcap_set_snaplen(h, 65535)
        lib.pcap_set_promisc(h, 0)
        lib.pcap_set_timeout(h, 200)
        lib.pcap_set_immediate_mode(h, 1)                # deliver each packet at once
        lib.pcap_set_buffer_size(h, 16 * 1024 * 1024)
        r = lib.pcap_activate(h)
        if r < 0:
            msg = (lib.pcap_geterr(h) or b"").decode(errors="replace")
            lib.pcap_close(h)
            # a missing / disabled adapter fails here too; only report access problems loudly
            if "denied" in msg.lower() or "admin" in msg.lower():
                self.on_error("Npcap needs administrator rights here (it was installed "
                              "admin-only): run SDS Meter as administrator")
            return
        _set_filter(lib, h, self.ports)
        try:
            r = _loop(lib, h, self.ports, self._deliver, lambda: self.running)
            if r == -1:
                self.on_error(f"capture stopped: {(lib.pcap_geterr(h) or b'').decode(errors='replace')}")
        finally:
            lib.pcap_close(h)

    def _deliver(self, *pkt):
        try:
            self.on_packet(*pkt)
        except Exception as e:                           # a bad packet must not end the capture
            self.on_error(f"packet: {e!r}")

    def stop(self):
        self.running = False                             # threads close their handle within 200 ms


def read_file(path, ports, on_packet):
    """Replay a .pcap / .pcapng capture; raises OSError if it cannot be opened."""
    lib, err = _lib(), ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    if lib is None:
        raise OSError("Npcap is not installed")
    h = lib.pcap_open_offline(path.encode("mbcs"), err)
    if not h:
        raise OSError(err.value.decode(errors="replace"))
    try:
        _loop(lib, h, ports, on_packet)
    finally:
        lib.pcap_close(h)
