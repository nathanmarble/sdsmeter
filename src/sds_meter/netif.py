"""Network adapters and packet parsing, for the capture in npcap.py.

  adapters()             [(friendly name, ipv4)] of the adapters that are up ("Wi-Fi", "Ethernet 2")
  default_ip()           ipv4 of the adapter holding the default route
  server_ports(exes)     remote ports of the established IPv4 TCP connections of the
                         processes named exes (e.g. the game client)
  parse(ip, lo, hi)      (src, sport, dst, dport, seq, payload) of an IPv4 TCP segment
                         with data to/from ports lo..hi, else None
"""
import ctypes, ctypes.wintypes as wt, socket, struct


# ---- adapter list (GetAdaptersAddresses: friendly names like "Wi-Fi", "Ethernet 2")

class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class _UNICAST(ctypes.Structure):
    pass


_UNICAST._fields_ = [("Length", wt.ULONG), ("Flags", wt.DWORD), ("Next", ctypes.POINTER(_UNICAST)),
                     ("Address", _SOCKET_ADDRESS)]


class _ADAPTER(ctypes.Structure):
    pass


_ADAPTER._fields_ = [("Length", wt.ULONG), ("IfIndex", wt.DWORD), ("Next", ctypes.POINTER(_ADAPTER)),
                     ("AdapterName", ctypes.c_char_p), ("FirstUnicastAddress", ctypes.POINTER(_UNICAST)),
                     ("FirstAnycastAddress", ctypes.c_void_p), ("FirstMulticastAddress", ctypes.c_void_p),
                     ("FirstDnsServerAddress", ctypes.c_void_p), ("DnsSuffix", ctypes.c_wchar_p),
                     ("Description", ctypes.c_wchar_p), ("FriendlyName", ctypes.c_wchar_p),
                     ("PhysicalAddress", ctypes.c_ubyte * 8), ("PhysicalAddressLength", wt.DWORD),
                     ("Flags", wt.DWORD), ("Mtu", wt.DWORD), ("IfType", wt.DWORD), ("OperStatus", ctypes.c_int)]

IF_TYPE_LOOPBACK, IF_OPER_UP = 24, 1


def adapters():
    """[(friendly name, ipv4)] for every adapter that is up, loopback excluded."""
    size = wt.ULONG(16384)
    for _ in range(3):
        buf = ctypes.create_string_buffer(size.value)
        r = ctypes.windll.iphlpapi.GetAdaptersAddresses(socket.AF_INET, 0x0E, None, buf, ctypes.byref(size))
        if r != 111:                                   # ERROR_BUFFER_OVERFLOW: retry bigger
            break
    if r != 0:
        return []
    out, p = [], ctypes.cast(buf, ctypes.POINTER(_ADAPTER))
    while p:
        a = p.contents
        if a.IfType != IF_TYPE_LOOPBACK and a.OperStatus == IF_OPER_UP:
            u = a.FirstUnicastAddress
            while u:
                sa = ctypes.string_at(u.contents.Address.lpSockaddr, 8)
                if struct.unpack("<H", sa[:2])[0] == socket.AF_INET:
                    ip = socket.inet_ntoa(sa[4:8])
                    if not ip.startswith("169.254."):  # no DHCP lease: not a real link
                        out.append((a.FriendlyName or a.Description or ip, ip))
                u = u.contents.Next
        p = a.Next
    return out


def default_ip():
    """Local address the OS would use to reach the internet (nothing is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 53))
            return s.getsockname()[0]
    except OSError:
        return None


# ---- connections of a process (GetExtendedTcpTable + a Toolhelp process list)

class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD), ("szExeFile", wt.WCHAR * 260)]

TH32CS_SNAPPROCESS, TCP_TABLE_OWNER_PID_CONNECTIONS, MIB_TCP_STATE_ESTAB = 2, 4, 5


def pids(exes):
    """Process ids of the running processes whose exe name is in exes (case ignored)."""
    k32 = ctypes.windll.kernel32
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == wt.HANDLE(-1).value:
        return set()
    names, out = {e.lower() for e in exes}, set()
    try:
        pe = _PROCESSENTRY32W(dwSize=ctypes.sizeof(_PROCESSENTRY32W))
        ok = k32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() in names:
                out.add(pe.th32ProcessID)
            ok = k32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k32.CloseHandle(snap)
    return out


def server_ports(exes):
    """{remote port: remote ip} of the established IPv4 TCP connections owned by the
    processes named exes; {} when none is running."""
    want = pids(exes)
    if not want:
        return {}
    size = wt.DWORD(0)
    for _ in range(3):                                 # the table can grow between the calls
        buf = ctypes.create_string_buffer(max(size.value, 4))
        r = ctypes.windll.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, socket.AF_INET,
                                                        TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        if r != 122:                                   # ERROR_INSUFFICIENT_BUFFER: retry bigger
            break
    if r != 0:
        return {}
    n, out = struct.unpack_from("<I", buf)[0], {}
    for i in range(n):            # MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid
        state, _, _, raddr, rport, pid = struct.unpack_from("<6I", buf, 4 + 24 * i)
        if state == MIB_TCP_STATE_ESTAB and pid in want:
            out[socket.ntohs(rport & 0xFFFF)] = socket.inet_ntoa(struct.pack("<I", raddr))
    return out


# ---- packets

def parse(pkt, lo, hi):
    """(src, sport, dst, dport, seq, payload) of an IPv4 TCP segment with data
    whose source or destination port is in lo..hi, else None."""
    if len(pkt) < 40 or pkt[0] >> 4 != 4 or pkt[9] != 6:
        return None
    ihl = (pkt[0] & 15) * 4
    if struct.unpack_from(">H", pkt, 6)[0] & 0x3FFF:   # fragment (MF set or offset): not ours
        return None
    total = struct.unpack_from(">H", pkt, 2)[0] or len(pkt)   # 0 with large-send offload
    sport, dport, seq = struct.unpack_from(">HHI", pkt, ihl)
    if not (lo <= sport <= hi or lo <= dport <= hi):
        return None
    start = ihl + (pkt[ihl + 12] >> 4) * 4
    payload = pkt[start:min(total, len(pkt))]
    if not payload:
        return None
    return socket.inet_ntoa(pkt[12:16]), sport, socket.inet_ntoa(pkt[16:20]), dport, seq, payload
