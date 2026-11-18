"""Address normalization, prefix lookups and protected-address discovery."""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import threading
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path

_LOOPBACK_V4 = ipaddress.ip_network('127.0.0.0/8')
_LOOPBACK_V6 = ipaddress.ip_network('::1/128')


@lru_cache(maxsize=65536)
def canonical_ip(value: str) -> str:
    """Strip a scope ID and unwrap IPv4-mapped IPv6. Non-IP text is returned without the scope."""
    text = str(value).split('%')[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def normalize_network(value):
    """Parse an IP or CIDR into a network, unwrapping IPv4-mapped IPv6. Raises ValueError."""
    net = ipaddress.ip_network(str(value).strip().split('%')[0], strict=False)
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 96:
        mapped = net.network_address.ipv4_mapped
        if mapped is not None:
            return ipaddress.ip_network(f'{mapped}/{net.prefixlen - 96}', strict=False)
    return net


def parse_address(value: str):
    """Return the canonical ipaddress object, or None if the value is not an IP."""
    try:
        return ipaddress.ip_address(canonical_ip(value))
    except ValueError:
        return None


class PrefixIndex:
    """Immutable membership index for a set of networks.

    Intervals are sorted by start and paired with the running maximum end. An address is
    covered if the largest end among intervals starting at or before it reaches it.
    """
    __slots__ = ('_families', '_size')

    def __init__(self, nets=()):
        intervals = {4: [], 6: []}
        for net in nets:
            intervals[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self._families = {version: self._build(items) for version, items in intervals.items()}
        self._size = len(intervals[4]) + len(intervals[6])

    @staticmethod
    def _build(items):
        items.sort()
        starts, max_ends, current = [], [], -1
        for start, end in items:
            current = max(current, end)
            starts.append(start)
            max_ends.append(current)
        return starts, max_ends

    def __len__(self):
        return self._size

    def contains(self, addr) -> bool:
        starts, max_ends = self._families[addr.version]
        if not starts:
            return False
        value = int(addr)
        idx = bisect_right(starts, value) - 1
        return idx >= 0 and max_ends[idx] >= value


# ----------------------------------------------------------------------------
# Protected addresses: this host plus gateway / DNS / DHCP infrastructure
# ----------------------------------------------------------------------------
def _discover_local() -> set[str]:
    found = {'127.0.0.1', '::1'}
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            found.add(canonical_ip(item[4][0]))
    except OSError:
        pass
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    found.add(canonical_ip(a.address))
    except Exception:
        pass
    return found


def _run(cmd, timeout) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ''


def _discover_infrastructure() -> set[str]:
    found: set[str] = set()
    route = Path('/proc/net/route')
    try:
        if route.exists():
            for line in route.read_text(errors='ignore').splitlines()[1:]:
                cols = line.split()
                if len(cols) > 2 and cols[1] == '00000000':
                    try:
                        found.add(str(ipaddress.ip_address(bytes.fromhex(cols[2])[::-1])))
                    except ValueError:
                        pass
    except OSError:
        pass
    if platform.system() == 'Windows':
        for line in _run(['route', 'print', '-4'], 2).splitlines():
            m = re.match(r'^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+', line)
            if m:
                found.add(canonical_ip(m.group(1)))
                break
        for line in _run(['ipconfig', '/all'], 3).splitlines():
            m = re.search(r'(?:DNS Servers|DHCP Server)[ .:]*([0-9a-fA-F:.]+)', line, re.I)
            if m and parse_address(m.group(1)) is not None:
                found.add(canonical_ip(m.group(1)))
    resolv = Path('/etc/resolv.conf')
    try:
        if resolv.exists():
            for line in resolv.read_text(errors='ignore').splitlines():
                m = re.match(r'\s*nameserver\s+([^\s#]+)', line)
                if m:
                    found.add(canonical_ip(m.group(1)))
    except OSError:
        pass
    return {x for x in found if x}


class ProtectedAddresses:
    """Snapshot of addresses that must never be blocked.

    `refresh()` does the slow discovery and swaps in new frozensets; readers on the packet
    path only read the current references and never block on discovery.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._local = frozenset({'127.0.0.1', '::1'})
        self._all = self._local

    def refresh(self) -> frozenset:
        local = frozenset(_discover_local())
        infra = frozenset(_discover_infrastructure())
        with self._lock:
            self._local = local
            self._all = local | infra
            return self._all

    def local(self) -> frozenset:
        return self._local

    def all(self) -> frozenset:
        return self._all


PROTECTED = ProtectedAddresses()


def is_protected(ip: str) -> bool:
    addr = parse_address(ip)
    if addr is None:
        return True
    return addr.is_loopback or addr.is_unspecified or addr.is_multicast or str(addr) in PROTECTED.all()


def blocks_self(net) -> bool:
    """True if the network covers loopback or any protected address."""
    if net.version == 4 and net.overlaps(_LOOPBACK_V4):
        return True
    if net.version == 6 and net.overlaps(_LOOPBACK_V6):
        return True
    for raw in PROTECTED.all():
        addr = parse_address(raw)
        if addr is not None and addr.version == net.version and addr in net:
            return True
    return False
