"""Convert scapy packets and raw L3 bytes into Packet records."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from .config import HTTP_PAYLOAD_MAX, HTTP_PORTS, SIG_PAYLOAD_MAX
from .models import Packet, utc


def _capture_time(pkt) -> float:
    try:
        return float(pkt.time)
    except (AttributeError, TypeError, ValueError):
        return time.time()


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec='milliseconds')
    except (OverflowError, OSError, ValueError):
        return utc()


def _has_icmpv6(pkt) -> bool:
    layer, depth = pkt, 0
    while layer is not None and depth < 64:
        if layer.__class__.__name__.startswith('ICMPv6'):
            return True
        layer = getattr(layer, 'payload', None)
        depth += 1
    return False


def _tcp_dns_query(raw: bytes) -> str:
    """DNS over TCP has a 2-byte length prefix; also try without it."""
    from scapy.layers.dns import DNS, DNSQR
    candidates = ([raw[2:]] if len(raw) >= 14 else []) + [raw]
    for data in candidates:
        if not data:
            continue
        try:
            d = DNS(data)
        except Exception:
            continue
        qr = d.getlayer(DNSQR)
        if d.qr == 0 and qr is not None and getattr(qr, 'qname', None):
            return qr.qname.decode('utf-8', 'replace').rstrip('.')
    return ''


def load_layers():
    """Import the scapy layers we parse.

    PcapReader picks the decoder from the file's link type when it opens the file, so the Ethernet,
    IP and DNS layers must be registered before then, or every packet is read as Raw.
    """
    import importlib
    for name in ('scapy.layers.l2', 'scapy.layers.inet', 'scapy.layers.inet6', 'scapy.layers.dns'):
        importlib.import_module(name)


def tls_sni(data: bytes) -> str:
    """Server name from a TLS ClientHello at the start of `data`, or '' if there is none.

    Every length is bounds-checked, so truncated or random input returns ''.
    """
    try:
        if len(data) < 9 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
            return ''
        end = min(len(data), 5 + int.from_bytes(data[3:5], 'big'))
        i = 9 + 2 + 32                                  # record + handshake headers, version, random
        if i >= end:
            return ''
        i += 1 + data[i]                                # session id
        i += 2 + int.from_bytes(data[i:i + 2], 'big')   # cipher suites
        i += 1 + data[i]                                # compression methods
        ext_end = min(end, i + 2 + int.from_bytes(data[i:i + 2], 'big'))
        i += 2
        while i + 4 <= ext_end:
            ext_type = int.from_bytes(data[i:i + 2], 'big')
            ext_len = int.from_bytes(data[i + 2:i + 4], 'big')
            i += 4
            if ext_type == 0:                           # server_name
                j, list_end = i + 2, min(ext_end, i + ext_len)
                while j + 3 <= list_end:
                    name_type, name_len = data[j], int.from_bytes(data[j + 1:j + 3], 'big')
                    j += 3
                    if j + name_len > list_end:
                        return ''
                    if name_type == 0:
                        name = data[j:j + name_len].decode('ascii')
                        return name.rstrip('.').lower() if name.isprintable() else ''
                    j += name_len
                return ''
            i += ext_len
    except (IndexError, ValueError, UnicodeDecodeError):
        pass
    return ''


def _arp_packet(arp, pkt, source) -> Optional[Packet]:
    op = {1: 'who-has', 2: 'is-at'}.get(int(arp.op), str(arp.op))
    ts = _capture_time(pkt)
    return Packet(_iso(ts), str(arp.psrc), str(arp.pdst), 'ARP', None, None, len(pkt), op, '', source, False, ts,
                  str(arp.hwsrc or '').lower())


def scapy_packet(pkt, source='live') -> Optional[Packet]:
    """Return a Packet for an IPv4/IPv6 or ARP scapy packet, or None if it cannot be parsed."""
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP
        if pkt.haslayer(ARP):
            return _arp_packet(pkt[ARP], pkt, source)
        if pkt.haslayer(IP):
            ip = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
        else:
            return None
        proto, sport, dport, flags, payload, data = 'IP', None, None, '', '', b''
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto, sport, dport, flags = 'TCP', int(tcp.sport), int(tcp.dport), str(tcp.flags)
            raw = bytes(tcp.payload)
            data = raw[:SIG_PAYLOAD_MAX]
            if 53 in (sport, dport):
                payload = _tcp_dns_query(raw)
            elif dport in HTTP_PORTS:
                payload = raw[:HTTP_PAYLOAD_MAX].decode('utf-8', 'replace')
            elif raw[:1] == b'\x16':
                payload = tls_sni(raw)          # TLS ClientHello server name
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto, sport, dport = 'UDP', int(udp.sport), int(udp.dport)
            data = bytes(udp.payload)[:SIG_PAYLOAD_MAX]
            if 53 in (sport, dport) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                payload = pkt[DNSQR].qname.decode('utf-8', 'replace').rstrip('.')
        elif pkt.haslayer(ICMP):
            proto = 'ICMP'
            data = bytes(pkt[ICMP].payload)[:SIG_PAYLOAD_MAX]
        elif _has_icmpv6(pkt):
            proto = 'ICMPv6'
        ts = _capture_time(pkt)
        return Packet(_iso(ts), str(ip.src), str(ip.dst), proto, sport, dport, len(pkt), flags, payload,
                      source, False, ts, data=data)
    except Exception:
        return None


def parse_raw(data: bytes, source='ips') -> Optional[Packet]:
    """Raw L3 bytes from WinDivert / NFQUEUE -> Packet."""
    if not data:
        return None
    version = data[0] >> 4
    try:                    # scapy raises on truncated headers (found by tests/test_fuzz.py)
        if version == 4:
            from scapy.layers.inet import IP
            return scapy_packet(IP(data), source)
        if version == 6:
            from scapy.layers.inet6 import IPv6
            return scapy_packet(IPv6(data), source)
    except Exception:
        return None
    return None
