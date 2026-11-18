"""Simulated traffic for demos and testing."""
from __future__ import annotations

import random
from typing import Iterator

from .models import Packet, utc

SOURCES = ('10.10.10.10', '10.10.10.20', '10.10.10.30')
TARGET = '10.10.10.1'
WEB_REQUESTS = ('GET /../../etc/passwd HTTP/1.1\r\nHost: demo.local',
                'GET /search?q=1%20UNION%20SELECT%20password HTTP/1.1\r\nHost: demo.local',
                'GET /index.html HTTP/1.1\r\nHost: demo.local')
MODES = ('normal', 'scan', 'horizontal', 'burst', 'web', 'dns', 'icmp', 'udpscan', 'brute', 'tls', 'arp')
WEIGHTS = (40, 10, 7, 7, 8, 8, 6, 6, 6, 6, 6)
GATEWAY_MAC = '02:00:5e:10:10:01'
SPOOFER_MAC = '02:00:5e:66:66:66'
_NAME_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'


def _packet(src, dst, proto, sport, dport, length, flags='', payload='', src_mac=''):
    return Packet(utc(), src, dst, proto, sport, dport, length, flags, payload, 'simulated', src_mac=src_mac)


def generate_round(rnd: random.Random) -> Iterator[Packet]:
    """Yield the packets for one randomly chosen traffic pattern."""
    mode = rnd.choices(MODES, WEIGHTS)[0]
    src, dst = rnd.choice(SOURCES), TARGET
    if mode == 'scan':
        for port in rnd.sample(range(20, 300), 25):
            yield _packet(src, dst, 'TCP', rnd.randint(40000, 60000), port, 60, 'S')
    elif mode == 'horizontal':
        for x in rnd.sample(range(10, 80), 45):
            yield _packet(src, f'10.10.{rnd.choice((20, 21, 22, 23))}.{x}', 'TCP', 50000, 443, 60, 'S')
    elif mode == 'burst':
        for _ in range(450):
            yield _packet(src, dst, 'TCP', 50000, 443, 60, 'S')
    elif mode == 'web':
        yield _packet(src, dst, 'TCP', 51000, 80, 220, 'PA', rnd.choice(WEB_REQUESTS))
    elif mode == 'dns':
        for _ in range(9):
            name = ''.join(rnd.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=45)) + '.example.com'
            yield _packet(src, '8.8.8.8', 'UDP', 53000, 53, 160, '', name)
    elif mode == 'icmp':
        for _ in range(260):
            yield _packet(src, dst, 'ICMP', None, None, 98)
    elif mode == 'udpscan':
        for port in rnd.sample(range(1, 1024), 25):
            yield _packet(src, dst, 'UDP', 41000, port, 42)
    elif mode == 'brute':
        for sport in rnd.sample(range(40000, 60000), 20):
            yield _packet(src, dst, 'TCP', sport, rnd.choice((22, 3389)), 60, 'S')
    elif mode == 'tls':
        for _ in range(9):
            name = ''.join(rnd.choices(_NAME_CHARS, k=45)) + '.example.net'
            yield _packet(src, '203.0.113.80', 'TCP', rnd.randint(40000, 60000), 443, 517, 'PA', name)
    elif mode == 'arp':
        # The gateway answers for itself, then another host claims the gateway's address.
        yield _packet(TARGET, src, 'ARP', None, None, 42, 'is-at', src_mac=GATEWAY_MAC)
        yield _packet(TARGET, src, 'ARP', None, None, 42, 'is-at', src_mac=SPOOFER_MAC)
    else:
        yield _packet(src, dst, 'TCP', 50000, rnd.choice((53, 80, 443)), rnd.randint(60, 900), 'A')
