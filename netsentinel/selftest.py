"""Live self-test: harmless traffic from this computer that a running live capture should flag.

Everything is sent to 192.0.2.0/24 (TEST-NET-1, RFC 5737). That range is reserved for documentation
and is never routed on the internet, so no real host receives these packets: the router forwards them
upstream and they are dropped. Ordinary sockets are used, so no administrator rights are needed and
the packets leave through the same adapter as normal traffic.
"""
from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

TEST_NETWORK = ipaddress.ip_network('192.0.2.0/24')
TARGET = '192.0.2.10'
HOLD_SECONDS = 1.5          # keep half-open connections long enough for the SYN to leave
DEFAULT_THRESHOLDS = {'NET-001': 20, 'NET-004': 40, 'NET-006': 20, 'AUTH-001': 15, 'DNS-001': 40}
DNS_NAMES = 10              # DNS-001 needs 8 distinct names
EXPECTED_RULES = tuple(DEFAULT_THRESHOLDS)


class SelfTestError(RuntimeError):
    pass


@dataclass(frozen=True)
class Step:
    rule_id: str
    description: str


STEPS = (
    Step('NET-001', 'TCP connection attempts to many ports on one address (port scan)'),
    Step('AUTH-001', 'repeated connection attempts to SSH (login brute force)'),
    Step('NET-004', 'TCP connection attempts to one port on many addresses (horizontal scan)'),
    Step('NET-006', 'UDP datagrams to many ports on one address (UDP scan)'),
    Step('DNS-001', 'DNS queries for long random names (DNS tunneling)'),
)


def is_test_address(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in TEST_NETWORK
    except ValueError:
        return False


def dns_query(name: str, query_id: Optional[int] = None) -> bytes:
    """A standard DNS A query for `name` in wire format."""
    qid = random.randrange(65536) if query_id is None else query_id
    header = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    labels = b''.join(bytes([len(x)]) + x.encode('ascii') for x in name.strip('.').split('.'))
    return header + labels + b'\x00' + struct.pack('!HH', 1, 1)


MAX_LABEL = 63                  # DNS label limit
MAX_NAME = 240                  # stay under the 253-character DNS name limit


def random_name(rnd: random.Random, length: int) -> str:
    """A random name of about `length` characters under `.invalid`, split into valid DNS labels."""
    text = ''.join(rnd.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=min(length, MAX_NAME)))
    labels = [text[i:i + MAX_LABEL - 13] for i in range(0, len(text), MAX_LABEL - 13)]
    return '.'.join(labels) + '.invalid'


def _unreachable(exc: OSError) -> bool:
    return getattr(exc, 'winerror', None) in (10051, 10065) or exc.errno in (101, 113, 10051, 10065)


def _tcp_attempts(targets: Iterable[tuple[str, int]], hold: float = HOLD_SECONDS) -> int:
    """Start a non-blocking TCP connection to each target (one SYN each), then close them all."""
    sockets, sent = [], 0
    try:
        for host, port in targets:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            sockets.append(s)
            try:
                s.connect((host, port))
            except (BlockingIOError, InterruptedError):
                pass
            except OSError as exc:
                if _unreachable(exc):
                    raise SelfTestError('This computer has no route to the test address. '
                                        'Is it connected to a network?') from exc
                if getattr(exc, 'winerror', None) != 10035:     # WSAEWOULDBLOCK means the SYN was sent
                    raise
            sent += 1
        time.sleep(hold)
    finally:
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
    return sent


def _udp_send(packets: Iterable[tuple[str, int, bytes]]) -> int:
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for host, port, payload in packets:
            try:
                s.sendto(payload, (host, port))
            except OSError as exc:
                if _unreachable(exc):
                    raise SelfTestError('This computer has no route to the test address. '
                                        'Is it connected to a network?') from exc
                raise
            sent += 1
    return sent


def _count(thresholds: dict, rule_id: str, extra: int = 5) -> int:
    return max(1, int(thresholds.get(rule_id, DEFAULT_THRESHOLDS[rule_id]))) + extra


def run_self_test(thresholds: Optional[dict] = None, log: Callable[[str], None] = print,
                  should_stop: Callable[[], bool] = lambda: False,
                  tcp: Callable = _tcp_attempts, udp: Callable = _udp_send) -> list[str]:
    """Send the test traffic. `thresholds` maps rule id -> current threshold so edited rules still fire.

    Returns the rule ids that were exercised. `tcp` and `udp` can be replaced for testing.
    """
    t = dict(DEFAULT_THRESHOLDS, **{k: v for k, v in (thresholds or {}).items() if k in DEFAULT_THRESHOLDS})
    rnd = random.Random(int.from_bytes(os.urandom(4), 'big'))
    done: list[str] = []
    log(f'Self-test: sending harmless test traffic to {TEST_NETWORK} (reserved, never routed on the internet).')
    for step in STEPS:
        if should_stop():
            break
        r = step.rule_id
        if r == 'NET-001':
            ports = rnd.sample(range(1000, 2000), _count(t, r))
            n = tcp((TARGET, p) for p in ports)
        elif r == 'AUTH-001':
            n = tcp([(TARGET, 22)] * _count(t, r))
        elif r == 'NET-004':
            hosts = min(250, _count(t, r))
            n = tcp((f'192.0.2.{i}', 443) for i in range(1, hosts + 1))
        elif r == 'NET-006':
            ports = rnd.sample(range(2000, 3000), _count(t, r))
            n = udp((TARGET, p, b'netsentinel self-test') for p in ports)
        else:   # DNS-001: names at least `threshold` characters long
            length = max(45, int(t[r]) + 5)
            n = udp((TARGET, 53, dns_query(random_name(rnd, length))) for _ in range(DNS_NAMES))
        log(f'Self-test: {r}: sent {n} packets ({step.description}).')
        done.append(r)
    return done


def evaluate(expected: Iterable[str], alerts: Iterable) -> tuple[list[str], list[str]]:
    """Split `expected` rule ids into (detected, missed) using alerts about the test network."""
    seen = {a.rule_id for a in alerts if is_test_address(getattr(a, 'dst_ip', ''))}
    expected = list(expected)
    return [r for r in expected if r in seen], [r for r in expected if r not in seen]


MISSED_HINT = ('Missed rules usually mean the capture is on the wrong adapter, the rule is disabled, this '
               "computer's address is a trusted host, or the same test ran less than a minute ago "
               '(rules wait between repeated alerts).')
