"""Seeded random-input smoke fuzzing of the code that reads untrusted data: rule text, raw packets, TLS
ClientHellos and signature matching. Each run is deterministic; set NETSENTINEL_FUZZ_SEED and
NETSENTINEL_FUZZ_CASES to explore further, e.g. in a nightly CI job."""
import os
import random

import pytest

from netsentinel.models import Packet, utc
from netsentinel.parsing import parse_raw, tls_sni
from netsentinel.signatures import STARTER_RULES, compile_rules, load_paths

SEED = int(os.environ.get('NETSENTINEL_FUZZ_SEED', '20261118'))
CASES = int(os.environ.get('NETSENTINEL_FUZZ_CASES', '300'))
TOKENS = ['alert', 'drop', 'pass', 'tcp', 'udp', 'http', 'dns', 'tls', 'any', '$HOME_NET', '!', '[', ']', '->',
          '<>', '(', ')', ';', ':', '"', '|', '\\', 'msg', 'content', 'pcre', 'nocase', 'depth', 'offset',
          'distance', 'within', 'isdataat', 'flowbits', 'threshold', 'sid', 'rev', 'http.uri', 'dns.query',
          'byte_test', 'fast_pattern', '/', ',', '1', '-1', '65536', '0x41', '/(a+)+$/', '!"x"', '|00 ff|', ' ']


def _rule(rng: random.Random) -> str:
    return ''.join(rng.choice(TOKENS) + rng.choice(('', ' ')) for _ in range(rng.randint(1, 40)))


def test_rule_parser_never_raises():
    rng = random.Random(SEED)
    text = '\n'.join(_rule(rng) for _ in range(CASES))
    text += '\n' + ''.join(chr(rng.randint(0, 0x2FF)) for _ in range(5000))
    rule_set, report = compile_rules(text)
    assert report.seen >= 1 and report.loaded <= report.seen


def test_raw_packet_and_tls_parsers_never_raise():
    rng = random.Random(SEED + 1)
    ipv4 = bytes.fromhex('450000280001000040060000c0a80001c0a80002')
    for _ in range(CASES):
        n = rng.randint(0, 120)
        junk = bytes(rng.randrange(256) for _ in range(n))
        for data in (junk, ipv4 + junk, bytes([0x60]) + junk, bytes([0x16, 0x03, 0x01]) + junk):
            parse_raw(data)
            assert isinstance(tls_sni(data), str)


def test_matching_random_payloads_never_raises():
    rng = random.Random(SEED + 2)
    rule_set, _ = load_paths([str(STARTER_RULES)])
    alphabet = b'GET POST /admin.php?id=1 UNION SELECT HTTP/1.1\r\nHost: User-Agent: sqlmap ../ %00 \x00\xff'
    for i in range(CASES):
        data = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 600)))
        proto = rng.choice(('TCP', 'UDP', 'ICMP'))
        p = Packet(utc(), '203.0.113.9', '192.168.1.10', proto, rng.randint(1, 65535), rng.choice((80, 53, 443, 4444)),
                   60 + len(data), rng.choice(('', 'S', 'PA', 'FPU')), '', 'test', False, 1000.0 + i, data=data)
        rule_set.match(p, p.src_ip, p.dst_ip, 1000.0 + i)
    assert rule_set.errors == 0


@pytest.mark.parametrize('payload', [b'', b'\x16', b'\x16\x03\x01\xff\xff' + b'\x01' * 10])
def test_truncated_client_hello(payload):
    assert tls_sni(payload) == ''
