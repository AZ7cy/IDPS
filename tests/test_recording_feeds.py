"""PCAP recording, SNI and ARP parsing, blocklist feeds and the new CLI options."""
import io
import os
import random

import pytest

from netsentinel.addresses import PROTECTED
from netsentinel.feeds import FeedResult, feed_source, parse_feed, update_feeds, validate_feed_url
from netsentinel.headless import run_headless
from netsentinel.parsing import tls_sni
from netsentinel.settings import Settings

SPAMHAUS = """; Spamhaus DROP List 2026/11/18 - (c) 2026 The Spamhaus Project SLU
; Expires: Wed, 18 Nov 2026 12:00:00 GMT
1.10.16.0/20 ; SBL256894
2.56.192.0/22 ; SBL459831
"""
FEODO = """################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist                #
################################################################
162.243.103.246
178.62.3.223
"""


# -- TLS SNI -----------------------------------------------------------------------
def client_hello(name: str) -> bytes:
    """A minimal TLS 1.2 ClientHello with a GREASE-like extension before server_name."""
    def u16(n):
        return n.to_bytes(2, 'big')
    host = name.encode()
    server_name = u16(len(host) + 3) + b'\x00' + u16(len(host)) + host
    extensions = (u16(0x0a0a) + u16(0)                                      # empty extension first
                  + u16(0) + u16(len(server_name)) + server_name)
    body = (b'\x03\x03' + bytes(32) + b'\x20' + bytes(32)                   # version, random, session id
            + u16(4) + b'\x13\x01\xc0\x2f' + b'\x01\x00'                    # cipher suites, compression
            + u16(len(extensions)) + extensions)
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + u16(len(handshake)) + handshake


def test_tls_sni_from_client_hello():
    assert tls_sni(client_hello('Example.ORG')) == 'example.org'


def test_tls_sni_is_total_on_bad_input():
    data = client_hello('example.org')
    for cut in range(len(data)):
        assert isinstance(tls_sni(data[:cut]), str)
    rnd = random.Random(5)
    for _ in range(2000):
        blob = bytes([0x16, 0x03, 0x01]) + bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 120)))
        assert isinstance(tls_sni(blob), str)
    assert tls_sni(b'') == '' and tls_sni(b'GET / HTTP/1.1\r\n') == ''


def test_parser_puts_sni_in_payload_and_parses_arp():
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import ARP, Ether
    from netsentinel.parsing import scapy_packet
    p = scapy_packet(IP(src='10.0.0.2', dst='93.184.216.34') / TCP(sport=50000, dport=443, flags='PA')
                     / client_hello('example.org'))
    assert p is not None and p.payload == 'example.org'
    a = scapy_packet(Ether(src='02:AA:00:00:00:01') / ARP(op=2, psrc='192.168.1.1', pdst='192.168.1.12',
                                                         hwsrc='02:AA:00:00:00:01'))
    assert a is not None
    assert (a.protocol, a.src_ip, a.dst_ip, a.flags, a.src_mac) == ('ARP', '192.168.1.1', '192.168.1.12', 'is-at',
                                                                     '02:aa:00:00:00:01')


# -- PCAP recording ----------------------------------------------------------------
def test_recorder_writes_readable_pcap(tmp_path):
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import rdpcap
    from netsentinel.recording import PcapRecorder
    path = tmp_path / 'out.pcap'
    rec = PcapRecorder(path)
    for port in range(5):
        assert rec.write(Ether() / IP(dst='10.0.0.1') / TCP(dport=1000 + port))
    rec.close()
    assert not rec.write(Ether() / IP())
    packets = rdpcap(str(path))
    assert len(packets) == 5 and packets[4][TCP].dport == 1004
    assert 'Saved 5 packets' in rec.summary()
    if os.name != 'nt':
        assert (path.stat().st_mode & 0o777) == 0o600


def test_recorder_stops_at_size_limit(tmp_path):
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether
    from netsentinel.recording import PcapRecorder
    rec = PcapRecorder(tmp_path / 'small.pcap', max_bytes=200)
    results = [rec.write(Ether() / IP()) for _ in range(10)]
    rec.close()
    assert rec.full and rec.size <= 200 and results.count(True) == rec.packets and rec.packets < 10
    assert 'limit' in rec.summary()


def test_ethernet_pcap_replays_in_a_fresh_process(tmp_path):
    """Real captures are Ethernet; the decoder must be loaded before PcapReader opens the file."""
    pytest.importorskip('scapy')
    import subprocess
    import sys
    from pathlib import Path
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import ARP, Ether
    from scapy.utils import wrpcap
    path = tmp_path / 'eth.pcap'
    wrpcap(str(path), [Ether() / IP(src='10.0.0.5', dst='10.0.0.1') / TCP(dport=80),
                       Ether() / ARP(op=2, psrc='10.0.0.1', hwsrc='02:00:00:00:00:01')])
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, 'NetSentinel_IDPS_v5.py', '--headless', '--source', 'pcap',
                             '--pcap', str(path), '--db', str(tmp_path / 'r.db')],
                            cwd=root, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0 and 'Processed 2 packets' in result.stdout, result.stdout + result.stderr


# -- feeds -------------------------------------------------------------------------
def test_validate_feed_url():
    assert validate_feed_url('https://www.spamhaus.org/drop/drop.txt') is None
    for bad in ('http://example.com/x.txt', 'ftp://example.com/x', 'https:///nohost', 'example.com',
                'https://exa mple.com/'):
        assert validate_feed_url(bad)


def test_parse_feed_formats_and_limits():
    entries, skipped = parse_feed(SPAMHAUS + FEODO + 'not-an-ip\n0.0.0.0/1\n2001:db8::/12\n')
    assert ('1.10.16.0/20', 'SBL256894') in entries and ('162.243.103.246/32', '') in entries
    assert len(entries) == 4 and skipped == 3        # invalid line, /1 and /12 are too broad


def fake_fetch(feeds):
    def fetch(url):
        value = feeds[url]
        if isinstance(value, Exception):
            raise value
        return value
    return fetch


def test_update_feeds_replaces_and_removes(store):
    a, b = 'https://a.example/list.txt', 'https://b.example/list.txt'
    results = update_feeds(store, [a, b], fake_fetch({a: '198.51.100.1\n198.51.100.2\n',
                                                      b: '203.0.113.0/24 ; bad range\n'}))
    assert [r.stored for r in results] == [2, 1] and not any(r.error for r in results)
    assert store.is_blocked('198.51.100.2') and store.is_blocked('203.0.113.9')
    store.block('192.0.2.50', 'manual entry')

    # Feed A drops one address: it is unblocked. Feed B is no longer configured: its entries go.
    results = update_feeds(store, [a], fake_fetch({a: '198.51.100.1\n'}))
    assert results[0].removed == 1
    assert store.is_blocked('198.51.100.1') and not store.is_blocked('198.51.100.2')
    assert not store.is_blocked('203.0.113.9') and store.is_blocked('192.0.2.50')
    sources = {r['ip']: r['source'] for r in store.block_rows()}
    assert sources == {'198.51.100.1/32': feed_source(a), '192.0.2.50/32': 'manual'}


def test_failed_or_garbage_feed_keeps_entries(store):
    url = 'https://a.example/list.txt'
    update_feeds(store, [url], fake_fetch({url: '198.51.100.7\n'}))
    for broken in (OSError('timed out'), '<html><body>503 Service Unavailable</body></html>\n'):
        result = update_feeds(store, [url], fake_fetch({url: broken}))[0]
        assert result.error and 'failed' in result.summary()
        assert store.is_blocked('198.51.100.7')


def test_feed_never_blocks_protected_trusted_or_manual(store, monkeypatch):
    monkeypatch.setattr(PROTECTED, '_all', frozenset({'192.168.1.1'}))
    store.trust('198.51.100.0/28')
    store.block('203.0.113.77', 'keep me', source='manual')
    url = 'https://a.example/list.txt'
    result = update_feeds(store, [url], fake_fetch({url: '192.168.1.0/24\n198.51.100.3\n203.0.113.77\n8.8.4.4\n'}))[0]
    assert result.stored == 1 and result.skipped == 3
    rows = {r['ip']: r for r in store.block_rows()}
    assert rows['203.0.113.77/32']['source'] == 'manual' and rows['203.0.113.77/32']['reason'] == 'keep me'
    assert not store.is_blocked('192.168.1.5') and store.is_blocked('8.8.4.4')


def test_feed_entries_survive_restart(tmp_path):
    from netsentinel.store import Store
    url = 'https://a.example/list.txt'
    s = Store(tmp_path / 'f.db')
    update_feeds(s, [url], fake_fetch({url: '198.51.100.9\n'}))
    s.close()
    s = Store(tmp_path / 'f.db')
    try:
        assert s.is_blocked('198.51.100.9') and s.block_rows()[0]['source'] == feed_source(url)
    finally:
        s.close()


def test_feed_result_summary():
    assert 'entries' in FeedResult('https://x.example/', stored=3).summary()


# -- settings and CLI --------------------------------------------------------------
def test_new_settings_and_bpf_migration(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text('{"bpf": "ip or ip6", "feed_urls": ["http://insecure.example/x"], "feed_interval_hours": 500, '
                    '"save_pcap": true, "save_pcap_path": "C:/x.pcap"}', encoding='utf-8')
    s = Settings(path)
    assert s.get('bpf') == 'ip or ip6 or arp'
    assert s.get('feed_urls') == [] and s.get('feed_interval_hours') == 24
    assert s.get('save_pcap') is True and s.get('save_pcap_path') == 'C:/x.pcap'
    assert s.set('feed_urls', ['https://www.spamhaus.org/drop/drop.txt'])
    assert not s.set('feed_urls', ['https://ok.example/', 'http://bad.example/'])
    custom = tmp_path / 'custom.json'
    custom.write_text('{"bpf": "tcp port 80"}', encoding='utf-8')
    assert Settings(custom).get('bpf') == 'tcp port 80'


def test_save_pcap_requires_live_source(tmp_path):
    out = io.StringIO()
    code = run_headless('sim', duration=1, db=str(tmp_path / 'h.db'), out=out, save_pcap=str(tmp_path / 'x.pcap'))
    assert code == 2 and '--save-pcap' in out.getvalue()


def test_invalid_feed_url_rejected(tmp_path):
    out = io.StringIO()
    code = run_headless('sim', duration=1, db=str(tmp_path / 'h.db'), out=out, feeds=['http://insecure.example/'])
    assert code == 2 and 'https' in out.getvalue()


def test_cli_parses_new_options():
    from netsentinel.app import build_parser
    args = build_parser().parse_args(['--headless', '--source', 'live', '--save-pcap', 'c.pcap',
                                      '--feed', 'https://a.example/1', '--feed', 'https://b.example/2',
                                      '--feed-interval', '6'])
    assert args.save_pcap == 'c.pcap' and args.feed == ['https://a.example/1', 'https://b.example/2']
    assert args.feed_interval == 6 and args.bpf == 'ip or ip6 or arp'
