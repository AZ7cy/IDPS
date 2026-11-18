"""ARP-001, AUTH-001, NET-006 and TLS-001."""
import random

from netsentinel.addresses import PROTECTED
from netsentinel.models import Packet, utc
from netsentinel.simulation import generate_round

from test_detector import fired

GOOD_MAC, BAD_MAC = '02:00:00:00:00:01', '02:00:00:00:00:66'


def arp(ip, mac, t, dst='192.168.1.50', op='is-at'):
    return Packet(utc(), ip, dst, 'ARP', None, None, 42, op, '', 'test', False, t, mac)


def random_names(seed, n, k=45, suffix='.example.net'):
    rnd = random.Random(seed)
    return [''.join(rnd.choices('abcdefghijklmnop0123456789', k=k)) + suffix for _ in range(n)]


# -- ARP-001 -----------------------------------------------------------------------
def test_arp_one_mac_per_ip_is_quiet(detector):
    packets = [arp(f'192.168.1.{i % 20}', f'02:00:00:00:01:{i % 20:02x}', 1000 + i) for i in range(200)]
    assert fired(detector, packets) == []


def test_arp_conflicting_macs_fire_once_without_block_target(detector):
    alerts = []
    for i in range(20):
        mac = GOOD_MAC if i % 2 == 0 else BAD_MAC
        alerts += detector.process(arp('192.168.1.1', mac, 1000 + i))[0]
    assert [a.rule_id for a in alerts] == ['ARP-001']
    a = alerts[0]
    assert a.block_target is None and GOOD_MAC in a.evidence and BAD_MAC in a.evidence
    assert a.src_ip == '192.168.1.1'


def test_arp_gateway_has_high_confidence(detector, monkeypatch):
    monkeypatch.setattr(PROTECTED, '_all', frozenset({'192.168.1.1'}))
    alerts = [a for p in (arp('192.168.1.1', GOOD_MAC, 1000), arp('192.168.1.1', BAD_MAC, 1001))
              for a in detector.process(p)[0]]
    assert alerts[0].confidence == 'high' and 'gateway' in alerts[0].evidence


def test_arp_old_binding_outside_window_is_quiet(detector):
    # A device replaced after the 300 s window (for example a new DHCP lease) is not spoofing.
    assert fired(detector, [arp('192.168.1.9', GOOD_MAC, 1000), arp('192.168.1.9', BAD_MAC, 1400)]) == []


def test_arp_ignores_probes_and_bad_macs(detector):
    packets = [arp('0.0.0.0', GOOD_MAC, 1000), arp('0.0.0.0', BAD_MAC, 1001),
               arp('192.168.1.7', '00:00:00:00:00:00', 1002), arp('192.168.1.7', GOOD_MAC, 1003),
               arp('192.168.1.7', 'ff:ff:ff:ff:ff:ff', 1004)]
    assert fired(detector, packets) == []


def test_arp_checked_even_for_trusted_ip(detector, store):
    store.trust('192.168.1.1')
    assert fired(detector, [arp('192.168.1.1', GOOD_MAC, 1000), arp('192.168.1.1', BAD_MAC, 1001)]) == ['ARP-001']


def test_arp_packets_do_not_trigger_ioc(detector, store):
    store.block('203.0.113.5', 'r')
    assert fired(detector, [arp('203.0.113.5', GOOD_MAC, 1000)]) == []


# -- AUTH-001 ----------------------------------------------------------------------
def test_ssh_brute_force(detector, pkt):
    packets = [pkt(src='10.0.0.66', dport=22, sport=40000 + i, t=1000 + i) for i in range(16)]
    alerts = [a for p in packets for a in detector.process(p)[0] if a.rule_id == 'AUTH-001']
    assert len(alerts) == 1 and 'SSH' in alerts[0].evidence and alerts[0].block_target == '10.0.0.66'


def test_syn_retransmits_count_as_one_attempt(detector, pkt):
    packets = [pkt(src='10.0.0.67', dport=3389, sport=40001, t=1000 + i) for i in range(50)]
    assert 'AUTH-001' not in fired(detector, packets)


def test_non_login_port_and_spread_out_attempts_are_quiet(detector, pkt):
    https = [pkt(src='10.0.0.68', dport=443, sport=40000 + i, t=1000 + i) for i in range(30)]
    slow = [pkt(src='10.0.0.69', dport=22, sport=41000 + i, t=2000 + i * 10) for i in range(30)]
    assert 'AUTH-001' not in fired(detector, https + slow)


# -- NET-006 -----------------------------------------------------------------------
def test_udp_port_scan(detector, pkt):
    packets = [pkt(src='10.0.0.70', proto='UDP', flags='', sport=41000, dport=port, t=1000 + i * 0.01)
               for i, port in enumerate(range(100, 125))]
    alerts = [a for p in packets for a in detector.process(p)[0] if a.rule_id == 'NET-006']
    assert len(alerts) == 1 and alerts[0].confidence == 'low'


def test_udp_replies_to_ephemeral_ports_are_not_a_scan(detector, pkt):
    # A DNS or QUIC server answering many client ports.
    packets = [pkt(src='8.8.8.8', dst='192.168.1.12', proto='UDP', flags='', sport=53, dport=port, t=1000 + i * 0.01)
               for i, port in enumerate(range(49152, 49252))]
    packets += [pkt(src='1.1.1.1', dst='192.168.1.12', proto='UDP', flags='', sport=443, dport=port,
                    t=1000 + i * 0.01) for i, port in enumerate(range(32768, 32868))]
    assert 'NET-006' not in fired(detector, packets)


# -- TLS-001 -----------------------------------------------------------------------
def test_tls_high_entropy_server_names(detector, pkt):
    packets = [pkt(src='10.0.0.71', dst='203.0.113.80', dport=443, flags='PA', payload=n, t=1000 + i)
               for i, n in enumerate(random_names(2, 9))]
    alerts = [a for p in packets for a in detector.process(p)[0] if a.rule_id == 'TLS-001']
    assert len(alerts) == 1 and alerts[0].block_target == '10.0.0.71'


def test_tls_normal_and_short_names_are_quiet(detector, pkt):
    normal = ['www.google.com', 'r3---sn-ab5l6nr6.googlevideo.com', 'login.microsoftonline.com',
              'd1a2b3c4d5e6f7.cloudfront.net', 'outlook.office365.com'] * 4
    short = random_names(3, 12, k=20)
    packets = [pkt(src='10.0.0.72', dport=443, flags='PA', payload=n, t=1000 + i)
               for i, n in enumerate(normal + short)]
    assert 'TLS-001' not in fired(detector, packets)


def test_tls_rule_ignores_http_and_dns_payloads(detector, pkt):
    names = random_names(4, 9)
    http = [pkt(src='10.0.0.73', dport=80, flags='PA', payload=n, t=1000 + i) for i, n in enumerate(names)]
    assert 'TLS-001' not in fired(detector, http)


# -- simulation --------------------------------------------------------------------
def test_simulation_triggers_new_rules(detector):
    rnd = random.Random(7)
    seen = set()
    for _ in range(400):
        for p in generate_round(rnd):
            seen.update(a.rule_id for a in detector.process(p)[0])
    assert {'ARP-001', 'AUTH-001', 'NET-006', 'TLS-001'} <= seen
