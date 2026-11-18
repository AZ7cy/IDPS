import random

from netsentinel.detector import BoundedMap, EventWindow, entropy


def fired(detector, packets):
    rules = []
    for p in packets:
        rules += [a.rule_id for a in detector.process(p)[0]]
    return rules


def test_event_window_keeps_counts_in_sync():
    w = EventWindow()
    for t, key in ((0, 'a'), (1, 'b'), (2, 'a'), (20, 'c')):
        w.add(t, key)
    w.trim(20, 10, 100)
    assert len(w) == 1 and w.unique() == 1 and dict(w.counts) == {'c': 1}
    for t in range(5):
        w.add(21 + t, t)
    w.trim(25, 10, 3)
    assert len(w) == 3 and w.unique() == 3


def test_bounded_map_never_evicts_touched_key():
    m = BoundedMap(EventWindow, cap=3)
    for k in 'abc':
        m.touch(k)
    m.touch('a')                  # a becomes most recent
    m.touch('d')                  # evicts b, the least recently touched
    assert 'b' not in m and 'a' in m and 'd' in m and len(m) == 3


def test_entropy():
    assert entropy('') == 0
    assert entropy('aaaa') == 0
    assert round(entropy('ab'), 3) == 1.0


def test_port_scan_net001(detector, pkt):
    rules = fired(detector, [pkt(dport=port, t=1000 + i * 0.01) for i, port in enumerate(range(20, 45))])
    assert rules.count('NET-001') == 1


def test_syn_burst_net002(detector, pkt):
    assert 'NET-002' in fired(detector, [pkt(src='10.0.0.7', dport=443, t=1000 + i * 0.01) for i in range(90)])


def test_syn_flood_net003_and_synack_suppression(detector, pkt):
    flood = [pkt(src=f'10.2.0.{i % 10}', dst='10.0.0.9', t=1000 + i * 0.01) for i in range(250)]
    assert 'NET-003' in fired(detector, flood)
    detector.reset()
    answered = []
    for i in range(250):
        answered.append(pkt(src=f'10.3.0.{i % 10}', dst='10.0.0.20', t=2000 + i * 0.01))
        answered.append(pkt(src='10.0.0.20', dst=f'10.3.0.{i % 10}', sport=80, dport=40000, flags='SA',
                            t=2000 + i * 0.01))
    assert 'NET-003' not in fired(detector, answered)


def test_horizontal_scan_net004(detector, pkt):
    packets = [pkt(src='10.0.0.6', dst=f'10.1.{i % 4}.{i}', dport=443, t=1000 + i * 0.01) for i in range(50)]
    alerts = [a for p in packets for a in detector.process(p)[0] if a.rule_id == 'NET-004']
    assert len(alerts) == 1 and alerts[0].confidence == 'medium'


def test_stealth_scan_net005(detector, pkt):
    assert 'NET-005' in fired(detector, [pkt(flags='FPU', dport=1000 + i, t=1000 + i * 0.01) for i in range(10)])
    detector.reset()
    assert 'NET-005' not in fired(detector, [pkt(flags='FA', t=1000 + i * 0.01) for i in range(10)])


def test_icmp_flood(detector, pkt):
    packets = [pkt(proto='ICMP', sport=None, dport=None, flags='', t=1000 + i * 0.001) for i in range(260)]
    assert fired(detector, packets).count('ICMP-001') == 1


def test_web_rule_patterns_and_scanner_ua(detector, pkt):
    attack = pkt(src='10.0.0.4', flags='PA', payload='GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n')
    assert fired(detector, [attack]) == ['WEB-001']
    scanner = pkt(src='10.0.0.40', sport=51001, dport=8080, flags='PA',
                  payload='GET /index.html HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n')
    assert fired(detector, [scanner]) == ['WEB-001']
    benign = pkt(src='10.0.0.41', sport=51002, flags='PA', payload='GET /index.html HTTP/1.1\r\nHost: nmap.org\r\n\r\n')
    assert fired(detector, [benign]) == []
    encoded = pkt(src='10.0.0.42', sport=51003, flags='PA',
                  payload='GET /?q=1%2520UNION%2520SELECT%2520x HTTP/1.1\r\nHost: x\r\n\r\n')
    assert fired(detector, [encoded]) == ['WEB-001']


def test_web_rule_reassembles_fragments(detector, pkt):
    parts = ['GET /a/..', '/../etc/passwd HTTP/1.1\r\n', 'Host: x\r\n\r\n']
    assert 'WEB-001' in fired(detector, [pkt(flags='PA', payload=p, t=1000 + i) for i, p in enumerate(parts)])


def test_dns_tunneling(detector, pkt):
    rnd = random.Random(1)
    names = [''.join(rnd.choices('abcdefghijklmnop0123456789', k=45)) + '.example.com' for _ in range(9)]
    packets = [pkt(proto='UDP', dst='8.8.8.8', dport=53, flags='', payload=n, t=1000 + i) for i, n in enumerate(names)]
    assert fired(detector, packets).count('DNS-001') == 1
    detector.reset()
    normal = [pkt(proto='UDP', dst='8.8.8.8', dport=53, flags='', payload='www.example.com', t=2000 + i) for i in range(20)]
    assert fired(detector, normal) == []


def test_ioc_rule(detector, store, pkt):
    store.block('203.0.113.0/24', 'r')
    alerts = detector.process(pkt(src='203.0.113.5', flags='A'))[0]
    assert [(a.rule_id, a.block_target) for a in alerts] == [('IOC-001', '203.0.113.5')]
    alerts = detector.process(pkt(src='10.0.0.2', dst='203.0.113.6', flags='A'))[0]
    assert [(a.rule_id, a.block_target) for a in alerts] == [('IOC-001', '203.0.113.6')]


def test_trusted_source_not_inspected(detector, store, pkt):
    store.trust('10.0.0.5')
    assert fired(detector, [pkt(dport=port, t=1000 + i * 0.01) for i, port in enumerate(range(20, 60))]) == []


def test_disabled_rule_and_custom_threshold(detector, store, pkt):
    rules = {r['id']: r for r in store.rules()}
    rules['NET-001'].update(enabled=0)
    store.save_rule(rules['NET-001'])
    rules['NET-002'].update(threshold=5)
    store.save_rule(rules['NET-002'])
    detector.load()
    result = fired(detector, [pkt(dport=port, t=1000 + i * 0.01) for i, port in enumerate(range(20, 45))])
    assert 'NET-001' not in result and 'NET-002' in result


def test_cap_keeps_current_key_accurate(detector, pkt):
    for i in range(5001):
        detector.port_scan.touch(('1.1.1.%d' % (i % 250), str(i))).add(999, 1)
    result = fired(detector, [pkt(src='9.9.9.9', dport=port, t=1000 + i * 0.01) for i, port in enumerate(range(100, 140))])
    assert result.count('NET-001') == 1
    assert detector.port_scan.get(('9.9.9.9', '10.0.0.1')).unique() == 40
    assert len(detector.port_scan) == 5000


def test_garbage_collection_drops_old_state(detector, pkt):
    detector.process(pkt(src='10.0.0.77', t=1000))
    assert ('10.0.0.77', '10.0.0.1') in detector.port_scan
    detector.process(pkt(src='10.0.0.78', t=1000 + detector.horizon + 60))
    assert ('10.0.0.77', '10.0.0.1') not in detector.port_scan
