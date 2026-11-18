from netsentinel.addresses import PROTECTED

ATTACK = 'GET /?q=1%20union%20select%201 HTTP/1.1\r\nHost: x\r\n\r\n'


def test_dry_run_reports_would_drop(detector, store, pkt):
    store.block('203.0.113.0/24', 'r')
    alerts, drop = detector.process(pkt(src='203.0.113.9', flags='A'), inline=True, dry_run=True)
    assert not drop and alerts[0].action == 'WOULD_DROP'


def test_active_mode_drops_blocklisted(detector, store, pkt):
    store.block('203.0.113.0/24', 'r')
    p = pkt(src='203.0.113.9', flags='A')
    alerts, drop = detector.process(p, inline=True, dry_run=False)
    assert drop and alerts[0].action == 'DROP' and p.dropped


def test_passive_mode_never_drops(detector, store, pkt):
    store.block('203.0.113.0/24', 'r')
    alerts, drop = detector.process(pkt(src='203.0.113.9', flags='A'), inline=False, dry_run=False)
    assert not drop and alerts[0].action == 'ALERT'


def test_trusted_peer_prevents_drop(detector, store, pkt):
    store.block('203.0.113.0/24', 'r')
    store.trust('10.0.0.1')
    _, drop = detector.process(pkt(src='203.0.113.9', dst='10.0.0.1', flags='A'), inline=True, dry_run=False)
    assert not drop


def _web(pkt, t, dst='127.0.0.1'):
    return pkt(src='198.51.100.7', dst=dst, sport=51000, flags='PA', payload=ATTACK, t=t)


def test_auto_block_requires_two_hits_to_local_host(detector, store, pkt):
    PROTECTED.refresh()
    a1, d1 = detector.process(_web(pkt, 1000), inline=True, auto_block=True, dry_run=False, ttl=60)
    assert not d1 and a1[0].action == 'ALERT'
    a2, d2 = detector.process(_web(pkt, 1031), inline=True, auto_block=True, dry_run=False, ttl=60)
    assert d2 and a2[0].action == 'DROP' and a2[0].confidence == 'high'
    row = [r for r in store.block_rows() if r['ip'] == '198.51.100.7/32'][0]
    assert row['source'] == 'auto' and row['expires']


def test_auto_block_dry_run_and_remote_destination(detector, store, pkt):
    PROTECTED.refresh()
    detector.process(_web(pkt, 1000), inline=True, auto_block=True, dry_run=True)
    a, d = detector.process(_web(pkt, 1031), inline=True, auto_block=True, dry_run=True)
    assert not d and a[0].action == 'WOULD_DROP' and not store.is_blocked('198.51.100.7')
    detector.reset()
    detector.process(_web(pkt, 2000, dst='203.0.113.80'), inline=True, auto_block=True, dry_run=False)
    a, d = detector.process(_web(pkt, 2031, dst='203.0.113.80'), inline=True, auto_block=True, dry_run=False)
    assert not d and not store.is_blocked('198.51.100.7')   # destination is not this host


def test_auto_block_confirmations_expire(detector, store, pkt):
    PROTECTED.refresh()
    detector.process(_web(pkt, 1000), inline=True, auto_block=True, dry_run=False)
    _, d = detector.process(_web(pkt, 1100), inline=True, auto_block=True, dry_run=False)
    assert not d    # second hit came after the 60 s confirmation window
