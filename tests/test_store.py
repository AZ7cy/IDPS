import sqlite3
import time

import pytest

from netsentinel.models import Alert
from netsentinel.store import Store, parse_blocklist_line

from conftest import wait_for


def test_schema_and_rule_seed(store):
    assert {r['id'] for r in store.rules()} == {'NET-001', 'NET-002', 'NET-003', 'NET-004', 'NET-005',
                                                'ICMP-001', 'WEB-001', 'DNS-001', 'IOC-001', 'ARP-001',
                                                'AUTH-001', 'NET-006', 'TLS-001', 'SIG-001', 'SIG-002',
                                                'WIFI-001', 'WIFI-002', 'WIFI-003'}


def test_block_normalizes_and_matches_cidr(store):
    assert store.block('203.0.113.9/24', 'r') == '203.0.113.0/24'
    assert store.is_blocked('203.0.113.200')
    assert store.is_blocked('::ffff:203.0.113.1')
    assert not store.is_blocked('203.0.114.1')
    assert store.block('not-an-ip', 'r') is None


def test_block_refuses_loopback_and_trusted(store):
    assert store.block('127.0.0.0/8', 'r') is None
    store.trust('192.0.2.0/28')
    assert store.block('192.0.2.0/24', 'r') is None
    assert store.overlaps_trusted('192.0.2.8')


def test_manual_block_not_downgraded(store):
    store.block('198.51.100.1', 'manual')
    store.block('198.51.100.1', 'auto', ttl=60, source='auto')
    row = store.block_rows()[0]
    assert row['source'] == 'manual' and row['expires'] is None


def test_block_many(store):
    store.block('198.51.100.50', 'manual')
    store.trust('192.0.2.0/24')
    added, skipped = store.block_many([('198.51.100.50', 'feed'), ('198.51.100.60', 'feed'),
                                       ('198.51.100.60', 'dup'), ('192.0.2.1', 'trusted'), ('bogus', 'x'),
                                       ('127.0.0.1', 'loopback')])
    assert (added, skipped) == (1, 5)
    assert store.is_blocked('198.51.100.60')


def test_unblock_and_expiry(store):
    store.block('198.51.100.70', 'r')
    version = store.blocks_version
    store.unblock('198.51.100.70')
    assert not store.is_blocked('198.51.100.70') and store.blocks_version > version
    store.block('198.51.100.80', 'r', ttl=1, source='auto')
    time.sleep(1.1)
    assert store.expire_blocks() == ['198.51.100.80/32']
    assert store.block_count() == 0


def test_trust_and_untrust_normalize(store):
    assert store.trust('::ffff:192.0.2.1') == '192.0.2.1/32'
    assert store.is_trusted('192.0.2.1')
    store.untrust('::ffff:192.0.2.1')
    assert store.trusted_rows() == []


def _alert(rule='WEB-001', severity='HIGH', src='10.0.0.4', dst='10.0.0.1', evidence="matched HTTP request marker 'x'"):
    return Alert(rule, 't', severity, 'd', src, dst, evidence, block_target=src)


def test_alert_write_filters_and_redaction(store):
    store.add_alert(_alert())
    store.add_alert(_alert('NET-002', 'MEDIUM', src='10.9.8.7', evidence='5 SYNs'))
    store.add_alert(_alert('ICMP-001', 'HIGH', src='172.16.0.1', evidence='n'))
    assert wait_for(lambda: len(store.alerts()) == 3)
    assert store.alert_generation > 0
    assert [a['rule_id'] for a in store.alerts(severity='HIGH')] == ['ICMP-001', 'WEB-001']
    assert [a['rule_id'] for a in store.alerts(rule_id='NET-002')] == ['NET-002']
    assert [a['rule_id'] for a in store.alerts(ip='9.8')] == ['NET-002']
    assert store.alerts(ip='%') == []                       # LIKE wildcards are escaped
    web = store.alerts(rule_id='WEB-001')[0]
    assert '<redacted>' in web['evidence']
    store.set_alert_status(web['id'], 'ACK')
    assert store.alerts(status='ACK')[0]['id'] == web['id']
    assert store.alert(web['id'])['status'] == 'ACK'
    assert store.alert(999_999) is None


def test_packets_only_persisted_when_enabled(store, pkt):
    store.add_packet(pkt())
    p = pkt(src='10.1.1.1')
    p.dropped = True
    store.add_packet(p)
    store.persist_packets = True
    store.add_packet(pkt(src='10.2.2.2'))
    assert wait_for(lambda: len(store.packets()) == 2)
    assert [r['src_ip'] for r in store.related_packets('10.2.2.2')] == ['10.2.2.2']


def test_reopen_keeps_blocks_and_migrates_rules(tmp_path):
    path = tmp_path / 'm.db'
    s = Store(path)
    s.block('203.0.113.0/24', 'r')
    s.close()
    db = sqlite3.connect(path)
    db.execute("UPDATE rules SET threshold=400, window=5 WHERE id='NET-002'")   # old shipped default
    db.execute("UPDATE rules SET threshold=33 WHERE id='NET-001'")              # analyst edit
    db.execute("UPDATE meta SET value='3' WHERE key='rule_version'")
    db.commit()
    db.close()
    s = Store(path)
    rules = {r['id']: r for r in s.rules()}
    assert rules['NET-002']['threshold'] == 80
    assert rules['NET-001']['threshold'] == 33
    assert s.is_blocked('203.0.113.5')
    s.close()


@pytest.mark.parametrize('line, expected', [
    ('', None),
    ('   # comment', None),
    ('203.0.113.7', ('203.0.113.7', '')),
    ('198.51.100.0/24 ; known scanner', ('198.51.100.0/24', 'known scanner')),
    ('2001:db8::/32, test range # note', ('2001:db8::/32', 'test range')),
    ('; reason only', ('', 'reason only')),
])
def test_parse_blocklist_line(line, expected):
    assert parse_blocklist_line(line) == expected
