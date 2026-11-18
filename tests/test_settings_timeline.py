import json

from netsentinel.settings import DEFAULTS, Settings
from netsentinel.timeline import AlertTimeline


def test_settings_roundtrip(tmp_path):
    path = tmp_path / 'settings.json'
    s = Settings(path)
    assert s.get('dry_run') is True and not path.exists()
    assert s.set('bpf', 'tcp')
    assert s.set('ttl', 900)
    assert s.set('auto_block', True)
    assert path.exists()
    assert Settings(path).get('bpf') == 'tcp' and Settings(path).get('ttl') == 900


def test_settings_reject_invalid_values(tmp_path):
    s = Settings(tmp_path / 'settings.json')
    assert not s.set('ttl', 5)                    # below range
    assert not s.set('ttl', True)                 # bool is not int
    assert not s.set('queue_num', '1')            # wrong type
    assert not s.set('notify_min_severity', 'X')
    assert not s.set('unknown', 1)
    assert s.get('ttl') == DEFAULTS['ttl']


def test_dry_run_forced_on_load(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps({'dry_run': False, 'ips_enabled': True, 'ttl': 'bad', 'bpf': 'udp'}))
    s = Settings(path)
    assert s.get('dry_run') is True
    assert s.get('ttl') == DEFAULTS['ttl'] and s.get('bpf') == 'udp'
    assert 'ips_enabled' not in s.as_dict()


def test_corrupt_settings_file_uses_defaults(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text('{not json')
    s = Settings(path)
    assert s.as_dict() == DEFAULTS and s.last_error


def test_timeline_buckets():
    tl = AlertTimeline(bucket_seconds=60, buckets=3)
    now = 10_000 * 60 + 30            # 30 s into a minute
    tl.add('NET-001', now)
    tl.add('NET-001', now - 10)
    tl.add('WEB-001', now - 60)       # previous minute
    tl.add('DNS-001', now - 200)      # outside the 3-minute range
    rules, counts = tl.series(now)
    assert rules == ['NET-001', 'WEB-001']
    assert counts[-1] == {'NET-001': 2} and counts[-2] == {'WEB-001': 1} and not counts[0]
    rules, counts = tl.series(now + 600)
    assert rules == [] and not any(counts)


def test_timeline_packet_series():
    tl = AlertTimeline(bucket_seconds=60, buckets=3)
    now = 10_000 * 60 + 30
    tl.add_packets(100, now)
    tl.add_packets(50, now - 5)
    tl.add_packets(7, now - 60)
    tl.add_packets(9, now - 200)      # outside the range
    assert tl.packet_series(now) == [0, 7, 150]
    tl.clear()
    assert tl.packet_series(now) == [0, 0, 0]
