"""Ping, channel advice, signal history, ET Open download, rule switches and match explanations."""
import io
import tarfile

import pytest

from netsentinel.models import Packet, utc
from netsentinel.rule_updates import (RULES_RETRY_SECONDS, RULES_UPDATE_SECONDS, check_archive, download_et_open,
                                      update_due)
from netsentinel.signatures import compile_rules, explain_match, rule_key
from netsentinel.wifi import (AccessPoint, ScanResult, SignalHistory, _ping_series, channel_advice, channel_load,
                              measure_latency, parse_ping_ms)


# -- ping ------------------------------------------------------------------------
@pytest.mark.parametrize('output, expected', [
    ('Reply from 1.1.1.1: bytes=32 time=23ms TTL=57', 23.0),
    ('1.1.1.1 からの応答: バイト数 =32 時間 =3ms TTL=57', 3.0),          # Japanese Windows
    ('Reply from 192.168.1.1: bytes=32 time<1ms TTL=64', 0.5),
    ('64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.4 ms', 12.4),       # Linux
    ('Request timed out.', None),
    ('Reply from 192.168.1.12: Destination host unreachable.', None),      # no TTL: not a real reply
])
def test_parse_ping(output, expected):
    assert parse_ping_ms(output) == expected


def test_ping_series_and_latency():
    replies = iter([10.0, None, 30.0, 20.0])
    assert _ping_series('h', 4, ping=lambda host: next(replies)) == (20.0, 0.25)
    assert _ping_series('h', 3, ping=lambda host: None) == (None, 1.0)
    fake = lambda host: {'192.168.1.1': None, '1.1.1.1': None, '8.8.8.8': 15.0}[host]
    result = measure_latency('192.168.1.1', count=2, ping=fake)     # first internet host blocked
    assert result == {'gateway_ms': None, 'internet_ms': 15.0, 'loss': 0.0, 'gateway': '192.168.1.1'}


# -- channels --------------------------------------------------------------------
def ap(ssid, bssid, ch, rssi, band='2.4 GHz'):
    return AccessPoint(ssid, bssid, rssi, 80, ch, band, 'WPA2-Personal')


def test_channel_load_counts_overlap_on_24ghz_only():
    aps = [ap('A', 'a', 6, -40), ap('B', 'b', 36, -40, '5 GHz')]
    assert channel_load(aps, 6, '2.4 GHz') == 1.0
    assert 0 < channel_load(aps, 8, '2.4 GHz') < 1.0          # 2 channels away still overlaps
    assert channel_load(aps, 11, '2.4 GHz') == 0.0
    assert channel_load(aps, 40, '5 GHz') == 0.0              # 5 GHz: only the exact channel counts


def test_channel_advice_suggests_a_quieter_channel():
    mine = ap('Home', 'h1', 6, -40)
    crowd = [ap(f'N{i}', f'n{i}', 6, -45) for i in range(4)] + [ap('Q', 'q', 11, -85)]
    advice = channel_advice(ScanResult([mine] + crowd, 'x', 'Home', 'h1'))
    assert any('channel 6' in line and 'Channel 1 is less crowded' in line for line in advice)
    calm = channel_advice(ScanResult([ap('Home', 'h1', 1, -40), ap('N', 'n', 11, -60)], 'x', 'Home', 'h1'))
    assert 'good choice' in calm[0]
    assert 'Connect to your network' in channel_advice(ScanResult([mine], 'x'))[-1]


# -- signal history --------------------------------------------------------------
def test_signal_history_drops_and_summary():
    h = SignalHistory(maxlen=10)
    home = lambda dbm: ScanResult([ap('Home', 'h1', 6, dbm)], 'x', 'Home', 'h1')
    for t, dbm in enumerate((-50, -55, -75, -52, -50)):
        h.add(home(dbm), t=1000 + t * 60)
    h.add(ScanResult([], 'x'), t=1300)                         # disconnected
    assert len(h) == 6 and h.drops() == 2
    text = h.summary()
    assert 'Now disconnected' in text and 'worst -75 dBm' in text and '2 drop(s)' in text
    h.clear()
    assert 'No readings' in h.summary()


# -- ET Open ---------------------------------------------------------------------
def archive(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_download_et_open_checks_and_replaces(tmp_path):
    good = archive({'rules/emerging-scan.rules': 'alert tcp any any -> any any (msg:"x"; sid:1;)\n'})
    dest = tmp_path / 'et.tar.gz'
    url = 'https://mirror.example.test/emerging.rules.tar.gz'      # no .md5 published there
    first = download_et_open(url, dest=dest, fetch=lambda url, should_stop: good)
    assert first.changed and first.rule_files == 1 and dest.read_bytes() == good
    assert not download_et_open(url, dest=dest, fetch=lambda url, should_stop: good).changed
    with pytest.raises(ValueError):
        download_et_open(url, dest=dest, fetch=lambda url, should_stop: b'<html>error</html>')
    with pytest.raises(ValueError):
        check_archive(archive({'README': 'no rules here'}))
    assert dest.read_bytes() == good                           # a failed download keeps the old file


def test_et_update_schedule():
    now = 10_000_000.0
    assert not update_due(False, 0, None, now)
    assert update_due(True, now - RULES_UPDATE_SECONDS, None, now)
    assert not update_due(True, now - 60, None, now)
    assert not update_due(True, 0, now - RULES_RETRY_SECONDS + 5, now)     # retry later after a failure


# -- signatures --------------------------------------------------------------------
RULES = ('alert http any any -> any any (msg:"admin probe"; http.uri; content:"/admin.php"; '
         'classtype:web-application-attack; sid:9100001; rev:2;)\n'
         'alert tcp any any -> any 4444 (msg:"other"; content:"evil"; sid:9100002;)\n')


def http_packet(uri):
    data = f'GET {uri} HTTP/1.1\r\nHost: shop.example\r\n\r\n'.encode()
    return Packet(utc(), '198.51.100.7', '192.168.1.10', 'TCP', 50000, 80, 120, 'PA', data.decode(), 'test',
                  False, 1000.0, data=data)


def test_rule_switches():
    rule_set, _ = compile_rules(RULES)
    p = http_packet('/admin.php?x=1')
    assert [rule_key(s) for s in rule_set.match(p, p.src_ip, p.dst_ip, 1000.0)] == ['1:9100001']
    assert rule_set.set_disabled(['1:9100001', '1:123']) == 1
    assert rule_set.match(p, p.src_ip, p.dst_ip, 1001.0) == []
    rule_set.set_disabled([])
    assert rule_set.match(p, p.src_ip, p.dst_ip, 1002.0)


def test_explain_match_hides_packet_bytes_unless_asked():
    rule_set, _ = compile_rules(RULES)
    sig = rule_set.rules[0]
    p = http_packet('/admin.php?user=secret')
    plain = explain_match(sig, p, p.src_ip, p.dst_ip)
    assert '[1:9100001:2] admin probe' in plain and 'http.uri' in plain
    assert 'content "/admin.php": found at byte 0' in plain and 'secret' not in plain
    assert 'Rule text: alert http' in plain
    detailed = explain_match(sig, p, p.src_ip, p.dst_ip, context=True)
    assert 'packet: /admin.php?user=secret' in detailed


def test_detector_records_detail_and_hits(store, detector):
    rule_set, _ = compile_rules(RULES)
    detector.set_signatures(rule_set)
    alerts, _ = detector.process(http_packet('/admin.php'))
    sig = [a for a in alerts if a.rule_id == 'SIG-001']
    assert sig and 'found at byte 0' in sig[0].detail
    assert detector.sig_hits['1:9100001'] == 1 and detector.sig_hits_version == 1
    store.flush()
    assert 'found at byte 0' in store.alerts(5, rule_id='SIG-001')[0]['detail']


# -- built-in starter rules and rule levels ------------------------------------------
def test_starter_rules_load_cleanly():
    from netsentinel.signatures import STARTER_RULES, load_paths
    rule_set, report = load_paths([str(STARTER_RULES)])
    assert len(rule_set.rules) == 38 and report.seen == 38          # nothing skipped
    assert len({s.sid for s in rule_set.rules}) == 38
    assert all(9200000 < s.sid < 9201000 for s in rule_set.rules)


def test_starter_log4shell_fires_and_normal_traffic_does_not():
    from netsentinel.signatures import STARTER_RULES, load_paths
    rule_set, _ = load_paths([str(STARTER_RULES)])
    attack = http_packet('/search?q=${jndi:ldap://203.0.113.9/a}')
    assert 9200001 in {s.sid for s in rule_set.match(attack, attack.src_ip, attack.dst_ip, 1000.0)}
    for uri in ('/index.html', '/search?q=password+manager', '/docs/sql-tutorial'):
        p = http_packet(uri)
        assert rule_set.match(p, p.src_ip, p.dst_ip, 5000.0) == []


def test_rule_levels():
    from netsentinel.signatures import STARTER_RULES, effective_off, level_off, load_paths
    rules, _ = compile_rules(
        'alert tcp any any -> any any (msg:"ET INFO dyn dns"; content:"a"; classtype:misc-activity; sid:1;)\n'
        'alert tcp any any -> any any (msg:"ET DYN_DNS lookup"; content:"b"; classtype:bad-unknown; sid:2;)\n'
        'alert tcp any any -> any any (msg:"ET MALWARE x"; content:"c"; classtype:trojan-activity; priority:2; sid:3;)\n'
        'alert tcp any any -> any any (msg:"ET EXPLOIT y"; content:"d"; classtype:attempted-admin; priority:1; sid:4;)\n')
    sigs = rules.rules
    assert level_off(sigs, 'all') == set()
    assert level_off(sigs, 'balanced') == {'1:1', '1:2'}
    assert level_off(sigs, 'essential') == {'1:1', '1:2', '1:3'}
    assert effective_off(sigs, 'essential', user_off={'1:4'}, user_on={'1:3'}) == {'1:1', '1:2', '1:4'}
    starter, _ = load_paths([str(STARTER_RULES)])
    assert level_off(starter.rules, 'essential') == set()           # built-in rules are always on


# -- My rules ------------------------------------------------------------------------
def test_every_template_builds_a_loadable_rule(tmp_path):
    from netsentinel.local_rules import TEMPLATES, add_rule, build_rule, check_rule, next_sid, read_rules
    path = tmp_path / 'local.rules'
    values = {'dns': 'https://www.Example.com/page', 'tls': 'bet365', 'uri': '/admin', 'ua': 'curl/',
              'word': 'say "hi"; x|y\\z', 'ip': '203.0.113.66', 'port': '6667, 6697', 'block': '/wp-login.php',
              'custom': ''}
    for t in TEMPLATES:
        text = build_rule(t.key, values[t.key], 'HIGH', sid=next_sid(path))
        assert check_rule(text) == '', (t.key, text)
        add_rule(text, path)
    assert len(read_rules(path)) == len(TEMPLATES) and next_sid(path) == 1_000_001 + len(TEMPLATES)
    dns = read_rules(path)[0]
    assert 'content:"www.example.com"' in dns and 'priority:1' in dns
    assert 'content:"say |22|hi|22||3B| x|7C|y|5C|z"' in read_rules(path)[4]     # special characters escaped
    assert 'alert ip 203.0.113.66 any <> any any' in read_rules(path)[5]


def test_my_rule_matches_traffic(tmp_path):
    from netsentinel.local_rules import add_rule, build_rule
    from netsentinel.signatures import load_paths
    path = tmp_path / 'local.rules'
    add_rule(build_rule('word', 'PROJECT-ORION', 'HIGH', sid=1_000_001), path)
    rule_set, _ = load_paths([str(path)])
    data = b'status of project-orion attached'
    p = Packet(utc(), '192.168.1.10', '198.51.100.9', 'TCP', 50000, 8080, 90, 'PA', '', 'test', False, 1.0,
               data=data)
    hits = rule_set.match(p, p.src_ip, p.dst_ip, 1.0)
    assert [s.sid for s in hits] == [1_000_001] and hits[0].severity == 'HIGH'


def test_bad_rules_are_explained(tmp_path):
    from netsentinel.local_rules import RuleInputError, add_rule, build_rule, check_rule, remove_rules, read_rules
    assert 'needs a sid' in check_rule('alert tcp any any -> any any (msg:"x"; content:"a";)')
    assert 'from 1000001' in check_rule('alert tcp any any -> any any (msg:"x"; content:"a"; sid:5;)')
    assert 'unsupported protocol "smtp"' in check_rule('alert smtp any any -> any any (msg:"x"; sid:1000500;)')
    assert 'empty' in check_rule('   ')
    for key, value in (('ip', 'not-an-ip'), ('port', '70000'), ('dns', ''), ('tls', '')):
        with pytest.raises(RuleInputError):
            build_rule(key, value)
    path = tmp_path / 'local.rules'
    rule = build_rule('tls', 'example', sid=1_000_007)
    add_rule(rule, path)
    with pytest.raises(RuleInputError, match='already have a rule with sid 1000007'):
        add_rule(rule, path)
    assert remove_rules([1_000_007], path) == 1 and read_rules(path) == []


# -- distance formula and automatic layout --------------------------------------------
def test_distance_formula_and_calibration():
    import math
    from netsentinel.wifi import REFERENCE_DBM, calibration_offset, distance_label, estimate_distance
    assert estimate_distance(REFERENCE_DBM['2.4 GHz'], '2.4 GHz', 3.0) == pytest.approx(1.0)
    assert estimate_distance(-68, '2.4 GHz', 3.0) == pytest.approx(10.0)          # 30 dB more = 10x further
    assert estimate_distance(-60, '2.4 GHz', 2.0) > estimate_distance(-60, '2.4 GHz', 3.5)   # walls: closer
    assert estimate_distance(-60, '5 GHz', 3.0) < estimate_distance(-60, '2.4 GHz', 3.0)
    assert estimate_distance(0, '2.4 GHz') == 0.5 and estimate_distance(-200, '2.4 GHz') == 80.0
    offset = calibration_offset(-31, '2.4 GHz')                 # this router is stronger than the default
    assert offset == 7.0 and estimate_distance(-31, '2.4 GHz', 3.0, offset) == pytest.approx(1.0)
    assert distance_label(4.26) == '~4.3 m' and distance_label(23.4) == '~23 m'
    assert math.isclose(estimate_distance(-50, '2.4 GHz', 3.0), 10 ** (12 / 30))


def _simulated_survey(noise_db, seed=1):
    import math
    import random
    from netsentinel.wifi import REFERENCE_DBM
    aps = {'a1': (2.0, 1.0, '2.4 GHz'), 'a2': (10.0, 2.0, '5 GHz'), 'a3': (6.0, 9.0, '2.4 GHz'),
           'a4': (-4.0, 6.0, '5 GHz')}
    spots = [(1, 3), (4, 2), (8, 2), (11, 5), (8, 7), (4, 7), (1, 6)]
    rnd = random.Random(seed)
    points = []
    for k, (x, y) in enumerate(spots):
        rows = []
        for b, (ax, ay, band) in aps.items():
            d = max(0.5, math.hypot(x - ax, y - ay))
            rows.append({'ssid': b, 'bssid': b, 'band': band,
                         'rssi': round(REFERENCE_DBM[band] - 30 * math.log10(d) + rnd.gauss(0, noise_db))})
        points.append((k, rows))
    return spots, points


def test_auto_layout_recovers_the_shape():
    import math
    from netsentinel.wifi import auto_layout
    for noise, allowed in ((0.0, 0.5), (3.0, 2.0)):
        spots, points = _simulated_survey(noise)
        layout = auto_layout(points, 3.0)
        assert layout.mode == 'solved' and layout.point_ids == list(range(len(spots)))
        # Compare spacing between spots (the map may be rotated or mirrored, so not raw coordinates).
        errors = [abs(math.dist(spots[i], spots[j]) - math.dist(layout.points[i], layout.points[j]))
                  for i in range(len(spots)) for j in range(i + 1, len(spots))]
        assert sum(errors) / len(errors) < allowed, (noise, sum(errors) / len(errors))
    strongest = max(layout.aps, key=lambda a: a[4])
    centre_y = sum(p[1] for p in layout.points) / len(layout.points)
    assert strongest[3] < centre_y                              # turned so the strongest is at the top


def test_auto_layout_radar_and_empty():
    import math
    from netsentinel.wifi import auto_layout, estimate_distance
    _spots, points = _simulated_survey(0.0)
    radar = auto_layout(points[:1], 3.0)
    from netsentinel.wifi import radar_radius
    assert radar.mode == 'radar' and radar.points == [(0.0, 0.0)] and len(radar.aps) == 4
    assert radar.distances == sorted(radar.distances)                  # nearest first
    for (_name, b, x, y, dbm), d in zip(radar.aps, radar.distances):
        band = '5 GHz' if b in ('a2', 'a4') else '2.4 GHz'
        assert d == pytest.approx(estimate_distance(dbm, band, 3.0))
        assert math.hypot(x, y) == pytest.approx(radar_radius(d))     # drawn on the compressed scale
    two_radios = [(1, [{'ssid': 'Home', 'bssid': 'h1', 'rssi': -40, 'band': '2.4 GHz'},
                       {'ssid': 'Home', 'bssid': 'h2', 'rssi': -48, 'band': '5 GHz'},
                       {'ssid': 'Other', 'bssid': 'o1', 'rssi': -70, 'band': '2.4 GHz'}])]
    grouped = auto_layout(two_radios, 3.0)
    assert [a[0] for a in grouped.aps] == ['Home (2 radios)', 'Other']
    assert auto_layout([], 3.0) is None and auto_layout([(1, [])], 3.0) is None


# -- Windows inline IPS filter ------------------------------------------------------
def test_old_windivert_filter_is_upgraded(tmp_path):
    import json
    from netsentinel.settings import Settings
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps({'ips_filter': 'ip or ip6'}))
    assert Settings(path).get('ips_filter') == 'ip or ipv6'
    path.write_text(json.dumps({'ips_filter': 'tcp.DstPort == 80'}))
    assert Settings(path).get('ips_filter') == 'tcp.DstPort == 80'      # custom filters are kept
    assert Settings(tmp_path / 'new.json').get('ips_filter') == 'ip or ipv6'


def test_windivert_filter_messages():
    from types import SimpleNamespace
    from netsentinel.workers import windivert_filter_error, windivert_open_error
    fake = SimpleNamespace(WinDivert=SimpleNamespace(
        check_filter=lambda f: (f == 'ip or ipv6', 6, 'Filter expression contains a bad token')))
    assert windivert_filter_error('ip or ipv6', fake) == ''
    message = windivert_filter_error('ip or ip6', fake)
    assert 'not valid WinDivert syntax' in message and '"ipv6" instead of "ip6"' in message
    assert windivert_filter_error('x', SimpleNamespace()) == ''          # no checker: let open() decide
    denied = OSError('denied')
    denied.winerror = 5
    assert 'Restart as Administrator' in windivert_open_error(denied)
    bad = OSError('bad')
    bad.winerror = 87
    assert 'rejected the filter' in windivert_open_error(bad)
