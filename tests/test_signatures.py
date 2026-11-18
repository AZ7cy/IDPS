"""Snort/Suricata rule parsing and matching."""
import io
import random
import tarfile

import pytest

from netsentinel.models import Packet, utc
from netsentinel.signatures import _View, compile_rules, load_paths, validate_home_net


def P(src='192.168.1.10', dst='203.0.113.5', proto='TCP', sport=40000, dport=80, flags='PA', data=b'', payload='',
      t=1000.0):
    return Packet(utc(), src, dst, proto, sport, dport, 60 + len(data), flags, payload, 'test', False, t, data=data)


def rules(text, home_net=''):
    rule_set, report = compile_rules(text, home_net)
    return rule_set, report


def sids(rule_set, packet, t=None):
    now = packet.capture_time if t is None else t
    return [s.sid for s in rule_set.match(packet, packet.src_ip, packet.dst_ip, now)]


def one(rule_text, packet, home_net=''):
    rule_set, report = rules(rule_text, home_net)
    assert report.loaded == 1, report.reasons
    return sids(rule_set, packet) == [rule_set.rules[0].sid]


HTTP = (b'GET /admin/login.php?user=%61dmin HTTP/1.1\r\nHost: Example.COM:8080\r\n'
        b'User-Agent: EvilBot/1.0\r\nCookie: session=abc\r\nAccept: */*\r\n\r\n')


# -- header ------------------------------------------------------------------------
def test_addresses_ports_variables_and_negation():
    rs, report = rules('''
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"in ssh"; sid:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443,8000:8100] (msg:"out web"; sid:2;)
alert tcp any any -> ![10.0.0.0/8,!10.1.1.1] !:1023 (msg:"neg"; sid:3;)
alert udp any any <> 198.51.100.7 53 (msg:"bidir"; sid:4;)
''')
    assert report.loaded == 4
    assert sids(rs, P(src='203.0.113.9', dst='192.168.1.10', dport=22)) == [1]
    assert sids(rs, P(src='192.168.1.10', dst='203.0.113.9', dport=8050)) == [2, 3]
    assert sids(rs, P(dst='10.2.2.2', dport=5000)) == []                    # inside 10/8
    assert sids(rs, P(dst='10.1.1.1', dport=5000)) == [3]                   # the exception inside the exclusion
    assert sids(rs, P(proto='UDP', src='198.51.100.7', dst='192.168.1.10', sport=53, dport=5353)) == [4]


def test_home_net_override_and_validation():
    rs, _ = rules('alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"x"; sid:1;)', home_net='[192.168.1.0/24]')
    assert sids(rs, P(src='10.9.9.9', dst='192.168.1.20')) == [1]
    assert sids(rs, P(src='192.168.1.9', dst='192.168.1.20')) == []
    assert validate_home_net('[192.168.1.0/24,fd00::/8]') is None
    assert validate_home_net('[192.168.1.0/24') and validate_home_net('not-an-ip')


def test_negated_spec_is_complement():
    rs, _ = rules('alert ip [10.0.0.0/8,192.168.0.0/16] any -> any any (msg:"a"; sid:1;)\n'
                  'alert ip ![10.0.0.0/8,192.168.0.0/16] any -> any any (msg:"b"; sid:2;)')
    rnd = random.Random(3)
    for _ in range(300):
        ip = f'{rnd.choice((10, 192, 172, 8))}.{rnd.choice((168, 1, 16))}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}'
        assert len(sids(rs, P(src=ip))) == 1


def test_unsupported_things_are_reported_not_loaded():
    _, report = rules('''
alert smtp any any -> any any (msg:"x"; sid:1;)
alert tcp any any -> any any (msg:"x"; byte_test:4,>,1000,0; sid:2;)
alert http any any -> any any (msg:"x"; http.request_body; content:"a"; sid:3;)
alert tcp $NOPE any -> any any (msg:"x"; sid:4;)
log tcp any any -> any any (msg:"x"; sid:5;)
alert tcp any any -> any any (msg:"no sid";)
alert tcp any any -> any any (msg:"ok"; content:"abc"; sid:7;)
alert tcp any any -> any any (msg:"dup"; content:"abc"; sid:7;)
var HOME_NET [10.0.0.0/8]
''')
    assert report.seen == 9 and report.loaded == 1 and report.skipped == 8
    reasons = set(report.reasons)
    assert {'unsupported protocol "smtp"', 'unsupported keyword "byte_test"', 'unsupported keyword "http.request_body"',
            'unknown variable $NOPE', 'unsupported action "log"', 'missing sid', 'duplicate sid',
            'not a rule (configuration line)'} == reasons
    assert all(line for _, line, _, _ in report.examples)


def test_comments_blank_lines_and_continuations():
    _, report = rules('# alert tcp any any -> any any (msg:"off"; sid:1;)\n\n'
                      'alert tcp any any -> any any (msg:"multi"; \\\n content:"abc"; sid:2;)\n')
    assert report.seen == 1 and report.loaded == 1


# -- content -----------------------------------------------------------------------
def test_content_hex_escapes_nocase_and_negation():
    rule = r'alert tcp any any -> any any (msg:"x"; content:"|41 42|c\;d\"e"; nocase; content:!"zzz"; sid:1;)'
    assert one(rule, P(data=b'..abC;D"E..'))
    assert not one(rule, P(data=b'..abc;d"e..zzz'))


def test_offset_depth_window():
    rule = 'alert tcp any any -> any any (msg:"x"; content:"KEY"; offset:2; depth:5; sid:1;)'
    assert one(rule, P(data=b'..KEY.....'))            # inside [2, 7)
    assert one(rule, P(data=b'....KEY...'))
    assert not one(rule, P(data=b'.....KEY..'))        # ends at 8, outside the window
    assert not one(rule, P(data=b'.KEY......'))


def test_distance_within_and_backtracking():
    rule = 'alert tcp any any -> any any (msg:"x"; content:"A"; content:"B"; distance:1; within:2; sid:1;)'
    assert one(rule, P(data=b'A.B'))
    assert one(rule, P(data=b'A..B'))
    assert not one(rule, P(data=b'AB'))                # distance 1 needs one byte between
    assert not one(rule, P(data=b'A...B'))             # outside within
    assert one(rule, P(data=b'A....A.B'))              # second A satisfies it (backtracking)


def test_startswith_endswith_isdataat():
    assert one('alert tcp any any -> any any (msg:"x"; content:"GET"; startswith; sid:1;)', P(data=b'GET /'))
    assert not one('alert tcp any any -> any any (msg:"x"; content:"GET"; startswith; sid:1;)', P(data=b' GET /'))
    assert one('alert tcp any any -> any any (msg:"x"; content:"end"; endswith; sid:1;)', P(data=b'the end'))
    assert not one('alert tcp any any -> any any (msg:"x"; content:"end"; endswith; sid:1;)', P(data=b'end.'))
    rule = 'alert tcp any any -> any any (msg:"x"; content:"id="; isdataat:!1,relative; sid:1;)'
    assert one(rule, P(data=b'user id='))
    assert not one(rule, P(data=b'user id=7'))


def test_pcre_flags_relative_and_buffer_flags():
    assert one('alert tcp any any -> any any (msg:"x"; pcre:"/^abc\\d+/i"; sid:1;)', P(data=b'ABC123'))
    rule = 'alert tcp any any -> any any (msg:"x"; content:"key="; pcre:"/^[0-9]{3}$/R"; sid:1;)'
    assert one(rule, P(data=b'key=123'))
    assert not one(rule, P(data=b'key=12a'))
    assert one('alert http any any -> any any (msg:"x"; pcre:"/login\\.php/U"; sid:1;)', P(data=HTTP))
    assert one('alert http any any -> any any (msg:"x"; pcre:!"/zzz/"; content:"GET"; sid:1;)', P(data=HTTP))
    _, report = rules('alert tcp any any -> any any (msg:"x"; pcre:"/a/P"; sid:1;)')
    assert report.reasons == {'unsupported pcre flag "P"': 1}


# -- buffers -----------------------------------------------------------------------
def test_suricata_http_sticky_buffers():
    rule = ('alert http $HOME_NET any -> any any (msg:"x"; flow:established,to_server; http.method; content:"GET"; '
            'http.uri; content:"/admin/login.php?user=admin"; http.host; content:"example.com"; bsize:11; '
            'http.user_agent; content:"evilbot"; nocase; http.cookie; content:"session="; startswith; '
            'http.header_names; content:"|0d 0a|Host|0d 0a|"; sid:1;)')
    assert one(rule, P(data=HTTP, flags='PA'))
    assert not one(rule, P(data=HTTP, flags='S'))                       # not established
    assert not one(rule, P(data=HTTP.replace(b'EvilBot', b'Mozilla'), flags='PA'))


def test_raw_and_normalized_uri():
    raw = 'alert http any any -> any any (msg:"x"; http.uri.raw; content:"%61dmin"; sid:1;)'
    norm = 'alert http any any -> any any (msg:"x"; http.uri; content:"%61dmin"; sid:1;)'
    assert one(raw, P(data=HTTP)) and not one(norm, P(data=HTTP))


def test_snort2_modifiers_and_snort3_sticky_buffers():
    snort2 = ('alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"x"; flow:to_server,established; '
              'content:"GET"; http_method; content:"/admin/"; http_uri; content:"EvilBot"; http_header; sid:1;)')
    assert one(snort2, P(data=HTTP))
    snort3 = ('alert http (msg:"x"; flow:to_server,established; http_uri; content:"/admin/",fast_pattern,nocase; '
              'content:"login",distance 0; http_header; content:"evilbot",nocase; service:http; sid:2;)')
    assert one(snort3, P(data=HTTP))
    # In Snort 2 syntax, http_uri moves the previous content, so "EvilBot" is not searched in the URI.
    wrong = ('alert tcp any any -> any any (msg:"x"; flow:established; content:"EvilBot"; http_uri; sid:3;)')
    assert not one(wrong, P(data=HTTP))


def test_dns_query_with_dotprefix_endswith_and_bsize():
    rule = ('alert dns $HOME_NET any -> any any (msg:"ET DNS Query to evil domain"; dns.query; dotprefix; '
            'content:".evil-example.com"; nocase; endswith; fast_pattern; classtype:trojan-activity; sid:1;)')
    q = dict(proto='UDP', dst='8.8.8.8', dport=53, flags='')
    assert one(rule, P(payload='a.b.Evil-Example.com', **q))
    assert one(rule, P(payload='evil-example.com', **q))                    # dotprefix makes the bare domain match
    assert not one(rule, P(payload='notevil-example.com', **q))
    size = 'alert dns any any -> any any (msg:"x"; dns.query; bsize:<6; sid:1;)'
    assert one(size, P(payload='a.io', **q)) and not one(size, P(payload='abcdef.io', **q))


def test_tls_sni_and_transforms():
    rule = ('alert tls $HOME_NET any -> any any (msg:"x"; tls.sni; to_lowercase; content:"bad.example"; endswith; '
            'sid:1;)')
    assert one(rule, P(dport=443, payload='Login.BAD.example'))
    md5 = ('alert tls any any -> any any (msg:"x"; tls.sni; to_md5; content:"|5d 41 40 2a bc 4b 2a 76 b9 71 9d 91 '
           '10 17 c5 92|"; sid:1;)')                                          # md5("hello")
    assert one(md5, P(dport=443, payload='hello'))


# -- other keywords ----------------------------------------------------------------
def test_flags_dsize_sameip():
    assert one('alert tcp any any -> any any (msg:"x"; flags:S,CE; sid:1;)', P(flags='SE'))
    assert not one('alert tcp any any -> any any (msg:"x"; flags:S; sid:1;)', P(flags='SA'))
    assert one('alert tcp any any -> any any (msg:"x"; flags:+S; sid:1;)', P(flags='SA'))
    assert one('alert tcp any any -> any any (msg:"x"; flags:!R; sid:1;)', P(flags='PA'))
    assert one('alert tcp any any -> any any (msg:"x"; dsize:3<>6; sid:1;)', P(data=b'abcd'))
    assert not one('alert tcp any any -> any any (msg:"x"; dsize:>10; sid:1;)', P(data=b'abcd'))
    assert one('alert ip any any -> any any (msg:"x"; sameip; sid:1;)', P(src='10.0.0.1', dst='10.0.0.1'))


def test_flowbits_across_packets():
    rs, report = rules('''
alert tcp any any -> any any (msg:"set"; content:"LOGIN"; flowbits:set,app.login; flowbits:noalert; sid:1;)
alert tcp any any -> any any (msg:"after login"; content:"DATA"; flowbits:isset,app.login; sid:2;)
''')
    assert report.loaded == 2
    first = P(sport=40000, dport=9000, data=b'LOGIN')
    reply = P(src='203.0.113.5', dst='192.168.1.10', sport=9000, dport=40000, data=b'DATA')
    other_flow = P(sport=40001, dport=9000, data=b'DATA')
    assert sids(rs, other_flow) == []
    assert sids(rs, first) == []                       # noalert
    assert sids(rs, reply) == [2]                      # same flow, opposite direction
    assert sids(rs, other_flow) == []


def test_threshold_limit_and_detection_filter():
    rs, _ = rules('alert tcp any any -> any any (msg:"x"; content:"a"; '
                  'threshold:type limit, track by_src, count 2, seconds 60; sid:1;)')
    hits = [sids(rs, P(data=b'a', t=1000 + i)) for i in range(5)]
    assert sum(1 for h in hits if h) == 2
    assert sids(rs, P(data=b'a', t=1100)) == [1]       # new window
    rs, _ = rules('alert tcp any any -> any any (msg:"x"; content:"a"; '
                  'detection_filter:track by_dst, count 3, seconds 60; sid:1;)')
    hits = [bool(sids(rs, P(data=b'a', t=1000 + i))) for i in range(5)]
    assert hits == [False, False, False, True, True]


def test_pass_rule_suppresses_alerts():
    rs, _ = rules('alert tcp any any -> any any (msg:"x"; content:"abc"; sid:1;)\n'
                  'pass tcp 192.168.1.10 any -> any any (msg:"allow"; content:"abc"; sid:2;)')
    assert sids(rs, P(data=b'abc')) == []
    assert sids(rs, P(src='192.168.1.11', data=b'abc')) == [1]


def test_severity_from_priority_and_classtype():
    rs, _ = rules('alert tcp any any -> any any (msg:"a"; classtype:trojan-activity; sid:1;)\n'
                  'alert tcp any any -> any any (msg:"b"; classtype:attempted-recon; sid:2;)\n'
                  'alert tcp any any -> any any (msg:"c"; classtype:trojan-activity; priority:3; sid:3;)\n'
                  'alert tcp any any -> any any (msg:"d"; sid:4;)')
    assert [s.severity for s in rs.rules] == ['HIGH', 'MEDIUM', 'LOW', 'LOW']


# -- prefilter ---------------------------------------------------------------------
def test_prefilter_matches_brute_force():
    """Property 2: the prefilter never hides a match."""
    rnd = random.Random(11)
    words = [b'alpha', b'beta', b'GET', b'evil', b'xyz', b'|', b'ab', b'pass=', b'cmd.exe', b'/etc/passwd']
    lines = []
    for sid in range(1, 160):
        parts = []
        for w in rnd.sample(words, rnd.randint(0, 3)):
            text = ''.join(f'|{b:02x}|' for b in w)
            mods = rnd.choice(['', ' nocase;', ' depth:20;', ' offset:1;', ' endswith;'])
            parts.append(f'content:"{text}";{mods}')
        if rnd.random() < 0.2:
            parts.append('pcre:"/[0-9]{3}/";')
        proto = rnd.choice(['tcp', 'udp', 'ip', 'http'])
        lines.append(f'alert {proto} any any -> any any (msg:"r{sid}"; {" ".join(parts)} sid:{sid};)')
    rs, report = rules('\n'.join(lines))
    assert report.loaded == len(lines), report.reasons
    for _ in range(400):
        payload = b' '.join(rnd.choice(words + [b'123', b'zz', b'GET /x HTTP/1.1\r\n']) for _ in range(rnd.randint(0, 6)))
        packet = P(proto=rnd.choice(['TCP', 'UDP']), dport=rnd.choice([80, 9999]), data=payload)
        view = _View(packet, packet.src_ip, packet.dst_ip)
        fast = {s.sid for s in rs.candidates(view) if rs.evaluate(s, view, packet.capture_time)}
        brute = {s.sid for s in rs.match_all(packet, packet.src_ip, packet.dst_ip, packet.capture_time)}
        assert fast == brute, payload


# -- loading -----------------------------------------------------------------------
def test_load_folder_and_archive(tmp_path):
    (tmp_path / 'rules').mkdir()
    (tmp_path / 'rules' / 'a.rules').write_text('alert tcp any any -> any any (msg:"a"; content:"aaa"; sid:1;)\n')
    (tmp_path / 'rules' / 'notes.txt').write_text('not rules')
    data = b'alert udp any any -> any any (msg:"b"; content:"bbb"; sid:2;)\n'
    archive = tmp_path / 'set.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        info = tarfile.TarInfo('rules/b.rules')
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    rs, report = load_paths([str(tmp_path / 'rules'), str(archive), str(tmp_path / 'missing.rules')])
    assert report.files == 2 and report.loaded == 2 and sorted(s.sid for s in rs.rules) == [1, 2]
    assert report.errors and 'not found' in report.errors[0]
    assert 'Loaded 2 of 2 rules' in report.summary()


# -- detector and IPS --------------------------------------------------------------
def test_detector_reports_sig001_alerts(detector, store):
    rs, _ = rules('alert http $HOME_NET any -> any any (msg:"ET TEST EvilBot UA"; http.user_agent; '
                  'content:"EvilBot"; classtype:trojan-activity; sid:9000001; rev:2;)')
    detector.set_signatures(rs)
    alerts = detector.process(P(data=HTTP))[0]
    sig = [a for a in alerts if a.rule_id == 'SIG-001']
    assert len(sig) == 1
    a = sig[0]
    assert a.title == a.description == 'ET TEST EvilBot UA' and a.severity == 'HIGH'
    assert a.evidence.startswith('[1:9000001:2] trojan-activity') and a.block_target == '192.168.1.10'
    assert not [a for a in detector.process(P(data=HTTP, t=1010))[0] if a.rule_id == 'SIG-001']   # cooldown
    rules_by_id = {r['id']: r for r in store.rules()}
    rules_by_id['SIG-001'].update(enabled=0)
    store.save_rule(rules_by_id['SIG-001'])
    detector.load()
    assert not [a for a in detector.process(P(data=HTTP, t=2000))[0] if a.rule_id == 'SIG-001']


def test_drop_rules_in_inline_mode(detector, store):
    rs, _ = rules('drop tcp any any -> any 4444 (msg:"block 4444"; content:"x"; sid:1;)')
    detector.set_signatures(rs)
    alerts, drop = detector.process(P(dport=4444, data=b'x', t=1000), inline=True, dry_run=True)
    assert not drop and alerts[0].action == 'WOULD_DROP'                 # Property 6: dry-run never drops
    alerts, drop = detector.process(P(dport=4444, data=b'x', t=1100), inline=True, dry_run=False)
    assert drop and alerts[0].action == 'DROP'
    assert store.block_count() == 0                                      # no blocklist entry
    alerts, drop = detector.process(P(dport=4444, data=b'x', t=1200))   # passive IDS never drops
    assert not drop and alerts[0].action == 'ALERT'
    store.trust('203.0.113.5')
    alerts, drop = detector.process(P(dport=4444, data=b'x', t=1300), inline=True, dry_run=False)
    assert not drop


@pytest.mark.parametrize('blob', [b'', b'\x00' * 50, bytes(range(256)), b'GET  HTTP/1.1\r\n', b'\x16\x03'])
def test_matching_never_raises_on_odd_payloads(blob):
    rs, _ = rules('alert http any any -> any any (msg:"x"; http.uri; content:"a"; sid:1;)\n'
                  'alert tcp any any -> any any (msg:"y"; pcre:"/(a|b)+c/"; sid:2;)')
    rs.match(P(data=blob), '192.168.1.10', '203.0.113.5', 1000.0)
    assert rs.errors == 0
