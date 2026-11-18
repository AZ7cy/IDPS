"""ReDoS protection, rule archive checks, download verification, feed guard and webhook transport."""
import hashlib
import io
import tarfile
import zipfile

import pytest

from netsentinel.models import Packet, utc


def tcp_packet(data: bytes, t=1000.0):
    return Packet(utc(), '198.51.100.7', '192.168.1.10', 'TCP', 50000, 4444, 60 + len(data), 'PA', '', 'test',
                  False, t, data=data)


# -- ReDoS ------------------------------------------------------------------------------
EVIL_PCRE = 'pcre:"/^(\\w+\\s?)*$/";'          # catastrophic backtracking on a long word ending in "!"
HOSTILE = b'a' * 3000 + b'!'


def _need_regex():
    import netsentinel.signatures as sg
    if not sg.PCRE_TIMEOUT_AVAILABLE:
        pytest.skip('the regex module is not installed')
    return sg


def test_slow_pcre_fails_closed_and_backs_off():
    sg = _need_regex()
    rules = (f'alert tcp any any -> any any (msg:"catastrophic"; content:"aaaa"; {EVIL_PCRE} sid:9300001;)\n'
             'alert tcp any any -> any any (msg:"normal"; content:"aaaa"; sid:9300002;)\n')
    rule_set, report = sg.compile_rules(rules)
    assert len(rule_set.rules) == 2, report.examples
    assert any(it.timed for g in rule_set.rules[0].groups for it in g.items if it.kind == 'pcre')
    hostile = tcp_packet(HOSTILE)
    src, dst = hostile.src_ip, hostile.dst_ip

    hits = rule_set.match(hostile, src, dst, 1000.0)
    assert sorted(s.sid for s in hits) == [9300001, 9300002]       # the slow rule still alerts
    assert [s.sid for s in rule_set.last_timeouts] == [9300001] and rule_set.pcre_timeouts == 1
    assert rule_set.rules[0].uid in rule_set.last_assumed

    import time
    started = time.perf_counter()
    for i in range(20):                                            # backed off: assumed, not re-run
        hits = rule_set.match(hostile, src, dst, 1001.0 + i)
        assert 9300001 in [s.sid for s in hits] and not rule_set.last_timeouts
    assert time.perf_counter() - started < 0.2
    assert rule_set.pcre_timeouts == 1

    rule_set.match(hostile, '198.51.100.99', dst, 1010.0)          # backoff is per source
    assert rule_set.pcre_timeouts == 2
    rule_set.match(hostile, src, dst, 1000.0 + sg.SIG_PCRE_BACKOFF + 1)   # expired: runs (and times out) again
    assert rule_set.pcre_timeouts == 3
    assert not rule_set.is_disabled(rule_set.rules[0])             # never switched off


def test_slow_negated_pcre_and_pass_rules_fail_closed():
    sg = _need_regex()
    rules = (f'pass tcp any any -> any any (msg:"allow"; content:"aaaa"; {EVIL_PCRE} sid:9300010;)\n'
             f'alert tcp any any -> any any (msg:"not-evil"; content:"aaaa"; pcre:!"/^(\\w+\\s?)*$/"; '
             'sid:9300011;)\n')
    rule_set, report = sg.compile_rules(rules)
    assert len(rule_set.rules) == 2, report.examples
    hostile = tcp_packet(HOSTILE)
    hits = rule_set.match(hostile, hostile.src_ip, hostile.dst_ip, 1000.0)
    # The pass rule's pcre timed out, so it must not suppress alerts; the negated pcre is assumed absent.
    assert [s.sid for s in hits] == [9300011]
    assert sorted(s.sid for s in rule_set.last_timeouts) == [9300010, 9300011]


def test_detector_reports_pcre_timeout_as_sig_002(detector):
    sg = _need_regex()
    rule_set, _ = sg.compile_rules(f'alert tcp any any -> any any (msg:"catastrophic"; content:"aaaa"; '
                                   f'{EVIL_PCRE} sid:9300001;)')
    detector.set_signatures(rule_set)
    alerts = detector.process(tcp_packet(HOSTILE, t=1000.0))[0]
    by_rule = {a.rule_id: a for a in alerts}
    assert by_rule['SIG-002'].severity == 'HIGH' and by_rule['SIG-002'].block_target is None
    assert '9300001' in by_rule['SIG-002'].evidence
    assert by_rule['SIG-001'].detail.startswith('pcre timed out (possible ReDoS); treated as match')
    assert 'timed out' in by_rule['SIG-001'].detail.split('\n', 1)[1]
    again = detector.process(tcp_packet(HOSTILE, t=1005.0))[0]     # SIG-002 is rate limited per source
    assert not [a for a in again if a.rule_id == 'SIG-002']


def test_missing_regex_module_is_reported_loudly(monkeypatch):
    import netsentinel.signatures as sg
    monkeypatch.setattr(sg, 'PCRE_TIMEOUT_AVAILABLE', False)
    _rs, report = sg.compile_rules('alert tcp any any -> any any (msg:"x"; content:"x"; sid:9300020;)')
    assert 'WARNING' in report.summary() and 'pip install regex' in report.summary()


def test_rule_count_does_not_depend_on_the_regex_module(monkeypatch):
    import netsentinel.signatures as sg
    from netsentinel.signatures import STARTER_RULES, load_paths
    with_module = len(load_paths([str(STARTER_RULES)])[0].rules)
    monkeypatch.setattr(sg, '_regex_engine', None)
    assert len(load_paths([str(STARTER_RULES)])[0].rules) == with_module


# -- rule archives ------------------------------------------------------------------------
def _tar(files: dict, extra=None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if extra:
            extra(tar)
    return buf.getvalue()


RULE = 'alert tcp any any -> any any (msg:"x"; content:"a"; sid:1;)\n'


def test_archive_limits(tmp_path, monkeypatch):
    import netsentinel.signatures as sg
    from netsentinel.signatures import ArchiveError, check_archive_members, load_paths
    with pytest.raises(ArchiveError, match='unsafe path'):
        check_archive_members([('../../evil.rules', 10)])
    with pytest.raises(ArchiveError, match='unsafe path'):
        check_archive_members([('C:/Windows/x.rules', 10)])
    monkeypatch.setattr(sg, 'SIG_ARCHIVE_MAX_MEMBERS', 2)
    with pytest.raises(ArchiveError, match='rule files'):
        check_archive_members([('a.rules', 1), ('b.rules', 1), ('c.rules', 1)])
    monkeypatch.setattr(sg, 'SIG_ARCHIVE_MAX_BYTES', 100)
    with pytest.raises(ArchiveError, match='MB of rules'):
        check_archive_members([('a.rules', 101)])
    bomb = tmp_path / 'bomb.zip'
    with zipfile.ZipFile(bomb, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('big.rules', '#' * 1000)
    rule_set, report = load_paths([str(bomb)])
    assert not rule_set.rules and 'MB of rules' in report.errors[0]


def test_download_is_verified_against_published_md5(tmp_path):
    from netsentinel.rule_updates import check_archive, download_et_open
    good = _tar({'rules/a.rules': RULE})
    md5 = hashlib.md5(good).hexdigest().encode() + b'\n'

    def fetch(url, should_stop=None, max_bytes=None):
        return md5 if url.endswith('.md5') else good
    result = download_et_open('https://example.test/r.tar.gz', tmp_path / 'r.tar.gz', fetch)
    assert result.verified and 'checksum verified' in result.summary()

    def tampered(url, should_stop=None, max_bytes=None):
        return md5 if url.endswith('.md5') else _tar({'rules/a.rules': RULE + RULE})
    with pytest.raises(ValueError, match='does not match the checksum'):
        download_et_open('https://example.test/r.tar.gz', tmp_path / 'other.tar.gz', tampered)
    assert not (tmp_path / 'other.tar.gz').exists()

    def link(tar):
        info = tarfile.TarInfo('rules/link.rules')
        info.type = tarfile.SYMTYPE
        info.linkname = '/etc/passwd'
        tar.addfile(info)
    with pytest.raises(ValueError, match='links'):
        check_archive(_tar({'rules/a.rules': RULE}, extra=link))


def test_et_downloads_require_the_published_md5(tmp_path):
    from netsentinel.rule_updates import ET_OPEN_URL, download_et_open, requires_md5
    good = _tar({'rules/a.rules': RULE})

    def no_md5(url, should_stop=None, max_bytes=None):
        if url.endswith('.md5'):
            raise OSError('404')
        return good
    assert requires_md5(ET_OPEN_URL) and not requires_md5('https://mirror.example.test/r.tar.gz')
    with pytest.raises(ValueError, match='publishes a checksum'):
        download_et_open(ET_OPEN_URL, tmp_path / 'et.tar.gz', no_md5)
    assert not (tmp_path / 'et.tar.gz').exists()
    assert not download_et_open('https://mirror.example.test/r.tar.gz', tmp_path / 'm.tar.gz', no_md5).verified


def _rules(n: int, start: int = 9400000) -> str:
    return ''.join(f'alert tcp any any -> any any (msg:"r{i}"; content:"x{i}"; sid:{start + i};)\n'
                   for i in range(n)) + '# alert tcp any any -> any any (msg:"commented"; sid:1;)\n'


def test_rule_update_refuses_a_sharp_drop_unless_forced(tmp_path):
    from netsentinel.rule_updates import RuleCountDropped, count_rules, download_et_open
    url, dest = 'https://mirror.example.test/r.tar.gz', tmp_path / 'r.tar.gz'
    big, small, fine = _tar({'rules/a.rules': _rules(400)}), _tar({'rules/a.rules': _rules(150)}), \
        _tar({'rules/a.rules': _rules(250)})
    assert count_rules(big) == 400                              # commented-out rules are not counted

    def serve(data):
        def fetch(u, should_stop=None, max_bytes=None):
            if u.endswith('.md5'):
                raise OSError('404')
            return data
        return fetch
    download_et_open(url, dest, serve(big))
    with pytest.raises(RuleCountDropped) as info:
        download_et_open(url, dest, serve(small))
    assert (info.value.old, info.value.new) == (400, 150) and dest.read_bytes() == big
    assert download_et_open(url, dest, serve(fine)).changed      # a 37% drop is allowed
    assert download_et_open(url, dest, serve(big)).changed
    assert download_et_open(url, dest, serve(small), force=True).changed and dest.read_bytes() == small


def test_gui_asks_before_accepting_a_smaller_rule_set(monkeypatch):
    pytest.importorskip('PyQt6')
    from types import SimpleNamespace
    from PyQt6.QtWidgets import QMessageBox
    import netsentinel.gui as gui
    calls, asked = [], []
    fake = SimpleNamespace(et_status=SimpleNamespace(setText=lambda t: None), log=lambda m: None,
                           et_worker=None, _et_force_next=False,
                           update_et_open=lambda **k: calls.append(k))
    monkeypatch.setattr(QMessageBox, 'question', lambda *a, **k: asked.append(a) or QMessageBox.StandardButton.Yes)
    gui.MainWindow._et_shrunk(fake, 'down from 400', automatic=True)
    assert not asked and not calls                              # automatic updates never accept on their own
    gui.MainWindow._et_shrunk(fake, 'down from 400', automatic=False)
    assert asked and calls == [{'force': True}]


# -- feeds --------------------------------------------------------------------------------
def test_feed_guard_refuses_mass_changes(store):
    from netsentinel.feeds import FeedResult, feed_change_error, update_feeds
    assert feed_change_error(set(), {'1.2.3.4/32'}) == ''               # first download
    assert feed_change_error({f'10.0.0.{i}/32' for i in range(10)}, set()) == ''   # small feed
    old = [f'198.51.100.{i}' for i in range(100)]
    url = 'https://feed.example/list.txt'
    first = update_feeds(store, [url], fetch=lambda u: '\n'.join(old))
    assert first[0].stored == 100 and not first[0].error
    nudged = update_feeds(store, [url], fetch=lambda u: '\n'.join(old[:90] + [f'203.0.113.{i}' for i in range(5)]))
    assert not nudged[0].error                                           # 15% change is normal churn
    poisoned = update_feeds(store, [url], fetch=lambda u: '\n'.join(f'203.0.{i // 250}.{i % 250}'
                                                                     for i in range(2000)))
    assert isinstance(poisoned[0], FeedResult) and 'safety limit' in poisoned[0].error and poisoned[0].guarded
    assert store.is_blocked('198.51.100.5') and not store.is_blocked('203.0.5.1')
    accepted = update_feeds(store, [url], fetch=lambda u: '\n'.join(f'203.0.{i // 250}.{i % 250}'
                                                                     for i in range(2000)), force_urls=[url])
    assert not accepted[0].error and accepted[0].stored == 2000          # the user accepted the change
    assert store.is_blocked('203.0.5.1') and not store.is_blocked('198.51.100.5')


def test_gui_offers_to_accept_a_refused_feed_change(monkeypatch):
    pytest.importorskip('PyQt6')
    from types import SimpleNamespace
    from PyQt6.QtWidgets import QMessageBox
    import netsentinel.gui as gui
    from netsentinel.feeds import FeedResult
    started = []
    fake = SimpleNamespace(log=lambda m: None, feed_worker=None, _feed_force_next=[],
                           update_feeds=lambda **k: started.append(k))
    refused = [FeedResult('https://feed.example/a', error='refused: ...', guarded=True)]
    monkeypatch.setattr(QMessageBox, 'question', lambda *a, **k: QMessageBox.StandardButton.No)
    assert not gui.MainWindow._ask_accept_feed_change(fake, refused) and not started
    monkeypatch.setattr(QMessageBox, 'question', lambda *a, **k: QMessageBox.StandardButton.Yes)
    assert gui.MainWindow._ask_accept_feed_change(fake, refused)
    assert started == [{'force_urls': ['https://feed.example/a']}]


# -- notifications --------------------------------------------------------------------------
@pytest.mark.parametrize('url, ok', [
    ('https://hooks.example.com/x', True), ('http://127.0.0.1:8080/hook', True),
    ('http://localhost/hook', True), ('http://192.168.1.5/hook', True),
    ('http://hooks.example.com/x', False), ('http://8.8.8.8/hook', False),
])
def test_plain_http_webhooks_only_on_local_networks(url, ok):
    from netsentinel.notify import NotificationSettings
    errors = NotificationSettings(webhook_url=url).validate()
    assert (errors == []) is ok, errors
