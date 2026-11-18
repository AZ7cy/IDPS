import hashlib
import os
import time

import pytest

pytest.importorskip('PyQt6')
pytestmark = pytest.mark.gui
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')      # conftest.py already sets it

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from netsentinel.gui import MainWindow  # noqa: E402
from netsentinel.models import Alert  # noqa: E402
from netsentinel.settings import Settings  # noqa: E402
from netsentinel.store import Store  # noqa: E402


@pytest.fixture(scope='module')
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app, tmp_path, monkeypatch):
    for name in ('warning', 'information', 'critical'):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    w = MainWindow(Store(tmp_path / 'gui.db'), Settings(tmp_path / 'settings.json'))
    yield w
    w.close()


def pump(app, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)


def test_simulation_populates_views(app, window):
    window.source.setCurrentIndex(1)
    window.start_ids()
    pump(app, 3)
    window.tabs.setCurrentWidget(window.packet_tab)     # the packet table only refreshes while visible
    window.tick()
    assert window.packet_count > 0 and window.alert_count > 0
    assert window.packet_table.rowCount() > 0 and window.alert_table.rowCount() > 0
    rules, counts = window.timeline.series()
    assert rules and sum(counts[-1].values()) + sum(counts[-2].values()) > 0
    assert window.stop_ids() and window.worker is None


def test_alert_filters_and_detail(app, window):
    store = window.store
    store.add_alert(Alert('WEB-001', 't', 'HIGH', 'd', '10.0.0.4', '10.0.0.1', 'e', block_target='10.0.0.4'))
    store.add_alert(Alert('NET-002', 't', 'MEDIUM', 'd', '10.9.9.9', '10.0.0.1', 'e', block_target='10.9.9.9'))
    pump(app, 0.6)
    window.refresh_alerts()
    assert window.alert_table.rowCount() == 2
    window.filter_severity.setCurrentIndex(window.filter_severity.findData('MEDIUM'))
    assert window.alert_table.rowCount() == 1
    window.clear_alert_filters()
    window.filter_ip.setText('10.0.0.4')
    assert window.alert_table.rowCount() == 1
    window.alert_table.selectRow(0)
    detail = window.alert_detail.toPlainText()
    assert 'WEB-001' in detail and 'Related packets involving 10.0.0.4' in detail


def test_block_trust_and_rules(app, window):
    window.block_ip.setText('203.0.113.5')
    window.add_block()
    window.block_ip.setText('127.0.0.1')
    window.add_block()
    assert window.block_list.count() == 1
    window.trust_ip.setText('192.0.2.1')
    window.add_trusted()
    assert window.trusted_list.count() == 1
    window.save_rules()
    assert window.rule_table.rowCount() == 18


def test_settings_are_remembered_but_dry_run_is_not(app, tmp_path, monkeypatch):
    for name in ('warning', 'information', 'critical'):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    settings_path = tmp_path / 'settings.json'
    w = MainWindow(Store(tmp_path / 'a.db'), Settings(settings_path))
    w.bpf.setText('tcp port 80')
    w.ttl.setValue(1234)
    w.source.setCurrentIndex(2)
    w.dry_run.setChecked(False)
    w.ips_on.setChecked(True)
    w.close()
    w2 = MainWindow(Store(tmp_path / 'b.db'), Settings(settings_path))
    try:
        assert w2.bpf.text() == 'tcp port 80' and w2.ttl.value() == 1234 and w2.source.currentIndex() == 2
        assert w2.dry_run.isChecked() and not w2.ips_on.isChecked()
    finally:
        w2.close()


def test_notification_settings_validation(app, window):
    window.notify_webhook.setText('ftp://bad')
    assert not window.save_notifications()
    window.notify_webhook.setText('')
    window.notify_syslog.setText('127.0.0.1:5514')
    assert window.save_notifications()
    assert window.settings.get('notify_syslog') == '127.0.0.1:5514'


def test_pcap_and_feed_settings(app, window, tmp_path):
    assert window.bpf.text() == 'ip or ip6 or arp'
    window.save_pcap.setChecked(True)
    window.save_pcap_path.setText(str(tmp_path / 'cap.pcap'))
    assert window.settings.get('save_pcap') and window.settings.get('save_pcap_path').endswith('cap.pcap')
    window.save_pcap_path.setText('')
    assert window._recording_path() is None          # ticked without a path: refuse to start
    window.save_pcap.setChecked(False)
    assert window._recording_path() == ''

    window.feed_urls.setPlainText('http://insecure.example/list.txt')
    assert not window.save_feeds()
    window.feed_urls.setPlainText('https://a.example/list.txt\nhttps://a.example/list.txt\n')
    assert window.save_feeds() and window.settings.get('feed_urls') == ['https://a.example/list.txt']
    window.feed_auto.setChecked(True)
    window.feed_interval.setValue(6)
    assert window.settings.get('feed_auto') and window.settings.get('feed_interval_hours') == 6
    window.settings.set('feed_last_update', __import__('time').time())
    assert not window._feed_update_due()
    window.settings.set('feed_last_update', 0.0)
    assert window._feed_update_due()


def test_feed_update_worker_updates_blocklist(app, window, monkeypatch):
    import netsentinel.workers as workers
    from netsentinel.feeds import update_feeds
    monkeypatch.setattr(workers, 'update_feeds', lambda store, urls, should_stop, force_urls=(): update_feeds(
        store, urls, fetch=lambda url: '198.51.100.21\n', should_stop=should_stop, force_urls=force_urls))
    window.feed_urls.setPlainText('https://a.example/list.txt')
    assert window.update_feeds()
    deadline = time.monotonic() + 5
    while window.feed_worker is not None and time.monotonic() < deadline:
        pump(app, 0.05)
    assert window.store.is_blocked('198.51.100.21')
    assert 'Last update' in window.feed_status.text()


def test_signature_tab_loads_rules(app, window, tmp_path):
    rules = tmp_path / 'local.rules'
    rules.write_text('alert tcp any any -> any any (msg:"local test"; content:"abc"; sid:1000001;)\n'
                     'alert smtp any any -> any any (msg:"unsupported"; sid:1000002;)\n', encoding='utf-8')
    window.sig_builtin.setChecked(False)                 # count only this file's rules
    window._add_signature_paths([str(rules)])
    deadline = time.monotonic() + 10
    while window.sig_worker is not None and time.monotonic() < deadline:
        pump(app, 0.05)
    assert window.settings.get('sig_paths') == [str(rules)]
    assert window.detector.signatures is not None and len(window.detector.signatures.rules) == 1
    assert 'Loaded 1 of 2 rules' in window.sig_status.text()
    assert window.sig_reasons.rowCount() == 1 and window.sig_examples.rowCount() == 1
    window.sig_home_net.setText('[not valid')
    assert not window.load_signatures()
    window.sig_home_net.setText('')
    window.sig_list.selectAll()
    window.remove_signature_paths()
    assert window.detector.signatures is None and window.settings.get('sig_paths') == []


def test_interface_picker(app, window):
    pump(app, 2)                       # interfaces load on a background thread
    assert window.iface.count() >= 1 and window.iface.itemText(0) == 'default'
    assert window.selected_iface() == ''
    window.iface.setEditText('my-custom-if')
    assert window.selected_iface() == 'my-custom-if'


def test_notification_settings_window(app, window):
    assert 'Notifications' not in [window.tabs.tabText(i) for i in range(window.tabs.count())]
    assert window.tabs.cornerWidget() is window.settings_btn
    window.settings_btn.click()
    assert window.notify_dialog.isVisible()
    window.notify_webhook.setText('https://unsaved.example/hook')
    window.notify_dialog.close()
    window.show_notification_settings()             # unsaved edits are discarded on reopen
    assert window.notify_webhook.text() == window.settings.get('notify_webhook')
    window.notify_dialog.close()


def test_nothing_scans_at_startup(app, tmp_path, monkeypatch):
    """A saved "Monitor every N s" must not start scanning on its own (and must not crash startup)."""
    import json
    import netsentinel.wifi as wifi
    from netsentinel.wifi import ScanResult
    calls = []
    monkeypatch.setattr(wifi, 'scan', lambda wait=0: calls.append(1) or ScanResult([], 'fake adapter'))
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps({'wifi_monitor': True, 'source_index': 0}))
    w = MainWindow(Store(tmp_path / 'm.db'), Settings(path))
    try:
        pump(app, 0.5)
        assert w.worker is None and w.ips is None
        assert w.wifi_tab.monitor is None and not w.wifi_tab.monitor_box.isChecked() and not calls
        assert w.engine.text() == 'IDS stopped'
        w.wifi_tab.monitor_box.setChecked(True)          # the user can still turn it on
        pump(app, 0.5)
        assert w.wifi_tab.monitor is not None and calls
        assert w.engine.text() == 'IDS stopped'          # Wi-Fi messages don't overwrite the IDS status
    finally:
        w.close()


def test_generated_floor_plan_survey(app, window, tmp_path, monkeypatch):
    import netsentinel.wifi as wifi
    from netsentinel.wifi import AccessPoint, ScanResult, plan_scale, plan_size_px, PLAN_MARGIN_PX
    from PyQt6.QtGui import QImage
    from PyQt6.QtWidgets import QInputDialog
    ap = AccessPoint('Home', 'aa:00:00:00:00:01', -48, 90, 6, '2.4 GHz', 'WPA2-Personal')
    monkeypatch.setattr(wifi, 'scan', lambda wait=0: ScanResult([ap], 'fake adapter', 'Home', ap.bssid))
    monkeypatch.setattr(wifi, 'measure_latency', lambda: {'gateway_ms': None, 'internet_ms': 23.0, 'loss': 0.25,
                                                          'gateway': '192.168.1.1'})
    monkeypatch.setattr(QInputDialog, 'getText', staticmethod(lambda *a, **k: ('Kitchen', True)))
    tab = window.wifi_tab
    assert tab.new_floor_plan((10.0, 8.0))
    assert tab.map.image is not None and tab.current_tool() == 'rooms' and tab.map.draw_mode
    w_px, h_px = plan_size_px(tab.plan)
    s = plan_scale(tab.plan)
    frac = lambda mx, my: ((PLAN_MARGIN_PX + mx * s) / w_px, (PLAN_MARGIN_PX + my * s) / h_px)
    tab._room_dragged(frac(0, 0), frac(4, 3))
    assert tab.plan['rooms'] == [{'name': 'Kitchen', 'x': 0.0, 'y': 0.0, 'w': 4.0, 'h': 3.0}]
    assert window.settings.get('wifi_plan') == tab.plan
    tab.set_tool('doors')
    tab._map_clicked(*frac(2.0, 3.1))               # near the kitchen's bottom wall
    assert tab.plan['doors'] == [{'x': 2.0, 'y': 3.0, 'vertical': False, 'w': 0.9}]
    tab.set_tool('windows')
    tab._map_clicked(*frac(9.9, 4.0))               # near the outer right wall
    assert tab.plan['windows'] == [{'x': 10.0, 'y': 4.0, 'vertical': True, 'w': 1.2}]
    tab.set_tool('routers')
    monkeypatch.setattr(QInputDialog, 'getText', staticmethod(lambda *a, **k: ('Router', True)))
    tab._map_clicked(*frac(5.0, 4.0))
    assert tab.plan['routers'] == [{'name': 'Router', 'x': 5.0, 'y': 4.0}] and len(tab.map.routers) == 1
    tab.undo_room()                                 # undo removes the router first
    assert tab.plan['routers'] == [] and tab.plan['windows']
    tab.add_router(5.0, 4.0, 'Router')
    tab.set_tool('points')
    assert not tab.map.draw_mode
    tab.map.pending = frac(2, 1.5)
    tab.point_name.setText('Kitchen table')
    tab.record_point()
    pump(app, 0.8)
    assert tab.point_table.rowCount() == 1
    point = window.store.wifi_points()[0]
    assert point['internet_ms'] == 23.0 and point['gateway_ms'] is None and point['loss'] == 0.25
    assert [tab.point_table.item(0, c).text() for c in (5, 6, 7)] == ['no reply', '23', '25%']
    tab.map_metric.setCurrentIndex(tab.map_metric.findData('internet_ms'))
    assert tab.map.mode == 'ms' and tab.map.points[0][3] == 23.0 and not tab.map_network.isEnabled()
    tab.map_metric.setCurrentIndex(tab.map_metric.findData('signal'))
    assert tab.map.points[0][3] == -48
    out = tab.save_map_image(str(tmp_path / 'map.png'))
    saved = QImage(out)
    assert not saved.isNull() and (saved.width(), saved.height()) == (w_px, h_px)
    for _ in range(4):                              # router, window, door, then the room
        tab.undo_room()
    assert tab.plan['rooms'] == [] and not tab.plan.get('doors') and not tab.undo_room_btn.isEnabled()
    tab.remove_floor_plan()
    assert tab.map.image is None and window.settings.get('wifi_plan') == {}


def test_splash_and_icon(app, tmp_path, monkeypatch):
    import netsentinel.splash as splash
    from PyQt6.QtGui import QColor, QImage
    monkeypatch.setattr(splash, 'LOGO_PATH', tmp_path / 'missing.png')
    assert splash.logo_pixmap() is None and splash.app_icon().isNull()
    s = splash.Splash()                              # still works without a logo
    s.step('Loading...', 0.5)
    s.close()
    img = QImage(400, 300, QImage.Format.Format_ARGB32)
    img.fill(QColor('#f97316'))
    img.save(str(tmp_path / 'logo.png'))
    monkeypatch.setattr(splash, 'LOGO_PATH', tmp_path / 'logo.png')
    assert not splash.app_icon().isNull()
    s = splash.Splash()
    assert s.width() == splash.SPLASH_WIDTH
    assert s.logo.width() <= splash.SPLASH_WIDTH - 2 * splash.LOGO_PADDING     # the whole logo fits
    assert s.logo_height == s.logo.height() + 2 * splash.LOGO_PADDING
    s.step('Opening the database...', 0.45)
    s.close()


def test_rule_browser_and_et_open(app, window, tmp_path, monkeypatch):
    import io
    import tarfile
    import netsentinel.rule_updates as ru
    rules = (b'alert http any any -> any any (msg:"admin probe"; http.uri; content:"/admin.php"; '
             b'classtype:web-application-attack; sid:9100001;)\n'
             b'alert tcp any any -> any 4444 (msg:"backdoor"; content:"evil"; classtype:trojan-activity; '
             b'sid:9100002;)\n')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        info = tarfile.TarInfo('rules/emerging-test.rules')
        info.size = len(rules)
        tar.addfile(info, io.BytesIO(rules))
    dest = tmp_path / 'emerging.rules.tar.gz'
    real = ru.download_et_open
    md5 = hashlib.md5(buf.getvalue()).hexdigest().encode()

    def fetch(url, should_stop=None, **k):
        return md5 if url.endswith('.md5') else buf.getvalue()
    monkeypatch.setattr(ru, 'download_et_open', lambda url='', should_stop=None, force=False: real(
        dest=dest, fetch=fetch, should_stop=should_stop, force=force))
    window.sig_builtin.setChecked(False)                 # count only the downloaded rules
    assert window.update_et_open()
    deadline = time.monotonic() + 10
    while (window.et_worker is not None or window.sig_worker is not None) and time.monotonic() < deadline:
        pump(app, 0.05)
    assert window.settings.get('sig_paths') == [str(dest)] and window.settings.get('sig_et_last') > 0
    browser = window.rule_browser
    assert browser.model.rowCount() == 2 and 'last downloaded' in window.et_status.text()
    browser.search.setText('backdoor')
    assert browser.proxy.rowCount() == 1
    browser._shown(False)                                   # "Disable shown"
    assert window.settings.get('sig_disabled') == ['1:9100002']
    assert window.detector.signatures.set_disabled(window.settings.get('sig_disabled')) == 1
    browser.search.setText('')
    browser.category.setCurrentIndex(browser.category.findData('web-application-attack'))
    assert browser.proxy.rowCount() == 1 and '1 off' in browser.summary.text()
    # "Why did this match?" in the alert detail panel
    from netsentinel.models import Packet, utc
    data = b'GET /admin.php HTTP/1.1\r\nHost: shop.example\r\n\r\n'
    window.detector.process(Packet(utc(), '198.51.100.7', '192.168.1.10', 'TCP', 50000, 80, 90, 'PA',
                                   data.decode(), 'test', False, time.time(), data=data))
    window.store.flush()
    window.refresh_alerts()
    window.alert_table.selectRow(0)
    assert 'Why this signature matched' in window.alert_detail.toPlainText()
    window.tick()
    assert browser.model.hits['1:9100001'] == 1


def test_wifi_channels_and_history_views(app, window, monkeypatch):
    import netsentinel.wifi as wifi
    from netsentinel.wifi import AccessPoint, ScanResult
    readings = iter([-50, -75, -52])
    aps = lambda dbm: [AccessPoint('Home', 'h1', dbm, 80, 6, '2.4 GHz', 'WPA2-Personal'),
                       AccessPoint('Next door', 'n1', -60, 70, 6, '2.4 GHz', 'WPA2-Personal'),
                       AccessPoint('Home', 'h2', -55, 80, 44, '5 GHz', 'WPA2-Personal')]
    monkeypatch.setattr(wifi, 'scan', lambda wait=0: ScanResult(aps(next(readings)), 'fake', 'Home', 'h1'))
    tab = window.wifi_tab
    for _ in range(3):
        tab.scan_now()
        pump(app, 0.4)
    assert len(tab.history) == 3 and '1 drop(s)' in tab.history_summary.text()
    assert '2.4 GHz: your network "Home"' in tab.channel_advice.text()
    tab.wifi_views.setCurrentIndex(1)
    tab.channel_chart.grab()                                # paints without errors
    tab.wifi_views.setCurrentIndex(2)
    tab.history_chart.grab()
    tab.clear_history()
    assert len(tab.history) == 0


def test_starter_rules_and_rule_levels(app, window, tmp_path):
    from netsentinel.signatures import STARTER_RULES

    def settle():
        deadline = time.monotonic() + 10
        while (window.sig_worker is not None or window._sig_reload_pending) and time.monotonic() < deadline:
            pump(app, 0.05)

    settle()                                                 # starter rules load at startup by themselves
    starter = window.detector.signatures
    assert starter is not None and len(starter.rules) == 38 and window.rule_browser.model.rowCount() == 38
    noisy = tmp_path / 'noisy.rules'
    noisy.write_text('alert tcp any any -> any any (msg:"ET INFO something ordinary"; content:"hello"; '
                     'classtype:misc-activity; sid:2900001;)\n'
                     'alert tcp any any -> any any (msg:"ET MALWARE beacon"; content:"beacon"; '
                     'classtype:trojan-activity; priority:2; sid:2900002;)\n', encoding='utf-8')
    window._add_signature_paths([str(noisy)])
    settle()
    model = window.rule_browser.model
    assert len(window.detector.signatures.rules) == 40
    assert model.disabled == {'1:2900001'}                   # Balanced: the informational rule is off
    window.sig_level.setCurrentIndex(window.sig_level.findData('essential'))
    assert model.disabled == {'1:2900001', '1:2900002'}      # priority 2 is off too; starter rules stay on
    window.rule_browser.set_enabled(['1:2900002'], True)     # the user's choice beats the level
    assert '1:2900002' not in model.disabled and window.settings.get('sig_enabled') == ['1:2900002']
    window.sig_level.setCurrentIndex(window.sig_level.findData('all'))
    assert model.disabled == set()
    assert STARTER_RULES.name in window.sig_status.text() or 'Loaded 40 of 40' in window.sig_status.text()


def test_my_rules_tab(app, window):
    def settle():
        deadline = time.monotonic() + 10
        while (window.sig_worker is not None or window._sig_reload_pending) and time.monotonic() < deadline:
            pump(app, 0.05)

    settle()
    editor = window.my_rules
    assert window.sig_advanced.isHidden() and not window.sig_advanced_btn.isChecked()
    editor.template.setCurrentIndex(editor.template.findData('dns'))
    editor.value.setText('tiktok.com')
    editor.severity.setCurrentIndex(editor.severity.findData('HIGH'))
    assert editor.make_rule() and 'dns.query; content:"tiktok.com"' in editor.editor.toPlainText()
    assert editor.check() and editor.add()
    settle()
    assert editor.table.rowCount() == 1 and editor.path.is_file()
    loaded = {s.sid: s for s in window.detector.signatures.rules}
    assert 1_000_001 in loaded and len(loaded) == 39           # 38 starter rules + 1 of mine
    window.sig_level.setCurrentIndex(window.sig_level.findData('essential'))
    assert '1:1000001' not in window.rule_browser.model.disabled      # my rules ignore the level
    editor.editor.setPlainText('alert tcp any any -> any any (msg:"no sid"; content:"x";)')
    assert not editor.add() and 'needs a sid' in editor.result.text()
    editor.table.selectRow(0)
    assert editor.delete_selected() == 1
    settle()
    assert 1_000_001 not in {s.sid for s in window.detector.signatures.rules}
    window.sig_advanced_btn.setChecked(True)
    assert not window.sig_advanced.isHidden()


def test_automatic_signal_map(app, window, monkeypatch):
    import math
    import netsentinel.wifi as wifi
    from netsentinel.wifi import REFERENCE_DBM, AccessPoint, ScanResult
    monkeypatch.setattr(wifi, 'measure_latency', lambda: {'gateway_ms': 3.0, 'internet_ms': 20.0, 'loss': 0.0,
                                                          'gateway': ''})
    aps = {'a1': (2.0, 1.0), 'a2': (10.0, 2.0), 'a3': (6.0, 9.0)}
    spots = iter([(1, 3), (8, 2), (11, 5), (4, 7), (6, 4)])
    here = [(5.0, 5.0)]

    def fake_scan(wait=0):
        x, y = here[0]
        found = [AccessPoint(b, b, round(REFERENCE_DBM['2.4 GHz'] - 30 * math.log10(max(0.5, math.hypot(x - ax, y - ay)))),
                             80, 6, '2.4 GHz', 'WPA2-Personal') for b, (ax, ay) in aps.items()]
        return ScanResult(found, 'fake', 'a1', 'a1')

    monkeypatch.setattr(wifi, 'scan', fake_scan)
    tab = window.wifi_tab
    assert tab.auto_mode() and not tab.plan_row.isVisibleTo(tab)     # automatic map is the default
    tab.scan_now()
    pump(app, 0.5)
    assert tab.map.image is not None and len(tab.map.routers) == 3   # radar from the last scan
    assert 'direction is unknown' in tab.layout_note.text() and '~' in tab.map.routers[0][2]
    assert tab.ap_table.horizontalHeaderItem(3).text() == 'Est. distance (m)'
    assert float(tab.ap_table.item(0, 3).text()) > 0
    for _ in range(5):
        here[0] = next(spots)
        tab.point_name.setText(f'Spot {here[0]}')
        tab.record_point()
        pump(app, 0.5)
    assert tab.point_table.rowCount() == 5 and 'Layout solved from 5 spot(s)' in tab.layout_note.text()
    assert all(p[0] is not None for p in tab.map.points) and len(tab.map.routers) == 3
    assert all(pt['x'] is None for pt in window.store.wifi_points())  # positions are worked out, not stored
    tab.environment.setCurrentIndex(tab.environment.findData('open'))
    assert window.settings.get('wifi_env') == 'open'
    tab.map.grab()
    monkeypatch.setattr(QMessageBox, 'question', staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    assert tab.new_floor_plan((10.0, 8.0)) and not tab.auto_mode() and window.settings.get('wifi_layout') == 'plan'
    tab.set_layout_mode('auto')
    assert tab.auto_mode() and tab.map.clip is not None
