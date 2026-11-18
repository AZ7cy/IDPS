"""Application entry point, command-line options and crash logging."""
from __future__ import annotations

import argparse
import sys
import threading
import time
import traceback
from typing import Optional

from .config import APP_NAME, CRASH_LOG, DEFAULT_BPF, FEED_INTERVAL_DEFAULT, SEVERITIES
from .models import utc


class CrashLogger:
    """Appends uncaught exceptions from any thread to the crash log."""

    def __init__(self, path=CRASH_LOG, echo_interval=30):
        self.path = path
        self.echo_interval = echo_interval
        self._last_echo = -float('inf')

    def write(self, exc_type, exc, tb, thread_name='main'):
        text = ''.join(traceback.format_exception(exc_type, exc, tb))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open('a', encoding='utf-8') as f:
                f.write(f'\n[{utc()}] [{thread_name}]\n{text}')
            from .secure import restrict_to_owner
            restrict_to_owner(self.path)
        except OSError:
            pass
        now = time.monotonic()
        if now - self._last_echo >= self.echo_interval:
            self._last_echo = now
            sys.__excepthook__(exc_type, exc, tb)

    def install(self):
        sys.excepthook = lambda t, e, tb: self.write(t, e, tb, 'main')
        threading.excepthook = lambda a: self.write(a.exc_type, a.exc_value, a.exc_traceback,
                                                    getattr(a.thread, 'name', 'thread'))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='NetSentinel_IDPS_v5.py', description=f'{APP_NAME}: desktop IDS/IPS.')
    from . import __version__
    p.add_argument('--version', action='version', version=f'{APP_NAME} {__version__}')
    p.add_argument('--db', help='database file (default: ~/.netsentinel/netsentinel.db)')
    p.add_argument('--list-interfaces', action='store_true', help='print capture interfaces and exit')
    h = p.add_argument_group('headless mode (passive IDS without the GUI)')
    h.add_argument('--headless', action='store_true', help='run without the GUI')
    h.add_argument('--source', choices=('sim', 'live', 'pcap'), default='sim', help='traffic source (default: sim)')
    h.add_argument('--iface', default='', help='capture interface for --source live (default: system default)')
    h.add_argument('--bpf', default=DEFAULT_BPF, help=f'BPF capture filter (default: "{DEFAULT_BPF}")')
    h.add_argument('--pcap', default='', help='PCAP/PCAPNG file for --source pcap')
    h.add_argument('--duration', type=float, help='stop after this many seconds')
    h.add_argument('--json-log', help='append alerts as JSON Lines to this file')
    h.add_argument('--persist-packets', action='store_true', help='store packet metadata in the database')
    h.add_argument('--save-pcap', metavar='FILE',
                   help='with --source live, also write captured packets to this PCAP file (full contents)')
    h.add_argument('--feed', action='append', default=[], metavar='URL',
                   help='download this https blocklist feed at startup and on --feed-interval (repeatable)')
    h.add_argument('--rules', action='append', default=[], metavar='PATH',
                   help='load Snort/Suricata rules from a .rules file, folder or .tar.gz/.zip archive (repeatable)')
    h.add_argument('--home-net', default='', metavar='CIDRS',
                   help='HOME_NET for the rules, e.g. "[192.168.1.0/24]" (default: private address ranges)')
    h.add_argument('--feed-interval', type=float, default=FEED_INTERVAL_DEFAULT, metavar='HOURS',
                   help=f'hours between feed updates (default: {FEED_INTERVAL_DEFAULT})')
    h.add_argument('--accept-feed-change', action='store_true',
                   help='on the first feed update, accept feeds that changed by more than half (refused by '
                        'default as a likely broken or compromised feed)')
    h.add_argument('--no-starter-rules', action='store_true',
                   help='do not load the built-in starter signature rules (loaded by default)')
    h.add_argument('--et-open', action='store_true',
                   help='download (or refresh) the free ET Open rule set and use it with --rules')
    h.add_argument('--et-open-url', default='', metavar='URL',
                   help='with --et-open, download this https .tar.gz rule set instead of the default '
                        '(implies --et-open)')
    h.add_argument('--accept-rule-drop', action='store_true',
                   help='with --et-open, accept a new rule set even if it has less than half the active rules '
                        'of the current one (refused by default as a likely broken download)')
    h.add_argument('--rule-level', choices=('balanced', 'essential', 'all'), default='balanced',
                   help='which loaded rules are on: balanced skips noisy informational rules (default)')
    h.add_argument('--self-test', action='store_true',
                   help='with --source live, send harmless test traffic to 192.0.2.0/24 (reserved, never routed), '
                        'report which rules caught it and exit')
    w = p.add_argument_group('Wi-Fi')
    w.add_argument('--wifi-scan', action='store_true',
                   help='list nearby Wi-Fi access points, check them with the WIFI-* rules and exit')
    n = p.add_argument_group('headless notifications')
    n.add_argument('--min-severity', choices=SEVERITIES, default='HIGH', help='minimum severity to notify')
    n.add_argument('--webhook', default='', help='POST alerts as JSON to this http(s) URL')
    n.add_argument('--syslog', default='', help='send alerts to syslog over UDP, host[:port]')
    return p


def print_interfaces() -> int:
    from .interfaces import list_interfaces
    items = list_interfaces()
    if not items:
        print('No interfaces found (is scapy or psutil installed?).')
        return 1
    for item in items:
        print(item.label)
    return 0


def main(argv: Optional[list[str]] = None):
    args = build_parser().parse_args(argv)
    if args.list_interfaces:
        sys.exit(print_interfaces())
    if args.wifi_scan:
        from .wifi import print_wifi_scan
        sys.exit(print_wifi_scan(args.db))
    if args.self_test and not args.headless:
        args.headless, args.source = True, 'live'      # --self-test alone means a live headless run
    if args.headless:
        from .headless import run_headless
        from .notify import NotificationSettings
        notify = None
        if args.webhook or args.syslog:
            notify = NotificationSettings(min_severity=args.min_severity, desktop=False,
                                          webhook_url=args.webhook, syslog_target=args.syslog)
        if args.source == 'pcap' and not args.pcap:
            print('error: --source pcap requires --pcap FILE')
            sys.exit(2)
        CrashLogger().install()
        if args.et_open or args.et_open_url:
            from .feeds import validate_feed_url
            from .rule_updates import ET_OPEN_PATH, ET_OPEN_URL, download_et_open
            url = args.et_open_url or ET_OPEN_URL
            error = validate_feed_url(url)
            if error:
                print(f'error: {error.replace("Feed URL", "Rule URL")}')
                sys.exit(2)
            try:
                print(download_et_open(url, force=args.accept_rule_drop).summary())
            except Exception as exc:
                if not ET_OPEN_PATH.is_file():
                    print(f'error: ET Open download failed: {exc}')
                    sys.exit(1)
                print(f'warning: ET Open download failed ({exc}); using the copy from the last download')
            if str(ET_OPEN_PATH) not in args.rules:
                args.rules.append(str(ET_OPEN_PATH))
        sys.exit(run_headless(args.source, args.iface, args.bpf, args.pcap, args.duration, args.json_log,
                              args.db, args.persist_packets, notify, save_pcap=args.save_pcap,
                              feeds=args.feed, feed_interval=args.feed_interval, rules=args.rules,
                              home_net=args.home_net, self_test=args.self_test,
                              starter_rules=not args.no_starter_rules, rule_level=args.rule_level,
                              accept_feed_change=args.accept_feed_change))
    run_gui(args.db)


def run_gui(db: Optional[str] = None):
    from PyQt6.QtWidgets import QApplication, QMessageBox

    from .splash import Splash, app_icon, set_windows_app_id

    set_windows_app_id()
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(app_icon())       # every window, the taskbar and the tray inherit it
    crash = CrashLogger()
    crash.install()
    splash = Splash()
    splash.show()
    splash.step('Loading the interface...', 0.15)
    try:
        from .gui import MainWindow     # the heaviest import (PyQt widgets, scapy, detector)
        from .store import Store
        splash.step('Opening the database...', 0.45)
        store = Store(db) if db else Store()
        splash.step('Loading detection rules and settings...', 0.7)
        window = MainWindow(store)
        splash.step('Starting NetSentinel...', 1.0)
    except Exception:
        info = sys.exc_info()
        crash.write(*info)
        splash.close()
        QMessageBox.critical(None, APP_NAME, f'NetSentinel failed to start.\n\n{info[1]}\n\nCrash log: {CRASH_LOG}')
        raise
    window.show()
    splash.finish_after_minimum(window)
    sys.exit(app.exec())
