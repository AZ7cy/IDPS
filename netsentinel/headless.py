"""Command-line passive IDS (no GUI, no PyQt6)."""
from __future__ import annotations

import json
import queue
import random
import threading
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Generator, Optional, TextIO, Union

PacketStream = Generator[Optional['Packet'], None, None]

from . import selftest
from .addresses import PROTECTED
from .config import CAPTURE_QUEUE_MAX, DB_PATH, DEFAULT_BPF, FEED_INTERVAL_DEFAULT, PROTECTION_REFRESH_INTERVAL
from .detector import Detector
from .feeds import update_feeds, validate_feed_url
from .secure import restrict_to_owner
from .interfaces import auto_interface
from .models import Packet, redact_evidence, utc
from .notify import Notifier, NotificationSettings, alert_summary
from .privileges import capture_error_message, is_admin
from .recording import PcapRecorder
from .signatures import STARTER_RULES, level_off, load_paths, validate_home_net
from .simulation import generate_round
from .store import Store


class SourceError(RuntimeError):
    pass


def simulated_source(stop: threading.Event) -> PacketStream:
    rnd = random.Random()
    while not stop.is_set():
        yield from generate_round(rnd)
        stop.wait(0.12)
        yield None


def pcap_source(path: str, stop: threading.Event) -> PacketStream:
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise SourceError(f'scapy is required for PCAP replay: {exc}') from exc
    from .parsing import load_layers, scapy_packet
    if not Path(path).is_file():
        raise SourceError(f'PCAP file not found: {path}')
    load_layers()
    try:
        reader = PcapReader(path)
    except Exception as exc:            # not a PCAP/PCAPNG file, or unreadable
        raise SourceError(f'cannot read PCAP file {path}: {exc}') from exc
    with reader:
        for raw in reader:
            if stop.is_set():
                return
            rec = scapy_packet(raw, 'pcap')
            if rec:
                yield rec


class _LiveCapture:
    def __init__(self, iface: Optional[str], bpf: str, recorder: Optional[PcapRecorder] = None):
        self.iface, self.bpf = iface or None, bpf or DEFAULT_BPF
        self.recorder = recorder
        self.queue: queue.Queue = queue.Queue(maxsize=CAPTURE_QUEUE_MAX)
        self.dropped = 0
        self.sniffer = None

    def _on_packet(self, pkt):
        from .parsing import scapy_packet
        if self.recorder is not None:
            self.recorder.write(pkt)
        rec = scapy_packet(pkt, 'live')
        if rec:
            try:
                self.queue.put_nowait(rec)
            except queue.Full:
                self.dropped += 1

    def packets(self, stop: threading.Event) -> PacketStream:
        try:
            from scapy.all import AsyncSniffer
        except ImportError as exc:
            raise SourceError(f'scapy is required for live capture: {exc}') from exc
        try:
            self.sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=self._on_packet, store=False)
            self.sniffer.start()
        except Exception as exc:
            raise SourceError(capture_error_message(exc, gui=False) or f'Live capture failed: {exc}') from exc
        try:
            while not stop.is_set():
                try:
                    yield self.queue.get(timeout=0.2)
                except queue.Empty:
                    thread = self.sniffer.thread
                    if thread is not None and not thread.is_alive():
                        exc = getattr(self.sniffer, 'exception', None)
                        if exc is not None:
                            raise SourceError(capture_error_message(exc, gui=False)
                                              or f'Live capture stopped: {exc}')
                        raise SourceError('Capture stopped unexpectedly. Check privileges, Npcap/interface '
                                          'and BPF filter.')
                    yield None
        finally:
            try:
                if self.sniffer.running:
                    self.sniffer.stop(join=True)
            except Exception:
                pass


def alert_record(a, keep_payload: bool) -> dict:
    data = asdict(a)
    data['logged_at'] = utc()
    if not keep_payload:
        data['evidence'] = redact_evidence(a.evidence)
    return data


def run_headless(source: str = 'sim', iface: str = '', bpf: str = DEFAULT_BPF, pcap: str = '',
                 duration: Optional[float] = None, json_log: Optional[str] = None,
                 db: Union[str, Path, None] = None,
                 persist_packets: bool = False, notify: Optional[NotificationSettings] = None,
                 out: Optional[TextIO] = None, stop: Optional[threading.Event] = None,
                 save_pcap: Optional[str] = None, feeds: Optional[list[str]] = None,
                 feed_interval: float = FEED_INTERVAL_DEFAULT, rules: Optional[list[str]] = None,
                 home_net: str = '', self_test: bool = False, starter_rules: bool = False,
                 rule_level: str = 'balanced', accept_feed_change: bool = False) -> int:
    """Run passive detection until the source ends, `duration` elapses or Ctrl+C. Returns an exit code.

    With `self_test`, live capture runs the self-test, reports which rules fired and returns 0 only
    if all of them did.
    """
    import sys
    out = out or sys.stdout
    stop = stop or threading.Event()
    say_lock = threading.Lock()

    def say(text):
        with say_lock:
            print(text, file=out, flush=True)

    if self_test and source != 'live':
        say('error: --self-test only works with --source live')
        return 2

    if notify is not None:
        errors = notify.validate()
        if errors:
            for e in errors:
                say(f'error: {e}')
            return 2
    if save_pcap and source != 'live':
        say('error: --save-pcap only works with --source live')
        return 2
    feeds = list(feeds or [])
    feed_errors = [e for e in map(validate_feed_url, feeds) if e]
    if feed_errors or feed_interval <= 0:
        for e in feed_errors or ['--feed-interval must be greater than 0']:
            say(f'error: {e}')
        return 2
    home_error = validate_home_net(home_net)
    if home_error:
        say(f'error: {home_error}')
        return 2
    PROTECTED.refresh()             # also used for the default HOME_NET
    rule_set = None
    sources = ([str(STARTER_RULES)] if starter_rules and STARTER_RULES.is_file() else []) + list(rules or [])
    if sources:
        rule_set, report = load_paths(sources, home_net)
        off = rule_set.set_disabled(level_off(rule_set.rules, rule_level))
        say(report.summary() + (' (includes the built-in starter rules)' if starter_rules else ''))
        say(f'Rule level {rule_level}: {len(rule_set.rules) - off:,} rule(s) active. HOME_NET = {report.home_net}')
        for err in report.errors:
            say(f'warning: {err}')
    store = Store(db or DB_PATH)
    store.persist_packets = persist_packets
    refresher_stop = threading.Event()

    def refresh_loop():
        while not refresher_stop.wait(PROTECTION_REFRESH_INTERVAL):
            try:
                PROTECTED.refresh()
            except Exception:
                pass

    threading.Thread(target=refresh_loop, name='NetSentinel-Protection', daemon=True).start()

    def feed_loop():
        forced = list(feeds) if accept_feed_change else []      # only the first update skips the change guard
        while not refresher_stop.is_set():
            try:
                for result in update_feeds(store, feeds, should_stop=refresher_stop.is_set, force_urls=forced):
                    say(('warning: ' if result.error else '') + result.summary())
                forced = []
            except Exception as exc:
                if not refresher_stop.is_set():
                    say(f'warning: feed update failed: {exc}')
            if refresher_stop.wait(feed_interval * 3600):
                return

    if feeds:
        threading.Thread(target=feed_loop, name='NetSentinel-Feeds', daemon=True).start()
    detector = Detector(store)
    if rule_set is not None:
        detector.set_signatures(rule_set)
    notifier = Notifier(notify, on_error=lambda m: say(f'warning: {m}')) if notify else None
    log: Optional[TextIO] = None
    live: Optional[_LiveCapture] = None
    recorder: Optional[PcapRecorder] = None
    packets_seen, by_rule, code = 0, Counter(), 0
    stream: Optional[PacketStream] = None
    test_state: Optional[_SelfTestState] = None
    started = time.monotonic()
    try:
        if json_log:
            Path(json_log).parent.mkdir(parents=True, exist_ok=True)
            log = open(json_log, 'a', encoding='utf-8')
            restrict_to_owner(json_log)                     # alert history: owner-only
        if source == 'sim':
            stream = simulated_source(stop)
        elif source == 'pcap':
            stream = pcap_source(pcap, stop)
        elif source == 'live':
            if save_pcap:
                try:
                    recorder = PcapRecorder(save_pcap)
                except Exception as exc:
                    raise SourceError(f'cannot write PCAP file {save_pcap}: {exc}') from exc
            if not is_admin():
                say('warning: ' + (
                    'not running as Administrator. Live capture may fail, depending on how Npcap was '
                    'installed; if it does, run this from an Administrator terminal.'
                    if sys.platform == 'win32' else
                    'not running as root. Live capture needs root or the cap_net_raw capability: '
                    'use "sudo ./run.sh".'))
            if not iface:
                iface = auto_interface() or ''
                say(f'Capturing on {iface} (chosen automatically; use --iface to pick another).' if iface
                    else 'No connected interface found; using the capture library default.')
            live = _LiveCapture(iface, bpf, recorder)
            stream = live.packets(stop)
        else:
            raise SourceError(f'unknown source {source!r}')
        say(f'IDPS headless IDS started (source={source}); press Ctrl+C to stop.')
        if self_test:
            test_state = _start_self_test(detector, say, stop)
        last_housekeeping = 0.0
        for rec in stream:
            now = time.monotonic()
            if duration is not None and now - started >= duration:
                break
            if test_state is not None and test_state.finished(now):
                break
            if now - last_housekeeping >= 1:
                store.expire_blocks()
                last_housekeeping = now
            if rec is None:
                continue
            packets_seen += 1
            alerts, _ = detector.process(rec)
            if test_state is not None:
                test_state.alerts.extend(alerts)
            for a in alerts:
                by_rule[a.rule_id] += 1
                say(alert_summary(a))
                if log:
                    log.write(json.dumps(alert_record(a, store.keep_payload)) + '\n')
            if alerts:
                if log:
                    log.flush()
                if notifier:
                    notifier.submit(alerts)
    except KeyboardInterrupt:
        say('Stopping...')
    except SourceError as exc:
        say(f'error: {exc}')
        code = 1
    finally:
        stop.set()
        refresher_stop.set()
        if stream is not None:
            stream.close()
        if recorder is not None:
            recorder.close()
        if log:
            log.close()
        if notifier:
            notifier.close()
        store.close()
    elapsed = time.monotonic() - started
    say(f'Processed {packets_seen:,} packets in {elapsed:.1f}s; {sum(by_rule.values()):,} alerts.')
    for rule_id, count in sorted(by_rule.items()):
        say(f'  {rule_id}: {count}')
    if recorder is not None:
        say('  ' + recorder.summary())
    if live and live.dropped:
        say(f'  capture queue drops: {live.dropped:,}')
    if rule_set is not None and rule_set.pcre_timeouts:
        say(f'  signature pcre timeouts (possible ReDoS, treated as matches): {rule_set.pcre_timeouts:,}')
    if test_state is not None and code == 0:
        code = test_state.report(say)
    return code


class _SelfTestState:
    """Self-test progress shared between the sender thread and the capture loop."""
    GRACE = 4.0             # seconds to keep capturing after the last test packet

    def __init__(self):
        self.alerts: list = []
        self.sent: list[str] = []
        self.done_at: Optional[float] = None
        self.error = ''

    def finished(self, now: float) -> bool:
        if self.done_at is None:
            return False
        detected, _ = selftest.evaluate(self.sent, self.alerts)
        return len(detected) == len(self.sent) or now - self.done_at >= self.GRACE

    def report(self, say) -> int:
        if self.error:
            say(f'Self-test failed: {self.error}')
            return 1
        detected, missed = selftest.evaluate(self.sent, self.alerts)
        for rule_id in self.sent:
            say(f'  self-test {rule_id}: {"detected" if rule_id in detected else "MISSED"}')
        if missed or not self.sent:
            say(f'Self-test: {len(detected)} of {len(self.sent)} rules detected. {selftest.MISSED_HINT}')
            return 1
        say(f'Self-test passed: all {len(detected)} rules detected live traffic.')
        return 0


def _start_self_test(detector: Detector, say, stop: threading.Event) -> _SelfTestState:
    state = _SelfTestState()
    thresholds = {rid: r['threshold'] for rid, r in detector.rules.items() if r['enabled']}

    def run():
        try:
            if stop.wait(2.0):              # let the sniffer start first
                return
            state.sent = [r for r in selftest.run_self_test(thresholds, log=say, should_stop=stop.is_set)
                          if r in thresholds]
        except Exception as exc:
            state.error = str(exc)
        finally:
            state.done_at = time.monotonic()

    threading.Thread(target=run, name='NetSentinel-SelfTest', daemon=True).start()
    return state
