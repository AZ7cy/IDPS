"""Background workers: capture sources, inline IPS engines and blocklist import."""
from __future__ import annotations

import queue
import random
import select
import threading
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

from .addresses import normalize_network
from .config import (CAPTURE_QUEUE_MAX, DEFAULT_BPF, LEGACY_WINDIVERT_FILTER, UI_BATCH_ALERTS, UI_BATCH_PACKETS,
                     UI_EMIT_INTERVAL, WINDIVERT_DEFAULT_FILTER)
from .detector import Detector
from .feeds import update_feeds
from .interfaces import auto_interface
from .models import Packet
from .parsing import load_layers, parse_raw, scapy_packet
from .privileges import capture_error_message
from .recording import PcapRecorder
from .signatures import load_paths
from .simulation import generate_round
from .store import parse_blocklist_line


class Worker(QThread):
    """Base worker: bounded capture queue, detection, and batched UI signals."""
    packet_batch = pyqtSignal(object, arguments=['packets'])
    alert_batch = pyqtSignal(object, arguments=['alerts'])
    status = pyqtSignal(str, arguments=['message'])
    error = pyqtSignal(str, arguments=['message'])

    def __init__(self, detector: Detector, auto_block=False, ttl=300, dry_run=True):
        super().__init__()
        self.detector = detector
        self.auto_block = auto_block
        self.ttl = ttl
        self.dry_run = dry_run
        self.stop_event = threading.Event()
        self.capture_queue: queue.Queue = queue.Queue(maxsize=CAPTURE_QUEUE_MAX)
        self.dropped_capture = 0
        self._ui_packets: list = []
        self._ui_alerts: list = []
        self.last_ui_emit = time.monotonic()
        self._last_error: dict = {}

    @property
    def active_blocking(self) -> bool:
        return bool(self.auto_block and not self.dry_run)

    def stop(self):
        self.stop_event.set()

    def enqueue(self, rec: Packet):
        try:
            self.capture_queue.put_nowait(rec)
        except queue.Full:
            self.dropped_capture += 1

    def emit_error(self, message: str, interval=10):
        now = time.monotonic()
        if now - self._last_error.get(message, -float('inf')) >= interval:
            self._last_error[message] = now
            self.error.emit(message)

    def drain(self, limit=500, allow_stopping=False) -> int:
        """Process up to `limit` queued packets. Returns how many were processed."""
        done = 0
        while done < limit and (allow_stopping or not self.stop_event.is_set()):
            try:
                rec = self.capture_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self.process_one(rec, inline=False)
            except Exception as exc:
                self.emit_error(f'Packet processing failed (fail-open): {exc}')
            done += 1
        self.flush_ui()
        return done

    def drain_all(self, batch=5000):
        while self.drain(batch, allow_stopping=True):
            pass

    def process_one(self, rec: Packet, inline=False) -> bool:
        self._ui_packets.append(rec)
        alerts, drop = self.detector.process(rec, inline, self.auto_block, self.ttl, self.dry_run)
        self._ui_alerts.extend(alerts)
        if (len(self._ui_packets) >= UI_BATCH_PACKETS or len(self._ui_alerts) >= UI_BATCH_ALERTS
                or time.monotonic() - self.last_ui_emit >= UI_EMIT_INTERVAL):
            self.flush_ui()
        return drop

    def flush_ui(self):
        if self._ui_packets:
            self.packet_batch.emit(self._ui_packets)
            self._ui_packets = []
        if self._ui_alerts:
            self.alert_batch.emit(self._ui_alerts)
            self._ui_alerts = []
        self.last_ui_emit = time.monotonic()

    def flush_ui_if_due(self):
        if time.monotonic() - self.last_ui_emit >= UI_EMIT_INTERVAL:
            self.flush_ui()


# ----------------------------------------------------------------------------
# Passive IDS sources
# ----------------------------------------------------------------------------
class LiveWorker(Worker):
    def __init__(self, detector, iface, bpf, save_path: str = ''):
        super().__init__(detector)
        self.iface = iface or None
        self.bpf = bpf or DEFAULT_BPF
        self.save_path = save_path
        self.recorder: Optional[PcapRecorder] = None
        self._recorder_reported = False
        self.sniffer = None

    def stop(self):
        super().stop()
        try:
            if self.sniffer is not None and self.sniffer.running:
                self.sniffer.stop(join=False)
        except Exception:
            pass

    def _on_packet(self, pkt):
        if self.stop_event.is_set():
            return
        recorder = self.recorder
        if recorder is not None and not recorder.write(pkt) and not self._recorder_reported:
            self._recorder_reported = True
            if recorder.error:
                self.emit_error(f'PCAP recording stopped: {recorder.error}. Detection continues.')
            elif recorder.full:
                self.status.emit('PCAP recording reached its size limit and stopped. Detection continues.')
        try:
            rec = scapy_packet(pkt, 'live')
            if rec:
                self.enqueue(rec)
        except Exception as exc:
            self.emit_error(f'Packet callback error: {exc}')

    def run(self):
        try:
            from scapy.all import AsyncSniffer
            if self.save_path:
                try:
                    self.recorder = PcapRecorder(self.save_path)
                except Exception as exc:
                    self.error.emit(f'Cannot write PCAP file {self.save_path}: {exc}')
                    return
            chosen = ''
            if not self.iface:
                self.iface = auto_interface()
                chosen = (f' on {self.iface} (chosen automatically; pick another interface if this is wrong)'
                          if self.iface else ' on the capture library default interface')
            else:
                chosen = f' on {self.iface}'
            self.sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=self._on_packet, store=False)
            self.sniffer.start()
            self.status.emit(f'Live IDS capture started{chosen}.'
                             + (f' Recording to {self.save_path}.' if self.recorder else ''))
            while not self.stop_event.wait(0.02):
                self.drain(1000)
                thread = self.sniffer.thread
                if thread is not None and not thread.is_alive():
                    self.error.emit(capture_stopped_message(getattr(self.sniffer, 'exception', None)))
                    break
            try:
                if self.sniffer.running:
                    self.sniffer.stop(join=True)
            except Exception:
                pass
            self.drain_all(2000)
        except Exception as exc:
            if not self.stop_event.is_set():
                self.error.emit(capture_error_message(exc) or f'Live capture failed: {exc}')
        finally:
            if self.recorder is not None:
                self.recorder.close()
                self.status.emit(self.recorder.summary())
            if self.dropped_capture:
                self.status.emit(f'Live capture stopped; dropped capture queue packets: {self.dropped_capture:,}.')
            self.flush_ui()


class SimWorker(Worker):
    def run(self):
        self.status.emit('Simulated traffic active.')
        rnd = random.Random()
        try:
            while not self.stop_event.is_set():
                for rec in generate_round(rnd):
                    self.enqueue(rec)
                self.drain(2500)
                self.stop_event.wait(0.12)
        except Exception as exc:
            if not self.stop_event.is_set():
                self.error.emit(f'Simulation failed: {exc}')
        finally:
            self.drain_all()
            if self.dropped_capture:
                self.status.emit(f'Simulation stopped; dropped queue packets: {self.dropped_capture:,}.')
            self.flush_ui()


class PcapWorker(Worker):
    def __init__(self, detector, path, auto_block=False, ttl=300, dry_run=True):
        super().__init__(detector, auto_block, ttl, dry_run)
        self.path = path

    def run(self):
        try:
            from scapy.utils import PcapReader
            load_layers()
            self.status.emit(f'PCAP replay started: {self.path}')
            pending = 0
            with PcapReader(self.path) as reader:
                for raw in reader:
                    if self.stop_event.is_set():
                        break
                    rec = scapy_packet(raw, 'pcap')
                    if rec:
                        self.enqueue(rec)
                        pending += 1
                        if pending >= 1000:
                            self.drain(1000)
                            pending = 0
            self.drain_all()
            self.status.emit(f'PCAP replay finished; dropped queue packets: {self.dropped_capture:,}.')
        except Exception as exc:
            if not self.stop_event.is_set():
                self.error.emit(f'PCAP replay failed: {exc}')
        finally:
            self.flush_ui()


# ----------------------------------------------------------------------------
# Inline IPS engines
# ----------------------------------------------------------------------------
class WinIPS(Worker):
    """WinDivert inline engine. Inspection errors fail open (packet is re-injected)."""

    def __init__(self, detector, flt, auto_block, ttl, dry_run=True):
        super().__init__(detector, auto_block, ttl, dry_run)
        self.flt = (flt or '').strip() or WINDIVERT_DEFAULT_FILTER
        if self.flt == LEGACY_WINDIVERT_FILTER:
            self.flt = WINDIVERT_DEFAULT_FILTER
        self.handle = None

    def stop(self):
        super().stop()
        try:
            if self.handle:
                self.handle.close()      # unblocks recv()
        except Exception:
            pass

    def run(self):
        try:
            # PyDivert only exists on Windows.
            import pydivert  # pyright: ignore[reportMissingImports]
        except Exception as exc:
            self.error.emit(f'PyDivert unavailable: {exc}')
            return
        problem = windivert_filter_error(self.flt, pydivert)
        if problem:
            self.error.emit(problem)
            return
        try:
            self.handle = pydivert.WinDivert(self.flt)
            self.handle.open()
            self.status.emit(f'Windows inline IPS active (filter "{self.flt}"). '
                             + ('Dry-run: nothing is dropped.' if self.dry_run else
                                'Blocking: blocklisted and drop-rule traffic is dropped.'))
            while not self.stop_event.is_set():
                try:
                    raw = self.handle.recv()
                except OSError as exc:
                    if not self.stop_event.is_set():    # stop() closes the handle; anything else is a failure
                        self.error.emit(f'Windows IPS stopped: {exc}')
                    break
                drop = False
                try:
                    rec = parse_raw(bytes(raw.raw))
                    if rec:
                        drop = self.process_one(rec, inline=True)
                except Exception as exc:
                    self.emit_error(f'IPS inspection error (fail-open): {exc}')
                if not drop:
                    self.handle.send(raw)
                self.flush_ui_if_due()
        except Exception as exc:
            if not self.stop_event.is_set():
                self.error.emit(windivert_open_error(exc))
        finally:
            try:
                if self.handle:
                    self.handle.close()
            except Exception:
                pass
            self.flush_ui()


def windivert_filter_error(flt: str, pydivert_module) -> str:
    """A plain-language error for an invalid WinDivert filter, or ''."""
    check = getattr(getattr(pydivert_module, 'WinDivert', None), 'check_filter', None)
    if check is None:
        return ''
    try:
        ok, position, message = check(flt)
    except Exception:
        return ''
    if ok:
        return ''
    return (f'The Windows filter "{flt}" is not valid WinDivert syntax ({message} at character {position}). '
            f'WinDivert is not BPF: use "ipv6" instead of "ip6", "tcp.DstPort == 80" instead of "tcp port 80". '
            f'The default is "{WINDIVERT_DEFAULT_FILTER}".')


def capture_stopped_message(exc: Optional[BaseException], gui: bool = True) -> str:
    """Why the capture thread ended on its own (scapy keeps the exception that stopped it)."""
    if exc is not None:
        return capture_error_message(exc, gui) or f'Live capture stopped: {exc}'
    return 'Capture stopped unexpectedly. Check privileges, Npcap/interface and BPF filter.'


def windivert_open_error(exc: Exception) -> str:
    code = getattr(exc, 'winerror', None)
    if code == 5:
        return ('Windows IPS needs Administrator rights: click "Restart as Administrator" on the Dashboard, or '
                'run IDPS from an Administrator terminal.')
    if code == 87:
        return 'Windows IPS failed: WinDivert rejected the filter. Check the Windows filter on the IPS tab.'
    if code in (2, 3, 577, 1275):
        return (f'Windows IPS failed: the WinDivert driver could not be loaded ({exc}). Reinstall pydivert, and '
                'check that antivirus or Secure Boot policy is not blocking the driver.')
    return f'Windows IPS failed: {exc}'


class LinuxIPS(Worker):
    """NFQUEUE inline engine. The queue is bound and unbound only on this thread."""

    def __init__(self, detector, qnum, auto_block, ttl, dry_run=True):
        super().__init__(detector, auto_block, ttl, dry_run)
        self.qnum = qnum

    def _verdict(self, pkt):
        drop = False
        try:
            rec = parse_raw(pkt.get_payload())
            if rec:
                drop = self.process_one(rec, inline=True)
        except Exception as exc:
            self.emit_error(f'IPS inspection error (fail-open): {exc}')
        try:
            if drop:
                pkt.drop()
            else:
                pkt.accept()
        except Exception as exc:
            self.emit_error(f'NFQUEUE verdict error: {exc}')

    def run(self):
        try:
            # NetfilterQueue only exists on Linux.
            from netfilterqueue import NetfilterQueue  # pyright: ignore[reportMissingImports]
        except Exception as exc:
            self.error.emit(f'NetFilterQueue unavailable: {exc}')
            return
        nfq = NetfilterQueue()
        try:
            nfq.bind(self.qnum, self._verdict)
            fd = nfq.get_fd()
            self.status.emit(f'Linux NFQUEUE IPS active on queue {self.qnum}.')
            while not self.stop_event.is_set():
                ready, _, _ = select.select([fd], [], [], 0.5)
                if ready:
                    nfq.run(block=False)
                self.flush_ui_if_due()
        except Exception as exc:
            if not self.stop_event.is_set():
                if capture_error_message(exc):          # missing root / cap_net_admin
                    self.error.emit('Linux IPS needs root: start IDPS with "sudo ./run.sh" and add the iptables '
                                    'NFQUEUE rule (see the README).')
                else:
                    self.error.emit(f'Linux IPS failed: {exc}')
        finally:
            try:
                nfq.unbind()
            except Exception:
                pass
            self.flush_ui()


# ----------------------------------------------------------------------------
# Blocklist import and feeds
# ----------------------------------------------------------------------------
class SignatureLoadWorker(QThread):
    """Parses Snort/Suricata rule files off the GUI thread."""
    result = pyqtSignal(object, object, arguments=['rule_set', 'report'])
    failed = pyqtSignal(str, arguments=['message'])

    def __init__(self, paths, home_net=''):
        super().__init__()
        self.paths = list(paths)
        self.home_net = home_net

    def run(self):
        try:
            rule_set, report = load_paths(self.paths, self.home_net, should_stop=self.isInterruptionRequested)
            if not self.isInterruptionRequested():
                self.result.emit(rule_set, report)
        except Exception as exc:
            self.failed.emit(str(exc))


class FeedUpdateWorker(QThread):
    """Downloads the configured feeds and replaces their blocklist entries."""
    result = pyqtSignal(object, arguments=['results'])
    failed = pyqtSignal(str, arguments=['message'])

    def __init__(self, store, urls, force_urls=()):
        super().__init__()
        self.store = store
        self.urls = list(urls)
        self.force_urls = list(force_urls)

    def run(self):
        try:
            self.result.emit(update_feeds(self.store, self.urls, should_stop=self.isInterruptionRequested,
                                          force_urls=self.force_urls))
        except Exception as exc:
            self.failed.emit(str(exc))


class BlocklistImportWorker(QThread):
    result = pyqtSignal(int, int, str, arguments=['added', 'skipped', 'name'])
    failed = pyqtSignal(str, arguments=['message'])

    def __init__(self, store, path):
        super().__init__()
        self.store = store
        self.path = Path(path)

    def run(self):
        try:
            default_reason = f'Imported from {self.path.name}'
            entries, parse_skipped = [], 0
            for raw in self.path.read_text(encoding='utf-8', errors='replace').splitlines():
                if self.isInterruptionRequested():
                    return
                parsed = parse_blocklist_line(raw)
                if parsed is None:
                    continue
                target, reason = parsed
                try:
                    entries.append((str(normalize_network(target)), reason or default_reason))
                except ValueError:
                    parse_skipped += 1
            if self.isInterruptionRequested():
                return
            added, skipped = self.store.block_many(entries, source='feed', default_reason=default_reason)
            self.result.emit(added, skipped + parse_skipped, self.path.name)
        except Exception as exc:
            self.failed.emit(str(exc))


# ----------------------------------------------------------------------------
# Self-test and Wi-Fi
# ----------------------------------------------------------------------------
class SelfTestWorker(QThread):
    """Sends the live self-test traffic off the GUI thread."""
    log = pyqtSignal(str, arguments=['message'])
    done = pyqtSignal(object, str, arguments=['rules', 'error'])

    def __init__(self, thresholds: dict):
        super().__init__()
        self.thresholds = dict(thresholds)

    def run(self):
        from .selftest import run_self_test
        try:
            rules = run_self_test(self.thresholds, log=self.log.emit, should_stop=self.isInterruptionRequested)
            self.done.emit(rules, '')
        except Exception as exc:
            self.done.emit([], str(exc))


class WifiScanWorker(QThread):
    """Scans once, or every `interval` seconds when `interval` is set, and checks the WIFI-* rules."""
    scanned = pyqtSignal(object, arguments=['result'])
    alert_batch = pyqtSignal(object, arguments=['alerts'])
    error = pyqtSignal(str, arguments=['message'])

    def __init__(self, wifi_detector, interval: Optional[float] = None, wait: Optional[float] = None,
                 measure: bool = False):
        super().__init__()
        self.wifi_detector = wifi_detector
        self.interval = interval
        self.wait_seconds = wait
        self.measure = measure          # also ping the router and the internet (survey recordings)
        self.stop_event = threading.Event()

        self.wake_event = threading.Event()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
        self.requestInterruption()

    def wake(self):
        """Restart the wait between scans, for example after the interval changed."""
        self.wake_event.set()

    def _sleep(self) -> bool:
        """Wait `interval` seconds (restarting on wake). Returns True when the worker should stop."""
        while True:
            self.wake_event.clear()
            if self.stop_event.is_set():
                return True
            if not self.wake_event.wait(self.interval or 0):
                return self.stop_event.is_set()

    def run(self):
        from .wifi import SCAN_WAIT_SECONDS, scan
        wait = SCAN_WAIT_SECONDS if self.wait_seconds is None else self.wait_seconds
        last_error = ''
        while not self.stop_event.is_set():
            try:
                latency: dict = {}
                pinger = None
                if self.measure:            # runs during the scan's wait, so a recording takes no longer
                    from .wifi import measure_latency
                    pinger = threading.Thread(target=lambda: latency.update(measure_latency()), daemon=True)
                    pinger.start()
                result = scan(wait)
                if pinger is not None:
                    pinger.join(30)
                    result.latency = dict(latency) if latency else None
                if self.stop_event.is_set():
                    return
                alerts = self.wifi_detector.inspect(result)
                for a in alerts:
                    self.wifi_detector.store.add_alert(a)
                self.scanned.emit(result)
                if alerts:
                    self.alert_batch.emit(alerts)
                last_error = ''
            except Exception as exc:
                message = f'Wi-Fi scan failed: {exc}'
                if message != last_error:       # report a persistent problem once
                    self.error.emit(message)
                    last_error = message
            if self.interval is None or self._sleep():
                return


class RuleDownloadWorker(QThread):
    """Downloads the ET Open rule archive off the GUI thread."""
    result = pyqtSignal(object, arguments=['download'])
    failed = pyqtSignal(str, arguments=['message'])
    shrunk = pyqtSignal(str, arguments=['message'])     # refused: far fewer rules than now (can be forced)

    def __init__(self, url: str = '', force: bool = False):
        super().__init__()
        self.url = url
        self.force = force

    def run(self):
        from .rule_updates import ET_OPEN_URL, RuleCountDropped, download_et_open
        try:
            self.result.emit(download_et_open(self.url or ET_OPEN_URL, should_stop=self.isInterruptionRequested,
                                              force=self.force))
        except RuleCountDropped as exc:
            if not self.isInterruptionRequested():
                self.shrunk.emit(str(exc))
        except Exception as exc:
            if not self.isInterruptionRequested():
                self.failed.emit(str(exc) or exc.__class__.__name__)
