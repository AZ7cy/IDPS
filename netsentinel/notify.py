"""Alert notifications: desktop callback, HTTP(S) webhook and syslog (UDP, RFC 5424)."""
from __future__ import annotations

import json
import queue
import socket
import threading
import time
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

from .config import (APP_NAME, NOTIFY_MAX_PER_MINUTE, NOTIFY_PER_KEY_INTERVAL, NOTIFY_QUEUE_MAX, NOTIFY_TIMEOUT,
                     SEVERITIES, SYSLOG_DEFAULT_PORT)
from .models import Alert, redact_evidence, utc

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SYSLOG_FACILITY = 16      # local0
SYSLOG_SEVERITY = {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 4, 'LOW': 5}


def parse_syslog_target(text: str) -> tuple[str, int]:
    """Parse 'host', 'host:port', '[v6]:port' or a bare IPv6 address. Raises ValueError."""
    text = text.strip()
    if not text:
        raise ValueError('syslog target is empty')
    if text.startswith('['):
        host, sep, rest = text[1:].partition(']')
        if not sep or not host:
            raise ValueError('invalid bracketed IPv6 syslog target')
        port_text = rest[1:] if rest.startswith(':') else ''
        if rest and not rest.startswith(':'):
            raise ValueError('invalid syslog target')
    elif text.count(':') == 1:
        host, port_text = text.split(':')
    else:
        host, port_text = text, ''      # hostname, IPv4 or bare IPv6
    port = int(port_text) if port_text else SYSLOG_DEFAULT_PORT
    if not host or not 0 < port < 65536:
        raise ValueError('invalid syslog host or port')
    return host, port


def valid_webhook(url: str) -> bool:
    parsed = urlparse(url.strip())
    return parsed.scheme in ('http', 'https') and bool(parsed.hostname)


def webhook_transport_ok(url: str) -> bool:
    """https anywhere; plain http only to localhost or a private/link-local address (a local collector)."""
    parsed = urlparse(url.strip())
    if parsed.scheme == 'https':
        return True
    host = (parsed.hostname or '').lower()
    if host == 'localhost' or host.endswith('.localhost'):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False                    # a public host name over plain http
    return ip.is_loopback or ip.is_private or ip.is_link_local


@dataclass
class NotificationSettings:
    min_severity: str = 'HIGH'
    desktop: bool = True
    webhook_url: str = ''
    syslog_target: str = ''
    include_evidence: bool = False

    def validate(self) -> list[str]:
        errors = []
        if self.min_severity not in SEVERITY_RANK:
            errors.append(f'Minimum severity must be one of {", ".join(SEVERITIES)}.')
        if self.webhook_url and not valid_webhook(self.webhook_url):
            errors.append('Webhook URL must start with http:// or https:// and include a host.')
        elif self.webhook_url and not webhook_transport_ok(self.webhook_url):
            errors.append('Use https:// for webhooks on the internet: alerts contain addresses and rule details. '
                          'Plain http:// is only allowed for this computer or a private network address.')
        if self.syslog_target:
            try:
                parse_syslog_target(self.syslog_target)
            except ValueError as exc:
                errors.append(f'Syslog target: {exc}.')
        return errors


def alert_payload(a: Alert, include_evidence: bool) -> dict:
    data = asdict(a)
    if not include_evidence:
        data['evidence'] = redact_evidence(a.evidence)
    data['app'] = APP_NAME
    data['sent_at'] = utc()
    return data


def alert_summary(a: Alert) -> str:
    return f'{a.severity} {a.rule_id} {a.src_ip} -> {a.dst_ip}: {a.title} [{a.action}]'


def syslog_message(a: Alert, hostname: Optional[str] = None) -> bytes:
    pri = SYSLOG_FACILITY * 8 + SYSLOG_SEVERITY.get(a.severity, 5)
    host = (hostname or socket.gethostname() or '-').replace(' ', '_')
    return f'<{pri}>1 {utc()} {host} netsentinel - - - {alert_summary(a)}'.encode('utf-8', 'replace')


class Notifier:
    """Selects alerts worth notifying and delivers them off the caller's thread."""

    def __init__(self, settings: Optional[NotificationSettings] = None,
                 desktop: Optional[Callable[[str, str], None]] = None,
                 on_error: Optional[Callable[[str], None]] = None,
                 per_key_interval: float = NOTIFY_PER_KEY_INTERVAL,
                 max_per_minute: int = NOTIFY_MAX_PER_MINUTE):
        self.settings = settings or NotificationSettings()
        self.desktop = desktop
        self.on_error = on_error
        self.per_key_interval = per_key_interval
        self.max_per_minute = max_per_minute
        self.sent = 0
        self.dropped = 0
        self.last_error = ''
        self._last_by_key: dict = {}
        self._recent: deque = deque()
        self._last_error_at: dict = {}
        self._queue: queue.Queue = queue.Queue(maxsize=NOTIFY_QUEUE_MAX)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._deliver_loop, name='NetSentinel-Notify', daemon=True)
        self._thread.start()

    def configure(self, settings: NotificationSettings):
        self.settings = settings

    def _remote_enabled(self) -> bool:
        return bool(self.settings.webhook_url or self.settings.syslog_target)

    def _allowed(self, a: Alert, now: float) -> bool:
        if SEVERITY_RANK.get(a.severity, -1) < SEVERITY_RANK.get(self.settings.min_severity, 2):
            return False
        key = (a.rule_id, a.src_ip)
        if now - self._last_by_key.get(key, -float('inf')) < self.per_key_interval:
            return False
        while self._recent and now - self._recent[0] >= 60:
            self._recent.popleft()
        if len(self._recent) >= self.max_per_minute:
            return False
        self._last_by_key[key] = now
        self._recent.append(now)
        if len(self._last_by_key) > 10_000:
            self._last_by_key = {k: t for k, t in self._last_by_key.items() if now - t < self.per_key_interval}
        return True

    def submit(self, alerts: Iterable[Alert], now: Optional[float] = None) -> list[Alert]:
        """Filter and dispatch alerts. Returns the alerts that were selected for notification."""
        now = time.monotonic() if now is None else now
        chosen = [a for a in alerts if self._allowed(a, now)]
        for a in chosen:
            if self.settings.desktop and self.desktop:
                try:
                    self.desktop(f'{APP_NAME}: {a.severity} {a.rule_id}', alert_summary(a))
                except Exception as exc:
                    self._report(f'Desktop notification failed: {exc}')
            if self._remote_enabled():
                self._enqueue(a, self.settings)
        return chosen

    def send_test(self) -> None:
        """Send a sample alert to every enabled channel, bypassing filters."""
        sample = Alert('TEST-000', 'Test notification', 'HIGH', 'NetSentinel notification test',
                       '192.0.2.1', '192.0.2.2', 'This is a test.', source='test')
        if self.settings.desktop and self.desktop:
            self.desktop(f'{APP_NAME}: test', alert_summary(sample))
        if self._remote_enabled():
            self._enqueue(sample, self.settings)

    def _enqueue(self, a: Alert, settings: NotificationSettings):
        try:
            self._queue.put_nowait((a, settings))
        except queue.Full:
            self.dropped += 1

    def _report(self, message: str):
        self.last_error = message
        now = time.monotonic()
        if now - self._last_error_at.get(message, -float('inf')) >= 30:
            self._last_error_at[message] = now
            if self.on_error:
                try:
                    self.on_error(message)
                except Exception:
                    pass

    def _deliver_loop(self):
        while not self._stop.is_set() or not self._queue.empty():
            try:
                a, settings = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if settings.webhook_url:
                    self._send_webhook(a, settings)
                if settings.syslog_target:
                    self._send_syslog(a, settings)
                self.sent += 1
            except Exception as exc:
                self._report(f'Notification delivery failed: {exc}')
            finally:
                self._queue.task_done()

    @staticmethod
    def _send_webhook(a: Alert, settings: NotificationSettings):
        if not valid_webhook(settings.webhook_url):
            raise ValueError('invalid webhook URL')
        body = json.dumps(alert_payload(a, settings.include_evidence)).encode('utf-8')
        req = urllib.request.Request(settings.webhook_url, data=body, method='POST',
                                     headers={'Content-Type': 'application/json', 'User-Agent': 'NetSentinel'})
        with urllib.request.urlopen(req, timeout=NOTIFY_TIMEOUT) as resp:
            if resp.status >= 400:
                raise OSError(f'webhook returned HTTP {resp.status}')

    @staticmethod
    def _send_syslog(a: Alert, settings: NotificationSettings):
        host, port = parse_syslog_target(settings.syslog_target)
        info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)[0]
        with socket.socket(info[0], socket.SOCK_DGRAM) as sock:
            sock.sendto(syslog_message(a), info[4])

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until queued notifications are delivered (used by tests and shutdown)."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.02)
        return not self._queue.unfinished_tasks

    def close(self, timeout: float = 5.0):
        self.flush(timeout)
        self._stop.set()
        self._thread.join(timeout=1)
