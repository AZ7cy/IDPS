import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from netsentinel.models import Alert
from netsentinel.notify import NotificationSettings, Notifier, parse_syslog_target, syslog_message


def alert(rule='WEB-001', severity='HIGH', src='10.0.0.4'):
    return Alert(rule, 'Suspicious HTTP request pattern', severity, 'd', src, '10.0.0.1',
                 "matched HTTP request marker 'secret'")


@pytest.mark.parametrize('text, expected', [
    ('syslog.local', ('syslog.local', 514)),
    ('10.0.0.5:1514', ('10.0.0.5', 1514)),
    ('[2001:db8::1]:600', ('2001:db8::1', 600)),
    ('2001:db8::1', ('2001:db8::1', 514)),
])
def test_parse_syslog_target(text, expected):
    assert parse_syslog_target(text) == expected


@pytest.mark.parametrize('text', ['', 'host:0', 'host:99999', '[::1', 'host:abc'])
def test_parse_syslog_target_rejects(text):
    with pytest.raises(ValueError):
        parse_syslog_target(text)


def test_settings_validation():
    assert NotificationSettings().validate() == []
    errors = NotificationSettings(min_severity='X', webhook_url='ftp://x', syslog_target='h:0').validate()
    assert len(errors) == 3


def test_severity_filter_and_rate_limits():
    calls = []
    n = Notifier(NotificationSettings(min_severity='HIGH'), desktop=lambda t, m: calls.append(m),
                 per_key_interval=60, max_per_minute=2)
    try:
        assert n.submit([alert(severity='MEDIUM')], now=0) == []
        assert len(n.submit([alert()], now=0)) == 1
        assert n.submit([alert()], now=10) == []                       # same rule + source within 60 s
        assert len(n.submit([alert(src='10.0.0.5')], now=10)) == 1
        assert n.submit([alert(src='10.0.0.6')], now=20) == []         # global cap of 2 per minute
        assert len(n.submit([alert(src='10.0.0.6')], now=80)) == 1
        assert len(calls) == 3
    finally:
        n.close()


def test_syslog_delivery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    sock.settimeout(3)
    port = sock.getsockname()[1]
    n = Notifier(NotificationSettings(desktop=False, syslog_target=f'127.0.0.1:{port}'))
    try:
        n.submit([alert(severity='CRITICAL', rule='IOC-001')])
        data = sock.recv(4096).decode()
        assert data.startswith('<130>1 ')                # local0 (16*8) + crit (2)
        assert 'IOC-001' in data and 'netsentinel' in data
    finally:
        n.close()
        sock.close()


def test_webhook_delivery_redacts_evidence():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers['Content-Length'])
            received.append((self.headers['Content-Type'], json.loads(self.rfile.read(length))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_address[1]}/hook'
    n = Notifier(NotificationSettings(desktop=False, webhook_url=url))
    try:
        n.submit([alert()])
        assert n.flush(5)
        content_type, body = received[0]
        assert content_type == 'application/json'
        assert body['rule_id'] == 'WEB-001' and body['app'] == 'IDPS'
        assert 'secret' not in body['evidence'] and '<redacted>' in body['evidence']
        assert n.sent == 1
    finally:
        n.close()
        server.shutdown()


def test_delivery_failure_is_reported_not_raised():
    errors = []
    n = Notifier(NotificationSettings(desktop=False, webhook_url='http://127.0.0.1:9/unreachable'),
                 on_error=errors.append)
    try:
        n.submit([alert()])
        assert n.flush(10)
        assert errors and n.last_error and n.sent == 0
    finally:
        n.close()


def test_syslog_message_format():
    msg = syslog_message(alert(severity='LOW'), hostname='my host').decode()
    assert msg.startswith('<133>1 ') and ' my_host netsentinel - - - ' in msg
