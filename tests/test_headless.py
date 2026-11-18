import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from netsentinel.app import build_parser
from netsentinel.headless import run_headless

ROOT = Path(__file__).resolve().parents[1]


def test_simulated_run_writes_jsonl(tmp_path):
    log, out = tmp_path / 'alerts.jsonl', io.StringIO()
    code = run_headless('sim', duration=2.5, json_log=str(log), db=str(tmp_path / 'h.db'), out=out)
    assert code == 0
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records and {'rule_id', 'severity', 'src_ip', 'logged_at'} <= set(records[0])
    assert 'Processed' in out.getvalue()


def test_missing_pcap_is_an_error(tmp_path):
    out = io.StringIO()
    assert run_headless('pcap', pcap=str(tmp_path / 'none.pcap'), db=str(tmp_path / 'h.db'), out=out) == 1
    assert 'not found' in out.getvalue() or 'scapy' in out.getvalue()


def test_invalid_notification_settings_rejected(tmp_path):
    from netsentinel.notify import NotificationSettings
    out = io.StringIO()
    code = run_headless('sim', duration=1, db=str(tmp_path / 'h.db'), out=out,
                        notify=NotificationSettings(webhook_url='ftp://nope'))
    assert code == 2 and 'Webhook URL' in out.getvalue()


def test_pcap_replay(tmp_path):
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap
    path = tmp_path / 'scan.pcap'
    wrpcap(str(path), [IP(src='10.0.0.5', dst='10.0.0.1') / TCP(sport=40000, dport=port, flags='S')
                       for port in range(20, 50)])
    log = tmp_path / 'alerts.jsonl'
    assert run_headless('pcap', pcap=str(path), json_log=str(log), db=str(tmp_path / 'h.db'), out=io.StringIO()) == 0
    assert 'NET-001' in {json.loads(line)['rule_id'] for line in log.read_text().splitlines()}


def test_pcap_replay_with_signature_rules(tmp_path):
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.utils import wrpcap
    path = tmp_path / 'dns.pcap'
    wrpcap(str(path), [IP(src='192.168.1.12', dst='8.8.8.8') / UDP(sport=5000, dport=53)
                       / DNS(rd=1, qd=DNSQR(qname='c2.evil-example.com'))])
    rules = tmp_path / 'test.rules'
    rules.write_text('alert dns $HOME_NET any -> any any (msg:"TEST DNS query to evil-example.com"; dns.query; '
                     'dotprefix; content:".evil-example.com"; endswith; classtype:trojan-activity; sid:9100001;)\n')
    log, out = tmp_path / 'alerts.jsonl', io.StringIO()
    assert run_headless('pcap', pcap=str(path), json_log=str(log), db=str(tmp_path / 'h.db'), out=out,
                        rules=[str(rules)]) == 0
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(r['rule_id'], r['severity']) for r in records] == [('SIG-001', 'HIGH')]
    assert 'Loaded 1 of 1 rules' in out.getvalue()
    assert run_headless('sim', duration=1, db=str(tmp_path / 'h.db'), out=io.StringIO(), home_net='[bad') == 2


def test_cli_parser():
    args = build_parser().parse_args(['--headless', '--source', 'pcap', '--pcap', 'x.pcap', '--duration', '5',
                                      '--min-severity', 'MEDIUM'])
    assert args.headless and args.source == 'pcap' and args.duration == 5 and args.min_severity == 'MEDIUM'


def test_headless_does_not_import_qt(tmp_path):
    code = ('import sys; from netsentinel.app import main\n'
            f'try:\n    main(["--headless", "--duration", "1", "--db", r"{tmp_path / "q.db"}"])\n'
            'except SystemExit as e:\n    assert e.code == 0, e.code\n'
            'assert not any(m.startswith("PyQt6") for m in sys.modules), "PyQt6 was imported"\n')
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_list_interfaces_cli():
    result = subprocess.run([sys.executable, 'idps.py', '--list-interfaces'], cwd=ROOT,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0 and result.stdout.strip()
