import os
import sys
import time
from pathlib import Path

import pytest

# GUI tests never open windows or depend on the desktop session (set before PyQt6 is imported anywhere).
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))     # also covered by pytest.ini pythonpath

from netsentinel.detector import Detector  # noqa: E402
from netsentinel.models import Packet, utc  # noqa: E402
from netsentinel.store import Store  # noqa: E402


@pytest.fixture(autouse=True)
def private_rule_files(tmp_path, monkeypatch):
    """Tests never read or write the real ~/.netsentinel/rules (My rules, ET Open)."""
    import netsentinel.local_rules as local_rules
    import netsentinel.rule_updates as rule_updates
    monkeypatch.setattr(local_rules, 'LOCAL_RULES', tmp_path / 'rules' / 'local.rules')
    monkeypatch.setattr(rule_updates, 'ET_OPEN_PATH', tmp_path / 'rules' / 'emerging.rules.tar.gz')


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / 'test.db')
    yield s
    s.close()


@pytest.fixture
def detector(store):
    return Detector(store)


@pytest.fixture
def pkt():
    """Packet factory. `t` sets the capture time used as the detector's clock."""
    def make(src='10.0.0.5', dst='10.0.0.1', proto='TCP', sport=40000, dport=80, flags='S', payload='',
             t=None, source='test', length=60):
        return Packet(utc(), src, dst, proto, sport, dport, length, flags, payload, source, False,
                      time.time() if t is None else t)
    return make


def wait_for(condition, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return condition()
