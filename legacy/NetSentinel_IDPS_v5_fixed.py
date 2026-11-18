from __future__ import annotations

import csv
import ipaddress
import json
import math
import os
import platform
import random
import re
import select
import socket
import sqlite3
import queue
import subprocess
import sys
import threading
import traceback
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from functools import lru_cache
from bisect import bisect_right
from typing import Optional
from urllib.parse import unquote_plus

from PyQt6.QtCore import QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout,
                             QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                             QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
                             QSpinBox, QStatusBar, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
                             QWidget)

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
APP = 'IDPS'
DB_PATH = Path.home() / '.netsentinel' / 'netsentinel.db'
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

MAX_PACKET_ROWS = 50_000
MAX_ALERT_ROWS = 20_000
SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
RULE_VERSION = 4
DNS_MIN_HITS = 8
DNS_MIN_ENTROPY = 3.8
HTTP_PORTS = {80, 8080, 8000, 8888}
MAX_DETECTOR_STATE_PER_KEY = 1000

# id, title, severity, enabled, threshold, window(s), description
# Threshold semantics:
# NET-001 = unique ports for one (source,destination) pair.
# NET-002 = inbound TCP SYNs per source in window.
# NET-003 = SYNs against one destination; source attribution is intentionally not auto-blocked.
# NET-004 = one source touching many destination hosts on one port.
# NET-005 = FIN/NULL/Xmas-style stealth TCP scans.
# ICMP-001 = ICMP packets per source in window.
# DNS-001 = minimum full query-name length.
RULE_SEED = [
    ('NET-001', 'TCP SYN port-scan pattern', 'HIGH', 1, 20, 10, 'Many destination ports from one source to one destination'),
    ('NET-002', 'TCP SYN connection burst', 'MEDIUM', 1, 80, 5, 'High inbound TCP SYN rate from one source'),
    ('NET-003', 'SYN flood indicator', 'HIGH', 1, 200, 5, 'High SYN volume with source diversity and a high SYN/ACK imbalance'),
    ('NET-004', 'Horizontal TCP scan', 'HIGH', 1, 40, 15, 'One source probes many destination hosts on one TCP port; browsing alone is not sufficient for auto-blocking'),
    ('NET-005', 'Stealth TCP scan', 'HIGH', 1, 8, 10, 'FIN/NULL/Xmas-style TCP probing pattern'),
    ('ICMP-001', 'ICMP flood indicator', 'HIGH', 1, 250, 5, 'High ICMP packet rate from one source'),
    ('WEB-001', 'Suspicious HTTP request pattern', 'HIGH', 1, 1, 60, 'Suspicious markers in plaintext HTTP request traffic only'),
    ('DNS-001', 'Possible DNS tunneling / DGA', 'MEDIUM', 1, 40, 60, 'Repeated long, high-entropy full DNS query names'),
    ('IOC-001', 'Known suspicious indicator', 'CRITICAL', 1, 1, 60, 'Source is in the local blocklist'),
]

# Only migrate old untouched defaults. Never overwrite a deliberate analyst change.
PREVIOUS_RULE_DEFAULTS = {
    'NET-001': (15, 10), 'NET-002': (80, 5), 'NET-002_V3': (400, 5),
    'NET-003': (100, 5), 'NET-004': (20, 15), 'NET-005': (8, 10),
    'WEB-001': (1, 60), 'DNS-001': (50, 60), 'IOC-001': (1, 60),
}

PATTERNS = [re.compile(x, re.I) for x in [
    r'\.\.[/\\]',
    r'\bunion\s+(?:all\s+)?select\b',
    r'\b(?:or|and)\s+1\s*=\s*1\b',
    r'<script\b',
    r'\bcmd(?:\.exe)?\s+/[ck]\b|\bpowershell(?:\.exe)?\s+-\w+',
    r'\b(?:wget|curl)\s+https?://',
    r'/etc/(?:passwd|shadow)|\bwin\.ini\b|\bboot\.ini\b',
]]
# Scanner names are only checked in User-Agent, never in Host/path text.
SCANNER_UA = re.compile(r'\b(?:sqlmap|nikto|nmap|masscan|zgrab)\b', re.I)
STEALTH_FLAGS = {'', 'F', 'U', 'FU', 'UF', 'FP', 'PF', 'FPU', 'UP', 'PU'}
# Only detections with strong source attribution are eligible for active auto-blocking.
# Only a verified, connection-oriented HTTP detection is eligible for active auto-blocking.
# The detector requires two independent hits inside 60s before a block is attempted.
AUTO_BLOCK_RULES = {'WEB-001'}
DB_PACKET_BUFFER_MAX = 100_000
DB_ALERT_BUFFER_MAX = 20_000
HTTP_MAX_BYTES_PER_FLOW = 32_768
HTTP_MAX_FRAGMENTS_PER_FLOW = 32


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c, n = Counter(s), len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


# ----------------------------------------------------------------------------
# Address normalization / local protection / trusted hosts
# ----------------------------------------------------------------------------
@lru_cache(maxsize=65536)
def canonical_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(str(value).split('%')[0])
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return str(value).split('%')[0]


class PrefixIndex:
    """Compact interval index for IPv4/IPv6 membership checks."""
    __slots__ = ('v4', 'v6')

    def __init__(self):
        self.v4 = ([], [], [])   # (intervals, starts, prefix_max_ends)
        self.v6 = ([], [], [])

    @staticmethod
    def _make(intervals):
        intervals = sorted(intervals)
        starts = [x[0] for x in intervals]
        max_ends, current = [], -1
        for _, end in intervals:
            current = max(current, end)
            max_ends.append(current)
        return intervals, starts, max_ends

    def clear(self):
        self.v4 = ([], [], []); self.v6 = ([], [], [])

    def rebuild(self, nets):
        v4 = [(int(n.network_address), int(n.broadcast_address)) for n in nets if n.version == 4]
        v6 = [(int(n.network_address), int(n.broadcast_address)) for n in nets if n.version == 6]
        self.v4 = self._make(v4); self.v6 = self._make(v6)

    def add(self, net):
        start, end = int(net.network_address), int(net.broadcast_address)
        intervals, starts, max_ends = self.v4 if net.version == 4 else self.v6
        idx = bisect_right(starts, start)
        intervals = list(intervals); intervals.insert(idx, (start, end))
        starts = list(starts); starts.insert(idx, start)
        max_ends = list(max_ends[:idx])
        current = max_ends[-1] if max_ends else -1
        for _, item_end in intervals[idx:]:
            current = max(current, item_end); max_ends.append(current)
        family = (intervals, starts, max_ends)
        if net.version == 4: self.v4 = family
        else: self.v6 = family

    def contains(self, addr) -> bool:
        _, starts, max_ends = self.v4 if addr.version == 4 else self.v6
        if not starts: return False
        value = int(addr); idx = bisect_right(starts, value) - 1
        return idx >= 0 and max_ends[idx] >= value


_LOCAL: set[str] = set()
_LOCAL_REFRESH = float("-inf")
_LOCAL_LOCK = threading.Lock()
_INFRA: set[str] = set()
_INFRA_REFRESH = float("-inf")


def _discover_infrastructure() -> set[str]:
    found: set[str] = set()
    try:
        if Path('/proc/net/route').exists():
            for line in Path('/proc/net/route').read_text(errors='ignore').splitlines()[1:]:
                cols = line.split()
                if len(cols) > 2 and cols[1] == '00000000':
                    try:
                        found.add(str(ipaddress.ip_address(bytes.fromhex(cols[2])[::-1])))
                    except Exception:
                        pass
    except Exception:
        pass
    if platform.system() == 'Windows':
        try:
            out = subprocess.run(['route', 'print', '-4'], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                m = re.match(r'^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+', line)
                if m:
                    found.add(canonical_ip(m.group(1))); break
        except Exception:
            pass
        try:
            out = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                m = re.search(r'(?:DNS Servers|DHCP Server)[ .:]*([0-9a-fA-F:.]+)', line, re.I)
                if m:
                    try: found.add(canonical_ip(m.group(1)))
                    except Exception: pass
        except Exception:
            pass
    try:
        resolv = Path('/etc/resolv.conf')
        if resolv.exists():
            for line in resolv.read_text(errors='ignore').splitlines():
                m = re.match(r'\s*nameserver\s+([^\s#]+)', line)
                if m:
                    found.add(canonical_ip(m.group(1)))
    except Exception:
        pass
    return {x for x in found if x}


def local_addrs(force=False) -> set[str]:
    global _LOCAL, _LOCAL_REFRESH
    now = time.monotonic()
    if not force and now - _LOCAL_REFRESH < 30:
        return set(_LOCAL)
    with _LOCAL_LOCK:
        if not force and now - _LOCAL_REFRESH < 30:
            return set(_LOCAL)
        found = {'127.0.0.1', '::1'}
        try:
            for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                found.add(canonical_ip(item[4][0]))
        except OSError:
            pass
        try:
            import psutil
            for values in psutil.net_if_addrs().values():
                for a in values:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        found.add(canonical_ip(a.address))
        except Exception:
            pass
        _LOCAL = found
        _LOCAL_REFRESH = now
        return set(_LOCAL)


def refresh_protection_cache() -> set[str]:
    global _INFRA, _INFRA_REFRESH
    local_addrs(force=True)
    infra = _discover_infrastructure()
    with _LOCAL_LOCK:
        _INFRA = infra
        _INFRA_REFRESH = time.monotonic()
        return set(_LOCAL) | set(_INFRA)


def cached_local_addrs() -> set[str]:
    with _LOCAL_LOCK:
        return set(_LOCAL)


def protected_addrs(force=False) -> set[str]:
    # Never perform route/ipconfig/getaddrinfo work on the packet path.
    with _LOCAL_LOCK:
        return set(_LOCAL) | set(_INFRA)


def is_protected(ip: str) -> bool:
    value = canonical_ip(ip)
    try:
        a = ipaddress.ip_address(value)
    except ValueError:
        return True
    return a.is_loopback or a.is_unspecified or a.is_multicast or value in protected_addrs()


def blocks_self(net) -> bool:
    if net.version == 4 and net.overlaps(ipaddress.ip_network('127.0.0.0/8')):
        return True
    if net.version == 6 and net.overlaps(ipaddress.ip_network('::1/128')):
        return True
    for raw in protected_addrs():
        try:
            a = ipaddress.ip_address(raw)
            if a.version == net.version and a in net:
                return True
        except ValueError:
            pass
    return False

# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------
@dataclass(slots=True)
class Packet:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    flags: str = ''
    payload: str = ''
    source: str = 'live'
    dropped: bool = False
    capture_time: float = 0.0


@dataclass(slots=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    description: str
    src_ip: str
    dst_ip: str
    evidence: str
    action: str = 'ALERT'
    block_target: Optional[str] = None
    confidence: str = 'medium'
    source: str = 'live'



def redact_evidence(evidence: str) -> str:
    if not evidence:
        return ''
    return re.sub(r"(?i)(matched(?: HTTP request)? marker)\s+(['\"]).*?\2", r"\1 <redacted>", evidence)

# ----------------------------------------------------------------------------
# Storage: one DB connection, batched writer thread, bounded retention
# ----------------------------------------------------------------------------
def normalize_network(value: str):
    n = ipaddress.ip_network(str(value).strip(), strict=False)
    if n.version == 6 and n.network_address.ipv4_mapped and n.prefixlen >= 96:
        mapped = n.network_address.ipv4_mapped
        return ipaddress.ip_network(f'{mapped}/{n.prefixlen - 96}', strict=False)
    return n


class Store:
    """SQLite store with a dedicated buffered writer connection."""
    def __init__(self, path=DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try: os.chmod(self.path.parent, 0o700)
        except OSError: pass
        self.lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self.db = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.keep_payload = False
        self.persist_packets = False
        self.packet_buf = deque(maxlen=DB_PACKET_BUFFER_MAX)
        self.alert_buf = deque(maxlen=DB_ALERT_BUFFER_MAX)
        self.buffer_drops = 0
        self.alert_generation = 0
        self._writer_error = ''
        self._rows: dict = {}
        self._exact = PrefixIndex()
        self._trusted_rows: dict = {}
        self._trusted_trie = PrefixIndex()
        self._trusted_nets: list = []
        self._writer_stop = threading.Event()
        self._compact_requested = threading.Event()
        self._compact_done = threading.Event()
        self._writer = None
        self._writer_db = None
        self._last_checkpoint = time.monotonic()
        self._init()
        self._load_blocks()
        self._load_trusted()
        self._chmod_files()
        self._writer = threading.Thread(target=self._writer_loop, name='NetSentinel-DB', daemon=True)
        self._writer.start()

    def _chmod_files(self):
        for suffix in ('', '-wal', '-shm'):
            try: os.chmod(str(self.path) + suffix, 0o600)
            except OSError: pass

    def _init(self):
        with self.lock:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=NORMAL')
            self.db.execute('PRAGMA busy_timeout=15000')
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS packets(id INTEGER PRIMARY KEY,timestamp TEXT,src_ip TEXT,dst_ip TEXT,protocol TEXT,
                    src_port INTEGER,dst_port INTEGER,length INTEGER,flags TEXT,payload TEXT,source TEXT,dropped INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,timestamp TEXT,rule_id TEXT,title TEXT,severity TEXT,
                    description TEXT,src_ip TEXT,dst_ip TEXT,evidence TEXT,action TEXT,status TEXT DEFAULT 'OPEN',
                    confidence TEXT DEFAULT 'medium',source TEXT DEFAULT 'live',block_target TEXT);
                CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY,title TEXT,severity TEXT,enabled INTEGER,threshold INTEGER,
                    window INTEGER,description TEXT);
                CREATE TABLE IF NOT EXISTS blocklist(ip TEXT PRIMARY KEY,reason TEXT,created_at TEXT,expires REAL,source TEXT DEFAULT 'manual');
                CREATE TABLE IF NOT EXISTS trusted(ip TEXT PRIMARY KEY,reason TEXT,created_at TEXT);
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
            """)
            pcols = {r['name'] for r in self.db.execute('PRAGMA table_info(packets)').fetchall()}
            if 'dropped' not in pcols: self.db.execute('ALTER TABLE packets ADD COLUMN dropped INTEGER DEFAULT 0')
            acols = {r['name'] for r in self.db.execute('PRAGMA table_info(alerts)').fetchall()}
            if 'confidence' not in acols: self.db.execute("ALTER TABLE alerts ADD COLUMN confidence TEXT DEFAULT 'medium'")
            if 'source' not in acols: self.db.execute("ALTER TABLE alerts ADD COLUMN source TEXT DEFAULT 'live'")
            if 'block_target' not in acols: self.db.execute("ALTER TABLE alerts ADD COLUMN block_target TEXT")
            bcols = {r['name'] for r in self.db.execute('PRAGMA table_info(blocklist)').fetchall()}
            if 'expires' not in bcols: self.db.execute('ALTER TABLE blocklist ADD COLUMN expires REAL')
            if 'source' not in bcols: self.db.execute("ALTER TABLE blocklist ADD COLUMN source TEXT DEFAULT 'manual'")
            for row in RULE_SEED: self.db.execute('INSERT OR IGNORE INTO rules VALUES (?,?,?,?,?,?,?)', row)
            old_row = self.db.execute("SELECT value FROM meta WHERE key='rule_version'").fetchone()
            old_version = int(old_row[0]) if old_row else 0
            if old_version < RULE_VERSION:
                for rid, _, _, _, new_th, new_win, _ in RULE_SEED:
                    old = PREVIOUS_RULE_DEFAULTS.get(rid)
                    if rid == 'NET-002': old = old or PREVIOUS_RULE_DEFAULTS.get('NET-002_V3')
                    if old:
                        self.db.execute('UPDATE rules SET threshold=?, window=? WHERE id=? AND threshold=? AND window=?',
                                        (new_th, new_win, rid, old[0], old[1]))
                self.db.execute("INSERT INTO meta(key,value) VALUES('rule_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(RULE_VERSION),))
            self.db.commit()

    def _writer_loop(self):
        conn = None
        try:
            conn = sqlite3.connect(self.path, timeout=15, check_same_thread=True)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL'); conn.execute('PRAGMA synchronous=NORMAL'); conn.execute('PRAGMA busy_timeout=15000')
            self._writer_db = conn
            while not self._writer_stop.wait(0.25):
                try: self.flush(conn)
                except Exception as exc: self._writer_error = str(exc)
                if self._compact_requested.is_set():
                    try:
                        self.flush(conn); conn.execute('PRAGMA wal_checkpoint(TRUNCATE)'); conn.execute('PRAGMA optimize'); conn.commit()
                        self._writer_error = ''
                    except Exception as exc: self._writer_error = str(exc)
                    finally:
                        self._compact_done.set(); self._compact_requested.clear()
            try: self.flush(conn)
            except Exception: pass
        finally:
            self._writer_db = None
            if conn is not None:
                try: conn.close()
                except Exception: pass

    def close(self):
        self._writer_stop.set()
        if self._writer and self._writer.is_alive(): self._writer.join(timeout=10)
        with self.lock:
            try: self.db.close()
            except Exception: pass
        self._chmod_files()

    def add_packet(self, p: Packet):
        if not self.persist_packets and not p.dropped:
            return
        row = (p.timestamp, canonical_ip(p.src_ip), canonical_ip(p.dst_ip), p.protocol, p.src_port, p.dst_port,
               p.length, p.flags, p.payload if self.keep_payload else '', p.source, int(bool(p.dropped)))
        with self.lock:
            if len(self.packet_buf) >= self.packet_buf.maxlen:
                self.packet_buf.popleft(); self.buffer_drops += 1
            self.packet_buf.append(row)

    def add_alert(self, a: Alert):
        evidence = a.evidence if self.keep_payload else redact_evidence(a.evidence)
        row = (utc(), a.rule_id, a.title, a.severity, a.description, canonical_ip(a.src_ip), canonical_ip(a.dst_ip),
               evidence, a.action, 'OPEN', a.confidence, getattr(a, 'source', 'live'), a.block_target)
        with self.lock:
            if len(self.alert_buf) >= self.alert_buf.maxlen:
                self.alert_buf.popleft(); self.buffer_drops += 1
            self.alert_buf.append(row)

    def flush(self, conn=None):
        if conn is None:
            conn = self._writer_db if threading.current_thread() is self._writer else self.db
            if conn is None: conn = self.db
        with self._flush_lock:
            with self.lock:
                packets, alerts = list(self.packet_buf), list(self.alert_buf)
                self.packet_buf.clear(); self.alert_buf.clear()
            if not packets and not alerts: return False
            try:
                conn.execute('BEGIN')
                if packets:
                    conn.executemany('INSERT INTO packets(timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length,flags,payload,source,dropped) VALUES(?,?,?,?,?,?,?,?,?,?,?)', packets)
                    conn.execute('DELETE FROM packets WHERE id < (SELECT COALESCE(MAX(id),0) FROM packets) - ?', (MAX_PACKET_ROWS,))
                if alerts:
                    conn.executemany('INSERT INTO alerts(timestamp,rule_id,title,severity,description,src_ip,dst_ip,evidence,action,status,confidence,source,block_target) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', alerts)
                    conn.execute('DELETE FROM alerts WHERE id < (SELECT COALESCE(MAX(id),0) FROM alerts) - ?', (MAX_ALERT_ROWS,))
                conn.commit()
                if alerts: self.alert_generation += 1
                if time.monotonic() - self._last_checkpoint > 30:
                    try: conn.execute('PRAGMA wal_checkpoint(PASSIVE)'); conn.execute('PRAGMA optimize')
                    except sqlite3.Error: pass
                    self._last_checkpoint = time.monotonic()
                self._writer_error = ''
                return True
            except Exception:
                try: conn.rollback()
                except Exception: pass
                with self.lock:
                    for buf, rows in ((self.packet_buf, packets), (self.alert_buf, alerts)):
                        room = buf.maxlen - len(buf)
                        keep = rows[-room:] if room > 0 else []
                        self.buffer_drops += len(rows) - len(keep)
                        buf.extendleft(reversed(keep))
                raise

    def packets(self, n=150):
        with self.lock: return [dict(x) for x in self.db.execute('SELECT * FROM packets ORDER BY id DESC LIMIT ?', (n,)).fetchall()]

    def alerts(self, n=200):
        with self.lock: return [dict(x) for x in self.db.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (n,)).fetchall()]

    def set_alert_status(self, aid: int, status: str):
        with self.lock: self.db.execute('UPDATE alerts SET status=? WHERE id=?', (status, aid)); self.db.commit()

    def rules(self):
        with self.lock: return [dict(x) for x in self.db.execute('SELECT * FROM rules ORDER BY id').fetchall()]

    def save_rule(self, r):
        with self.lock:
            self.db.execute('UPDATE rules SET enabled=?,severity=?,threshold=?,window=? WHERE id=?',
                            (r['enabled'], r['severity'], r['threshold'], r['window'], r['id'])); self.db.commit()

    def _load_blocks(self):
        with self.lock:
            rows = self.db.execute('SELECT * FROM blocklist ORDER BY ip').fetchall()
            canonical = {}
            for r in rows:
                try:
                    key = str(normalize_network(str(r['ip'])))
                except ValueError:
                    continue
                candidate = dict(r); candidate['ip'] = key
                current = canonical.get(key)
                if current is None:
                    canonical[key] = candidate
                else:
                    # Prefer a manual entry over feed/auto when legacy rows collide.
                    rank = {'manual': 3, 'auto': 2, 'feed': 1}
                    if rank.get(candidate.get('source'), 0) > rank.get(current.get('source'), 0):
                        canonical[key] = candidate
            try:
                self.db.execute('BEGIN')
                self.db.execute('DELETE FROM blocklist')
                values = [(r['ip'], r.get('reason',''), r.get('created_at') or utc(), r.get('expires'), r.get('source') or 'manual')
                          for r in canonical.values()]
                if values:
                    self.db.executemany('INSERT INTO blocklist(ip,reason,created_at,expires,source) VALUES(?,?,?,?,?)', values)
                self.db.commit()
            except Exception:
                self.db.rollback(); raise
            self._rows = canonical
            self._rebuild()

    def _rebuild(self):
        self._exact = PrefixIndex()
        self._exact.rebuild([normalize_network(k) for k in self._rows])


    def is_blocked(self, ip: str) -> bool:
        try: return self._exact.contains(ipaddress.ip_address(canonical_ip(ip)))
        except ValueError: return False

    def overlaps_trusted(self, target: str) -> bool:
        try: net = normalize_network(target)
        except ValueError: return False
        return any(net.version == n.version and net.overlaps(n) for n in self._trusted_nets)

    def block(self, target: str, reason: str, ttl: Optional[int] = None, source='manual') -> Optional[str]:
        try: n = normalize_network(target)
        except ValueError: return None
        if blocks_self(n) or self.overlaps_trusted(str(n)): return None
        key = str(n)
        now = utc(); exp = time.time() + ttl if ttl else None
        with self.lock:
            existing = self._rows.get(key)
            if existing and existing.get('expires') is None and source != 'manual': return key
            if existing and existing.get('expires') is None and source == 'manual': exp = None
            self.db.execute('''INSERT INTO blocklist(ip,reason,created_at,expires,source) VALUES(?,?,?,?,?)
                               ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at,
                               expires=excluded.expires,source=excluded.source''', (key, reason, now, exp, source))
            self.db.commit()
            is_new = key not in self._rows
            self._rows[key] = {'ip': key, 'reason': reason, 'created_at': now, 'expires': exp, 'source': source}
            if is_new: self._exact.add(n)
        return key

    def block_many(self, entries, source='feed', default_reason='Imported blocklist') -> tuple[int,int]:
        with self.lock:
            trusted_nets = list(self._trusted_nets)
            existing_rows = {k: dict(v) for k, v in self._rows.items()}
        protected = protected_addrs()
        candidates, skipped, seen = [], 0, set()
        for target, reason in entries:
            try: n = normalize_network(target)
            except ValueError: skipped += 1; continue
            unsafe = any((ipaddress.ip_address(raw).version == n.version and ipaddress.ip_address(raw) in n) for raw in protected if raw)
            if not unsafe: unsafe = any(n.version == t.version and n.overlaps(t) for t in trusted_nets)
            key = str(n); existing = existing_rows.get(key)
            if unsafe or key in seen or (existing and existing.get('source') in ('manual','auto')):
                skipped += 1; continue
            seen.add(key); candidates.append((key, reason or default_reason))
        if not candidates: return 0, skipped
        now = utc(); rows = [(k,why,now,None,source) for k,why in candidates]
        with self.lock:
            previous = {k: dict(self._rows[k]) if k in self._rows else None for k,_ in candidates}
            for k,why in candidates: self._rows[k]={'ip':k,'reason':why,'created_at':now,'expires':None,'source':source}
            try:
                self.db.execute('BEGIN')
                self.db.executemany('INSERT INTO blocklist(ip,reason,created_at,expires,source) VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at,expires=excluded.expires,source=excluded.source', rows)
                self.db.commit()
            except Exception:
                self.db.rollback()
                for k,old in previous.items():
                    if old is None: self._rows.pop(k,None)
                    else: self._rows[k]=old
                self._rebuild(); raise
            self._rebuild()
        return len(candidates), skipped

    def unblock(self, key: str):
        try: key = str(normalize_network(key))
        except ValueError: return
        with self.lock:
            self.db.execute('DELETE FROM blocklist WHERE ip=?', (key,)); self.db.commit(); self._rows.pop(key, None); self._rebuild()

    def blocks(self):
        with self.lock: return sorted(self._rows)

    def block_rows(self, limit=None):
        with self.lock:
            keys = sorted(self._rows) if limit is None else sorted(self._rows)[:max(0, int(limit))]
            return [dict(self._rows[k]) for k in keys]

    def _load_trusted(self):
        with self.lock:
            rows = self.db.execute('SELECT * FROM trusted ORDER BY ip').fetchall(); self._trusted_rows = {str(r['ip']): dict(r) for r in rows}; self._rebuild_trusted()

    def _rebuild_trusted(self):
        trie = PrefixIndex(); nets = []
        for k in self._trusted_rows:
            try: nets.append(normalize_network(k))
            except ValueError: pass
        trie.rebuild(nets); self._trusted_trie, self._trusted_nets = trie, nets

    def is_trusted(self, ip: str) -> bool:
        try: return self._trusted_trie.contains(ipaddress.ip_address(canonical_ip(ip)))
        except ValueError: return False

    def trust(self, target: str, reason='Trusted host') -> Optional[str]:
        try: n = normalize_network(target)
        except ValueError: return None
        key = str(n)
        with self.lock:
            now = utc(); self.db.execute('INSERT OR REPLACE INTO trusted(ip,reason,created_at) VALUES(?,?,?)', (key, reason, now)); self.db.commit()
            self._trusted_rows[key] = {'ip': key, 'reason': reason, 'created_at': now}; self._rebuild_trusted()
        return key

    def untrust(self, key):
        try: key = str(normalize_network(key))
        except ValueError: key = str(key)
        with self.lock:
            self.db.execute('DELETE FROM trusted WHERE ip=?', (key,)); self.db.commit(); self._trusted_rows.pop(key, None); self._rebuild_trusted()

    def trusted_rows(self):
        with self.lock: return [dict(self._trusted_rows[k]) for k in sorted(self._trusted_rows)]

    def compact(self):
        if not self._writer or not self._writer.is_alive(): return False
        self._compact_done.clear(); self._compact_requested.set()
        ok = self._compact_done.wait(10)
        self._chmod_files()
        return ok

    def expire_blocks(self):
        now = time.time()
        with self.lock:
            dead = [k for k, r in self._rows.items() if r.get('expires') and r['expires'] < now]
            if dead:
                self.db.executemany('DELETE FROM blocklist WHERE ip=?', [(k,) for k in dead]); self.db.commit()
                for k in dead: self._rows.pop(k, None)
                self._rebuild()
        return dead

# ----------------------------------------------------------------------------
# Detection engine
# ----------------------------------------------------------------------------
class Detector:
    def __init__(self, store: Store):
        self.store = store
        self.lock = threading.RLock()
        self.rate_by_src = defaultdict(deque)
        self.pair_ports = defaultdict(deque)
        self.pair_port_counts = defaultdict(Counter)
        self.syn_by_dst = defaultdict(deque)
        self.syn_source_counts = defaultdict(Counter)
        self.ack_by_dst = defaultdict(deque)
        self.horizontal = defaultdict(deque)
        self.horizontal_counts = defaultdict(Counter)
        self.stealth_by_src = defaultdict(deque)
        self.dns = defaultdict(deque)
        self.icmp = defaultdict(deque)
        self.http_fragments = defaultdict(deque)
        self.cool: dict = {}
        self.block_confirm = defaultdict(deque)
        self.last_gc = float('-inf')
        self.rules: dict = {}
        self.horizon = 120
        self.load()

    def load(self):
        rules = {x['id']: x for x in self.store.rules()}
        with self.lock:
            self.rules = rules
            self.horizon = max([120] + [int(r['window']) for r in rules.values()])

    def reset(self):
        with self.lock:
            for d in (self.rate_by_src, self.pair_ports, self.pair_port_counts,
                      self.syn_by_dst, self.syn_source_counts, self.ack_by_dst, self.horizontal, self.horizontal_counts, self.stealth_by_src, self.dns, self.icmp, self.http_fragments):
                d.clear()
            self.cool.clear(); self.block_confirm.clear(); self.last_gc = float('-inf')

    @staticmethod
    def _on(r): return bool(r and r['enabled'])

    @staticmethod
    def _first_time(item):
        return item if isinstance(item, (int, float)) else item[0]

    @classmethod
    def _trim(cls, q, now, span, cap=None):
        while q and now - cls._first_time(q[0]) > span: q.popleft()
        limit = cap if cap is not None else MAX_DETECTOR_STATE_PER_KEY
        while len(q) > max(1, limit): q.popleft()

    def _once(self, key, seconds=10, now=None):
        t = time.time() if now is None else now; old = self.cool.get(key, -float('inf'))
        if t - old < seconds: return False
        self.cool[key] = t; return True

    def _cap_keys(self, d, now, cap=5000, keep=None, companions=()):
        if len(d) <= cap: return
        candidates = [(k, q) for k, q in d.items() if k != keep]
        victims = sorted(candidates, key=lambda kv: self._first_time(kv[1][-1]) if kv[1] else -float('inf'))[:len(d)-cap]
        for k, _ in victims:
            d.pop(k, None)
            for c in companions: c.pop(k, None)

    def _gc_dict(self, d, now):
        stale = [k for k, q in list(d.items()) if not q or now - self._first_time(q[-1]) > self.horizon]
        for k in stale: d.pop(k, None)
        if len(d) > 5000:
            oldest = sorted(d.items(), key=lambda kv: self._first_time(kv[1][-1]) if kv[1] else -1)[:len(d)-5000]
            for k, _ in oldest: d.pop(k, None)

    def _gc(self, now):
        if now - self.last_gc < 15: return
        self.last_gc = now
        for d in (self.rate_by_src, self.pair_ports, self.syn_by_dst, self.ack_by_dst,
                  self.horizontal, self.stealth_by_src, self.dns, self.icmp, self.http_fragments):
            self._gc_dict(d, now)
        for d, owner in ((self.pair_port_counts, self.pair_ports), (self.syn_source_counts, self.syn_by_dst)):
            for k, q in list(d.items()):
                if k not in owner or not q: d.pop(k, None)
        for k, q in list(self.horizontal_counts.items()):
            src = k[0]
            if src not in self.horizontal or not q or not any(x[2] == k[1] for x in self.horizontal[src]): self.horizontal_counts.pop(k, None)
        self.cool = {k: t for k, t in self.cool.items() if now - t < 300}
        for k, q in list(self.block_confirm.items()):
            while q and now - q[0] > 120: q.popleft()
            if not q: self.block_confirm.pop(k, None)

    def _alert(self, r, p, evidence, *, block_target=None, confidence='medium'):
        a = Alert(r['id'], r['title'], r['severity'], r['description'], canonical_ip(p.src_ip), canonical_ip(p.dst_ip),
                  evidence, 'ALERT', block_target, confidence)
        # Keep simulation/real telemetry visible in the alert record.
        a.source = p.source
        return a

    def _http_fingerprint(self, p: Packet, now: float) -> str:
        if p.protocol != 'TCP' or p.dst_port not in HTTP_PORTS or not p.payload:
            return ''
        key = (canonical_ip(p.src_ip), canonical_ip(p.dst_ip), p.src_port, p.dst_port)
        q = self.http_fragments[key]
        q.append((now, p.payload[:8192]))
        while q and now - q[0][0] > 5: q.popleft()
        while len(q) > HTTP_MAX_FRAGMENTS_PER_FLOW: q.popleft()
        total = sum(len(x[1]) for x in q)
        while q and total > HTTP_MAX_BYTES_PER_FLOW:
            total -= len(q.popleft()[1])
        return ''.join(x[1] for x in q)

    @staticmethod
    def _event_time(p: Packet) -> float:
        if getattr(p, 'capture_time', 0.0):
            return float(p.capture_time)
        try:
            return datetime.fromisoformat(p.timestamp.replace('Z', '+00:00')).timestamp()
        except Exception:
            return time.time()

    def _confirm_block(self, a: Alert, now: float) -> bool:
        if a.rule_id not in AUTO_BLOCK_RULES: return False
        target = canonical_ip(a.block_target or '')
        key = (a.rule_id, target)
        q = self.block_confirm[key]
        q.append(now)
        while q and now - q[0] > 60: q.popleft()
        return len(q) >= 2

    def inspect(self, p: Packet):
        out, now = [], self._event_time(p)
        src, dst = canonical_ip(p.src_ip), canonical_ip(p.dst_ip)
        trusted_src = self.store.is_trusted(src)
        with self.lock:
            if p.protocol == 'TCP' and 'S' in str(p.flags or '').upper() and 'A' in str(p.flags or '').upper():
                aq = self.ack_by_dst[src]; aq.append(now); self._trim(aq, now, self.horizon, MAX_DETECTOR_STATE_PER_KEY + 100)
            if trusted_src: return out
            self._gc(now); rules = self.rules
            flags = str(p.flags or '').upper()
            is_tcp = p.protocol == 'TCP'
            is_syn = is_tcp and 'S' in flags and 'A' not in flags
            is_stealth = is_tcp and 'A' not in flags and flags in STEALTH_FLAGS


            r = rules.get('NET-002')
            if self._on(r) and is_syn:
                rq = self.rate_by_src[src]; rq.append(now); self._cap_keys(self.rate_by_src, now, keep=src)
                limit = max(MAX_DETECTOR_STATE_PER_KEY, int(r['threshold']) + 20)
                while rq and now - rq[0] > r['window']: rq.popleft()
                while len(rq) > limit: rq.popleft()
                n = len(rq)
                if n >= r['threshold'] and self._once(('NET-002', src), 15, now):
                    out.append(self._alert(r, p, f'{n} TCP SYNs in {r["window"]}s', block_target=src, confidence='medium'))

            if is_syn:
                r = rules.get('NET-001')
                if self._on(r) and p.dst_port is not None:
                    pk = (src, dst); pq = self.pair_ports[pk]; counts = self.pair_port_counts[pk]
                    pq.append((now, p.dst_port)); counts[p.dst_port] += 1
                    self._cap_keys(self.pair_ports, now, keep=pk, companions=(self.pair_port_counts,))
                    limit = max(MAX_DETECTOR_STATE_PER_KEY, int(r['threshold']) + 20)
                    while pq and now - pq[0][0] > r['window']:
                        _, old_port = pq.popleft(); counts[old_port] -= 1
                        if counts[old_port] <= 0: del counts[old_port]
                    while len(pq) > limit:
                        _, old_port = pq.popleft(); counts[old_port] -= 1
                        if counts[old_port] <= 0: del counts[old_port]
                    if len(counts) >= r['threshold'] and self._once(('NET-001', src, dst), 15, now):
                        out.append(self._alert(r, p, f'{len(counts)} unique destination ports on {dst} in {r["window"]}s', block_target=src, confidence='medium'))

                r = rules.get('NET-003')
                if self._on(r):
                    sq = self.syn_by_dst[dst]; sc = self.syn_source_counts[dst]; sq.append((now, src)); sc[src] += 1
                    self._cap_keys(self.syn_by_dst, now, keep=dst, companions=(self.syn_source_counts,))
                    while sq and now - sq[0][0] > r['window']:
                        _, old_src = sq.popleft(); sc[old_src] -= 1
                        if sc[old_src] <= 0: del sc[old_src]
                    limit = max(MAX_DETECTOR_STATE_PER_KEY, int(r['threshold']) + 50)
                    while len(sq) > limit:
                        _, old_src = sq.popleft(); sc[old_src] -= 1
                        if sc[old_src] <= 0: del sc[old_src]
                    aq = self.ack_by_dst[dst]; self._trim(aq, now, r['window'], limit)
                    syns, acks, srcs = len(sq), len(aq), len(sc)
                    ratio_ok = acks == 0 or syns / max(1, acks) >= 3.0
                    if syns >= r['threshold'] and srcs >= 5 and ratio_ok and self._once(('NET-003', dst), 15, now):
                        out.append(self._alert(r, p, f'{syns} SYNs from {srcs} source(s), {acks} SYN/ACKs to {dst} in {r["window"]}s', confidence='low'))

                r = rules.get('NET-004')
                if self._on(r) and p.dst_port is not None:
                    h = self.horizontal[src]; hc = self.horizontal_counts[(src, p.dst_port)]
                    h.append((now, dst, p.dst_port)); hc[dst] += 1
                    self._cap_keys(self.horizontal, now, keep=src)
                    while h and now - h[0][0] > r['window']:
                        _, old_dst, old_port = h.popleft(); c = self.horizontal_counts[(src, old_port)]; c[old_dst] -= 1
                        if c[old_dst] <= 0: del c[old_dst]
                    limit = max(MAX_DETECTOR_STATE_PER_KEY, int(r['threshold']) + 20)
                    while len(h) > limit:
                        _, old_dst, old_port = h.popleft(); c = self.horizontal_counts[(src, old_port)]; c[old_dst] -= 1
                        if c[old_dst] <= 0: del c[old_dst]
                    hosts_count = len(hc)
                    if hosts_count >= r['threshold']:
                        try:
                            scopes = {str(ipaddress.ip_network(f'{d}/24', strict=False)) if ':' not in d else str(ipaddress.ip_network(f'{d}/64', strict=False)) for d in hc}
                        except ValueError:
                            scopes = set()
                    else:
                        scopes = set()
                    if hosts_count >= r['threshold'] and len(scopes) >= 1 and self._once(('NET-004', src, p.dst_port), 30, now):
                        confidence = 'medium' if len(scopes) >= 3 else 'low'
                        out.append(self._alert(r, p, f'{hosts_count} destination hosts across {len(scopes)} network scope(s) on TCP/{p.dst_port}; no automatic block', block_target=src, confidence=confidence))

            r = rules.get('NET-005')
            if self._on(r) and is_stealth:
                sq = self.stealth_by_src[src]; sq.append(now); self._cap_keys(self.stealth_by_src, now, keep=src); self._trim(sq, now, r['window'], max(MAX_DETECTOR_STATE_PER_KEY, int(r['threshold']) + 20))
                stealth = len(sq)
                if stealth >= r['threshold'] and self._once(('NET-005', src), 20, now):
                    out.append(self._alert(r, p, f'{stealth} stealth-style TCP probes in {r["window"]}s; no automatic block', block_target=src, confidence='medium'))

            r = rules.get('ICMP-001')
            if self._on(r) and p.protocol in ('ICMP', 'ICMPv6'):
                iq = self.icmp[src]; iq.append((now,)); self._cap_keys(self.icmp, now, keep=src); self._trim(iq, now, r['window'], max(MAX_DETECTOR_STATE_PER_KEY, int(r['threshold']) + 20))
                if len(iq) >= r['threshold'] and self._once(('ICMP-001', src), 15, now):
                    out.append(self._alert(r, p, f'{len(iq)} ICMP packets in {r["window"]}s; source may be spoofed', block_target=src, confidence='low'))

            r = rules.get('WEB-001')
            if self._on(r) and is_tcp and p.dst_port in HTTP_PORTS:
                text = self._http_fingerprint(p, now)
                if text:
                    matches = list(re.finditer(r'(?im)(?:^|\r?\n)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/1\.[01]\s*(?:\r?\n|$)', text))
                    for idx, match in enumerate(matches):
                        start_i = match.start(); end_i = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
                        request = text[start_i:end_i]
                        target = match.group(2)
                        header_end = request.find('\r\n\r\n')
                        if header_end < 0: header_end = request.find('\n\n')
                        headers = request[:header_end if header_end >= 0 else len(request)]
                        target_decoded = unquote_plus(unquote_plus(target))
                        hit = next((rx.search(target_decoded) for rx in PATTERNS if rx.search(target_decoded)), None)
                        ua = re.search(r'(?im)^User-Agent:\s*([^\r\n]+)', headers)
                        if not hit and ua:
                            hit = SCANNER_UA.search(ua.group(1))
                        if hit and self._once(('WEB-001', src), 30, now):
                            marker = hit.group(0)[:80]
                            out.append(self._alert(r, p, f'matched HTTP request marker {marker!r}; target/User-Agent context verified', block_target=src, confidence='medium'))
                            break

            r = rules.get('DNS-001')
            if self._on(r) and p.protocol in ('UDP','TCP') and p.dst_port == 53 and p.payload:
                qname = p.payload.rstrip('.').lower(); labels = [x for x in qname.split('.') if x]
                if labels:
                    e = entropy(''.join(labels[:-1]) if len(labels) > 1 else labels[0])
                    long_enough = len(qname) >= r['threshold']
                    if long_enough and e >= DNS_MIN_ENTROPY:
                        d = self.dns[src]; d.append((now, qname, e)); self._trim(d, now, r['window'], max(MAX_DETECTOR_STATE_PER_KEY, DNS_MIN_HITS + 20))
                        unique_names = {x[1] for x in d if now - x[0] <= r['window']}
                        if len(unique_names) >= DNS_MIN_HITS and self._once(('DNS-001', src), 30, now):
                            out.append(self._alert(r, p, f'{len(unique_names)} long/high-entropy full DNS query names in {r["window"]}s', block_target=src, confidence='medium'))

            r = rules.get('IOC-001')
            if self._on(r):
                bad_src, bad_dst = self.store.is_blocked(src), self.store.is_blocked(dst)
                if (bad_src or bad_dst) and self._once(('IOC-001', src, dst), 30, now):
                    if bad_src:
                        out.append(self._alert(r, p, 'Source IP is in local blocklist; inline policy marks this packet for drop', block_target=src, confidence='high'))
                    else:
                        out.append(self._alert(r, p, 'Destination IP is in local blocklist (outbound IOC)', block_target=dst, confidence='high'))
        return out

    def process(self, p: Packet, inline=False, auto_block=False, ttl=300, dry_run=True):
        alerts = self.inspect(p); drop = False
        src, dst = canonical_ip(p.src_ip), canonical_ip(p.dst_ip)
        trusted_src, trusted_dst = self.store.is_trusted(src), self.store.is_trusted(dst)
        blocked_src, blocked_dst = self.store.is_blocked(src), self.store.is_blocked(dst)
        if inline and not trusted_src and not trusted_dst and (blocked_src or blocked_dst):
            if dry_run:
                for a in alerts:
                    if a.rule_id == 'IOC-001': a.action = 'WOULD_DROP'
            else:
                drop = True
        for a in alerts:
            if inline and a.rule_id == 'IOC-001':
                a.action = 'WOULD_DROP' if (dry_run or trusted_src or trusted_dst) else 'DROP'
            elif inline and auto_block and a.rule_id in AUTO_BLOCK_RULES and a.severity in ('HIGH','CRITICAL') and a.block_target:
                confirmed = self._confirm_block(a, self._event_time(p)) if a.confidence in ('medium', 'high') else False
                if confirmed:
                    a.confidence = 'high'
                    target = canonical_ip(a.block_target)
                    if (not trusted_src and not trusted_dst and not self.store.is_trusted(target)
                            and not is_protected(target) and dst in cached_local_addrs()):
                        if dry_run:
                            a.action = 'WOULD_DROP'
                        else:
                            key = self.store.block(target, f'Auto-block by {a.rule_id}', ttl, source='auto')
                            if key:
                                a.action, drop = 'DROP', True
            self.store.add_alert(a)
        p.dropped = bool(drop)
        self.store.add_packet(p)
        return alerts, drop

# ----------------------------------------------------------------------------
# Packet parsing
# ----------------------------------------------------------------------------
def _scapy_capture_time(pkt) -> float:
    try: return float(getattr(pkt, 'time'))
    except Exception: return time.time()

def _scapy_timestamp(ts: float) -> str:
    try: return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec='milliseconds')
    except Exception: return utc()

def _has_icmpv6_layer(pkt) -> bool:
    layer = pkt
    seen = 0
    while layer is not None and seen < 64:
        if layer.__class__.__name__.startswith('ICMPv6'):
            return True
        layer = getattr(layer, 'payload', None)
        seen += 1
    return False

def scapy_packet(pkt, source='live') -> Optional[Packet]:
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP): ip = pkt[IP]
        elif pkt.haslayer(IPv6): ip = pkt[IPv6]
        else: return None
        proto, sp, dp, flags, payload = 'IP', None, None, '', ''
        if pkt.haslayer(TCP):
            x = pkt[TCP]; proto, sp, dp, flags = 'TCP', int(x.sport), int(x.dport), str(x.flags)
            raw = bytes(x.payload)
            if dp == 53 or sp == 53:
                try:
                    for dns_raw in ([raw[2:]] if len(raw) >= 14 else []) + [raw]:
                        if not dns_raw: continue
                        d = DNS(dns_raw)
                        qr = d.getlayer(DNSQR)
                        if d.qr == 0 and qr is not None and getattr(qr, 'qname', None):
                            payload = qr.qname.decode('utf-8', 'replace').rstrip('.')
                            break
                except Exception: pass
            elif dp in HTTP_PORTS:
                payload = raw[:8192].decode('utf-8', 'replace')
        elif pkt.haslayer(UDP):
            x = pkt[UDP]; proto, sp, dp = 'UDP', int(x.sport), int(x.dport)
            if (dp == 53 or sp == 53) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                payload = pkt[DNSQR].qname.decode('utf-8', 'replace').rstrip('.')
        elif pkt.haslayer(ICMP): proto = 'ICMP'
        elif _has_icmpv6_layer(pkt): proto = 'ICMPv6'
        ts = _scapy_capture_time(pkt)
        return Packet(_scapy_timestamp(ts), str(ip.src), str(ip.dst), proto, sp, dp, len(pkt), flags, payload, source, False, ts)
    except Exception:
        return None


def parse_raw(data: bytes, source='ips') -> Optional[Packet]:
    """Raw L3 bytes (WinDivert / NFQUEUE) -> Packet, IPv4 or IPv6."""
    if not data:
        return None
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    ver = data[0] >> 4
    if ver == 4:
        return scapy_packet(IP(data), source)
    if ver == 6:
        return scapy_packet(IPv6(data), source)
    return None


# ----------------------------------------------------------------------------
# Workers
# ----------------------------------------------------------------------------
class Worker(QThread):
    packet_batch = pyqtSignal(object)
    alert_batch = pyqtSignal(object)
    status = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, detector: Detector, auto_block=False, ttl=300, dry_run=True):
        super().__init__()
        self.detector, self.auto_block, self.ttl, self.dry_run = detector, auto_block, ttl, dry_run
        self._active_policy = bool(auto_block and not dry_run)
        self._dry_run_policy = bool(dry_run)
        self.stop_event = threading.Event()
        self.capture_queue: queue.Queue[Packet] = queue.Queue(maxsize=20_000)
        self.ui_packets: list[Packet] = []
        self.ui_alerts: list[Alert] = []
        self.last_ui_emit = time.monotonic()
        self.dropped_capture = 0
        self._last_error = defaultdict(lambda: -float('inf'))

    def stop(self): self.stop_event.set()

    def enqueue(self, rec: Packet):
        try: self.capture_queue.put_nowait(rec)
        except queue.Full: self.dropped_capture += 1

    def emit_error(self, message: str, interval=10):
        now = time.monotonic(); last = self._last_error.get(message, -float('inf'))
        if now - last >= interval:
            self._last_error[message] = now; self.error.emit(message)

    def drain(self, limit=500, allow_stopping=False):
        done = 0
        while done < limit and (allow_stopping or not self.stop_event.is_set()):
            try: rec = self.capture_queue.get_nowait()
            except queue.Empty: break
            try: self._process_one(rec, inline=False)
            except Exception as exc: self.emit_error(f'Packet processing failed (fail-open): {exc}')
            done += 1
        self.flush_ui()
        return done

    def _process_one(self, rec: Packet, inline=False) -> bool:
        self.ui_packets.append(rec)
        alerts, drop = self.detector.process(rec, inline, self.auto_block, self.ttl, self.dry_run)
        self.ui_alerts.extend(alerts)
        if len(self.ui_packets) >= 100 or len(self.ui_alerts) >= 20 or time.monotonic() - self.last_ui_emit >= 0.1:
            self.flush_ui()
        return drop

    def flush_ui(self):
        if self.ui_packets:
            self.packet_batch.emit(self.ui_packets); self.ui_packets = []
        if self.ui_alerts:
            self.alert_batch.emit(self.ui_alerts); self.ui_alerts = []
        self.last_ui_emit = time.monotonic()


class LiveWorker(Worker):
    def __init__(self, detector, iface, bpf):
        super().__init__(detector); self.iface, self.bpf = iface or None, bpf or 'ip or ip6'; self.sniffer = None

    def stop(self):
        super().stop()
        try:
            if self.sniffer is not None and self.sniffer.running: self.sniffer.stop(join=False)
        except Exception: pass

    def run(self):
        try:
            from scapy.all import AsyncSniffer
            def cb(x):
                if self.stop_event.is_set(): return
                try:
                    p = scapy_packet(x, 'live')
                    if p: self.enqueue(p)
                except Exception as exc: self.emit_error(f'Packet callback error: {exc}')
            self.sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=cb, store=False)
            self.sniffer.start(); self.status.emit('Live IDS capture started; detection is queued off the capture callback.')
            while not self.stop_event.wait(0.02):
                self.drain(1000)
                if self.stop_event.is_set(): break
                if self.sniffer.thread and not self.sniffer.thread.is_alive():
                    self.error.emit('Capture stopped unexpectedly. Check privileges, Npcap/interface and BPF filter.')
                    break
            try:
                if self.sniffer is not None and self.sniffer.running: self.sniffer.stop(join=True)
            except Exception: pass
            while self.drain(2000, allow_stopping=True): pass
        except Exception as exc:
            if not self.stop_event.is_set(): self.error.emit(f'Live capture failed: {exc}')
        finally:
            if self.dropped_capture: self.status.emit(f'Live capture stopped; dropped capture queue packets: {self.dropped_capture:,}.')
            self.flush_ui()


class SimWorker(Worker):
    def run(self):
        self.status.emit('Simulated traffic active.')
        rnd = random
        web = ['GET /../../etc/passwd HTTP/1.1\r\nHost: demo.local',
               'GET /search?q=1%20UNION%20SELECT%20password HTTP/1.1\r\nHost: demo.local',
               'GET /index.html HTTP/1.1\r\nHost: demo.local']
        try:
            while not self.stop_event.is_set():
                mode = rnd.choices(['normal','scan','horizontal','burst','web','dns','icmp'], [45,12,8,8,10,10,7])[0]
                src, dst = rnd.choice(['10.10.10.10','10.10.10.20','10.10.10.30']), '10.10.10.1'
                if mode == 'scan':
                    for port in rnd.sample(range(20,300),25): self.enqueue(Packet(utc(),src,dst,'TCP',rnd.randint(40000,60000),port,60,'S','', 'simulated'))
                elif mode == 'horizontal':
                    for host in [f'10.10.{rnd.choice([20,21,22,23])}.{x}' for x in rnd.sample(range(10,80),45)]: self.enqueue(Packet(utc(),src,host,'TCP',50000,443,60,'S','', 'simulated'))
                elif mode == 'burst':
                    for _ in range(450): self.enqueue(Packet(utc(),src,dst,'TCP',50000,443,60,'S','', 'simulated'))
                elif mode == 'web': self.enqueue(Packet(utc(),src,dst,'TCP',51000,80,220,'PA',rnd.choice(web),'simulated'))
                elif mode == 'dns':
                    for _ in range(9):
                        name=''.join(rnd.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=45))+'.example.com'
                        self.enqueue(Packet(utc(),src,'8.8.8.8','UDP',53000,53,160,'',name,'simulated'))
                elif mode == 'icmp':
                    for _ in range(260): self.enqueue(Packet(utc(),src,dst,'ICMP',None,None,98,'','', 'simulated'))
                else: self.enqueue(Packet(utc(),src,dst,'TCP',50000,rnd.choice([53,80,443]),rnd.randint(60,900),'A','','simulated'))
                self.drain(2500); self.stop_event.wait(0.12)
        except Exception as exc:
            if not self.stop_event.is_set(): self.error.emit(f'Simulation failed: {exc}')
        finally:
            while self.drain(5000, allow_stopping=True): pass
            if self.dropped_capture: self.status.emit(f'Simulation stopped; dropped queue packets: {self.dropped_capture:,}.')
            self.flush_ui()


class PcapWorker(Worker):
    def __init__(self, detector, path, auto_block=False, ttl=300, dry_run=True):
        super().__init__(detector, auto_block, ttl, dry_run); self.path = path

    def run(self):
        try:
            from scapy.utils import PcapReader
            self.status.emit(f'PCAP replay started: {self.path}')
            pending = 0
            for raw in PcapReader(self.path):
                if self.stop_event.is_set(): break
                rec = scapy_packet(raw, 'pcap')
                if rec:
                    self.enqueue(rec); pending += 1
                    if pending >= 1000:
                        self.drain(1000); pending = 0
            if pending: self.drain(1000)
            while self.drain(5000, allow_stopping=True): pass
            self.status.emit(f'PCAP replay finished; dropped queue packets: {self.dropped_capture:,}.')
        except Exception as exc:
            if not self.stop_event.is_set(): self.error.emit(f'PCAP replay failed: {exc}')
        finally:
            self.flush_ui()

class WinIPS(Worker):
    def __init__(self, detector, flt, auto_block, ttl, dry_run=True):
        super().__init__(detector, auto_block, ttl, dry_run); self.flt, self.w = flt or 'ip or ip6', None

    def stop(self):
        super().stop()
        try:
            if self.w: self.w.close()
        except Exception: pass

    def run(self):
        try: import pydivert
        except Exception as e: self.error.emit(f'PyDivert unavailable: {e}'); return
        try:
            self.w = pydivert.WinDivert(self.flt); self.w.open(); self.status.emit('Windows inline IPS active.')
            while not self.stop_event.is_set():
                try: raw = self.w.recv()
                except OSError: break
                drop = False
                try:
                    rec = parse_raw(bytes(raw.raw))
                    if rec: drop = self._process_one(rec, inline=True)
                except Exception as exc: self.emit_error(f'IPS inspection error (fail-open): {exc}')
                if not drop: self.w.send(raw)
                if time.monotonic() - self.last_ui_emit >= 0.1: self.flush_ui()
        except Exception as e:
            if not self.stop_event.is_set(): self.error.emit(f'Windows IPS failed: {e}')
        finally:
            try:
                if self.w: self.w.close()
            except Exception: pass
            self.flush_ui()


class LinuxIPS(Worker):
    def __init__(self, detector, qnum, auto_block, ttl, dry_run=True):
        super().__init__(detector, auto_block, ttl, dry_run); self.qnum, self.nfq = qnum, None

    def stop(self):
        # Do not unbind from the GUI thread. The worker owns the C extension and unbinds in run().
        super().stop()

    def run(self):
        try: from netfilterqueue import NetfilterQueue
        except Exception as e: self.error.emit(f'NetFilterQueue unavailable: {e}'); return
        def cb(pkt):
            drop = False
            try:
                rec = parse_raw(pkt.get_payload())
                if rec: drop = self._process_one(rec, inline=True)
            except Exception as exc: self.emit_error(f'IPS inspection error (fail-open): {exc}')
            try: pkt.drop() if drop else pkt.accept()
            except Exception as exc: self.emit_error(f'NFQUEUE verdict error: {exc}')
        self.nfq = NetfilterQueue()
        try:
            self.nfq.bind(self.qnum, cb); fd = self.nfq.get_fd(); self.status.emit(f'Linux NFQUEUE IPS active on queue {self.qnum}.')
            while not self.stop_event.is_set():
                ready, _, _ = select.select([fd], [], [], 0.5)
                if ready: self.nfq.run(block=False)
                if time.monotonic() - self.last_ui_emit >= 0.1: self.flush_ui()
        except Exception as e:
            if not self.stop_event.is_set(): self.error.emit(f'Linux IPS failed: {e}')
        finally:
            try:
                if self.nfq: self.nfq.unbind()
            except Exception: pass
            self.flush_ui()

# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
class BlocklistImportWorker(QThread):
    result = pyqtSignal(int, int, str)
    failed = pyqtSignal(str)

    def __init__(self, store, path):
        super().__init__(); self.store, self.path = store, Path(path)

    def run(self):
        try:
            entries, parse_skipped = [], 0
            for raw in self.path.read_text(encoding='utf-8', errors='replace').splitlines():
                if self.isInterruptionRequested(): return
                line = raw.strip()
                if not line or line.startswith('#'): continue
                line = line.split('#', 1)[0].strip()
                reason = ''
                if ';' in line:
                    value, reason = line.split(';', 1); line, reason = value.strip(), reason.strip()
                elif ',' in line:
                    value, reason = line.split(',', 1); line, reason = value.strip(), reason.strip()
                if not line: parse_skipped += 1; continue
                try:
                    entries.append((str(normalize_network(line)), reason or f'Imported from {self.path.name}'))
                except ValueError:
                    parse_skipped += 1
            if self.isInterruptionRequested(): return
            added, skipped = self.store.block_many(entries, source='feed', default_reason=f'Imported from {self.path.name}')
            self.result.emit(added, skipped + parse_skipped, self.path.name)
        except Exception as exc:
            self.failed.emit(str(exc))

class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.store = Store()
        refresh_protection_cache()
        self._protection_stop = threading.Event()
        self._protection_thread = threading.Thread(target=self._protection_loop, name='NetSentinel-Protection', daemon=True)
        self._protection_thread.start()
        self.detector = Detector(self.store)
        self.worker: Optional[Worker] = None
        self.ips: Optional[Worker] = None
        self.zombies: list = []                     # workers that did not stop in time; keep them referenced
        self.count = self.alert_count = self.last_count = 0
        self.dropped_capture = 0
        self._last_error_dialog = defaultdict(lambda: -float('inf'))
        self.import_worker = None
        self.sources: set = set()
        self.recent: deque = deque(maxlen=300)
        self.dirty_packets = self.dirty_alerts = False
        self.block_snapshot: Optional[list] = None
        self.build()
        self.refresh_all()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)

    def _protection_loop(self):
        while not self._protection_stop.wait(30):
            try: refresh_protection_cache()
            except Exception: pass

    # -- layout ----------------------------------------------------------------
    @staticmethod
    def cell(text, editable=False):
        it = QTableWidgetItem(str(text))
        if not editable:
            it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
        return it

    def table(self, headers, editable=False):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setStretchLastSection(True)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        if not editable:
            t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        return t

    def build(self):
        self.setWindowTitle(APP)
        self.resize(1450, 900)
        menu = self.menuBar().addMenu('File')
        import_act = QAction('Import IP/CIDR blocklist', self)
        import_act.triggered.connect(self.import_blocklist)
        menu.addAction(import_act)
        compact_act = QAction('Compact database', self)
        compact_act.triggered.connect(lambda: self.store.compact())
        menu.addAction(compact_act)
        act = QAction('Export alerts (JSON / CSV)', self)
        act.triggered.connect(self.export)
        menu.addAction(act)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self.dashboard(), 'Dashboard')
        self.tabs.addTab(self.packet_tab(), 'Packets')
        self.tabs.addTab(self.alert_tab(), 'Alerts')
        self.tabs.addTab(self.rule_tab(), 'Detection Rules')
        self.tabs.addTab(self.ips_tab(), 'IPS / Blocklist')
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.setStyleSheet('''QMainWindow,QWidget{background:#0b1220;color:#e7edf7}QTabWidget::pane{border:1px solid #26364d}
            QTabBar::tab{background:#121c2d;padding:10px 18px}QTabBar::tab:selected{background:#1c3553}
            QGroupBox{border:1px solid #2b405d;border-radius:8px;margin-top:12px;padding:12px}
            QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 5px}
            QPushButton{background:#1d4ed8;border:0;border-radius:6px;padding:9px 14px}QPushButton:disabled{background:#2a3547;color:#7b8798}
            QLineEdit,QComboBox,QSpinBox,QPlainTextEdit,QTableWidget,QListWidget{background:#0f1928;border:1px solid #2a3c55;border-radius:5px;padding:6px}
            QTableWidget{gridline-color:#22324a}QHeaderView::section{background:#17263a;padding:7px;border:0}
            QMenu{background:#121c2d;border:1px solid #2a3c55}QMenu::item:selected{background:#1c3553}''')

    def card(self, title, label):
        g = QGroupBox(title)
        QVBoxLayout(g).addWidget(label)
        return g

    def dashboard(self):
        w = QWidget()
        root = QVBoxLayout(w)
        g = QGroupBox('Capture control')
        f = QGridLayout(g)
        self.source = QComboBox()
        self.source.addItems(['Live packet capture', 'Simulated traffic', 'PCAP replay'])
        self.iface = QLineEdit()
        self.pcap_path = QLineEdit()
        self.pcap_browse = QPushButton('Browse PCAP')
        self.pcap_browse.clicked.connect(self.choose_pcap)
        self.iface.setPlaceholderText('Interface (blank = default, e.g. eth0)')
        self.bpf = QLineEdit('ip or ip6')
        self.keep_payload = QCheckBox('Save packet payloads to the database (may contain sensitive data)')
        self.keep_payload.toggled.connect(lambda v: setattr(self.store, 'keep_payload', v))
        self.persist_packets = QCheckBox('Persist packet metadata to SQLite (higher I/O; dropped packets are always persisted)')
        self.persist_packets.toggled.connect(lambda v: setattr(self.store, 'persist_packets', v))
        self.start_btn, self.stop_btn = QPushButton('Start IDS'), QPushButton('Stop')
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_ids)
        self.stop_btn.clicked.connect(lambda: self.stop_ids())
        f.addWidget(QLabel('Source'), 0, 0)
        f.addWidget(self.source, 0, 1)
        f.addWidget(QLabel('Interface'), 0, 2)
        f.addWidget(self.iface, 0, 3)
        f.addWidget(QLabel('BPF'), 1, 0)
        f.addWidget(self.bpf, 1, 1, 1, 3)
        f.addWidget(self.keep_payload, 2, 0, 1, 4)
        f.addWidget(self.persist_packets, 3, 0, 1, 4)
        f.addWidget(self.start_btn, 0, 4)
        f.addWidget(self.stop_btn, 1, 4)
        f.addWidget(QLabel('PCAP'), 4, 0)
        f.addWidget(self.pcap_path, 4, 1, 1, 3)
        f.addWidget(self.pcap_browse, 4, 4)
        root.addWidget(g)

        grid = QGridLayout()
        self.lbl_pk, self.lbl_al, self.lbl_us, self.lbl_bl, self.lbl_drop = QLabel('0'), QLabel('0'), QLabel('0'), QLabel('0'), QLabel('0')
        for x in (self.lbl_pk, self.lbl_al, self.lbl_us, self.lbl_bl, self.lbl_drop):
            x.setFont(QFont('Segoe UI', 22, QFont.Weight.Bold))
        for i, (t, x) in enumerate([('Packets', self.lbl_pk), ('Alerts', self.lbl_al), ('Sources', self.lbl_us), ('Blocks', self.lbl_bl), ('Capture queue drops', self.lbl_drop)]):
            grid.addWidget(self.card(t, x), 0, i)
        root.addLayout(grid)

        s = QGroupBox('Engine status')
        sl = QVBoxLayout(s)
        self.engine, self.rate = QLabel('IDS stopped'), QLabel('Packet rate: 0/s')
        sl.addWidget(self.engine)
        sl.addWidget(self.rate)
        root.addWidget(s)

        lg = QGroupBox('Live detection console')
        ll = QVBoxLayout(lg)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(2000)
        ll.addWidget(self.console)
        root.addWidget(lg, 1)
        return w

    def packet_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        self.pt = self.table(['Time', 'Source', 'Destination', 'Proto', 'SPort', 'DPort', 'Len', 'Flags', 'Dropped', 'Origin'])
        l.addWidget(self.pt)
        return w

    def alert_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.addWidget(QLabel('Right-click an alert to acknowledge/close it or block its source.'))
        self.at = self.table(['ID', 'Time', 'Rule', 'Severity', 'Confidence', 'Source', 'Destination', 'Block Target', 'Action', 'Status', 'Source Type', 'Description', 'Evidence'])
        self.at.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.at.customContextMenuRequested.connect(self.alert_menu)
        l.addWidget(self.at)
        return w

    def rule_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.addWidget(QLabel('Detection rules are stored in SQLite. DNS-001 Threshold = minimum full query-name length; NET-004/NET-005 are detection-only by default.'))
        self.rt = self.table(['Enabled', 'Rule', 'Severity', 'Threshold', 'Window (s)', 'Description'], editable=True)
        l.addWidget(self.rt)
        b = QPushButton('Save rule changes')
        b.clicked.connect(self.save_rules)
        l.addWidget(b)
        return w

    def ips_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        g = QGroupBox('Inline prevention')
        f = QFormLayout(g)
        self.ips_on = QCheckBox('Enable inline IPS (safety switch)')
        self.ips_on.toggled.connect(self.safety_changed)
        self.auto_block = QCheckBox('Enable automatic blocking (WEB-001 only, after repeated verified detections)')
        self.dry_run = QCheckBox('Dry-run: report would-block; do not drop blocklisted traffic or add auto-block entries (recommended)')
        self.dry_run.setChecked(True)
        self.ttl = QSpinBox()
        self.ttl.setRange(10, 86400)
        self.ttl.setValue(300)
        self.ttl.setSuffix(' s')
        self.auto_block.toggled.connect(self.runtime_policy_changed)
        self.ttl.valueChanged.connect(self.runtime_policy_changed)
        self.dry_run.toggled.connect(self.runtime_policy_changed)
        self.ips_filter = QLineEdit('ip or ip6')
        self.queue = QSpinBox()
        self.queue.setRange(0, 65535)
        self.queue.setValue(1)
        self.ips_start, self.ips_stop = QPushButton('Start inline IPS'), QPushButton('Stop IPS')
        self.ips_stop.setEnabled(False)
        self.ips_start.clicked.connect(self.start_ips)
        self.ips_stop.clicked.connect(lambda: self.stop_ips())
        f.addRow('Platform', QLabel(platform.system()))
        f.addRow('Safety switch', self.ips_on)
        f.addRow('Prevention policy', self.auto_block)
        f.addRow('Safety mode', self.dry_run)
        f.addRow('Auto-block duration', self.ttl)
        f.addRow('Windows filter', self.ips_filter)
        f.addRow('Linux NFQUEUE', self.queue)
        r = QHBoxLayout()
        r.addWidget(self.ips_start)
        r.addWidget(self.ips_stop)
        f.addRow(r)
        l.addWidget(g)
        note = QLabel('IPS is opt-in and never edits firewall policy itself. Use only on systems you are authorized to control.\n'
                      'Linux: route traffic into the queue yourself, e.g.  sudo iptables -I FORWARD -j NFQUEUE --queue-num 1 --queue-bypass\n'
                      '(use INPUT/OUTPUT instead of FORWARD to protect this host). --queue-bypass makes traffic flow if this program is not running.\n'
                      'Remove the rule when finished:  sudo iptables -D FORWARD -j NFQUEUE --queue-num 1 --queue-bypass\n'
                      'This machine and detected gateway/DNS/DHCP infrastructure are protected from blocking. Trusted sources are not inspected; trusted destinations are still monitored. Dry-run also prevents blocklist drops.')
        note.setWordWrap(True)
        l.addWidget(note)
        tb = QGroupBox('Trusted sources (never alert/block); trusted destinations remain monitored')
        tl = QVBoxLayout(tb)
        tr = QHBoxLayout()
        self.trust_ip, self.trust_reason = QLineEdit(), QLineEdit()
        self.trust_ip.setPlaceholderText('Trusted IP or CIDR')
        self.trust_reason.setPlaceholderText('Reason')
        tadd, trem = QPushButton('Trust'), QPushButton('Remove trusted')
        tadd.clicked.connect(self.add_trusted)
        trem.clicked.connect(self.remove_trusted)
        tr.addWidget(self.trust_ip); tr.addWidget(self.trust_reason); tr.addWidget(tadd); tr.addWidget(trem)
        tl.addLayout(tr)
        self.tlist = QListWidget()
        tl.addWidget(self.tlist)
        l.addWidget(tb)

        b = QGroupBox('Blocklist (single IPs or CIDR ranges)')
        bl = QVBoxLayout(b)
        row = QHBoxLayout()
        self.ip, self.reason = QLineEdit(), QLineEdit()
        self.ip.setPlaceholderText('IP or CIDR, e.g. 203.0.113.7 or 203.0.113.0/24')
        self.reason.setPlaceholderText('Reason')
        add, rem = QPushButton('Add'), QPushButton('Remove selected')
        add.clicked.connect(self.add_block)
        rem.clicked.connect(self.remove_block)
        for x in (self.ip, self.reason, add, rem):
            row.addWidget(x)
        bl.addLayout(row)
        self.blist = QListWidget()
        bl.addWidget(self.blist)
        l.addWidget(b, 1)
        return w

    # -- helpers ---------------------------------------------------------------
    def log(self, s):
        self.console.appendPlainText(f'[{datetime.now().strftime("%H:%M:%S")}] {s}')

    def status(self, s):
        self.engine.setText(s)
        self.statusbar.showMessage(s)
        self.log(s)

    def error(self, s):
        now = time.monotonic(); last = self._last_error_dialog.get(s, -float('inf'))
        if now - last < 30: return
        self._last_error_dialog[s] = now
        self.engine.setText('ERROR: ' + s)
        self.statusbar.showMessage('ERROR: ' + s, 10000)
        self.log('ERROR: ' + s)

    def reset_counters(self):
        self.count = self.alert_count = self.last_count = 0
        self.dropped_capture = 0
        self._last_error_dialog.clear()
        self.sources.clear()
        self.recent.clear()
        self.dirty_packets = self.dirty_alerts = True
        self.detector.reset()

    def connect_worker(self, w: Worker):
        w.packet_batch.connect(self.on_packet_batch)
        w.alert_batch.connect(self.on_alert_batch)
        w.status.connect(self.status)
        w.error.connect(self.error)

    def halt(self, w: Worker) -> bool:
        w.stop()
        if w.wait(4000):
            return True
        if w not in self.zombies:
            self.zombies.append(w)
        self.status('Worker did not stop within 4 seconds; keeping the thread referenced.')
        return False

    # -- worker slots (cheap: no DB, no detection) -------------------------------
    def on_packet_batch(self, batch):
        self.count += len(batch)
        for w in (self.worker, self.ips):
            if w is not None: self.dropped_capture = max(self.dropped_capture, w.dropped_capture)
        for p in batch:
            if len(self.sources) < 100_000:
                self.sources.add(p.src_ip)
            # Do not retain packet payloads in the GUI unless the user explicitly enabled it.
            view = Packet(p.timestamp, p.src_ip, p.dst_ip, p.protocol, p.src_port, p.dst_port, p.length, p.flags,
                          p.payload if self.store.keep_payload else '', p.source, p.dropped, p.capture_time)
            self.recent.append(view)
        self.dirty_packets = True

    def on_alert_batch(self, batch):
        self.alert_count += len(batch)
        self.dirty_alerts = True
        for a in batch:
            self.log(f'{a.severity} {a.rule_id} {a.src_ip} -> {a.dst_ip} | {a.title} | {a.action}')

    def safety_changed(self, enabled):
        if not enabled and self.ips:
            self.status('IPS safety switch disabled; stopping inline IPS.')
            self.stop_ips(quiet=True)
        self.runtime_policy_changed()

    def runtime_policy_changed(self, *_):
        if not self.ips: return
        new_dry = self.dry_run.isChecked()
        new_auto = self.auto_block.isChecked()
        previous_dry = getattr(self.ips, '_dry_run_policy', True)
        previous_active = getattr(self.ips, '_active_policy', False)
        enabling_active = (previous_dry and not new_dry) or (new_auto and not previous_active and not new_dry)
        if enabling_active:
            ans = QMessageBox.question(self, 'Enable active blocking',
                'This changes the running IPS to active blocking. Imported blocklist entries can also drop traffic. Continue?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                self.dry_run.blockSignals(True); self.dry_run.setChecked(True); self.dry_run.blockSignals(False)
                new_dry = True
        self.ips.auto_block = new_auto; self.ips.ttl = self.ttl.value(); self.ips.dry_run = new_dry
        self.ips._dry_run_policy = new_dry
        self.ips._active_policy = new_auto and not new_dry
        self.status(f'Runtime IPS policy updated: auto-block={self.ips.auto_block}, dry-run={self.ips.dry_run}, ttl={self.ips.ttl}s')

    def choose_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open PCAP', '', 'PCAP files (*.pcap *.pcapng);;All files (*)')
        if path: self.pcap_path.setText(path)

    # -- IDS -------------------------------------------------------------------
    def start_ids(self):
        if self.ips:
            QMessageBox.information(self, APP, 'Inline IPS already inspects traffic. Stop it before starting the passive IDS.')
            return
        if self.worker and not self.stop_ids(quiet=True):
            return
        self.detector.load()
        self.reset_counters()
        if self.source.currentIndex() == 0:
            self.worker = LiveWorker(self.detector, self.iface.text().strip(), self.bpf.text().strip())
        elif self.source.currentIndex() == 1:
            self.worker = SimWorker(self.detector)
        else:
            path = self.pcap_path.text().strip()
            if not path or not Path(path).exists():
                QMessageBox.warning(self, APP, 'Choose an existing PCAP/PCAPNG file first.')
                return
            self.worker = PcapWorker(self.detector, path)
        self.connect_worker(self.worker)
        self.worker.finished.connect(self.on_ids_finished)
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_ids(self, quiet=False):
        w = self.worker
        ok = True
        if w:
            ok = self.halt(w)
            if ok:
                self.worker = None
        if ok:
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            if not quiet:
                self.status('IDS stopped.')
        return ok

    def on_ids_finished(self):
        sender = self.sender()
        if isinstance(sender, QThread): sender.wait(0); sender.deleteLater()
        if sender is self.worker:
            self.worker = None
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status('IDS stopped.')

    # -- IPS -------------------------------------------------------------------
    def start_ips(self):
        if not self.ips_on.isChecked():
            QMessageBox.warning(self, 'Safety switch', 'Enable the explicit IPS safety switch first.')
            return
        if self.auto_block.isChecked() and not self.dry_run.isChecked():
            ans = QMessageBox.question(self, 'Enable active blocking',
                                       'Active auto-blocking will add temporary blocklist entries and may interrupt legitimate traffic. Continue?',
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                       QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                return
        if self.worker:
            QMessageBox.information(self, APP, 'Stop the passive IDS first; the IPS inspects traffic itself.')
            return
        if self.ips and not self.stop_ips(quiet=True):
            return
        self.detector.load()
        self.reset_counters()
        auto, ttl, system = self.auto_block.isChecked(), self.ttl.value(), platform.system()
        if system == 'Windows':
            self.ips = WinIPS(self.detector, self.ips_filter.text().strip(), auto, ttl, self.dry_run.isChecked())
        elif system == 'Linux':
            self.ips = LinuxIPS(self.detector, self.queue.value(), auto, ttl, self.dry_run.isChecked())
        else:
            QMessageBox.information(self, 'Platform', 'Inline IPS is implemented for Windows and Linux.')
            return
        self.connect_worker(self.ips)
        self.ips.finished.connect(self.on_ips_finished)
        self.ips.start()
        self.ips_start.setEnabled(False)
        self.ips_stop.setEnabled(True)

    def stop_ips(self, quiet=False):
        w = self.ips
        ok = True
        if w:
            ok = self.halt(w)
            if ok:
                self.ips = None
        if ok:
            self.ips_start.setEnabled(True)
            self.ips_stop.setEnabled(False)
            if not quiet:
                self.status('Inline IPS stopped.')
        return ok

    def on_ips_finished(self):
        sender = self.sender()
        if isinstance(sender, QThread): sender.wait(0); sender.deleteLater()
        if sender is self.ips:
            self.ips = None
            self.ips_start.setEnabled(True)
            self.ips_stop.setEnabled(False)
            self.status('Inline IPS stopped.')

    # -- periodic UI refresh (once a second, only if something changed) -----------
    def tick(self):
        self.store.expire_blocks()
        if self.store._writer_error:
            self.statusbar.showMessage('Database writer error: ' + self.store._writer_error, 5000)
        self.zombies = [z for z in self.zombies if z.isRunning()]
        self.lbl_pk.setText(f'{self.count:,}')
        self.lbl_al.setText(f'{self.alert_count:,}')
        self.lbl_us.setText(f'{len(self.sources):,}')
        block_count = len(self.store._rows)
        blocks = self.store.block_rows(2000)
        self.lbl_bl.setText(f'{block_count:,}')
        self.lbl_drop.setText(f'{self.dropped_capture:,}')
        if self.store.buffer_drops:
            self.statusbar.showMessage(f'Database buffer dropped {self.store.buffer_drops:,} oldest rows while the writer was unavailable.', 5000)
        self.rate.setText(f'Packet rate: {max(0, self.count - self.last_count)}/s')
        self.last_count = self.count
        if self.dirty_packets:
            self.dirty_packets = False
            self.refresh_packets()
        block_snapshot = [(r['ip'], r.get('expires'), r.get('reason'), r.get('source')) for r in blocks]
        if block_snapshot != self.block_snapshot or any(r.get('expires') for r in blocks):
            self.refresh_blocks()
        if self.store.alert_generation > getattr(self, '_seen_alert_generation', -1) or self.dirty_alerts:
            # Only refresh after the writer has committed, eliminating the buffered-alert race.
            if self.store.alert_generation > getattr(self, '_seen_alert_generation', -1):
                self._seen_alert_generation = self.store.alert_generation
                self.dirty_alerts = False
                self.refresh_alerts()

    def refresh_packets(self):
        rows = list(self.recent)[::-1][:150]
        self.pt.setRowCount(len(rows))
        for i, p in enumerate(rows):
            vals = [p.timestamp, p.src_ip, p.dst_ip, p.protocol, p.src_port or '', p.dst_port or '', p.length, p.flags, 'DROP' if p.dropped else '', p.source]
            for j, v in enumerate(vals):
                self.pt.setItem(i, j, self.cell(v))

    def refresh_alerts(self):
        selected_id = None
        selected = self.at.selectedItems() if hasattr(self, 'at') else []
        if selected:
            try:
                selected_id = int(self.at.item(self.at.row(selected[0]), 0).text())
            except Exception:
                selected_id = None
        rows = self.store.alerts(200)
        self.at.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [r['id'], r['timestamp'], r['rule_id'], r['severity'], r.get('confidence',''), r['src_ip'], r['dst_ip'], r.get('block_target') or '', r['action'],
                    r['status'], r.get('source','live'), r['description'], r['evidence']]
            for j, v in enumerate(vals):
                it = self.cell(v if v is not None else '')
                if j == 3 and r['severity'] in ('HIGH', 'CRITICAL'):
                    it.setForeground(QColor('#ff8a65'))
                self.at.setItem(i, j, it)
        if selected_id is not None:
            for i, r in enumerate(rows):
                if r['id'] == selected_id:
                    self.at.selectRow(i)
                    break

    def refresh_rules(self):
        rows = self.store.rules()
        self.rt.setRowCount(len(rows))
        for i, r in enumerate(rows):
            x = QTableWidgetItem()
            x.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            x.setCheckState(Qt.CheckState.Checked if r['enabled'] else Qt.CheckState.Unchecked)
            self.rt.setItem(i, 0, x)
            self.rt.setItem(i, 1, self.cell(r['id']))
            self.rt.setItem(i, 2, self.cell(r['severity'], True))
            self.rt.setItem(i, 3, self.cell(r['threshold'], True))
            self.rt.setItem(i, 4, self.cell(r['window'], True))
            self.rt.setItem(i, 5, self.cell(r['description']))

    def refresh_trusted(self):
        rows = self.store.trusted_rows()
        self.tlist.clear()
        for r in rows:
            it = QListWidgetItem(f"{r['ip']}  -  {r['reason']}")
            it.setData(Qt.ItemDataRole.UserRole, r['ip'])
            self.tlist.addItem(it)

    def refresh_blocks(self):
        rows = self.store.block_rows(2000)
        self.block_snapshot = [(r['ip'], r.get('expires'), r.get('reason'), r.get('source')) for r in rows]
        self.blist.clear()
        for r in rows:
            exp = '' if not r.get('expires') else f" (expires {datetime.fromtimestamp(r['expires']).strftime('%H:%M:%S')})"
            src = r.get('source','manual')
            it = QListWidgetItem(f"{r['ip']}  -  {r['reason']} [{src}]{exp}")
            it.setData(Qt.ItemDataRole.UserRole, r['ip'])
            self.blist.addItem(it)

    def refresh_all(self):
        self.refresh_rules()
        self.refresh_blocks()
        self.refresh_trusted()
        self.refresh_alerts()

    # -- actions ---------------------------------------------------------------
    def save_rules(self):
        rows = self.store.rules()
        try:                                              # validate everything first, then save
            for i, r in enumerate(rows):
                sev = self.rt.item(i, 2).text().strip().upper()
                if sev not in SEVERITIES:
                    raise ValueError(f'{r["id"]}: severity must be one of {", ".join(SEVERITIES)}')
                r['severity'] = sev
                r['enabled'] = int(self.rt.item(i, 0).checkState() == Qt.CheckState.Checked)
                r['threshold'] = max(1, int(self.rt.item(i, 3).text()))
                r['window'] = max(1, int(self.rt.item(i, 4).text()))
        except ValueError as e:
            QMessageBox.warning(self, 'Rules', f'Invalid value - {e}')
            return
        for r in rows:
            self.store.save_rule(r)
        self.detector.load()
        self.log('Detection rules saved.')
        self.refresh_rules()

    def block_target(self, text, reason) -> bool:
        try:
            net = normalize_network(text)
        except ValueError:
            QMessageBox.warning(self, 'Invalid address', 'Enter a valid IPv4/IPv6 address or CIDR range.')
            return False
        if blocks_self(net):
            QMessageBox.warning(self, 'Refused', 'That range includes this machine\'s own address; blocking it would cut you off.')
            return False
        if self.store.overlaps_trusted(str(net)):
            QMessageBox.warning(self, 'Trusted range', 'That target overlaps a trusted address.')
            return False
        if not self.store.block(text, reason or 'Manual block', source='manual'):
            QMessageBox.warning(self, 'Refused', 'The block was rejected because it would affect a protected local address.')
            return False
        self.refresh_blocks()
        return True

    def add_trusted(self):
        text = self.trust_ip.text().strip()
        try:
            net = normalize_network(text)
        except ValueError:
            QMessageBox.warning(self, 'Invalid address', 'Enter a valid IP or CIDR range.')
            return
        if blocks_self(net):
            QMessageBox.information(self, 'Trusted local address', 'This address is already protected as a local address.')
        self.store.trust(text, self.trust_reason.text().strip() or 'Trusted host')
        self.trust_ip.clear(); self.trust_reason.clear(); self.refresh_trusted()

    def remove_trusted(self):
        x = self.tlist.currentItem()
        if x:
            self.store.untrust(x.data(Qt.ItemDataRole.UserRole))
            self.refresh_trusted()

    def add_block(self):
        if self.block_target(self.ip.text(), self.reason.text().strip()):
            self.ip.clear()
            self.reason.clear()

    def remove_block(self):
        x = self.blist.currentItem()
        if x:
            self.store.unblock(x.data(Qt.ItemDataRole.UserRole))
            self.refresh_blocks()

    def alert_menu(self, pos):
        row = self.at.rowAt(pos.y())
        if row < 0:
            return
        aid = int(self.at.item(row, 0).text())
        src = self.at.item(row, 5).text()
        target = self.at.item(row, 7).text().strip() or src
        m = QMenu(self)
        ack, close, blk = m.addAction('Acknowledge'), m.addAction('Close'), m.addAction(f'Block target {target}')
        chosen = m.exec(self.at.viewport().mapToGlobal(pos))
        if chosen == ack:
            self.store.set_alert_status(aid, 'ACK')
        elif chosen == close:
            self.store.set_alert_status(aid, 'CLOSED')
        elif chosen == blk:
            self.block_target(target, f'Blocked from alert #{aid}')
        self.refresh_alerts()

    def import_blocklist(self):
        if self.import_worker and self.import_worker.isRunning():
            self.status('A blocklist import is already running.')
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import blocklist', '', 'Text files (*.txt *.csv);;All files (*)')
        if not path: return
        self.import_worker = BlocklistImportWorker(self.store, path)
        self.import_worker.result.connect(self.on_blocklist_imported)
        self.import_worker.failed.connect(self.on_blocklist_import_failed)
        self.import_worker.finished.connect(self.on_import_finished)
        self.status(f'Importing blocklist in background: {Path(path).name}')
        self.import_worker.start()

    def on_import_finished(self):
        sender = self.sender()
        if isinstance(sender, QThread): sender.wait(0); sender.deleteLater()
        if sender is self.import_worker: self.import_worker = None

    def on_blocklist_imported(self, added, skipped, name):
        self.refresh_blocks()
        self.log(f'Imported {added} entries from {name}; skipped {skipped}.')
        self.status(f'Blocklist import complete: {added} added, {skipped} skipped.')

    def on_blocklist_import_failed(self, message):
        self.error(f'Blocklist import failed: {message}')

    def export(self):
        p, _ = QFileDialog.getSaveFileName(self, 'Export alerts', 'netsentinel_alerts.json', 'JSON (*.json);;CSV (*.csv)')
        if not p:
            return
        rows = self.store.alerts(5000)
        if p.lower().endswith('.csv'):
            with open(p, 'w', newline='', encoding='utf-8') as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ['id'])
                w.writeheader()
                w.writerows(rows)
        else:
            Path(p).write_text(json.dumps(rows, indent=2), encoding='utf-8')
        self.log(f'Exported {len(rows)} alerts to {p}')

    def closeEvent(self, e):
        self.timer.stop(); self._protection_stop.set()
        ids_ok = self.halt(self.worker) if self.worker else True
        ips_ok = self.halt(self.ips) if self.ips else True
        if not ids_ok or not ips_ok:
            ans = QMessageBox.warning(self, APP,
                'A worker is still running. Waiting is safer than destroying a live QThread.',
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel)
            if ans == QMessageBox.StandardButton.Yes:
                # Last-resort exit: stop the writer and flush what it can before terminating.
                try: self.store.close()
                except Exception: pass
                os._exit(2)
            self.timer.start(1000); e.ignore(); return
        if self.import_worker and self.import_worker.isRunning():
            self.import_worker.requestInterruption()
            if not self.import_worker.wait(5000):
                self.status('Waiting for blocklist import to stop before closing.')
                self.timer.start(1000); e.ignore(); return
        self.worker = None; self.ips = None
        self.store.close(); e.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP)
    crash_log = DB_PATH.parent / 'netsentinel-crash.log'
    last_crash_report = {'t': float('-inf')}
    def write_crash(exc_type, exc, tb, thread_name='main'):
        now = time.monotonic(); text = ''.join(traceback.format_exception(exc_type, exc, tb))
        try:
            with crash_log.open('a', encoding='utf-8') as f: f.write(f'\n[{utc()}] [{thread_name}]\n{text}')
            os.chmod(crash_log, 0o600)
        except Exception: pass
        if now - last_crash_report['t'] >= 30:
            last_crash_report['t'] = now
            try: sys.__excepthook__(exc_type, exc, tb)
            except Exception: pass
    def excepthook(exc_type, exc, tb):
        write_crash(exc_type, exc, tb, 'main')
    def thread_excepthook(args):
        write_crash(args.exc_type, args.exc_value, args.exc_traceback, getattr(args.thread, 'name', 'thread'))
    sys.excepthook = excepthook
    threading.excepthook = thread_excepthook
    try:
        w = Main(); w.show(); sys.exit(app.exec())
    except Exception:
        info=sys.exc_info(); excepthook(*info)
        try: QMessageBox.critical(None, APP, f'IDPS failed to start.\n\n{info[1]}\n\nCrash log: {crash_log}')
        except Exception: pass
        raise


if __name__ == '__main__':
    main()