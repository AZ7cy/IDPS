"""SQLite storage with a batched writer thread, blocklist and trusted list."""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections import deque
from pathlib import Path
from typing import Iterable, Optional, Union

from .addresses import PrefixIndex, blocks_self, canonical_ip, normalize_network, parse_address
from .config import (ALERT_BUFFER_MAX, CHECKPOINT_INTERVAL, DB_PATH, MAX_ALERT_ROWS, MAX_PACKET_ROWS,
                     PACKET_BUFFER_MAX, PREVIOUS_RULE_DEFAULTS, RULE_SEED, RULE_VERSION, WRITER_INTERVAL)
from .models import Alert, Packet, redact_evidence, utc
from .secure import restrict_to_owner

SCHEMA = """
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
CREATE TABLE IF NOT EXISTS wifi_known(bssid TEXT PRIMARY KEY,ssid TEXT,security TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS wifi_points(id INTEGER PRIMARY KEY,name TEXT,x REAL,y REAL,timestamp TEXT);
CREATE TABLE IF NOT EXISTS wifi_readings(point_id INTEGER REFERENCES wifi_points(id) ON DELETE CASCADE,
    ssid TEXT,bssid TEXT,rssi INTEGER,signal INTEGER,channel INTEGER,band TEXT,security TEXT);
CREATE INDEX IF NOT EXISTS wifi_readings_point ON wifi_readings(point_id);
"""

# Columns added after the first release: (table, column, definition)
MIGRATED_COLUMNS = [
    ('packets', 'dropped', 'INTEGER DEFAULT 0'),
    ('alerts', 'confidence', "TEXT DEFAULT 'medium'"),
    ('alerts', 'source', "TEXT DEFAULT 'live'"),
    ('alerts', 'block_target', 'TEXT'),
    ('blocklist', 'expires', 'REAL'),
    ('blocklist', 'source', "TEXT DEFAULT 'manual'"),
    ('alerts', 'detail', 'TEXT'),                   # why a signature matched
    ('wifi_points', 'gateway_ms', 'REAL'),          # ping to the router, ms
    ('wifi_points', 'internet_ms', 'REAL'),         # ping to the internet, ms
    ('wifi_points', 'loss', 'REAL'),                # internet packet loss, 0..1
]

INSERT_PACKET = ('INSERT INTO packets(timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length,flags,payload,'
                 'source,dropped) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
INSERT_ALERT = ('INSERT INTO alerts(timestamp,rule_id,title,severity,description,src_ip,dst_ip,evidence,action,'
                'status,confidence,source,block_target,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
UPSERT_BLOCK = ('INSERT INTO blocklist(ip,reason,created_at,expires,source) VALUES(?,?,?,?,?) '
                'ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at,'
                'expires=excluded.expires,source=excluded.source')

# When legacy rows normalize to the same network, keep the most deliberate one.
SOURCE_RANK = {'manual': 3, 'auto': 2, 'feed': 1}
FEED_PREFIX = 'feed:'           # downloaded feeds use source 'feed:<url>'


def source_rank(source: str) -> int:
    return SOURCE_RANK.get(source, 1 if source.startswith(FEED_PREFIX) else 0)


def parse_blocklist_line(raw: str):
    """Parse one blocklist file line into (target, reason).

    Returns None for blank and comment lines. `#` starts a comment; an optional reason follows
    `;` or `,`. `target` may be empty or invalid; callers validate it.
    """
    line = raw.strip()
    if not line or line.startswith('#'):
        return None
    line = line.split('#', 1)[0].strip()
    reason = ''
    for sep in (';', ','):
        if sep in line:
            line, reason = (part.strip() for part in line.split(sep, 1))
            break
    return line, reason


def _configure(conn: sqlite3.Connection):
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA busy_timeout=15000')


class Store:
    """Owns the database. Thread-safe; packet-path lookups do not take the lock."""

    def __init__(self, path: Union[str, os.PathLike] = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._chmod(self.path.parent, 0o700)
        self.lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self.db = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        _configure(self.db)

        self.keep_payload = False
        self.persist_packets = False
        self._packet_buf: deque = deque()
        self._alert_buf: deque = deque()
        self.buffer_drops = 0
        self.alert_generation = 0
        self.blocks_version = 0
        self.writer_error = ''

        self._blocks: dict[str, dict] = {}
        self._block_index = PrefixIndex()
        self._trusted: dict[str, dict] = {}
        self._trusted_nets: tuple = ()
        self._trusted_index = PrefixIndex()

        self._stop = threading.Event()
        self._compact_requested = threading.Event()
        self._compact_done = threading.Event()
        self._last_checkpoint = time.monotonic()

        self._create_schema()
        self._load_blocks()
        self._load_trusted()
        self._secure_files()
        self._writer = threading.Thread(target=self._writer_loop, name='NetSentinel-DB', daemon=True)
        self._writer.start()

    # -- setup -------------------------------------------------------------------
    @staticmethod
    def _chmod(path, mode):
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    def _secure_files(self):
        for suffix in ('', '-wal', '-shm'):
            restrict_to_owner(str(self.path) + suffix)      # Windows: ACL; elsewhere: mode 0600

    def _create_schema(self):
        with self.lock:
            db = self.db
            db.executescript(SCHEMA)
            for table, column, definition in MIGRATED_COLUMNS:
                existing = {r['name'] for r in db.execute(f'PRAGMA table_info({table})')}
                if column not in existing:
                    db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
            db.executemany('INSERT OR IGNORE INTO rules VALUES (?,?,?,?,?,?,?)', RULE_SEED)
            row = db.execute("SELECT value FROM meta WHERE key='rule_version'").fetchone()
            if (int(row[0]) if row else 0) < RULE_VERSION:
                for rid, _title, _sev, _on, threshold, window, _desc in RULE_SEED:
                    for old_threshold, old_window in PREVIOUS_RULE_DEFAULTS.get(rid, ()):
                        db.execute('UPDATE rules SET threshold=?, window=? WHERE id=? AND threshold=? AND window=?',
                                   (threshold, window, rid, old_threshold, old_window))
                db.execute("INSERT INTO meta(key,value) VALUES('rule_version',?) "
                           "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(RULE_VERSION),))
            db.commit()

    # -- writer thread -----------------------------------------------------------
    def _writer_loop(self):
        conn = sqlite3.connect(self.path, timeout=15)
        try:
            _configure(conn)
            while not self._stop.wait(WRITER_INTERVAL):
                self._safe_flush(conn)
                if self._compact_requested.is_set():
                    try:
                        self.flush(conn)
                        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                        conn.execute('PRAGMA optimize')
                        conn.commit()
                        self.writer_error = ''
                    except Exception as exc:
                        self.writer_error = str(exc)
                    finally:
                        self._compact_requested.clear()
                        self._compact_done.set()
            self._safe_flush(conn)
        finally:
            conn.close()

    def _safe_flush(self, conn):
        try:
            self.flush(conn)
        except Exception as exc:
            self.writer_error = str(exc)

    def _push(self, buf: deque, row, limit: int):
        with self.lock:
            if len(buf) >= limit:
                buf.popleft()
                self.buffer_drops += 1
            buf.append(row)

    def add_packet(self, p: Packet):
        if not self.persist_packets and not p.dropped:
            return
        row = (p.timestamp, canonical_ip(p.src_ip), canonical_ip(p.dst_ip), p.protocol, p.src_port, p.dst_port,
               p.length, p.flags, p.payload if self.keep_payload else '', p.source, int(bool(p.dropped)))
        self._push(self._packet_buf, row, PACKET_BUFFER_MAX)

    def add_alert(self, a: Alert):
        evidence = a.evidence if self.keep_payload else redact_evidence(a.evidence)
        row = (utc(), a.rule_id, a.title, a.severity, a.description, canonical_ip(a.src_ip), canonical_ip(a.dst_ip),
               evidence, a.action, 'OPEN', a.confidence, a.source, a.block_target, a.detail or None)
        self._push(self._alert_buf, row, ALERT_BUFFER_MAX)

    def flush(self, conn: Optional[sqlite3.Connection] = None) -> bool:
        """Write buffered rows in one transaction. On failure, re-queue what fits and re-raise."""
        conn = conn or self.db
        with self._flush_lock:
            with self.lock:
                packets, alerts = list(self._packet_buf), list(self._alert_buf)
                self._packet_buf.clear()
                self._alert_buf.clear()
            if not packets and not alerts:
                return False
            try:
                conn.execute('BEGIN')
                if packets:
                    conn.executemany(INSERT_PACKET, packets)
                    conn.execute('DELETE FROM packets WHERE id < (SELECT COALESCE(MAX(id),0) FROM packets) - ?',
                                 (MAX_PACKET_ROWS,))
                if alerts:
                    conn.executemany(INSERT_ALERT, alerts)
                    conn.execute('DELETE FROM alerts WHERE id < (SELECT COALESCE(MAX(id),0) FROM alerts) - ?',
                                 (MAX_ALERT_ROWS,))
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                self._requeue(packets, alerts)
                raise
            if alerts:
                self.alert_generation += 1
            self.writer_error = ''
            if time.monotonic() - self._last_checkpoint > CHECKPOINT_INTERVAL:
                try:
                    conn.execute('PRAGMA wal_checkpoint(PASSIVE)')
                    conn.execute('PRAGMA optimize')
                except sqlite3.Error:
                    pass
                self._last_checkpoint = time.monotonic()
            return True

    def _requeue(self, packets, alerts):
        with self.lock:
            for buf, rows, limit in ((self._packet_buf, packets, PACKET_BUFFER_MAX),
                                     (self._alert_buf, alerts, ALERT_BUFFER_MAX)):
                room = max(0, limit - len(buf))
                keep = rows[-room:] if room else []
                self.buffer_drops += len(rows) - len(keep)
                buf.extendleft(reversed(keep))

    def compact(self) -> bool:
        if not self._writer.is_alive():
            return False
        self._compact_done.clear()
        self._compact_requested.set()
        ok = self._compact_done.wait(10)
        self._secure_files()
        return ok

    def close(self):
        self._stop.set()
        if self._writer.is_alive():
            self._writer.join(timeout=10)
        with self.lock:
            try:
                self.db.close()
            except sqlite3.Error:
                pass
        self._secure_files()

    # -- alerts and rules -------------------------------------------------------
    def _query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, params).fetchall()]

    def _write(self, sql, params=()):
        with self.lock:
            self.db.execute(sql, params)
            self.db.commit()

    def packets(self, limit=150):
        return self._query('SELECT * FROM packets ORDER BY id DESC LIMIT ?', (limit,))

    def alerts(self, limit=200, severity: Optional[str] = None, rule_id: Optional[str] = None,
               status: Optional[str] = None, ip: Optional[str] = None):
        """Newest alerts, optionally filtered. `ip` matches part of src, dst or block target."""
        where, params = [], []
        for column, value in (('severity', severity), ('rule_id', rule_id), ('status', status)):
            if value:
                where.append(f'{column}=?')
                params.append(value)
        if ip:
            pattern = '%' + ip.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
            where.append("(src_ip LIKE ? ESCAPE '\\' OR dst_ip LIKE ? ESCAPE '\\' "
                         "OR block_target LIKE ? ESCAPE '\\')")
            params += [pattern] * 3
        sql = 'SELECT * FROM alerts'
        if where:
            sql += ' WHERE ' + ' AND '.join(where)
        return self._query(sql + ' ORDER BY id DESC LIMIT ?', (*params, limit))

    def alert(self, alert_id: int) -> Optional[dict]:
        rows = self._query('SELECT * FROM alerts WHERE id=?', (alert_id,))
        return rows[0] if rows else None

    def related_packets(self, ip: str, limit=50):
        """Newest stored packets with `ip` as source or destination."""
        key = canonical_ip(ip)
        return self._query('SELECT * FROM packets WHERE src_ip=? OR dst_ip=? ORDER BY id DESC LIMIT ?',
                           (key, key, limit))

    def set_alert_status(self, alert_id: int, status: str):
        self._write('UPDATE alerts SET status=? WHERE id=?', (status, alert_id))

    def rules(self):
        return self._query('SELECT * FROM rules ORDER BY id')

    def save_rule(self, r):
        self._write('UPDATE rules SET enabled=?,severity=?,threshold=?,window=? WHERE id=?',
                    (r['enabled'], r['severity'], r['threshold'], r['window'], r['id']))

    # -- blocklist ---------------------------------------------------------------
    def _load_blocks(self):
        with self.lock:
            merged: dict[str, dict] = {}
            for row in self.db.execute('SELECT * FROM blocklist ORDER BY ip').fetchall():
                try:
                    key = str(normalize_network(row['ip']))
                except ValueError:
                    continue
                entry = {'ip': key, 'reason': row['reason'] or '', 'created_at': row['created_at'] or utc(),
                         'expires': row['expires'], 'source': row['source'] or 'manual'}
                current = merged.get(key)
                if current is None or source_rank(entry['source']) > source_rank(current['source']):
                    merged[key] = entry
            try:
                self.db.execute('BEGIN')
                self.db.execute('DELETE FROM blocklist')
                self.db.executemany('INSERT INTO blocklist(ip,reason,created_at,expires,source) VALUES(?,?,?,?,?)',
                                    [self._block_values(e) for e in merged.values()])
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self._blocks = merged
            self._reindex_blocks()

    @staticmethod
    def _block_values(e):
        return (e['ip'], e['reason'], e['created_at'], e['expires'], e['source'])

    def _reindex_blocks(self):
        self._block_index = PrefixIndex(normalize_network(k) for k in self._blocks)
        self.blocks_version += 1

    def is_blocked(self, ip: str) -> bool:
        addr = parse_address(ip)
        return addr is not None and self._block_index.contains(addr)

    def overlaps_trusted(self, target) -> bool:
        try:
            net = target if hasattr(target, 'prefixlen') else normalize_network(target)
        except ValueError:
            return False
        return any(net.version == t.version and net.overlaps(t) for t in self._trusted_nets)

    def block(self, target: str, reason: str, ttl: Optional[int] = None, source='manual') -> Optional[str]:
        """Add or update a block. Returns the normalized key, or None if invalid or unsafe."""
        try:
            net = normalize_network(target)
        except ValueError:
            return None
        if blocks_self(net) or self.overlaps_trusted(net):
            return None
        key = str(net)
        expires = time.time() + ttl if ttl else None
        with self.lock:
            existing = self._blocks.get(key)
            if existing and existing['expires'] is None:
                if source != 'manual':
                    return key          # never downgrade a permanent block
                expires = None
            entry = {'ip': key, 'reason': reason, 'created_at': utc(), 'expires': expires, 'source': source}
            self.db.execute(UPSERT_BLOCK, self._block_values(entry))
            self.db.commit()
            self._blocks[key] = entry
            self._reindex_blocks()
        return key

    def _accept(self, entries: Iterable[tuple[str, str]], source: str,
                default_reason: str) -> tuple[dict[str, dict], int]:
        """Safety filter for bulk entries. Returns ({key: entry}, skipped).

        Skips invalid networks, duplicates, anything covering a protected or trusted address, and keys
        that are already manual or automatic blocks.
        """
        with self.lock:
            existing = {k: v['source'] for k, v in self._blocks.items()}
        trusted = self._trusted_nets
        now = utc()
        accepted: dict[str, dict] = {}
        skipped = 0
        for target, reason in entries:
            try:
                net = normalize_network(target)
            except ValueError:
                skipped += 1
                continue
            key = str(net)
            unsafe = blocks_self(net) or any(t.version == net.version and net.overlaps(t) for t in trusted)
            if unsafe or key in accepted or existing.get(key) in ('manual', 'auto'):
                skipped += 1
                continue
            accepted[key] = {'ip': key, 'reason': reason or default_reason, 'created_at': now,
                             'expires': None, 'source': source}
        return accepted, skipped

    def feed_keys(self, source: str) -> set:
        """Blocklist keys currently stored for one feed."""
        with self.lock:
            return {k for k, e in self._blocks.items() if e['source'] == source}

    def replace_feed(self, source: str, entries: Iterable[tuple[str, str]],
                     default_reason='Blocklist feed') -> tuple[int, int, int]:
        """Make the entries with `source` exactly the accepted `entries`. Returns (stored, removed, skipped)."""
        accepted, skipped = self._accept(entries, source, default_reason)
        with self.lock:
            stale = [k for k, e in self._blocks.items() if e['source'] == source and k not in accepted]
            try:
                self.db.execute('BEGIN')
                self.db.executemany('DELETE FROM blocklist WHERE ip=?', [(k,) for k in stale])
                self.db.executemany(UPSERT_BLOCK, [self._block_values(e) for e in accepted.values()])
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            for k in stale:
                del self._blocks[k]
            self._blocks.update(accepted)
            self._reindex_blocks()
        return len(accepted), len(stale), skipped

    def remove_feeds_except(self, sources: Iterable[str]) -> int:
        """Delete entries from downloaded feeds whose source is not in `sources`. Returns the count."""
        keep = set(sources)
        with self.lock:
            dead = [k for k, e in self._blocks.items()
                    if e['source'].startswith(FEED_PREFIX) and e['source'] not in keep]
            if dead:
                self.db.executemany('DELETE FROM blocklist WHERE ip=?', [(k,) for k in dead])
                self.db.commit()
                for k in dead:
                    del self._blocks[k]
                self._reindex_blocks()
        return len(dead)

    def block_many(self, entries: Iterable[tuple[str, str]], source='feed',
                   default_reason='Imported blocklist') -> tuple[int, int]:
        """Bulk import. Returns (added, skipped)."""
        accepted, skipped = self._accept(entries, source, default_reason)
        if not accepted:
            return 0, skipped
        with self.lock:
            try:
                self.db.execute('BEGIN')
                self.db.executemany(UPSERT_BLOCK, [self._block_values(e) for e in accepted.values()])
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            self._blocks.update(accepted)
            self._reindex_blocks()
        return len(accepted), skipped

    def unblock(self, key: str):
        try:
            key = str(normalize_network(key))
        except ValueError:
            return
        with self.lock:
            self.db.execute('DELETE FROM blocklist WHERE ip=?', (key,))
            self.db.commit()
            if self._blocks.pop(key, None) is not None:
                self._reindex_blocks()

    def expire_blocks(self) -> list[str]:
        now = time.time()
        with self.lock:
            dead = [k for k, e in self._blocks.items() if e['expires'] and e['expires'] < now]
            if dead:
                self.db.executemany('DELETE FROM blocklist WHERE ip=?', [(k,) for k in dead])
                self.db.commit()
                for k in dead:
                    del self._blocks[k]
                self._reindex_blocks()
        return dead

    def block_count(self) -> int:
        return len(self._blocks)

    def blocks(self) -> list[str]:
        with self.lock:
            return sorted(self._blocks)

    def block_rows(self, limit: Optional[int] = None) -> list[dict]:
        with self.lock:
            keys = sorted(self._blocks)
            if limit is not None:
                keys = keys[:max(0, int(limit))]
            return [dict(self._blocks[k]) for k in keys]

    # -- trusted hosts ---------------------------------------------------------
    def _load_trusted(self):
        with self.lock:
            rows = self.db.execute('SELECT * FROM trusted ORDER BY ip').fetchall()
            self._trusted = {str(r['ip']): dict(r) for r in rows}
            self._reindex_trusted()

    def _reindex_trusted(self):
        nets = []
        for key in self._trusted:
            try:
                nets.append(normalize_network(key))
            except ValueError:
                pass
        self._trusted_index = PrefixIndex(nets)
        self._trusted_nets = tuple(nets)

    def is_trusted(self, ip: str) -> bool:
        addr = parse_address(ip)
        return addr is not None and self._trusted_index.contains(addr)

    def trust(self, target: str, reason='Trusted host') -> Optional[str]:
        try:
            key = str(normalize_network(target))
        except ValueError:
            return None
        entry = {'ip': key, 'reason': reason, 'created_at': utc()}
        with self.lock:
            self.db.execute('INSERT OR REPLACE INTO trusted(ip,reason,created_at) VALUES(?,?,?)',
                            (key, reason, entry['created_at']))
            self.db.commit()
            self._trusted[key] = entry
            self._reindex_trusted()
        return key

    def untrust(self, key: str):
        try:
            key = str(normalize_network(key))
        except ValueError:
            key = str(key)
        with self.lock:
            self.db.execute('DELETE FROM trusted WHERE ip=?', (key,))
            self.db.commit()
            self._trusted.pop(key, None)
            self._reindex_trusted()

    def trusted_rows(self) -> list[dict]:
        with self.lock:
            return [dict(self._trusted[k]) for k in sorted(self._trusted)]

    # -- Wi-Fi: trusted access points and survey points ---------------------------
    def wifi_known(self) -> dict[str, dict]:
        """Trusted access points: bssid -> row."""
        return {r['bssid']: r for r in self._query('SELECT * FROM wifi_known ORDER BY ssid, bssid')}

    def trust_access_points(self, aps) -> int:
        """Trust (or refresh) these access points. Returns how many were stored."""
        rows = [(a.bssid, a.ssid, a.security, utc()) for a in aps if a.bssid]
        with self.lock:
            self.db.executemany('INSERT INTO wifi_known(bssid,ssid,security,created_at) VALUES(?,?,?,?) '
                                'ON CONFLICT(bssid) DO UPDATE SET ssid=excluded.ssid,security=excluded.security',
                                rows)
            self.db.commit()
        return len(rows)

    def untrust_access_point(self, bssid: str):
        self._write('DELETE FROM wifi_known WHERE bssid=?', (bssid,))

    def add_wifi_point(self, name: str, x: Optional[float], y: Optional[float], aps,
                       latency: Optional[dict] = None) -> int:
        """Store one survey point, the access points heard there and its ping results. Returns the point id."""
        lat = latency or {}
        with self.lock:
            cur = self.db.execute('INSERT INTO wifi_points(name,x,y,timestamp,gateway_ms,internet_ms,loss) '
                                  'VALUES(?,?,?,?,?,?,?)',
                                  (name, x, y, utc(), lat.get('gateway_ms'), lat.get('internet_ms'),
                                   lat.get('loss') if latency else None))
            point_id = int(cur.lastrowid or 0)
            self.db.executemany('INSERT INTO wifi_readings(point_id,ssid,bssid,rssi,signal,channel,band,security) '
                                'VALUES(?,?,?,?,?,?,?,?)',
                                [(point_id, a.ssid, a.bssid, a.rssi, a.signal, a.channel, a.band, a.security)
                                 for a in aps])
            self.db.commit()
        return point_id

    def wifi_points(self) -> list[dict]:
        return self._query('SELECT * FROM wifi_points ORDER BY id')

    def wifi_readings(self, point_id: Optional[int] = None) -> list[dict]:
        if point_id is None:
            return self._query('SELECT * FROM wifi_readings ORDER BY point_id, rssi DESC')
        return self._query('SELECT * FROM wifi_readings WHERE point_id=? ORDER BY rssi DESC', (point_id,))

    def delete_wifi_point(self, point_id: int):
        with self.lock:
            self.db.execute('DELETE FROM wifi_readings WHERE point_id=?', (point_id,))
            self.db.execute('DELETE FROM wifi_points WHERE id=?', (point_id,))
            self.db.commit()

    def clear_wifi_survey(self):
        with self.lock:
            self.db.execute('DELETE FROM wifi_readings')
            self.db.execute('DELETE FROM wifi_points')
            self.db.commit()
