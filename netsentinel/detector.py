"""Detection engine: sliding-window state, rule checks and inline policy."""
from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import unquote_plus

from .addresses import PROTECTED, canonical_ip, is_protected
from .config import (AUTO_BLOCK_CONFIRM_WINDOW, AUTO_BLOCK_CONFIRMATIONS, AUTO_BLOCK_RULES, COOLDOWN_RETENTION,
                     DNS_MIN_ENTROPY, DNS_MIN_HITS, GC_INTERVAL, HTTP_FRAGMENT_SECONDS, HTTP_MAX_BYTES_PER_FLOW,
                     HTTP_MAX_FRAGMENTS_PER_FLOW, HTTP_PAYLOAD_MAX, HTTP_PORTS, HTTP_REQUEST_LINE, IGNORED_MACS,
                     LOGIN_PORTS, MAX_EVENTS_PER_KEY, MAX_KEYS_PER_TABLE, MIN_STATE_HORIZON, PATTERNS, SCANNER_UA,
                     SIG_RULE_ID, SIG_TIMEOUT_RULE_ID, STEALTH_FLAGS, SYN_FLOOD_MIN_RATIO, SYN_FLOOD_MIN_SOURCES, TLS_MIN_HITS,
                     UDP_SCAN_MAX_PORT, USER_AGENT_HEADER, WIFI_RULE_PREFIX)
from .models import Alert, Packet
from .signatures import RuleSet, explain_match, rule_key
from .store import Store


def entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def event_time(p: Packet) -> float:
    if p.capture_time:
        return float(p.capture_time)
    try:
        return datetime.fromisoformat(p.timestamp.replace('Z', '+00:00')).timestamp()
    except (ValueError, AttributeError):
        return time.time()


# ----------------------------------------------------------------------------
# State containers
# ----------------------------------------------------------------------------
class EventWindow:
    """Time-ordered events with an in-sync count of distinct keys."""
    __slots__ = ('events', 'counts')

    def __init__(self):
        self.events: deque = deque()
        self.counts: Counter = Counter()

    def add(self, t: float, key=None):
        self.events.append((t, key))
        if key is not None:
            self.counts[key] += 1

    def _pop(self):
        _, key = self.events.popleft()
        if key is not None:
            self.counts[key] -= 1
            if self.counts[key] <= 0:
                del self.counts[key]

    def trim(self, now: float, span: float, cap: int):
        while self.events and now - self.events[0][0] > span:
            self._pop()
        while len(self.events) > max(1, cap):
            self._pop()

    def __len__(self):
        return len(self.events)

    def unique(self) -> int:
        return len(self.counts)

    @property
    def last_time(self) -> float:
        return self.events[-1][0] if self.events else -math.inf


class FlowBuffer:
    """Recent HTTP payload fragments for one TCP flow."""
    __slots__ = ('fragments', 'size')

    def __init__(self):
        self.fragments: deque = deque()
        self.size = 0

    def add(self, t: float, text: str):
        self.fragments.append((t, text))
        self.size += len(text)

    def _pop(self):
        self.size -= len(self.fragments.popleft()[1])

    def trim(self, now: float):
        while self.fragments and now - self.fragments[0][0] > HTTP_FRAGMENT_SECONDS:
            self._pop()
        while self.fragments and (len(self.fragments) > HTTP_MAX_FRAGMENTS_PER_FLOW
                                  or self.size > HTTP_MAX_BYTES_PER_FLOW):
            self._pop()

    def text(self) -> str:
        return ''.join(x[1] for x in self.fragments)

    @property
    def last_time(self) -> float:
        return self.fragments[-1][0] if self.fragments else -math.inf


class BoundedMap:
    """Key -> state map capped at `cap` keys, evicting the least recently touched.

    `touch()` moves the key to the end before evicting from the front, so the key being
    updated is never the one evicted.
    """

    def __init__(self, factory: Callable, cap: int = MAX_KEYS_PER_TABLE):
        self._items: OrderedDict = OrderedDict()
        self._factory = factory
        self.cap = max(1, cap)

    def touch(self, key):
        value = self._items.get(key)
        if value is None:
            value = self._factory()
            self._items[key] = value
        else:
            self._items.move_to_end(key)
        while len(self._items) > self.cap:
            self._items.popitem(last=False)
        return value

    def get(self, key):
        return self._items.get(key)

    def prune(self, is_stale: Callable) -> None:
        for key in [k for k, v in self._items.items() if is_stale(v)]:
            del self._items[key]

    def clear(self):
        self._items.clear()

    def __len__(self):
        return len(self._items)

    def __contains__(self, key):
        return key in self._items


@dataclass(slots=True)
class _Event:
    packet: Packet
    now: float
    src: str
    dst: str
    flags: str
    is_tcp: bool

    @property
    def is_syn(self) -> bool:
        return self.is_tcp and 'S' in self.flags and 'A' not in self.flags

    @property
    def is_synack(self) -> bool:
        return self.is_tcp and 'S' in self.flags and 'A' in self.flags

    @property
    def is_stealth(self) -> bool:
        return self.is_tcp and 'A' not in self.flags and self.flags in STEALTH_FLAGS


def _per_key_cap(rule, extra=20) -> int:
    return max(MAX_EVENTS_PER_KEY, int(rule['threshold']) + extra)


def _network_scope(ip: str) -> Optional[str]:
    try:
        prefix = 64 if ':' in ip else 24
        return str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))
    except ValueError:
        return None


def _dga_like(name: str, min_len: int) -> bool:
    """True for a long name whose labels (without the top-level domain) look random.

    Shared by DNS-001 (query names) and TLS-001 (TLS server names).
    """
    labels = [x for x in name.split('.') if x]
    if not labels or len(name) < min_len:
        return False
    return entropy(''.join(labels[:-1]) if len(labels) > 1 else labels[0]) >= DNS_MIN_ENTROPY


def _http_requests(text: str):
    """Yield (target, headers) for each HTTP/1.x request found in the reassembled text."""
    matches = list(HTTP_REQUEST_LINE.finditer(text))
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        request = text[match.start():end]
        header_end = request.find('\r\n\r\n')
        if header_end < 0:
            header_end = request.find('\n\n')
        yield match.group(2), request if header_end < 0 else request[:header_end]


def _suspicious_marker(target: str, headers: str) -> Optional[str]:
    decoded = unquote_plus(unquote_plus(target))
    for rx in PATTERNS:
        m = rx.search(decoded)
        if m:
            return m.group(0)
    ua = USER_AGENT_HEADER.search(headers)
    if ua:
        m = SCANNER_UA.search(ua.group(1))
        if m:
            return m.group(0)
    return None


# ----------------------------------------------------------------------------
# Detector
# ----------------------------------------------------------------------------
class Detector:
    def __init__(self, store: Store):
        self.store = store
        self.lock = threading.RLock()
        self.rules: dict = {}
        self.horizon = MIN_STATE_HORIZON
        self.signatures: Optional[RuleSet] = None
        self.sig_hits: Counter = Counter()      # rule_key -> SIG-001 alerts raised; kept across rule reloads
        self.sig_hits_version = 0               # bumped on every hit, so the GUI knows when to refresh
        self._init_state()
        self.load()

    def _init_state(self):
        self.syn_rate = BoundedMap(EventWindow)      # NET-002: src
        self.port_scan = BoundedMap(EventWindow)     # NET-001: (src, dst) -> dst ports
        self.syn_to_dst = BoundedMap(EventWindow)    # NET-003: dst -> sources
        self.synack_from = BoundedMap(EventWindow)   # NET-003: SYN/ACKs sent by a server
        self.horizontal = BoundedMap(EventWindow)    # NET-004: (src, dst port) -> dst hosts
        self.stealth = BoundedMap(EventWindow)       # NET-005: src
        self.icmp = BoundedMap(EventWindow)          # ICMP-001: src
        self.dns = BoundedMap(EventWindow)           # DNS-001: src -> query names
        self.http_flows = BoundedMap(FlowBuffer)     # WEB-001: (src, dst, sport, dport)
        self.arp = BoundedMap(EventWindow)           # ARP-001: claimed IP -> sender MACs
        self.auth = BoundedMap(EventWindow)          # AUTH-001: (src, dst, port) -> source ports
        self.udp_scan = BoundedMap(EventWindow)      # NET-006: (src, dst) -> dst ports
        self.tls = BoundedMap(EventWindow)           # TLS-001: src -> server names
        self.cooldowns: dict = {}
        self.block_confirm: dict = {}
        self.last_gc = -math.inf

    def _tables(self):
        return (self.syn_rate, self.port_scan, self.syn_to_dst, self.synack_from, self.horizontal,
                self.stealth, self.icmp, self.dns, self.http_flows, self.arp, self.auth, self.udp_scan, self.tls)

    def load(self):
        rules = {r['id']: r for r in self.store.rules()}
        with self.lock:
            self.rules = rules
            # Wi-Fi rules have long windows but keep no packet state, so they do not set the horizon.
            self.horizon = max([MIN_STATE_HORIZON] + [int(r['window']) for r in rules.values()
                                                      if not r['id'].startswith(WIFI_RULE_PREFIX)])

    def reset(self):
        with self.lock:
            self._init_state()
            if self.signatures is not None:
                self.signatures.reset_state()

    def set_signatures(self, rule_set: Optional[RuleSet]):
        """Replace the active Snort/Suricata rule set (None to remove it)."""
        with self.lock:
            self.signatures = rule_set

    # -- helpers ---------------------------------------------------------------
    def _rule(self, rule_id):
        r = self.rules.get(rule_id)
        return r if r and r['enabled'] else None

    def _cooldown(self, key, seconds: float, now: float) -> bool:
        """True (and starts the cooldown) if `key` has not fired within `seconds`."""
        if now - self.cooldowns.get(key, -math.inf) < seconds:
            return False
        self.cooldowns[key] = now
        return True

    @staticmethod
    def _alert(r, e: _Event, evidence: str, block_target=None, confidence='medium') -> Alert:
        return Alert(r['id'], r['title'], r['severity'], r['description'], e.src, e.dst, evidence,
                     'ALERT', block_target, confidence, e.packet.source)

    def _collect_garbage(self, now: float):
        if now - self.last_gc < GC_INTERVAL:
            return
        self.last_gc = now
        cutoff = now - self.horizon
        for table in self._tables():
            table.prune(lambda state: state.last_time < cutoff)
        self.cooldowns = {k: t for k, t in self.cooldowns.items() if now - t < COOLDOWN_RETENTION}
        if self.signatures is not None:
            self.signatures.prune(now)
        for key in list(self.block_confirm):
            q = self.block_confirm[key]
            while q and now - q[0] > 2 * AUTO_BLOCK_CONFIRM_WINDOW:
                q.popleft()
            if not q:
                del self.block_confirm[key]

    # -- inspection --------------------------------------------------------------
    def inspect(self, p: Packet) -> list[Alert]:
        e = _Event(p, event_time(p), canonical_ip(p.src_ip), canonical_ip(p.dst_ip),
                   str(p.flags or '').upper(), p.protocol == 'TCP')
        out: list[Alert] = []
        with self.lock:
            if e.is_synack:
                # Counted even for trusted servers so NET-003 sees real handshake replies.
                w = self.synack_from.touch(e.src)
                w.add(e.now)
                w.trim(e.now, self.horizon, MAX_EVENTS_PER_KEY + 100)
            if p.protocol == 'ARP':
                # Checked even for trusted addresses: claiming a trusted IP is the attack.
                self._collect_garbage(e.now)
                self._check_arp(e, out)
                return out
            if self.store.is_trusted(e.src):
                return out
            self._collect_garbage(e.now)
            for check in (self._check_syn_burst, self._check_port_scan, self._check_syn_flood,
                          self._check_horizontal, self._check_stealth, self._check_icmp,
                          self._check_web, self._check_dns, self._check_ioc, self._check_auth,
                          self._check_udp_scan, self._check_tls, self._check_signatures):
                check(e, out)
        return out

    def _check_syn_burst(self, e: _Event, out: list):
        r = self._rule('NET-002')
        if not r or not e.is_syn:
            return
        w = self.syn_rate.touch(e.src)
        w.add(e.now)
        w.trim(e.now, r['window'], _per_key_cap(r))
        if len(w) >= r['threshold'] and self._cooldown(('NET-002', e.src), 15, e.now):
            out.append(self._alert(r, e, f'{len(w)} TCP SYNs in {r["window"]}s', block_target=e.src))

    def _check_port_scan(self, e: _Event, out: list):
        r = self._rule('NET-001')
        port = e.packet.dst_port
        if not r or not e.is_syn or port is None:
            return
        w = self.port_scan.touch((e.src, e.dst))
        w.add(e.now, port)
        w.trim(e.now, r['window'], _per_key_cap(r))
        ports = w.unique()
        if ports >= r['threshold'] and self._cooldown(('NET-001', e.src, e.dst), 15, e.now):
            out.append(self._alert(r, e, f'{ports} unique destination ports on {e.dst} in {r["window"]}s',
                                   block_target=e.src))

    def _check_syn_flood(self, e: _Event, out: list):
        r = self._rule('NET-003')
        if not r or not e.is_syn:
            return
        cap = _per_key_cap(r, 50)
        w = self.syn_to_dst.touch(e.dst)
        w.add(e.now, e.src)
        w.trim(e.now, r['window'], cap)
        replies = self.synack_from.get(e.dst)
        acks = 0
        if replies is not None:
            replies.trim(e.now, r['window'], cap)
            acks = len(replies)
        syns, sources = len(w), w.unique()
        ratio_ok = acks == 0 or syns / acks >= SYN_FLOOD_MIN_RATIO
        if (syns >= r['threshold'] and sources >= SYN_FLOOD_MIN_SOURCES and ratio_ok
                and self._cooldown(('NET-003', e.dst), 15, e.now)):
            # Sources may be spoofed, so this rule never names a block target.
            out.append(self._alert(r, e, f'{syns} SYNs from {sources} source(s), {acks} SYN/ACKs to {e.dst} '
                                         f'in {r["window"]}s', confidence='low'))

    def _check_horizontal(self, e: _Event, out: list):
        r = self._rule('NET-004')
        port = e.packet.dst_port
        if not r or not e.is_syn or port is None:
            return
        w = self.horizontal.touch((e.src, port))
        w.add(e.now, e.dst)
        w.trim(e.now, r['window'], _per_key_cap(r))
        hosts = w.unique()
        if hosts < r['threshold']:
            return
        scopes = {s for s in map(_network_scope, w.counts) if s}
        if scopes and self._cooldown(('NET-004', e.src, port), 30, e.now):
            confidence = 'medium' if len(scopes) >= 3 else 'low'
            out.append(self._alert(r, e, f'{hosts} destination hosts across {len(scopes)} network scope(s) on '
                                         f'TCP/{port}; no automatic block', block_target=e.src,
                                   confidence=confidence))

    def _check_stealth(self, e: _Event, out: list):
        r = self._rule('NET-005')
        if not r or not e.is_stealth:
            return
        w = self.stealth.touch(e.src)
        w.add(e.now)
        w.trim(e.now, r['window'], _per_key_cap(r))
        if len(w) >= r['threshold'] and self._cooldown(('NET-005', e.src), 20, e.now):
            out.append(self._alert(r, e, f'{len(w)} stealth-style TCP probes in {r["window"]}s; no automatic block',
                                   block_target=e.src))

    def _check_icmp(self, e: _Event, out: list):
        r = self._rule('ICMP-001')
        if not r or e.packet.protocol not in ('ICMP', 'ICMPv6'):
            return
        w = self.icmp.touch(e.src)
        w.add(e.now)
        w.trim(e.now, r['window'], _per_key_cap(r))
        if len(w) >= r['threshold'] and self._cooldown(('ICMP-001', e.src), 15, e.now):
            out.append(self._alert(r, e, f'{len(w)} ICMP packets in {r["window"]}s; source may be spoofed',
                                   block_target=e.src, confidence='low'))

    def _check_web(self, e: _Event, out: list):
        r = self._rule('WEB-001')
        p = e.packet
        if not r or not e.is_tcp or p.dst_port not in HTTP_PORTS or not p.payload:
            return
        flow = self.http_flows.touch((e.src, e.dst, p.src_port, p.dst_port))
        flow.add(e.now, p.payload[:HTTP_PAYLOAD_MAX])
        flow.trim(e.now)
        for target, headers in _http_requests(flow.text()):
            marker = _suspicious_marker(target, headers)
            if marker:
                if self._cooldown(('WEB-001', e.src), 30, e.now):
                    out.append(self._alert(r, e, f'matched HTTP request marker {marker[:80]!r}; '
                                                 'target/User-Agent context verified', block_target=e.src))
                return

    def _check_dns(self, e: _Event, out: list):
        r = self._rule('DNS-001')
        p = e.packet
        if not r or p.protocol not in ('UDP', 'TCP') or p.dst_port != 53 or not p.payload:
            return
        qname = p.payload.rstrip('.').lower()
        if not _dga_like(qname, r['threshold']):
            return
        w = self.dns.touch(e.src)
        w.add(e.now, qname)
        w.trim(e.now, r['window'], max(MAX_EVENTS_PER_KEY, DNS_MIN_HITS + 20))
        names = w.unique()
        if names >= DNS_MIN_HITS and self._cooldown(('DNS-001', e.src), 30, e.now):
            out.append(self._alert(r, e, f'{names} long/high-entropy full DNS query names in {r["window"]}s',
                                   block_target=e.src))

    def _check_ioc(self, e: _Event, out: list):
        r = self._rule('IOC-001')
        if not r:
            return
        bad_src, bad_dst = self.store.is_blocked(e.src), self.store.is_blocked(e.dst)
        if not (bad_src or bad_dst) or not self._cooldown(('IOC-001', e.src, e.dst), 30, e.now):
            return
        if bad_src:
            out.append(self._alert(r, e, 'Source IP is in local blocklist; inline policy marks this packet for drop',
                                   block_target=e.src, confidence='high'))
        else:
            out.append(self._alert(r, e, 'Destination IP is in local blocklist (outbound IOC)',
                                   block_target=e.dst, confidence='high'))

    def _check_signatures(self, e: _Event, out: list):
        r = self._rule(SIG_RULE_ID)
        rule_set = self.signatures
        if not r or rule_set is None or not rule_set.rules:
            return
        hits = rule_set.match(e.packet, e.src, e.dst, e.now)
        assumed = rule_set.last_assumed
        if rule_set.last_timeouts:
            self._report_pcre_timeouts(rule_set.last_timeouts, e, out)
        for sig in hits:
            if not self._cooldown((SIG_RULE_ID, sig.uid, e.src, e.dst), r['window'], e.now):
                continue
            self.sig_hits[rule_key(sig)] += 1
            self.sig_hits_version += 1
            target = e.dst if sig.target == 'src' else e.src
            timed_out = sig.uid in assumed
            try:
                detail = explain_match(sig, e.packet, e.src, e.dst, context=self.store.keep_payload,
                                       pcre_assumed=timed_out)
            except Exception as exc:            # an explanation must never stop the alert
                detail = f'Could not explain this match: {exc}'
            if timed_out:
                detail = 'pcre timed out (possible ReDoS); treated as match.\n' + detail
            out.append(Alert(SIG_RULE_ID, sig.msg or f'sid {sig.sid}', sig.severity, sig.msg or f'sid {sig.sid}',
                             e.src, e.dst, sig.evidence(), 'ALERT', target, 'medium', e.packet.source,
                             drop_requested=sig.is_drop, detail=detail))

    def _report_pcre_timeouts(self, sigs: list, e: _Event, out: list):
        """SIG-002: a pcre ran past its time limit on this packet, which hostile payloads can cause on purpose."""
        r = self._rule(SIG_TIMEOUT_RULE_ID)
        if not r or not self._cooldown((SIG_TIMEOUT_RULE_ID, e.src), r['window'], e.now):
            return
        names = ', '.join(f'[{s.gid}:{s.sid}] {s.msg[:60]}' for s in sigs[:3]) + (' ...' if len(sigs) > 3 else '')
        # No block target: a large legitimate payload can also be slow, so this alone never blocks.
        out.append(self._alert(r, e, f'{len(sigs)} signature pcre(s) exceeded the time limit on a '
                                     f'{len(e.packet.data)}-byte payload: {names}. The rule(s) were '
                                     'treated as matched; their pcre is skipped for this source for a while.',
                               confidence='low'))

    def _check_arp(self, e: _Event, out: list):
        r = self._rule('ARP-001')
        mac = e.packet.src_mac
        if not r or not mac or mac in IGNORED_MACS or e.src in ('', '0.0.0.0'):
            return
        w = self.arp.touch(e.src)
        w.add(e.now, mac)
        w.trim(e.now, r['window'], _per_key_cap(r))
        macs = w.unique()
        if macs >= max(2, int(r['threshold'])) and self._cooldown(('ARP-001', e.src), 60, e.now):
            gateway = e.src in PROTECTED.all()
            role = 'gateway/infrastructure address ' if gateway else ''
            # No block target: the claimed IP belongs to the victim, and the attacker is only known by MAC.
            out.append(self._alert(r, e, f'{role}{e.src} claimed by {macs} MAC addresses in {r["window"]}s: '
                                         f'{", ".join(sorted(w.counts))}',
                                   confidence='high' if gateway else 'medium'))

    def _check_auth(self, e: _Event, out: list):
        r = self._rule('AUTH-001')
        p = e.packet
        service = LOGIN_PORTS.get(p.dst_port) if p.dst_port is not None else None
        if not r or not e.is_syn or service is None:
            return
        w = self.auth.touch((e.src, e.dst, p.dst_port))
        w.add(e.now, p.src_port)              # SYN retransmits reuse the source port, so count once
        w.trim(e.now, r['window'], _per_key_cap(r))
        attempts = w.unique()
        if attempts >= r['threshold'] and self._cooldown(('AUTH-001', e.src, e.dst, p.dst_port), 60, e.now):
            out.append(self._alert(r, e, f'{attempts} {service} connection attempts (TCP/{p.dst_port}) to {e.dst} '
                                         f'in {r["window"]}s', block_target=e.src))

    def _check_udp_scan(self, e: _Event, out: list):
        r = self._rule('NET-006')
        port = e.packet.dst_port
        if not r or e.packet.protocol != 'UDP' or port is None or port > UDP_SCAN_MAX_PORT:
            return
        w = self.udp_scan.touch((e.src, e.dst))
        w.add(e.now, port)
        w.trim(e.now, r['window'], _per_key_cap(r))
        ports = w.unique()
        if ports >= r['threshold'] and self._cooldown(('NET-006', e.src, e.dst), 15, e.now):
            out.append(self._alert(r, e, f'{ports} unique UDP destination ports on {e.dst} in {r["window"]}s; '
                                         'source may be spoofed', block_target=e.src, confidence='low'))

    def _check_tls(self, e: _Event, out: list):
        r = self._rule('TLS-001')
        p = e.packet
        # The parser stores the TLS server name in `payload` only for these ports.
        if not r or not e.is_tcp or not p.payload or p.dst_port == 53 or p.dst_port in HTTP_PORTS:
            return
        name = p.payload.rstrip('.').lower()
        if not _dga_like(name, r['threshold']):
            return
        w = self.tls.touch(e.src)
        w.add(e.now, name)
        w.trim(e.now, r['window'], max(MAX_EVENTS_PER_KEY, TLS_MIN_HITS + 20))
        names = w.unique()
        if names >= TLS_MIN_HITS and self._cooldown(('TLS-001', e.src), 30, e.now):
            out.append(self._alert(r, e, f'{names} long/high-entropy TLS server names in {r["window"]}s',
                                   block_target=e.src))

    # -- policy ------------------------------------------------------------------
    def _confirm_block(self, a: Alert, now: float) -> bool:
        key = (a.rule_id, canonical_ip(a.block_target or ''))
        with self.lock:
            q = self.block_confirm.setdefault(key, deque())
            q.append(now)
            while q and now - q[0] > AUTO_BLOCK_CONFIRM_WINDOW:
                q.popleft()
            return len(q) >= AUTO_BLOCK_CONFIRMATIONS

    def _auto_block_eligible(self, a: Alert) -> bool:
        return (a.rule_id in AUTO_BLOCK_RULES and a.severity in ('HIGH', 'CRITICAL')
                and bool(a.block_target) and a.confidence in ('medium', 'high'))

    def process(self, p: Packet, inline=False, auto_block=False, ttl=300, dry_run=True):
        """Inspect a packet, apply the prevention policy and store the results.

        Returns (alerts, drop). `drop` is only ever True for inline, non-dry-run operation.
        """
        alerts = self.inspect(p)
        src, dst = canonical_ip(p.src_ip), canonical_ip(p.dst_ip)
        trusted = self.store.is_trusted(src) or self.store.is_trusted(dst)
        blocklisted = self.store.is_blocked(src) or self.store.is_blocked(dst)
        blocklist_drop = inline and not dry_run and not trusted and blocklisted
        drop = blocklist_drop
        now = event_time(p)
        for a in alerts:
            if inline and a.rule_id == 'IOC-001':
                a.action = 'DROP' if blocklist_drop else 'WOULD_DROP'
            elif inline and a.drop_requested:
                # A drop-type Snort/Suricata rule drops only this packet; it never adds a blocklist entry.
                if dry_run or trusted:
                    a.action = 'WOULD_DROP'
                else:
                    a.action = 'DROP'
                    drop = True
            elif inline and auto_block and self._auto_block_eligible(a) and self._confirm_block(a, now):
                a.confidence = 'high'
                target = canonical_ip(a.block_target)
                safe = (not trusted and not self.store.is_trusted(target) and not is_protected(target)
                        and dst in PROTECTED.local())
                if safe and dry_run:
                    a.action = 'WOULD_DROP'
                elif safe and self.store.block(target, f'Auto-block by {a.rule_id}', ttl, source='auto'):
                    a.action = 'DROP'
                    drop = True
            self.store.add_alert(a)
        p.dropped = bool(drop)
        self.store.add_packet(p)
        return alerts, drop
