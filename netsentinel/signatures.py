"""Snort 2.9, Snort 3 and Suricata rules: parser, compiler and matcher (Qt-free).

Only part of the rule language is supported. A rule that uses anything else is not loaded; the
load report says why, so nothing is skipped silently.
"""
from __future__ import annotations

import functools
import hashlib
import ipaddress
import re
import tarfile
import threading
import warnings
import zipfile
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import unquote_to_bytes

from .addresses import PrefixIndex, canonical_ip
from .config import (HTTP_PORTS, SIG_ARCHIVE_MAX_BYTES, SIG_ARCHIVE_MAX_MEMBERS, SIG_BACKTRACK, SIG_DEFAULT_HOME_NET,
                     SIG_FLOW_CAP, SIG_FLOW_TIMEOUT, SIG_MAX_EXAMPLES, SIG_PCRE_BACKOFF, SIG_PCRE_BACKOFF_CAP,
                     SIG_PCRE_TIMEOUT)


class RuleError(ValueError):
    """The rule cannot be loaded. The message is the skip reason shown to the user."""


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
ALERT_ACTIONS = frozenset({'alert'})
DROP_ACTIONS = frozenset({'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth', 'sdrop'})
ACTIONS = ALERT_ACTIONS | DROP_ACTIONS | {'pass'}
PROTOCOLS = {'ip': 'ip', 'tcp': 'tcp', 'tcp-pkt': 'tcp', 'tcp-stream': 'tcp', 'udp': 'udp', 'icmp': 'icmp',
             'http': 'http', 'http1': 'http', 'dns': 'dns', 'tls': 'tls', 'ssl': 'tls'}
ARCHIVE_SUFFIXES = ('.tar.gz', '.tgz', '.tar', '.zip')
CONFIG_PREFIXES = ('include', 'var', 'ipvar', 'portvar', 'config', 'preprocessor', 'output', 'dynamicpreprocessor',
                   'dynamicengine', 'dynamicdetection')

_SERVER_GROUPS = ('HTTP_SERVERS', 'SMTP_SERVERS', 'SQL_SERVERS', 'DNS_SERVERS', 'TELNET_SERVERS', 'AIM_SERVERS',
                  'DC_SERVERS', 'DNP3_SERVER', 'DNP3_CLIENT', 'MODBUS_CLIENT', 'MODBUS_SERVER', 'ENIP_CLIENT',
                  'ENIP_SERVER', 'SIP_SERVERS', 'SNMP_SERVERS', 'SSH_SERVERS', 'FTP_SERVERS')
DEFAULT_VARIABLES = {
    'HOME_NET': SIG_DEFAULT_HOME_NET,
    'EXTERNAL_NET': '!$HOME_NET',
    **{name: '$HOME_NET' for name in _SERVER_GROUPS},
    'HTTP_PORTS': '[' + ','.join(str(p) for p in sorted(HTTP_PORTS)) + ']',
    'SHELLCODE_PORTS': '!80',
    'ORACLE_PORTS': '1521',
    'SSH_PORTS': '22',
    'FTP_PORTS': '21',
    'SIP_PORTS': '[5060,5061,5600]',
    'FILE_DATA_PORTS': '[$HTTP_PORTS,110,143]',
    'DNP3_PORTS': '20000',
    'MODBUS_PORTS': '502',
    'GTP_PORTS': '[2123,2152,3386]',
    'GENEVE_PORTS': '6081',
    'VXLAN_PORTS': '4789',
    'TEREDO_PORTS': '3544',
}

# Classtype priorities from the Snort/Suricata classification.config and the ET Open additions.
CLASSTYPE_PRIORITY = {
    'not-suspicious': 3, 'unknown': 3, 'bad-unknown': 2, 'attempted-recon': 2, 'successful-recon-limited': 2,
    'successful-recon-largescale': 2, 'attempted-dos': 2, 'successful-dos': 2, 'attempted-user': 1,
    'unsuccessful-user': 1, 'successful-user': 1, 'attempted-admin': 1, 'successful-admin': 1,
    'rpc-portmap-decode': 2, 'shellcode-detect': 1, 'string-detect': 3, 'suspicious-filename-detect': 2,
    'suspicious-login': 2, 'system-call-detect': 2, 'tcp-connection': 4, 'trojan-activity': 1,
    'unusual-client-port-connection': 2, 'network-scan': 3, 'denial-of-service': 2, 'non-standard-protocol': 2,
    'protocol-command-decode': 3, 'web-application-activity': 2, 'web-application-attack': 1, 'misc-activity': 3,
    'misc-attack': 2, 'icmp-event': 3, 'inappropriate-content': 1, 'policy-violation': 1, 'default-login-attempt': 2,
    'sdf': 2, 'file-format': 1, 'malware-cnc': 1, 'client-side-exploit': 1, 'targeted-activity': 1,
    'exploit-kit': 1, 'external-ip-check': 2, 'domain-c2': 1, 'pup-activity': 2, 'credential-theft': 1,
    'social-engineering': 2, 'coin-mining': 2, 'command-and-control': 1, 'successful-recon': 2,
}
PRIORITY_SEVERITY = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW', 4: 'LOW'}
DEFAULT_PRIORITY = 3

# Buffer keyword -> canonical buffer name. Dotted names are always sticky; underscore names are
# Snort 2 content modifiers when they follow a content, and sticky otherwise.
BUFFERS = {
    'pkt_data': 'pkt',
    'http.uri': 'http.uri', 'http_uri': 'http.uri',
    'http.uri.raw': 'http.uri.raw', 'http_raw_uri': 'http.uri.raw',
    'http.method': 'http.method', 'http_method': 'http.method',
    'http.protocol': 'http.protocol', 'http_protocol': 'http.protocol', 'http_version': 'http.protocol',
    'http.request_line': 'http.request_line', 'http_request_line': 'http.request_line',
    'http.start': 'http.start', 'http_start': 'http.start',
    'http.header': 'http.header', 'http_header': 'http.header',
    'http.header.raw': 'http.header.raw', 'http_raw_header': 'http.header.raw',
    'http.header_names': 'http.header_names', 'http_header_names': 'http.header_names',
    'http.host': 'http.host', 'http_host': 'http.host',
    'http.host.raw': 'http.host.raw', 'http_raw_host': 'http.host.raw',
    'http.user_agent': 'http.user_agent', 'http_user_agent': 'http.user_agent',
    'http.cookie': 'http.cookie', 'http_cookie': 'http.cookie', 'http_raw_cookie': 'http.cookie',
    'http.accept': 'http.accept', 'http_accept': 'http.accept',
    'http.accept_enc': 'http.accept_enc', 'http_accept_enc': 'http.accept_enc',
    'http.accept_lang': 'http.accept_lang', 'http_accept_lang': 'http.accept_lang',
    'http.connection': 'http.connection', 'http_connection': 'http.connection',
    'http.content_len': 'http.content_len', 'http_content_len': 'http.content_len',
    'http.content_type': 'http.content_type', 'http_content_type': 'http.content_type',
    'http.referer': 'http.referer', 'http_referer': 'http.referer',
    'dns.query': 'dns.query', 'dns_query': 'dns.query',
    'tls.sni': 'tls.sni', 'tls_sni': 'tls.sni',
}
HEADER_BUFFERS = {'http.user_agent': b'user-agent', 'http.cookie': b'cookie', 'http.accept': b'accept',
                  'http.accept_enc': b'accept-encoding', 'http.accept_lang': b'accept-language',
                  'http.connection': b'connection', 'http.content_len': b'content-length',
                  'http.content_type': b'content-type', 'http.referer': b'referer'}
PCRE_BUFFER_FLAGS = {'U': 'http.uri', 'I': 'http.uri.raw', 'H': 'http.header', 'D': 'http.header.raw',
                     'M': 'http.method', 'C': 'http.cookie', 'K': 'http.cookie', 'W': 'http.host',
                     'Z': 'http.host.raw', 'V': 'http.user_agent'}
PCRE_FLAGS = {'i': re.I, 's': re.S, 'm': re.M, 'x': re.X}

# ReDoS protection. Python's re has no timeout, so one badly written pcre fed hostile traffic can stall the
# IDS. The `regex` module (a required dependency) accepts a timeout: every pcre gets SIG_PCRE_TIMEOUT seconds
# per packet. A timeout must not let an attacker dodge a rule, so it fails closed: the pcre counts as matched,
# the rule still alerts, SIG-002 reports the timeout, and that rule's pcre is not run again for the same
# source for SIG_PCRE_BACKOFF seconds (still assumed matched), so repeating the payload cannot stall the IDS.
try:
    import regex as _regex_engine        # pyright: ignore[reportMissingImports]
except ImportError:                       # broken install: warned about loudly (see PCRE_TIMEOUT_WARNING)
    _regex_engine = None
PCRE_TIMEOUT_AVAILABLE = _regex_engine is not None
PCRE_TIMEOUT_WARNING = ('WARNING: the "regex" package is not installed, so signature pcre checks run on '
                        "Python's re with NO time limit. A hostile payload can stall detection (ReDoS). "
                        'Install it with: pip install regex')


class PcreTimeout(Exception):
    """A pcre took longer than SIG_PCRE_TIMEOUT on one packet (or is backed off after doing so)."""


class _PcreGuard(threading.local):
    """Per-thread state for one rule evaluation: skip = backed off, assume the pcre matched; hit = a pcre
    result was assumed; timed_out = a pcre really ran past the limit."""

    def __init__(self):
        self.skip = False
        self.hit = False
        self.timed_out = False


_PCRE_GUARD = _PcreGuard()


def _pcre_run(it, subject: bytes, anchored: bool = False, pos: int = 0):
    """search/match with the timeout when the regex module is in use. Raises PcreTimeout."""
    rx = it.regex
    if getattr(it, 'timed', False):
        guard = _PCRE_GUARD
        if guard.skip:
            guard.hit = True
            raise PcreTimeout()
        try:
            # concurrent=False: keep the GIL. By default regex releases and re-takes it on every call, and
            # with thousands of short pcre calls per second the GUI thread could not get it back for up to
            # a second at a time (the window froze). The timeout still applies.
            return (rx.match(subject, pos, timeout=SIG_PCRE_TIMEOUT, concurrent=False) if anchored
                    else rx.search(subject, pos, timeout=SIG_PCRE_TIMEOUT, concurrent=False))
        except TimeoutError:
            guard.hit = guard.timed_out = True
            raise PcreTimeout() from None
    return rx.match(subject, pos) if anchored else rx.search(subject, pos)
_WS = re.compile(rb'\s+')


def _url_decode(b: bytes) -> bytes:
    return unquote_to_bytes(b.replace(b'+', b' '))


def _header_lowercase(b: bytes) -> bytes:
    return b'\r\n'.join(line.split(b':', 1)[0].lower() + (b':' + line.split(b':', 1)[1] if b':' in line else b'')
                        for line in b.split(b'\r\n'))


TRANSFORMS: dict[str, Callable[[bytes], bytes]] = {
    'dotprefix': lambda b: b'.' + b,
    'to_lowercase': bytes.lower,
    'to_uppercase': bytes.upper,
    'header_lowercase': _header_lowercase,
    'strip_whitespace': lambda b: _WS.sub(b'', b),
    'compress_whitespace': lambda b: _WS.sub(b' ', b),
    'url_decode': _url_decode,
    'to_md5': lambda b: hashlib.md5(b).digest(),
    'to_sha1': lambda b: hashlib.sha1(b).digest(),
    'to_sha256': lambda b: hashlib.sha256(b).digest(),
    'strip_pseudo_headers': lambda b: b,      # HTTP/2 only; HTTP/1 headers have none
}

IGNORED = frozenset({'reference', 'metadata', 'tag', 'service', 'rem', 'prefilter', 'requires', 'fast_pattern',
                     'rawbytes'})
FLOW_TOKENS = frozenset({'to_server', 'to_client', 'from_server', 'from_client', 'established', 'not_established',
                         'stateless', 'only_stream', 'no_stream', 'only_frag', 'no_frag'})


# ----------------------------------------------------------------------------
# Addresses and ports
# ----------------------------------------------------------------------------
def _split_top(text: str) -> list[str]:
    """Split a list body on commas outside brackets."""
    parts, depth, current = [], 0, []
    for ch in text:
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth < 0:
                raise RuleError(f'unbalanced brackets in "{text}"')
        if ch == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if depth:
        raise RuleError(f'unbalanced brackets in "{text}"')
    parts.append(''.join(current).strip())
    return [p for p in parts if p]


class _Any:
    __slots__ = ()
    is_any = True
    hosts = None

    def test(self, value) -> bool:
        return True


ANY = _Any()


class _Not:
    __slots__ = ('child',)
    is_any = False
    hosts = None

    def __init__(self, child):
        self.child = child

    def test(self, value) -> bool:
        return not self.child.test(value)


class _List:
    """Positive items union, minus negative items. Only negatives means everything else."""
    __slots__ = ('pos', 'neg', 'hosts')
    is_any = False

    def __init__(self, pos, neg):
        self.pos, self.neg = pos, neg
        self.hosts = pos[0].hosts if len(pos) == 1 and not neg else None

    def test(self, value) -> bool:
        if self.pos and not any(c.test(value) for c in self.pos):
            return False
        return not any(c.test(value) for c in self.neg)


class _Nets:
    """A list of networks, tested with one prefix-index lookup."""
    __slots__ = ('nets', 'index', 'hosts')
    is_any = False

    def __init__(self, nets):
        self.nets = list(nets)
        self.index = PrefixIndex(self.nets)
        single = all(n.prefixlen == n.max_prefixlen for n in self.nets)
        self.hosts = frozenset(str(n.network_address) for n in self.nets) if single else None

    def test(self, value) -> bool:
        return value is not None and self.index.contains(value)


class _Ports:
    __slots__ = ('ranges',)
    is_any = False
    hosts = None

    def __init__(self, ranges):
        self.ranges = tuple(ranges)

    def test(self, value) -> bool:
        return value is not None and any(lo <= value <= hi for lo, hi in self.ranges)


def _resolve(token: str, variables: dict, seen: tuple) -> str:
    name = token[1:]
    if name not in variables:
        raise RuleError(f'unknown variable ${name}')
    if name in seen:
        raise RuleError(f'variable ${name} refers to itself')
    return variables[name]


def _parse_spec(text: str, variables: dict, leaf: Callable, seen: tuple = ()):
    text = text.strip()
    if not text:
        raise RuleError('empty address or port')
    if text.startswith('!'):
        child = _parse_spec(text[1:], variables, leaf, seen)
        return _Not(child)
    if text.startswith('['):
        if not text.endswith(']'):
            raise RuleError(f'unbalanced brackets in "{text}"')
        pos, neg = [], []
        for part in _split_top(text[1:-1]):
            if part.startswith('!'):
                neg.append(_parse_spec(part[1:], variables, leaf, seen))
            else:
                pos.append(_parse_spec(part, variables, leaf, seen))
        if any(c.is_any for c in pos):
            pos = []
        return _merge(pos, neg, leaf)
    if text.startswith('$'):
        return _parse_spec(_resolve(text, variables, seen), variables, leaf, seen + (text[1:],))
    if text.lower() == 'any':
        return ANY
    return leaf(text)


def _merge(pos, neg, leaf):
    """Combine leaf value lists so a list of 500 hosts is one index lookup."""
    def combine(items):
        nets = [c for c in items if isinstance(c, _Nets)]
        ports = [c for c in items if isinstance(c, _Ports)]
        rest = [c for c in items if not isinstance(c, (_Nets, _Ports))]
        out = rest
        if nets:
            merged = []
            for n in nets:
                merged.extend(n.nets)
            out.append(_Nets(merged))
        if ports:
            out.append(_Ports([r for p in ports for r in p.ranges]))
        return out
    pos, neg = combine(pos), combine(neg)
    if not pos and not neg:
        return ANY
    if len(pos) == 1 and not neg:
        return pos[0]
    return _List(pos, neg)


def _addr_leaf(text: str):
    try:
        return _Nets([ipaddress.ip_network(text, strict=False)])
    except ValueError:
        raise RuleError(f'invalid address "{text}"') from None


def _port_leaf(text: str):
    try:
        if ':' in text:
            lo, hi = text.split(':', 1)
            lo_v, hi_v = int(lo) if lo.strip() else 0, int(hi) if hi.strip() else 65535
        else:
            lo_v = hi_v = int(text)
    except ValueError:
        raise RuleError(f'invalid port "{text}"') from None
    if not (0 <= lo_v <= hi_v <= 65535):
        raise RuleError(f'invalid port range "{text}"')
    return _Ports([(lo_v, hi_v)])


class _Interner:
    """Shares compiled specs between rules so each one is evaluated once per packet."""

    def __init__(self, variables: dict):
        self.variables = variables
        self._addr: dict[str, object] = {}
        self._port: dict[str, object] = {}

    def addr(self, text: str):
        node = self._addr.get(text)
        if node is None:
            node = self._addr[text] = _parse_spec(text, self.variables, _addr_leaf)
        return node

    def port(self, text: str):
        node = self._port.get(text)
        if node is None:
            node = self._port[text] = _parse_spec(text, self.variables, _port_leaf)
        return node


# ----------------------------------------------------------------------------
# Rule objects
# ----------------------------------------------------------------------------
@dataclass(slots=True)
class Item:
    """One content, pcre or isdataat check inside a buffer."""
    kind: str                           # 'content' | 'pcre' | 'isdataat'
    buffer: str = 'pkt'
    transforms: tuple = ()
    pattern: bytes = b''
    lower: bytes = b''
    nocase: bool = False
    negated: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None
    startswith: bool = False
    endswith: bool = False
    fast: bool = False
    regex: Optional[re.Pattern] = None
    relative: bool = False
    anchored: bool = False
    position: int = 0
    sticky: bool = False                # buffer came from a sticky keyword (not a Snort 2 modifier)
    timed: bool = False                 # pcre runs on the regex module, with a timeout

    @property
    def key(self):
        return self.buffer, self.transforms


@dataclass(slots=True)
class Group:
    key: tuple
    items: list
    bsize: Optional[Callable[[int], bool]] = None
    needs_lower: bool = False


@dataclass(slots=True)
class Signature:
    gid: int
    sid: int
    rev: int
    msg: str
    action: str
    proto: str
    src: object
    sport: object
    dst: object
    dport: object
    bidirectional: bool
    groups: tuple = ()
    flags: Optional[tuple] = None
    established: Optional[bool] = None
    dsize: Optional[Callable[[int], bool]] = None
    urilen: Optional[tuple] = None
    sameip: bool = False
    flowbit_checks: tuple = ()
    flowbit_actions: tuple = ()
    noalert: bool = False
    threshold: Optional[tuple] = None
    detection_filter: Optional[tuple] = None
    priority: int = DEFAULT_PRIORITY
    classtype: str = ''
    target: Optional[str] = None
    source: str = ''
    line: int = 0
    order: int = 0
    uid: int = 0
    text: str = ''

    @property
    def severity(self) -> str:
        return PRIORITY_SEVERITY.get(self.priority, 'LOW')

    @property
    def is_drop(self) -> bool:
        return self.action in DROP_ACTIONS

    def evidence(self) -> str:
        where = f'{Path(self.source).name}:{self.line}' if self.source else ''
        return f'[{self.gid}:{self.sid}:{self.rev}] {self.classtype or "unclassified"}' + (f'; {where}' if where else '')


# ----------------------------------------------------------------------------
# Option parsing helpers
# ----------------------------------------------------------------------------
def _split_options(body: str) -> list[tuple[str, str]]:
    """Split `key:value; key; ...` on unescaped semicolons.

    Like Snort and Suricata, quotes are not tracked: a `;` inside a value must be written `\\;` or
    `|3b|`, and a pcre may contain a bare `"`.
    """
    options, current, escape = [], [], False
    for ch in body:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == '\\':
            current.append(ch)
            escape = True
            continue
        if ch == ';':
            options.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        options.append(tail)
    result = []
    for opt in options:
        if not opt:
            continue
        key, sep, value = opt.partition(':')
        result.append((key.strip().lower(), value.strip() if sep else ''))
    return result


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _content_bytes(text: str) -> bytes:
    """Rule content string -> bytes. `|41 42|` is hex; backslash escapes the next character."""
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '|':
            end = text.find('|', i + 1)
            if end < 0:
                raise RuleError('unterminated |hex| in content')
            hex_text = text[i + 1:end].replace(' ', '')
            try:
                out += bytes.fromhex(hex_text)
            except ValueError:
                raise RuleError('invalid |hex| in content') from None
            i = end + 1
        elif ch == '\\' and i + 1 < n:
            out += text[i + 1].encode('utf-8')
            i += 2
        else:
            out += ch.encode('utf-8')
            i += 1
    if not out:
        raise RuleError('empty content')
    return bytes(out)


def _quoted_split(value: str) -> tuple[str, str, bool]:
    """'!"abc", nocase' -> ('abc', ', nocase', negated)."""
    value = value.strip()
    negated = value.startswith('!')
    if negated:
        value = value[1:].strip()
    if not value.startswith('"'):
        raise RuleError('content must be quoted')
    i, escape = 1, False
    while i < len(value):
        ch = value[i]
        if escape:
            escape = False
        elif ch == '\\':
            escape = True
        elif ch == '"':
            return value[1:i], value[i + 1:].strip(), negated
        i += 1
    raise RuleError('unterminated quoted string')


def _int(value: str, name: str) -> int:
    try:
        return int(value.strip())
    except ValueError:
        raise RuleError(f'{name} needs a number, got "{value}"') from None


def _comparator(value: str, name: str) -> Callable[[int], bool]:
    """`N`, `<N`, `>N`, `<=N`, `>=N`, `!N`, `N<>M` (exclusive) or `N-M` (inclusive)."""
    v = value.strip().split(',')[0].strip()
    try:
        if '<>' in v:
            lo, hi = (int(x) for x in v.split('<>', 1))
            return lambda n: lo < n < hi
        for op, fn in (('<=', lambda a, b: a <= b), ('>=', lambda a, b: a >= b), ('<', lambda a, b: a < b),
                       ('>', lambda a, b: a > b), ('!', lambda a, b: a != b), ('=', lambda a, b: a == b)):
            if v.startswith(op):
                ref = int(v[len(op):])
                return lambda n, f=fn, r=ref: f(n, r)
        if '-' in v[1:]:
            lo, hi = (int(x) for x in v.split('-', 1))
            return lambda n: lo <= n <= hi
        ref = int(v)
        return lambda n: n == ref
    except ValueError:
        raise RuleError(f'invalid {name} value "{value}"') from None


def _flags_spec(value: str) -> tuple:
    v, _, mask = value.replace(' ', '').partition(',')
    mod = ''
    if v and v[0] in '+*!':
        mod, v = v[0], v[1:]
    elif v and v[-1] in '+*!':
        mod, v = v[-1], v[:-1]
    letters = v.upper().replace('1', 'C').replace('2', 'E')
    ignore = mask.upper().replace('1', 'C').replace('2', 'E')
    allowed = set('FSRPAUCE0')
    if not set(letters) <= allowed or not set(ignore) <= allowed:
        raise RuleError(f'invalid flags "{value}"')
    return mod, frozenset(letters) - {'0'}, frozenset(ignore) - {'0'}


def _flags_ok(spec: tuple, flags: str) -> bool:
    mod, want, ignore = spec
    have = (set(flags.upper()) & set('FSRPAUCE')) - ignore
    if mod == '+':
        return want <= have
    if mod == '*':
        return bool(want & have)
    if mod == '!':
        return not (want & have)
    return have == want


def _pairs(value: str) -> dict:
    """'type limit, track by_src, count 1, seconds 60' -> dict."""
    out = {}
    for part in value.split(','):
        bits = part.split()
        if len(bits) != 2:
            raise RuleError(f'invalid threshold "{value}"')
        out[bits[0].lower()] = bits[1].lower()
    return out


def _threshold_spec(value: str, kind: str) -> tuple:
    p = _pairs(value)
    track = p.get('track', 'by_src')
    if track not in ('by_src', 'by_dst', 'by_rule', 'by_both', 'by_flow'):
        raise RuleError(f'unsupported {kind} track "{track}"')
    try:
        count, seconds = int(p['count']), int(p['seconds'])
    except (KeyError, ValueError):
        raise RuleError(f'{kind} needs count and seconds') from None
    ttype = p.get('type', 'filter' if kind == 'detection_filter' else '')
    if kind == 'threshold' and ttype not in ('limit', 'threshold', 'both'):
        raise RuleError(f'unsupported threshold type "{ttype}"')
    return ttype, track, count, seconds


def _compile_pcre(value: str) -> tuple:
    """'"/abc/iR"' -> (regex, negated, relative, anchored, buffer or None)."""
    negated = value.strip().startswith('!')
    text = _unquote(value.strip()[1:] if negated else value)
    if not text.startswith('/') or text.rfind('/') == 0:
        raise RuleError('pcre must look like "/pattern/flags"')
    end = text.rfind('/')
    pattern, flag_text = text[1:end], text[end + 1:]
    flags, relative, anchored, buffer = 0, False, False, None
    for ch in flag_text:
        if ch in PCRE_FLAGS:
            flags |= PCRE_FLAGS[ch]
        elif ch == 'R':
            relative = True
        elif ch == 'A':
            anchored = True
        elif ch in 'BOE':
            pass
        elif ch in PCRE_BUFFER_FLAGS:
            buffer = PCRE_BUFFER_FLAGS[ch]
        else:
            raise RuleError(f'unsupported pcre flag "{ch}"')
    # PCRE syntax that Python's re spells differently: named groups (?<name>...) are (?P<name>...),
    # and a one-digit hex escape \x2 is \x02.
    pattern = re.sub(r'\(\?<(?![=!])', '(?P<', pattern)
    pattern = re.sub(r'(?<!\\)\\x([0-9a-fA-F])(?![0-9a-fA-F])', r'\\x0\1', pattern)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', FutureWarning)      # "possible nested set" notes from re
            regex = re.compile(pattern.encode('utf-8'), flags)
    except (re.error, ValueError, OverflowError, RecursionError) as exc:
        raise RuleError(f'pcre not supported by Python re ({exc.__class__.__name__})') from None
    # Python re decides which rules load (so the rule count does not depend on an optional module); the
    # regex module, when present, runs the same pattern with a timeout.
    if _regex_engine is not None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                regex = _regex_engine.compile(pattern.encode('utf-8'), flags)
        except Exception:
            pass                                                 # keep the re version, without a timeout
    return regex, negated, relative, anchored, buffer


# ----------------------------------------------------------------------------
# Rule parser
# ----------------------------------------------------------------------------
def parse_rule(text: str, interner: _Interner, source: str = '', line: int = 0) -> Signature:
    text = text.strip()
    open_at = text.find('(')
    if open_at < 0 or not text.endswith(')'):
        raise RuleError('malformed rule: missing ( ... )')
    header = text[:open_at].split()
    body = text[open_at + 1:-1]
    if not header:
        raise RuleError('malformed rule header')
    action = header[0].lower()
    if action not in ACTIONS:
        raise RuleError(f'unsupported action "{action}"')
    snort3 = False
    if len(header) == 2:
        proto_name, src_t, sport_t, dir_t, dst_t, dport_t = header[1], 'any', 'any', '->', 'any', 'any'
        snort3 = True
    elif len(header) == 7:
        proto_name, src_t, sport_t, dir_t, dst_t, dport_t = header[1:]
    else:
        raise RuleError('malformed rule header')
    proto = PROTOCOLS.get(proto_name.lower())
    if proto is None:
        raise RuleError(f'unsupported protocol "{proto_name}"')
    if dir_t not in ('->', '<>'):
        raise RuleError(f'unsupported direction "{dir_t}"')
    sport, dport = interner.port(sport_t), interner.port(dport_t)
    if proto == 'icmp' and not (sport.is_any and dport.is_any):
        raise RuleError('ports on an icmp rule')
    # Ports on an ip rule apply to TCP and UDP packets; packets without ports never match them.
    sig = Signature(gid=1, sid=0, rev=1, msg='', action=action, proto=proto, src=interner.addr(src_t), sport=sport,
                    dst=interner.addr(dst_t), dport=dport, bidirectional=dir_t == '<>', source=source, line=line,
                    text=text)

    options = _split_options(body)
    if not snort3:
        snort3 = any(k == 'service' for k, _ in options) or any(
            k == 'content' and _quoted_split(v)[1].startswith(',') for k, v in options if v.strip(' !').startswith('"'))

    items: list[Item] = []
    sticky, transforms = 'pkt', ()
    last_content: Optional[Item] = None
    bsizes: dict = {}
    checks, actions = [], []
    priority = None
    explicit_sid = False
    previous_key = ''

    def need_content(name):
        if last_content is None or last_content.kind != 'content':
            raise RuleError(f'"{name}" without a preceding content')
        return last_content

    for key, value in options:
        if key in BUFFERS:
            buffer = BUFFERS[key]
            if value:
                raise RuleError(f'unsupported keyword "{key}:{value}"')
            follows_content = previous_key in ('content', 'uricontent', 'nocase', 'depth', 'offset', 'distance',
                                               'within', 'fast_pattern', 'rawbytes', 'startswith', 'endswith')
            if ('.' not in key and key != 'pkt_data' and not snort3 and follows_content
                    and last_content is not None and not last_content.sticky):
                last_content.buffer, last_content.transforms = buffer, ()     # Snort 2 content modifier
            else:
                sticky, transforms = buffer, ()
        elif key in TRANSFORMS:
            if sticky == 'pkt':
                raise RuleError(f'transform "{key}" without a sticky buffer')
            transforms = transforms + (key,)
        elif key in ('content', 'uricontent'):
            raw, rest, negated = _quoted_split(value)
            pattern = _content_bytes(raw)
            item = Item('content', buffer=sticky if key == 'content' else 'http.uri',
                        transforms=transforms if key == 'content' else (), pattern=pattern, lower=pattern.lower(),
                        negated=negated, sticky=sticky != 'pkt')
            if rest:
                if not rest.startswith(','):
                    raise RuleError('unexpected text after content')
                for sub in (s.strip() for s in rest[1:].split(',') if s.strip()):
                    name, _, arg = sub.partition(' ')
                    _apply_modifier(item, name.lower(), arg.strip())
            items.append(item)
            last_content = item
        elif key in ('nocase', 'depth', 'offset', 'distance', 'within', 'startswith', 'endswith'):
            _apply_modifier(need_content(key), key, value)
        elif key in ('fast_pattern', 'rawbytes'):
            if key == 'fast_pattern' and last_content is not None:
                last_content.fast = True
        elif key == 'pcre':
            regex, negated, relative, anchored, buffer = _compile_pcre(value)
            if buffer is None:
                if relative and last_content is not None:
                    buffer, tf = last_content.buffer, last_content.transforms
                else:
                    buffer, tf = sticky, transforms
            else:
                tf = ()
            items.append(Item('pcre', buffer=buffer, transforms=tf, regex=regex, negated=negated,
                              timed=_regex_engine is not None and not isinstance(regex, re.Pattern),
                              relative=relative, anchored=anchored, sticky=True))
        elif key == 'isdataat':
            negated = value.startswith('!')
            parts = [x.strip().lower() for x in value.lstrip('!').split(',')]
            relative = 'relative' in parts[1:]
            if relative and last_content is not None:
                buffer, tf = last_content.buffer, last_content.transforms
            else:
                buffer, tf = sticky, transforms
            items.append(Item('isdataat', buffer=buffer, transforms=tf, position=_int(parts[0], 'isdataat'),
                              negated=negated, relative=relative, sticky=True))
        elif key == 'bsize':
            if sticky == 'pkt':
                raise RuleError('"bsize" without a sticky buffer')
            bsizes[(sticky, transforms)] = _comparator(value, 'bsize')
        elif key == 'dsize':
            sig.dsize = _comparator(value, 'dsize')
        elif key == 'urilen':
            norm = 'norm' in value.lower()
            sig.urilen = (_comparator(value, 'urilen'), 'http.uri' if norm else 'http.uri.raw')
        elif key == 'flags':
            sig.flags = _flags_spec(value)
        elif key == 'flow':
            for token in (t.strip().lower() for t in value.split(',') if t.strip()):
                if token not in FLOW_TOKENS:
                    raise RuleError(f'unsupported flow option "{token}"')
                if token == 'established':
                    sig.established = True
                elif token == 'not_established':
                    sig.established = False
        elif key == 'flowbits':
            parts = [x.strip() for x in value.split(',', 1)]
            op = parts[0].lower()
            if op == 'noalert':
                sig.noalert = True
            elif op in ('set', 'unset', 'toggle', 'isset', 'isnotset') and len(parts) == 2 and parts[1]:
                mode = 'all' if '&' in parts[1] else 'any'
                names = tuple(n.strip() for n in re.split(r'[|&]', parts[1]) if n.strip())
                (checks if op in ('isset', 'isnotset') else actions).append((op, names, mode))
            else:
                raise RuleError(f'unsupported flowbits "{value}"')
        elif key == 'noalert':
            sig.noalert = True
        elif key == 'sameip':
            sig.sameip = True
        elif key == 'threshold':
            sig.threshold = _threshold_spec(value, 'threshold')
        elif key == 'detection_filter':
            sig.detection_filter = _threshold_spec(value, 'detection_filter')
        elif key == 'msg':
            sig.msg = _unquote(value).replace('\\"', '"').replace('\\;', ';').replace('\\\\', '\\')
        elif key == 'sid':
            sig.sid, explicit_sid = _int(value, 'sid'), True
        elif key == 'rev':
            sig.rev = _int(value, 'rev')
        elif key == 'gid':
            sig.gid = _int(value, 'gid')
        elif key == 'classtype':
            sig.classtype = value.strip()
        elif key == 'priority':
            priority = _int(value, 'priority')
        elif key == 'target':
            t = value.strip().lower()
            sig.target = 'src' if t == 'src_ip' else 'dst' if t == 'dest_ip' else None
        elif key in IGNORED:
            pass
        else:
            raise RuleError(f'unsupported keyword "{key}"')
        previous_key = key

    if not explicit_sid:
        raise RuleError('missing sid')
    sig.priority = priority if priority is not None else CLASSTYPE_PRIORITY.get(sig.classtype, DEFAULT_PRIORITY)
    sig.flowbit_checks, sig.flowbit_actions = tuple(checks), tuple(actions)
    sig.groups = _group(items, bsizes)
    _check_buffers(sig)
    action_rank = 0 if action == 'pass' else 1 if action in DROP_ACTIONS else 2
    flow_rank = (0 if actions and not checks else 1 if not actions and not checks else 2 if actions else 3)
    sig.order = action_rank * 4 + flow_rank
    return sig


def _apply_modifier(item: Item, name: str, value: str):
    if name == 'nocase':
        item.nocase = True
    elif name in ('depth', 'offset', 'distance', 'within'):
        number = _int(value, name)
        if name in ('depth', 'within') and number <= 0:
            raise RuleError(f'{name} must be positive')
        setattr(item, name, number)
    elif name == 'startswith':
        item.startswith = True
    elif name == 'endswith':
        item.endswith = True
    elif name in ('fast_pattern', 'fast_pattern_only', 'fast_pattern_offset', 'fast_pattern_length', 'rawbytes'):
        item.fast = item.fast or name == 'fast_pattern'
    else:
        raise RuleError(f'unsupported content option "{name}"')
    if (item.offset is not None or item.depth is not None) and (item.distance is not None or item.within is not None):
        raise RuleError('content mixes absolute (offset/depth) and relative (distance/within) modifiers')
    item.relative = item.distance is not None or item.within is not None


def _group(items: list[Item], bsizes: dict) -> tuple:
    groups: dict = {}
    for item in items:
        g = groups.get(item.key)
        if g is None:
            g = groups[item.key] = Group(item.key, [])
        g.items.append(item)
        g.needs_lower = g.needs_lower or (item.kind == 'content' and item.nocase)
    for key, check in bsizes.items():
        g = groups.get(key)
        if g is None:
            g = groups[key] = Group(key, [])
        g.bsize = check
    return tuple(groups.values())


def _check_buffers(sig: Signature):
    """Application buffers only exist for their protocol, so e.g. dns.query in an http rule can never match."""
    for g in sig.groups:
        name = g.key[0]
        family = 'http' if name.startswith('http.') else 'dns' if name == 'dns.query' else (
            'tls' if name == 'tls.sni' else None)
        if family and sig.proto not in (family, 'tcp', 'udp', 'ip'):
            raise RuleError(f'buffer {name} in a {sig.proto} rule')


# ----------------------------------------------------------------------------
# Per-packet view
# ----------------------------------------------------------------------------
_REQUEST = re.compile(rb'([A-Z][A-Z_-]{2,15}) (\S+) (HTTP/[0-9]\.[0-9])\r?\n')
TLS_RECORD_TYPES = frozenset({0x14, 0x15, 0x16, 0x17})


class _Http:
    __slots__ = ('method', 'uri_raw', 'protocol', 'request_line', 'start', 'header_raw', 'headers')

    def __init__(self, data: bytes, m):
        self.method, self.uri_raw, self.protocol = m.group(1), m.group(2), m.group(3)
        self.request_line = data[m.start():m.end()].rstrip(b'\r\n')
        end = data.find(b'\r\n\r\n', m.end())
        block_end = end if end >= 0 else len(data)
        self.start = data[:end + 4] if end >= 0 else data
        self.header_raw = data[m.end():block_end] + (b'\r\n' if end >= 0 else b'')
        headers = []
        for line in data[m.end():block_end].split(b'\n'):
            line = line.rstrip(b'\r')
            name, sep, value = line.partition(b':')
            if sep and name.strip():
                headers.append((name.strip(), value.strip()))
        self.headers = headers

    def header(self, lname: bytes) -> Optional[bytes]:
        values = [v for n, v in self.headers if n.lower() == lname]
        return b', '.join(values) if values else None


class _View:
    """Lazily built buffers and cached spec results for one packet."""
    __slots__ = ('p', 'src', 'dst', 'src_ip', 'dst_ip', 'sport', 'dport', 'data', 'flags', 'protos', 'flow_key',
                 '_buffers', '_lower', '_specs', '_http', '_http_done')

    def __init__(self, p, src: str, dst: str):
        self.p, self.src, self.dst = p, src, dst
        self.src_ip, self.dst_ip = _ip(src), _ip(dst)
        self.sport, self.dport = p.src_port, p.dst_port
        self.data = p.data or b''
        self.flags = str(p.flags or '')
        self._buffers, self._lower, self._specs = {}, {}, {}
        self._http, self._http_done = None, False
        a = (src, self.sport if self.sport is not None else -1)
        b = (dst, self.dport if self.dport is not None else -1)
        self.flow_key = (p.protocol,) + ((a, b) if a <= b else (b, a))
        self.protos = self._protocols()

    def http(self) -> Optional[_Http]:
        if not self._http_done:
            self._http_done = True
            if self.p.protocol == 'TCP' and self.data:
                m = _REQUEST.match(self.data)
                if m:
                    self._http = _Http(self.data, m)
        return self._http

    def _sni(self) -> Optional[bytes]:
        p = self.p
        if p.protocol == 'TCP' and p.payload and 53 not in (self.sport, self.dport) and p.dst_port not in HTTP_PORTS:
            return p.payload.encode('utf-8', 'replace')
        return None

    def _dns_query(self) -> Optional[bytes]:
        p = self.p
        if p.protocol in ('UDP', 'TCP') and p.payload and 53 in (self.sport, self.dport):
            return p.payload.rstrip('.').encode('utf-8', 'replace')
        return None

    def _protocols(self) -> frozenset:
        proto = self.p.protocol
        keys = {'ip'}
        ports = (self.sport, self.dport)
        if proto == 'TCP':
            keys.add('tcp')
            if self.http() is not None or any(x in HTTP_PORTS for x in ports) or self.data.startswith(b'HTTP/'):
                keys.add('http')
            if self._sni() is not None or (len(self.data) > 1 and self.data[0] in TLS_RECORD_TYPES
                                            and self.data[1] == 3):
                keys.add('tls')
            if 53 in ports:
                keys.add('dns')
        elif proto == 'UDP':
            keys.add('udp')
            if 53 in ports:
                keys.add('dns')
        elif proto in ('ICMP', 'ICMPv6'):
            keys.add('icmp')
        return frozenset(keys)

    def _base(self, name: str) -> Optional[bytes]:
        if name == 'pkt':
            return self.data
        if name == 'dns.query':
            return self._dns_query()
        if name == 'tls.sni':
            return self._sni()
        h = self.http()
        if h is None:
            return None
        if name == 'http.uri':
            return unquote_to_bytes(h.uri_raw)
        if name == 'http.uri.raw':
            return h.uri_raw
        if name == 'http.method':
            return h.method
        if name == 'http.protocol':
            return h.protocol
        if name == 'http.request_line':
            return h.request_line
        if name == 'http.start':
            return h.start
        if name == 'http.header':
            return b''.join(n + b': ' + v + b'\r\n' for n, v in h.headers)
        if name == 'http.header.raw':
            return h.header_raw
        if name == 'http.header_names':
            return b'\r\n' + b'\r\n'.join(n for n, _ in h.headers) + b'\r\n\r\n'
        if name in ('http.host', 'http.host.raw'):
            raw = h.header(b'host')
            if raw is None or name == 'http.host.raw':
                return raw
            host = raw.lower()
            if not host.startswith(b'[') and host.count(b':') == 1:
                host = host.split(b':', 1)[0]
            return host
        lname = HEADER_BUFFERS.get(name)
        return h.header(lname) if lname else None

    def buffer(self, key: tuple) -> Optional[bytes]:
        if key in self._buffers:
            return self._buffers[key]
        name, transforms = key
        value = self._base(name)
        if value is not None:
            for t in transforms:
                value = TRANSFORMS[t](value)
        self._buffers[key] = value
        return value

    def lower(self, key: tuple) -> Optional[bytes]:
        if key in self._lower:
            return self._lower[key]
        value = self.buffer(key)
        low = value.lower() if value is not None else None
        self._lower[key] = low
        return low

    def spec(self, node, value) -> bool:
        if node.is_any:
            return True
        k = (id(node), value)
        result = self._specs.get(k)
        if result is None:
            result = self._specs[k] = node.test(value)
        return result


def _ip(value: str):
    try:
        return ipaddress.ip_address(canonical_ip(value))
    except ValueError:
        return None


# ----------------------------------------------------------------------------
# Matching
# ----------------------------------------------------------------------------
def _match_items(buf: bytes, low: Optional[bytes], items: list, i: int, prev_end: int) -> bool:
    if i == len(items):
        return True
    it = items[i]
    n = len(buf)
    if it.kind == 'isdataat':
        # As in Suricata: absolute N means a byte exists at index N; relative N means at least N bytes
        # remain after the previous match.
        ok = prev_end + it.position <= n if it.relative else it.position < n
        return (ok != it.negated) and _match_items(buf, low, items, i + 1, prev_end)
    if it.kind == 'pcre':
        start = prev_end if it.relative else 0
        if start > n:
            return it.negated and _match_items(buf, low, items, i + 1, prev_end)
        # A relative pcre sees the rest of the buffer as its subject, so ^ anchors at the previous match.
        subject = buf[start:] if start else buf
        try:
            m = _pcre_run(it, subject, it.anchored)
        except PcreTimeout:
            # Fail closed: the result is unknown, so assume the rule's condition holds (a negated pcre is
            # assumed absent). Later relative checks continue from where the pcre's subject started.
            return _match_items(buf, low, items, i + 1, prev_end if it.negated else start)
        if it.negated:
            return m is None and _match_items(buf, low, items, i + 1, prev_end)
        return m is not None and _match_items(buf, low, items, i + 1, start + m.end())
    pattern = it.lower if it.nocase else it.pattern
    hay = low if it.nocase else buf
    size = len(pattern)
    if it.relative:
        lo = prev_end + (it.distance or 0)
        hi = lo + it.within if it.within is not None else n
    else:
        lo = it.offset or 0
        hi = lo + it.depth if it.depth is not None else n
    if it.startswith:
        hi = min(hi, lo + size) if it.relative else min(hi, size)
        lo = lo if it.relative else 0
    lo, hi = max(lo, 0), min(hi, n)
    if it.endswith:
        lo = max(lo, n - size)
    if it.negated:
        found = hi - lo >= size and hay.find(pattern, lo, hi) >= 0
        return not found and _match_items(buf, low, items, i + 1, prev_end)
    if hi - lo < size:
        return False
    pos, tries = hay.find(pattern, lo, hi), 0
    while pos >= 0 and tries < SIG_BACKTRACK:
        end = pos + size
        if (not it.endswith or end == n) and _match_items(buf, low, items, i + 1, end):
            return True
        pos, tries = hay.find(pattern, pos + 1, hi), tries + 1
    return False


def _header_ok(sig: Signature, v: _View) -> bool:
    def side(src_node, src_ip, sport_node, sport, dst_node, dst_ip, dport_node, dport):
        return (v.spec(sport_node, sport) and v.spec(dport_node, dport)
                and v.spec(src_node, src_ip) and v.spec(dst_node, dst_ip))
    if side(sig.src, v.src_ip, sig.sport, v.sport, sig.dst, v.dst_ip, sig.dport, v.dport):
        return True
    return sig.bidirectional and side(sig.src, v.dst_ip, sig.sport, v.dport, sig.dst, v.src_ip, sig.dport, v.sport)


def _established(v: _View) -> bool:
    if v.p.protocol != 'TCP':
        return True                     # UDP/ICMP flows: approximated as established
    flags = v.flags.upper()
    return 'A' in flags and 'S' not in flags


@dataclass
class _FlowState:
    last: float
    bits: set = field(default_factory=set)


class RuleSet:
    """Compiled rules with a prefilter index, flowbits and threshold state."""

    def __init__(self, signatures: Iterable[Signature] = ()):
        self.rules: list[Signature] = list(signatures)
        for uid, sig in enumerate(self.rules):
            sig.uid = uid
        self.errors = 0
        self._flows: OrderedDict = OrderedDict()
        self._limits: dict = {}
        self._disabled_uids: frozenset = frozenset()
        self.pcre_timeouts = 0                      # pcre runs that hit SIG_PCRE_TIMEOUT (ReDoS protection)
        self._backoff: OrderedDict = OrderedDict()  # (uid, src) -> time until which the pcre is assumed matched
        self.last_timeouts: list[Signature] = []    # rules whose pcre timed out in the last match() call
        self.last_assumed: set[int] = set()         # uids that alerted on an assumed pcre in the last call
        self._build_index()

    # -- per-rule switches ---------------------------------------------------------
    def set_disabled(self, keys: Iterable[str]) -> int:
        """Turn off the rules whose rule_key() is in `keys`. Returns how many loaded rules are now off."""
        wanted = set(keys)
        self._disabled_uids = frozenset(s.uid for s in self.rules if rule_key(s) in wanted)
        return len(self._disabled_uids)

    def is_disabled(self, sig: Signature) -> bool:
        return sig.uid in self._disabled_uids

    # -- index -----------------------------------------------------------------
    def _build_index(self):
        fast = {}
        for sig in self.rules:
            item = _fast_pattern(sig)
            if item is not None:
                fast[sig.uid] = item
        gram_counts: Counter = Counter()
        for item in fast.values():
            low = item.lower
            gram_counts.update({low[i:i + 4] for i in range(len(low) - 3)})
        self._grams: dict = {}
        self._short: dict = {}
        self._hosts: dict = {}
        self._always: list = []
        for sig in self.rules:
            item = fast.get(sig.uid)
            if item is not None:
                low = item.lower
                if len(low) >= 4:
                    gram = min((low[i:i + 4] for i in range(len(low) - 3)), key=lambda g: gram_counts[g])
                    self._grams.setdefault(item.key, {}).setdefault(gram, []).append(sig)
                else:
                    self._short.setdefault(item.key, []).append((low, sig))
                continue
            hosts = _host_list(sig)
            if hosts:
                for h in hosts:
                    self._hosts.setdefault(h, []).append(sig)
            else:
                self._always.append(sig)

    def candidates(self, v: _View) -> list[Signature]:
        found: dict[int, Signature] = {}
        for sig in self._always:
            found[sig.uid] = sig
        if self._hosts:
            for ip in (v.src, v.dst):
                for sig in self._hosts.get(ip, ()):
                    found[sig.uid] = sig
        for key, table in self._grams.items():
            low = v.lower(key)
            if low is None or len(low) < 4:
                continue
            get = table.get
            for i in range(len(low) - 3):
                hits = get(low[i:i + 4])
                if hits:
                    for sig in hits:
                        found[sig.uid] = sig
        for key, entries in self._short.items():
            low = v.lower(key)
            if low:
                for pattern, sig in entries:
                    if pattern in low:
                        found[sig.uid] = sig
        return sorted((s for s in found.values() if s.proto in v.protos), key=lambda s: (s.order, s.uid))

    # -- evaluation --------------------------------------------------------------
    def _flow(self, v: _View, now: float, create: bool) -> Optional[_FlowState]:
        state = self._flows.get(v.flow_key)
        if state is None and create:
            state = self._flows[v.flow_key] = _FlowState(now)
            while len(self._flows) > SIG_FLOW_CAP:
                self._flows.popitem(last=False)
        if state is not None:
            state.last = now
            self._flows.move_to_end(v.flow_key)
        return state

    def evaluate(self, sig: Signature, v: _View, now: float) -> bool:
        """True if every condition of `sig` holds for the packet (no side effects)."""
        if sig.proto not in v.protos or not _header_ok(sig, v):
            return False
        if sig.sameip and v.src != v.dst:
            return False
        if sig.flags is not None and (v.p.protocol != 'TCP' or not _flags_ok(sig.flags, v.flags)):
            return False
        if sig.established is not None and _established(v) != sig.established:
            return False
        if sig.dsize is not None and not sig.dsize(len(v.data)):
            return False
        if sig.urilen is not None:
            uri = v.buffer((sig.urilen[1], ()))
            if uri is None or not sig.urilen[0](len(uri)):
                return False
        if sig.flowbit_checks:
            state = self._flows.get(v.flow_key)
            bits = state.bits if state is not None else set()
            for op, names, mode in sig.flowbit_checks:
                present = [n in bits for n in names]
                ok = all(present) if mode == 'all' else any(present)
                if (op == 'isset') != ok:
                    return False
        for g in sig.groups:
            buf = v.buffer(g.key)
            if buf is None:
                return False
            if g.bsize is not None and not g.bsize(len(buf)):
                return False
            if g.items and not _match_items(buf, v.lower(g.key) if g.needs_lower else None, g.items, 0, 0):
                return False
        return True

    def _apply_flowbits(self, sig: Signature, v: _View, now: float):
        state = self._flow(v, now, create=True)
        for op, names, _mode in sig.flowbit_actions:
            for name in names:
                if op == 'set':
                    state.bits.add(name)
                elif op == 'unset':
                    state.bits.discard(name)
                elif name in state.bits:
                    state.bits.discard(name)
                else:
                    state.bits.add(name)

    def _track(self, track: str, v: _View):
        return {'by_src': v.src, 'by_dst': v.dst, 'by_both': (v.src, v.dst), 'by_rule': None,
                'by_flow': v.flow_key}[track]

    def _rate_ok(self, sig: Signature, v: _View, now: float) -> bool:
        if sig.detection_filter is not None:
            _type, track, count, seconds = sig.detection_filter
            key = ('df', sig.uid, self._track(track, v))
            w = self._limits.get(key)
            if w is None or now - w[0] > seconds:
                w = self._limits[key] = [now, 0, False, seconds]
            w[1] += 1
            if w[1] <= count:
                return False
        if sig.threshold is not None:
            ttype, track, count, seconds = sig.threshold
            key = ('th', sig.uid, self._track(track, v))
            w = self._limits.get(key)
            if w is None or now - w[0] > seconds:
                w = self._limits[key] = [now, 0, False, seconds]
            w[1] += 1
            if ttype == 'limit':
                return w[1] <= count
            if ttype == 'threshold':
                if w[1] >= count:
                    self._limits[key] = [now, 0, False, seconds]
                    return True
                return False
            if w[1] >= count and not w[2]:
                w[2] = True
                return True
            return False
        return True

    def match(self, packet, src: str, dst: str, now: float) -> list[Signature]:
        """Signatures that alert for this packet, after pass rules, flowbits and thresholds."""
        if not self.rules:
            return []
        v = _View(packet, src, dst)
        alerts = []
        self.last_timeouts = []
        self.last_assumed = set()
        disabled = self._disabled_uids
        guard = _PCRE_GUARD
        backoff = self._backoff
        for sig in self.candidates(v):
            if sig.uid in disabled:
                continue
            key = (sig.uid, src)
            until = backoff.get(key) if backoff else None
            if until is not None and now >= until:
                del backoff[key]
                until = None
            guard.skip, guard.hit, guard.timed_out = until is not None, False, False
            try:
                ok = self.evaluate(sig, v, now)
            except Exception:
                self.errors += 1
                continue
            finally:
                guard.skip = False
            if guard.timed_out:
                self.pcre_timeouts += 1
                self.last_timeouts.append(sig)
                backoff[key] = now + SIG_PCRE_BACKOFF
                backoff.move_to_end(key)
                while len(backoff) > SIG_PCRE_BACKOFF_CAP:
                    backoff.popitem(last=False)
            if not ok:
                continue
            if guard.hit:
                if sig.action == 'pass':
                    continue                # an assumed match must never let traffic skip the other rules
                self.last_assumed.add(sig.uid)
            if sig.action == 'pass':
                return []
            if sig.flowbit_actions:
                self._apply_flowbits(sig, v, now)
            if sig.noalert or not self._rate_ok(sig, v, now):
                continue
            alerts.append(sig)
        return alerts

    def match_all(self, packet, src: str, dst: str, now: float) -> list[Signature]:
        """Reference matcher without the prefilter (for tests): rules whose conditions hold."""
        v = _View(packet, src, dst)
        return [s for s in sorted(self.rules, key=lambda s: (s.order, s.uid)) if self.evaluate(s, v, now)]

    # -- state -------------------------------------------------------------------
    def reset_state(self):
        self._flows.clear()
        self._limits.clear()
        self._backoff.clear()

    def prune(self, now: float):
        for key in [k for k, s in self._flows.items() if now - s.last > SIG_FLOW_TIMEOUT]:
            del self._flows[key]
        for key in [k for k, w in self._limits.items() if now - w[0] > w[3]]:
            del self._limits[key]


def rule_key(sig: Signature) -> str:
    """Stable identity for a rule across reloads: 'gid:sid'."""
    return f'{sig.gid}:{sig.sid}'


# ----------------------------------------------------------------------------
# Rule levels: which downloaded rules are on without the user choosing each one
# ----------------------------------------------------------------------------
STARTER_RULES = Path(__file__).resolve().parent / 'assets' / 'starter.rules'
RULE_LEVELS = (('balanced', 'Balanced (recommended)'), ('essential', 'Essential: high severity only'),
               ('all', 'Everything'))
# Informational and policy rules: true but rarely an attack, and they fire on ordinary home traffic
# (dynamic DNS names, games, chat and file-sharing apps, "what is my IP" checks, ...).
NOISY_CLASSTYPES = frozenset({'misc-activity', 'not-suspicious', 'protocol-command-decode', 'unknown',
                              'external-ip-check', 'policy-violation', 'string-detect'})
NOISY_PREFIXES = ('ET INFO', 'ET HUNTING', 'ET POLICY', 'ET DYN_DNS', 'ET RETIRED', 'ET GAMES', 'ET CHAT',
                  'ET P2P', 'ET FILE_SHARING', 'ET TA_ABUSED_SERVICES', 'GPL ICMP_INFO', 'GPL INFO')


@functools.lru_cache(maxsize=4096)
def source_name(source: str) -> str:
    """File name of a rule's source. Cached: 42,000 ET rules share about 50 sources, and building a Path
    per rule made switching rule levels and loading the rule list take seconds."""
    return Path(source).name if source else ''


def is_starter(sig: Signature) -> bool:
    return source_name(sig.source) == STARTER_RULES.name


def is_always_on(sig: Signature) -> bool:
    """Built-in starter rules and the user's own rules ignore the rule level."""
    return source_name(sig.source) in (STARTER_RULES.name, 'local.rules')


def level_off(rules: Iterable[Signature], level: str) -> set[str]:
    """Rule keys that `level` switches off. Built-in starter rules and My rules are always on."""
    if level == 'all':
        return set()
    off = set()
    for s in rules:
        if is_always_on(s):
            continue
        noisy = (s.classtype or 'unclassified') in NOISY_CLASSTYPES or s.msg.startswith(NOISY_PREFIXES)
        if noisy or (level == 'essential' and s.priority != 1):
            off.add(rule_key(s))
    return off


def effective_off(rules: Iterable[Signature], level: str, user_off: Iterable[str],
                  user_on: Iterable[str]) -> set[str]:
    """Rules that are off: the level's choice, overridden by the user's own switches."""
    return (level_off(rules, level) - set(user_on)) | set(user_off)


EXPLAIN_CONTEXT = 24        # bytes shown on each side of a matched content
EXPLAIN_MAX_TEXT = 700      # characters of rule text shown


def _printable(data: bytes, limit: int = 120) -> str:
    text = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data[:limit])
    return text + ('...' if len(data) > limit else '')


def explain_match(sig: Signature, packet, src: str, dst: str, context: bool = False,
                  pcre_assumed: bool = False) -> str:
    """Why `sig` matched `packet`: the rule, then each buffer and where each content was found.

    Packet bytes around a match are only shown when `context` is True (payload saving is on), because
    they can contain user data. Rule contents themselves come from the rule file and are always shown.
    `pcre_assumed`: the match relied on a timed-out (or backed-off) pcre, so do not run the pcre again.
    """
    guard = _PCRE_GUARD
    old, guard.skip = guard.skip, pcre_assumed
    try:
        return _explain(sig, packet, src, dst, context)
    finally:
        guard.skip = old


def _explain(sig: Signature, packet, src: str, dst: str, context: bool) -> str:
    v = _View(packet, src, dst)
    lines = [f'Rule [{sig.gid}:{sig.sid}:{sig.rev}] {sig.msg or "(no message)"}',
             f'Action {sig.action}; protocol {sig.proto}; priority {sig.priority} ({sig.severity}); '
             f'classtype {sig.classtype or "unclassified"}'
             + (f'; from {Path(sig.source).name} line {sig.line}' if sig.source else '')]
    checks = []
    if sig.flags is not None:
        checks.append(f'TCP flags {v.flags or "-"}')
    if sig.established is not None:
        checks.append('established connection' if sig.established else 'not established')
    if sig.dsize is not None:
        checks.append(f'payload size {len(v.data)} bytes')
    if sig.flowbit_checks:
        checks.append('flowbits ' + ', '.join(f'{op} {"|".join(names)}' for op, names, _ in sig.flowbit_checks))
    lines.append(f'Header matched: {sig.proto} {src}:{v.sport if v.sport is not None else "any"} -> '
                 f'{dst}:{v.dport if v.dport is not None else "any"}'
                 + (f'; {"; ".join(checks)}' if checks else ''))
    for g in sig.groups:
        name, transforms = g.key
        label = name + (f' (transforms: {", ".join(transforms)})' if transforms else '')
        buf = v.buffer(g.key)
        if buf is None:
            lines.append(f'  {label}: not present')
            continue
        lines.append(f'  Buffer {label}, {len(buf)} bytes:')
        low = buf.lower()
        prev = 0
        for it in g.items:
            if it.kind == 'content':
                desc = f'content "{_printable(it.pattern, 80)}"' + (' (nocase)' if it.nocase else '')
                if it.negated:
                    lines.append(f'    {desc}: absent, as the rule requires')
                    continue
                pat, hay = (it.lower, low) if it.nocase else (it.pattern, buf)
                pos = hay.find(pat, prev if it.relative else 0)
                if pos < 0:
                    pos = hay.find(pat)
                if pos < 0:
                    lines.append(f'    {desc}: matched')
                    continue
                prev = pos + len(pat)
                line = f'    {desc}: found at byte {pos}'
                if context:
                    a, b = max(0, pos - EXPLAIN_CONTEXT), min(len(buf), prev + EXPLAIN_CONTEXT)
                    line += f'\n      packet: {"..." if a else ""}{_printable(buf[a:b], 200)}{"..." if b < len(buf) else ""}'
                lines.append(line)
            elif it.kind == 'pcre':
                pattern = it.regex.pattern if it.regex is not None else ''
                if isinstance(pattern, bytes):
                    pattern = pattern.decode('latin-1')
                if it.negated:
                    lines.append(f'    pcre /{pattern[:80]}/: no match, as the rule requires')
                    continue
                try:
                    m = _pcre_run(it, buf, pos=prev if it.relative else 0) if it.regex is not None else None
                except PcreTimeout:
                    lines.append(f'    pcre /{pattern[:80]}/: timed out (possible ReDoS); treated as match')
                    continue
                if m is None:
                    lines.append(f'    pcre /{pattern[:80]}/: matched')
                    continue
                prev = m.end()
                line = f'    pcre /{pattern[:80]}/: matched bytes {m.start()}-{m.end()}'
                if context:
                    line += f'\n      packet: {_printable(m.group(0), 200)}'
                lines.append(line)
            else:
                lines.append(f'    isdataat {it.position}{" relative" if it.relative else ""}: satisfied')
    if not sig.groups:
        lines.append('  No content checks: the header and options above decided the match.')
    if not context and any(it.kind != 'isdataat' for g in sig.groups for it in g.items):
        lines.append('  (Turn on "Save packet payloads" on the Dashboard to also see the matching packet bytes.)')
    text = ' '.join(sig.text.split())
    if text:
        lines.append('Rule text: ' + (text[:EXPLAIN_MAX_TEXT] + ' ...' if len(text) > EXPLAIN_MAX_TEXT else text))
    return '\n'.join(lines)


def _fast_pattern(sig: Signature) -> Optional[Item]:
    contents = [it for g in sig.groups for it in g.items if it.kind == 'content' and not it.negated]
    if not contents:
        return None
    marked = [it for it in contents if it.fast]
    return max(marked or contents, key=lambda it: len(it.pattern))


def _host_list(sig: Signature) -> Optional[frozenset]:
    """Exact hosts for a content-less rule whose source or destination is a plain host list."""
    for node in (sig.src, sig.dst):
        hosts = getattr(node, 'hosts', None)
        if hosts:
            return hosts
    return None


# ----------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------
@dataclass
class LoadReport:
    files: int = 0
    seen: int = 0
    loaded: int = 0
    reasons: Counter = field(default_factory=Counter)
    examples: list = field(default_factory=list)       # (file, line, reason, rule text)
    errors: list = field(default_factory=list)
    home_net: str = ''

    @property
    def skipped(self) -> int:
        return self.seen - self.loaded

    def skip(self, source: str, line: int, reason: str, text: str):
        self.reasons[reason] += 1
        if len(self.examples) < SIG_MAX_EXAMPLES:
            self.examples.append((source, line, reason, text[:400]))

    def summary(self) -> str:
        text = (f'Loaded {self.loaded:,} of {self.seen:,} rules from {self.files:,} file(s); '
                f'{self.skipped:,} skipped.')
        if self.reasons:
            top = ', '.join(f'{reason} ({count:,})' for reason, count in self.reasons.most_common(3))
            text += f' Most common skip reasons: {top}.'
        if self.errors:
            text += f' {len(self.errors)} file error(s): {self.errors[0]}'
        if not PCRE_TIMEOUT_AVAILABLE and self.loaded:
            text += ' ' + PCRE_TIMEOUT_WARNING
        return text


def local_networks() -> list[str]:
    """This computer's networks that the private ranges miss: IPv6 /64 prefixes and public IPv4 hosts.

    Home connections usually have public IPv6 addresses, and Windows rotates the temporary ones, so
    the whole /64 is used.
    """
    from .addresses import PROTECTED
    nets = set()
    for value in PROTECTED.local():
        addr = _ip(value)
        if addr is None or addr.is_loopback or addr.is_link_local or addr.is_private or addr.is_unspecified:
            continue
        prefix = 64 if addr.version == 6 else 32
        nets.add(str(ipaddress.ip_network(f'{addr}/{prefix}', strict=False)))
    return sorted(nets)


def default_home_net() -> str:
    return '[' + ','.join([SIG_DEFAULT_HOME_NET[1:-1]] + local_networks()) + ']'


def variables_for(home_net: str = '') -> dict:
    variables = dict(DEFAULT_VARIABLES)
    variables['HOME_NET'] = home_net.strip() or default_home_net()
    return variables


def validate_home_net(text: str) -> Optional[str]:
    """Error message for an invalid HOME_NET value, or None."""
    if not text.strip():
        return None
    try:
        _Interner(dict(DEFAULT_VARIABLES, HOME_NET=text.strip())).addr('$HOME_NET')
    except RuleError as exc:
        return f'Invalid HOME_NET: {exc}'
    return None


def _logical_lines(text: str):
    """Yield (line number, rule text) joining backslash continuations; skips blanks and comments."""
    buffer, start = '', 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buffer:
            start = number
        if line.endswith('\\'):
            buffer += line[:-1]
            continue
        buffer += line
        stripped = buffer.strip()
        buffer = ''
        if stripped and not stripped.startswith('#'):
            yield start, stripped
    if buffer.strip() and not buffer.strip().startswith('#'):
        yield start, buffer.strip()


def parse_text(text: str, source: str, interner: _Interner, report: LoadReport, seen_ids: set,
               out: list) -> None:
    for line, rule in _logical_lines(text):
        report.seen += 1
        first = rule.split(None, 1)[0].lower()
        if first in CONFIG_PREFIXES:
            report.skip(source, line, 'not a rule (configuration line)', rule)
            continue
        try:
            sig = parse_rule(rule, interner, source, line)
        except RuleError as exc:
            report.skip(source, line, str(exc), rule)
            continue
        except Exception as exc:             # a parser bug must not stop the rest of the file loading
            report.skip(source, line, f'parser error ({exc.__class__.__name__})', rule)
            continue
        ident = (sig.gid, sig.sid)
        if ident in seen_ids:
            report.skip(source, line, 'duplicate sid', rule)
            continue
        seen_ids.add(ident)
        out.append(sig)
        report.loaded += 1


class ArchiveError(ValueError):
    """A rule archive is unsafe or too large to load."""


def check_archive_members(members: list[tuple[str, int]], archive: str = 'archive'):
    """Refuse archives with too many members, too much content, or unsafe names. Raises ArchiveError.

    Rules are read in memory and never extracted to disk, but names are still checked so a malicious
    archive cannot smuggle path tricks into messages or a future extraction step.
    """
    if len(members) > SIG_ARCHIVE_MAX_MEMBERS:
        raise ArchiveError(f'{archive} has {len(members):,} rule files; the limit is {SIG_ARCHIVE_MAX_MEMBERS:,}')
    total = sum(max(0, size) for _name, size in members)
    if total > SIG_ARCHIVE_MAX_BYTES:
        raise ArchiveError(f'{archive} would unpack to {total / 1_048_576:.0f} MB of rules; the limit is '
                           f'{SIG_ARCHIVE_MAX_BYTES // 1_048_576} MB')
    for name, _size in members:
        parts = name.replace('\\', '/').split('/')
        if name.startswith(('/', '\\')) or '..' in parts or (len(name) > 1 and name[1] == ':'):
            raise ArchiveError(f'{archive} contains an unsafe path: {name[:80]}')


def _rule_sources(path: Path):
    """Yield (name, text) for every rule file in a file, folder or archive."""
    name = path.name.lower()
    if path.is_dir():
        for p in sorted(path.rglob('*.rules')):
            yield str(p), p.read_text(encoding='utf-8', errors='replace')
    elif name.endswith(('.tar.gz', '.tgz', '.tar')):
        with tarfile.open(path) as tar:
            members = [m for m in tar.getmembers() if m.isfile() and m.name.endswith('.rules')]
            check_archive_members([(m.name, m.size) for m in members], path.name)
            for member in sorted(members, key=lambda m: m.name):
                f = tar.extractfile(member)
                if f is not None:
                    # Read no more than the declared size, so a lying header cannot inflate memory use.
                    yield f'{path.name}/{member.name}', f.read(member.size).decode('utf-8', 'replace')
    elif name.endswith('.zip'):
        with zipfile.ZipFile(path) as z:
            infos = [i for i in z.infolist() if not i.is_dir() and i.filename.endswith('.rules')]
            check_archive_members([(i.filename, i.file_size) for i in infos], path.name)
            for info in sorted(infos, key=lambda i: i.filename):
                with z.open(info) as f:
                    yield f'{path.name}/{info.filename}', f.read(info.file_size + 1)[:info.file_size].decode(
                        'utf-8', 'replace')
    else:
        yield str(path), path.read_text(encoding='utf-8', errors='replace')


def load_paths(paths: Iterable[str], home_net: str = '',
               should_stop: Callable[[], bool] = lambda: False) -> tuple[RuleSet, LoadReport]:
    """Load rules from files, folders and archives. Never raises for bad input; see the report."""
    variables = variables_for(home_net)
    report = LoadReport(home_net=variables['HOME_NET'])
    interner = _Interner(variables)
    signatures: list[Signature] = []
    seen_ids: set = set()
    for raw in paths:
        path = Path(raw)
        if should_stop():
            break
        if not path.exists():
            report.errors.append(f'{raw}: not found')
            continue
        try:
            for name, text in _rule_sources(path):
                if should_stop():
                    break
                report.files += 1
                parse_text(text, name, interner, report, seen_ids, signatures)
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ArchiveError, EOFError) as exc:
            report.errors.append(f'{raw}: {exc}')
    return RuleSet(signatures), report


def compile_rules(text: str, home_net: str = '', source: str = 'inline') -> tuple[RuleSet, LoadReport]:
    """Load rules from a string (used by tests and tools)."""
    variables = variables_for(home_net)
    report = LoadReport(files=1, home_net=variables['HOME_NET'])
    signatures: list[Signature] = []
    parse_text(text, source, _Interner(variables), report, set(), signatures)
    return RuleSet(signatures), report
