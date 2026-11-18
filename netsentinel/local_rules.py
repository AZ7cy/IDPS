"""The user's own rules ("My rules"): templates, checking, and the local.rules file (Qt-free)."""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import DATA_DIR

LOCAL_RULES = DATA_DIR / 'rules' / 'local.rules'
SID_MIN, SID_MAX = 1_000_001, 1_999_999          # the range Snort and Suricata reserve for local rules
SEVERITIES = (('HIGH', 1), ('MEDIUM', 2), ('LOW', 3))
_SID = re.compile(r'\bsid\s*:\s*(\d+)\s*;')
_MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')
HEADER = ('# My rules: written in NetSentinel on the Signatures tab. One rule per line; # starts a comment.\n'
          '# SIDs 1000001-1999999 are for local rules.\n')


@dataclass(frozen=True)
class Template:
    key: str
    label: str              # shown in the template list
    value_label: str        # what the value field asks for
    example: str            # placeholder for the value field
    message: str            # default alert message; {v} is the value
    rule: str               # rule body; {v} = escaped value, {msg}, {prio}, {sid}


TEMPLATES = (
    Template('dns', 'A website is looked up (DNS)', 'Domain', 'tiktok.com', 'Lookup of {v}',
             'alert dns $HOME_NET any -> any any (msg:"{msg}"; dns.query; content:"{v}"; nocase; endswith; '
             'priority:{prio}; sid:{sid}; rev:1;)'),
    Template('tls', 'An HTTPS site is opened (server name)', 'Site name contains', 'bet365',
             'HTTPS connection to {v}',
             'alert tls $HOME_NET any -> any any (msg:"{msg}"; tls.sni; content:"{v}"; nocase; '
             'priority:{prio}; sid:{sid}; rev:1;)'),
    Template('uri', 'A page on your web server is requested', 'Page path', '/admin', 'Request for {v}',
             'alert http any any -> $HOME_NET any (msg:"{msg}"; flow:to_server; http.uri; content:"{v}"; nocase; '
             'priority:{prio}; sid:{sid}; rev:1;)'),
    Template('ua', 'A browser or tool is used (User-Agent)', 'User-Agent contains', 'curl/',
             'HTTP client {v}',
             'alert http any any -> any any (msg:"{msg}"; flow:to_server; http.user_agent; content:"{v}"; nocase; '
             'priority:{prio}; sid:{sid}; rev:1;)'),
    Template('word', 'A word or phrase is sent unencrypted', 'Word or phrase', 'PROJECT-ORION',
             '"{v}" sent unencrypted',
             'alert tcp any any -> any any (msg:"{msg}"; content:"{v}"; nocase; priority:{prio}; sid:{sid}; rev:1;)'),
    Template('ip', 'Traffic to or from an address', 'IP address or range', '203.0.113.66',
             'Traffic with {v}',
             'alert ip {v} any <> any any (msg:"{msg}"; threshold:type limit, track by_both, count 1, seconds 300; '
             'priority:{prio}; sid:{sid}; rev:1;)'),
    Template('port', 'A connection to a port', 'Port or ports (e.g. 6667,6697)', '6667',
             'Connection to port {v}',
             'alert tcp $HOME_NET any -> any [{v}] (msg:"{msg}"; flags:S; threshold:type limit, track by_src, '
             'count 1, seconds 300; priority:{prio}; sid:{sid}; rev:1;)'),
    Template('block', 'Block a page on your web server (inline IPS)', 'Page path', '/wp-login.php',
             'Blocked request for {v}',
             'drop http any any -> $HOME_NET any (msg:"{msg}"; flow:to_server; http.uri; content:"{v}"; nocase; '
             'priority:{prio}; sid:{sid}; rev:1;)'),
    Template('custom', 'Write your own rule', '', '', 'My rule',
             'alert tcp any any -> any any (msg:"{msg}"; content:"change me"; priority:{prio}; sid:{sid}; rev:1;)'),
)
TEMPLATE_BY_KEY = {t.key: t for t in TEMPLATES}


class RuleInputError(ValueError):
    pass


def escape_content(value: str) -> str:
    """Text for inside content:"..." — characters with a meaning in rules are written as hex bytes."""
    out = []
    for ch in value:
        if ch in '";\\|' or not ch.isprintable():
            out.append('|' + ' '.join(f'{b:02X}' for b in ch.encode('utf-8')) + '|')
        else:
            out.append(ch)
    return ''.join(out)


def escape_message(value: str) -> str:
    return ''.join('' if ch in '"\\;' or not ch.isprintable() else ch for ch in value).strip()[:120]


def _value(template: Template, value: str) -> str:
    value = value.strip()
    if template.key == 'custom':
        return ''
    if not value:
        raise RuleInputError(f'Enter a {template.value_label.lower()}.')
    if template.key == 'ip':
        try:
            if '/' not in value:
                return str(ipaddress.ip_address(value))
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise RuleInputError(f'"{value}" is not an IP address or range.') from exc
    if template.key == 'port':
        ports = [p.strip() for p in value.replace(' ', ',').split(',') if p.strip()]
        if not ports or not all(p.isdigit() and 0 < int(p) < 65536 for p in ports):
            raise RuleInputError('Enter port numbers from 1 to 65535, separated by commas.')
        return ','.join(str(int(p)) for p in ports)
    if template.key == 'dns':
        value = value.lower().removeprefix('http://').removeprefix('https://').split('/')[0].strip('.')
        if not value or ' ' in value:
            raise RuleInputError('Enter a domain name such as example.com.')
    if len(value) > 200:
        raise RuleInputError('The value is too long (200 characters at most).')
    return value


def build_rule(key: str, value: str, severity: str = 'MEDIUM', message: str = '', sid: int = SID_MIN) -> str:
    """Rule text for a template. Raises RuleInputError for an unusable value."""
    template = TEMPLATE_BY_KEY[key]
    v = _value(template, value)
    shown = v if template.key in ('ip', 'port', 'dns') else value.strip()
    msg = escape_message(message) or escape_message(template.message.format(v=shown))
    prio = dict(SEVERITIES).get(severity, 2)
    body_value = v if template.key in ('ip', 'port') else escape_content(v)
    return template.rule.format(v=body_value, msg=msg, prio=prio, sid=sid)


def rule_sid(text: str) -> Optional[int]:
    m = _SID.search(text)
    return int(m.group(1)) if m else None


def rule_message(text: str) -> str:
    m = _MSG.search(text)
    return m.group(1) if m else ''


def check_rule(text: str) -> str:
    """'' if `text` is exactly one rule NetSentinel can load, else the reason it can't."""
    from .signatures import compile_rules
    lines = [ln for ln in text.strip().splitlines() if ln.strip() and not ln.lstrip().startswith('#')]
    if not lines:
        return 'The rule is empty.'
    if len(lines) > 1 and not all(ln.rstrip().endswith('\\') for ln in lines[:-1]):
        return 'Write one rule at a time (one line).'
    sid = rule_sid(text)
    if sid is None:
        return 'The rule needs a sid, for example sid:1000001;'
    if not SID_MIN <= sid <= SID_MAX:
        return f'Use a sid from {SID_MIN} to {SID_MAX} for your own rules.'
    rule_set, report = compile_rules(text)
    if len(rule_set.rules) == 1:
        return ''
    if report.examples:
        return f'NetSentinel cannot load this rule: {report.examples[0][2]}.'
    return 'NetSentinel cannot load this rule.'


def _path(path: Optional[Path]) -> Path:
    """`path`, or LOCAL_RULES looked up now (not when the function was defined), so tests can redirect it."""
    return Path(path) if path is not None else LOCAL_RULES


def read_rules(path: Optional[Path] = None) -> list[str]:
    """The rule lines in the local file, without comments."""
    path = _path(path)
    if not Path(path).is_file():
        return []
    return [ln.strip() for ln in Path(path).read_text(encoding='utf-8').splitlines()
            if ln.strip() and not ln.lstrip().startswith('#')]


def next_sid(path: Optional[Path] = None) -> int:
    used = {s for s in map(rule_sid, read_rules(path)) if s}
    sid = SID_MIN
    while sid in used:
        sid += 1
    return sid


def _write(rules: list[str], path: Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(HEADER + ''.join(r + '\n' for r in rules), encoding='utf-8')
    os.replace(tmp, path)


def add_rule(text: str, path: Optional[Path] = None) -> int:
    """Check and append one rule. Returns its sid. Raises RuleInputError if it can't be used."""
    text = ' '.join(text.replace('\\\n', ' ').split())
    error = check_rule(text)
    if error:
        raise RuleInputError(error)
    sid = rule_sid(text)
    rules = read_rules(path)
    if sid in {rule_sid(r) for r in rules}:
        raise RuleInputError(f'You already have a rule with sid {sid}. Change the sid, or delete the old rule.')
    _write(rules + [text], _path(path))
    return sid


def remove_rules(sids, path: Optional[Path] = None) -> int:
    """Delete the rules with these sids. Returns how many were removed."""
    sids = set(sids)
    rules = read_rules(path)
    kept = [r for r in rules if rule_sid(r) not in sids]
    if len(kept) != len(rules):
        _write(kept, _path(path))
    return len(rules) - len(kept)
