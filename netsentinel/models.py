"""Packet and alert records."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


def utc() -> str:
    """Current UTC time as an ISO-8601 string with milliseconds."""
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


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
    src_mac: str = ''           # ARP sender MAC; not stored in the database
    data: bytes = b''           # raw L4 payload for signature matching; never stored or shown


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
    drop_requested: bool = False    # a drop-type signature matched; the inline policy decides
    detail: str = ''                # SIG-001: why the signature matched (see signatures.explain_match)


_MARKER = re.compile(r"(?i)(matched(?: HTTP request)? marker)\s+(['\"]).*?\2")


def redact_evidence(evidence: str) -> str:
    """Hide the matched HTTP marker, which can contain user data."""
    if not evidence:
        return ''
    return _MARKER.sub(r'\1 <redacted>', evidence)
