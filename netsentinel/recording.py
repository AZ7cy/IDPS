"""Write live-captured packets to a PCAP file (Qt-free)."""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Union

from .config import PCAP_MAX_BYTES
from .secure import restrict_to_owner

PCAP_HEADER_BYTES = 24
PCAP_RECORD_HEADER_BYTES = 16


class PcapRecorder:
    """Appends raw scapy packets to a new PCAP file, up to `max_bytes`.

    The constructor raises if the file cannot be created. After that, `write` never raises:
    a write error is kept in `error` and recording stops.
    """

    def __init__(self, path: Union[str, os.PathLike], max_bytes: int = PCAP_MAX_BYTES):
        from scapy.utils import PcapWriter
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.packets = 0
        self.size = PCAP_HEADER_BYTES
        self.full = False
        self.error = ''
        self._lock = threading.Lock()
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._writer = PcapWriter(str(self.path), append=False, sync=False)
        # The header is written with the first packet; create the file now so permissions can be set.
        self.path.touch()
        restrict_to_owner(self.path)            # captures hold payloads: Windows ACL, elsewhere 0600

    @property
    def active(self) -> bool:
        return self._writer is not None and not self.full

    def write(self, pkt) -> bool:
        with self._lock:
            if self._writer is None or self.full:
                return False
            size = PCAP_RECORD_HEADER_BYTES + len(pkt)
            if self.size + size > self.max_bytes:
                self.full = True
                return False
            try:
                self._writer.write(pkt)
            except Exception as exc:
                self.error = str(exc) or exc.__class__.__name__
                self._close_locked()
                return False
            self.packets += 1
            self.size += size
            return True

    def _close_locked(self):
        writer, self._writer = self._writer, None
        if writer is not None:
            try:
                writer.close()
            except Exception as exc:
                self.error = self.error or str(exc)

    def close(self):
        with self._lock:
            self._close_locked()

    def summary(self) -> str:
        text = f'Saved {self.packets:,} packets to {self.path}'
        if self.full:
            text += f' (stopped at the {self.max_bytes // (1024 * 1024):,} MB limit)'
        if self.error:
            text += f'; recording error: {self.error}'
        return text
