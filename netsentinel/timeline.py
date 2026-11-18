"""Alert and packet counts per time bucket, for the dashboard chart."""
from __future__ import annotations

import time
from collections import Counter, deque
from typing import Optional

from .config import TIMELINE_BUCKET_SECONDS, TIMELINE_BUCKETS


class AlertTimeline:
    def __init__(self, bucket_seconds: int = TIMELINE_BUCKET_SECONDS, buckets: int = TIMELINE_BUCKETS):
        self.bucket_seconds = bucket_seconds
        self.buckets = buckets
        self._events: deque = deque()     # (time, rule_id), in arrival order
        self._packets: dict[int, int] = {}  # bucket index -> packets captured

    @property
    def span(self) -> float:
        return self.bucket_seconds * self.buckets

    def add(self, rule_id: str, t: Optional[float] = None):
        self._events.append((time.time() if t is None else t, rule_id))

    def add_packets(self, count: int, t: Optional[float] = None):
        if count <= 0:
            return
        bucket = int((time.time() if t is None else t) // self.bucket_seconds)
        self._packets[bucket] = self._packets.get(bucket, 0) + count

    def clear(self):
        self._events.clear()
        self._packets.clear()

    def series(self, now: Optional[float] = None):
        """Return (sorted rule ids, list of Counters oldest -> newest)."""
        now = time.time() if now is None else now
        newest = int(now // self.bucket_seconds)
        while self._events and newest - int(self._events[0][0] // self.bucket_seconds) >= self.buckets:
            self._events.popleft()
        counts = [Counter() for _ in range(self.buckets)]
        for t, rule_id in self._events:
            age = newest - int(t // self.bucket_seconds)
            if 0 <= age < self.buckets:
                counts[self.buckets - 1 - age][rule_id] += 1
        rules = sorted({r for c in counts for r in c})
        return rules, counts

    def packet_series(self, now: Optional[float] = None) -> list[int]:
        """Packets captured per bucket, oldest -> newest, aligned with `series()`."""
        now = time.time() if now is None else now
        newest = int(now // self.bucket_seconds)
        for bucket in [b for b in self._packets if newest - b >= self.buckets]:
            del self._packets[bucket]
        return [self._packets.get(newest - age, 0) for age in range(self.buckets - 1, -1, -1)]
