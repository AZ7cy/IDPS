"""Stacked bar chart of alerts per time bucket, with captured packets as a line, drawn with QPainter."""
from __future__ import annotations

from collections import Counter

from typing import Optional

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QPainter, QPen, QPolygonF
from PyQt6.QtWidgets import QSizePolicy, QWidget

PALETTE = ('#60a5fa', '#f87171', '#34d399', '#fbbf24', '#a78bfa', '#f472b6', '#22d3ee', '#fb923c', '#a3e635',
           '#e5e7eb')
AXIS = QColor('#40536f')
TEXT = QColor('#c7d2e3')
PACKET_LINE = QColor('#38bdf8')
PACKET_FILL = QColor(56, 189, 248, 40)


def short_number(n: int) -> str:
    if n >= 1_000_000:
        return f'{n / 1_000_000:.1f}M'
    if n >= 10_000:
        return f'{n // 1000}k'
    if n >= 1000:
        return f'{n / 1000:.1f}k'
    return str(n)


class AlertChart(QWidget):
    def __init__(self, bucket_seconds: int = 60, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.bucket_seconds = bucket_seconds
        self.rules: list[str] = []
        self.counts: list[Counter] = []
        self.packets: list[int] = []
        self._colors: dict[str, QColor] = {}
        self.setMinimumHeight(170)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def color(self, rule_id: str) -> QColor:
        if rule_id not in self._colors:
            self._colors[rule_id] = QColor(PALETTE[len(self._colors) % len(PALETTE)])
        return self._colors[rule_id]

    def set_series(self, rules, counts, packets=None):
        packets = list(packets) if packets is not None else []
        if rules == self.rules and counts == self.counts and packets == self.packets:
            return
        self.rules, self.counts, self.packets = list(rules), list(counts), packets
        for r in sorted(self.rules):
            self.color(r)
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        legend_h, left, right, bottom, top = 22, 36, 44, 20, 8
        plot = QRectF(left, top + legend_h, max(10, w - left - right), max(10, h - top - legend_h - bottom))
        p.setPen(QPen(AXIS))
        p.drawLine(plot.bottomLeft(), plot.bottomRight())
        p.drawLine(plot.bottomLeft(), plot.topLeft())
        totals = [sum(c.values()) for c in self.counts] or [0]
        peak = max(1, max(totals))
        n = len(self.counts) or len(self.packets)
        slot = plot.width() / n if n else plot.width()

        # Packets captured: filled line on its own (right-hand) scale, drawn behind the alert bars.
        packet_peak = max(self.packets) if self.packets else 0
        if packet_peak:
            first = next(i for i, v in enumerate(self.packets) if v)     # skip minutes before capture started
            points = [QPointF(plot.left() + (i + 0.5) * slot, plot.bottom() - plot.height() * v / packet_peak)
                      for i, v in enumerate(self.packets) if i >= first]
            if len(points) == 1:                    # one minute so far: draw a short marker, not a dot
                points.insert(0, QPointF(points[0].x() - slot / 2, points[0].y()))
            area = QPolygonF([QPointF(points[0].x(), plot.bottom())] + points
                             + [QPointF(points[-1].x(), plot.bottom())])
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(PACKET_FILL)
            p.drawPolygon(area)
            p.setPen(QPen(PACKET_LINE, 2))
            p.drawPolyline(QPolygonF(points))
            p.setPen(PACKET_LINE)
            p.drawText(QRectF(plot.right() + 4, plot.top() - 6, right - 4, 12), Qt.AlignmentFlag.AlignLeft,
                       short_number(packet_peak))
            p.drawText(QRectF(plot.right() + 4, plot.bottom() - 6, right - 4, 12), Qt.AlignmentFlag.AlignLeft, '0')

        p.setPen(TEXT)
        p.drawText(QRectF(0, plot.top() - 6, left - 4, 12), Qt.AlignmentFlag.AlignRight, str(peak))
        p.drawText(QRectF(0, plot.bottom() - 6, left - 4, 12), Qt.AlignmentFlag.AlignRight, '0')
        if n:
            minutes = n * self.bucket_seconds // 60
            p.drawText(QRectF(plot.left(), plot.bottom() + 3, 120, 14), Qt.AlignmentFlag.AlignLeft,
                       f'-{minutes} min')
            p.drawText(QRectF(plot.right() - 60, plot.bottom() + 3, 60, 14), Qt.AlignmentFlag.AlignRight, 'now')
            bar = max(1.0, slot * 0.75)
            for i, bucket in enumerate(self.counts):
                x = plot.left() + i * slot + (slot - bar) / 2
                y = plot.bottom()
                for rule_id in self.rules:
                    value = bucket.get(rule_id, 0)
                    if not value:
                        continue
                    height = plot.height() * value / peak
                    y -= height
                    p.fillRect(QRectF(x, y, bar, height), self.color(rule_id))
        if not any(totals):
            p.setPen(TEXT)
            text = ('No alerts in this period. The blue line shows packets captured.' if packet_peak
                    else 'No packets or alerts in this period')
            p.drawText(plot, int(Qt.AlignmentFlag.AlignCenter) | int(Qt.TextFlag.TextWordWrap), text)

        # Legend: packets first, then one entry per rule.
        x = float(left)
        if packet_peak:
            p.setPen(QPen(PACKET_LINE, 2))
            p.drawLine(QPointF(x, top + 9), QPointF(x + 12, top + 9))
            p.setPen(TEXT)
            label = 'packets (right scale)'
            p.drawText(QRectF(x + 16, top, 160, 18), Qt.AlignmentFlag.AlignVCenter, label)
            x += 16 + p.fontMetrics().horizontalAdvance(label) + 14
        for rule_id in self.rules:
            p.fillRect(QRectF(x, top + 4, 10, 10), self.color(rule_id))
            p.setPen(TEXT)
            p.drawText(QRectF(x + 14, top, 90, 18), Qt.AlignmentFlag.AlignVCenter, rule_id)
            x += 14 + p.fontMetrics().horizontalAdvance(rule_id) + 14
        p.end()
