"""Wi-Fi tab: nearby access points, trusted baseline, and the signal survey map."""
from __future__ import annotations

import csv
import math
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QImage, QMouseEvent, QPainter, QPainterPath, QPen, QPolygonF
from PyQt6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox,
                             QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                             QMessageBox, QPushButton, QSpinBox, QSplitter, QTabWidget, QVBoxLayout, QWidget)

from .config import WIFI_INTERVAL_MAX, WIFI_INTERVAL_MIN, WIFI_MAX_POINTS
from .gui import button_row, cell, display_time, fit_columns, make_table, note_label, secondary
from .wifi import (CHANNELS_24, DROP_DBM, NON_OVERLAPPING_24, SignalHistory, channel_advice)
from .wifi import (ENVIRONMENTS, PATH_LOSS, REFERENCE_DBM, Layout, auto_layout, calibration_offset, distance_label,
                   estimate_distance, radar_radius)
from .wifi import (DOOR_WIDTH_M, NO_SIGNAL_DBM, PLAN_MARGIN_PX, PLAN_MAX_ITEMS, PLAN_MAX_M, PLAN_MAX_ROOMS, PLAN_MIN_M,
                   WINDOW_WIDTH_M, ScanResult, WifiDetector, network_key, plan_fraction_to_metres,
                   plan_metres_to_fraction, plan_scale, plan_size_px, resize_plan, room_area, room_from_drag,
                   signal_quality_label, snap_opening, strongest_by_network, validate_plan)
from .workers import WifiScanWorker

AP_COLUMNS = ['Network', 'BSSID', 'Signal (dBm)', 'Est. distance (m)', 'Quality', 'Channel', 'Band', 'Security',
              'Trusted', 'Connected']
POINT_COLUMNS = ['Location', 'Time', 'Networks heard', 'Strongest network', 'Map network (dBm)',
                 'Ping router (ms)', 'Ping internet (ms)', 'Loss']
EMPTY_AUTO_TEXT = ('Click "Scan now" (left) to see the networks around you at their estimated distance.\n\n'
                   'Then record signal at 3 or more spots and NetSentinel maps where they and the access points are.')
EMPTY_PLAN_TEXT = ('Click "New floor plan..." and enter the size of the area in metres, or "Use an image..." for a '
                   'picture of your floor plan.')
SURVEY_HELP = (
    'Automatic map: click "Scan now" to see nearby networks at their estimated distance. Then walk to 3 or more '
    'spots, type a name and click "Record signal here" at each; NetSentinel works out where the spots and the '
    'access points are and colours the area by signal.\n\n'
    'Floor plan: choose "Floor plan" under Map, click "New floor plan..." and enter the size in metres. Use the '
    'Tool list to draw rooms, doors, windows and your router, then pick "Record points" and click each spot '
    'before recording.\n\n'
    'Distance: d = 10 ^ ((P1m - RSSI) / (10 x n)) metres. "Walls" sets n; "Calibrate..." measures P1m 1 m from '
    'your router.\n\n'
    'Each recording scans for about 4 seconds and, with "Measure ping", pings your router and 1.1.1.1 at the '
    'same time. Many routers ignore pings, so "no reply" for the router is normal.\n\n'
    'Colours: signal green -60 dBm or better, yellow about -67 dBm (the usual minimum for video calls), red '
    '-85 dBm or worse. Ping green under 40 ms, yellow about 80 ms, red over 150 ms.')
MAP_METRICS = (('Signal strength (dBm)', 'signal'), ('Ping to the internet (ms)', 'internet_ms'),
               ('Ping to the router (ms)', 'gateway_ms'))
STRONGEST = ''          # map key meaning "strongest network at each point"
PLAN_TOOLS = (('Record points', 'points'), ('Draw rooms', 'rooms'), ('Add doors', 'doors'),
              ('Add windows', 'windows'), ('Place router', 'routers'))
PLAN_ITEMS = (('rooms', 'room'), ('doors', 'door'), ('windows', 'window'), ('routers', 'router'))
HEAT_COLUMNS = 64       # heat map resolution across the floor plan
HEAT_RADIUS = 0.35      # how far (fraction of the plan width) a reading colours the map
COLOR_STOPS = ((-45, (34, 197, 94)), (-60, (163, 230, 53)), (-67, (250, 204, 21)), (-75, (249, 115, 22)),
               (-85, (239, 68, 68)), (-100, (127, 29, 29)))


def _ms(value, measured: bool = True) -> str:
    """Ping for display: '23.5', 'no reply' when measured without a reply, '' when not measured."""
    if value is not None:
        return f'{value:g}'
    return 'no reply' if measured else ''


def signal_color(dbm: float, alpha: int = 255) -> QColor:
    """Green for strong signal through yellow and orange to dark red for none."""
    if dbm >= COLOR_STOPS[0][0]:
        return QColor(*COLOR_STOPS[0][1], alpha)
    for (hi, c1), (lo, c2) in zip(COLOR_STOPS, COLOR_STOPS[1:]):
        if dbm >= lo:
            f = (hi - dbm) / (hi - lo)
            return QColor(*(int(a + (b - a) * f) for a, b in zip(c1, c2)), alpha)
    return QColor(*COLOR_STOPS[-1][1], alpha)


PLAN_BG, PLAN_GRID, PLAN_GRID_MAJOR = QColor('#f1f5f9'), QColor('#dbe2ea'), QColor('#b8c4d3')
PLAN_WALL, PLAN_ROOM, PLAN_TEXT = QColor('#334155'), QColor('#e6ecf3'), QColor('#1e293b')


def plan_clip(plan: dict) -> tuple[float, float, float, float]:
    """The area inside the outer walls, as fractions of the rendered plan image."""
    w_px, h_px = plan_size_px(plan)
    s = plan_scale(plan)
    return (PLAN_MARGIN_PX / w_px, PLAN_MARGIN_PX / h_px, plan['width'] * s / w_px, plan['length'] * s / h_px)


ROOM_TINTS = ('#eef2ff', '#ecfdf5', '#fff7ed', '#fdf2f8', '#f0f9ff', '#fefce8', '#f5f3ff', '#f0fdfa')
LABEL = QColor('#64748b')
WINDOW_BLUE = QColor('#0284c7')


def _font(size: float, bold: bool = False) -> QFont:
    f = QFont('Segoe UI')
    f.setPointSizeF(size)
    f.setBold(bold)
    return f


def _dimension(p: QPainter, a: QPointF, b: QPointF, text: str, vertical: bool):
    """Architect-style dimension line between a and b, with end ticks and the length in a gap."""
    p.setPen(QPen(LABEL, 1))
    p.drawLine(a, b)
    for c in (a, b):
        d = QPointF(5, 0) if vertical else QPointF(0, 5)
        p.drawLine(c - d, c + d)
        t = QPointF(4, 4) if vertical else QPointF(4, -4)
        p.drawLine(c - t, c + t)            # 45-degree architectural tick
    mid = (a + b) / 2
    p.setFont(_font(8.5, True))
    box = QRectF(mid.x() - 34, mid.y() - 9, 68, 18)
    if vertical:
        p.save()
        p.translate(mid)
        p.rotate(-90)
        box = QRectF(-34, -9, 68, 18)
    p.fillRect(box.adjusted(8, 2, -8, -2), PLAN_BG)
    p.setPen(PLAN_TEXT)
    p.drawText(box, Qt.AlignmentFlag.AlignCenter, text)
    if vertical:
        p.restore()


def render_plan(plan: dict) -> QImage:
    """Draw a generated floor plan.

    Contents: a 1 m grid (0.5 m when zoomed in), outer and interior walls, tinted rooms labelled with
    name, size and area, doors with swing arcs, windows, overall dimension lines, a north arrow, a
    scale bar and a summary. Routers and survey points are drawn on top by SignalMap.
    """
    s = plan_scale(plan)
    w_px, h_px = plan_size_px(plan)
    m = PLAN_MARGIN_PX
    img = QImage(w_px, h_px, QImage.Format.Format_RGB32)
    img.fill(PLAN_BG)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    width, length = plan['width'], plan['length']
    inner = QRectF(m, m, width * s, length * s)
    p.fillRect(inner, QColor('#ffffff'))
    to_px = lambda mx, my: QPointF(m + mx * s, m + my * s)

    # Grid: 0.5 m minor lines when there is room for them, 1 m lines, darker every 5 m.
    if s >= 40:
        p.setPen(QPen(QColor('#eef2f6'), 1))
        for i in range(int(width * 2) + 1):
            if i % 2:
                p.drawLine(to_px(i / 2, 0), to_px(i / 2, length))
        for j in range(int(length * 2) + 1):
            if j % 2:
                p.drawLine(to_px(0, j / 2), to_px(width, j / 2))
    label_step = 1 if s >= 28 else 2 if s >= 14 else 5
    p.setFont(_font(7.5))
    for i in range(int(math.floor(width)) + 1):
        p.setPen(QPen(PLAN_GRID_MAJOR if i % 5 == 0 else PLAN_GRID, 1))
        p.drawLine(to_px(i, 0), to_px(i, length))
        if i % label_step == 0:
            p.setPen(LABEL)
            p.drawText(QRectF(m + i * s - 20, m - 18, 40, 14), Qt.AlignmentFlag.AlignCenter, f'{i}')
    for j in range(int(math.floor(length)) + 1):
        p.setPen(QPen(PLAN_GRID_MAJOR if j % 5 == 0 else PLAN_GRID, 1))
        p.drawLine(to_px(0, j), to_px(width, j))
        if j % label_step == 0 and j:
            p.setPen(LABEL)
            p.drawText(QRectF(m - 26, m + j * s - 7, 22, 14),
                       int(Qt.AlignmentFlag.AlignRight) | int(Qt.AlignmentFlag.AlignVCenter), f'{j}')

    # Rooms: tint, interior walls, label with name, size and area.
    rooms = plan.get('rooms', [])
    for k, r in enumerate(rooms):
        rect = QRectF(to_px(r['x'], r['y']), to_px(r['x'] + r['w'], r['y'] + r['h']))
        tint = QColor(ROOM_TINTS[k % len(ROOM_TINTS)])
        tint.setAlpha(200)
        p.fillRect(rect, tint)
    p.setPen(QPen(PLAN_WALL, 3, cap=Qt.PenCapStyle.SquareCap))
    p.setBrush(Qt.BrushStyle.NoBrush)
    for r in rooms:
        p.drawRect(QRectF(to_px(r['x'], r['y']), to_px(r['x'] + r['w'], r['y'] + r['h'])))
    p.setPen(QPen(PLAN_WALL, 5, cap=Qt.PenCapStyle.SquareCap))
    p.drawRect(inner)                                               # outer walls

    # Openings: clear the wall, then draw the symbol.
    def gap(o, thickness):
        half = o['w'] / 2
        a = to_px(o['x'], o['y'] - half) if o['vertical'] else to_px(o['x'] - half, o['y'])
        b = to_px(o['x'], o['y'] + half) if o['vertical'] else to_px(o['x'] + half, o['y'])
        p.setPen(QPen(QColor('#ffffff'), thickness, cap=Qt.PenCapStyle.FlatCap))
        p.drawLine(a, b)
        return a, b
    for o in plan.get('windows', []):
        a, b = gap(o, 6)
        off = QPointF(2, 0) if o['vertical'] else QPointF(0, 2)
        p.setPen(QPen(WINDOW_BLUE, 1.4))
        p.drawLine(a - off, b - off)
        p.drawLine(a + off, b + off)
        end = QPointF(3.5, 0) if o['vertical'] else QPointF(0, 3.5)
        p.drawLine(a - end, a + end)
        p.drawLine(b - end, b + end)
    for o in plan.get('doors', []):
        a, b = gap(o, 6)
        leaf = o['w'] * s
        # Hinged at `a`, opening 90 degrees to the right or downwards; doors on the outer right and
        # bottom walls open into the building instead.
        sign = -1.0 if (o['vertical'] and o['x'] >= width - 1e-6) or (not o['vertical']
                                                                      and o['y'] >= length - 1e-6) else 1.0
        swing = QPointF(sign * leaf, 0) if o['vertical'] else QPointF(0, sign * leaf)
        p.setPen(QPen(PLAN_WALL, 1.6))
        p.drawLine(a, a + swing)
        along = b - a                               # direction of the closed door, along the wall
        start = math.degrees(math.atan2(-swing.y(), swing.x()))
        end = math.degrees(math.atan2(-along.y(), along.x()))
        span = (end - start + 180) % 360 - 180      # the 90-degree turn between open and closed
        p.setPen(QPen(PLAN_WALL, 1, Qt.PenStyle.DashLine))
        p.drawArc(QRectF(a.x() - leaf, a.y() - leaf, 2 * leaf, 2 * leaf), int(start * 16), int(span * 16))

    # Room labels last, so walls and openings never cover them.
    for r in rooms:
        rect = QRectF(to_px(r['x'], r['y']), to_px(r['x'] + r['w'], r['y'] + r['h'])).adjusted(8, 6, -6, -6)
        p.setPen(PLAN_TEXT)
        p.setFont(_font(10, True))
        p.drawText(rect, int(Qt.AlignmentFlag.AlignLeft) | int(Qt.AlignmentFlag.AlignTop), r['name'])
        p.setPen(LABEL)
        p.setFont(_font(8))
        p.drawText(rect.adjusted(0, 17, 0, 0), int(Qt.AlignmentFlag.AlignLeft) | int(Qt.AlignmentFlag.AlignTop),
                   f'{r["w"]:g} x {r["h"]:g} m  |  {room_area(r):g} m\u00b2')

    # Overall dimensions, north arrow, scale bar and summary.
    _dimension(p, QPointF(m, m - 34), QPointF(m + width * s, m - 34), f'{width:g} m', vertical=False)
    _dimension(p, QPointF(m - 40, m), QPointF(m - 40, m + length * s), f'{length:g} m', vertical=True)
    nx, ny = w_px - 26, 22
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(PLAN_TEXT)
    p.drawPolygon(QPolygonF([QPointF(nx, ny - 12), QPointF(nx + 6, ny + 6), QPointF(nx, ny + 2),
                             QPointF(nx - 6, ny + 6)]))
    p.setPen(PLAN_TEXT)
    p.setFont(_font(8, True))
    p.drawText(QRectF(nx - 10, ny + 6, 20, 14), Qt.AlignmentFlag.AlignCenter, 'N')
    bar = s * (1 if s >= 40 else 2 if s >= 20 else 5)
    y = h_px - 30
    p.setPen(QPen(PLAN_TEXT, 2))
    p.drawLine(QPointF(m, y), QPointF(m + bar, y))
    for x in (m, m + bar):
        p.drawLine(QPointF(x, y - 4), QPointF(x, y + 4))
    p.setFont(_font(8))
    total = width * length
    rooms_area = sum(room_area(r) for r in rooms)
    summary = (f'{bar / s:g} m    Floor {width:g} x {length:g} m = {total:g} m\u00b2    {len(rooms)} room(s)'
               + (f', {rooms_area:g} m\u00b2 drawn' if rooms else '')
               + f'    {len(plan.get("doors", []))} door(s), {len(plan.get("windows", []))} window(s), '
                 f'{len(plan.get("routers", []))} router(s)')
    # Leave the right-hand 330 px of the bottom margin for the signal legend that SignalMap draws.
    p.drawText(QRectF(m + bar + 8, y - 8, max(80, w_px - m - bar - 8 - 330), 16),
               int(Qt.AlignmentFlag.AlignVCenter) | int(Qt.TextFlag.TextWordWrap), summary)
    p.end()
    return img


AUTO_MARGIN_PX = 64
AUTO_TARGET_PX = 1100


def render_auto(layout: Layout) -> tuple[QImage, Callable[[float, float], tuple[float, float]], tuple]:
    """Draw an estimated layout. Returns (image, metres -> image fraction, clip)."""
    radar = layout.mode == 'radar'
    coords = [p for p in layout.points if not math.isnan(p[0])] + [(a[2], a[3]) for a in layout.aps]
    if radar:                                       # centred on you, with room for the labels
        reach = max([math.hypot(*c) for c in coords] + [radar_radius(5)]) + 9      # room for the labels
        min_x, max_x, min_y, max_y = -reach, reach, -reach, reach
    else:
        min_x = min(c[0] for c in coords) - 2
        max_x = max(c[0] for c in coords) + 2
        min_y = min(c[1] for c in coords) - 2
        max_y = max(c[1] for c in coords) + 2
    span_x, span_y = max(4.0, max_x - min_x), max(4.0, max_y - min_y)
    s = max(8.0, min(120.0, AUTO_TARGET_PX / max(span_x, span_y)))
    m = AUTO_MARGIN_PX
    w_px, h_px = int(span_x * s) + 2 * m, int(span_y * s) + 2 * m
    img = QImage(w_px, h_px, QImage.Format.Format_RGB32)
    img.fill(PLAN_BG)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    inner = QRectF(m, m, span_x * s, span_y * s)
    p.fillRect(inner, QColor('#ffffff'))
    to_px = lambda x, y: QPointF(m + (x - min_x) * s, m + (y - min_y) * s)
    step = 1 if s >= 40 else 2 if s >= 20 else 5
    p.setFont(_font(7.5))
    # A metre grid only makes sense on the solved map; the radar uses a compressed distance scale.
    for k in (range(int(math.floor(min_x / step)), int(math.ceil(max_x / step)) + 1) if not radar else ()):
        x = k * step
        if min_x <= x <= min_x + span_x:
            p.setPen(QPen(PLAN_GRID_MAJOR if x % (step * 5) == 0 else PLAN_GRID, 1))
            p.drawLine(to_px(x, min_y), to_px(x, min_y + span_y))
    for k in (range(int(math.floor(min_y / step)), int(math.ceil(max_y / step)) + 1) if not radar else ()):
        y = k * step
        if min_y <= y <= min_y + span_y:
            p.setPen(QPen(PLAN_GRID_MAJOR if y % (step * 5) == 0 else PLAN_GRID, 1))
            p.drawLine(to_px(min_x, y), to_px(min_x + span_x, y))
    if layout.mode == 'radar':                     # distance rings around you
        centre = to_px(0, 0)
        for r in (1, 2, 5, 10, 20, 40, 80):
            radius = radar_radius(r) * s
            if radius > min(inner.width(), inner.height()) / 2:
                break
            p.setPen(QPen(QColor('#93c5fd'), 1, Qt.PenStyle.DashLine))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(centre, radius, radius)
            p.setPen(QColor('#3b82f6'))
            p.drawText(QRectF(centre.x() + 4, centre.y() - radius - 14, 60, 14), Qt.AlignmentFlag.AlignLeft,
                       f'{r} m')
        p.setPen(QPen(QColor('#cbd5e1'), 1))
        for _name, _b, x, y, _dbm in layout.aps:
            p.drawLine(centre, to_px(x, y))
    else:                                           # faint lines from each access point to its nearest spots
        p.setPen(QPen(QColor(148, 163, 184, 70), 1))
        for _name, _b, ax, ay, _dbm in layout.aps:
            near = sorted((math.hypot(px - ax, py - ay), (px, py)) for px, py in layout.points)[:2]
            for _d, (px, py) in near:
                p.drawLine(to_px(ax, ay), to_px(px, py))
    p.setPen(QPen(PLAN_WALL, 2))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRect(inner)
    p.setPen(PLAN_TEXT)
    p.setFont(_font(9.5, True))
    if layout.mode == 'radar':
        title = ('Estimated distance of each access point from you. Directions are unknown, and rings are spaced '
                 'logarithmically so near and far both fit. Record 3 or more spots to work out positions.')
    else:
        title = (f'Estimated layout from signal strength, typical error about {max(1.0, layout.error_m * 2):.0f} m. '
                 'Not a floor plan: no walls, and the map may be rotated or mirrored.')
    p.drawText(QRectF(m, 10, w_px - 2 * m, 36), int(Qt.AlignmentFlag.AlignLeft) | int(Qt.TextFlag.TextWordWrap),
               title)
    if not radar:                                   # a scale bar only fits a linear map
        bar = s * (1 if s >= 40 else 2 if s >= 20 else 5)
        y = h_px - 30
        p.setPen(QPen(PLAN_TEXT, 2))
        p.drawLine(QPointF(m, y), QPointF(m + bar, y))
        for x in (m, m + bar):
            p.drawLine(QPointF(x, y - 4), QPointF(x, y + 4))
        p.setFont(_font(8))
        p.drawText(QRectF(m + bar + 8, y - 8, 300, 16), Qt.AlignmentFlag.AlignVCenter,
                   f'{bar / s:g} m (estimated)')
    p.end()
    frac = lambda x, y: ((m + (x - min_x) * s) / w_px, (m + (y - min_y) * s) / h_px)
    clip = (m / w_px, m / h_px, span_x * s / w_px, span_y * s / h_px)
    return img, frac, clip


def draw_router(p: QPainter, c: QPointF, name: str, size: float = 1.0, avoid: Optional[list] = None) -> QRectF:
    """Access point marker: a dark disc with Wi-Fi arcs and a label. Returns the label's rectangle.

    The label moves down, step by step, while it would overlap a rectangle in `avoid`.
    """
    r = 10 * size
    p.setPen(QPen(QColor('#ffffff'), 2))
    p.setBrush(QColor('#1d4ed8'))
    p.drawEllipse(c, r, r)
    p.setPen(QPen(QColor('#ffffff'), 1.6 * size))
    p.setBrush(Qt.BrushStyle.NoBrush)
    for k in (0.35, 0.6):
        rr = r * k * 1.6
        p.drawArc(QRectF(c.x() - rr, c.y() - rr + r * 0.3, 2 * rr, 2 * rr), 45 * 16, 90 * 16)
    p.setBrush(QColor('#ffffff'))
    p.drawEllipse(c + QPointF(0, r * 0.35), 1.6 * size, 1.6 * size)
    p.setFont(_font(8 * size, True))
    width = p.fontMetrics().horizontalAdvance(name) + 8
    label = QRectF(c.x() - width / 2, c.y() + r + 2, width, 15 * size)
    for _ in range(12):
        if not any(label.intersects(other) for other in (avoid or ())):
            break
        label.translate(0, 14 * size)
    if label.top() > c.y() + r + 3:                 # moved: a thin leader line back to its marker
        p.setPen(QPen(QColor(30, 58, 138, 120), 1))
        p.drawLine(QPointF(c.x(), c.y() + r), QPointF(c.x(), label.top()))
    p.setPen(QColor('#ffffff'))
    p.drawText(label.translated(1, 1), Qt.AlignmentFlag.AlignHCenter, name)
    p.setPen(QColor('#1e3a8a'))
    p.drawText(label, Qt.AlignmentFlag.AlignHCenter, name)
    return label


def draw_legend(p: QPainter, rect: QRectF, mode: str = 'dbm'):
    """Colour scale with labels: signal from -90 to -40 dBm, or ping from 300 down to 10 ms."""
    p.setPen(Qt.PenStyle.NoPen)
    steps = 60
    for k in range(steps):
        dbm = -90 + 50 * k / (steps - 1)
        p.setBrush(signal_color(dbm))
        p.drawRect(QRectF(rect.x() + rect.width() * k / steps, rect.y(), rect.width() / steps + 0.6, 10))
    p.setPen(LABEL)
    p.setFont(_font(7.5))
    if mode == 'ms':
        ticks = [(ms_to_scale(ms), f'{ms:g}') for ms in (300, 150, 80, 40, 20)]
        title = 'Ping ms'
    else:
        ticks = [(dbm, str(dbm)) for dbm in (-90, -80, -67, -60, -50, -40)]
        title = 'Signal dBm'
    for value, text in ticks:
        x = rect.x() + rect.width() * (value + 90) / 50
        p.drawText(QRectF(x - 18, rect.y() + 11, 36, 12), Qt.AlignmentFlag.AlignCenter, text)
    p.drawText(QRectF(rect.x() - 70, rect.y() - 2, 66, 14),
               int(Qt.AlignmentFlag.AlignRight) | int(Qt.AlignmentFlag.AlignVCenter), title)


# Ping in ms mapped onto the dBm colour scale, so both maps use the same green-to-red colours.
PING_STOPS = ((10, -42), (20, -50), (40, -60), (80, -67), (150, -80), (300, -90))


def ms_to_scale(ms: float) -> float:
    if ms <= PING_STOPS[0][0]:
        return PING_STOPS[0][1]
    for (a, va), (b, vb) in zip(PING_STOPS, PING_STOPS[1:]):
        if ms <= b:
            return va + (vb - va) * (ms - a) / (b - a)
    return PING_STOPS[-1][1] - 5


CHART_BG, CHART_AXIS, CHART_TEXT = QColor('#0f1928'), QColor('#40536f'), QColor('#c7d2e3')
MINE, OTHER = QColor('#f97316'), QColor('#60a5fa')


class ChannelChart(QWidget):
    """Which channels nearby access points use, drawn like a spectrum view.

    2.4 GHz networks are 20 MHz wide and spill over neighbouring channels, so each is drawn as a curve
    spanning 4 channels each side. 5 GHz networks are drawn as bars on their channel. Height = signal.
    """

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(220)
        self.result: Optional[ScanResult] = None

    def set_result(self, result: Optional[ScanResult]):
        self.result = result
        self.update()

    def _own(self) -> set:
        r = self.result
        c = r.connected() if r else None
        return {a.bssid for a in r.access_points if c and a.ssid and a.ssid == c.ssid} if r else set()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), CHART_BG)
        aps = self.result.access_points if self.result else []
        if not aps:
            p.setPen(CHART_TEXT)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 'Scan to see channel use.')
            p.end()
            return
        own = self._own()
        w, h = self.width(), self.height()
        gap = 18
        left = QRectF(40, 26, (w - 40 - gap - 12) * 0.45, h - 26 - 34)
        right = QRectF(left.right() + gap + 28, 26, w - left.right() - gap - 28 - 12, h - 26 - 34)
        five = sorted({a.channel for a in aps if a.band == '5 GHz' and a.channel})
        self._panel(p, left, '2.4 GHz', [a for a in aps if a.band == '2.4 GHz'], list(CHANNELS_24), own,
                    curves=True)
        self._panel(p, right, '5 GHz', [a for a in aps if a.band == '5 GHz'], five or [36, 44, 149], own,
                    curves=False)
        p.setFont(_font(8))
        p.setPen(MINE)
        p.drawText(QRectF(12, h - 16, 300, 14), Qt.AlignmentFlag.AlignLeft, '\u25a0 your network')
        p.setPen(OTHER)
        p.drawText(QRectF(110, h - 16, 300, 14), Qt.AlignmentFlag.AlignLeft, '\u25a0 other networks')
        p.end()

    def _panel(self, p: QPainter, rect: QRectF, title: str, aps, channels: list, own: set, curves: bool):
        p.setPen(CHART_TEXT)
        p.setFont(_font(9, True))
        p.drawText(QRectF(rect.x(), 4, rect.width(), 18), Qt.AlignmentFlag.AlignLeft, title)
        p.setPen(QPen(CHART_AXIS, 1))
        p.drawLine(rect.bottomLeft(), rect.bottomRight())
        p.drawLine(rect.bottomLeft(), rect.topLeft())
        p.setFont(_font(7.5))
        for dbm in (-90, -70, -50, -30):        # signal axis
            y = rect.bottom() - rect.height() * (dbm + 100) / 70
            p.setPen(QPen(QColor('#1c2a3f'), 1, Qt.PenStyle.DashLine))
            p.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            p.setPen(CHART_TEXT)
            p.drawText(QRectF(rect.left() - 34, y - 7, 30, 14),
                       int(Qt.AlignmentFlag.AlignRight) | int(Qt.AlignmentFlag.AlignVCenter), str(dbm))
        if curves:
            lo, hi = 1 - 2.5, 13 + 2.5
            x_of = lambda ch: rect.left() + rect.width() * (ch - lo) / (hi - lo)
        else:
            slots = {ch: i for i, ch in enumerate(channels)}
            step = rect.width() / max(1, len(channels))
            x_of = lambda ch: rect.left() + step * (slots.get(ch, 0) + 0.5)
        for ch in channels:
            p.setPen(CHART_TEXT if not curves or ch in NON_OVERLAPPING_24 else QColor('#64748b'))
            p.drawText(QRectF(x_of(ch) - 12, rect.bottom() + 3, 24, 14), Qt.AlignmentFlag.AlignCenter, str(ch))
        y_of = lambda dbm: rect.bottom() - rect.height() * max(0, min(70, dbm + 100)) / 70
        p.setFont(_font(7.5))
        placed: list[QRectF] = []                   # labels already drawn, so later ones move up to avoid them
        # Weakest first, so strong networks and their labels end up on top.
        for ap in sorted(aps, key=lambda a: a.rssi):
            color = MINE if ap.bssid in own else OTHER
            top = y_of(ap.rssi)
            x = x_of(ap.channel)
            fill = QColor(color)
            fill.setAlpha(55)
            if curves:
                half = x_of(ap.channel + 2) - x
                path = QPainterPath(QPointF(x - 2 * half, rect.bottom()))
                path.cubicTo(QPointF(x - half, top), QPointF(x + half, top), QPointF(x + 2 * half, rect.bottom()))
                p.setPen(QPen(color, 1.6))
                p.setBrush(fill)
                p.drawPath(path)
                label_y = top - 2 + (rect.bottom() - top) * 0.25
            else:
                bar = QRectF(x - 9, top, 18, rect.bottom() - top)
                p.setPen(QPen(color, 1.4))
                p.setBrush(fill)
                p.drawRect(bar)
                label_y = top
            text = ap.name[:18]
            width = p.fontMetrics().horizontalAdvance(text) + 6
            box = QRectF(x - width / 2, label_y - 14, width, 13)
            while any(box.intersects(other) for other in placed) and box.top() > rect.top() - 20:
                box.translate(0, -13)
            placed.append(box)
            p.setPen(color)
            p.drawText(box, Qt.AlignmentFlag.AlignCenter, text)


class HistoryChart(QWidget):
    """The connected network's signal over time, with quality bands and gaps when disconnected."""

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(220)
        self.points: list = []

    def set_history(self, history: SignalHistory):
        self.points = list(history.points)
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), CHART_BG)
        plot = QRectF(42, 12, max(10, self.width() - 56), max(10, self.height() - 40))
        bands = ((-30, -60, QColor(34, 197, 94, 28)), (-60, -67, QColor(163, 230, 53, 24)),
                 (-67, -80, QColor(249, 115, 22, 24)), (-80, -100, QColor(239, 68, 68, 26)))
        y_of = lambda dbm: plot.top() + plot.height() * (-30 - max(-100, min(-30, dbm))) / 70
        for hi, lo, color in bands:
            p.fillRect(QRectF(plot.left(), y_of(hi), plot.width(), y_of(lo) - y_of(hi)), color)
        p.setFont(_font(7.5))
        for dbm in (-30, -50, -67, -80, -100):
            p.setPen(CHART_TEXT)
            p.drawText(QRectF(2, y_of(dbm) - 7, 36, 14),
                       int(Qt.AlignmentFlag.AlignRight) | int(Qt.AlignmentFlag.AlignVCenter), str(dbm))
        p.setPen(QPen(QColor('#94a3b8'), 1, Qt.PenStyle.DashLine))
        p.drawLine(QPointF(plot.left(), y_of(DROP_DBM)), QPointF(plot.right(), y_of(DROP_DBM)))
        p.setPen(QPen(CHART_AXIS, 1))
        p.drawRect(plot)
        if not self.points:
            p.setPen(CHART_TEXT)
            p.drawText(plot, Qt.AlignmentFlag.AlignCenter, 'No readings yet')
            p.end()
            return
        t0, t1 = self.points[0][0], self.points[-1][0]
        span = max(1.0, t1 - t0)
        x_of = lambda t: plot.left() + plot.width() * ((t - t0) / span if len(self.points) > 1 else 1.0)
        segment: list[QPointF] = []

        def flush():
            if len(segment) > 1:
                p.setPen(QPen(MINE, 2))
                p.drawPolyline(QPolygonF(segment))
            segment.clear()

        for t, dbm, _name in self.points:
            if dbm is None:                     # disconnected: break the line and mark it
                flush()
                p.setPen(QPen(QColor('#ef4444'), 1))
                p.drawLine(QPointF(x_of(t), plot.top()), QPointF(x_of(t), plot.bottom()))
                continue
            pt = QPointF(x_of(t), y_of(dbm))
            segment.append(pt)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(signal_color(dbm))
            p.drawEllipse(pt, 2.6, 2.6)
        flush()
        p.setPen(CHART_TEXT)
        fmt = '%H:%M:%S' if span < 3600 else '%H:%M'
        p.drawText(QRectF(plot.left(), plot.bottom() + 4, 120, 14), Qt.AlignmentFlag.AlignLeft,
                   datetime.fromtimestamp(t0).strftime(fmt))
        p.drawText(QRectF(plot.right() - 120, plot.bottom() + 4, 120, 14), Qt.AlignmentFlag.AlignRight,
                   datetime.fromtimestamp(t1).strftime(fmt))
        name = self.points[-1][2]
        if name:
            p.drawText(QRectF(plot.left() + 6, plot.top() + 4, plot.width() - 12, 14), Qt.AlignmentFlag.AlignLeft,
                       f'Connected to {name}')
        p.end()


class SignalMap(QWidget):
    """Floor plan with survey points and an interpolated signal heat map.

    Click to place a point. In draw mode, drag to draw a room instead.
    """
    clicked = pyqtSignal(float, float, arguments=['x', 'y'])
    dragged = pyqtSignal(object, object, arguments=['start', 'end'])     # image fractions (x, y)

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(260)
        self.image: Optional[QImage] = None
        self.points: list[tuple[float, float, str, Optional[int]]] = []    # x, y (0..1), name, dBm
        self.pending: Optional[tuple[float, float]] = None
        self.draw_mode = False
        self.clip: Optional[tuple[float, float, float, float]] = None     # x, y, w, h as image fractions
        self.routers: list[tuple[float, float, str]] = []                 # x, y as image fractions, name
        self._drag: Optional[tuple[tuple[float, float], tuple[float, float]]] = None
        self._heat: Optional[QImage] = None
        self.mode = 'dbm'               # 'dbm' for signal, 'ms' for ping; point values use this unit
        self.show_heat = True           # off for the radar view, where one reading cannot be interpolated
        self.empty_text = EMPTY_PLAN_TEXT
        self.setCursor(Qt.CursorShape.CrossCursor)

    def set_mode(self, mode: str):
        if mode != self.mode:
            self.mode = mode
            self._heat = None
            self.update()

    def _scale(self, value: float) -> float:
        """A point value on the dBm colour scale."""
        return ms_to_scale(value) if self.mode == 'ms' else value

    def _label(self, value) -> str:
        if self.mode == 'ms':
            return f'{value:g} ms' if value is not None else 'no reply'
        return f'{value} dBm' if value is not None and value > NO_SIGNAL_DBM else 'no signal'

    def set_image(self, path: str) -> bool:
        image = QImage(path) if path else QImage()
        return self.set_qimage(None if image.isNull() else image)

    def set_qimage(self, image: Optional[QImage], clip=None) -> bool:
        self.image = image
        self.clip = clip if image is not None else None
        self.pending = None
        self._heat = None
        self.update()
        return self.image is not None

    def set_points(self, points):
        self.points = list(points)
        self._heat = None
        self.update()

    def image_rect(self) -> QRectF:
        if self.image is None:
            return QRectF()
        w, h = self.width() - 8, self.height() - 8
        scale = min(w / self.image.width(), h / self.image.height())
        iw, ih = self.image.width() * scale, self.image.height() * scale
        return QRectF((self.width() - iw) / 2, (self.height() - ih) / 2, iw, ih)

    def heat_image(self) -> Optional[QImage]:
        """Inverse-distance-weighted signal estimate, faded out away from the readings."""
        samples = [(x, y, self._scale(v)) for x, y, _n, v in self.points if v is not None and x is not None]
        if self.image is None or not samples:
            return None
        if self._heat is not None:
            return self._heat
        aspect = self.image.height() / self.image.width()
        cols = HEAT_COLUMNS
        rows = max(1, int(round(cols * aspect)))
        heat = QImage(cols, rows, QImage.Format.Format_ARGB32)
        heat.fill(QColor(0, 0, 0, 0))
        for j in range(rows):
            py = (j + 0.5) / rows
            for i in range(cols):
                px = (i + 0.5) / cols
                total = weight_sum = 0.0
                nearest = math.inf
                for x, y, v in samples:
                    d = math.hypot(px - x, (py - y) * aspect)
                    nearest = min(nearest, d)
                    w = 1.0 / max(d, 1e-3) ** 2
                    total += w * v
                    weight_sum += w
                fade = 1.0 - nearest / HEAT_RADIUS
                if fade > 0:
                    heat.setPixelColor(i, j, signal_color(total / weight_sum, int(150 * min(1.0, fade * 1.5))))
        self._heat = heat
        return heat

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor('#0f1928'))
        if self.image is None:
            p.setPen(QColor('#9fb0c8'))
            p.drawText(self.rect().adjusted(20, 20, -20, -20),
                       int(Qt.AlignmentFlag.AlignCenter) | int(Qt.TextFlag.TextWordWrap), self.empty_text)
            p.end()
            return
        rect = self.image_rect()
        self._paint_map(p, rect)
        if self._drag is not None:                  # room being drawn
            (x1, y1), (x2, y2) = self._drag
            band = QRectF(QPointF(rect.x() + x1 * rect.width(), rect.y() + y1 * rect.height()),
                          QPointF(rect.x() + x2 * rect.width(), rect.y() + y2 * rect.height())).normalized()
            p.setPen(QPen(QColor('#2563eb'), 2, Qt.PenStyle.DashLine))
            p.setBrush(QColor(37, 99, 235, 40))
            p.drawRect(band)
        if self.pending is not None:
            c = QPointF(rect.x() + self.pending[0] * rect.width(), rect.y() + self.pending[1] * rect.height())
            p.setPen(QPen(QColor('#38bdf8'), 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(c, 10, 10)
            p.drawLine(c + QPointF(-15, 0), c + QPointF(15, 0))
            p.drawLine(c + QPointF(0, -15), c + QPointF(0, 15))
        p.end()

    def _paint_map(self, p: QPainter, rect: QRectF, size: float = 1.0):
        """Plan, heat map and survey points into `rect`. `size` scales markers and labels."""
        if self.image is None:
            return
        p.drawImage(rect, self.image)
        heat = self.heat_image() if self.show_heat else None
        if heat is not None:
            p.save()
            if self.clip is not None:           # generated plan: colour only inside the outer walls
                cx, cy, cw, ch = self.clip
                p.setClipRect(QRectF(rect.x() + cx * rect.width(), rect.y() + cy * rect.height(),
                                     cw * rect.width(), ch * rect.height()))
            p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            p.drawImage(rect, heat)
            p.restore()
        if self.clip is not None:                   # generated plan: legend in the bottom margin
            k = rect.width() / self.image.width()
            p.save()
            p.translate(rect.topLeft())
            p.scale(k, k)
            draw_legend(p, QRectF(self.image.width() - 250, self.image.height() - 36, 200, 10), self.mode)
            p.restore()
        # Router labels keep clear of the survey points and their labels, which are drawn on top.
        p.setFont(QFont('Segoe UI', max(7, int(round(8 * size)))))
        placed: list[QRectF] = []
        for x, y, name, value in self.points:
            if x is not None and y is not None:
                c = QPointF(rect.x() + x * rect.width(), rect.y() + y * rect.height())
                text_w = p.fontMetrics().horizontalAdvance(f'{name}  {self._label(value)}')
                placed.append(QRectF(c.x() - 9 * size, c.y() - 9 * size, text_w + 22 * size, 18 * size))
        for fx, fy, name in self.routers:
            placed.append(draw_router(p, QPointF(rect.x() + fx * rect.width(), rect.y() + fy * rect.height()),
                                      name, max(0.8, size), avoid=placed))
        p.setFont(QFont('Segoe UI', max(7, int(round(8 * size)))))
        r = 7 * size
        for x, y, name, value in self.points:
            if x is None or y is None:
                continue
            c = QPointF(rect.x() + x * rect.width(), rect.y() + y * rect.height())
            p.setPen(QPen(QColor('#0b1220'), 2))
            p.setBrush(QBrush(signal_color(self._scale(value)) if value is not None else QColor('#7f1d1d')))
            p.drawEllipse(c, r, r)
            label = f'{name}  {self._label(value)}'
            p.setPen(QColor('#ffffff'))
            p.drawText(c + QPointF(r + 4, r * 0.7), label)
            p.setPen(QColor('#0b1220'))
            p.drawText(c + QPointF(r + 3, r * 0.6), label)

    def render_image(self) -> QImage:
        """The map at the plan's own resolution, for saving as a picture."""
        if self.image is None:
            return QImage()
        out = QImage(self.image.size(), QImage.Format.Format_RGB32)
        out.fill(QColor('#ffffff'))
        p = QPainter(out)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._paint_map(p, QRectF(0, 0, out.width(), out.height()), size=max(1.0, out.width() / 900))
        p.end()
        return out

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update()

    def _fraction(self, event: QMouseEvent, clamp: bool = False) -> Optional[tuple[float, float]]:
        rect = self.image_rect()
        pos = event.position()
        if not clamp and not rect.contains(pos):
            return None
        x, y = (pos.x() - rect.x()) / rect.width(), (pos.y() - rect.y()) / rect.height()
        return (min(max(x, 0.0), 1.0), min(max(y, 0.0), 1.0)) if clamp else (x, y)

    def mousePressEvent(self, event: Optional[QMouseEvent]):
        if event is None or self.image is None:
            return
        at = self._fraction(event)
        if at is None:
            return
        if self.draw_mode:
            self._drag = (at, at)
            self.update()
            return
        self.pending = at
        self.update()
        self.clicked.emit(*at)

    def mouseMoveEvent(self, event: Optional[QMouseEvent]):
        if event is not None and self._drag is not None:
            self._drag = (self._drag[0], self._fraction(event, clamp=True) or self._drag[1])
            self.update()

    def mouseReleaseEvent(self, event: Optional[QMouseEvent]):
        if event is None or self._drag is None:
            return
        start, end = self._drag[0], self._fraction(event, clamp=True) or self._drag[1]
        self._drag = None
        self.update()
        self.dragged.emit(start, end)


class WifiTab(QWidget):
    def __init__(self, store, settings, status: Callable[[str], None], error: Callable[[str], None],
                 on_alerts: Callable[[list], None]):
        super().__init__()
        self.store = store
        self.settings = settings
        self.status = status
        self.report_error = error
        self.on_alerts = on_alerts
        self.detector = WifiDetector(store)
        self.last_result: Optional[ScanResult] = None
        self.monitor: Optional[WifiScanWorker] = None
        self.workers: list[WifiScanWorker] = []
        self.plan: dict = {}
        self._edits: list[str] = []         # item kinds added this session, for Undo
        self._layout: Optional[Layout] = None
        self._layout_key = self._layout_drawn = None
        self.history = SignalHistory()
        self._build()
        self.monitor_box.setChecked(settings.get('wifi_monitor'))
        self.interval.setValue(settings.get('wifi_interval'))
        self.plan = dict(settings.get('wifi_plan'))
        if self.plan:
            self.map.set_qimage(render_plan(self.plan), plan_clip(self.plan))
        elif settings.get('wifi_floor_plan') and not self.map.set_image(settings.get('wifi_floor_plan')):
            self.status(f'Could not open the floor plan {settings.get("wifi_floor_plan")}.')
        self._update_routers()
        self._update_plan_buttons()
        for combo, value in ((self.layout_mode, settings.get('wifi_layout')), (self.environment, settings.get('wifi_env'))):
            combo.blockSignals(True)
            combo.setCurrentIndex(max(0, combo.findData(value)))
            combo.blockSignals(False)
        self.monitor_box.toggled.connect(self.set_monitoring)
        self.interval.valueChanged.connect(self._interval_changed)
        self._layout_changed()

    # -- automatic map -----------------------------------------------------------------
    def auto_mode(self) -> bool:
        return self.layout_mode.currentData() == 'auto'

    def set_layout_mode(self, mode: str):
        index = self.layout_mode.findData(mode)
        if index >= 0 and index != self.layout_mode.currentIndex():
            self.layout_mode.setCurrentIndex(index)     # calls _layout_changed

    def _layout_changed(self, *_):
        auto = self.auto_mode()
        self.settings.set('wifi_layout', 'auto' if auto else 'plan')
        self.plan_row.setVisible(not auto)
        self.map.empty_text = EMPTY_AUTO_TEXT if auto else EMPTY_PLAN_TEXT
        if auto:
            self.set_tool('points')
            self.map.pending = None
        else:
            self.map.show_heat = True
            self._show_plan_image()
        self.refresh_points()

    def _show_plan_image(self):
        if self.plan:
            self.map.set_qimage(render_plan(self.plan), plan_clip(self.plan))
        elif self.settings.get('wifi_floor_plan'):
            self.map.set_image(self.settings.get('wifi_floor_plan'))
        else:
            self.map.set_qimage(None)
        self._update_routers()

    def _auto_map(self, points: list, by_point: dict) -> dict:
        """Lay out the survey (or the last scan) automatically. Returns point id -> image fraction."""
        entries = [(pt['id'], by_point.get(pt['id'], [])) for pt in points]
        if not any(rows for _pid, rows in entries) and self.last_result is not None:
            entries = [('scan', [{'ssid': a.ssid, 'bssid': a.bssid, 'rssi': a.rssi, 'band': a.band}
                                 for a in self.last_result.access_points])]
        key = (tuple((pid, len(rows)) for pid, rows in entries), self.path_loss(), self.settings.get('wifi_cal'),
               self.last_result.timestamp if self.last_result is not None and entries[:1] and entries[0][0] == 'scan'
               else '')
        if key != self._layout_key:
            self._layout_key = key
            self._layout = auto_layout(entries, self.path_loss(), self.settings.get('wifi_cal'))
        layout = self._layout
        self.map.show_heat = layout is not None and layout.mode == 'solved'
        if layout is None:
            self.map.set_qimage(None)
            self.map.routers = []
            self.layout_note.setText('')
            return {}
        image, frac, clip = render_auto(layout)
        if self.map.image is None or self.map.image.size() != image.size() or key != self._layout_drawn:
            self.map.set_qimage(image, clip)
            self._layout_drawn = key
        self.map.routers = [(*frac(x, y), name if layout.mode == 'solved'
                             else f'{name} {distance_label(layout.distances[k])}')
                            for k, (name, _b, x, y, _dbm) in enumerate(layout.aps)]
        if layout.mode == 'radar':
            self.layout_note.setText(f'{len(layout.aps)} access point(s) shown at their estimated distance from you; '
                                     'their direction is unknown. Record signal at 3 or more spots around the area '
                                     'and NetSentinel works out where they are.')
        else:
            self.layout_note.setText(f'Layout solved from {len(layout.points)} spot(s) and {len(layout.aps)} access '
                                     f'point(s); the distances fit to within about {layout.error_m:g} m on average. '
                                     'More spots, spread around the area, give a better map.')
        return {pid: frac(x, y) for pid, (x, y) in zip(layout.point_ids, layout.points) if not math.isnan(x)}

    # -- layout ----------------------------------------------------------------
    def _build(self):
        root = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter)

        left = QWidget()
        lv = QVBoxLayout(left)
        box = QGroupBox('Nearby access points')
        bv = QVBoxLayout(box)
        self.scan_btn = QPushButton('Scan now')
        self.scan_btn.clicked.connect(self.scan_now)
        self.monitor_box = QCheckBox('Monitor every')
        self.monitor_box.setToolTip('Scan in the background and check the WIFI-* rules after each scan.')
        self.interval = QSpinBox()
        self.interval.setRange(WIFI_INTERVAL_MIN, WIFI_INTERVAL_MAX)
        self.interval.setSuffix(' s')
        row = QHBoxLayout()
        for w in (self.scan_btn, self.monitor_box, self.interval):
            row.addWidget(w)
        row.addStretch(1)
        bv.addLayout(row)
        self.scan_status = note_label('No scan yet. Scanning uses this computer\'s Wi-Fi adapter and needs no '
                                      'Ethernet connection or administrator rights.')
        bv.addWidget(self.scan_status)
        self.wifi_views = QTabWidget()
        ap_page = QWidget()
        av = QVBoxLayout(ap_page)
        av.setContentsMargins(4, 6, 4, 4)
        self.ap_table = make_table(AP_COLUMNS)
        self.ap_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.ap_table.setSortingEnabled(True)
        av.addWidget(self.ap_table, 1)
        trust_sel = secondary(QPushButton('Trust selected'))
        trust_sel.clicked.connect(self.trust_selected)
        trust_all = secondary(QPushButton('Trust all visible'))
        trust_all.clicked.connect(self.trust_all)
        untrust = secondary(QPushButton('Untrust selected'))
        untrust.clicked.connect(self.untrust_selected)
        av.addLayout(button_row(trust_sel, trust_all, untrust))
        av.addWidget(note_label(
            'Rules (Detection Rules tab): WIFI-001 flags open and WEP networks. WIFI-002 flags a possible evil twin: '
            'an unknown access point using the name of your trusted or connected network, especially with weaker '
            'security. WIFI-003 flags strong access points that are not trusted (possible rogue APs); it starts '
            'once you trust a baseline. Trust your own access points first, ideally with "Trust all visible" in a '
            'place where you know every network.'))
        self.wifi_views.addTab(ap_page, 'Access points')

        channel_page = QWidget()
        cv = QVBoxLayout(channel_page)
        cv.setContentsMargins(4, 6, 4, 4)
        self.channel_chart = ChannelChart()
        cv.addWidget(self.channel_chart, 1)
        self.channel_advice = note_label('Scan to see which channels nearby networks use.')
        cv.addWidget(self.channel_advice)
        self.wifi_views.addTab(channel_page, 'Channels')

        history_page = QWidget()
        hv = QVBoxLayout(history_page)
        hv.setContentsMargins(4, 6, 4, 4)
        self.history_chart = HistoryChart()
        hv.addWidget(self.history_chart, 1)
        self.history_summary = note_label('Each scan adds the signal of the network you are connected to. Tick '
                                          '"Monitor every" to build a history in the background.')
        hv.addWidget(self.history_summary)
        clear_history = secondary(QPushButton('Clear history'))
        clear_history.clicked.connect(self.clear_history)
        hv.addLayout(button_row(clear_history))
        self.wifi_views.addTab(history_page, 'Signal history')
        bv.addWidget(self.wifi_views, 1)
        lv.addWidget(box, 1)
        splitter.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        sbox = QGroupBox('Signal survey')
        sv = QVBoxLayout(sbox)
        new_plan = QPushButton('New floor plan...')
        new_plan.setToolTip('Generate a scaled floor plan from the size of the area, in metres.')
        new_plan.clicked.connect(self.new_floor_plan)
        self.tool = QComboBox()
        for label, key in PLAN_TOOLS:
            self.tool.addItem(label, key)
        self.tool.setToolTip('What a click or drag on the plan does.')
        self.tool.currentIndexChanged.connect(self._tool_changed)
        self.undo_room_btn = secondary(QPushButton('Undo'))
        self.undo_room_btn.setToolTip('Remove the last room, door, window or router you added.')
        self.undo_room_btn.clicked.connect(self.undo_room)
        load = secondary(QPushButton('Use an image...'))
        load.setToolTip('Use an existing floor plan picture (PNG or JPG) instead of a generated plan.')
        load.clicked.connect(self.choose_floor_plan)
        remove = secondary(QPushButton('Remove plan'))
        remove.clicked.connect(self.remove_floor_plan)
        self.save_map_btn = secondary(QPushButton('Save map image...'))
        self.save_map_btn.setToolTip('Save the plan with the signal colours and points as a PNG image.')
        self.save_map_btn.clicked.connect(self.save_map_image)
        self.map_network = QComboBox()
        self.map_network.addItem('Strongest network at each point', STRONGEST)
        self.map_network.setMinimumWidth(220)
        self.map_network.currentIndexChanged.connect(lambda *_: self.refresh_points())
        self.layout_mode = QComboBox()
        self.layout_mode.addItem('Automatic map (estimated from signal)', 'auto')
        self.layout_mode.addItem('Floor plan (draw or use an image)', 'plan')
        self.layout_mode.setToolTip('Automatic: NetSentinel works out roughly where your recorded spots and the '
                                    'access points are from signal strength. Floor plan: you draw the area.')
        self.layout_mode.currentIndexChanged.connect(self._layout_changed)
        self.environment = QComboBox()
        for key, label, n in ENVIRONMENTS:
            self.environment.addItem(f'{label} (n = {n:g})', key)
        self.environment.setToolTip('How much walls weaken the signal; used in the distance formula.')
        self.environment.currentIndexChanged.connect(self._environment_changed)
        self.calibrate_btn = secondary(QPushButton('Calibrate...'))
        self.calibrate_btn.setToolTip('Measure your router\'s signal 1 m away so distance estimates fit your '
                                      'router and laptop.')
        self.calibrate_btn.clicked.connect(self.calibrate)
        row = QHBoxLayout()
        row.addWidget(QLabel('Map'))
        row.addWidget(self.layout_mode, 1)
        row.addWidget(QLabel('Walls'))
        row.addWidget(self.environment)
        row.addWidget(self.calibrate_btn)
        sv.addLayout(row)
        self.plan_row = QWidget()
        row = QHBoxLayout(self.plan_row)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(new_plan)
        row.addWidget(QLabel('Tool'))
        row.addWidget(self.tool)
        for w in (self.undo_room_btn, load, remove):
            row.addWidget(w)
        row.addStretch(1)
        sv.addWidget(self.plan_row)
        self.map_metric = QComboBox()
        for label, key in MAP_METRICS:
            self.map_metric.addItem(label, key)
        self.map_metric.setToolTip('Colour the map by signal strength or by ping (delay).')
        self.map_metric.currentIndexChanged.connect(lambda *_: self.refresh_points())
        row = QHBoxLayout()
        row.addWidget(QLabel('Show'))
        row.addWidget(self.map_metric)
        row.addWidget(QLabel('for'))
        row.addWidget(self.map_network, 1)
        row.addWidget(self.save_map_btn)
        sv.addLayout(row)
        self.map = SignalMap()
        self.map.clicked.connect(self._map_clicked)
        self.map.dragged.connect(self._room_dragged)
        # Map on top, recordings below, with a handle between them so either can be made bigger.
        map_area = QWidget()
        mv = QVBoxLayout(map_area)
        mv.setContentsMargins(0, 0, 0, 0)
        mv.addWidget(self.map, 1)
        self.layout_note = note_label('')
        mv.addWidget(self.layout_note)
        records = QWidget()
        sv_records = QVBoxLayout(records)
        sv_records.setContentsMargins(0, 4, 0, 0)
        self.survey_split = QSplitter(Qt.Orientation.Vertical)
        self.survey_split.setChildrenCollapsible(False)
        self.survey_split.addWidget(map_area)
        self.survey_split.addWidget(records)
        self.survey_split.setStretchFactor(0, 3)
        self.survey_split.setStretchFactor(1, 2)
        sv.addWidget(self.survey_split, 1)
        sv_outer, sv = sv, sv_records               # the rest goes in the lower half
        self.point_name = QLineEdit()
        self.point_name.setPlaceholderText('Location name, for example "Kitchen" (optional)')
        self.point_name.returnPressed.connect(self.record_point)
        self.record_btn = QPushButton('Record signal here')
        self.record_btn.clicked.connect(self.record_point)
        self.measure_ping = QCheckBox('Measure ping')
        self.measure_ping.setChecked(True)
        self.measure_ping.setToolTip('Also ping the router and the internet (1.1.1.1) 4 times at each point.')
        row = QHBoxLayout()
        row.addWidget(self.point_name, 1)
        row.addWidget(self.measure_ping)
        row.addWidget(self.record_btn)
        sv.addLayout(row)
        self.point_table = make_table(POINT_COLUMNS)
        self.point_table.setMinimumHeight(110)
        sv.addWidget(self.point_table, 1)
        delete = secondary(QPushButton('Delete point'))
        delete.clicked.connect(self.delete_point)
        clear = secondary(QPushButton('Clear survey'))
        clear.clicked.connect(self.clear_survey)
        export = secondary(QPushButton('Export CSV...'))
        export.clicked.connect(self.export_csv)
        help_btn = secondary(QPushButton('How it works'))
        help_btn.clicked.connect(self.show_survey_help)
        sv.addLayout(button_row(delete, clear, export, help_btn))
        rv.addWidget(sbox, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)              # the survey gets the larger share
        splitter.setSizes([560, 840])
        del sv_outer

    # -- workers -----------------------------------------------------------------
    def _start(self, worker: WifiScanWorker) -> WifiScanWorker:
        worker.alert_batch.connect(self.on_alerts)
        worker.error.connect(self._scan_failed)
        worker.finished.connect(lambda w=worker: self._finished(w))
        self.workers.append(worker)
        worker.start()
        return worker

    def _finished(self, worker: WifiScanWorker):
        if worker in self.workers:
            self.workers.remove(worker)
        if worker is self.monitor:
            self.monitor = None
        worker.deleteLater()
        self._update_buttons()

    def _update_buttons(self):
        one_shot = [w for w in self.workers if w is not self.monitor]
        self.scan_btn.setEnabled(not one_shot)
        self.record_btn.setEnabled(not one_shot)

    def _scan_failed(self, message: str):
        self.scan_status.setText(message)
        self.report_error(message)

    def scan_now(self):
        worker = WifiScanWorker(self.detector)
        worker.scanned.connect(self.show_scan)
        self._start(worker)
        self.scan_status.setText('Scanning...')
        self._update_buttons()

    def set_monitoring(self, enabled: bool):
        self.settings.set('wifi_monitor', bool(enabled))
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
        if enabled:
            self.monitor = WifiScanWorker(self.detector, interval=float(self.interval.value()))
            self.monitor.scanned.connect(self.show_scan)
            self._start(self.monitor)
            self.status(f'Wi-Fi monitoring started (every {self.interval.value()} s).')
        else:
            self.status('Wi-Fi monitoring stopped.')

    def _interval_changed(self, value: int):
        self.settings.set('wifi_interval', value)
        if self.monitor is not None:
            self.monitor.interval = float(value)
            self.monitor.wake()             # end the current wait so the new interval applies now

    def shutdown(self, timeout_ms: int = 8000) -> bool:
        for w in list(self.workers):
            w.stop()
        ok = True
        for w in list(self.workers):
            if not w.wait(timeout_ms):
                ok = False
            else:
                try:
                    w.disconnect()
                except (TypeError, RuntimeError):
                    pass
        return ok

    def show_survey_help(self):
        QMessageBox.information(self, 'Signal survey', SURVEY_HELP)

    def clear_history(self):
        self.history.clear()
        self.history_chart.set_history(self.history)
        self.history_summary.setText(self.history.summary())

    # -- access points -------------------------------------------------------------
    def show_scan(self, result: ScanResult):
        self.last_result = result
        self.refresh_access_points()
        if self.auto_mode() and not self.store.wifi_points():
            self.refresh_points()                   # the automatic map starts from the latest scan
        self.channel_chart.set_result(result)
        self.channel_advice.setText('\n'.join(channel_advice(result)))
        self.history.add(result)
        self.history_chart.set_history(self.history)
        self.history_summary.setText(self.history.summary())
        connected = (f'connected to {result.connected_ssid}' if result.connected_ssid else 'not connected')
        self.scan_status.setText(f'{len(result.access_points)} access point(s) at {display_time(result.timestamp)} '
                                 f'on {result.interface or "the Wi-Fi adapter"}, {connected}.')

    # -- distance estimates ----------------------------------------------------------
    def path_loss(self) -> float:
        return PATH_LOSS.get(self.settings.get('wifi_env'), 3.0)

    def distance(self, rssi: float, band: str) -> float:
        return estimate_distance(rssi, band, self.path_loss(), self.settings.get('wifi_cal'))

    def distance_formula(self, rssi: float, band: str) -> str:
        n, cal = self.path_loss(), self.settings.get('wifi_cal')
        p1m = REFERENCE_DBM.get(band, -40.0) + cal
        d = self.distance(rssi, band)
        return (f'd = 10 ^ ((P1m - RSSI) / (10 x n)) = 10 ^ (({p1m:g} - ({rssi})) / (10 x {n:g})) = {d:.1f} m\n'
                f'P1m = signal 1 m from the access point ({band or "unknown band"}'
                + (f', calibrated {cal:+g} dB' if cal else ', default') + f'); n = {n:g} for '
                f'"{self.environment.currentText()}". Walls, people and furniture make real distances vary.')

    def _environment_changed(self, *_):
        self.settings.set('wifi_env', self.environment.currentData() or 'home')
        self.refresh_access_points()
        self.refresh_points()

    def calibrate(self) -> bool:
        """Measure the connected access point's signal 1 m away and use it as P1m."""
        result = self.last_result
        connected = result.connected() if result else None
        if connected is None:
            QMessageBox.information(self, 'Calibrate distances', 'Connect to your Wi-Fi network and click "Scan '
                                    'now" first, then calibrate standing about 1 m from your router.')
            return False
        if QMessageBox.question(self, 'Calibrate distances',
                                f'Hold the laptop about 1 metre from the access point of "{connected.name}", then '
                                'click Yes. NetSentinel scans for about 4 seconds.') != QMessageBox.StandardButton.Yes:
            return False
        worker = WifiScanWorker(self.detector)
        worker.scanned.connect(self._calibrated)
        self._start(worker)
        self.scan_status.setText('Calibrating... keep the laptop 1 m from the router.')
        self._update_buttons()
        return True

    def _calibrated(self, result: ScanResult):
        self.show_scan(result)
        ap = result.connected()
        if ap is None:
            self.scan_status.setText('Calibration failed: not connected to Wi-Fi.')
            return
        offset = calibration_offset(ap.rssi, ap.band)
        if not self.settings.set('wifi_cal', offset):
            self.scan_status.setText(f'Calibration failed: {ap.rssi} dBm at 1 m is outside the expected range.')
            return
        self.refresh_access_points()
        self.refresh_points()
        self.status(f'Calibrated: {ap.rssi} dBm at 1 m from {ap.name} ({ap.band}); distance estimates adjusted by '
                    f'{offset:+g} dB.')

    def refresh_access_points(self):
        result = self.last_result
        aps = result.access_points if result else []
        known = self.store.wifi_known()
        t = self.ap_table
        t.setSortingEnabled(False)
        t.setRowCount(len(aps))
        for i, ap in enumerate(aps):
            distance = self.distance(ap.rssi, ap.band)
            values = (ap.name, ap.bssid, ap.rssi, distance, f'{ap.signal}% ({signal_quality_label(ap.rssi)})',
                      ap.channel or '', ap.band, ap.security, 'yes' if ap.bssid in known else '',
                      'yes' if result and ap.bssid == result.connected_bssid else '')
            for j, v in enumerate(values):
                item = cell(v)
                if j == 2:
                    item.setData(Qt.ItemDataRole.DisplayRole, int(ap.rssi))   # numeric sort
                    item.setForeground(signal_color(ap.rssi))
                if j == 3:
                    item.setData(Qt.ItemDataRole.DisplayRole, round(distance, 1))
                    item.setToolTip(self.distance_formula(ap.rssi, ap.band))
                if j == 7 and ap.security in ('Open', 'WEP'):
                    item.setForeground(QColor('#f87171'))
                t.setItem(i, j, item)
        t.setSortingEnabled(True)
        fit_columns(t)

    def _selected_aps(self):
        result = self.last_result
        if not result:
            return []
        rows = {i.row() for i in self.ap_table.selectedItems()}
        bssids = set()
        for r in rows:
            item = self.ap_table.item(r, 1)
            if item is not None:
                bssids.add(item.text())
        return [a for a in result.access_points if a.bssid in bssids]

    def trust_selected(self):
        aps = self._selected_aps()
        if not aps:
            QMessageBox.information(self, 'Wi-Fi', 'Select one or more access points first.')
            return
        n = self.store.trust_access_points(aps)
        self.status(f'Trusted {n} access point(s).')
        self.refresh_access_points()

    def trust_all(self):
        result = self.last_result
        if not result or not result.access_points:
            QMessageBox.information(self, 'Wi-Fi', 'Scan first, then trust the access points you recognise.')
            return
        n = self.store.trust_access_points(result.access_points)
        self.status(f'Trusted {n} visible access point(s) as the Wi-Fi baseline.')
        self.refresh_access_points()

    def untrust_selected(self):
        aps = self._selected_aps()
        for ap in aps:
            self.store.untrust_access_point(ap.bssid)
        if aps:
            self.status(f'Removed {len(aps)} access point(s) from the trusted list.')
        self.refresh_access_points()

    # -- survey ------------------------------------------------------------------
    def choose_floor_plan(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open floor plan', '',
                                              'Images (*.png *.jpg *.jpeg *.bmp *.gif);;All files (*)')
        if path:
            self.set_floor_plan(path)

    def set_floor_plan(self, path: str) -> bool:
        """Use an image file as the floor plan ('' removes it). Replaces any generated plan."""
        if path:
            self.set_layout_mode('plan')
        ok = self.map.set_image(path)
        if path and not ok:
            QMessageBox.warning(self, 'Wi-Fi', f'Could not open {path} as an image.')
            if self.plan:
                self.map.set_qimage(render_plan(self.plan), plan_clip(self.plan))   # keep the generated plan
            return False
        self.settings.set('wifi_floor_plan', path if ok else '')
        if ok:
            self._set_plan({}, redraw=False)
        self.refresh_points()
        return True

    def remove_floor_plan(self):
        self._set_plan({})
        self.set_floor_plan('')

    # -- generated floor plan ------------------------------------------------------
    def _set_plan(self, plan: dict, redraw: bool = True) -> bool:
        if not validate_plan(plan):
            return False
        self.plan = plan
        self.settings.set('wifi_plan', plan)
        if redraw:
            self.map.set_qimage(render_plan(plan) if plan else None, plan_clip(plan) if plan else None)
        if not plan:
            self.set_tool('points')
            self._edits.clear()
        self._update_routers()
        self._update_plan_buttons()
        return True

    def _update_routers(self):
        if self.auto_mode():                        # the automatic map places access points itself
            return
        plan = self.plan
        self.map.routers = ([(*plan_metres_to_fraction(plan, r['x'], r['y']), r['name'])
                             for r in plan.get('routers', [])] if plan else [])
        self.map.update()

    def _update_plan_buttons(self):
        has_plan = bool(self.plan)
        self.tool.setEnabled(has_plan)
        self.undo_room_btn.setEnabled(has_plan and any(self.plan.get(k) for k, _ in PLAN_ITEMS))

    def set_tool(self, key: str):
        index = self.tool.findData(key)
        if index >= 0:
            self.tool.setCurrentIndex(index)

    def current_tool(self) -> str:
        return self.tool.currentData() or 'points'

    def plan_dialog(self) -> Optional[tuple[float, float]]:
        """Ask for the plan size in metres. Returns (width, length), or None if cancelled."""
        dialog = QDialog(self)
        dialog.setWindowTitle('New floor plan')
        form = QFormLayout(dialog)
        width, length = QDoubleSpinBox(), QDoubleSpinBox()
        for box, value in ((width, self.plan.get('width', 12.0)), (length, self.plan.get('length', 9.0))):
            box.setRange(PLAN_MIN_M, PLAN_MAX_M)
            box.setDecimals(1)
            box.setSingleStep(0.5)
            box.setSuffix(' m')
            box.setValue(value)
        form.addRow(note_label('Enter the size of the area to survey. Measure it, pace it out (one long step is '
                               'about 0.75 m), or use the size from a lease or listing. Rooms that still fit '
                               'are kept.'))
        form.addRow('Width (left to right)', width)
        form.addRow('Length (top to bottom)', length)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return width.value(), length.value()

    def new_floor_plan(self, size: Optional[tuple[float, float]] = None) -> bool:
        if not size:
            size = self.plan_dialog()
        if not size:
            return False
        self.set_layout_mode('plan')
        if self.store.wifi_points() and not self.plan and QMessageBox.question(
                self, 'Wi-Fi', 'Recorded points keep their position on the map as a fraction of its size, so '
                               'they may land in different places on the new plan. Continue?') != \
                QMessageBox.StandardButton.Yes:
            return False
        plan = resize_plan(self.plan or {}, *size)
        self.settings.set('wifi_floor_plan', '')
        self._set_plan(plan)
        self.refresh_points()
        if not plan['rooms']:
            self.set_tool('rooms')
        self.status(f'Floor plan {plan["width"]:g} x {plan["length"]:g} m. Drag to add rooms, then use the Tool '
                    'list to add doors, windows and your router, and switch to "Record points" to survey.')
        return True

    def _tool_changed(self, *_):
        tool = self.current_tool()
        self.map.draw_mode = tool == 'rooms'
        self.map.setCursor(Qt.CursorShape.PointingHandCursor if tool in ('doors', 'windows', 'routers')
                           else Qt.CursorShape.CrossCursor)
        if tool != 'points':
            self.map.pending = None
            self.map.update()
        hints = {'rooms': 'Drag on the plan to draw a room.',
                 'doors': 'Click on a wall to add a 0.9 m door.',
                 'windows': 'Click on a wall to add a 1.2 m window.',
                 'routers': 'Click where your router or access point is.'}
        if tool in hints:
            self.status(hints[tool])

    def _add_item(self, key: str, item: dict) -> bool:
        if len(self.plan.get(key, [])) >= PLAN_MAX_ITEMS:
            return False
        if not self._set_plan(dict(self.plan, **{key: list(self.plan.get(key, [])) + [item]})):
            return False
        self._edits.append(key)
        self._update_plan_buttons()
        return True

    def add_opening(self, key: str, mx: float, my: float) -> bool:
        """Add a door or window on the wall nearest (mx, my) metres."""
        width = DOOR_WIDTH_M if key == 'doors' else WINDOW_WIDTH_M
        opening = snap_opening(self.plan, mx, my, width)
        if opening is None:
            self.status(f'Click closer to a wall to add a {"door" if key == "doors" else "window"}.')
            return False
        if opening in self.plan.get(key, []):
            return False
        return self._add_item(key, opening)

    def add_router(self, mx: float, my: float, name: str) -> bool:
        return self._add_item('routers', {'name': name.strip()[:40] or 'Router', 'x': round(mx, 2),
                                          'y': round(my, 2)})

    def _room_dragged(self, start, end):
        if not self.plan or len(self.plan.get('rooms', [])) >= PLAN_MAX_ROOMS:
            return
        room = room_from_drag(self.plan, start, end, 'Room')
        if room is None:
            self.status('Drag a larger area to draw a room (at least 0.5 x 0.5 m).')
            return
        name, ok = QInputDialog.getText(self, 'Room name', f'Name for this {room["w"]:g} x {room["h"]:g} m room:',
                                        text=f'Room {len(self.plan.get("rooms", [])) + 1}')
        if not ok:
            return
        self.add_room(room, name)

    def add_room(self, room: dict, name: str = '') -> bool:
        room = dict(room, name=(name.strip()[:60] or room.get('name') or 'Room'))
        if len(self.plan.get('rooms', [])) >= PLAN_MAX_ROOMS:
            return False
        return self._add_item('rooms', room)

    def undo_room(self):
        """Undo the last addition this session; after that, remove the most recent item of any kind."""
        while self._edits and not self.plan.get(self._edits[-1]):
            self._edits.pop()
        key = self._edits.pop() if self._edits else next(
            (k for k, _ in reversed(PLAN_ITEMS) if self.plan.get(k)), None)
        if key is None:
            return
        items = list(self.plan[key])
        items.pop()
        plan = dict(self.plan, **{key: items})
        if key == 'rooms':
            # Openings that sat on the removed room's walls go too.
            plan = resize_plan(plan, plan['width'], plan['length'])
            for k in ('doors', 'windows', 'routers'):
                if k in self.plan and k not in plan:
                    plan[k] = []
        self._set_plan(plan)

    def save_map_image(self, path: Optional[str] = None) -> Optional[str]:
        """Save the plan with heat map and points at the plan's full resolution."""
        if self.map.image is None:
            QMessageBox.information(self, 'Wi-Fi', 'Create or load a floor plan first.')
            return None
        if not path:
            path, _ = QFileDialog.getSaveFileName(self, 'Save signal map', 'netsentinel_signal_map.png',
                                                  'PNG image (*.png)')
        if not path:
            return None
        image = self.map.render_image()
        if not image.save(path):
            QMessageBox.warning(self, 'Wi-Fi', f'Could not write {path}.')
            return None
        self.status(f'Saved the signal map to {Path(path).name}.')
        return path

    def _map_clicked(self, x: float, y: float):
        if self.auto_mode():                        # positions are worked out, not clicked
            self.map.pending = None
            self.map.update()
            self.point_name.setFocus()
            return
        tool = self.current_tool()
        if tool == 'points' or not self.plan:
            self.point_name.setFocus()
            return
        self.map.pending = None                     # only "Record points" places the survey marker
        mx, my = plan_fraction_to_metres(self.plan, x, y)
        if tool in ('doors', 'windows'):
            self.add_opening(tool, mx, my)
        elif tool == 'routers':
            name, ok = QInputDialog.getText(self, 'Router', 'Name for this router or access point:',
                                            text=f'Router {len(self.plan.get("routers", [])) + 1}')
            if ok:
                self.add_router(mx, my, name)

    def record_point(self):
        if not self.record_btn.isEnabled():     # Enter in the name box while a scan is already running
            return
        if len(self.store.wifi_points()) >= WIFI_MAX_POINTS:
            QMessageBox.warning(self, 'Wi-Fi', f'The survey already has {WIFI_MAX_POINTS} points.')
            return
        name = self.point_name.text().strip() or f'Point {len(self.store.wifi_points()) + 1}'
        pos = self.map.pending if self.map.image is not None and not self.auto_mode() else None
        worker = WifiScanWorker(self.detector, measure=self.measure_ping.isChecked())
        worker.scanned.connect(lambda result, n=name, p=pos: self._save_point(result, n, p))
        self._start(worker)
        self.scan_status.setText(f'Recording "{name}"... stay still for about 4 seconds'
                                 + (' while signal and ping are measured.' if self.measure_ping.isChecked() else '.'))
        self._update_buttons()

    def _save_point(self, result: ScanResult, name: str, pos):
        x, y = pos if pos else (None, None)
        self.store.add_wifi_point(name, x, y, result.access_points, result.latency)
        self.show_scan(result)
        self.point_name.clear()
        self.map.pending = None
        self.refresh_points()
        best = result.access_points[0] if result.access_points else None
        lat = result.latency or {}
        ping = (f' Ping: router {_ms(lat.get("gateway_ms"))}, internet {_ms(lat.get("internet_ms"))}, '
                f'{(lat.get("loss") or 0) * 100:.0f}% loss.' if result.latency else '')
        self.status(f'Recorded "{name}": {len(result.access_points)} access point(s)'
                    + (f', strongest {best.name} at {best.rssi} dBm.' if best else ', no Wi-Fi signal.') + ping)

    def refresh_points(self):
        points = self.store.wifi_points()
        readings = self.store.wifi_readings()
        by_point: dict[int, list[dict]] = {}
        for r in readings:
            by_point.setdefault(r['point_id'], []).append(r)
        keys = sorted({network_key(r) for r in readings}, key=str.lower)
        current = self.map_network.currentData()
        self.map_network.blockSignals(True)
        self.map_network.clear()
        self.map_network.addItem('Strongest network at each point', STRONGEST)
        for k in keys:
            self.map_network.addItem(k, k)
        idx = self.map_network.findData(current)
        self.map_network.setCurrentIndex(max(0, idx))
        self.map_network.blockSignals(False)
        selected = self.map_network.currentData() or STRONGEST
        metric = self.map_metric.currentData() or 'signal'
        self.map_network.setEnabled(metric == 'signal')
        self.map.set_mode('dbm' if metric == 'signal' else 'ms')

        map_points = []
        positions = self._auto_map(points, by_point) if self.auto_mode() else None
        if positions is None:
            self.layout_note.setText('')
        elif 'scan' in positions and self.last_result is not None:     # no recordings yet: the last scan
            best = self.last_result.access_points[0] if self.last_result.access_points else None
            dbm = best.rssi if best else NO_SIGNAL_DBM
            map_points.append((*positions['scan'], 'You are here',
                               dbm if metric == 'signal' else None))
        t = self.point_table
        t.setRowCount(len(points))
        for i, pt in enumerate(points):
            rows = by_point.get(pt['id'], [])
            strongest = max(rows, key=lambda r: r['rssi']) if rows else None
            if selected == STRONGEST:
                value = int(strongest['rssi']) if strongest else NO_SIGNAL_DBM
            else:
                value = strongest_by_network(rows).get(selected, NO_SIGNAL_DBM)
            x, y = positions.get(pt['id'], (None, None)) if positions is not None else (pt['x'], pt['y'])
            map_points.append((x, y, pt['name'], value if metric == 'signal' else pt.get(metric)))
            loss = pt.get('loss')
            values = (pt['name'], display_time(pt['timestamp']), len(rows),
                      f'{network_key(strongest)} ({strongest["rssi"]} dBm)' if strongest else 'none',
                      value if value > NO_SIGNAL_DBM else 'not heard',
                      _ms(pt.get('gateway_ms'), measured=loss is not None),
                      _ms(pt.get('internet_ms'), measured=loss is not None),
                      f'{loss * 100:.0f}%' if loss is not None else '')
            for j, v in enumerate(values):
                item = cell(v)
                if j == 0:
                    item.setData(Qt.ItemDataRole.UserRole, pt['id'])
                if j == 4:
                    item.setForeground(signal_color(value))
                if j in (5, 6):
                    ms = pt.get('gateway_ms' if j == 5 else 'internet_ms')
                    if ms is not None:
                        item.setForeground(signal_color(ms_to_scale(ms)))
                t.setItem(i, j, item)
        fit_columns(t)
        self.map.set_points(map_points)

    def delete_point(self):
        items = self.point_table.selectedItems()
        if not items:
            return
        item = self.point_table.item(items[0].row(), 0)
        point_id = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if point_id is not None:
            self.store.delete_wifi_point(int(point_id))
            self.refresh_points()

    def clear_survey(self):
        if not self.store.wifi_points():
            return
        if QMessageBox.question(self, 'Wi-Fi', 'Delete every recorded survey point?') != \
                QMessageBox.StandardButton.Yes:
            return
        self.store.clear_wifi_survey()
        self.refresh_points()

    def export_csv(self, path: Optional[str] = None) -> Optional[str]:
        if not path:
            path, _ = QFileDialog.getSaveFileName(self, 'Export survey', 'netsentinel_wifi_survey.csv',
                                                  'CSV (*.csv)')
        if not path:
            return None
        points = {p['id']: p for p in self.store.wifi_points()}
        fields = ['location', 'x', 'y', 'time', 'ssid', 'bssid', 'rssi_dbm', 'quality', 'channel', 'band',
                  'security', 'ping_router_ms', 'ping_internet_ms', 'loss_pct']
        blank = lambda v: '' if v is None else v
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(fields)
                for r in self.store.wifi_readings():
                    p = points.get(r['point_id'])
                    if p is None:
                        continue
                    writer.writerow([p['name'], '' if p['x'] is None else f'{p["x"]:.4f}',
                                     '' if p['y'] is None else f'{p["y"]:.4f}', p['timestamp'], r['ssid'],
                                     r['bssid'], r['rssi'], r['signal'], r['channel'], r['band'], r['security'],
                                     blank(p.get('gateway_ms')), blank(p.get('internet_ms')),
                                     '' if p.get('loss') is None else round(p['loss'] * 100)])
        except OSError as exc:              # for example the file is open in Excel
            QMessageBox.warning(self, 'Wi-Fi', f'Could not write {path}: {exc}')
            return None
        self.status(f'Exported the Wi-Fi survey to {Path(path).name}.')
        return path
