"""Main window."""
from __future__ import annotations

import csv
import itertools
import json
import os
import platform
import threading
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QObject, QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QFontMetrics, QPainter
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout,
                             QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
                             QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
                             QScrollArea, QSizePolicy, QSpinBox, QSplitter, QStatusBar, QStyle, QSystemTrayIcon,
                             QTableWidget,
                             QTableWidgetItem, QTabWidget, QToolButton, QVBoxLayout, QWidget)

from .addresses import PROTECTED, blocks_self, canonical_ip, normalize_network
from .charts import AlertChart
from .config import (APP_NAME, DEFAULT_BPF, WINDIVERT_DEFAULT_FILTER, SIG_DEFAULT_HOME_NET, ERROR_DIALOG_INTERVAL, FEED_INTERVAL_MAX, FEED_INTERVAL_MIN,
                     GUI_ALERT_ROWS, GUI_BLOCK_ROWS, GUI_PACKET_ROWS, GUI_RECENT_PACKETS, GUI_RELATED_PACKETS,
                     PROTECTION_REFRESH_INTERVAL, SEVERITIES, TTL_MAX, TTL_MIN, WORKER_STOP_TIMEOUT_MS)
from .detector import Detector
from .feeds import validate_feed_url
from .interfaces import list_interfaces
from .models import Packet
from .notify import Notifier, NotificationSettings
from .settings import Settings
from .signatures import validate_home_net
from .store import Store
from .timeline import AlertTimeline
from .selftest import MISSED_HINT as SELF_TEST_HINT, evaluate as evaluate_self_test
from .privileges import can_restart_as_admin, privilege_note
from .privileges import restart_as_admin as relaunch_as_admin
from .rule_updates import update_due as et_update_due
from .workers import (BlocklistImportWorker, FeedUpdateWorker, LinuxIPS, LiveWorker, PcapWorker,
                      RuleDownloadWorker, SelfTestWorker, SignatureLoadWorker, SimWorker, WinIPS, Worker)

STYLE = '''QMainWindow,QWidget{background:#0b1220;color:#e7edf7}QTabWidget::pane{border:1px solid #26364d}
QTabBar::tab{background:#121c2d;padding:10px 18px}QTabBar::tab:selected{background:#1c3553}
QGroupBox{border:1px solid #2b405d;border-radius:8px;margin-top:12px;padding:12px}
QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 5px}
QPushButton{background:#1d4ed8;border:0;border-radius:6px;padding:9px 14px}QPushButton:disabled{background:#2a3547;color:#7b8798}
QLineEdit,QComboBox,QSpinBox,QPlainTextEdit,QTableWidget,QListWidget{background:#0f1928;border:1px solid #2a3c55;border-radius:5px;padding:6px}
QTableWidget{gridline-color:#22324a}QHeaderView::section{background:#17263a;padding:7px;border:0}
QMenu{background:#121c2d;border:1px solid #2a3c55}QMenu::item:selected{background:#1c3553}
QTableWidget{alternate-background-color:#111c2c;selection-background-color:#1e3a8a;selection-color:#ffffff}
QTableWidget::item{padding:0 4px;border:0}QTableWidget::item:selected{background:#1e3a8a;color:#ffffff}
QListWidget::item:selected{background:#1e3a8a;color:#ffffff}QLabel#note{color:#9fb0c8}
QPushButton#secondary{background:#26364d}QPushButton#secondary:hover{background:#30455f}
QPushButton:hover{background:#2563eb}QScrollArea{border:0}
QToolButton#gear{background:transparent;border:0;padding:2px 12px;color:#c7d2e3}
QFrame#adminBanner{background:#3b2a12;border:1px solid #b45309;border-radius:6px}
QFrame#adminBanner QLabel{color:#fde68a;background:transparent}
QToolButton#gear:hover{background:#1c3553;color:#ffffff;border-radius:6px}
QTableView{background:#0f1928;border:1px solid #2a3c55;border-radius:5px;gridline-color:#22324a;
alternate-background-color:#111c2c;selection-background-color:#1e3a8a;selection-color:#ffffff}
QTableView::item:selected{background:#1e3a8a;color:#ffffff}QTabWidget QTabWidget::pane{border:1px solid #26364d}'''

WINDOW_SIZE = (1450, 950)       # preferred size; smaller screens get a window that fits
QUIET_HINT_SECONDS = 30         # live capture time before explaining that no alerts is normal
SUMMARY_SECONDS = 10            # how often the console summarises captured traffic
SOURCE_LABELS = ('Live capture', 'Simulated traffic', 'PCAP replay')


def note_label(text) -> QLabel:
    label = QLabel(text)
    label.setObjectName('note')
    label.setWordWrap(True)
    return label


def secondary(button: QPushButton) -> QPushButton:
    button.setObjectName('secondary')
    return button


def button_row(*buttons, align_right=False) -> QHBoxLayout:
    row = QHBoxLayout()
    if align_right:
        row.addStretch(1)
    for b in buttons:
        row.addWidget(b)
    if not align_right:
        row.addStretch(1)
    return row


def scrollable(widget: QWidget) -> QScrollArea:
    """Wrap a tab so it scrolls instead of forcing the window taller than the screen."""
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidget(widget)
    return area


def display_time(value) -> str:
    """ISO-8601 UTC timestamp -> local 'YYYY-MM-DD HH:MM:SS' for tables."""
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone().strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return '' if value is None else str(value)

IPS_NOTE = (
    'The IPS is opt-in and never changes firewall rules. Use it only on systems you are authorized to control. '
    'This machine and the detected gateway, DNS and DHCP servers are never blocked. Dry-run also prevents '
    'blocklist drops. The safety switch is never remembered, and dry-run is always on at startup.\n'
    'Linux: route traffic into the queue yourself, for example '
    '"sudo iptables -I INPUT -j NFQUEUE --queue-num 1 --queue-bypass", and remove the rule with -D when finished.')

PACKET_COLUMNS = ['Time', 'Source', 'Destination', 'Proto', 'SPort', 'DPort', 'Len', 'Flags', 'Dropped', 'Origin']
ALERT_COLUMNS = ['ID', 'Time', 'Rule', 'Severity', 'Confidence', 'Source', 'Destination', 'Block Target', 'Action',
                 'Status', 'Source Type', 'Description', 'Evidence']
ALERT_FIELDS = ['id', 'timestamp', 'rule_id', 'severity', 'confidence', 'src_ip', 'dst_ip', 'block_target',
                'action', 'status', 'source', 'description', 'evidence']
DETAIL_LABELS = dict(zip(ALERT_FIELDS, ['Alert ID', 'Time', 'Rule', 'Severity', 'Confidence', 'Source',
                                        'Destination', 'Block target', 'Action', 'Status', 'Source type',
                                        'Description', 'Evidence']))
FEED_PLACEHOLDER = ('One https URL per line, for example:\n'
                    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt\n'
                    'https://www.spamhaus.org/drop/drop.txt')
RULE_COLUMNS = ['Enabled', 'Rule', 'Severity', 'Threshold', 'Window (s)', 'Description']
STATUSES = ('OPEN', 'ACK', 'CLOSED')
ALL = ''
YES, NO = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No


def cell(text, editable=False) -> QTableWidgetItem:
    item = QTableWidgetItem('' if text is None else str(text))
    if not editable:
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


def make_table(headers, editable=False) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setWordWrap(False)
    vertical = t.verticalHeader()
    if vertical is not None:
        vertical.setVisible(False)
        vertical.setDefaultSectionSize(30)
    header = t.horizontalHeader()
    if header is not None:
        header.setStretchLastSection(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        # Interactive, not ResizeToContents: with ResizeToContents Qt re-measures the whole column on every
        # setItem, which froze the window for over a second per refresh under heavy live traffic.
        # fit_columns() sizes the columns once after each refresh instead.
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    if not editable:
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    return t


# resizeColumnToContents measures the text only; the style sheet adds cell padding on top, so without this
# extra room Qt cuts values short with "..." (most visible with Segoe UI at 125% display scaling).
COLUMN_PADDING = 18


class FitLabel(QLabel):
    """A big number that shrinks its font to fit the space it has, so it is never cut off."""

    def __init__(self, text='0', size: float = 20, minimum: float = 9):
        super().__init__(text)
        self.max_size, self.min_size = size, minimum
        font = QFont('Segoe UI', int(size), QFont.Weight.Bold)
        self.setFont(font)
        self.setMinimumHeight(QFontMetrics(font).height() + 6)
        self.setMinimumWidth(10)                    # let the layout shrink it; paintEvent copes
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

    def paintEvent(self, _event):
        p = QPainter(self)
        font = QFont(self.font())
        size = self.max_size
        rect = self.contentsRect()
        while size > self.min_size:
            font.setPointSizeF(size)
            fm = QFontMetrics(font)
            if fm.horizontalAdvance(self.text()) <= rect.width() and fm.height() <= rect.height() + 4:
                break
            size -= 1
        font.setPointSizeF(size)
        p.setFont(font)
        p.setPen(self.palette().color(self.foregroundRole()))
        p.drawText(rect, int(Qt.AlignmentFlag.AlignLeft) | int(Qt.AlignmentFlag.AlignVCenter), self.text())
        p.end()


def fit_columns(table: QTableWidget, columns=None):
    """Size columns (default: all but the last, which stretches) to their contents plus cell padding."""
    header = table.horizontalHeader()
    for column in (range(table.columnCount() - 1) if columns is None else columns):
        table.resizeColumnToContents(column)
        title = table.horizontalHeaderItem(column)
        # Never narrower than the column title (an empty table would otherwise squeeze it to "Locati...").
        title_w = (header.fontMetrics().horizontalAdvance(title.text()) + 28) if header and title else 0
        table.setColumnWidth(column, max(table.columnWidth(column) + COLUMN_PADDING, title_w))


def cell_text(table: QTableWidget, row: int, column: int) -> str:
    """Text of a table cell, or '' if the cell is empty."""
    item = table.item(row, column)
    return item.text() if item is not None else ''


def cell_checked(table: QTableWidget, row: int, column: int) -> bool:
    item = table.item(row, column)
    return item is not None and item.checkState() == Qt.CheckState.Checked


def list_item(text, key) -> QListWidgetItem:
    item = QListWidgetItem(text)
    item.setData(Qt.ItemDataRole.UserRole, key)
    return item


def filter_combo(all_label, values) -> QComboBox:
    combo = QComboBox()
    combo.addItem(all_label, ALL)
    for v in values:
        combo.addItem(v, v)
    return combo


class _Bridge(QObject):
    """Carries messages from background threads to the GUI thread."""
    error = pyqtSignal(str, arguments=['message'])
    interfaces = pyqtSignal(object, arguments=['items'])
    alerts = pyqtSignal(object, arguments=['result'])      # (generation, filters, rows) from a background read


class MainWindow(QMainWindow):
    def __init__(self, store: Optional[Store] = None, settings: Optional[Settings] = None):
        super().__init__()
        self.store = store or Store()
        self.settings = settings or Settings()
        PROTECTED.refresh()
        self._protection_stop = threading.Event()
        threading.Thread(target=self._protection_loop, name='NetSentinel-Protection', daemon=True).start()
        self.detector = Detector(self.store)

        self.worker: Optional[Worker] = None        # passive IDS
        self.ips: Optional[Worker] = None           # inline IPS
        self.import_worker: Optional[BlocklistImportWorker] = None
        self.feed_worker: Optional[FeedUpdateWorker] = None
        self.sig_worker: Optional[SignatureLoadWorker] = None
        self.self_test_worker: Optional[SelfTestWorker] = None
        self.et_worker: Optional[RuleDownloadWorker] = None
        self._et_attempt: Optional[float] = None         # last ET Open download attempt this session
        self._et_force_next = False                      # user accepted a much smaller rule set
        self._feed_force_next: list = []                 # feeds whose large change the user accepted
        self._feed_manual = False                        # the running feed update was started by the user
        self._seen_sig_hits = -1
        self._sig_disabled: set = set(self.settings.get('sig_disabled'))     # switched off by the user
        self._sig_enabled: set = set(self.settings.get('sig_enabled'))       # switched on despite the level
        self._sig_level_off: set = set()
        self._sig_reload_pending = False
        self._self_test_alerts: Optional[list] = None   # collecting alerts while a self-test runs
        self.last_self_test = ''
        self._closing = False
        # Traffic since the last console summary
        self._summary_protocols: Counter = Counter()
        self._summary_talkers: Counter = Counter()
        self._summary_alerts = 0
        self._last_summary = time.monotonic()
        self._capture_label = ''                          # e.g. "Live capture", shown in the engine status
        self._last_error_at = -float('inf')
        self._live_started_at: Optional[float] = None    # for the "no alerts yet" hint
        self._quiet_hint_shown = False
        self._save_pcap_confirmed: Optional[str] = None     # path whose overwrite the save dialog confirmed
        self.zombies: list = []                     # workers that did not stop in time stay referenced

        self.packet_count = self.alert_count = self.last_packet_count = 0
        self.dropped_capture = 0
        self.sources: set = set()
        self.recent: deque = deque(maxlen=GUI_RECENT_PACKETS)
        self.timeline = AlertTimeline()
        self.packets_dirty = False
        self._packet_col_chars = [0] * len(PACKET_COLUMNS)    # longest text seen per packet column
        self._seen_alert_generation = -1
        self._seen_blocks_version = -1
        self._last_error_shown: dict = {}

        self.bridge = _Bridge()
        self.bridge.error.connect(self.error)
        self.bridge.interfaces.connect(self._set_interfaces)
        self.bridge.alerts.connect(self._alerts_fetched)
        self._alert_fetch: Optional[threading.Thread] = None
        self._alert_fetch_again = False
        self._detail_shown_for: Optional[int] = None     # alert id the detail panel currently shows
        self._alert_rows: dict = {}                      # id -> row currently in the alert table
        self._alert_seq = 0                              # bumped per alert-table load; newest result wins
        self.tray: Optional[QSystemTrayIcon] = None
        self.notifier = Notifier(self._notification_settings(), desktop=self._desktop_notify,
                                 on_error=self.bridge.error.emit)

        self._build()
        self._apply_settings()
        self._bind_settings()
        if self.settings.last_error:
            self.log(self.settings.last_error)
        self.refresh_rules()
        self.refresh_trusted()
        self.refresh_blocks()
        self.refresh_alerts()
        self.reload_interfaces()
        if self.settings.get('sig_paths') or self.settings.get('sig_builtin') or self.my_rules.path.is_file():
            self.load_signatures()      # the starter rules load on first start, with nothing to choose
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)

    def _protection_loop(self):
        while not self._protection_stop.wait(PROTECTION_REFRESH_INTERVAL):
            try:
                PROTECTED.refresh()
            except Exception:
                pass

    # -- layout ----------------------------------------------------------------
    def _build(self):
        self.setWindowTitle(APP_NAME)
        screen = QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            self.resize(min(WINDOW_SIZE[0], int(avail.width() * 0.95)), min(WINDOW_SIZE[1], int(avail.height() * 0.92)))
        else:
            self.resize(*WINDOW_SIZE)
        bar = self.menuBar()
        menu = bar.addMenu('File') if bar is not None else None
        for label, slot in (('Import IP/CIDR blocklist', self.import_blocklist),
                            ('Compact database', self.compact_database),
                            ('Export alerts (JSON / CSV)', self.export_alerts)):
            action = QAction(label, self)
            action.triggered.connect(slot)
            if menu is not None:
                menu.addAction(action)
        # Created before the tabs: tabs such as Wi-Fi can report status while they are being built.
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        from .splash import logo_pixmap
        logo = logo_pixmap()
        if logo is not None:                    # small logo at the left of the tab bar
            badge = QLabel()
            badge.setPixmap(logo.scaledToHeight(34, Qt.TransformationMode.SmoothTransformation))
            badge.setContentsMargins(8, 2, 10, 2)
            badge.setToolTip(APP_NAME)
            self.tabs.setCornerWidget(badge, Qt.Corner.TopLeftCorner)
        self.tabs.addTab(scrollable(self._dashboard_tab()), 'Dashboard')
        self.packet_tab = self._packet_tab()
        self.tabs.addTab(self.packet_tab, 'Packets')
        self.tabs.addTab(self._alert_tab(), 'Alerts')
        self.tabs.addTab(self._rule_tab(), 'Detection Rules')
        self.tabs.addTab(self._signature_tab(), 'Signatures')
        self.tabs.addTab(scrollable(self._ips_tab()), 'IPS / Blocklist')
        from .wifi_gui import WifiTab       # imported here: wifi_gui uses this module's helpers
        # Wi-Fi messages go to the console and status bar, not the engine status, which describes packet capture.
        self.wifi_tab = WifiTab(self.store, self.settings, self.wifi_status, self.error, self.on_alert_batch)
        self.tabs.addTab(self.wifi_tab, 'Wi-Fi')
        # Notification settings live in their own window, opened from the gear button beside the tabs.
        self.notify_dialog = self._notification_dialog()
        self.settings_btn = QToolButton()
        self.settings_btn.setObjectName('gear')
        self.settings_btn.setText('\u2699')                 # gear symbol
        self.settings_btn.setFont(QFont('Segoe UI Symbol', 15))
        self.settings_btn.setToolTip('Notification settings')
        self.settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.settings_btn.clicked.connect(self.show_notification_settings)
        self.tabs.setCornerWidget(self.settings_btn, Qt.Corner.TopRightCorner)
        if menu is not None:
            menu.addSeparator()
            action = QAction('Notification settings...', self)
            action.triggered.connect(self.show_notification_settings)
            menu.addAction(action)
        self.tabs.currentChanged.connect(self._tab_changed)
        self.setStyleSheet(STYLE)
        from .splash import app_icon
        icon = app_icon()
        if not icon.isNull():
            self.setWindowIcon(icon)
        style = self.style()
        if style is not None and QSystemTrayIcon.isSystemTrayAvailable():
            if icon.isNull():
                icon = style.standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)
            self.tray = QSystemTrayIcon(icon, self)
            self.tray.setToolTip(APP_NAME)
            self.tray.show()

    @staticmethod
    def _card(title, widget) -> QGroupBox:
        box = QGroupBox(title)
        QVBoxLayout(box).addWidget(widget)
        return box

    def _dashboard_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        # Shown when IDPS lacks Administrator/root rights, which live capture and the inline IPS need.
        self.admin_banner = QFrame()
        self.admin_banner.setObjectName('adminBanner')
        banner = QHBoxLayout(self.admin_banner)
        banner.setContentsMargins(12, 6, 8, 6)
        self.admin_note = QLabel(privilege_note())
        self.admin_note.setWordWrap(True)
        banner.addWidget(self.admin_note, 1)
        self.restart_admin_btn = QPushButton('Restart as Administrator')
        self.restart_admin_btn.setToolTip('Close IDPS and open it again with Administrator rights. Windows asks '
                                          'for permission first.')
        self.restart_admin_btn.clicked.connect(self.restart_as_admin)
        self.restart_admin_btn.setVisible(can_restart_as_admin())
        banner.addWidget(self.restart_admin_btn)
        self.admin_banner.setVisible(bool(self.admin_note.text()))
        root.addWidget(self.admin_banner)

        box = QGroupBox('Capture control')
        outer = QHBoxLayout(box)
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        outer.addLayout(grid, 1)
        self.source = QComboBox()
        self.source.addItems(['Live packet capture', 'Simulated traffic', 'PCAP replay'])
        self.source.setMinimumWidth(200)
        self.iface = QComboBox()
        self.iface.setEditable(True)
        self.iface.setToolTip('Pick an interface or type its name. "default" picks a connected adapter '
                              'that has a network address.')
        self.iface.addItem('default', '')
        iface_refresh = secondary(QPushButton('Refresh'))
        iface_refresh.clicked.connect(self.reload_interfaces)
        self.bpf = QLineEdit(DEFAULT_BPF)
        self.pcap_path = QLineEdit()
        pcap_browse = secondary(QPushButton('Browse...'))
        pcap_browse.clicked.connect(self.choose_pcap)
        self.keep_payload = QCheckBox('Save packet payloads to the database (may contain sensitive data)')
        self.keep_payload.toggled.connect(self._keep_payload_changed)
        self.persist_packets = QCheckBox('Store packet metadata in the database (more disk I/O)')
        self.persist_packets.setToolTip('Dropped packets are always stored.')
        self.persist_packets.toggled.connect(lambda v: setattr(self.store, 'persist_packets', v))
        self.start_btn, self.stop_btn = QPushButton('Start IDS'), secondary(QPushButton('Stop'))
        self.self_test_btn = secondary(QPushButton('Run self-test'))
        self.self_test_btn.setToolTip('Sends harmless test traffic to 192.0.2.0/24 (reserved, never routed) and '
                                      'checks that the live capture detects it. Starts live capture if needed.')
        for b in (self.start_btn, self.stop_btn, self.self_test_btn):
            b.setMinimumWidth(130)
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_ids)
        self.stop_btn.clicked.connect(lambda: self.stop_ids())
        self.self_test_btn.clicked.connect(self.run_self_test)
        self.pcap_path.setPlaceholderText('PCAP/PCAPNG file to replay (for the "PCAP replay" source)')
        self.save_pcap = QCheckBox('Save live capture to PCAP')
        self.save_pcap.setToolTip('Writes every captured packet, including full contents, to the file. '
                                  'Recording stops at 1 GB; detection continues.')
        self.save_pcap_path = QLineEdit()
        self.save_pcap_path.setPlaceholderText('PCAP file to write (contains full packet contents)')
        save_browse = secondary(QPushButton('Browse...'))
        save_browse.clicked.connect(self.choose_save_pcap)

        def line(*items):
            row = QHBoxLayout()
            for item, stretch in items:
                row.addWidget(item, stretch)
            return row

        iface_label = QLabel('Interface')
        iface_label.setContentsMargins(12, 0, 0, 0)
        rows = (('Source', line((self.source, 0), (iface_label, 0), (self.iface, 1), (iface_refresh, 0))),
                ('Capture filter', line((self.bpf, 1))),
                ('PCAP replay', line((self.pcap_path, 1), (pcap_browse, 0))),
                ('Recording', line((self.save_pcap, 0), (self.save_pcap_path, 1), (save_browse, 0))),
                ('Storage', line((self.keep_payload, 0), (self.persist_packets, 0), (QWidget(), 1))))
        for i, (label, row) in enumerate(rows):
            grid.addWidget(QLabel(label), i, 0)
            grid.addLayout(row, i, 1)
        grid.setColumnStretch(1, 1)
        buttons = QVBoxLayout()
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.stop_btn)
        buttons.addWidget(self.self_test_btn)
        buttons.addStretch(1)
        outer.addSpacing(8)
        outer.addLayout(buttons)
        root.addWidget(box)

        counters = QGridLayout()
        self.lbl_packets, self.lbl_alerts, self.lbl_sources, self.lbl_blocks, self.lbl_drops = (
            FitLabel('0') for _ in range(5))
        for i, (title, label) in enumerate((('Packets', self.lbl_packets), ('Alerts', self.lbl_alerts),
                                            ('Sources', self.lbl_sources), ('Blocks', self.lbl_blocks),
                                            ('Capture queue drops', self.lbl_drops))):
            card = self._card(title, label)
            card.setMinimumWidth(110)
            counters.addWidget(card, 0, i)
            counters.setColumnStretch(i, 1)
        root.addLayout(counters)

        self.chart = AlertChart(self.timeline.bucket_seconds)
        minutes = self.timeline.span // 60

        console_box = QGroupBox('Engine status and detection console')
        console_layout = QVBoxLayout(console_box)
        status_row = QHBoxLayout()
        self.engine = QLabel('IDS stopped')
        self.engine.setWordWrap(True)
        self.rate = QLabel('Packet rate: 0/s')
        status_row.addWidget(self.engine, 1)
        status_row.addWidget(self.rate)
        console_layout.addLayout(status_row)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(2000)
        self.console.setMinimumHeight(150)
        self.console.setFont(QFont('Consolas', 9))
        console_layout.addWidget(self.console, 1)

        bottom = QHBoxLayout()
        bottom.addWidget(self._card(f'Packets and alerts per minute (last {minutes:g} min)', self.chart), 1)
        bottom.addWidget(console_box, 1)
        root.addLayout(bottom, 1)
        return w

    def _packet_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        self.packet_table = make_table(PACKET_COLUMNS)
        layout.addWidget(self.packet_table)
        return w

    def _alert_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(note_label('Select an alert to see its details. Right-click to acknowledge/close it or '
                                    'block its source.'))
        filters = QHBoxLayout()
        self.filter_severity = filter_combo('All severities', SEVERITIES)
        self.filter_rule = filter_combo('All rules', [r['id'] for r in self.store.rules()])
        self.filter_status = filter_combo('All statuses', STATUSES)
        self.filter_ip = QLineEdit()
        self.filter_ip.setPlaceholderText('Filter by IP (source, destination or block target)')
        clear = secondary(QPushButton('Clear filters'))
        clear.clicked.connect(self.clear_alert_filters)
        for combo in (self.filter_severity, self.filter_rule, self.filter_status):
            combo.currentIndexChanged.connect(lambda *_: self.refresh_alerts())
            filters.addWidget(combo)
        self.filter_ip.textChanged.connect(lambda *_: self.refresh_alerts())
        filters.addWidget(self.filter_ip, 1)
        filters.addWidget(clear)
        layout.addLayout(filters)

        self.alert_table = make_table(ALERT_COLUMNS)
        header = self.alert_table.horizontalHeader()
        if header is not None:
            description = ALERT_FIELDS.index('description')
            header.setSectionResizeMode(description, QHeaderView.ResizeMode.Interactive)
            header.resizeSection(description, 260)
        self.alert_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.alert_table.customContextMenuRequested.connect(self.alert_menu)
        self.alert_table.itemSelectionChanged.connect(self.show_alert_detail)
        self.alert_detail = QPlainTextEdit()
        self.alert_detail.setReadOnly(True)
        self.alert_detail.setFont(QFont('Consolas', 9))
        self.alert_detail.setPlaceholderText('Select an alert to see its details and related packets.')
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.alert_table)
        splitter.addWidget(self.alert_detail)
        splitter.setSizes([520, 280])
        layout.addWidget(splitter, 1)
        return w

    def _rule_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(note_label(
            'Double-click Severity, Threshold or Window to edit. DNS-001 and TLS-001: Threshold = minimum name '
            'length. ARP-001: Threshold = number of MAC addresses for one IP, and the capture filter must include '
            '"arp". NET-004 and NET-005 never block automatically.'))
        self.rule_table = make_table(RULE_COLUMNS, editable=True)
        layout.addWidget(self.rule_table)
        save = QPushButton('Save rule changes')
        save.clicked.connect(self.save_rules)
        layout.addLayout(button_row(save, align_right=True))
        return w

    def _signature_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(note_label(
            'Load Snort 2.9, Snort 3 or Suricata rules: .rules files, folders, or .tar.gz/.zip archives such as '
            'ET Open. IDPS matches them itself, so Snort and Suricata do not need to be installed. Rules '
            'that use features IDPS does not support are skipped and listed below. SIG-001 on the Detection '
            'Rules tab turns signature matching on or off.'))
        top = QHBoxLayout()
        files_box = QGroupBox('Rule sources')
        files_layout = QVBoxLayout(files_box)
        self.sig_list = QListWidget()
        self.sig_list.setMinimumHeight(90)
        self.sig_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        files_layout.addWidget(self.sig_list)
        add_files, add_folder = secondary(QPushButton('Add files...')), secondary(QPushButton('Add folder...'))
        remove = secondary(QPushButton('Remove selected'))
        self.sig_load_btn = QPushButton('Load rules')
        add_files.clicked.connect(self.add_signature_files)
        add_folder.clicked.connect(self.add_signature_folder)
        remove.clicked.connect(self.remove_signature_paths)
        self.sig_load_btn.clicked.connect(lambda: self.load_signatures())
        files_layout.addLayout(button_row(add_files, add_folder, remove, self.sig_load_btn))
        # Rule files and HOME_NET are only needed for other rule sets and unusual networks: hidden until asked for.
        self.sig_advanced = QWidget()
        advanced = QHBoxLayout(self.sig_advanced)
        advanced.setContentsMargins(0, 0, 0, 0)
        advanced.addWidget(files_box, 3)
        vars_box = QGroupBox('Network variables')
        form = QFormLayout(vars_box)
        self.sig_home_net = QLineEdit()
        self.sig_home_net.setPlaceholderText(SIG_DEFAULT_HOME_NET)
        form.addRow('HOME_NET', self.sig_home_net)
        form.addRow(note_label('Leave blank for the private address ranges plus this computer\'s public IPv6 '
                               'prefixes. EXTERNAL_NET is everything outside HOME_NET, and server groups such as '
                               '$HTTP_SERVERS equal HOME_NET. Click Load rules to apply a change.'))
        advanced.addWidget(vars_box, 2)
        self.sig_advanced.setVisible(False)
        et_box = QGroupBox('Automatic setup')
        et_layout = QVBoxLayout(et_box)
        et_layout.addWidget(note_label(
            'Not sure what to load? IDPS always starts with its built-in starter rules (Log4Shell, '
            'Shellshock, attack tools, crypto miners, reverse shells, exposed services). "Set up automatically" '
            'adds the free ET Open set (about 42,000 rules, 5 MB), keeps it updated daily, and switches off its '
            'noisy informational rules.'))
        self.et_btn = QPushButton('Set up automatically')
        self.et_btn.setToolTip('Download ET Open, turn on daily updates and use the Balanced rule level.')
        self.et_btn.clicked.connect(lambda: self.set_up_signatures())
        self.sig_level = QComboBox()
        from .signatures import RULE_LEVELS
        for key, label in RULE_LEVELS:
            self.sig_level.addItem(label, key)
        self.sig_level.setToolTip('Balanced: everything except informational and policy rules. Essential: only '
                                  'priority 1 (HIGH) rules. Everything: all loaded rules. Your own switches in '
                                  'the rule list always win.')
        self.sig_level.currentIndexChanged.connect(self._sig_level_changed)
        et_layout.addLayout(button_row(self.et_btn, QLabel('Rule level'), self.sig_level))
        self.sig_builtin = QCheckBox('Built-in starter rules')
        self.sig_builtin.toggled.connect(self._sig_builtin_changed)
        self.et_auto = QCheckBox('Update ET Open daily')
        self.et_auto.setToolTip('Download the rule set again once a day while IDPS is open.')
        self.et_auto.toggled.connect(lambda v: self.settings.set('sig_et_auto', bool(v)))
        et_layout.addLayout(button_row(self.sig_builtin, self.et_auto))
        self.et_status = note_label('')
        et_layout.addWidget(self.et_status)
        self.sig_advanced_btn = secondary(QPushButton('Advanced: other rule files and HOME_NET'))
        self.sig_advanced_btn.setCheckable(True)
        self.sig_advanced_btn.setToolTip('Load rule files or archives from elsewhere, or change which addresses '
                                         'count as your network. Most people never need this.')
        self.sig_advanced_btn.toggled.connect(self.sig_advanced.setVisible)
        et_layout.addLayout(button_row(self.sig_advanced_btn))
        top.addWidget(et_box, 1)
        layout.addLayout(top)
        layout.addWidget(self.sig_advanced)
        self.sig_status = QLabel('No signature rules loaded.')
        self.sig_status.setWordWrap(True)
        layout.addWidget(self.sig_status)
        self.sig_reasons = make_table(['Rules', 'Skip reason'])
        self.sig_examples = make_table(['File', 'Line', 'Reason', 'Rule'])
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._card('Skipped rules by reason', self.sig_reasons))
        split.addWidget(self._card('Skipped rule examples', self.sig_examples))
        split.setSizes([420, 900])
        from .sig_gui import RuleBrowser
        self.rule_browser = RuleBrowser(self._signature_switches_changed)
        self.sig_tabs = QTabWidget()
        from .sig_gui import MyRulesEditor
        self.my_rules = MyRulesEditor(self.load_signatures, self.status)
        self.sig_tabs.addTab(self.rule_browser, 'Loaded rules')
        self.sig_tabs.addTab(self.my_rules, 'My rules')
        self.sig_tabs.addTab(split, 'Skipped rules')
        layout.addWidget(self.sig_tabs, 1)
        return w

    def _ips_tab(self) -> QWidget:
        w = QWidget()
        columns = QHBoxLayout(w)
        left, right = QVBoxLayout(), QVBoxLayout()
        columns.addLayout(left, 1)
        columns.addLayout(right, 1)

        box = QGroupBox('Inline prevention')
        form = QFormLayout(box)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.ips_on = QCheckBox('Enable inline IPS (safety switch)')
        self.ips_on.toggled.connect(self.safety_changed)
        self.auto_block = QCheckBox('Automatic blocking (WEB-001 only, after repeated verified detections)')
        self.dry_run = QCheckBox('Dry-run: only report what would be blocked (recommended)')
        self.dry_run.setToolTip('Dry-run never drops blocklisted traffic and never adds auto-block entries.')
        self.dry_run.setChecked(True)
        self.ttl = QSpinBox()
        self.ttl.setRange(TTL_MIN, TTL_MAX)
        self.ttl.setSuffix(' s')
        self.ttl.setMaximumWidth(160)
        self.auto_block.toggled.connect(self.policy_changed)
        self.dry_run.toggled.connect(self.policy_changed)
        self.ttl.valueChanged.connect(self.policy_changed)
        self.ips_filter = QLineEdit(WINDIVERT_DEFAULT_FILTER)
        self.ips_filter.setToolTip('WinDivert filter language (not BPF): for example "ip or ipv6", '
                                   '"tcp.DstPort == 80" or "inbound and tcp".')
        self.queue_num = QSpinBox()
        self.queue_num.setRange(0, 65535)
        self.queue_num.setMaximumWidth(160)
        self.ips_start, self.ips_stop = QPushButton('Start inline IPS'), secondary(QPushButton('Stop IPS'))
        self.ips_stop.setEnabled(False)
        self.ips_start.clicked.connect(self.start_ips)
        self.ips_stop.clicked.connect(lambda: self.stop_ips())
        form.addRow('Platform', QLabel(platform.system()))
        form.addRow('Safety switch', self.ips_on)
        form.addRow('Prevention', self.auto_block)
        form.addRow('Safety mode', self.dry_run)
        form.addRow('Auto-block duration', self.ttl)
        form.addRow('Windows filter', self.ips_filter)
        form.addRow('Linux NFQUEUE', self.queue_num)
        form.addRow(button_row(self.ips_start, self.ips_stop))
        left.addWidget(box)
        left.addWidget(note_label(IPS_NOTE))

        trusted_box = QGroupBox('Trusted sources (never alerted on or blocked)')
        trusted_layout = QVBoxLayout(trusted_box)
        row = QHBoxLayout()
        self.trust_ip, self.trust_reason = QLineEdit(), QLineEdit()
        self.trust_ip.setPlaceholderText('Trusted IP or CIDR')
        self.trust_reason.setPlaceholderText('Reason')
        add_trust, remove_trust = QPushButton('Trust'), secondary(QPushButton('Remove selected'))
        add_trust.clicked.connect(self.add_trusted)
        remove_trust.clicked.connect(self.remove_trusted)
        row.addWidget(self.trust_ip, 3)
        row.addWidget(self.trust_reason, 2)
        row.addWidget(add_trust)
        row.addWidget(remove_trust)
        trusted_layout.addLayout(row)
        self.trusted_list = QListWidget()
        self.trusted_list.setMinimumHeight(90)
        trusted_layout.addWidget(self.trusted_list)
        trusted_layout.addWidget(note_label('Traffic to trusted destinations is still inspected.'))
        right.addWidget(trusted_box, 2)

        block_box = QGroupBox('Blocklist (single IPs or CIDR ranges)')
        block_layout = QVBoxLayout(block_box)
        row = QHBoxLayout()
        self.block_ip, self.block_reason = QLineEdit(), QLineEdit()
        self.block_ip.setPlaceholderText('IP or CIDR, e.g. 203.0.113.7 or 203.0.113.0/24')
        self.block_reason.setPlaceholderText('Reason')
        add_block, remove_block = QPushButton('Add'), secondary(QPushButton('Remove selected'))
        add_block.clicked.connect(self.add_block)
        remove_block.clicked.connect(self.remove_block)
        row.addWidget(self.block_ip, 3)
        row.addWidget(self.block_reason, 2)
        row.addWidget(add_block)
        row.addWidget(remove_block)
        block_layout.addLayout(row)
        self.block_list = QListWidget()
        self.block_list.setMinimumHeight(120)
        block_layout.addWidget(self.block_list)
        right.addWidget(block_box, 3)

        feed_box = QGroupBox('Blocklist feeds')
        feed_layout = QVBoxLayout(feed_box)
        feed_layout.addWidget(note_label('Downloaded over HTTPS. Nothing is downloaded until you add a URL.'))
        self.feed_urls = QPlainTextEdit()
        self.feed_urls.setPlaceholderText(FEED_PLACEHOLDER)
        self.feed_urls.setFixedHeight(76)
        feed_layout.addWidget(self.feed_urls)
        self.feed_auto = QCheckBox('Update automatically every')
        self.feed_interval = QSpinBox()
        self.feed_interval.setRange(FEED_INTERVAL_MIN, FEED_INTERVAL_MAX)
        self.feed_interval.setSuffix(' h')
        self.feed_interval.setMaximumWidth(100)
        save_feeds_btn, update_feeds_btn = secondary(QPushButton('Save feeds')), QPushButton('Update now')
        save_feeds_btn.clicked.connect(self.save_feeds)
        update_feeds_btn.clicked.connect(lambda: self.update_feeds())
        row = QHBoxLayout()
        row.addWidget(self.feed_auto)
        row.addWidget(self.feed_interval)
        row.addStretch(1)
        row.addWidget(save_feeds_btn)
        row.addWidget(update_feeds_btn)
        feed_layout.addLayout(row)
        self.feed_status = note_label('')
        feed_layout.addWidget(self.feed_status)
        left.addWidget(feed_box)
        left.addStretch(1)
        return w

    def _notification_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        box = QGroupBox('Alert notifications')
        form = QFormLayout(box)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.notify_severity = QComboBox()
        self.notify_severity.addItems(SEVERITIES)
        self.notify_severity.setMaximumWidth(200)
        self.notify_desktop = QCheckBox('Show a desktop notification')
        self.notify_webhook = QLineEdit()
        self.notify_webhook.setPlaceholderText('https://example.com/hooks/netsentinel  (leave blank to disable)')
        self.notify_syslog = QLineEdit()
        self.notify_syslog.setPlaceholderText('syslog.example.com:514  (UDP, leave blank to disable)')
        form.addRow('Minimum severity', self.notify_severity)
        form.addRow('Desktop', self.notify_desktop)
        form.addRow('Webhook (JSON POST)', self.notify_webhook)
        form.addRow('Syslog (RFC 5424)', self.notify_syslog)
        save = QPushButton('Save notification settings')
        save.clicked.connect(self.save_notifications)
        test = secondary(QPushButton('Send test notification'))
        test.clicked.connect(self.test_notification)
        form.addRow(button_row(save, test))
        layout.addWidget(box)
        layout.addWidget(note_label(
            'Each rule and source notifies at most once per minute, and at most 30 notifications are sent per '
            'minute in total. Evidence is redacted unless payload saving is enabled. Webhook and syslog delivery '
            'runs in the background and never slows packet processing.'))
        self.notify_status = QLabel('')
        layout.addWidget(self.notify_status)
        layout.addStretch(1)
        return w

    def _notification_dialog(self) -> QDialog:
        """Separate window holding every notification setting, opened from the gear button."""
        dialog = QDialog(self)
        dialog.setWindowTitle('Notification settings')
        dialog.setMinimumWidth(640)
        layout = QVBoxLayout(dialog)
        layout.addWidget(self._notification_tab())
        close = secondary(QPushButton('Close'))
        close.clicked.connect(dialog.close)
        layout.addLayout(button_row(close, align_right=True))
        return dialog

    def show_notification_settings(self):
        # Show the saved values, so edits that were never saved don't linger after closing the window.
        s = self.settings
        self.notify_severity.setCurrentText(s.get('notify_min_severity'))
        self.notify_desktop.setChecked(s.get('notify_desktop'))
        self.notify_webhook.setText(s.get('notify_webhook'))
        self.notify_syslog.setText(s.get('notify_syslog'))
        self.notify_dialog.show()
        self.notify_dialog.raise_()
        self.notify_dialog.activateWindow()

    # -- settings ----------------------------------------------------------------
    def _apply_settings(self):
        s = self.settings
        self.source.setCurrentIndex(s.get('source_index'))
        self._select_iface(s.get('iface'))
        self.bpf.setText(s.get('bpf'))
        self.pcap_path.setText(s.get('pcap_path'))
        self.keep_payload.setChecked(s.get('keep_payload'))
        self.persist_packets.setChecked(s.get('persist_packets'))
        self.store.keep_payload = s.get('keep_payload')
        self.store.persist_packets = s.get('persist_packets')
        self.auto_block.setChecked(s.get('auto_block'))
        self.dry_run.setChecked(True)
        self.ttl.setValue(s.get('ttl'))
        self.ips_filter.setText(s.get('ips_filter'))
        self.queue_num.setValue(s.get('queue_num'))
        self.notify_severity.setCurrentText(s.get('notify_min_severity'))
        self.notify_desktop.setChecked(s.get('notify_desktop'))
        self.notify_webhook.setText(s.get('notify_webhook'))
        self.notify_syslog.setText(s.get('notify_syslog'))
        self.save_pcap.setChecked(s.get('save_pcap'))
        self.save_pcap_path.setText(s.get('save_pcap_path'))
        self.feed_urls.setPlainText('\n'.join(s.get('feed_urls')))
        self.feed_auto.setChecked(s.get('feed_auto'))
        self.feed_interval.setValue(s.get('feed_interval_hours'))
        for path in s.get('sig_paths'):
            self.sig_list.addItem(list_item(path, path))
        self.sig_home_net.setText(s.get('sig_home_net'))
        for widget, value in ((self.et_auto, s.get('sig_et_auto')), (self.sig_builtin, s.get('sig_builtin'))):
            widget.blockSignals(True)
            widget.setChecked(value)
            widget.blockSignals(False)
        self.sig_level.blockSignals(True)
        self.sig_level.setCurrentIndex(max(0, self.sig_level.findData(s.get('sig_level'))))
        self.sig_level.blockSignals(False)
        self._show_et_status()

    def _bind_settings(self):
        s = self.settings
        self.source.currentIndexChanged.connect(lambda v: s.set('source_index', v))
        self.iface.currentTextChanged.connect(lambda *_: s.set('iface', self.selected_iface()))
        self.bpf.textChanged.connect(lambda v: s.set('bpf', v))
        self.pcap_path.textChanged.connect(lambda v: s.set('pcap_path', v))
        self.keep_payload.toggled.connect(lambda v: s.set('keep_payload', v))
        self.persist_packets.toggled.connect(lambda v: s.set('persist_packets', v))
        self.auto_block.toggled.connect(lambda v: s.set('auto_block', v))
        self.ttl.valueChanged.connect(lambda v: s.set('ttl', v))
        self.ips_filter.textChanged.connect(lambda v: s.set('ips_filter', v))
        self.queue_num.valueChanged.connect(lambda v: s.set('queue_num', v))
        self.save_pcap.toggled.connect(lambda v: s.set('save_pcap', v))
        self.save_pcap_path.textChanged.connect(lambda v: s.set('save_pcap_path', v))
        self.feed_auto.toggled.connect(lambda v: s.set('feed_auto', v))
        self.feed_interval.valueChanged.connect(lambda v: s.set('feed_interval_hours', v))

    def _keep_payload_changed(self, enabled):
        self.store.keep_payload = enabled
        self.notifier.configure(self._notification_settings())

    # -- interfaces ------------------------------------------------------------
    def reload_interfaces(self):
        def load():
            try:
                items = list_interfaces()
            except Exception:
                items = []
            self.bridge.interfaces.emit(items)
        threading.Thread(target=load, name='NetSentinel-Interfaces', daemon=True).start()

    def _set_interfaces(self, items):
        current = self.selected_iface()
        self.iface.blockSignals(True)
        self.iface.clear()
        self.iface.addItem('default', '')
        for item in items:
            self.iface.addItem(item.label, item.name)
        self.iface.blockSignals(False)
        self._select_iface(current)

    def _select_iface(self, name: str):
        idx = self.iface.findData(name)
        if idx >= 0:
            self.iface.setCurrentIndex(idx)
        else:
            self.iface.setEditText(name)

    def selected_iface(self) -> str:
        """Interface name to capture on; '' means the library default."""
        text = self.iface.currentText().strip()
        idx = self.iface.findText(text)
        if idx >= 0:
            return self.iface.itemData(idx) or ''
        return '' if text.lower() == 'default' else text

    # -- messages and notifications ---------------------------------------------
    def log(self, text):
        self.console.appendPlainText(f'[{datetime.now().strftime("%H:%M:%S")}] {text}')

    def wifi_status(self, text):
        """Wi-Fi tab messages: console and status bar only, so "IDS stopped" stays accurate."""
        self.statusbar.showMessage(text)
        self.log(text)

    def status(self, text):
        self.engine.setText(text)
        self.statusbar.showMessage(text)
        self.log(text)

    def error(self, text):
        now = time.monotonic()
        if now - self._last_error_shown.get(text, -float('inf')) < ERROR_DIALOG_INTERVAL:
            return
        self._last_error_shown[text] = now
        self._last_error_at = now
        self.engine.setText('ERROR: ' + text)
        self.statusbar.showMessage('ERROR: ' + text, 10000)
        self.log('ERROR: ' + text)

    def _notification_settings(self) -> NotificationSettings:
        s = self.settings
        return NotificationSettings(min_severity=s.get('notify_min_severity'), desktop=s.get('notify_desktop'),
                                    webhook_url=s.get('notify_webhook'), syslog_target=s.get('notify_syslog'),
                                    include_evidence=self.store.keep_payload)

    def _desktop_notify(self, title, message):
        if self.tray is not None and self.tray.isVisible():
            self.tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Warning, 8000)
        else:
            self.statusbar.showMessage(f'{title}: {message}', 8000)

    def save_notifications(self) -> bool:
        candidate = NotificationSettings(min_severity=self.notify_severity.currentText(),
                                         desktop=self.notify_desktop.isChecked(),
                                         webhook_url=self.notify_webhook.text().strip(),
                                         syslog_target=self.notify_syslog.text().strip(),
                                         include_evidence=self.store.keep_payload)
        errors = candidate.validate()
        if errors:
            QMessageBox.warning(self, 'Notifications', '\n'.join(errors))
            return False
        s = self.settings
        s.set('notify_min_severity', candidate.min_severity)
        s.set('notify_desktop', candidate.desktop)
        s.set('notify_webhook', candidate.webhook_url)
        s.set('notify_syslog', candidate.syslog_target)
        self.notifier.configure(candidate)
        self.status('Notification settings saved.')
        return True

    def test_notification(self):
        if self.save_notifications():
            self.notifier.send_test()
            self.status('Test notification sent to the enabled channels.')

    # -- worker management -------------------------------------------------------
    def _reset_counters(self):
        self.packet_count = self.alert_count = self.last_packet_count = 0
        self.dropped_capture = 0
        self.sources.clear()
        self.recent.clear()
        self.timeline.clear()
        self._summary_protocols.clear()
        self._summary_talkers.clear()
        self._summary_alerts = 0
        self._last_summary = time.monotonic()
        self.packets_dirty = True
        self._last_error_shown.clear()
        self.detector.reset()

    def _attach(self, w: Worker, on_finished):
        w.packet_batch.connect(self.on_packet_batch)
        w.alert_batch.connect(self.on_alert_batch)
        w.status.connect(self.status)
        w.error.connect(self.error)
        w.finished.connect(on_finished)
        w.start()

    def _halt(self, w: Worker) -> bool:
        w.stop()
        if w.wait(WORKER_STOP_TIMEOUT_MS):
            return True
        if w not in self.zombies:
            self.zombies.append(w)
        self.status('Worker did not stop within 4 seconds; keeping the thread referenced.')
        return False

    def _release_sender(self) -> Optional[QThread]:
        sender = self.sender()
        if isinstance(sender, QThread):
            sender.wait(0)
            sender.deleteLater()
            return sender
        return None

    def on_packet_batch(self, batch):
        self.packet_count += len(batch)
        self.timeline.add_packets(len(batch))
        for w in (self.worker, self.ips):
            if w is not None:
                self.dropped_capture = max(self.dropped_capture, w.dropped_capture)
        keep_payload = self.store.keep_payload
        protocols, talkers = self._summary_protocols, self._summary_talkers
        for p in batch:
            if len(self.sources) < 100_000:
                self.sources.add(p.src_ip)
            protocols[p.protocol] += 1
            if len(talkers) < 10_000:
                talkers[(p.src_ip, p.dst_ip)] += 1
            # The GUI never retains payloads unless the analyst chose to save them.
            self.recent.append(Packet(p.timestamp, p.src_ip, p.dst_ip, p.protocol, p.src_port, p.dst_port,
                                      p.length, p.flags, p.payload if keep_payload else '', p.source,
                                      p.dropped, p.capture_time))
        self.packets_dirty = True

    def on_alert_batch(self, batch):
        if self._self_test_alerts is not None:
            self._self_test_alerts.extend(batch)
        self.alert_count += len(batch)
        self._summary_alerts += len(batch)
        now = time.time()
        for a in batch:
            self.timeline.add(a.rule_id, now)
            self.log(f'{a.severity} {a.rule_id} {a.src_ip} -> {a.dst_ip} | {a.title} | {a.action}')
        self.notifier.submit(batch)

    # -- IDS -------------------------------------------------------------------
    def choose_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open PCAP', '', 'PCAP files (*.pcap *.pcapng);;All files (*)')
        if path:
            self.pcap_path.setText(path)

    def choose_save_pcap(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save live capture', self.save_pcap_path.text() or 'capture.pcap',
                                              'PCAP files (*.pcap);;All files (*)')
        if path:
            self.save_pcap_path.setText(path)
            self._save_pcap_confirmed = path      # the save dialog already asked about overwriting

    def _recording_path(self) -> Optional[str]:
        """PCAP path for a live capture: '' for no recording, None if the user cancelled."""
        if not self.save_pcap.isChecked():
            return ''
        path = self.save_pcap_path.text().strip()
        if not path:
            QMessageBox.warning(self, APP_NAME, 'Choose a PCAP file to save the capture to, or untick '
                                                '"Save live capture to PCAP".')
            return None
        if (Path(path).exists() and self._save_pcap_confirmed != path
                and QMessageBox.question(self, APP_NAME, f'{path} already exists. Overwrite it?', YES | NO, NO) != YES):
            return None
        return path

    def start_ids(self):
        if self.ips:
            QMessageBox.information(self, APP_NAME,
                                    'Inline IPS already inspects traffic. Stop it before starting the passive IDS.')
            return
        if self.worker and not self.stop_ids(quiet=True):
            return
        mode = self.source.currentIndex()
        if mode == 2:
            path = self.pcap_path.text().strip()
            if not path or not Path(path).exists():
                QMessageBox.warning(self, APP_NAME, 'Choose an existing PCAP/PCAPNG file first.')
                return
        save_path = self._recording_path() if mode == 0 else ''
        if save_path is None:
            return
        self._save_pcap_confirmed = None
        self.detector.load()
        self._reset_counters()
        self._live_started_at = time.monotonic() if mode == 0 else None
        self._capture_label = SOURCE_LABELS[mode]
        self._quiet_hint_shown = False
        if mode == 0:
            self.worker = LiveWorker(self.detector, self.selected_iface(), self.bpf.text().strip(), save_path)
        elif mode == 1:
            self.worker = SimWorker(self.detector)
        else:
            self.worker = PcapWorker(self.detector, self.pcap_path.text().strip())
        self._attach(self.worker, self.on_ids_finished)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_ids(self, quiet=False) -> bool:
        if self.worker:
            if not self._halt(self.worker):
                return False
            self.worker = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if not quiet:
            self.status('IDS stopped.')
        return True

    def on_ids_finished(self):
        sender = self._release_sender()
        if sender is not None and sender is self.worker:
            self.worker = None
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status('IDS stopped.')

    # -- live self-test ----------------------------------------------------------
    def run_self_test(self) -> bool:
        """Send the self-test traffic and report which rules the live capture caught."""
        if self.self_test_worker is not None or self._self_test_alerts is not None:
            return False
        if self.ips:
            QMessageBox.information(self, APP_NAME, 'Stop the inline IPS first; the self-test uses the passive '
                                                    'live capture.')
            return False
        delay = 0
        if not isinstance(self.worker, LiveWorker):
            if QMessageBox.question(self, APP_NAME, 'The self-test needs live packet capture. Start it now?',
                                    YES | NO, YES) != YES:
                return False
            self.source.setCurrentIndex(0)
            self.start_ids()
            if not isinstance(self.worker, LiveWorker):
                return False
            delay = 2500                # give the sniffer time to open the adapter
        thresholds = {rid: r['threshold'] for rid, r in self.detector.rules.items() if r['enabled']}
        self._self_test_alerts = []
        self.self_test_btn.setEnabled(False)
        QTimer.singleShot(delay, lambda: self._send_self_test(thresholds))
        return True

    def _send_self_test(self, thresholds):
        if self._closing:
            return
        if not isinstance(self.worker, LiveWorker):
            # Live capture failed to start (for example Npcap is missing); its error is already shown.
            self._finish_self_test('Self-test stopped: live capture is not running. See the console for the '
                                   'capture error.')
            return
        worker = SelfTestWorker(thresholds)
        worker.log.connect(self.log)
        worker.done.connect(lambda rules, error: self._self_test_sent(rules, error, thresholds))
        worker.finished.connect(worker.deleteLater)
        self.self_test_worker = worker
        worker.start()

    def _self_test_sent(self, rules, error, thresholds):
        self.self_test_worker = None
        if error:
            self._finish_self_test(f'Self-test failed: {error}')
            return
        expected = [r for r in rules if r in thresholds]
        QTimer.singleShot(4000, lambda: self._report_self_test(expected))

    def _report_self_test(self, expected):
        if self._closing:
            return
        detected, missed = evaluate_self_test(expected, self._self_test_alerts or [])
        if missed or not expected:
            text = (f'Self-test: {len(detected)} of {len(expected)} rules detected the test traffic. '
                    f'Missed: {", ".join(missed) or "none"}.\n\n{SELF_TEST_HINT}')
        else:
            text = f'Self-test passed: live capture detected all {len(detected)} rules ({", ".join(detected)}).'
        self._finish_self_test(text)

    def _finish_self_test(self, text):
        self._self_test_alerts = None
        self.self_test_btn.setEnabled(True)
        self.status(text.split('\n')[0])
        self.last_self_test = text
        QMessageBox.information(self, 'Self-test', text)

    # -- IPS -------------------------------------------------------------------
    def _confirm_active_blocking(self, text) -> bool:
        return QMessageBox.question(self, 'Enable active blocking', text, YES | NO, NO) == YES

    def start_ips(self):
        if not self.ips_on.isChecked():
            QMessageBox.warning(self, 'Safety switch', 'Enable the explicit IPS safety switch first.')
            return
        if self.worker:
            QMessageBox.information(self, APP_NAME, 'Stop the passive IDS first; the IPS inspects traffic itself.')
            return
        system = platform.system()
        if system not in ('Windows', 'Linux'):
            QMessageBox.information(self, 'Platform', 'Inline IPS is implemented for Windows and Linux.')
            return
        auto, dry, ttl = self.auto_block.isChecked(), self.dry_run.isChecked(), self.ttl.value()
        if auto and not dry and not self._confirm_active_blocking(
                'Active auto-blocking will add temporary blocklist entries and may interrupt legitimate traffic. '
                'Continue?'):
            return
        if self.ips and not self.stop_ips(quiet=True):
            return
        self.detector.load()
        self._reset_counters()
        if system == 'Windows':
            self.ips = WinIPS(self.detector, self.ips_filter.text().strip(), auto, ttl, dry)
        else:
            self.ips = LinuxIPS(self.detector, self.queue_num.value(), auto, ttl, dry)
        self._attach(self.ips, self.on_ips_finished)
        self.ips_start.setEnabled(False)
        self.ips_stop.setEnabled(True)

    def stop_ips(self, quiet=False) -> bool:
        if self.ips:
            if not self._halt(self.ips):
                return False
            self.ips = None
        self.ips_start.setEnabled(True)
        self.ips_stop.setEnabled(False)
        if not quiet:
            self.status('Inline IPS stopped.')
        return True

    def on_ips_finished(self):
        sender = self._release_sender()
        if sender is not None and sender is self.ips:
            self.ips = None
            self.ips_start.setEnabled(True)
            self.ips_stop.setEnabled(False)
            self.status('Inline IPS stopped.')

    def safety_changed(self, enabled):
        if not enabled and self.ips:
            self.status('IPS safety switch disabled; stopping inline IPS.')
            self.stop_ips(quiet=True)
        self.policy_changed()

    def policy_changed(self, *_):
        """Apply policy edits to a running IPS; confirm before it starts dropping traffic."""
        ips = self.ips
        if not ips:
            return
        new_auto, new_dry = self.auto_block.isChecked(), self.dry_run.isChecked()
        starts_dropping = not new_dry and (ips.dry_run or (new_auto and not ips.active_blocking))
        if starts_dropping and not self._confirm_active_blocking(
                'This changes the running IPS to active blocking. Imported blocklist entries can also drop '
                'traffic. Continue?'):
            self.dry_run.blockSignals(True)
            self.dry_run.setChecked(True)
            self.dry_run.blockSignals(False)
            new_dry = True
        ips.auto_block, ips.dry_run, ips.ttl = new_auto, new_dry, self.ttl.value()
        self.status(f'Runtime IPS policy updated: auto-block={ips.auto_block}, dry-run={ips.dry_run}, '
                    f'ttl={ips.ttl}s')

    # -- periodic refresh ------------------------------------------------------
    def tick(self):
        store = self.store
        store.expire_blocks()
        if store.writer_error:
            self.statusbar.showMessage('Database writer error: ' + store.writer_error, 5000)
        elif store.buffer_drops:
            self.statusbar.showMessage(f'Database buffer dropped {store.buffer_drops:,} oldest rows while the '
                                       'writer was unavailable.', 5000)
        self.zombies = [z for z in self.zombies if z.isRunning()]
        self.lbl_packets.setText(f'{self.packet_count:,}')
        self.lbl_alerts.setText(f'{self.alert_count:,}')
        self.lbl_sources.setText(f'{len(self.sources):,}')
        self.lbl_blocks.setText(f'{store.block_count():,}')
        self.lbl_drops.setText(f'{self.dropped_capture:,}')
        self.rate.setText(f'Packet rate: {max(0, self.packet_count - self.last_packet_count)}/s')
        self.last_packet_count = self.packet_count
        if self.tabs.currentIndex() == 0:
            self.chart.set_series(*self.timeline.series(), self.timeline.packet_series())
        self._update_engine_status()
        self._log_traffic_summary()
        if self.packets_dirty and self.tabs.currentWidget() is self.packet_tab:
            self.packets_dirty = False
            self.refresh_packets()
        if store.blocks_version != self._seen_blocks_version:
            self.refresh_blocks()
        if store.alert_generation != self._seen_alert_generation:
            self.refresh_alerts_in_background()
        if self._feed_update_due():
            self.update_feeds(automatic=True)
        if et_update_due(self.settings.get('sig_et_auto'), self.settings.get('sig_et_last'), self._et_attempt,
                         time.time()):
            self.update_et_open(automatic=True)
        if self.detector.sig_hits_version != self._seen_sig_hits:
            self._seen_sig_hits = self.detector.sig_hits_version
            self.rule_browser.refresh_hits()
        self._quiet_capture_hint()
        n = self.notifier
        text = f'Notifications sent: {n.sent:,}; dropped: {n.dropped:,}'
        self.notify_status.setText(text + (f'; last error: {n.last_error}' if n.last_error else ''))

    def _running_label(self) -> str:
        """What is inspecting traffic right now, or '' if nothing is."""
        if self.ips is not None:
            return 'Inline IPS'
        if self.worker is not None:
            return self._capture_label or 'Capture'
        return ''

    def _update_engine_status(self):
        """Keep the engine status line live while capturing (an error stays visible for 15 s)."""
        label = self._running_label()
        if not label or time.monotonic() - self._last_error_at < 15:
            return
        self.engine.setText(f'{label} running: {self.packet_count:,} packets inspected, {self.alert_count:,} '
                            f'alerts, {len(self.sources):,} sources.'
                            + ('' if self.packet_count else ' Waiting for packets...'))

    def _log_traffic_summary(self):
        """Every SUMMARY_SECONDS, write what was captured to the console, even when nothing was flagged."""
        now = time.monotonic()
        if now - self._last_summary < SUMMARY_SECONDS:
            return
        seconds = now - self._last_summary
        self._last_summary = now
        protocols, talkers = self._summary_protocols, self._summary_talkers
        total = sum(protocols.values())
        alerts, self._summary_alerts = self._summary_alerts, 0
        if not total or not self._running_label():
            protocols.clear()
            talkers.clear()
            return
        mix = ', '.join(f'{proto} {count:,}' for proto, count in protocols.most_common(5))
        busiest = ', '.join(f'{src} -> {dst} ({count:,})' for (src, dst), count in talkers.most_common(2))
        self.log(f'Traffic: {total:,} packets in the last {seconds:.0f} s ({mix}); busiest: {busiest}; '
                 + (f'{alerts:,} alert(s).' if alerts else 'nothing suspicious.'))
        protocols.clear()
        talkers.clear()

    def _quiet_capture_hint(self):
        """Explain once that a quiet live capture is normal, so no alerts does not look like a fault."""
        started = self._live_started_at
        if (started is None or self._quiet_hint_shown or not isinstance(self.worker, LiveWorker)
                or time.monotonic() - started < QUIET_HINT_SECONDS):
            return
        self._quiet_hint_shown = True
        if self.packet_count == 0:
            self.log('Live capture has seen no packets yet. Pick the adapter that carries your traffic '
                     '(usually Wi-Fi) in the Interface list, then start again.')
        elif self.alert_count == 0:
            self.log(f'Live capture is working: {self.packet_count:,} packets inspected and no attacks found, '
                     'which is normal for everyday traffic. Click "Run self-test" to see live detection fire.')

    def refresh_packets(self):
        """Show the newest packets. Runs only while the Packets tab is visible (see _tab_changed).

        Existing cells are updated in place, and painting is paused during the update: replacing 1,500
        cells every second stalled the window by up to half a second under heavy traffic.
        """
        table = self.packet_table
        rows = list(itertools.islice(reversed(self.recent), GUI_PACKET_ROWS))
        longest = self._packet_col_chars
        grew: set = set()
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(len(rows))
            for i, p in enumerate(rows):
                values = (display_time(p.timestamp), p.src_ip, p.dst_ip, p.protocol, p.src_port or '',
                          p.dst_port or '', p.length, p.flags, 'DROP' if p.dropped else '', p.source)
                for j, v in enumerate(values):
                    text = '' if v is None else str(v)
                    if len(text) > longest[j]:      # e.g. the first IPv6 address: widen that column
                        longest[j] = len(text)
                        grew.add(j)
                    item = table.item(i, j)
                    if item is None:
                        table.setItem(i, j, cell(text))
                    elif item.text() != text:
                        item.setText(text)
        finally:
            table.setUpdatesEnabled(True)
        # Columns only ever grow, and only when a longer value appears, so they don't jump every second.
        grew.discard(table.columnCount() - 1)
        if grew:
            fit_columns(table, sorted(grew))

    def _tab_changed(self, index: int):
        if self.tabs.widget(index) is self.packet_tab and self.packets_dirty:
            self.packets_dirty = False
            self.refresh_packets()

    def _selected_alert_id(self) -> Optional[int]:
        items = self.alert_table.selectedItems()
        if not items:
            return None
        try:
            return int(cell_text(self.alert_table, items[0].row(), 0))
        except ValueError:
            return None

    def alert_filters(self) -> dict:
        return {'severity': self.filter_severity.currentData() or None,
                'rule_id': self.filter_rule.currentData() or None,
                'status': self.filter_status.currentData() or None,
                'ip': self.filter_ip.text().strip() or None}

    def clear_alert_filters(self):
        for combo in (self.filter_severity, self.filter_rule, self.filter_status):
            combo.blockSignals(True)
            combo.setCurrentIndex(0)
            combo.blockSignals(False)
        self.filter_ip.blockSignals(True)
        self.filter_ip.clear()
        self.filter_ip.blockSignals(False)
        self.refresh_alerts()

    def refresh_alerts(self):
        """Reload the alert table now (after a user action)."""
        self._seen_alert_generation = self.store.alert_generation
        self._alert_seq += 1                             # a background read started before this is now stale
        self._fill_alert_table(self.store.alerts(GUI_ALERT_ROWS, **self.alert_filters()), detail=True)

    def refresh_alerts_in_background(self):
        """Periodic reload: read the database on a helper thread. While detection is busy, a query on the GUI
        thread waits for the GIL after every row and could freeze the window for a few hundred ms."""
        if self._alert_fetch is not None and self._alert_fetch.is_alive():
            self._alert_fetch_again = True
            return
        generation, filters = self.store.alert_generation, self.alert_filters()
        self._seen_alert_generation = generation
        self._alert_seq += 1
        seq = self._alert_seq

        def fetch():
            try:
                # Own read connection: does not hold Store.lock, which the GUI and detection threads need.
                rows = self.store.alerts(GUI_ALERT_ROWS, **filters, own_connection=True)
            except Exception as exc:                     # database closed or busy: try again next tick
                self._seen_alert_generation = -1
                if not self._closing:
                    self.bridge.error.emit(f'Could not read alerts: {exc}')
                return
            self.bridge.alerts.emit((seq, filters, rows))

        self._alert_fetch = threading.Thread(target=fetch, name='IDPS-AlertRead', daemon=True)
        self._alert_fetch.start()

    def _alerts_fetched(self, result):
        seq, filters, rows = result
        if self._closing:
            self._seen_alert_generation = -1             # a cancelled close must not leave the table stale
            return
        # Show it only if nothing newer was shown meanwhile (a direct refresh after a filter change or an
        # acknowledge) and the filters still match.
        if seq == self._alert_seq and filters == self.alert_filters():
            self._fill_alert_table(rows)
        if self._alert_fetch_again:
            self._alert_fetch_again = False
            QTimer.singleShot(0, self.refresh_alerts_in_background)

    def _fill_alert_table(self, rows: list[dict], detail: bool = False):
        """Show `rows`. The detail panel is rebuilt when asked or when the selected alert changed."""
        selected = self._selected_alert_id()
        self._alert_rows = {r['id']: r for r in rows}
        table = self.alert_table
        table.blockSignals(True)
        table.clearSelection()
        table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, field in enumerate(ALERT_FIELDS):
                value = r.get(field)
                item = cell(display_time(value) if field == 'timestamp' else value)
                if field == 'severity' and r['severity'] in ('HIGH', 'CRITICAL'):
                    item.setForeground(QColor('#ff8a65'))
                table.setItem(i, j, item)
            if r['id'] == selected:
                table.selectRow(i)
        fit_columns(table)
        table.blockSignals(False)
        if detail or self._selected_alert_id() != self._detail_shown_for:
            self.show_alert_detail()                     # asked for, or the selection changed or disappeared

    def related_packets(self, ip: str) -> list[dict]:
        """Recent packets involving `ip`, from memory and (if enabled) the database, newest first."""
        key = canonical_ip(ip)
        rows: list[dict] = []
        for p in reversed(self.recent):
            if canonical_ip(p.src_ip) == key or canonical_ip(p.dst_ip) == key:
                rows.append({'timestamp': p.timestamp, 'src_ip': p.src_ip, 'dst_ip': p.dst_ip,
                             'protocol': p.protocol, 'src_port': p.src_port, 'dst_port': p.dst_port,
                             'length': p.length, 'flags': p.flags, 'dropped': int(p.dropped)})
                if len(rows) >= GUI_RELATED_PACKETS:
                    break
        rows += self.store.related_packets(key, GUI_RELATED_PACKETS)
        seen, merged = set(), []
        for r in sorted(rows, key=lambda r: r['timestamp'] or '', reverse=True):
            ident = (r['timestamp'], r['src_ip'], r['dst_ip'], r['src_port'], r['dst_port'], r['protocol'])
            if ident not in seen:
                seen.add(ident)
                merged.append(r)
        return merged[:GUI_RELATED_PACKETS]

    def show_alert_detail(self):
        alert_id = self._selected_alert_id()
        self._detail_shown_for = alert_id
        alert = None
        if alert_id is not None:
            alert = self._alert_rows.get(alert_id) or self.store.alert(alert_id)    # usually already read
        if alert is None:
            self.alert_detail.clear()
            return
        width = max(len(v) for v in DETAIL_LABELS.values())
        values = {f: alert.get(f) if alert.get(f) is not None else '' for f in ALERT_FIELDS}
        values['timestamp'] = display_time(alert.get('timestamp'))
        lines = [f'{DETAIL_LABELS[f]:<{width}}  {values[f]}' for f in ALERT_FIELDS]
        if alert.get('detail'):
            lines += ['', 'Why this signature matched:'] + ['  ' + x for x in str(alert['detail']).splitlines()]
        packets = self.related_packets(alert['src_ip'])
        lines += ['', f'Related packets involving {alert["src_ip"]} (newest first, up to {GUI_RELATED_PACKETS}):']
        if not self.store.persist_packets:
            lines.append('  Note: packet persistence is off, so only packets from this session are shown.')
        if not packets:
            lines.append('  (none)')
        for r in packets:
            ports = f'{r["src_port"] or ""} -> {r["dst_port"] or ""}'
            dropped = ' DROP' if r.get('dropped') else ''
            lines.append(f'  {r["timestamp"]}  {r["protocol"]:<6} {r["src_ip"]} -> {r["dst_ip"]}  '
                         f'ports {ports}  len {r["length"]}  flags {r["flags"] or "-"}{dropped}')
        self.alert_detail.setPlainText('\n'.join(lines))

    def refresh_rules(self):
        rows = self.store.rules()
        self.rule_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            enabled = QTableWidgetItem()
            enabled.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            enabled.setCheckState(Qt.CheckState.Checked if r['enabled'] else Qt.CheckState.Unchecked)
            self.rule_table.setItem(i, 0, enabled)
            self.rule_table.setItem(i, 1, cell(r['id']))
            self.rule_table.setItem(i, 2, cell(r['severity'], editable=True))
            self.rule_table.setItem(i, 3, cell(r['threshold'], editable=True))
            self.rule_table.setItem(i, 4, cell(r['window'], editable=True))
            self.rule_table.setItem(i, 5, cell(r['description']))
        fit_columns(self.rule_table)

    def refresh_trusted(self):
        self.trusted_list.clear()
        for r in self.store.trusted_rows():
            self.trusted_list.addItem(list_item(f"{r['ip']}  -  {r['reason']}", r['ip']))

    def refresh_blocks(self):
        self._seen_blocks_version = self.store.blocks_version
        self.block_list.clear()
        for r in self.store.block_rows(GUI_BLOCK_ROWS):
            expires = (f" (expires {datetime.fromtimestamp(r['expires']).strftime('%H:%M:%S')})"
                       if r.get('expires') else '')
            text = f"{r['ip']}  -  {r['reason']} [{r.get('source') or 'manual'}]{expires}"
            self.block_list.addItem(list_item(text, r['ip']))

    # -- actions ---------------------------------------------------------------
    def save_rules(self):
        rows = self.store.rules()
        try:
            # Validate every row before saving any of them.
            for i, r in enumerate(rows):
                t = self.rule_table
                severity = cell_text(t, i, 2).strip().upper()
                if severity not in SEVERITIES:
                    raise ValueError(f'{r["id"]}: severity must be one of {", ".join(SEVERITIES)}')
                r['severity'] = severity
                r['enabled'] = int(cell_checked(t, i, 0))
                r['threshold'] = max(1, int(cell_text(t, i, 3)))
                r['window'] = max(1, int(cell_text(t, i, 4)))
        except ValueError as exc:
            QMessageBox.warning(self, 'Rules', f'Invalid value - {exc}')
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
            QMessageBox.warning(self, 'Refused', "That range includes this machine's own address; blocking it "
                                                 'would cut you off.')
            return False
        if self.store.overlaps_trusted(net):
            QMessageBox.warning(self, 'Trusted range', 'That target overlaps a trusted address.')
            return False
        if not self.store.block(str(net), reason or 'Manual block', source='manual'):
            QMessageBox.warning(self, 'Refused', 'The block was rejected because it would affect a protected '
                                                 'local address.')
            return False
        self.refresh_blocks()
        return True

    def add_block(self):
        if self.block_target(self.block_ip.text(), self.block_reason.text().strip()):
            self.block_ip.clear()
            self.block_reason.clear()

    def remove_block(self):
        item = self.block_list.currentItem()
        if item:
            self.store.unblock(item.data(Qt.ItemDataRole.UserRole))
            self.refresh_blocks()

    def add_trusted(self):
        text = self.trust_ip.text().strip()
        try:
            net = normalize_network(text)
        except ValueError:
            QMessageBox.warning(self, 'Invalid address', 'Enter a valid IP or CIDR range.')
            return
        if blocks_self(net):
            QMessageBox.information(self, 'Trusted local address',
                                    'This address is already protected as a local address.')
        self.store.trust(str(net), self.trust_reason.text().strip() or 'Trusted host')
        self.trust_ip.clear()
        self.trust_reason.clear()
        self.refresh_trusted()

    def remove_trusted(self):
        item = self.trusted_list.currentItem()
        if item:
            self.store.untrust(item.data(Qt.ItemDataRole.UserRole))
            self.refresh_trusted()

    def alert_menu(self, pos):
        row = self.alert_table.rowAt(pos.y())
        if row < 0:
            return
        t = self.alert_table
        try:
            alert_id = int(cell_text(t, row, 0))
        except ValueError:
            return
        target = cell_text(t, row, 7).strip() or cell_text(t, row, 5)
        menu = QMenu(self)
        ack = menu.addAction('Acknowledge')
        close = menu.addAction('Close')
        block = menu.addAction(f'Block target {target}')
        viewport = t.viewport()
        chosen = menu.exec(viewport.mapToGlobal(pos) if viewport is not None else pos)
        if chosen == ack:
            self.store.set_alert_status(alert_id, 'ACK')
        elif chosen == close:
            self.store.set_alert_status(alert_id, 'CLOSED')
        elif chosen == block:
            self.block_target(target, f'Blocked from alert #{alert_id}')
        self.refresh_alerts()

    def compact_database(self):
        ok = self.store.compact()
        self.status('Database compacted.' if ok else 'Database compaction did not finish.')

    def import_blocklist(self):
        if self.import_worker and self.import_worker.isRunning():
            self.status('A blocklist import is already running.')
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import blocklist', '', 'Text files (*.txt *.csv);;All files (*)')
        if not path:
            return
        self.import_worker = BlocklistImportWorker(self.store, path)
        self.import_worker.result.connect(self.on_blocklist_imported)
        self.import_worker.failed.connect(lambda msg: self.error(f'Blocklist import failed: {msg}'))
        self.import_worker.finished.connect(self.on_import_finished)
        self.status(f'Importing blocklist in background: {Path(path).name}')
        self.import_worker.start()

    def on_import_finished(self):
        if self._release_sender() is self.import_worker:
            self.import_worker = None

    def on_blocklist_imported(self, added, skipped, name):
        self.refresh_blocks()
        self.log(f'Imported {added} entries from {name}; skipped {skipped}.')
        self.status(f'Blocklist import complete: {added} added, {skipped} skipped.')

    # -- signatures ------------------------------------------------------------
    def _signature_paths(self) -> list[str]:
        return [self.sig_list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.sig_list.count())]

    def _add_signature_paths(self, paths):
        current = self._signature_paths()
        for path in paths:
            if path and path not in current:
                self.sig_list.addItem(list_item(path, path))
                current.append(path)
        self.settings.set('sig_paths', current)
        self.load_signatures()

    def add_signature_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, 'Add Snort/Suricata rules', '',
            'Rule files and archives (*.rules *.tar.gz *.tgz *.tar *.zip);;All files (*)')
        if paths:
            self._add_signature_paths(paths)

    def add_signature_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Add a folder of .rules files')
        if path:
            self._add_signature_paths([path])

    def remove_signature_paths(self):
        for item in self.sig_list.selectedItems():
            self.sig_list.takeItem(self.sig_list.row(item))
        self.settings.set('sig_paths', self._signature_paths())
        self.load_signatures()

    def load_signatures(self) -> bool:
        """Parse the rule sources in the background. Returns True if loading started."""
        if self.sig_worker and self.sig_worker.isRunning():
            self._sig_reload_pending = True         # reload with the new choices once this load finishes
            self.sig_status.setText('Rules are loading; your change will be applied as soon as they finish.')
            return True
        home_net = self.sig_home_net.text().strip()
        error = validate_home_net(home_net)
        if error:
            QMessageBox.warning(self, 'Signatures', error)
            return False
        self.settings.set('sig_home_net', home_net)
        from .signatures import STARTER_RULES
        paths = ([str(STARTER_RULES)] if self.sig_builtin.isChecked() and STARTER_RULES.is_file() else []) \
            + ([str(self.my_rules.path)] if self.my_rules.path.is_file() else []) + self._signature_paths()
        if not paths:
            self.detector.set_signatures(None)
            self._show_signature_report(None)
            self.rule_browser.set_rules(None, set(), self.detector.sig_hits)
            return False
        self.sig_status.setText(f'Loading rules from {len(paths)} source(s)...')
        self.sig_load_btn.setEnabled(False)
        self.sig_worker = SignatureLoadWorker(paths, home_net)
        self.sig_worker.result.connect(self.on_signatures_loaded)
        self.sig_worker.failed.connect(lambda msg: self.error(f'Loading signature rules failed: {msg}'))
        self.sig_worker.finished.connect(self.on_signature_worker_finished)
        self.sig_worker.start()
        return True

    def on_signatures_loaded(self, rule_set, report):
        self.detector.set_signatures(rule_set)
        self._show_signature_report(report)
        off = self._apply_rule_switches()
        self.log(report.summary() + f' {len(rule_set.rules) - off:,} rule(s) active at the '
                 f'"{self.sig_level.currentText()}" level.')

    def _apply_rule_switches(self) -> int:
        """Combine the rule level with the user's own switches, apply it and refresh the browser."""
        from .signatures import effective_off, level_off
        rule_set = self.detector.signatures
        rules = rule_set.rules if rule_set is not None else []
        level = self.sig_level.currentData() or 'balanced'
        self._sig_level_off = level_off(rules, level)
        effective = effective_off(rules, level, self._sig_disabled, self._sig_enabled)
        off = rule_set.set_disabled(effective) if rule_set is not None else 0
        self.rule_browser.set_rules(rule_set, effective, self.detector.sig_hits)
        return off

    def _signature_switches_changed(self, keys, on: bool):
        """Rules switched on or off in the rule browser: remember the choice, which overrides the level."""
        keys = set(keys)
        if on:
            self._sig_disabled -= keys
            self._sig_enabled |= keys & self._sig_level_off      # only needed where the level turns them off
        else:
            self._sig_enabled -= keys
            self._sig_disabled |= keys
        rule_set = self.detector.signatures
        if rule_set is not None:
            rule_set.set_disabled(self.rule_browser.model.disabled)
        self.settings.set('sig_disabled', sorted(self._sig_disabled))
        self.settings.set('sig_enabled', sorted(self._sig_enabled))

    def _sig_level_changed(self, *_):
        self.settings.set('sig_level', self.sig_level.currentData() or 'balanced')
        if self.detector.signatures is not None:
            off = self._apply_rule_switches()
            self.status(f'Rule level "{self.sig_level.currentText()}": '
                        f'{len(self.detector.signatures.rules) - off:,} rule(s) active.')

    def _sig_builtin_changed(self, on: bool):
        self.settings.set('sig_builtin', bool(on))
        self.load_signatures()

    def set_up_signatures(self) -> bool:
        """One click: download ET Open, update it daily, Balanced level, starter rules on."""
        self.sig_level.setCurrentIndex(max(0, self.sig_level.findData('balanced')))
        if not self.sig_builtin.isChecked():
            self.sig_builtin.blockSignals(True)
            self.sig_builtin.setChecked(True)
            self.sig_builtin.blockSignals(False)
            self.settings.set('sig_builtin', True)
        self.et_auto.setChecked(True)
        return self.update_et_open()

    # -- ET Open download ------------------------------------------------------
    def update_et_open(self, automatic: bool = False, force: bool = False) -> bool:
        if self.et_worker is not None and self.et_worker.isRunning():
            return False
        self._et_attempt = time.time()
        self.et_btn.setEnabled(False)
        self.et_status.setText('Downloading ET Open...')
        worker = RuleDownloadWorker(self.settings.get('sig_et_url'), force=force)
        worker.result.connect(self.on_et_downloaded)
        worker.failed.connect(lambda msg: self._et_failed(msg, automatic))
        worker.shrunk.connect(lambda msg: self._et_shrunk(msg, automatic))
        worker.finished.connect(self.on_et_worker_finished)
        self.et_worker = worker
        worker.start()
        return True

    def on_et_downloaded(self, download):
        self.settings.set('sig_et_last', time.time())
        self._show_et_status()
        self.log(download.summary())
        if download.path not in self._signature_paths():
            self._add_signature_paths([download.path])       # also loads the rules
        elif download.changed or self.detector.signatures is None:
            self.load_signatures()

    def _et_failed(self, message: str, automatic: bool):
        self.et_status.setText(f'Download failed: {message}. The previous rules are kept.')
        (self.log if automatic else self.error)(f'ET Open download failed: {message}')

    def _et_shrunk(self, message: str, automatic: bool):
        """The new ET Open set is much smaller than the current one: keep the old rules unless the user agrees."""
        self.et_status.setText(f'Update not applied: {message}. Click "Update ET Open now" to review it.')
        self.log(f'ET Open update not applied: {message}')
        if automatic:
            return                  # never accept a large change without a person deciding
        answer = QMessageBox.question(
            self, 'Accept a much smaller rule set?',
            f'The downloaded ET Open rules look very different from the ones in use:\n\n{message}.\n\n'
            'This can happen when the publisher retires many rules, or when the download is broken. '
            'Accept the new rules anyway?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            self.log('Accepting the smaller ET Open rule set at your request.')
            if self.et_worker is not None and self.et_worker.isRunning():
                self._et_force_next = True          # started from on_et_worker_finished
            else:
                self.update_et_open(force=True)

    def on_et_worker_finished(self):
        self.et_btn.setEnabled(True)
        if self._release_sender() is self.et_worker:
            self.et_worker = None
        if self._et_force_next and not self._closing:
            self._et_force_next = False
            self.update_et_open(force=True)

    def _show_et_status(self):
        last = self.settings.get('sig_et_last')
        self.et_status.setText(f'ET Open last downloaded {datetime.fromtimestamp(last).strftime("%Y-%m-%d %H:%M")}.'
                               if last else 'ET Open not downloaded yet. Starter rules only.')
        self.et_btn.setText('Update ET Open now' if last else 'Set up automatically')

    def on_signature_worker_finished(self):
        self.sig_load_btn.setEnabled(True)
        if self._release_sender() is self.sig_worker:
            self.sig_worker = None
            if self._sig_reload_pending and not self._closing:
                self._sig_reload_pending = False
                self.load_signatures()

    def _show_signature_report(self, report):
        self.sig_reasons.setRowCount(0)
        self.sig_examples.setRowCount(0)
        if report is None:
            self.sig_status.setText('No signature rules loaded.')
            return
        enabled = any(r['id'] == 'SIG-001' and r['enabled'] for r in self.store.rules())
        self.sig_status.setText(report.summary() + f'\nHOME_NET = {report.home_net}'
                                + ('' if enabled else '\nSIG-001 is disabled, so these rules are not being matched.'))
        reasons = report.reasons.most_common()
        self.sig_reasons.setRowCount(len(reasons))
        for i, (reason, count) in enumerate(reasons):
            self.sig_reasons.setItem(i, 0, cell(f'{count:,}'))
            self.sig_reasons.setItem(i, 1, cell(reason))
        self.sig_examples.setRowCount(len(report.examples))
        for i, (source, line, reason, text) in enumerate(report.examples):
            for j, value in enumerate((Path(source).name, line, reason, text)):
                self.sig_examples.setItem(i, j, cell(value))
        fit_columns(self.sig_reasons)
        fit_columns(self.sig_examples)

    def _feed_url_list(self) -> list[str]:
        return list(dict.fromkeys(line.strip() for line in self.feed_urls.toPlainText().splitlines() if line.strip()))

    def save_feeds(self) -> bool:
        urls = self._feed_url_list()
        errors = [e for e in map(validate_feed_url, urls) if e]
        if errors:
            QMessageBox.warning(self, 'Blocklist feeds', '\n'.join(errors))
            return False
        self.settings.set('feed_urls', urls)
        self.feed_status.setText(f'Saved {len(urls)} feed(s).' if urls else 'No feeds configured.')
        return True

    def update_feeds(self, automatic=False, force_urls=()) -> bool:
        """Start a background feed download. Returns True if one was started.

        `force_urls`: feeds whose large change the user accepted (skips the change guard once)."""
        if self.feed_worker and self.feed_worker.isRunning():
            if not automatic:
                self.status('A feed update is already running.')
            return False
        if not automatic and not force_urls and not self.save_feeds():
            return False
        self._feed_manual = not automatic
        urls = self.settings.get('feed_urls')
        # With no URLs this still runs, so entries from feeds removed from the list are cleaned up.
        self.feed_status.setText(f'Downloading {len(urls)} feed(s)...' if urls
                                 else 'No feeds configured; removing entries from earlier feeds.')
        self.settings.set('feed_last_update', time.time())
        self.feed_worker = FeedUpdateWorker(self.store, urls, force_urls)
        self.feed_worker.result.connect(self.on_feeds_updated)
        self.feed_worker.failed.connect(lambda msg: self.error(f'Feed update failed: {msg}'))
        self.feed_worker.finished.connect(self.on_feed_worker_finished)
        self.feed_worker.start()
        return True

    def _feed_update_due(self) -> bool:
        s = self.settings
        return (s.get('feed_auto') and bool(s.get('feed_urls'))
                and time.time() - s.get('feed_last_update') >= s.get('feed_interval_hours') * 3600)

    def on_feeds_updated(self, results):
        self.refresh_blocks()
        for r in results:
            self.log(r.summary())
        failed = sum(1 for r in results if r.error)
        stored = sum(r.stored for r in results if not r.error)
        when = datetime.now().strftime('%Y-%m-%d %H:%M')
        self.feed_status.setText(f'Last update {when}: {stored:,} entries from {len(results) - failed} feed(s)'
                                 + (f'; {failed} failed (see console)' if failed else '') + '.')
        guarded = [r for r in results if r.guarded]
        if guarded and self._feed_manual:
            self._ask_accept_feed_change(guarded)

    def _ask_accept_feed_change(self, guarded) -> bool:
        """A manual update was refused by the change guard: let the user accept the change explicitly."""
        details = '\n\n'.join(f'{r.url}:\n{r.error}' for r in guarded[:5])
        answer = QMessageBox.question(
            self, 'Accept a large feed change?',
            f'{len(guarded)} feed(s) changed much more than usual, so the previous entries were kept:\n\n'
            f'{details}\n\nA broken or compromised feed can do this. Accept the new entries anyway?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return False
        urls = [r.url for r in guarded]
        self.log(f'Accepting the large change for {len(urls)} feed(s) at your request.')
        if self.feed_worker is not None and self.feed_worker.isRunning():
            self._feed_force_next = urls            # started from on_feed_worker_finished
        else:
            self.update_feeds(force_urls=urls)
        return True

    def on_feed_worker_finished(self):
        if self._release_sender() is self.feed_worker:
            self.feed_worker = None
        if self._feed_force_next and not self._closing:
            urls, self._feed_force_next = self._feed_force_next, []
            self.update_feeds(force_urls=urls)

    def export_alerts(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export alerts', 'netsentinel_alerts.json',
                                              'JSON (*.json);;CSV (*.csv)')
        if not path:
            return
        rows = self.store.alerts(5000, **self.alert_filters())
        if path.lower().endswith('.csv'):
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ['id'])
                writer.writeheader()
                writer.writerows(rows)
        else:
            Path(path).write_text(json.dumps(rows, indent=2), encoding='utf-8')
        self.log(f'Exported {len(rows)} alerts to {path}')

    # -- administrator rights ------------------------------------------------------
    def restart_as_admin(self) -> bool:
        """Open IDPS again with Administrator rights (Windows asks first), then close this window."""
        running = (self.worker is not None and self.worker.isRunning()) or (self.ips is not None and self.ips.isRunning())
        if running and QMessageBox.question(
                self, APP_NAME, 'Restarting stops the running capture or IPS. Restart as Administrator now?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return False
        # These can keep the window from closing, which would leave two copies of IDPS open on one database.
        busy = [name for name, w in (('the signature rules to finish loading', self.sig_worker),
                                     ('the ET Open download to finish', self.et_worker),
                                     ('the blocklist feed download to finish', self.feed_worker),
                                     ('the blocklist import to finish', self.import_worker),
                                     ('the self-test to finish', self.self_test_worker))
                if w is not None and w.isRunning()]
        if busy:
            message = f'Wait for {busy[0]}, then click "Restart as Administrator" again.'
            self.status(message)
            QMessageBox.information(self, APP_NAME, message)
            return False
        self.settings.save()                    # the new window starts with the same settings
        problem = relaunch_as_admin(owner=int(self.winId()))
        if problem:
            self.status(problem)
            QMessageBox.information(self, APP_NAME, problem)
            return False
        self.restart_admin_btn.setEnabled(False)            # never start a third copy
        self.log('Opening IDPS as Administrator; this window closes.')
        QTimer.singleShot(0, self.close)
        return True

    # -- shutdown ----------------------------------------------------------------
    def closeEvent(self, event):
        self._closing = True
        self.timer.stop()
        self._protection_stop.set()
        if self.self_test_worker is not None:
            self.self_test_worker.requestInterruption()
            if self.self_test_worker.wait(10000):
                try:
                    self.self_test_worker.disconnect()
                except (TypeError, RuntimeError):
                    pass
        if not self.wifi_tab.shutdown():
            self.status('Waiting for the Wi-Fi scan to finish before closing.')
            self._closing = False
            self.timer.start(1000)
            event.ignore()
            return
        ids_ok = self._halt(self.worker) if self.worker else True
        ips_ok = self._halt(self.ips) if self.ips else True
        if not (ids_ok and ips_ok):
            answer = QMessageBox.warning(self, APP_NAME,
                                         'A worker is still running. Waiting is safer than destroying a live QThread.',
                                         QMessageBox.StandardButton.Cancel | YES, QMessageBox.StandardButton.Cancel)
            if answer == YES:
                try:
                    self.store.close()   # flush what the writer can before the forced exit
                except Exception:
                    pass
                os._exit(2)
            self._closing = False
            self.timer.start(1000)
            event.ignore()
            return
        if self.import_worker and self.import_worker.isRunning():
            self.import_worker.requestInterruption()
            if not self.import_worker.wait(5000):
                self.status('Waiting for blocklist import to stop before closing.')
                self._closing = False
                self.timer.start(1000)
                event.ignore()
                return
        if self.sig_worker and self.sig_worker.isRunning():
            self.sig_worker.requestInterruption()
            if not self.sig_worker.wait(5000):
                self.status('Waiting for signature rules to finish loading before closing.')
                self._closing = False
                self.timer.start(1000)
                event.ignore()
                return
        if self.et_worker and self.et_worker.isRunning():
            self.et_worker.requestInterruption()            # the download checks this between chunks
            if not self.et_worker.wait(5000):
                self.status('Waiting for the ET Open download to stop before closing.')
                self._closing = False
                self.timer.start(1000)
                event.ignore()
                return
        if self.feed_worker and self.feed_worker.isRunning():
            self.feed_worker.requestInterruption()
            if not self.feed_worker.wait(5000):
                self.status('Waiting for the feed download to finish before closing.')
                self._closing = False
                self.timer.start(1000)
                event.ignore()
                return
        for thread in (self.import_worker, self.sig_worker, self.feed_worker, self.et_worker):
            # Results queued by a thread that just finished must not reach a closed window.
            if thread is not None:
                try:
                    thread.disconnect()
                except (TypeError, RuntimeError):
                    pass
        self.worker = self.ips = None
        self.notifier.close(timeout=2)
        if self.tray is not None:
            self.tray.hide()
        self.store.close()
        event.accept()
