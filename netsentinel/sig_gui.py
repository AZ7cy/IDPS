"""Rule browser for loaded Snort/Suricata rules: search, switch rules on and off, see hit counts."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable, Optional

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                             QPushButton, QTableView, QVBoxLayout, QWidget)

from .signatures import RuleSet, rule_key

COLUMNS = ('On', 'SID', 'Message', 'Category', 'Severity', 'Action', 'Protocol', 'Hits', 'File')
ON, SID, MSG, CATEGORY, SEVERITY, ACTION, PROTO, HITS, FILE = range(len(COLUMNS))
ALL_CATEGORIES = ''
UNCLASSIFIED = 'unclassified'


class RuleModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.rows: list[tuple] = []         # (key, sid, msg, category, severity, action, proto, file)
        self.disabled: set[str] = set()
        self.hits: Counter = Counter()
        self.on_toggle: Callable[[list[str], bool], None] = lambda keys, on: None

    def load(self, rule_set: Optional[RuleSet], disabled: set, hits: Counter):
        self.beginResetModel()
        self.rows = [(rule_key(s), s.sid, s.msg, s.classtype or UNCLASSIFIED, s.severity, s.action, s.proto,
                      Path(s.source).name if s.source else '') for s in (rule_set.rules if rule_set else [])]
        self.disabled, self.hits = disabled, hits
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def flags(self, index):
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        return base | Qt.ItemFlag.ItemIsUserCheckable if index.column() == ON else base

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        key, sid, msg, category, severity, action, proto, file = self.rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.CheckStateRole and col == ON:
            return Qt.CheckState.Unchecked if key in self.disabled else Qt.CheckState.Checked
        if role == Qt.ItemDataRole.ForegroundRole:
            if key in self.disabled:
                return QColor('#64748b')
            if col == SEVERITY and severity == 'HIGH':
                return QColor('#ff8a65')
            if col == HITS and self.hits.get(key):
                return QColor('#fbbf24')
        if role == Qt.ItemDataRole.UserRole:        # sort keys
            return {SID: sid, HITS: self.hits.get(key, 0), ON: key not in self.disabled}.get(col)
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        return {SID: sid, MSG: msg, CATEGORY: category, SEVERITY: severity, ACTION: action, PROTO: proto,
                HITS: self.hits.get(key, 0) or '', FILE: file}.get(col, '')

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if role != Qt.ItemDataRole.CheckStateRole or index.column() != ON:
            return False
        on = value in (Qt.CheckState.Checked, Qt.CheckState.Checked.value)     # enum or int, by Qt version
        self.on_toggle([self.rows[index.row()][0]], on)
        return True

    def refresh(self, column: Optional[int] = None):
        if not self.rows:
            return
        left = self.index(0, column if column is not None else 0)
        right = self.index(len(self.rows) - 1, column if column is not None else len(COLUMNS) - 1)
        self.dataChanged.emit(left, right)


class RuleFilter(QSortFilterProxyModel):
    def __init__(self, model: RuleModel):
        super().__init__()
        self.setSourceModel(model)
        self.model_ = model
        self.text = ''
        self.category = ALL_CATEGORIES
        self.only = ''              # '', 'on', 'off' or 'hit'
        self.setSortRole(Qt.ItemDataRole.DisplayRole)

    def set_filter(self, text: str, category: str, only: str):
        self.text, self.category, self.only = text.strip().lower(), category, only
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        key, sid, msg, category, severity, action, proto, file = self.model_.rows[row]
        if self.category and category != self.category:
            return False
        if self.only == 'on' and key in self.model_.disabled:
            return False
        if self.only == 'off' and key not in self.model_.disabled:
            return False
        if self.only == 'hit' and not self.model_.hits.get(key):
            return False
        t = self.text
        return not t or t in msg.lower() or t == str(sid) or t in key or t in category or t in file.lower()

    def lessThan(self, left, right):
        a = self.model_.data(left, Qt.ItemDataRole.UserRole)
        b = self.model_.data(right, Qt.ItemDataRole.UserRole)
        if a is not None and b is not None:
            return a < b
        return str(self.model_.data(left)).lower() < str(self.model_.data(right)).lower()


class RuleBrowser(QWidget):
    """Table of loaded rules. `on_change(keys, on)` is called after rules are switched on or off."""

    def __init__(self, on_change: Callable[[set, bool], None]):
        super().__init__()
        self.on_change = on_change
        self.model = RuleModel()
        self.model.on_toggle = self.set_enabled
        self.proxy = RuleFilter(self.model)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText('Search message, SID, gid:sid, category or file')
        self.search.textChanged.connect(self._filter)
        self.category = QComboBox()
        self.category.setMinimumWidth(200)
        self.category.currentIndexChanged.connect(self._filter)
        self.only = QComboBox()
        for label, key in (('All rules', ''), ('Enabled', 'on'), ('Disabled', 'off'), ('Fired this session', 'hit')):
            self.only.addItem(label, key)
        self.only.currentIndexChanged.connect(self._filter)
        row.addWidget(self.search, 2)
        row.addWidget(self.category, 1)
        row.addWidget(self.only)
        layout.addLayout(row)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(SID, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        vertical = self.table.verticalHeader()
        if vertical is not None:
            vertical.setVisible(False)
            vertical.setDefaultSectionSize(26)
        header = self.table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            header.setStretchLastSection(True)
            for col, width in ((ON, 40), (SID, 80), (MSG, 430), (CATEGORY, 170), (SEVERITY, 70), (ACTION, 60),
                               (PROTO, 60), (HITS, 55)):
                header.resizeSection(col, width)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        buttons = []
        for label, slot in (('Enable selected', lambda: self._selected(True)),
                            ('Disable selected', lambda: self._selected(False)),
                            ('Enable shown', lambda: self._shown(True)),
                            ('Disable shown', lambda: self._shown(False))):
            b = QPushButton(label)
            b.setObjectName('secondary')
            b.clicked.connect(slot)
            row.addWidget(b)
            buttons.append(b)
        row.addStretch(1)
        self.summary = QLabel('No rules loaded.')
        self.summary.setObjectName('note')
        row.addWidget(self.summary)
        layout.addLayout(row)

    # -- data ----------------------------------------------------------------------
    def set_rules(self, rule_set: Optional[RuleSet], disabled: set, hits: Counter):
        self.model.load(rule_set, disabled, hits)
        categories = Counter(r[3] for r in self.model.rows)
        current = self.category.currentData()
        self.category.blockSignals(True)
        self.category.clear()
        self.category.addItem(f'All categories ({len(self.model.rows):,})', ALL_CATEGORIES)
        for name, count in sorted(categories.items()):
            self.category.addItem(f'{name} ({count:,})', name)
        self.category.setCurrentIndex(max(0, self.category.findData(current)))
        self.category.blockSignals(False)
        self._filter()

    def refresh_hits(self):
        self.model.refresh(HITS)
        if self.only.currentData() == 'hit':
            self.proxy.invalidateFilter()
        self._update_summary()

    def _filter(self, *_):
        self.proxy.set_filter(self.search.text(), self.category.currentData() or ALL_CATEGORIES,
                              self.only.currentData() or '')
        self._update_summary()

    def _update_summary(self):
        total = len(self.model.rows)
        loaded = {r[0] for r in self.model.rows}
        off = len(self.model.disabled & loaded)
        fired = sum(1 for k in loaded if self.model.hits.get(k))
        self.summary.setText(f'{total:,} rules, {total - off:,} on, {off:,} off, {fired:,} fired; '
                             f'showing {self.proxy.rowCount():,}' if total else 'No rules loaded.')

    # -- switching -------------------------------------------------------------------
    def set_enabled(self, keys, on: bool):
        disabled = self.model.disabled
        if on:
            disabled.difference_update(keys)
        else:
            disabled.update(keys)
        self.model.refresh()
        if self.only.currentData() in ('on', 'off'):
            self.proxy.invalidateFilter()
        self._update_summary()
        self.on_change(set(keys), on)

    def _selected(self, on: bool):
        rows = {self.proxy.mapToSource(i).row() for i in self.table.selectionModel().selectedRows()}
        if rows:
            self.set_enabled([self.model.rows[r][0] for r in rows], on)

    def _shown(self, on: bool):
        keys = [self.model.rows[self.proxy.mapToSource(self.proxy.index(i, 0)).row()][0]
                for i in range(self.proxy.rowCount())]
        if keys:
            self.set_enabled(keys, on)


class MyRulesEditor(QWidget):
    """Write rules from a template or by hand, check them, and keep them in local.rules.

    `on_changed()` is called after a rule is added or deleted, so the window can reload the rules.
    """

    def __init__(self, on_changed: Callable[[], None], status: Callable[[str], None], path=None):
        super().__init__()
        from .local_rules import LOCAL_RULES, SEVERITIES, TEMPLATES
        self.path = Path(path) if path else LOCAL_RULES
        self.on_changed = on_changed
        self.status = status
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 6, 0, 0)
        intro = QLabel('Pick what to watch for, fill in the value and click "Make rule", or write a rule yourself. '
                       '"Add rule" checks it and saves it to your own rule file, which loads with the others and '
                       'is always on.')
        intro.setObjectName('note')
        intro.setWordWrap(True)
        layout.addWidget(intro)
        row = QHBoxLayout()
        self.template = QComboBox()
        for t in TEMPLATES:
            self.template.addItem(t.label, t.key)
        self.template.currentIndexChanged.connect(self._template_changed)
        self.value = QLineEdit()
        self.value.returnPressed.connect(self.make_rule)
        self.severity = QComboBox()
        for name, _prio in SEVERITIES:
            self.severity.addItem(name, name)
        self.severity.setCurrentIndex(1)
        self.message = QLineEdit()
        self.message.setPlaceholderText('Alert message (optional)')
        make = QPushButton('Make rule')
        make.setObjectName('secondary')
        make.clicked.connect(self.make_rule)
        for w, stretch in ((self.template, 2), (self.value, 2), (self.severity, 0), (self.message, 2), (make, 0)):
            row.addWidget(w, stretch)
        layout.addLayout(row)
        from PyQt6.QtWidgets import QPlainTextEdit
        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText('alert tcp any any -> any any (msg:"My rule"; content:"text"; sid:1000001; '
                                       'rev:1;)')
        self.editor.setMaximumHeight(70)
        self.editor.textChanged.connect(lambda: self.result.setText(''))
        layout.addWidget(self.editor)
        row = QHBoxLayout()
        check = QPushButton('Check rule')
        check.setObjectName('secondary')
        check.clicked.connect(self.check)
        self.add_btn = QPushButton('Add rule')
        self.add_btn.clicked.connect(self.add)
        self.result = QLabel('')
        self.result.setWordWrap(True)
        row.addWidget(check)
        row.addWidget(self.add_btn)
        row.addWidget(self.result, 1)
        layout.addLayout(row)
        from .gui import make_table
        self.table = make_table(['SID', 'Message', 'Rule'])
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        delete = QPushButton('Delete selected')
        delete.setObjectName('secondary')
        delete.clicked.connect(self.delete_selected)
        open_file = QPushButton('Show rule file')
        open_file.setObjectName('secondary')
        open_file.setToolTip('Open the folder with local.rules, for editing or sharing it.')
        open_file.clicked.connect(self.show_file)
        row.addWidget(delete)
        row.addWidget(open_file)
        row.addStretch(1)
        self.count = QLabel('')
        self.count.setObjectName('note')
        row.addWidget(self.count)
        layout.addLayout(row)
        self._template_changed()
        self.refresh()

    # -- building ----------------------------------------------------------------
    def _template_changed(self, *_):
        from .local_rules import TEMPLATE_BY_KEY
        t = TEMPLATE_BY_KEY[self.template.currentData()]
        self.value.setEnabled(t.key != 'custom')
        self.value.setPlaceholderText(f'{t.value_label}, for example {t.example}' if t.example else '')
        if t.key == 'custom':
            self.make_rule()

    def make_rule(self) -> bool:
        from .local_rules import RuleInputError, build_rule, next_sid
        try:
            text = build_rule(self.template.currentData(), self.value.text(), self.severity.currentData(),
                              self.message.text(), sid=next_sid(self.path))
        except RuleInputError as exc:
            self._show(str(exc), ok=False)
            return False
        self.editor.setPlainText(text)
        self._show('Rule ready. Edit it if you like, then click "Add rule".', ok=True)
        return True

    # -- checking and saving -------------------------------------------------------
    def _show(self, text: str, ok: bool):
        self.result.setStyleSheet(f'color: {"#86efac" if ok else "#fca5a5"}')
        self.result.setText(text)

    def check(self) -> bool:
        from .local_rules import check_rule
        error = check_rule(self.editor.toPlainText())
        self._show(error or 'The rule is valid and NetSentinel can load it.', ok=not error)
        return not error

    def add(self) -> bool:
        from .local_rules import RuleInputError, add_rule
        try:
            sid = add_rule(self.editor.toPlainText(), self.path)
        except RuleInputError as exc:
            self._show(str(exc), ok=False)
            return False
        except OSError as exc:
            self._show(f'Could not save the rule: {exc}', ok=False)
            return False
        self._show(f'Added rule {sid}. It is active as soon as the rules reload.', ok=True)
        self.editor.clear()
        self.value.clear()
        self.message.clear()
        self.refresh()
        self.status(f'Added your rule {sid} to {self.path.name}.')
        self.on_changed()
        return True

    def refresh(self):
        from .gui import cell, fit_columns
        from .local_rules import read_rules, rule_message, rule_sid
        rules = read_rules(self.path)
        self.table.setRowCount(len(rules))
        for i, text in enumerate(rules):
            for j, value in enumerate((rule_sid(text) or '', rule_message(text), text)):
                self.table.setItem(i, j, cell(value))
        fit_columns(self.table)
        header = self.table.horizontalHeader()
        if header is not None:          # sized before the tab is first shown, so set sensible minimums
            header.resizeSection(0, max(header.sectionSize(0), 80))
            header.resizeSection(1, max(header.sectionSize(1), 260))
        self.count.setText(f'{len(rules)} rule(s) in {self.path}' if rules else 'No rules of your own yet.')

    def delete_selected(self) -> int:
        from .local_rules import remove_rules
        sids = set()
        for item in self.table.selectedItems():
            sid_item = self.table.item(item.row(), 0)
            if sid_item is not None and sid_item.text().isdigit():
                sids.add(int(sid_item.text()))
        if not sids:
            return 0
        removed = remove_rules(sids, self.path)
        self.refresh()
        if removed:
            self.status(f'Deleted {removed} of your rule(s).')
            self.on_changed()
        return removed

    def show_file(self):
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QDesktopServices
        self.path.parent.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.path.parent)))
