"""
One tab per dataset: a table with its own search bar and filter state.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

from ..report import neutralize
from .dataset import Dataset
from .models import SEVERITY_COLORS, ArtifactTableModel
from .qt import QtCore, QtGui, QtWidgets, Qt

ALL_COLUMNS = "All columns"


class DetailPanel(QtWidgets.QWidget):
    """Vertical field list for the selected row."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        header = QtWidgets.QLabel("Record details")
        font = header.font()
        font.setBold(True)
        header.setFont(font)
        layout.addWidget(header)

        self.table = QtWidgets.QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Field", "Value"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self.table.setWordWrap(True)
        layout.addWidget(self.table)

    def show_row(self, mapping: dict) -> None:
        populated = [(k, v) for k, v in mapping.items() if v not in ("", None)]
        self.table.setRowCount(len(populated))
        for row, (key, value) in enumerate(populated):
            key_item = QtWidgets.QTableWidgetItem(key)
            key_item.setFont(QtGui.QFont("", -1, QtGui.QFont.Weight.Bold))
            self.table.setItem(row, 0, key_item)

            value_item = QtWidgets.QTableWidgetItem(str(value))
            if key == "severity":
                colour = SEVERITY_COLORS.get(str(value))
                if colour:
                    value_item.setForeground(QtGui.QBrush(QtGui.QColor(colour)))
            self.table.setItem(row, 1, value_item)
        self.table.resizeRowsToContents()

    def clear(self) -> None:
        self.table.setRowCount(0)


class ArtifactTab(QtWidgets.QWidget):

    def __init__(self, dataset: Dataset, parent=None):
        super().__init__(parent)
        self.dataset = dataset
        self.model = ArtifactTableModel(dataset, self)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        layout.addLayout(self._build_search_bar())

        splitter = QtWidgets.QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_table())
        self.detail = DetailPanel()
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([1000, 320])
        self.splitter = splitter
        layout.addWidget(splitter, 1)

        self.status = QtWidgets.QLabel()
        self.status.setContentsMargins(2, 0, 2, 0)
        layout.addWidget(self.status)

        self._debounce = QtCore.QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(180)
        self._debounce.timeout.connect(self._apply_search)

        self._update_status()

    # widgets

    def _build_search_bar(self) -> QtWidgets.QHBoxLayout:
        bar = QtWidgets.QHBoxLayout()

        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Search this tab\u2026")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.textChanged.connect(lambda _: self._debounce.start())
        bar.addWidget(self.search_box, 1)

        bar.addWidget(QtWidgets.QLabel("in"))
        self.column_combo = QtWidgets.QComboBox()
        self.column_combo.addItem(ALL_COLUMNS)
        self.column_combo.addItems(self.dataset.columns)
        self.column_combo.setMaxVisibleItems(30)
        self.column_combo.currentIndexChanged.connect(lambda _: self._apply_search())
        bar.addWidget(self.column_combo)

        self.case_toggle = QtWidgets.QToolButton()
        self.case_toggle.setText("Aa")
        self.case_toggle.setCheckable(True)
        self.case_toggle.setToolTip("Case sensitive")
        self.case_toggle.toggled.connect(lambda _: self._apply_search())
        bar.addWidget(self.case_toggle)

        self.regex_toggle = QtWidgets.QToolButton()
        self.regex_toggle.setText(".*")
        self.regex_toggle.setCheckable(True)
        self.regex_toggle.setToolTip("Regular expression")
        self.regex_toggle.toggled.connect(lambda _: self._apply_search())
        bar.addWidget(self.regex_toggle)

        clear = QtWidgets.QToolButton()
        clear.setText("Clear")
        clear.setToolTip("Clear the search and any active hunt")
        clear.clicked.connect(self.clear_all)
        bar.addWidget(clear)

        return bar

    def _build_table(self) -> QtWidgets.QTableView:
        view = QtWidgets.QTableView()
        view.setModel(self.model)
        view.setSortingEnabled(True)

        view.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        view.setAlternatingRowColors(True)
        view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        view.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        view.customContextMenuRequested.connect(self._context_menu)
        view.verticalHeader().setDefaultSectionSize(20)
        view.verticalHeader().setVisible(False)

        header = view.horizontalHeader()
        header.setSectionsMovable(True)
        header.setStretchLastSection(True)
        header.setDefaultSectionSize(130)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._header_menu)

        view.selectionModel().currentRowChanged.connect(self._on_row_selected)

        self.model.layoutChanged.connect(self._refresh_detail)
        self.model.modelReset.connect(self._refresh_detail)
        self.view = view
        return view

    def _refresh_detail(self) -> None:
        current = self.view.currentIndex()
        if current.isValid() and current.row() < self.model.rowCount():
            self.detail.show_row(self.model.row_mapping(current.row()))
        else:
            self.view.clearSelection()
            self.detail.clear()

    # behaviour

    def _apply_search(self) -> None:
        column = self.column_combo.currentIndex() - 1  # -1 == all columns
        self.model.set_query(
            self.search_box.text(), column,
            self.case_toggle.isChecked(), self.regex_toggle.isChecked(),
        )
        self._update_status()

    def _on_row_selected(self, current, _previous) -> None:
        if current.isValid():
            self.detail.show_row(self.model.row_mapping(current.row()))
        else:
            self.detail.clear()

    def apply_hunt(self, indices, title: str) -> int:
        self.model.set_hunt(indices, title)
        self._update_status()
        return self.model.visible_count

    def clear_hunt(self) -> None:
        self.model.set_hunt(None, "")
        self._update_status()

    def clear_all(self) -> None:
        self.search_box.clear()
        self.column_combo.setCurrentIndex(0)
        self.case_toggle.setChecked(False)
        self.regex_toggle.setChecked(False)
        self.model.clear_filters()
        self._update_status()

    def filter_by_value(self, column: int, value: str) -> None:
        """Exact match on one column, expressed as an anchored regex."""
        self.column_combo.setCurrentIndex(column + 1)
        self.regex_toggle.setChecked(True)
        self.case_toggle.setChecked(True)
        self.search_box.setText("^" + re.escape(value) + "$")
        self._apply_search()

    def _update_status(self) -> None:
        parts = [f"{self.model.visible_count:,} of {self.model.total_count:,} rows"]
        if self.model.hunt_title:
            parts.append(f"hunt: {self.model.hunt_title}")
        if self.model.regex_error:
            parts.append(f"invalid regex: {self.model.regex_error}")
        self.status.setText("   \u2022   ".join(parts))
        colour = "#c0392b" if self.model.regex_error else ""
        self.status.setStyleSheet(f"color: {colour};" if colour else "")

    # context menu

    def _context_menu(self, point) -> None:
        index = self.view.indexAt(point)
        if not index.isValid():
            return
        value = self.model.data(index) or ""
        column_name = self.dataset.columns[index.column()]

        menu = QtWidgets.QMenu(self)
        menu.addAction("Copy cell", lambda: self._copy(value))
        menu.addAction("Copy row(s) as CSV", lambda: self._copy_rows())
        if self.dataset.has("path"):
            menu.addAction(
                "Copy path",
                lambda: self._copy(self.model.row_mapping(index.row()).get("path", "")),
            )
        menu.addSeparator()
        if value:
            menu.addAction(
                f'Filter {column_name} = "{value[:40]}"',
                lambda: self.filter_by_value(index.column(), value),
            )
        menu.addAction("Clear filters", self.clear_all)
        menu.exec(self.view.viewport().mapToGlobal(point))

    def _header_menu(self, point) -> None:
        header = self.view.horizontalHeader()
        menu = QtWidgets.QMenu(self)
        menu.addAction("Resize columns to contents", self.view.resizeColumnsToContents)
        menu.addSeparator()
        hide_menu = menu.addMenu("Show columns")
        for i, name in enumerate(self.dataset.columns):
            action = hide_menu.addAction(name)
            action.setCheckable(True)
            action.setChecked(not header.isSectionHidden(i))
            action.toggled.connect(
                lambda checked, section=i: header.setSectionHidden(section, not checked)
            )
        menu.exec(header.mapToGlobal(point))

    def _copy(self, text: str) -> None:
        QtWidgets.QApplication.clipboard().setText(str(text))

    def _copy_rows(self) -> None:
        """Copy the selected rows as CSV, matching what export writes."""
        rows = sorted({i.row() for i in self.view.selectionModel().selectedIndexes()})
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(self.dataset.columns)
        for row in rows:
            writer.writerow([neutralize(v) for v in self.model.row_tuple(row)])
        self._copy(buffer.getvalue())

    # export

    def export_visible(self, path: Path) -> int:
        """Export exactly what is on screen, filters and hunt included."""
        with path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(self.dataset.columns)
            count = 0
            for row in self.model.visible_rows():
                writer.writerow([neutralize(v) for v in row])
                count += 1
        return count
