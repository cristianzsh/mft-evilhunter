"""
Qt table model.
"""

from __future__ import annotations

import math

import re
from typing import List, Optional, Sequence, Set

from .dataset import SEVERITY_ORDER, Dataset
from .qt import (
    DisplayRole,
    ForegroundRole,
    Horizontal,
    QtCore,
    QtGui,
    Qt,
    ToolTipRole,
)

SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#d35400",
    "medium": "#b7950b",
    "low": "#1f6f8b",
    "info": "#7f8c8d",
}

SORT_BY = {"lifetime": "seconds"}


def _sort_key(value: str):
    """Numbers sort numerically, everything else case-insensitively."""
    if value == "":
        return (2, "")
    try:
        number = float(value)
    except ValueError:
        return (1, value.lower())

    if not math.isfinite(number) or "_" in value:
        return (1, value.lower())
    return (0, number)


class ArtifactTableModel(QtCore.QAbstractTableModel):
    def __init__(self, dataset: Dataset, parent=None):
        super().__init__(parent)
        self.dataset = dataset
        self._visible: List[int] = list(range(len(dataset.rows)))
        self._hunt: Optional[Set[int]] = None
        self._hunt_title: str = ""
        self._query: str = ""
        self._column: int = -1
        self._case_sensitive = False
        self._regex = False
        self._regex_error = ""
        self._sort_column = -1
        self._sort_desc = False
        self._severity_col = (dataset.col("severity")
                              if dataset.has("severity") else -1)

    # Qt plumbing

    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._visible)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.dataset.columns)

    def headerData(self, section, orientation, role=DisplayRole):
        if role != DisplayRole:
            return None
        if orientation == Horizontal:
            return self.dataset.columns[section]
        return str(self._visible[section]) if section < len(self._visible) else ""

    def data(self, index, role=DisplayRole):
        if not index.isValid():
            return None
        row = self.dataset.rows[self._visible[index.row()]]

        if role in (DisplayRole, ToolTipRole):
            value = row[index.column()]
            if role == ToolTipRole and len(value) < 40:
                return None
            return value

        if role == ForegroundRole and self._severity_col >= 0:
            colour = SEVERITY_COLORS.get(row[self._severity_col])
            if colour:
                return QtGui.QBrush(QtGui.QColor(colour))

        return None

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        if column < 0:
            self._sort_column, self._sort_desc = -1, False
            self._refilter()
            return
        self.layoutAboutToBeChanged.emit()
        desc = order == Qt.SortOrder.DescendingOrder
        rows = self.dataset.rows
        name = self.dataset.columns[column]
        if name in SORT_BY and SORT_BY[name] in self.dataset.columns:
            column = self.dataset.columns.index(SORT_BY[name])
        if name == "severity":
            self._visible.sort(
                key=lambda i: SEVERITY_ORDER.get(rows[i][column], 0), reverse=desc
            )
        else:
            self._visible.sort(key=lambda i: _sort_key(rows[i][column]), reverse=desc)
        self._sort_column, self._sort_desc = column, desc
        self.layoutChanged.emit()

    # filtering

    @property
    def regex_error(self) -> str:
        return self._regex_error

    @property
    def hunt_title(self) -> str:
        return self._hunt_title

    def set_hunt(self, indices: Optional[Sequence[int]], title: str = "") -> None:
        self._hunt = set(indices) if indices is not None else None
        self._hunt_title = title
        self._refilter()

    def set_query(self, query: str, column: int, case_sensitive: bool,
                  regex: bool) -> None:
        self._query = query
        self._column = column
        self._case_sensitive = case_sensitive
        self._regex = regex
        self._refilter()

    def clear_filters(self) -> None:
        self._hunt = None
        self._hunt_title = ""
        self._query = ""
        self._column = -1
        self._refilter()

    def _matcher(self):
        """Return a predicate over cell text, or None to accept everything."""
        self._regex_error = ""
        query = self._query
        if not query:
            return None

        if self._regex:
            try:
                flags = 0 if self._case_sensitive else re.IGNORECASE
                pattern = re.compile(query, flags)
            except (re.error, OverflowError, RecursionError) as exc:
                self._regex_error = str(exc) or type(exc).__name__
                return None
            return lambda value: pattern.search(value) is not None

        if self._case_sensitive:
            return lambda value: query in value
        needle = query.lower()
        return lambda value: needle in value.lower()

    def _refilter(self) -> None:
        rows = self.dataset.rows
        candidates = (sorted(self._hunt) if self._hunt is not None
                      else range(len(rows)))
        matcher = self._matcher()

        self.beginResetModel()
        try:
            if matcher is None:
                self._visible = list(candidates)
            elif self._column >= 0:
                col = self._column
                self._visible = [i for i in candidates if matcher(rows[i][col])]
            else:
                self._visible = [i for i in candidates if any(matcher(v) for v in rows[i])]
        finally:
            self.endResetModel()

        if self._sort_column >= 0:
            order = (Qt.SortOrder.DescendingOrder if self._sort_desc
                     else Qt.SortOrder.AscendingOrder)
            self.sort(self._sort_column, order)

    # access

    def source_index(self, view_row: int) -> int:
        return self._visible[view_row]

    def row_tuple(self, view_row: int):
        return self.dataset.rows[self._visible[view_row]]

    def row_mapping(self, view_row: int) -> dict:
        return dict(zip(self.dataset.columns, self.row_tuple(view_row)))

    def visible_rows(self):
        for i in self._visible:
            yield self.dataset.rows[i]

    @property
    def visible_count(self) -> int:
        return len(self._visible)

    @property
    def total_count(self) -> int:
        return len(self.dataset.rows)
