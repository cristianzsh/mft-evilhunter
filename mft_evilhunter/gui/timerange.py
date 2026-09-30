"""
Attack window selection for the open dialog.
"""

from __future__ import annotations

import datetime
from typing import Optional, Tuple

from .qt import Qt, QtCore, QtWidgets

DISPLAY_FORMAT = "yyyy-MM-dd HH:mm:ss"


def iso_bounds(start: Optional[datetime.datetime], end: Optional[datetime.datetime]) -> Tuple[str, str]:
    """Convert a window to comparable ISO strings."""
    lower = start.replace(microsecond=0).isoformat() if start else ""
    upper = end.replace(microsecond=999999).isoformat() if end else ""
    return lower, upper


def to_datetime(value) -> datetime.datetime:
    """QDateTime to aware UTC datetime."""
    date, time = value.date(), value.time()
    return datetime.datetime(date.year(), date.month(), date.day(),
                             time.hour(), time.minute(), time.second(),
                             tzinfo=datetime.timezone.utc)


def to_qdatetime(value: datetime.datetime) -> "QtCore.QDateTime":
    return QtCore.QDateTime(QtCore.QDate(value.year, value.month, value.day),
                            QtCore.QTime(value.hour, value.minute, value.second),
                            QtCore.QTimeZone.utc())


class TimeRangeFields(QtWidgets.QGroupBox):
    """Optional attack window, off by default."""

    def __init__(self, parent=None):
        super().__init__("Attack window (UTC)", parent)
        self.setCheckable(True)
        self.setChecked(False)
        self.setToolTip("Keep only rows with at least one timestamp inside the window")

        layout = QtWidgets.QHBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel("From"))
        self.start = self._field()
        layout.addWidget(self.start, 1)
        layout.addWidget(QtWidgets.QLabel("to"))
        self.end = self._field()
        layout.addWidget(self.end, 1)

        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        self.start.setDateTime(to_qdatetime(now - datetime.timedelta(days=7)))
        self.end.setDateTime(to_qdatetime(now))

    def _field(self) -> "QtWidgets.QDateTimeEdit":
        field = QtWidgets.QDateTimeEdit()
        field.setDisplayFormat(DISPLAY_FORMAT)
        field.setCalendarPopup(True)

        if hasattr(field, "setTimeZone"):
            field.setTimeZone(QtCore.QTimeZone.utc())
        else:
            field.setTimeSpec(Qt.TimeSpec.UTC)
        return field

    def bounds(self) -> Tuple[str, str]:
        """ISO bounds, or two empty strings when the window is off."""
        if not self.isChecked():
            return "", ""
        return iso_bounds(to_datetime(self.start.dateTime()),
                          to_datetime(self.end.dateTime()))

    def set_window(self, start: datetime.datetime, end: datetime.datetime) -> None:
        self.setChecked(True)
        self.start.setDateTime(to_qdatetime(start))
        self.end.setDateTime(to_qdatetime(end))
