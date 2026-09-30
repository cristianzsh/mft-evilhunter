"""
Qt binding shim.
"""

from __future__ import annotations

BINDING = ""

try:
    from PySide6 import QtCore, QtGui, QtWidgets  # type: ignore

    BINDING = "PySide6"
    Signal = QtCore.Signal
    Slot = QtCore.Slot
    Property = QtCore.Property
except ImportError as pyside_error: # pragma: no cover
    try:
        from PyQt6 import QtCore, QtGui, QtWidgets  # type: ignore

        BINDING = "PyQt6"
        Signal = QtCore.pyqtSignal
        Slot = QtCore.pyqtSlot
        Property = QtCore.pyqtProperty
    except ImportError as exc:
        raise SystemExit(
            "The GUI needs a Qt binding. Install one of:\n"
            "    pip install PySide6\n"
            "    pip install PyQt6\n"
            f"PySide6: {pyside_error}\n"
            f"PyQt6: {exc}"
        ) from exc


Qt = QtCore.Qt

# Frequently used enum members, pulled out so call sites stay readable.
DisplayRole = Qt.ItemDataRole.DisplayRole
ToolTipRole = Qt.ItemDataRole.ToolTipRole
ForegroundRole = Qt.ItemDataRole.ForegroundRole
BackgroundRole = Qt.ItemDataRole.BackgroundRole
UserRole = Qt.ItemDataRole.UserRole
TextAlignmentRole = Qt.ItemDataRole.TextAlignmentRole

Horizontal = Qt.Orientation.Horizontal
Vertical = Qt.Orientation.Vertical

AscendingOrder = Qt.SortOrder.AscendingOrder
DescendingOrder = Qt.SortOrder.DescendingOrder


def exec_(dialog):
    """exec() across bindings; PyQt6 dropped exec_()."""
    return dialog.exec()


__all__ = [
    "BINDING", "QtCore", "QtGui", "QtWidgets", "Qt", "Signal", "Slot", "Property",
    "DisplayRole", "ToolTipRole", "ForegroundRole", "BackgroundRole", "UserRole",
    "TextAlignmentRole", "Horizontal", "Vertical", "AscendingOrder",
    "DescendingOrder", "exec_",
]
