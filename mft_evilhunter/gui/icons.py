"""
Application icon loading.
"""

from __future__ import annotations

from typing import Optional

from .assets import icon_path
from .qt import QtCore, QtGui

_cache: Optional["QtGui.QIcon"] = None

ICON_SIZES = (16, 32, 48, 64, 128, 256)


def load_icon() -> "QtGui.QIcon":
    """Return the application icon with every bundled size registered."""
    global _cache
    if _cache is not None:
        return _cache

    icon = QtGui.QIcon()
    for size in ICON_SIZES:
        path = icon_path(f"icon-{size}.png")
        if path.exists():
            icon.addFile(str(path), QtCore.QSize(size, size))

    if icon.isNull():
        fallback = icon_path("icon.png")
        if fallback.exists():
            icon.addFile(str(fallback))

    _cache = icon
    return icon
