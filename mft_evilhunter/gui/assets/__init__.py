"""Bundled icon assets."""

import sys
from pathlib import Path


def asset_dir() -> Path:
    """Locate the assets directory."""
    here = Path(__file__).resolve().parent
    if here.is_dir() and (here / "icon.png").exists():
        return here
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidate = Path(base) / "mft_evilhunter" / "gui" / "assets"
        if candidate.exists():
            return candidate
        return Path(base)
    return here


def icon_path(name: str = "icon.png") -> Path:
    return asset_dir() / name
