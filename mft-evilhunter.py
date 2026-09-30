"""
MFT-EvilHunter: NTFS $MFT, $LogFile, and $UsnJrnl IOC hunting for DFIR.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _check_qt() -> None:
    for binding in ("PySide6", "PyQt6"):
        try:
            __import__(binding)
            return
        except ImportError:
            continue
    sys.exit(
        "MFT-EvilHunter needs a Qt binding.\n\n"
        "    pip install PySide6\n\n"
        "(PyQt6 works too)."
    )


def main() -> int:
    if "--version" in sys.argv:
        from mft_evilhunter import __version__
        print(f"MFT-EvilHunter {__version__}")
        return 0

    if "-h" in sys.argv or "--help" in sys.argv:
        print(__doc__.strip())
        return 0

    _check_qt()
    from mft_evilhunter.gui.app import main as run
    return run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
