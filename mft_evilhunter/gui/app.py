"""
GUI entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .icons import load_icon
from .qt import QtWidgets


def main(argv=None) -> int:
    argv = list(sys.argv if argv is None else argv)

    app = QtWidgets.QApplication(argv[:1])
    app.setApplicationName("MFT-EvilHunter")
    app.setWindowIcon(load_icon())

    from .mainwindow import MainWindow

    window = MainWindow()
    window.show()

    paths = [Path(a) for a in argv[1:] if not a.startswith("-")]
    if paths:
        window.prefill_open_dialog(
            mft_path=paths[0] if len(paths) > 0 else None,
            usnjrnl_path=paths[1] if len(paths) > 1 else None,
            logfile_path=paths[2] if len(paths) > 2 else None,
        )

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
