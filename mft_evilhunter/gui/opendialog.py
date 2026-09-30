"""
Open dialog and the memory estimate shown before a large load.
"""

from __future__ import annotations

from pathlib import Path

from ..ioc import RuleSet
from .dataset import AnalysisOptions
from .qt import QtWidgets, Qt
from .timerange import TimeRangeFields
from .workers import LoadRequest


class OpenDialog(QtWidgets.QDialog):
    """$MFT, $LogFile and $UsnJrnl are all optional, at least one is required."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Open evidence")
        self.setMinimumWidth(560)

        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()

        self.mft_edit, mft_row = self._file_row("Select a raw $MFT file")
        form.addRow("$MFT:", mft_row)

        self.usn_edit, usn_row = self._file_row(
            "Optional: raw $Extend\\$UsnJrnl:$J stream"
        )
        form.addRow("$UsnJrnl ($J):", usn_row)

        self.log_edit, log_row = self._file_row("Optional: raw $LogFile")
        form.addRow("$LogFile:", log_row)
        layout.addLayout(form)

        hint = QtWidgets.QLabel(
            "<small>$LogFile covers hours to days; $J reaches back weeks and "
            "records why each change happened. Supplying both gives the widest "
            "view of deleted files.</small>"
        )
        hint.setWordWrap(True)
        hint.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(hint)

        options = QtWidgets.QGroupBox("Analysis")
        opt_layout = QtWidgets.QVBoxLayout(options)
        self.chk_timestomp = QtWidgets.QCheckBox("Timestomping analysis")
        self.chk_anomalies = QtWidgets.QCheckBox("Masquerading and naming anomalies")
        self.chk_timeline = QtWidgets.QCheckBox("Build combined MACB timeline")
        self.chk_carve = QtWidgets.QCheckBox(
            "$LogFile: carve for $FILE_NAME structures missed by opcode decoding"
        )
        for box in (self.chk_timestomp, self.chk_anomalies,
                    self.chk_timeline, self.chk_carve):
            box.setChecked(True)
            opt_layout.addWidget(box)
        layout.addWidget(options)

        self.window_fields = TimeRangeFields()
        layout.addWidget(self.window_fields)
        window_hint = QtWidgets.QLabel(
            "<small>With a window set, only rows with a timestamp inside it are "
            "kept. Paths are still reconstructed from the whole $MFT.</small>")
        window_hint.setWordWrap(True)
        window_hint.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(window_hint)

        rules_box = QtWidgets.QGroupBox("IOC rules")
        rules_layout = QtWidgets.QHBoxLayout(rules_box)
        self.rules_edit = QtWidgets.QLineEdit()
        self.rules_edit.setPlaceholderText("Built-in rule pack only (or add a .json pack or .txt IOC list)")
        browse = QtWidgets.QPushButton("Browse\u2026")
        browse.clicked.connect(self._pick_rules)
        rules_layout.addWidget(self.rules_edit, 1)
        rules_layout.addWidget(browse)
        layout.addWidget(rules_box)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Open
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_if_valid)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _file_row(self, placeholder: str):
        widget = QtWidgets.QWidget()
        row = QtWidgets.QHBoxLayout(widget)
        row.setContentsMargins(0, 0, 0, 0)
        edit = QtWidgets.QLineEdit()
        edit.setPlaceholderText(placeholder)
        button = QtWidgets.QPushButton("Browse\u2026")
        button.clicked.connect(lambda: self._pick_file(edit))
        row.addWidget(edit, 1)
        row.addWidget(button)
        return edit, widget

    def _pick_file(self, edit: QtWidgets.QLineEdit) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file")
        if path:
            edit.setText(path)

    def _pick_rules(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select rule pack or IOC list", "",
            "Rule packs and IOC lists (*.json *.txt);;All files (*)"
        )
        if path:
            self.rules_edit.setText(path)

    def _accept_if_valid(self) -> None:
        if not any((self.mft_edit.text(), self.log_edit.text(), self.usn_edit.text())):
            QtWidgets.QMessageBox.warning(
                self, "Nothing to open",
                "Select at least one of $MFT, $LogFile or $UsnJrnl."
            )
            return
        lower, upper = self.window_fields.bounds()
        if lower and upper and lower > upper:
            QtWidgets.QMessageBox.warning(
                self, "Attack window", "The window starts after it ends.")
            return
        self.accept()

    def request(self) -> LoadRequest:
        rules = RuleSet.builtin()
        if self.rules_edit.text():
            rules = rules.extend(RuleSet.load_custom(Path(self.rules_edit.text())))
        return LoadRequest(
            mft_path=Path(self.mft_edit.text()) if self.mft_edit.text() else None,
            logfile_path=Path(self.log_edit.text()) if self.log_edit.text() else None,
            usnjrnl_path=Path(self.usn_edit.text()) if self.usn_edit.text() else None,
            carve=self.chk_carve.isChecked(),
            options=AnalysisOptions(
                timestomping=self.chk_timestomp.isChecked(),
                anomalies=self.chk_anomalies.isChecked(),
                timeline=self.chk_timeline.isChecked(),
                window_start=self.window_fields.bounds()[0],
                window_end=self.window_fields.bounds()[1],
            ),
            rules=rules,
        )


# Measured on some tests: about 2.7 KB per $MFT record for the parsed entries
# and about twice that once every tab is built. The timeline expands each record
# into up to eight rows, so it is the tab offered for dropping first.
BYTES_PER_RECORD = 2_700
TIMELINE_MULTIPLIER = 3.0
LARGE_VOLUME_RECORDS = 400_000


def estimate_records(mft_path, record_size: int = 1024) -> int:
    try:
        return mft_path.stat().st_size // max(record_size, 512)
    except OSError:
        return 0


def estimate_memory_gb(records: int, timeline: bool) -> float:
    grams = records * BYTES_PER_RECORD * 2.0
    if timeline:
        grams *= TIMELINE_MULTIPLIER
    return grams / (1024 ** 3)
