"""
Main window, menus, and the Hunt wiring.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set

from .. import __version__
from .dataset import Dataset
from .icons import load_icon
from . import hunts as hunts_module
from .qt import QtGui, QtWidgets, Qt
from .opendialog import (
    LARGE_VOLUME_RECORDS, OpenDialog, estimate_memory_gb, estimate_records,
)
from .tabs import ArtifactTab
from .workers import LoadWorker


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"MFT-EvilHunter {__version__}")
        self.setWindowIcon(load_icon())
        self.resize(1500, 860)

        self.tabs: Dict[str, ArtifactTab] = {}
        self._worker: Optional[LoadWorker] = None
        # Cancelled workers still running towards their next progress report
        self._retired: Set[LoadWorker] = set()

        self.tab_widget = QtWidgets.QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.currentChanged.connect(self._on_tab_changed)
        self.setCentralWidget(self.tab_widget)
        self._window_label = ""

        self._build_menus()
        self._build_status_bar()
        self._show_placeholder()

    def _build_menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        self._add(file_menu, "&Open evidence\u2026", self.open_evidence,
                  QtGui.QKeySequence.StandardKey.Open)
        file_menu.addSeparator()
        self.export_action = self._add(
            file_menu, "&Export current tab\u2026", self.export_current_tab,
            QtGui.QKeySequence.StandardKey.Save
        )
        self.export_all_action = self._add(
            file_menu, "Export &all tabs\u2026", self.export_all_tabs
        )
        file_menu.addSeparator()
        self.close_action = self._add(file_menu, "&Close case", self.close_case)
        self._add(file_menu, "&Quit", self.close, QtGui.QKeySequence.StandardKey.Quit)

        self.hunt_menu = self.menuBar().addMenu("&Hunt")
        self._build_hunt_menu()

        view_menu = self.menuBar().addMenu("&View")
        self._add(view_menu, "&Focus search", self._focus_search,
                  QtGui.QKeySequence("Ctrl+F"))
        self._add(view_menu, "&Resize columns to contents", self._resize_columns)
        self._add(view_menu, "Toggle &details panel", self._toggle_details)

        help_menu = self.menuBar().addMenu("&Help")
        self._add(help_menu, "&About", self._about)

    def _add(self, menu, text, slot, shortcut=None):
        action = menu.addAction(text)
        action.triggered.connect(slot)
        if shortcut is not None:
            action.setShortcut(shortcut)
        return action

    def _build_hunt_menu(self) -> None:
        self.hunt_menu.clear()
        for group in hunts_module.groups():
            submenu = self.hunt_menu.addMenu(group)
            for hunt in hunts_module.hunts_in_group(group):
                action = submenu.addAction(hunt.title.replace("&", "&&"))
                action.setToolTip(hunt.description)
                action.setStatusTip(hunt.description)
                action.triggered.connect(
                    lambda _checked=False, key=hunt.key: self.run_hunt(key)
                )
        self.hunt_menu.setToolTipsVisible(True)
        self.hunt_menu.addSeparator()
        self._add(self.hunt_menu, "&Clear hunt", self.clear_hunt,
                  QtGui.QKeySequence("Ctrl+Shift+C"))

    def _build_status_bar(self) -> None:
        self.progress = QtWidgets.QProgressBar()
        self.progress.setMaximumWidth(240)
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().showMessage("Open an $MFT to begin.")

    def _show_placeholder(self) -> None:
        placeholder = QtWidgets.QLabel(
            "<h2>MFT-EvilHunter</h2>"
            "<p>File \u2192 Open evidence\u2026 to load an <code>$MFT</code>, "
            "optionally with a <code>$LogFile</code>.</p>"
            "<p>Then use the <b>Hunt</b> menu to filter for PsExec artifacts, "
            "suspicious file names, ransomware indicators, timestomping and more.</p>"
        )
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setTextFormat(Qt.TextFormat.RichText)
        self.tab_widget.addTab(placeholder, "Welcome")
        self._set_case_actions_enabled(False)

    def _set_case_actions_enabled(self, enabled: bool) -> None:
        for action in (self.export_action, self.export_all_action, self.close_action):
            action.setEnabled(enabled)
        self.hunt_menu.setEnabled(enabled)

    # load

    def prefill_open_dialog(self, mft_path=None, logfile_path=None, usnjrnl_path=None) -> None:
        """Open the dialog with paths already populated."""
        self.open_evidence(prefill=(mft_path, logfile_path, usnjrnl_path))

    def open_evidence(self, prefill=None) -> None:
        dialog = OpenDialog(self)
        if prefill:
            mft_path, logfile_path, usnjrnl_path = prefill
            if mft_path:
                dialog.mft_edit.setText(str(mft_path))
            if logfile_path:
                dialog.log_edit.setText(str(logfile_path))
            if usnjrnl_path:
                dialog.usn_edit.setText(str(usnjrnl_path))
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        try:
            request = dialog.request()
        except (Exception, SystemExit) as exc:
            QtWidgets.QMessageBox.critical(self, "Could not load rules", str(exc))
            return

        for label, path in (("$MFT", request.mft_path),
                            ("$LogFile", request.logfile_path),
                            ("$UsnJrnl", request.usnjrnl_path)):
            if path and not path.is_file():
                QtWidgets.QMessageBox.critical(
                    self, "File not found", f"{label}: {path}"
                )
                return

        if not self._confirm_large_volume(request):
            return

        self.close_case()
        opts = request.options
        self._window_label = (f"{opts.window_start[:19]} to {opts.window_end[:19]} UTC"
                              if opts.windowed else "")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)

        worker = LoadWorker(request, self)
        worker.progress.connect(self._on_progress)
        worker.loaded.connect(self._on_loaded)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(lambda w=worker: self._on_finished(w))
        self._worker = worker
        worker.start()

    def _confirm_large_volume(self, request) -> bool:
        """Warn before loading a volume large enough to exhaust memory."""
        if not request.mft_path:
            return True

        records = estimate_records(request.mft_path, request.record_size or 1024)
        if records < LARGE_VOLUME_RECORDS:
            return True

        wants_timeline = request.options.timeline
        estimate = estimate_memory_gb(records, wants_timeline)
        without = estimate_memory_gb(records, False)

        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Icon.Warning)
        box.setWindowTitle("Large volume")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(
            f"<b>This $MFT holds roughly {records:,} records.</b>"
            f"<p>Estimated peak memory: <b>{estimate:.1f} GB</b>"
            + (f", or {without:.1f} GB without the combined timeline."
               if wants_timeline else ".")
            + "</p><p>The estimate is about 2.7 KB per record for the parsed "
              "records and roughly double that once every tab is built. The "
              "timeline alone triples it, because each record becomes up to "
              "eight MACB rows.</p>"
        )
        if wants_timeline:
            skip = box.addButton("Load without timeline",
                                 QtWidgets.QMessageBox.ButtonRole.AcceptRole)
        else:
            skip = None
        proceed = box.addButton("Load anyway",
                                QtWidgets.QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QtWidgets.QMessageBox.StandardButton.Cancel)
        box.exec()

        clicked = box.clickedButton()
        if clicked is skip:
            request.options.timeline = False
            return True
        return clicked is proceed

    def _from_current_worker(self) -> bool:
        """
        A cancelled worker that was still mid parse can finish after a new
        case has started loading. Its signals must not touch the window.
        """
        return self.sender() is self._worker

    def _on_progress(self, done: int, total: int, label: str) -> None:
        if not self._from_current_worker():
            return
        if total > 1:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
            self.statusBar().showMessage(f"{label}\u2026 {done:,}/{total:,}")
        else:
            self.progress.setRange(0, 0)
            self.statusBar().showMessage(f"{label}\u2026")

    def _on_failed(self, message: str) -> None:
        if not self._from_current_worker():
            return
        self.progress.setVisible(False)
        self.statusBar().showMessage("Load failed.")
        QtWidgets.QMessageBox.critical(self, "Load failed", message)

    def _discard_tabs(self) -> None:
        """
        QTabWidget.clear() removes pages without deleting them, and each page
        holds a model with the whole dataset.
        """
        pages = [self.tab_widget.widget(i) for i in range(self.tab_widget.count())]
        self.tab_widget.clear()
        for page in pages:
            page.setParent(None)
            page.deleteLater()
        self.tabs.clear()

    def _on_loaded(self, datasets: Dict[str, Dataset], stats: dict) -> None:
        if not self._from_current_worker():
            return
        self._discard_tabs()

        for name, dataset in datasets.items():
            if not len(dataset) and name in ("$MFT", "$LogFile", "$UsnJrnl",
                                             "Short-lived files", "Execution",
                                             "Renames", "Host artifacts",
                                             "Timeline"):
                continue  # artifact not supplied, or timeline switched off
            tab = ArtifactTab(dataset, self)
            self.tabs[name] = tab
            self.tab_widget.addTab(tab, f"{name}  ({len(dataset):,})")

        self._set_case_actions_enabled(bool(self.tabs))

        summary = []
        if "mft_records" in stats:
            summary.append(f"{stats['mft_records']:,} MFT records")
            if stats.get("unreliable_paths"):
                summary.append(f"{stats['unreliable_paths']:,} unreliable paths")
        if "logfile_events" in stats:
            summary.append(f"{stats['logfile_events']:,} $LogFile events")
            if stats.get("carved_events"):
                summary.append(f"{stats['carved_events']:,} carved")
        if "usn_records" in stats:
            summary.append(f"{stats['usn_records']:,} $UsnJrnl records")
            if stats.get("short_lived"):
                summary.append(f"{stats['short_lived']:,} short-lived files")
        if stats.get("renames"):
            summary.append(f"{stats['renames']:,} renames")
        if stats.get("executions"):
            summary.append(f"{stats['executions']:,} executables ran")
        if stats.get("host_artifacts"):
            summary.append(f"{stats['host_artifacts']:,} host artifacts")
        iocs = len(datasets.get("IOC Matches", Dataset("", [])))
        if iocs:
            summary.append(f"{iocs:,} IOC matches")
        if self._window_label:
            summary.append(f"window {self._window_label}")
            self.setWindowTitle(f"MFT-EvilHunter {__version__}  [{self._window_label}]")
        else:
            self.setWindowTitle(f"MFT-EvilHunter {__version__}")
        self.statusBar().showMessage("Loaded: " + ", ".join(summary))

        empty = [label for key, label in (("mft_records", "$MFT"),
                                          ("logfile_events", "$LogFile"),
                                          ("usn_records", "$UsnJrnl"))
                 if key in stats and not stats[key]]
        if empty:
            QtWidgets.QMessageBox.warning(
                self, "Nothing parsed",
                f"No records were found in {' and '.join(empty)}. "
                "Check that the right file was picked for each field.")

    def _stop_worker(self) -> None:
        """Cancel a running load without waiting for it."""
        worker = self._worker
        self._worker = None
        if worker is not None and worker.isRunning():
            worker.cancel()
            self._retired.add(worker)
        self.progress.setVisible(False)

    def _on_finished(self, worker) -> None:
        self._retired.discard(worker)
        if worker is self._worker:
            self._worker = None
            self.progress.setVisible(False)
        worker.deleteLater()

    def close_case(self) -> None:
        self._stop_worker()
        self._discard_tabs()
        self._show_placeholder()
        self.statusBar().showMessage("Open an $MFT to begin.")

    # hunts

    # Which tab to surface after a hunt
    TAB_PRIORITY = ("IOC Matches", "Execution", "Renames", "Host artifacts",
                    "Short-lived files", "$MFT", "$LogFile",
                    "$UsnJrnl", "Timestomping", "Anomalies", "Timeline")

    def run_hunt(self, key: str) -> None:
        hunt = hunts_module.HUNTS_BY_KEY[key]
        results: List[tuple] = []

        for name, tab in self.tabs.items():
            if not hunt.applies_to(tab.dataset):
                tab.clear_hunt()
                continue
            indices = hunts_module.apply_hunt(hunt, tab.dataset)
            count = tab.apply_hunt(indices, hunt.title)
            results.append((name, count))

        if not results:
            self.statusBar().showMessage(
                f"Hunt '{hunt.title}' does not apply to any loaded tab."
            )
            return

        hits = {name for name, count in results if count}
        if hits:
            for name in self.TAB_PRIORITY:
                if name in hits:
                    self.tab_widget.setCurrentIndex(list(self.tabs).index(name))
                    break

        detail = ", ".join(f"{name}: {count:,}" for name, count in results)
        total = sum(count for _, count in results)
        self.statusBar().showMessage(
            f"Hunt '{hunt.title}' \u2014 {total:,} row(s)   [{detail}]"
            + ("" if total else "   (nothing matched)")
        )

    def clear_hunt(self) -> None:
        for tab in self.tabs.values():
            tab.clear_hunt()
        self.statusBar().showMessage("Hunt cleared.")

    # export

    def _current_tab(self) -> Optional[ArtifactTab]:
        widget = self.tab_widget.currentWidget()
        return widget if isinstance(widget, ArtifactTab) else None

    def export_current_tab(self) -> None:
        tab = self._current_tab()
        if tab is None:
            return
        suggested = f"{tab.dataset.name.strip('$').lower()}.csv"
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export visible rows", suggested, "CSV (*.csv)"
        )
        if not path:
            return
        try:
            count = tab.export_visible(Path(path))
        except OSError as exc:
            QtWidgets.QMessageBox.critical(self, "Export failed", str(exc))
            return
        self.statusBar().showMessage(f"Exported {count:,} visible row(s) to {path}")

    def export_all_tabs(self) -> None:
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Export all tabs to folder"
        )
        if not directory:
            return
        written = []
        for name, tab in self.tabs.items():
            safe = name.strip("$").lower().replace(" ", "_")
            path = Path(directory) / f"{safe}.csv"
            try:
                written.append((path.name, tab.export_visible(path)))
            except OSError as exc:
                QtWidgets.QMessageBox.critical(self, "Export failed", str(exc))
                return
        detail = ", ".join(f"{n} ({c:,})" for n, c in written)
        self.statusBar().showMessage(
            f"Exported visible rows of {len(written)} tab(s), filters and hunt included: {detail}")

    # view

    def _focus_search(self) -> None:
        tab = self._current_tab()
        if tab:
            tab.search_box.setFocus()
            tab.search_box.selectAll()

    def _resize_columns(self) -> None:
        tab = self._current_tab()
        if tab:
            tab.view.resizeColumnsToContents()

    def _toggle_details(self) -> None:
        tab = self._current_tab()
        if not tab:
            return
        sizes = tab.splitter.sizes()
        tab.splitter.setSizes([sizes[0] + sizes[1], 0] if sizes[1] else [1000, 320])

    def _on_tab_changed(self, _index: int) -> None:
        pass

    def _about(self) -> None:
        box = QtWidgets.QMessageBox(self)
        box.setWindowTitle("About MFT-EvilHunter")
        box.setIconPixmap(load_icon().pixmap(96, 96))
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(
            f"<h3>MFT-EvilHunter {__version__}</h3>"
            "<p>NTFS <code>$MFT</code>, <code>$LogFile</code>, and <code>$UsnJrnl</code> IOC hunting for DFIR.</p>"
            "<p><a href='https://github.com/cristianzsh/mft-evilhunter'>https://github.com/cristianzsh/mft-evilhunter</a></p>"
            "<p>By Cristian Souza<br>"
            "<a href='https://cristian.sh'>https://cristian.sh</a><br>cristianmsbr@gmail.com</p>"
        )
        box.exec()

    def closeEvent(self, event) -> None:
        # A QThread destroyed while running aborts the process
        self._stop_worker()
        self.hide()
        for worker in list(self._retired):
            worker.wait()
        event.accept()
