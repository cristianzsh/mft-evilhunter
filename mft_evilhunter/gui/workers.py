"""
Background loading.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import baseline as baseline_mod
from .. import execution, hostartifacts, logfile, mft, usnjrnl
from ..ioc import RuleSet
from .dataset import AnalysisOptions, build_datasets
from .qt import QtCore, Signal


@dataclass
class LoadRequest:
    mft_path: Optional[Path] = None
    logfile_path: Optional[Path] = None
    usnjrnl_path: Optional[Path] = None
    record_size: int = 0
    page_size: int = 0
    carve: bool = True
    options: AnalysisOptions = None
    rules: RuleSet = None

    def __post_init__(self):
        if self.options is None:
            self.options = AnalysisOptions()
        if self.rules is None:
            self.rules = RuleSet.builtin()


class _Cancelled(Exception):
    pass


class LoadWorker(QtCore.QThread):
    progress = Signal(int, int, str)
    loaded = Signal(object, object) # datasets, stats
    failed = Signal(str)

    def __init__(self, request: LoadRequest, parent=None):
        super().__init__(parent)
        self.request = request
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def _tick(self, done: int, total: int, label: str) -> bool:
        """Every progress report is a cancellation point."""
        if self._cancelled:
            raise _Cancelled()
        self.progress.emit(done, total, label)
        return True

    def run(self) -> None: # pragma: no cover
        try:
            self._run()
        except _Cancelled:
            return
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    def _run(self) -> None:
        req = self.request
        entries = None
        events = None
        stats = {}

        if req.mft_path:
            record_size = req.record_size or mft.detect_record_size(req.mft_path)
            stats["record_size"] = record_size
            self._tick(0, 1, "Parsing $MFT")
            entries = mft.parse_mft(
                req.mft_path, record_size,
                progress=lambda d, t: self._tick(d, t, "Parsing $MFT records"),
            )
            if self._cancelled:
                return
            self._tick(0, 1, "Reconstructing paths")
            mft.build_paths(entries)
            stats["mft_records"] = len(entries)
            stats["unreliable_paths"] = sum(
                1 for e in entries.values() if not e.path_reliable
            )

        if req.logfile_path:
            page_size = req.page_size or logfile.detect_page_size(req.logfile_path)
            stats["page_size"] = page_size
            self._tick(0, 1, "Parsing $LogFile")
            events = list(logfile.parse_logfile(
                req.logfile_path, page_size=page_size, carve=req.carve,
                progress=lambda d, t: self._tick(d, t, "Reading $LogFile pages"),
            ))
            if self._cancelled:
                return
            if entries:
                self._tick(0, 1, "Resolving $LogFile paths")
                logfile.resolve_event_paths(events, entries)
            stats["logfile_events"] = len(events)
            stats["carved_events"] = sum(1 for e in events if e.source == "carved")

        usn_records = None
        lifetimes = None
        renames = None
        if req.usnjrnl_path:
            self._tick(0, 1, "Parsing $UsnJrnl")
            usn_records = list(usnjrnl.parse_usnjrnl(
                req.usnjrnl_path,
                progress=lambda d, t: self._tick(d, t, "Reading $UsnJrnl"),
            ))
            if self._cancelled:
                return
            if entries:
                self._tick(0, 1, "Resolving $UsnJrnl paths")
                usnjrnl.resolve_usn_paths(usn_records, entries)
            self._tick(0, 1, "Correlating file lifetimes")
            lifetimes = usnjrnl.correlate_lifetimes(usn_records)
            stats["usn_records"] = len(usn_records)
            stats["short_lived"] = len(lifetimes)
            self._tick(0, 1, "Correlating renames")
            renames = usnjrnl.correlate_renames(usn_records)
            stats["renames"] = len(renames)

        if self._cancelled:
            return

        self._tick(0, 1, "Collecting host artifacts")
        volume_baseline = baseline_mod.derive_baseline(entries) if entries else None
        if volume_baseline is not None:
            stats["activity_start"] = volume_baseline.earliest_activity
            stats["activity_end"] = volume_baseline.latest_activity
        host_artifacts = hostartifacts.collect_host_artifacts(
            entries, volume_baseline)
        stats["host_artifacts"] = len(host_artifacts)

        self._tick(0, 1, "Reconstructing execution evidence")
        executions = execution.build_execution_evidence(
            entries, usn_records, events)
        stats["executions"] = len(executions)

        datasets = build_datasets(
            entries, events, req.rules, req.options,
            progress=lambda d, t, label: self._tick(d, t, label),
            usn_records=usn_records, lifetimes=lifetimes,
            executions=executions, renames=renames,
            host_artifacts=host_artifacts,
        )
        if self._cancelled:
            return

        self.loaded.emit(datasets, stats)
