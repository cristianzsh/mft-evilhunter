"""
Tabular datasets for the GUI.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .. import baseline as baseline_mod, detect, report
from ..ioc import SEVERITY_ORDER as IOC_SEVERITY_ORDER
from ..usnjrnl import USN_REASON_FILE_DELETE as USN_FILE_DELETE
from ..ioc import Match, RuleSet, Subject
from ..paths import is_resolved_source

# Re-exported so the Qt-free GUI layer has one severity ranking
SEVERITY_ORDER = IOC_SEVERITY_ORDER

# Columns appended to the raw artifact fields once rules and heuristics have run.
ANALYSIS_COLUMNS = ["severity", "rules", "categories", "mitre", "extracted", "findings"]

# A mass encryption event can touch tens of thousands of files. Cap the rows.
MASS_EXTENSION_ROW_CAP = 200


def _intern(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, str):
        value = str(value)
    return sys.intern(value) if len(value) <= 64 else value


# Columns holding an ISO 8601 timestamp. Values are UTC from one formatter, so
# they compare correctly as plain strings.
TIMESTAMP_COLUMN_NAMES = frozenset({
    "timestamp", "created", "deleted", "last_modified",
    "first_executed", "last_executed",
    "si_created", "si_modified", "si_mft_modified", "si_accessed",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
})


def is_timestamp_column(name: str) -> bool:
    return name in TIMESTAMP_COLUMN_NAMES


@dataclass
class Dataset:
    """A single tab's worth of table data."""

    name: str
    columns: List[str]
    rows: List[Tuple[str, ...]] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        self._index = {c: i for i, c in enumerate(self.columns)}
        self.timestamp_columns = tuple(
            i for i, c in enumerate(self.columns) if is_timestamp_column(c))

    def __len__(self) -> int:
        return len(self.rows)

    def has(self, column: str) -> bool:
        return column in self._index

    def col(self, column: str) -> int:
        return self._index[column]

    def value(self, row: Sequence[str], column: str, default: str = "") -> str:
        idx = self._index.get(column)
        return row[idx] if idx is not None else default

    def append(self, mapping: dict) -> None:
        self.rows.append(tuple(_intern(mapping.get(c, "")) for c in self.columns))


# Analysis

@dataclass
class AnalysisOptions:
    timestomping: bool = True
    anomalies: bool = True
    timestomp_threshold: int = 3600
    timeline: bool = True

    window_start: str = ""
    window_end: str = ""

    @property
    def windowed(self) -> bool:
        return bool(self.window_start or self.window_end)

    def in_window(self, row: dict) -> bool:
        """True if any timestamp column of the row falls inside the window."""
        if not self.windowed:
            return True
        lo, hi = self.window_start, self.window_end
        for column in TIMESTAMP_COLUMN_NAMES:
            value = row.get(column)
            if not value:
                continue
            if lo and value < lo:
                continue
            if hi and value > hi:
                continue
            return True
        return False

    def in_window_value(self, value: str) -> bool:
        if not self.windowed or not value:
            return not self.windowed
        return not ((self.window_start and value < self.window_start)
                    or (self.window_end and value > self.window_end))


def _summarise_matches(matches) -> dict:
    if not matches:
        return {"severity": "", "rules": "", "categories": "", "mitre": "", "extracted": ""}
    best = max(matches, key=lambda m: SEVERITY_ORDER.get(m.severity, 0))
    extracted = []
    for m in matches:
        if m.extracted_str:
            extracted.append(m.extracted_str)
    return {
        "severity": best.severity,
        "rules": " | ".join(sorted({m.rule_name for m in matches})),
        "categories": " | ".join(sorted({m.category for m in matches})),
        "mitre": " | ".join(sorted({t for m in matches for t in m.mitre})),
        "extracted": "; ".join(sorted(set(extracted))),
    }


def _entry_subject(entry) -> Subject:
    return Subject(
        name=entry.name, path=entry.path, extension=entry.extension,
        size=entry.logical_size, is_deleted=entry.is_deleted,
        is_directory=entry.is_directory, artifact="$MFT",
        zone_id=entry.zone_id, download_url=entry.zone_host_url,
        path_reliable=entry.path_reliable,
    )


def _usn_subject(record) -> Subject:
    return Subject(
        name=record.name, path=record.path or "\\" + record.name,
        extension=record.extension, size=0,
        is_deleted=bool(record.reason & USN_FILE_DELETE),
        is_directory=record.is_directory, artifact="$UsnJrnl",
        path_reliable=is_resolved_source(record.path_source),
    )


def _lifetime_subject(lifetime) -> Subject:
    name = lifetime.name
    return Subject(
        name=name, path=lifetime.path or "\\" + name,
        extension="." + name.rsplit(".", 1)[-1].lower() if "." in name else "",
        size=0, is_deleted=True, is_directory=False, artifact="$UsnJrnl",
        path_reliable=is_resolved_source(lifetime.path_source),
    )


def _event_subject(event) -> Subject:
    return Subject(
        name=event.name, path=event.path or "\\" + event.name,
        extension=event.extension, size=event.real_size,
        is_deleted=event.action in ("FileNameRemoved", "FileRecordDeleted"),
        is_directory=False, artifact="$LogFile",
        path_reliable=is_resolved_source(event.path_source),
    )


def _ioc_row(artifact: str, match, row: dict, *, record_key: str,
             lsn_key: str = "", deleted: str = "",
             created_key: str = "", modified_key: str = "",
             fn_created_key: str = "") -> dict:
    """One IOC Matches row."""
    return {
        "artifact": artifact,
        "severity": match.severity,
        "rule": match.rule_name,
        "rule_title": match.title,
        "category": match.category,
        "mitre": ", ".join(match.mitre),
        "extracted": match.extracted_str,
        "evidence": match.evidence,
        "name": row["name"],
        "extension": row["extension"],
        "path": row["path"],
        "is_deleted": deleted,
        "zone": row.get("zone", ""),
        "download_url": row.get("download_url", ""),
        "download_referrer": row.get("download_referrer", ""),
        "record_number": row.get(record_key, ""),
        "lsn": row.get(lsn_key, "") if lsn_key else "",
        "si_created": row.get(created_key, "") if created_key else "",
        "si_modified": row.get(modified_key, "") if modified_key else "",
        "fn_created": row.get(fn_created_key, "") if fn_created_key else "",
    }


IOC_COLUMNS = [
    "artifact", "severity", "rule", "rule_title", "category", "mitre",
    "extracted", "name", "extension", "path",
    "zone", "download_url", "download_referrer",
    "is_deleted", "evidence",
    "record_number", "lsn", "si_created", "si_modified", "fn_created",
]

FINDING_COLUMNS = [
    "severity", "finding", "finding_detail", "name", "extension", "path",
    "is_deleted", "ads_names", "logical_size", "record_number",
    "si_created", "si_modified", "si_mft_modified", "si_accessed",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
]


def _tab_schemas() -> Dict[str, Dataset]:
    """Every tab, declared in one place instead of inline in the build loop."""
    return {
        "$MFT": Dataset("$MFT", report.MFT_FIELDS + ANALYSIS_COLUMNS, description="Every parsed MFT record."),
        "$LogFile": Dataset("$LogFile", report.LOGFILE_FIELDS + ANALYSIS_COLUMNS, description="Filename events recovered from $LogFile."),
        "$UsnJrnl": Dataset("$UsnJrnl", report.USN_FIELDS + ANALYSIS_COLUMNS, description="Change records from $Extend\\$UsnJrnl:$J."),
        "Short-lived files": Dataset("Short-lived files", report.LIFETIME_FIELDS, description="Files the journal saw both created and deleted, shortest first."),
        "Execution": Dataset("Execution", report.EXECUTION_FIELDS, description="Executables that ran, reconstructed from Prefetch filenames in the $MFT."),
        "Renames": Dataset("Renames", report.RENAME_FIELDS, description="Rename chains recovered from $UsnJrnl: what a file was called before it was called what it is called now."),
        "Host artifacts": Dataset("Host artifacts", report.HOST_ARTIFACT_FIELDS, description="Event log lifecycle, user profiles and RDP client evidence inferred from $MFT metadata."),
        "IOC Matches": Dataset("IOC Matches", IOC_COLUMNS, description="One row per rule hit, across every artifact."),
        "Timestomping": Dataset("Timestomping", FINDING_COLUMNS, description="$SI/$FN divergence and sub-second precision analysis."),
        "Anomalies": Dataset("Anomalies", FINDING_COLUMNS, description="Masquerading, machine-generated names and suspicious streams."),
        "Timeline": Dataset("Timeline", report.TIMELINE_FIELDS, description="Combined timeline across every artifact."),
    }


def _ingest_mft(datasets, entries, rules, options, timeline_rows,
                volume_baseline, progress) -> None:
    values = list(entries.values())
    total = len(values)
    for index, entry in enumerate(values):
        if progress and index % 5000 == 0:
            progress(index, total, "Analysing $MFT records")

        row = report.mft_row(entry)
        if not options.in_window(row):
            continue
        matches = rules.match(_entry_subject(entry))
        summary = _summarise_matches(matches)

        findings = []
        if options.timestomping:
            findings += [("timestomp", f) for f in detect.detect_timestomping(
                entry, options.timestomp_threshold, volume_baseline)]
        if options.anomalies:
            findings += [("anomaly", f) for f in detect.detect_masquerading(entry)]

        summary["findings"] = " | ".join(sorted({f.kind for _, f in findings}))
        datasets["$MFT"].append({**row, **summary})

        for match in matches:
            datasets["IOC Matches"].append(_ioc_row(
                "$MFT", match, row, record_key="record_number",
                deleted=row["is_deleted"], created_key="si_created",
                modified_key="si_modified", fn_created_key="fn_created",
            ))

        for kind, finding in findings:
            tab = "Timestomping" if kind == "timestomp" else "Anomalies"
            datasets[tab].append({
                **row, "severity": finding.severity,
                "finding": finding.kind, "finding_detail": finding.detail,
            })

        if options.timeline:
            timeline_rows.extend(report.timeline_rows_from_entry(entry, matches))


def _emit_synthetic(datasets, match, rows, options, artifact, deleted_key="", **keys) -> None:
    """IOC rows for a heuristic finding that spans many records."""
    for row in rows[:MASS_EXTENSION_ROW_CAP]:
        if options.in_window(row):
            deleted = row.get(deleted_key, "") if deleted_key else ""
            datasets["IOC Matches"].append(_ioc_row(artifact, match, row, deleted=deleted, **keys))


def _ingest_mass_extension(datasets, entries, options) -> None:
    """Family-agnostic ransomware detection."""
    for extension, records, first, last in detect.detect_mass_extension_change(entries):
        match = Match(
            rule_name="ransomware_mass_extension",
            title=f"{len(records):,} files gained the unrecognised extension "
                  f"{extension} within hours",
            severity="critical", category="impact", mitre=["T1486"],
            extracted={"extension": extension, "files": str(len(records)),
                       "window_start": first.isoformat(),
                       "window_end": last.isoformat()},
            evidence=extension,
        )
        rows = [dict(report.mft_row(e), deleted="true" if e.is_deleted else "") for e in records]
        _emit_synthetic(datasets, match, rows, options, "$MFT", deleted_key="deleted",
                        record_key="record_number", created_key="si_created",
                        modified_key="si_modified", fn_created_key="fn_created")


def _ingest_note_fanout(datasets, records, options) -> None:
    """Notes that can only be recognised by where they turned up."""
    for name, dirs, chosen, first, last in detect.detect_note_fanout(records):
        match = Match(
            rule_name="ransom_note_fanout",
            title=f"{name} was created in {dirs:,} directories within "
                  f"{int((last - first).total_seconds()) // 60 + 1} minutes",
            severity="critical", category="impact", mitre=["T1486"],
            extracted={"name": name, "directories": str(dirs),
                       "window_start": first.isoformat(), "window_end": last.isoformat()},
            evidence=name,
        )
        _emit_synthetic(datasets, match, [report.usn_row(r) for r in chosen], options,
                        "$UsnJrnl", record_key="file_record", lsn_key="usn",
                        fn_created_key="timestamp")


def _ingest_logfile(datasets, events, rules, options, timeline_rows, progress) -> None:
    total = len(events)
    for index, event in enumerate(events):
        if progress and index % 5000 == 0:
            progress(index, total, "Analysing $LogFile events")

        row = report.logfile_row(event)
        if not options.in_window(row):
            continue

        matches = [] if event.is_dos_alias else rules.match(_event_subject(event))
        summary = _summarise_matches(matches)
        summary["findings"] = ""
        datasets["$LogFile"].append({**row, **summary})

        for match in matches:
            datasets["IOC Matches"].append(_ioc_row(
                "$LogFile", match, row, record_key="mft_record",
                lsn_key="lsn", fn_created_key="fn_created",
            ))

        if options.timeline:
            timeline_rows.extend(report.timeline_rows_from_event(event, matches))


def _ingest_usn(datasets, records, rules, options, timeline_rows, progress) -> None:
    total = len(records)
    for index, record in enumerate(records):
        if progress and index % 20000 == 0:
            progress(index, total, "Analysing $UsnJrnl records")

        row = report.usn_row(record)
        if not options.in_window(row):
            continue
        matches = rules.match(_usn_subject(record))
        summary = _summarise_matches(matches)
        summary["findings"] = ""
        datasets["$UsnJrnl"].append({**row, **summary})

        for match in matches:
            datasets["IOC Matches"].append(_ioc_row(
                "$UsnJrnl", match, row, record_key="file_record", lsn_key="usn",
                deleted="true" if record.reason & USN_FILE_DELETE else "",
                fn_created_key="timestamp",
            ))

        if options.timeline:
            timeline_rows.extend(report.timeline_rows_from_usn(record, matches))


def build_datasets(
    entries: Optional[dict],
    events: Optional[list],
    rules: RuleSet,
    options: Optional[AnalysisOptions] = None,
    progress: Optional[Callable[[int, int, str], None]] = None,
    usn_records: Optional[list] = None,
    lifetimes: Optional[list] = None,
    executions: Optional[list] = None,
    renames: Optional[list] = None,
    host_artifacts: Optional[list] = None,
) -> Dict[str, Dataset]:
    """Run rules and heuristics once and produce every tab."""
    options = options or AnalysisOptions()
    datasets = _tab_schemas()
    timeline_rows: List[dict] = []

    volume_baseline = baseline_mod.derive_baseline(entries) if entries else None

    if entries:
        _ingest_mft(datasets, entries, rules, options, timeline_rows,
                    volume_baseline, progress)
        _ingest_mass_extension(datasets, entries, options)

    if events:
        _ingest_logfile(datasets, events, rules, options, timeline_rows, progress)

    if usn_records:
        _ingest_usn(datasets, usn_records, rules, options, timeline_rows, progress)
        _ingest_note_fanout(datasets, usn_records, options)

    for lifetime in lifetimes or ():
        row = report.lifetime_row(lifetime, rules.match(_lifetime_subject(lifetime)))
        if options.in_window(row):
            datasets["Short-lived files"].append(row)

    for item in executions or ():
        row = report.execution_row(item)
        if not options.in_window(row):
            continue
        datasets["Execution"].append(row)
        if options.timeline:
            timeline_rows.extend(report.timeline_rows_from_execution(item))

    for rename in renames or ():
        row = report.rename_row(rename)
        if not options.in_window(row):
            continue
        datasets["Renames"].append(row)
        if options.timeline and rename.severity:
            timeline_rows.extend(report.timeline_rows_from_rename(rename))

    for artifact in host_artifacts or ():
        row = report.host_artifact_row(artifact)
        if not options.in_window(row):
            continue
        datasets["Host artifacts"].append(row)
        if options.timeline:
            timeline_rows.extend(report.timeline_rows_from_host_artifact(artifact))

    if timeline_rows:
        timeline_rows = [r for r in timeline_rows
                         if options.in_window_value(r["timestamp"])]
        timeline_rows.sort(key=lambda row: row["timestamp"])
        for row in timeline_rows:
            datasets["Timeline"].append(row)

    # Highest severity first.
    ioc = datasets["IOC Matches"]
    severity = ioc.col("severity")
    ioc.rows.sort(key=lambda row: -SEVERITY_ORDER.get(row[severity], 0))

    if progress:
        progress(1, 1, "Ready")

    return datasets
