"""
CSV reporting.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, List

from .filetypes import detect_content_type, resident_preview, zone_label
from .paths import is_noise
from .ntfs import describe_file_attributes, iso

DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize(value) -> str:
    """Prefix a cell that Excel would interpret as a formula."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, str):
        return str(value)
    if value.startswith(DANGEROUS_PREFIXES):
        return "'" + value
    return value


class CsvWriter:
    def __init__(self, path: Path, fieldnames: List[str]):
        self.path = path
        self.fieldnames = fieldnames
        self.count = 0
        self._fh = path.open("w", newline="", encoding="utf-8-sig")
        self._writer = csv.DictWriter(
            self._fh, fieldnames=fieldnames, extrasaction="ignore"
        )
        self._writer.writeheader()

    def write(self, row: dict) -> None:
        self._writer.writerow({k: neutralize(row.get(k)) for k in self.fieldnames})
        self.count += 1

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# Field definitions

MFT_FIELDS = [
    "record_number", "sequence_number", "in_use", "is_deleted", "is_directory",
    "is_extension_record", "hard_link_count",
    "name", "extension", "path", "path_reliable", "path_note", "all_paths",
    "parent_record", "parent_sequence",
    "logical_size", "physical_size",
    "si_created", "si_modified", "si_mft_modified", "si_accessed",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
    "fn_namespace", "file_attributes",
    "ads_names", "zone_id", "zone", "download_url", "download_referrer",
    "has_reparse_point", "has_attribute_list",
    "resident_data_len", "content_type", "resident_preview",
    "attributes", "parse_error",
]


LOGFILE_FIELDS = [
    "lsn", "transaction_id", "action", "redo_op", "undo_op", "source",
    "name", "extension", "path", "path_source",
    "mft_record", "mft_sequence", "parent_record", "parent_sequence",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
    "real_size", "allocated_size", "file_attributes", "namespace",
    "page_offset",
]

USN_FIELDS = [
    "usn", "timestamp", "action", "reason", "source_info",
    "name", "extension", "path", "path_source",
    "file_record", "file_sequence", "parent_record", "parent_sequence",
    "is_directory", "file_attributes", "security_id", "version", "offset",
]

LIFETIME_FIELDS = [
    "seconds", "lifetime", "name", "extension", "path", "path_source", "os_churn",
    "created", "deleted", "file_record", "file_sequence", "parent_record",
    "severity", "rules", "extracted",
]

EXECUTION_FIELDS = [
    "first_executed", "last_executed", "image", "severity", "category", "notes",
    "binary_present", "binary_path", "outside_windows",
    "prefetch_file", "prefetch_deleted", "path_hash", "source",
]

RENAME_FIELDS = [
    "timestamp", "severity", "old_name", "new_name", "notes",
    "old_path", "new_path", "hop", "total_hops",
    "os_churn", "path_source", "file_record", "file_sequence",
]

HOST_ARTIFACT_FIELDS = [
    "category", "severity", "name", "detail", "timestamp", "last_modified",
    "size", "path", "notes",
]

TIMELINE_FIELDS = [
    "timestamp", "artifact", "source_attribute", "macb", "action",
    "name", "extension", "path", "is_deleted", "size",
    "record_number", "lsn", "rule", "severity", "extracted", "notes",
]


TIMELINE_DEFAULTS = {field: "" for field in TIMELINE_FIELDS}


def timeline_row(**values) -> dict:
    """Build a timeline row from a small set of overrides."""
    row = dict(TIMELINE_DEFAULTS)
    row.update(values)
    return row


# Row builders

def mft_row(entry) -> dict:
    fn = entry.best_fn
    fn_ts = fn.timestamps if fn else None
    return {
        "record_number": entry.record_number,
        "sequence_number": entry.sequence_number,
        "in_use": entry.in_use,
        "is_deleted": entry.is_deleted,
        "is_directory": entry.is_directory,
        "is_extension_record": entry.is_extension_record,
        "hard_link_count": entry.hard_link_count,
        "name": entry.name,
        "extension": entry.extension,
        "path": entry.path,
        "path_reliable": entry.path_reliable,
        "path_note": entry.path_note,
        "all_paths": " | ".join(entry.all_paths),
        "parent_record": fn.parent_record if fn else "",
        "parent_sequence": fn.parent_sequence if fn else "",
        "logical_size": entry.logical_size,
        "physical_size": entry.physical_size,
        "si_created": iso(entry.si.timestamps.created),
        "si_modified": iso(entry.si.timestamps.modified),
        "si_mft_modified": iso(entry.si.timestamps.mft_modified),
        "si_accessed": iso(entry.si.timestamps.accessed),
        "fn_created": iso(fn_ts.created) if fn_ts else "",
        "fn_modified": iso(fn_ts.modified) if fn_ts else "",
        "fn_mft_modified": iso(fn_ts.mft_modified) if fn_ts else "",
        "fn_accessed": iso(fn_ts.accessed) if fn_ts else "",
        "fn_namespace": fn.namespace_name if fn else "",
        "file_attributes": describe_file_attributes(entry.si.file_attributes),
        "ads_names": " | ".join(entry.ads_names),
        "zone_id": entry.zone_id,
        "zone": zone_label(entry.zone_id),
        "download_url": entry.zone_host_url,
        "download_referrer": entry.zone_referrer_url,
        "has_reparse_point": entry.has_reparse_point,
        "has_attribute_list": entry.has_attribute_list,
        "resident_data_len": len(entry.resident_data) or "",
        "content_type": (detect_content_type(entry.resident_data)[0] or "")
                        if entry.resident_data else "",

        # Resident content
        "resident_preview": resident_preview(entry.resident_data),
        "attributes": entry.attribute_types,
        "parse_error": entry.parse_error,
    }


def logfile_row(event) -> dict:
    return {
        "lsn": event.lsn,
        "transaction_id": event.transaction_id,
        "action": event.action,
        "redo_op": event.redo_op,
        "undo_op": event.undo_op,
        "source": event.source,
        "name": event.name,
        "extension": event.extension,
        "path": event.path,
        "path_source": event.path_source,
        "mft_record": event.mft_record if event.mft_record is not None else "",
        "mft_sequence": event.mft_sequence if event.mft_sequence is not None else "",
        "parent_record": event.parent_record,
        "parent_sequence": event.parent_sequence,
        "fn_created": iso(event.created),
        "fn_modified": iso(event.modified),
        "fn_mft_modified": iso(event.mft_modified),
        "fn_accessed": iso(event.accessed),
        "real_size": event.real_size,
        "allocated_size": event.allocated_size,
        "file_attributes": f"0x{event.file_attributes:08X}" if event.file_attributes else "",
        "namespace": "DOS (8.3 alias)" if event.is_dos_alias else "WIN32",
        "page_offset": event.page_offset,
    }


def humanise_seconds(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 90:
        return f"{seconds:.1f} s"
    if seconds < 5400:
        return f"{seconds / 60:.1f} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} d"


def usn_row(record) -> dict:
    return {
        "usn": record.usn,
        "timestamp": iso(record.timestamp),
        "action": record.primary_action,
        "reason": record.reason_text,
        "source_info": record.source_text,
        "name": record.name,
        "extension": record.extension,
        "path": record.path,
        "path_source": record.path_source,
        "file_record": record.file_record,
        "file_sequence": record.file_sequence,
        "parent_record": record.parent_record,
        "parent_sequence": record.parent_sequence,
        "is_directory": record.is_directory,
        "file_attributes": f"0x{record.file_attributes:08X}" if record.file_attributes else "",
        "security_id": record.security_id or "",
        "version": record.version,
        "offset": record.offset,
    }


def lifetime_row(lifetime, matches=None) -> dict:
    matches = matches or []
    best = matches[0] if matches else None
    name = lifetime.name
    return {
        "seconds": f"{lifetime.seconds:.3f}",
        "lifetime": humanise_seconds(lifetime.seconds),
        "name": name,
        "extension": "." + name.rsplit(".", 1)[-1].lower() if "." in name else "",
        "path": lifetime.path,
        "path_source": lifetime.path_source,
        "os_churn": "true" if is_noise(lifetime.path) else "",
        "created": iso(lifetime.created),
        "deleted": iso(lifetime.deleted),
        "file_record": lifetime.file_record,
        "file_sequence": lifetime.file_sequence,
        "parent_record": lifetime.parent_record,
        "severity": best.severity if best else "",
        "rules": " | ".join(sorted({m.rule_name for m in matches})),
        "extracted": "; ".join(sorted({m.extracted_str for m in matches if m.extracted_str})),
    }


def timeline_rows_from_usn(record, matches=None):
    """One row per journal record."""
    if not record.timestamp:
        return
    best = matches[0] if matches else None
    yield timeline_row(
        timestamp=iso(record.timestamp), artifact="$UsnJrnl",
        source_attribute="USN", action=record.primary_action,
        name=record.name, extension=record.extension, path=record.path,
        record_number=record.file_record, lsn=record.usn,
        rule=best.rule_name if best else "",
        severity=best.severity if best else "",
        extracted=best.extracted_str if best else "",
        notes=record.reason_text,
    )


def execution_row(item) -> dict:
    return {
        "first_executed": iso(item.first_seen),
        "last_executed": iso(item.last_seen),
        "image": item.image,
        "severity": item.severity,
        "category": item.lolbin_category,
        "notes": item.notes,
        "binary_present": item.binary_present,
        "binary_path": " | ".join(item.binary_paths),
        "outside_windows": item.binary_outside_windows,
        "prefetch_file": item.prefetch_name,
        "prefetch_deleted": item.prefetch_deleted,
        "path_hash": item.path_hash,
        "source": item.source,
    }


def rename_row(rename) -> dict:
    return {
        "timestamp": iso(rename.timestamp),
        "severity": rename.severity,
        "old_name": rename.old_name,
        "new_name": rename.new_name,
        "notes": rename.notes,
        "old_path": rename.old_path,
        "new_path": rename.new_path,
        "hop": rename.hop,
        "total_hops": rename.total_hops,
        "os_churn": "true" if rename.os_churn else "",
        "path_source": rename.path_source,
        "file_record": rename.file_record,
        "file_sequence": rename.file_sequence,
    }


def host_artifact_row(artifact) -> dict:
    return {
        "category": artifact.category,
        "severity": artifact.severity,
        "name": artifact.name,
        "detail": artifact.detail,
        "timestamp": iso(artifact.timestamp),
        "last_modified": iso(artifact.last_modified),
        "size": artifact.size or "",
        "path": artifact.path,
        "notes": artifact.notes,
    }


def timeline_rows_from_rename(rename):
    if not rename.timestamp:
        return
    yield timeline_row(
        timestamp=iso(rename.timestamp), artifact="$UsnJrnl",
        source_attribute="USN", action="Rename",
        name=rename.new_name, extension=rename.new_extension,
        path=rename.new_path, record_number=rename.file_record,
        severity=rename.severity, extracted=f"from={rename.old_name}",
        notes=rename.notes,
    )


def timeline_rows_from_host_artifact(artifact):
    if not artifact.timestamp:
        return
    yield timeline_row(
        timestamp=iso(artifact.timestamp), artifact=artifact.category,
        source_attribute="$SI", action=artifact.detail, name=artifact.name,
        path=artifact.path, size=artifact.size or "",
        severity=artifact.severity, notes=artifact.notes,
    )


def timeline_rows_from_execution(item):
    """First and last execution as two timeline points."""
    for label, when in (("FirstExecuted", item.first_seen),
                        ("LastExecuted", item.last_seen)):
        if not when:
            continue
        yield timeline_row(
            timestamp=iso(when), artifact="Prefetch", source_attribute="$SI",
            action=label, name=item.image, extension=".exe",
            path=" | ".join(item.binary_paths),
            is_deleted="" if item.binary_present else "true",
            rule=item.lolbin_category, severity=item.severity,
            notes=item.notes,
        )

MACB_LABELS = [
    ("modified", "M..."),
    ("accessed", ".A.."),
    ("mft_modified", "..C."),
    ("created", "...B"),
]


def timeline_rows_from_entry(entry, matches=None) -> Iterable[dict]:
    best = matches[0] if matches else None
    sources = [("$SI", entry.si.timestamps)]
    if entry.best_fn:
        sources.append(("$FN", entry.best_fn.timestamps))

    for source, stamps in sources:
        for attribute, macb in MACB_LABELS:
            value = getattr(stamps, attribute)
            if not value:
                continue
            yield timeline_row(
                timestamp=iso(value), artifact="$MFT",
                source_attribute=source, macb=macb,
                action="deleted-record" if entry.is_deleted else "",
                name=entry.name, extension=entry.extension, path=entry.path,
                is_deleted=entry.is_deleted, size=entry.logical_size,
                record_number=entry.record_number,
                rule=best.rule_name if best else "",
                severity=best.severity if best else "",
                extracted=best.extracted_str if best else "",
                notes=entry.path_note,
            )


def timeline_rows_from_event(event, matches=None) -> Iterable[dict]:
    best = matches[0] if matches else None
    for attribute, macb in MACB_LABELS:
        value = getattr(event, attribute)
        if not value:
            continue
        yield timeline_row(
            timestamp=iso(value), artifact="$LogFile", source_attribute="$FN",
            macb=macb, action=event.action, name=event.name,
            extension=event.extension, path=event.path, size=event.real_size,
            record_number=event.mft_record if event.mft_record is not None else "",
            lsn=event.lsn,
            rule=best.rule_name if best else "",
            severity=best.severity if best else "",
            extracted=best.extracted_str if best else "",
            notes=f"{event.source}; {event.path_source}",
        )


def write_timeline(path: Path, rows: List[dict]) -> int:
    rows.sort(key=lambda r: r["timestamp"])
    with CsvWriter(path, TIMELINE_FIELDS) as w:
        for row in rows:
            w.write(row)
        return w.count
