"""
$MFT parsing and path reconstruction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import ntfs
from .paths import is_noise
from .ntfs import _SLOTS
from .ntfs import (
    ATTR_ATTRIBUTE_LIST,
    ATTR_DATA,
    ATTR_FILE_NAME,
    ATTR_REPARSE_POINT,
    ATTR_STANDARD_INFORMATION,
    Attribute,
    FileNameAttr,
    NAMESPACE_DOS,
    StandardInformation,
    ROOT_RECORD_NUMBER,
)

FLAG_IN_USE = 0x0001
FLAG_IS_DIRECTORY = 0x0002

MAX_RESIDENT_CARVE = 4096


@dataclass(**_SLOTS)
class MftEntry:
    record_number: int
    sequence_number: int = 0
    in_use: bool = False
    is_directory: bool = False
    base_record: int = 0
    base_sequence: int = 0
    hard_link_count: int = 0
    used_size: int = 0
    allocated_size: int = 0

    si: StandardInformation = field(default_factory=StandardInformation)
    file_names: List[FileNameAttr] = field(default_factory=list)
    best_fn: Optional[FileNameAttr] = None

    name: str = ""
    extension: str = ""
    path: str = ""
    all_paths: List[str] = field(default_factory=list)
    path_reliable: bool = True
    path_note: str = ""

    logical_size: int = 0
    physical_size: int = 0
    ads_names: List[str] = field(default_factory=list)
    resident_data: bytes = b""
    zone_id: str = ""
    zone_host_url: str = ""
    zone_referrer_url: str = ""
    has_reparse_point: bool = False
    has_attribute_list: bool = False
    attribute_types: str = ""

    parse_error: str = ""

    @property
    def is_deleted(self) -> bool:
        return not self.in_use

    @property
    def is_extension_record(self) -> bool:
        """True for records that are continuations of another base record."""
        return self.base_record != 0

    @property
    def parent_record(self) -> Optional[int]:
        return self.best_fn.parent_record if self.best_fn else None


def parse_zone_identifier(raw: bytes) -> dict:
    """Decode a $DATA:Zone.Identifier stream."""
    if not raw:
        return {}

    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")

    values = {}
    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            values[key] = value
    return values


def get_extension(name: str) -> str:
    base = name.rsplit("\\", 1)[-1]
    if "." not in base or base.startswith(".") and base.count(".") == 1:
        return ""
    return "." + base.rsplit(".", 1)[-1].lower()


def parse_record(raw: bytes, record_number: int, record_size: int) -> Optional[MftEntry]:
    """Parse one MFT record. Returns None only for slack/zeroed slots."""
    if len(raw) < 48 or raw[0:4] not in (b"FILE", b"BAAD"):
        return None

    entry = MftEntry(record_number=record_number)

    fix = ntfs.apply_fixup(raw, record_size)
    data = fix.data
    if fix.warning:
        entry.parse_error = fix.warning

    if raw[0:4] == b"BAAD":
        entry.parse_error = ("BAAD record; " + entry.parse_error).strip("; ")

    try:
        entry.sequence_number = ntfs.u16(data, 16)
        entry.hard_link_count = ntfs.u16(data, 18)
        first_attr_offset = ntfs.u16(data, 20)
        flags = ntfs.u16(data, 22)
        entry.used_size = ntfs.u32(data, 24)
        entry.allocated_size = ntfs.u32(data, 28)
        base_ref = ntfs.u64(data, 32)

        entry.in_use = bool(flags & FLAG_IN_USE)
        entry.is_directory = bool(flags & FLAG_IS_DIRECTORY)
        entry.base_record = ntfs.ref_record(base_ref)
        entry.base_sequence = ntfs.ref_sequence(base_ref)

        if first_attr_offset < 42 or first_attr_offset >= len(data):
            entry.parse_error = (entry.parse_error + "; bad attribute offset").strip("; ")
            return entry

        seen_types = []
        for attr in ntfs.iter_attributes(data, first_attr_offset):
            seen_types.append(attr.type_name + (f":{attr.name}" if attr.name else ""))
            _absorb_attribute(entry, attr)

        entry.attribute_types = " | ".join(seen_types)

    except Exception as exc: # never let one record kill the run
        entry.parse_error = (entry.parse_error + f"; {type(exc).__name__}: {exc}").strip("; ")

    entry.best_fn = ntfs.choose_best_filename(entry.file_names)
    if entry.best_fn:
        entry.name = entry.best_fn.name
        entry.extension = get_extension(entry.name)
        if not entry.logical_size:
            entry.logical_size = entry.best_fn.real_size
            entry.physical_size = entry.best_fn.allocated_size
    else:
        entry.name = f"[NoFileName-{record_number}]"

    return entry


def _absorb_attribute(entry: MftEntry, attr: Attribute) -> None:
    if attr.type_id == ATTR_STANDARD_INFORMATION and attr.content:
        entry.si = ntfs.parse_standard_information(attr.content)

    elif attr.type_id == ATTR_FILE_NAME and attr.content:
        fn = ntfs.parse_file_name(attr.content)
        if fn:
            entry.file_names.append(fn)

    elif attr.type_id == ATTR_ATTRIBUTE_LIST:
        entry.has_attribute_list = True

    elif attr.type_id == ATTR_REPARSE_POINT:
        entry.has_reparse_point = True

    elif attr.type_id == ATTR_DATA:
        if attr.name:
            entry.ads_names.append(attr.name)
            # Zone.Identifier is tiny and resident, so provenance needs no volume.
            if attr.name.lower() == "zone.identifier" and attr.content:
                zone = parse_zone_identifier(attr.content)
                entry.zone_id = zone.get("zoneid", "")
                entry.zone_host_url = zone.get("hosturl", "")
                entry.zone_referrer_url = zone.get("referrerurl", "")
        else:
            if attr.non_resident:
                entry.logical_size = attr.real_size
                entry.physical_size = attr.allocated_size
            else:
                entry.logical_size = len(attr.content)
                entry.physical_size = len(attr.content)
                if 0 < len(attr.content) <= MAX_RESIDENT_CARVE:
                    entry.resident_data = attr.content


# File-level parsing

def detect_record_size(path: Path, default: int = 1024) -> int:
    """Infer record size by locating the second FILE signature."""
    with path.open("rb") as fh:
        head = fh.read(8192)
    if head[0:4] not in (b"FILE", b"BAAD"):
        return default
    for candidate in (1024, 4096, 512, 2048):
        if len(head) > candidate and head[candidate:candidate + 4] in (b"FILE", b"BAAD"):
            return candidate
    return default


def parse_mft(path: Path, record_size: int, progress=None,) -> Dict[int, MftEntry]:
    """Parse an entire $MFT into a record-number keyed dict."""
    entries: Dict[int, MftEntry] = {}
    total = path.stat().st_size // record_size

    with path.open("rb") as fh:
        number = 0
        while True:
            raw = fh.read(record_size)
            if len(raw) < record_size:
                break
            entry = parse_record(raw, number, record_size)
            if entry is not None:
                entries[number] = entry
            number += 1
            if progress and number % 25000 == 0:
                if progress(number, total) is False:
                    break

    if progress:
        progress(number, total)
    merge_extension_records(entries)
    return entries


def merge_extension_records(entries: Dict[int, MftEntry]) -> None:
    """Fold extension records into their base record and drop them."""

    for number in [n for n, e in entries.items() if e.base_record]:
        ext = entries[number]
        base = entries.get(ext.base_record)
        if base is None or base.base_record or base.sequence_number != ext.base_sequence:
            continue
        base.file_names.extend(ext.file_names)
        for name in ext.ads_names:
            if name not in base.ads_names:
                base.ads_names.append(name)
        if ext.zone_id and not base.zone_id:
            base.zone_id = ext.zone_id
            base.zone_host_url = ext.zone_host_url
            base.zone_referrer_url = ext.zone_referrer_url
        if ext.logical_size and not base.logical_size:
            base.logical_size = ext.logical_size
            base.physical_size = ext.physical_size
        if ext.resident_data and not base.resident_data:
            base.resident_data = ext.resident_data
        base.has_reparse_point = base.has_reparse_point or ext.has_reparse_point
        if ext.attribute_types:
            base.attribute_types = " | ".join(t for t in (base.attribute_types, ext.attribute_types) if t)
        best = ntfs.choose_best_filename(base.file_names)
        if best is not None:
            base.best_fn = best
            base.name = best.name
            base.extension = get_extension(best.name)
            if not base.logical_size:
                base.logical_size = best.real_size
                base.physical_size = best.allocated_size
        del entries[number]


# Path reconstruction

def parent_deleted(parent: MftEntry, expected_sequence: int) -> bool:
    """True when the parent record is the deleted directory the child named."""
    return not parent.in_use and parent.sequence_number == expected_sequence + 1


def primary_file_names(names: List[FileNameAttr]) -> List[FileNameAttr]:
    """Drop 8.3 aliases that only duplicate a long name in the same directory."""
    long_parents = {fn.parent_record for fn in names if fn.namespace != NAMESPACE_DOS}
    return [fn for fn in names
            if fn.namespace != NAMESPACE_DOS or fn.parent_record not in long_parents]


def build_paths(entries: Dict[int, MftEntry], release_file_names: bool = True) -> None:
    """Reconstruct full paths, recording reliability."""
    cache: Dict[int, tuple] = {}

    def resolve(record_number: int, depth: int, stack: frozenset) -> tuple:
        if record_number in cache:
            return cache[record_number]

        if record_number == ROOT_RECORD_NUMBER:
            return "", True, ""

        if depth > 128:
            return f"\\$DepthLimit\\{record_number}", False, "depth limit exceeded"

        if record_number in stack:
            return f"\\$Cycle\\{record_number}", False, "parent cycle detected"

        entry = entries.get(record_number)
        if entry is None or entry.best_fn is None:
            return f"\\$Orphan\\{record_number}", False, "parent record missing or nameless"

        fn = entry.best_fn
        parent_path, parent_ok, note = resolve(fn.parent_record, depth + 1, stack | {record_number})

        parent = entries.get(fn.parent_record)
        if parent is not None and fn.parent_sequence and parent.sequence_number != fn.parent_sequence:
            if parent_deleted(parent, fn.parent_sequence):
                note = note or "parent directory deleted"
            else:
                parent_ok = False
                note = (
                    f"parent sequence mismatch (child expects {fn.parent_sequence}, "
                    f"record {fn.parent_record} is at {parent.sequence_number})"
                )
        elif parent is not None and not parent.is_directory:
            parent_ok = False
            note = note or "parent record is not a directory"

        result = (parent_path + "\\" + entry.name, parent_ok, note)
        if "depth limit" not in note:
            cache[record_number] = result
        return result

    for number, entry in entries.items():
        if number == ROOT_RECORD_NUMBER:
            entry.path = "\\"
            entry.all_paths = []
            if release_file_names:
                entry.file_names = []
            continue

        paths = []
        reliable = True
        note = ""

        for fn in primary_file_names(entry.file_names or []):
            parent_path, ok, why = resolve(fn.parent_record, 0, frozenset({number}))
            candidate = (parent_path + "\\" + fn.name) or "\\"

            parent = entries.get(fn.parent_record)
            if parent is not None and fn.parent_sequence and parent.sequence_number != fn.parent_sequence:
                if parent_deleted(parent, fn.parent_sequence):
                    why = why or "parent directory deleted"
                else:
                    ok = False
                    why = (
                        f"parent sequence mismatch (expects {fn.parent_sequence}, "
                        f"found {parent.sequence_number})"
                    )
            elif parent is None:
                ok = False
                why = why or f"parent record {fn.parent_record} not present in MFT"

            paths.append(candidate)
            if not ok:
                reliable = False
                note = note or why

        if not paths:
            paths = [f"\\$Orphan\\{entry.name}"]
            reliable = False
            note = "no $FILE_NAME attribute"

        best_index = 0
        primary = primary_file_names(entry.file_names or [])
        if entry.best_fn is not None and entry.best_fn in primary:
            best_index = min(primary.index(entry.best_fn), len(paths) - 1)

        if len(paths) > 1:
            ranked = sorted(range(len(paths)),
                            key=lambda i: (is_noise(paths[i]), i != best_index, i))
            best_index = ranked[0]

        entry.path = paths[best_index]
        # Only keep the list when it says something the primary path does not
        entry.all_paths = paths if len(paths) > 1 else []
        entry.path_reliable = reliable
        entry.path_note = note

        if release_file_names:
            entry.file_names = []
