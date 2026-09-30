"""
$UsnJrnl:$J parsing.
$LogFile covers hours to days.
$J covers weeks and records why each change happened.
"""

from __future__ import annotations

import datetime
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from . import ntfs
from .filetypes import SYSTEM_BINARY_NAMES
from .paths import is_resolved_source, resolve_child_path

# Reason flags. USN_REASON_CLOSE is set on the final record for a change set.
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
USN_REASON_NAMED_DATA_EXTEND = 0x00000020
USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_INDEXABLE_CHANGE = 0x00004000
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_HARD_LINK_CHANGE = 0x00010000
USN_REASON_COMPRESSION_CHANGE = 0x00020000
USN_REASON_ENCRYPTION_CHANGE = 0x00040000
USN_REASON_OBJECT_ID_CHANGE = 0x00080000
USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
USN_REASON_STREAM_CHANGE = 0x00200000
USN_REASON_TRANSACTED_CHANGE = 0x00400000
USN_REASON_INTEGRITY_CHANGE = 0x00800000
USN_REASON_CLOSE = 0x80000000

REASON_NAMES = [
    (USN_REASON_DATA_OVERWRITE, "DATA_OVERWRITE"),
    (USN_REASON_DATA_EXTEND, "DATA_EXTEND"),
    (USN_REASON_DATA_TRUNCATION, "DATA_TRUNCATION"),
    (USN_REASON_NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE"),
    (USN_REASON_NAMED_DATA_EXTEND, "NAMED_DATA_EXTEND"),
    (USN_REASON_NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION"),
    (USN_REASON_FILE_CREATE, "FILE_CREATE"),
    (USN_REASON_FILE_DELETE, "FILE_DELETE"),
    (USN_REASON_EA_CHANGE, "EA_CHANGE"),
    (USN_REASON_SECURITY_CHANGE, "SECURITY_CHANGE"),
    (USN_REASON_RENAME_OLD_NAME, "RENAME_OLD_NAME"),
    (USN_REASON_RENAME_NEW_NAME, "RENAME_NEW_NAME"),
    (USN_REASON_INDEXABLE_CHANGE, "INDEXABLE_CHANGE"),
    (USN_REASON_BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE"),
    (USN_REASON_HARD_LINK_CHANGE, "HARD_LINK_CHANGE"),
    (USN_REASON_COMPRESSION_CHANGE, "COMPRESSION_CHANGE"),
    (USN_REASON_ENCRYPTION_CHANGE, "ENCRYPTION_CHANGE"),
    (USN_REASON_OBJECT_ID_CHANGE, "OBJECT_ID_CHANGE"),
    (USN_REASON_REPARSE_POINT_CHANGE, "REPARSE_POINT_CHANGE"),
    (USN_REASON_STREAM_CHANGE, "STREAM_CHANGE"),
    (USN_REASON_TRANSACTED_CHANGE, "TRANSACTED_CHANGE"),
    (USN_REASON_INTEGRITY_CHANGE, "INTEGRITY_CHANGE"),
    (USN_REASON_CLOSE, "CLOSE"),
]

SOURCE_NAMES = [
    (0x00000001, "DATA_MANAGEMENT"),
    (0x00000002, "AUXILIARY_DATA"),
    (0x00000004, "REPLICATION_MANAGEMENT"),
    (0x00000008, "CLIENT_REPLICATION_MANAGEMENT"),
]

FILE_ATTRIBUTE_DIRECTORY = 0x00000010

# Header sizes up to the filename fields.
V2_HEADER = 0x3C
V3_HEADER = 0x4C

MIN_RECORD = 0x38
MAX_RECORD = 4096 # 0x4C + 255*2 + padding leaves plenty of headroom
ZERO8 = b"\x00" * 8

# A busy volume yields hundreds of thousands of journal records. __slots__ drops
# the per-instance __dict__, which is a large share of the footprint at that
# count. dataclass gained slots= in 3.10, so 3.9 keeps the dict.
_SLOTS = {"slots": True} if sys.version_info >= (3, 10) else {}


def describe_reason(flags: int) -> str:
    names = [name for bit, name in REASON_NAMES if flags & bit]
    return " | ".join(names) if names else f"0x{flags:08X}"


def describe_source(flags: int) -> str:
    return " | ".join(name for bit, name in SOURCE_NAMES if flags & bit)


@dataclass(**_SLOTS)
class UsnRecord:
    usn: int
    version: str
    timestamp: Optional[datetime.datetime]
    name: str
    file_record: int
    file_sequence: int
    parent_record: int
    parent_sequence: int
    reason: int
    source_info: int
    security_id: int
    file_attributes: int
    offset: int

    path: str = ""
    path_source: str = ""

    @property
    def reason_text(self) -> str:
        return describe_reason(self.reason)

    @property
    def source_text(self) -> str:
        return describe_source(self.source_info)

    @property
    def is_directory(self) -> bool:
        return bool(self.file_attributes & FILE_ATTRIBUTE_DIRECTORY)

    @property
    def extension(self) -> str:
        return "." + self.name.rsplit(".", 1)[-1].lower() if "." in self.name else ""

    @property
    def primary_action(self) -> str:
        for bit, label in (
            (USN_REASON_FILE_DELETE, "FileDelete"),
            (USN_REASON_FILE_CREATE, "FileCreate"),
            (USN_REASON_RENAME_NEW_NAME, "RenameNew"),
            (USN_REASON_RENAME_OLD_NAME, "RenameOld"),
            (USN_REASON_NAMED_DATA_OVERWRITE, "StreamWrite"),
            (USN_REASON_NAMED_DATA_EXTEND, "StreamWrite"),
            (USN_REASON_STREAM_CHANGE, "StreamChange"),
            (USN_REASON_SECURITY_CHANGE, "SecurityChange"),
            (USN_REASON_BASIC_INFO_CHANGE, "BasicInfoChange"),
            (USN_REASON_DATA_EXTEND, "DataExtend"),
            (USN_REASON_DATA_OVERWRITE, "DataOverwrite"),
            (USN_REASON_DATA_TRUNCATION, "DataTruncate"),
        ):
            if self.reason & bit:
                return label
        return "Other"


# Record decoding

def _plausible(buf: bytes, pos: int, remaining: int) -> Optional[int]:
    """Return the record length if a valid header starts at pos, else None."""
    if pos + 8 > len(buf):
        return None
    length = ntfs.u32(buf, pos)
    if length < MIN_RECORD or length > MAX_RECORD or length % 8:
        return None
    major = ntfs.u16(buf, pos + 4)
    if major not in (2, 3, 4):
        return None
    return length


def decode_record(raw: bytes, offset: int) -> Optional[UsnRecord]:
    """Decode one USN_RECORD. Returns None for V4 and for malformed records."""
    if len(raw) < MIN_RECORD:
        return None

    major = ntfs.u16(raw, 4)

    if major == 2:
        header = V2_HEADER
        if len(raw) < header:
            return None
        file_ref = ntfs.u64(raw, 0x08)
        parent_ref = ntfs.u64(raw, 0x10)
        file_record, file_sequence = ntfs.ref_record(file_ref), ntfs.ref_sequence(file_ref)
        parent_record, parent_sequence = ntfs.ref_record(parent_ref), ntfs.ref_sequence(parent_ref)
        usn = ntfs.u64(raw, 0x18)
        timestamp = ntfs.filetime_to_dt(ntfs.u64(raw, 0x20))
        reason = ntfs.u32(raw, 0x28)
        source_info = ntfs.u32(raw, 0x2C)
        security_id = ntfs.u32(raw, 0x30)
        attributes = ntfs.u32(raw, 0x34)
        name_len = ntfs.u16(raw, 0x38)
        name_off = ntfs.u16(raw, 0x3A)

    elif major == 3:
        header = V3_HEADER
        if len(raw) < header:
            return None
        # FILE_ID_128: the low 8 bytes still carry the MFT reference on NTFS.
        file_ref = ntfs.u64(raw, 0x08)
        parent_ref = ntfs.u64(raw, 0x18)
        file_record, file_sequence = ntfs.ref_record(file_ref), ntfs.ref_sequence(file_ref)
        parent_record, parent_sequence = ntfs.ref_record(parent_ref), ntfs.ref_sequence(parent_ref)
        usn = ntfs.u64(raw, 0x28)
        timestamp = ntfs.filetime_to_dt(ntfs.u64(raw, 0x30))
        reason = ntfs.u32(raw, 0x38)
        source_info = ntfs.u32(raw, 0x3C)
        security_id = ntfs.u32(raw, 0x40)
        attributes = ntfs.u32(raw, 0x44)
        name_len = ntfs.u16(raw, 0x48)
        name_off = ntfs.u16(raw, 0x4A)

    else:
        # V4 records describe extents of a change already reported by a V3
        # record and carry no filename of their own.
        return None

    if name_len == 0 or name_len % 2 or name_off < header:
        return None
    if name_off + name_len > len(raw):
        return None

    name = ntfs.decode_utf16le(raw[name_off:name_off + name_len])
    if not name or ntfs.has_illegal_chars(name):
        return None

    return UsnRecord(
        usn=usn,
        version=f"{major}.{ntfs.u16(raw, 6)}",
        timestamp=timestamp,
        name=name,
        file_record=file_record,
        file_sequence=file_sequence,
        parent_record=parent_record,
        parent_sequence=parent_sequence,
        reason=reason,
        source_info=source_info,
        security_id=security_id,
        file_attributes=attributes,
        offset=offset,
    )


# Streaming

CHUNK = 4 << 20
_NON_ZERO = re.compile(rb"[^\x00]")


def parse_usnjrnl(path: Path, progress=None) -> Iterator[UsnRecord]:
    """Stream records out of a raw $J stream with flat memory use.
    Sparse regions are skipped with bytes.lstrip, since a zero run at the head of
    the journal is otherwise millions of Python level iterations.
    """
    total = max(path.stat().st_size, 1)
    seen = 0

    with path.open("rb") as fh:
        buf = b""
        base = 0
        exhausted = False

        while True:
            if not exhausted:
                data = fh.read(CHUNK)
                if not data:
                    exhausted = True
                else:
                    buf += data
                    seen += len(data)
                    if progress:
                        if progress(seen, total) is False:
                            break

            pos = 0
            while pos + MIN_RECORD <= len(buf):
                length = _plausible(buf, pos, len(buf) - pos)

                if length is None:
                    if buf[pos:pos + 8] == ZERO8:
                        # Sparse or deallocated region: jump to the next
                        # non-zero byte in one C-level search, without copying.
                        found = _NON_ZERO.search(buf, pos)
                        skip = (found.start() if found else len(buf)) - pos
                        pos += max(8, skip - (skip % 8))
                    else:
                        pos += 8
                    continue

                if pos + length > len(buf):
                    if exhausted:
                        pos = len(buf)
                    break  # need more data for this record

                record = decode_record(buf[pos:pos + length], base + pos)
                if record is not None:
                    yield record
                pos += length

            buf = buf[pos:]
            base += pos

            if exhausted:
                break

    if progress:
        progress(total, total)


# Path resolution

def resolve_usn_paths(records: List[UsnRecord], mft_entries: Dict[int, object]) -> None:
    """Attach directory context to journal records using a parsed $MFT."""
    for record in records:
        record.path, record.path_source = resolve_child_path(
            mft_entries.get(record.parent_record), record.name,
            record.parent_record, record.parent_sequence,
        )


# Lifetime correlation

@dataclass(**_SLOTS)
class FileLifetime:
    """A file the journal saw both created and deleted."""
    file_record: int
    file_sequence: int
    name: str
    path: str
    created: datetime.datetime
    deleted: datetime.datetime
    parent_record: int
    path_source: str = ""

    @property
    def seconds(self) -> float:
        return (self.deleted - self.created).total_seconds()


def correlate_lifetimes(records: List[UsnRecord]) -> List[FileLifetime]:
    """Pair FILE_CREATE with FILE_DELETE for the same file reference.
    Matching on record and sequence keeps two files that reused one MFT record
    apart. Short lived files are typical of tooling that cleans up after itself.
    """
    created: Dict[tuple, UsnRecord] = {}
    lifetimes: List[FileLifetime] = []

    for record in records:
        if record.timestamp is None:
            continue
        key = (record.file_record, record.file_sequence)

        if record.reason & USN_REASON_FILE_CREATE:
            existing = created.get(key)
            if existing is None or record.timestamp < existing.timestamp:
                created[key] = record

        if record.reason & USN_REASON_FILE_DELETE:
            birth = created.pop(key, None)
            if birth is not None and record.timestamp >= birth.timestamp:
                lifetimes.append(FileLifetime(
                    file_record=record.file_record,
                    file_sequence=record.file_sequence,
                    name=record.name,
                    path=record.path or birth.path,
                    created=birth.timestamp,
                    deleted=record.timestamp,
                    parent_record=record.parent_record,
                    path_source=record.path_source or birth.path_source,
                ))

    lifetimes.sort(key=lambda item: item.seconds)
    return lifetimes


# Rename correlation



@dataclass(**_SLOTS)
class Rename:
    """One rename hop: a file changing name, directory, or both."""
    file_record: int
    file_sequence: int
    timestamp: Optional[datetime.datetime]
    old_name: str
    new_name: str
    old_path: str
    new_path: str
    path_source: str = ""
    hop: int = 1
    total_hops: int = 1

    @property
    def path_reliable(self) -> bool:
        return is_resolved_source(self.path_source)

    @property
    def moved(self) -> bool:
        # Without an $MFT the paths are bare names and say nothing about directories.
        if "\\" not in self.old_path or "\\" not in self.new_path:
            return False
        return self.old_path.rsplit("\\", 1)[0].lower() != \
            self.new_path.rsplit("\\", 1)[0].lower()

    @property
    def renamed(self) -> bool:
        return self.old_name.lower() != self.new_name.lower()

    @staticmethod
    def _extension(name: str) -> str:
        return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""

    @property
    def old_extension(self) -> str:
        return self._extension(self.old_name)

    @property
    def new_extension(self) -> str:
        return self._extension(self.new_name)

    @property
    def os_churn(self) -> bool:
        """True for renames that are ordinary system housekeeping.
        ESE log rotation and installer temp-to-final renames dominate a real journal.
        Both happen inside install managed directories, which separates them from an
        operator renaming a payload in a user profile.
        """
        from .paths import is_install_managed, is_noise

        target = self.new_path or self.new_name
        return is_noise(target) or is_install_managed(target, self.new_name)

    @property
    def notes(self) -> str:
        from .filetypes import EXECUTABLE_EXTENSIONS

        parts = []
        if self.new_name.lower() in SYSTEM_BINARY_NAMES:
            parts.append("renamed onto a system binary name")
        if (self.new_extension in EXECUTABLE_EXTENSIONS
                and self.old_extension not in EXECUTABLE_EXTENSIONS):
            parts.append("became executable")
        if self.moved and self.renamed:
            parts.append("moved and renamed")
        elif self.moved:
            parts.append("moved")
        if self.total_hops > 2:
            parts.append(f"{self.total_hops} hops in the chain")
        return "; ".join(parts)

    @property
    def severity(self) -> str:
        """
        Chain length is deliberately not a severity signal: database log
        rotation routinely produces 30-plus hops and would otherwise dominate.
        """
        from .filetypes import EXECUTABLE_EXTENSIONS

        if self.new_name.lower() in SYSTEM_BINARY_NAMES:
            return "critical"
        if self.os_churn:
            return ""

        if not self.path_reliable:
            return ""
        if (self.new_extension in EXECUTABLE_EXTENSIONS
                and self.old_extension not in EXECUTABLE_EXTENSIONS):
            return "high"
        if self.new_extension in EXECUTABLE_EXTENSIONS and self.moved:
            return "medium"
        return ""


def correlate_renames(records: List[UsnRecord]) -> List[Rename]:
    """Pair RENAME_OLD_NAME with RENAME_NEW_NAME for the same file reference.
    The $MFT shows only a file's final name. The journal shows every name it had
    before that. Hops are numbered per file.
    """
    pending: Dict[tuple, UsnRecord] = {}
    renames: List[Rename] = []

    for record in records:
        key = (record.file_record, record.file_sequence)

        if record.reason & USN_REASON_RENAME_OLD_NAME:
            pending[key] = record
            continue

        if record.reason & USN_REASON_RENAME_NEW_NAME:
            previous = pending.pop(key, None)
            if previous is None:
                continue
            renames.append(Rename(
                file_record=record.file_record,
                file_sequence=record.file_sequence,
                timestamp=record.timestamp or previous.timestamp,
                old_name=previous.name,
                new_name=record.name,
                old_path=previous.path or previous.name,
                new_path=record.path or record.name,
                path_source=record.path_source,
            ))

    # Number the hops within each file's chain.
    chains: Dict[tuple, List[Rename]] = {}
    for rename in renames:
        chains.setdefault((rename.file_record, rename.file_sequence), []).append(rename)
    for chain in chains.values():
        chain.sort(key=lambda r: (r.timestamp or datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc)))
        for index, rename in enumerate(chain, start=1):
            rename.hop = index
            rename.total_hops = len(chain)

    renames.sort(key=lambda r: (r.timestamp or datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc)))
    return renames
