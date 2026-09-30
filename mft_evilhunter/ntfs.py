"""
Low-level NTFS structures shared by the $MFT and $LogFile parsers.
"""

from __future__ import annotations

import datetime
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

# Constants
_SLOTS = {"slots": True} if sys.version_info >= (3, 10) else {}

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# Sanity window for FILETIME values. Used to reject garbage when carving
# structures out of unstructured $LogFile payloads.
MIN_SANE_TIME = datetime.datetime(1980, 1, 1, tzinfo=datetime.timezone.utc)
MAX_SANE_TIME = datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc)

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_END = 0xFFFFFFFF

ATTR_EA_INFORMATION = 0xD0
ATTR_EA = 0xE0
ATTR_LOGGED_UTILITY_STREAM = 0x100

ATTRIBUTE_NAMES = {
    ATTR_STANDARD_INFORMATION: "$STANDARD_INFORMATION",
    ATTR_ATTRIBUTE_LIST: "$ATTRIBUTE_LIST",
    ATTR_FILE_NAME: "$FILE_NAME",
    ATTR_OBJECT_ID: "$OBJECT_ID",
    ATTR_SECURITY_DESCRIPTOR: "$SECURITY_DESCRIPTOR",
    ATTR_VOLUME_NAME: "$VOLUME_NAME",
    ATTR_VOLUME_INFORMATION: "$VOLUME_INFORMATION",
    ATTR_DATA: "$DATA",
    ATTR_INDEX_ROOT: "$INDEX_ROOT",
    ATTR_INDEX_ALLOCATION: "$INDEX_ALLOCATION",
    ATTR_BITMAP: "$BITMAP",
    ATTR_REPARSE_POINT: "$REPARSE_POINT",
    ATTR_EA_INFORMATION: "$EA_INFORMATION",
    ATTR_EA: "$EA",
    ATTR_LOGGED_UTILITY_STREAM: "$LOGGED_UTILITY_STREAM",
}

NAMESPACE_POSIX = 0
NAMESPACE_WIN32 = 1
NAMESPACE_DOS = 2
NAMESPACE_WIN32_DOS = 3

NAMESPACE_NAMES = {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32_DOS"}

# $FILE_NAME flags
FILE_ATTRIBUTE_READONLY = 0x0001
FILE_ATTRIBUTE_HIDDEN = 0x0002
FILE_ATTRIBUTE_SYSTEM = 0x0004
FILE_ATTRIBUTE_ARCHIVE = 0x0020
FILE_ATTRIBUTE_TEMPORARY = 0x0100
FILE_ATTRIBUTE_SPARSE = 0x0200
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
FILE_ATTRIBUTE_COMPRESSED = 0x0800
FILE_ATTRIBUTE_ENCRYPTED = 0x4000

FILE_ATTRIBUTE_NAMES = (
    (FILE_ATTRIBUTE_READONLY, "READONLY"),
    (FILE_ATTRIBUTE_HIDDEN, "HIDDEN"),
    (FILE_ATTRIBUTE_SYSTEM, "SYSTEM"),
    (FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE"),
    (FILE_ATTRIBUTE_TEMPORARY, "TEMPORARY"),
    (FILE_ATTRIBUTE_SPARSE, "SPARSE"),
    (FILE_ATTRIBUTE_REPARSE_POINT, "REPARSE_POINT"),
    (FILE_ATTRIBUTE_COMPRESSED, "COMPRESSED"),
    (FILE_ATTRIBUTE_ENCRYPTED, "ENCRYPTED"),
)


def describe_file_attributes(flags: int) -> str:
    """Decode $STANDARD_INFORMATION flags into readable names."""
    if not flags:
        return ""
    names = [name for bit, name in FILE_ATTRIBUTE_NAMES if flags & bit]
    return " | ".join(names) if names else f"0x{flags:08X}"

ROOT_RECORD_NUMBER = 5

# Characters that are illegal in NTFS filenames
ILLEGAL_NAME_CHARS = set('\\/:*?"<>|') | {chr(c) for c in range(0, 32)}


# Binary helpers

def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def filetime_to_dt(value: int) -> Optional[datetime.datetime]:
    """Convert a Windows FILETIME to an aware datetime, or None."""
    if value <= 0 or value > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        # Integer division. A float loses the microsecond at this magnitude.
        return FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)
    except (OverflowError, OSError, ValueError):
        return None


def is_sane_time(ts: Optional[datetime.datetime]) -> bool:
    return ts is not None and MIN_SANE_TIME <= ts <= MAX_SANE_TIME


def iso(ts: Optional[datetime.datetime]) -> str:
    return ts.isoformat() if ts else ""


def ref_record(ref: int) -> int:
    """Record number from an MFT reference (low 48 bits)."""
    return ref & 0x0000FFFFFFFFFFFF


def ref_sequence(ref: int) -> int:
    """Sequence number from an MFT reference (high 16 bits)."""
    return (ref >> 48) & 0xFFFF


def decode_utf16le(raw: bytes) -> str:
    try:
        return raw.decode("utf-16le", errors="replace")
    except Exception:
        return ""


def has_illegal_chars(name: str) -> bool:
    return any(ch in ILLEGAL_NAME_CHARS for ch in name)


# Fixup (update sequence array)

@dataclass
class FixupResult:
    data: bytes
    applied: bool
    warning: str = ""


def apply_fixup(buf: bytes, record_size: int, sector_size: int = 512, strict: bool = False,) -> FixupResult:
    """Apply the NTFS update sequence array to a FILE/RCRD/INDX record."""
    if len(buf) < 48:
        return FixupResult(buf, False, "record too short")

    usa_offset = u16(buf, 4)
    usa_count = u16(buf, 6)

    if usa_offset == 0 or usa_count == 0:
        return FixupResult(buf, False, "no update sequence array")

    usa_size = usa_count * 2
    if usa_offset + usa_size > len(buf):
        return FixupResult(buf, False, "USA outside record")

    usa = buf[usa_offset:usa_offset + usa_size]
    usn = usa[0:2]

    sectors = min(record_size // sector_size, usa_count - 1)
    if sectors <= 0:
        return FixupResult(buf, False, "no sectors to fix")

    fixed = bytearray(buf)
    mismatches = 0

    for i in range(sectors):
        end = ((i + 1) * sector_size) - 2
        if end + 2 > len(fixed):
            break
        if fixed[end:end + 2] != usn:
            mismatches += 1
            if strict:
                return FixupResult(buf, False, f"USN mismatch in sector {i}")
            continue
        fixed[end:end + 2] = usa[2 + (i * 2):4 + (i * 2)]

    warning = f"{mismatches} USN mismatch(es)" if mismatches else ""
    return FixupResult(bytes(fixed), True, warning)


# $STANDARD_INFORMATION

@dataclass(**_SLOTS)
class Timestamps:
    created: Optional[datetime.datetime] = None
    modified: Optional[datetime.datetime] = None
    mft_modified: Optional[datetime.datetime] = None
    accessed: Optional[datetime.datetime] = None

    def as_list(self):
        return [self.created, self.modified, self.mft_modified, self.accessed]


@dataclass(**_SLOTS)
class StandardInformation:
    timestamps: Timestamps = field(default_factory=Timestamps)
    file_attributes: int = 0
    security_id: int = 0
    usn: int = 0


def parse_standard_information(content: bytes) -> StandardInformation:
    si = StandardInformation()
    if len(content) < 48:
        return si

    si.timestamps = Timestamps(
        created=filetime_to_dt(u64(content, 0)),
        modified=filetime_to_dt(u64(content, 8)),
        mft_modified=filetime_to_dt(u64(content, 16)),
        accessed=filetime_to_dt(u64(content, 24)),
    )
    si.file_attributes = u32(content, 32)

    if len(content) >= 72:
        si.security_id = u32(content, 52)
        si.usn = u64(content, 64)

    return si


# $FILE_NAME

@dataclass(**_SLOTS)
class FileNameAttr:
    parent_ref: int = 0
    parent_record: int = 0
    parent_sequence: int = 0
    name: str = ""
    namespace: int = 0
    timestamps: Timestamps = field(default_factory=Timestamps)
    allocated_size: int = 0
    real_size: int = 0
    flags: int = 0

    @property
    def namespace_name(self) -> str:
        return NAMESPACE_NAMES.get(self.namespace, str(self.namespace))


FILE_NAME_MIN_LEN = 66


def parse_file_name(content: bytes, validate: bool = False) -> Optional[FileNameAttr]:
    """Decode a $FILE_NAME attribute body."""
    if len(content) < FILE_NAME_MIN_LEN:
        return None

    name_len = content[64]
    namespace = content[65]
    name_bytes = name_len * 2

    if name_len == 0 or FILE_NAME_MIN_LEN + name_bytes > len(content):
        return None

    if validate and namespace > 3:
        return None

    ts = Timestamps(
        created=filetime_to_dt(u64(content, 8)),
        modified=filetime_to_dt(u64(content, 16)),
        mft_modified=filetime_to_dt(u64(content, 24)),
        accessed=filetime_to_dt(u64(content, 32)),
    )

    if validate:
        # A genuine $FILE_NAME has four plausible timestamps.
        if not all(is_sane_time(t) for t in ts.as_list()):
            return None

    name = decode_utf16le(content[FILE_NAME_MIN_LEN:FILE_NAME_MIN_LEN + name_bytes])

    if validate:
        if not name or has_illegal_chars(name) or "\ufffd" in name:
            return None

    parent_ref = u64(content, 0)
    fn = FileNameAttr(
        parent_ref=parent_ref,
        parent_record=ref_record(parent_ref),
        parent_sequence=ref_sequence(parent_ref),
        name=name,
        namespace=namespace,
        timestamps=ts,
        allocated_size=u64(content, 40),
        real_size=u64(content, 48),
        flags=u32(content, 56),
    )

    if validate:
        # Allocated size is cluster aligned for non resident data and 8 byte aligned for resident data.
        if fn.allocated_size and fn.allocated_size % 8 != 0:
            return None
        if fn.parent_record == 0:
            return None

    return fn


def choose_best_filename(names) -> Optional[FileNameAttr]:
    """Prefer the Win32 (long) name over the 8.3 DOS name."""
    if not names:
        return None
    order = {NAMESPACE_WIN32: 0, NAMESPACE_WIN32_DOS: 1, NAMESPACE_POSIX: 2, NAMESPACE_DOS: 3}
    return sorted(names, key=lambda fn: (order.get(fn.namespace, 99), -len(fn.name)))[0]


# Attribute walking

@dataclass(**_SLOTS)
class Attribute:
    type_id: int
    length: int
    non_resident: bool
    name: str
    flags: int
    instance: int
    content: bytes = b""
    # Non-resident only
    start_vcn: int = 0
    last_vcn: int = 0
    allocated_size: int = 0
    real_size: int = 0
    initialized_size: int = 0

    @property
    def type_name(self) -> str:
        return ATTRIBUTE_NAMES.get(self.type_id, f"0x{self.type_id:X}")


def iter_attributes(record: bytes, first_offset: int):
    """Yield attributes from a FILE record."""
    off = first_offset
    guard = 0

    while off + 16 <= len(record) and guard < 512:
        guard += 1
        type_id = u32(record, off)
        if type_id == ATTR_END:
            return

        length = u32(record, off + 4)
        if length < 16 or off + length > len(record):
            return

        non_resident = bool(record[off + 8])
        # The resident header is 24 bytes and the non resident one 64.
        if length < (64 if non_resident else 24):
            return
        name_len = record[off + 9]
        name_off = u16(record, off + 10)
        flags = u16(record, off + 12)
        instance = u16(record, off + 14)

        name = ""
        if name_len:
            start = off + name_off
            end = start + name_len * 2
            if end <= off + length and end <= len(record):
                name = decode_utf16le(record[start:end])

        attr = Attribute(
            type_id=type_id,
            length=length,
            non_resident=non_resident,
            name=name,
            flags=flags,
            instance=instance,
        )

        if not non_resident:
            content_size = u32(record, off + 16)
            content_off = u16(record, off + 20)
            start = off + content_off
            end = start + content_size
            if 0 <= content_off < length and end <= len(record) and end <= off + length:
                attr.content = record[start:end]
        else:
            if off + 64 <= len(record):
                attr.start_vcn = u64(record, off + 16)
                attr.last_vcn = u64(record, off + 24)
                attr.allocated_size = u64(record, off + 40)
                attr.real_size = u64(record, off + 48)
                attr.initialized_size = u64(record, off + 56)

        yield attr
        off += length


def subsecond_is_zero(when) -> bool:
    """True if a timestamp has no sub-second component."""
    return when is not None and when.microsecond == 0
