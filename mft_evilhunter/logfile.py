"""
$LogFile parsing.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from . import ntfs
from .ntfs import _SLOTS, NAMESPACE_DOS
from .paths import resolve_child_path
from .ntfs import FileNameAttr

RESTART_MAGIC = (b"RSTR", b"CHKD")
RECORD_MAGIC = b"RCRD"

LFS_HEADER_SIZE = 0x30 # LSN through reserved
NTFS_CLIENT_HEADER_SIZE = 0x28 # redo_op through target_lcn
INDEX_ENTRY_FILENAME_OFFSET = 0x10

DEFAULT_PAGE_SIZE = 4096

# Redo/undo operation codes.
OPCODES = {
    0x00: "Noop",
    0x01: "CompensationLogRecord",
    0x02: "InitializeFileRecordSegment",
    0x03: "DeallocateFileRecordSegment",
    0x04: "WriteEndOfFileRecordSegment",
    0x05: "CreateAttribute",
    0x06: "DeleteAttribute",
    0x07: "UpdateResidentValue",
    0x08: "UpdateNonResidentValue",
    0x09: "UpdateMappingPairs",
    0x0A: "DeleteDirtyClusters",
    0x0B: "SetNewAttributeSizes",
    0x0C: "AddIndexEntryRoot",
    0x0D: "DeleteIndexEntryRoot",
    0x0E: "AddIndexEntryAllocation",
    0x0F: "DeleteIndexEntryAllocation",
    0x10: "WriteEndOfIndexBuffer",
    0x11: "SetIndexEntryVcnRoot",
    0x12: "SetIndexEntryVcnAllocation",
    0x13: "UpdateFileNameRoot",
    0x14: "UpdateFileNameAllocation",
    0x15: "SetBitsInNonResidentBitMap",
    0x16: "ClearBitsInNonResidentBitMap",
    0x17: "HotFix",
    0x18: "EndTopLevelAction",
    0x19: "PrepareTransaction",
    0x1A: "CommitTransaction",
    0x1B: "ForgetTransaction",
    0x1C: "OpenNonResidentAttribute",
    0x1D: "OpenAttributeTableDump",
    0x1E: "AttributeNamesDump",
    0x1F: "DirtyPageTableDump",
    0x20: "TransactionTableDump",
    0x21: "UpdateRecordDataRoot",
    0x22: "UpdateRecordDataAllocation",
}

# Opcodes whose payload carries an INDEX_ENTRY
ADD_INDEX_OPS = {0x0C, 0x0E}
DELETE_INDEX_OPS = {0x0D, 0x0F}
INDEX_OPS = ADD_INDEX_OPS | DELETE_INDEX_OPS

FILE_CREATE_OPS = {0x02}
FILE_DELETE_OPS = {0x03}

# Human-readable action derived from the opcode pair, for the CSV.
ACTION_BY_OP = {
    0x02: "FileRecordCreated",
    0x03: "FileRecordDeleted",
    0x0C: "FileNameAdded",
    0x0E: "FileNameAdded",
    0x0D: "FileNameRemoved",
    0x0F: "FileNameRemoved",
}


@dataclass(**_SLOTS)
class LogRecord:
    lsn: int
    previous_lsn: int
    undo_next_lsn: int
    client_data_length: int
    record_type: int
    transaction_id: int
    flags: int
    redo_op: int
    undo_op: int
    target_attribute: int
    mft_cluster_index: int
    target_vcn: int
    page_offset: int
    redo_data: bytes = b""
    undo_data: bytes = b""

    @property
    def redo_op_name(self) -> str:
        return OPCODES.get(self.redo_op, f"0x{self.redo_op:02X}")

    @property
    def undo_op_name(self) -> str:
        return OPCODES.get(self.undo_op, f"0x{self.undo_op:02X}")


@dataclass(**_SLOTS)
class LogEvent:
    """One filename-bearing observation recovered from the $LogFile."""
    lsn: int
    transaction_id: int
    redo_op: str
    undo_op: str
    action: str
    source: str # "structured" or "carved"
    name: str = ""
    parent_record: int = 0
    parent_sequence: int = 0
    mft_record: Optional[int] = None
    mft_sequence: Optional[int] = None
    created: Optional[datetime.datetime] = None
    modified: Optional[datetime.datetime] = None
    mft_modified: Optional[datetime.datetime] = None
    accessed: Optional[datetime.datetime] = None
    real_size: int = 0
    allocated_size: int = 0
    file_attributes: int = 0
    namespace: int = 1
    page_offset: int = 0
    path: str = "" # filled in later if an $MFT is available
    path_source: str = ""

    @property
    def extension(self) -> str:
        base = self.name
        return "." + base.rsplit(".", 1)[-1].lower() if "." in base else ""

    @property
    def is_dos_alias(self) -> bool:
        """True for the 8.3 short name."""
        return self.namespace == NAMESPACE_DOS


# Page handling

def detect_page_size(path: Path, default: int = DEFAULT_PAGE_SIZE) -> int:
    """Read the restart page to learn the log page size."""
    with path.open("rb") as fh:
        head = fh.read(0x40)
    if len(head) >= 0x18 and head[0:4] in RESTART_MAGIC:
        page_size = ntfs.u32(head, 0x14)
        if page_size in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
            return page_size
    return default


def _records_start(page: bytes) -> int:
    """Offset of the first log record in an RCRD page."""
    usa_offset = ntfs.u16(page, 4)
    usa_count = ntfs.u16(page, 6)
    end = usa_offset + usa_count * 2
    return (end + 7) & ~7


LFS_MULTI_PAGE = 0x0001
LFS_RECORD_NORMAL = 1
MAX_MULTI_PAGE_RECORD = 1 << 20


def _plausible_header(page: bytes, off: int, page_size: int) -> bool:
    if off + LFS_HEADER_SIZE + NTFS_CLIENT_HEADER_SIZE > len(page):
        return False
    lsn = ntfs.u64(page, off)
    if lsn == 0:
        return False
    length = ntfs.u32(page, off + 0x18)
    multi_page = ntfs.u16(page, off + 0x28) & LFS_MULTI_PAGE
    limit = MAX_MULTI_PAGE_RECORD if multi_page else page_size
    if length < NTFS_CLIENT_HEADER_SIZE or length > limit:
        return False
    redo_op = ntfs.u16(page, off + 0x30)
    undo_op = ntfs.u16(page, off + 0x32)
    return redo_op in OPCODES and undo_op in OPCODES


def _spills(page: bytes, off: int, page_size: int) -> bool:
    """True for a multi page record whose data runs past this page."""
    flags = ntfs.u16(page, off + 0x28)
    if not flags & LFS_MULTI_PAGE or flags & ~0xF:
        return False
    lsn = ntfs.u64(page, off)
    if lsn == 0 or lsn > ntfs.u64(page, 0x08):
        return False
    if ntfs.u32(page, off + 0x20) != LFS_RECORD_NORMAL:
        return False
    length = ntfs.u32(page, off + 0x18)
    if length < NTFS_CLIENT_HEADER_SIZE or length > MAX_MULTI_PAGE_RECORD:
        return False
    return off + LFS_HEADER_SIZE + length > len(page)


def _page_position(page: bytes) -> int:
    """1 for a page that starts a record run, 2 and up for continuations."""
    return ntfs.u16(page, 0x16)


def parse_page_records(page: bytes, page_size: int, file_offset: int, start: Optional[int] = None):
    """Walk the log records inside one fixed-up RCRD page."""
    records: List[LogRecord] = []
    off = _records_start(page) if start is None else start
    spill = None

    # True while off was reached by stepping over whole records, so a header
    # there is trusted more than one found by scanning 8 bytes at a time.
    chained = True
    last_lsn = 0

    while off + LFS_HEADER_SIZE <= len(page):
        if chained and ntfs.u64(page, off) > last_lsn and _spills(page, off, page_size):
            length = ntfs.u32(page, off + 0x18)
            spill = (page[off:], off + LFS_HEADER_SIZE + length - len(page), file_offset + off)
            break

        if not _plausible_header(page, off, page_size):
            off += 8
            chained = False
            continue

        rec = _read_record(page, off, file_offset)
        if rec is None:
            off += 8
            chained = False
            continue

        records.append(rec)
        last_lsn = rec.lsn
        chained = True
        advance = (LFS_HEADER_SIZE + rec.client_data_length + 7) & ~7
        off += max(advance, 8)

    return records, spill


def _read_record(page: bytes, off: int, file_offset: int) -> Optional[LogRecord]:
    try:
        client_data_length = ntfs.u32(page, off + 0x18)
        rec = LogRecord(
            lsn=ntfs.u64(page, off),
            previous_lsn=ntfs.u64(page, off + 0x08),
            undo_next_lsn=ntfs.u64(page, off + 0x10),
            client_data_length=client_data_length,
            record_type=ntfs.u32(page, off + 0x20),
            transaction_id=ntfs.u32(page, off + 0x24),
            flags=ntfs.u16(page, off + 0x28),
            redo_op=ntfs.u16(page, off + 0x30),
            undo_op=ntfs.u16(page, off + 0x32),
            target_attribute=ntfs.u16(page, off + 0x3C),
            mft_cluster_index=ntfs.u16(page, off + 0x44),
            target_vcn=ntfs.u32(page, off + 0x48),
            page_offset=file_offset + off,
        )

        client = off + LFS_HEADER_SIZE
        redo_offset = ntfs.u16(page, off + 0x34)
        redo_length = ntfs.u16(page, off + 0x36)
        undo_offset = ntfs.u16(page, off + 0x38)
        undo_length = ntfs.u16(page, off + 0x3A)

        end_of_record = client + client_data_length

        rs, re_ = client + redo_offset, client + redo_offset + redo_length
        if redo_length and re_ <= min(len(page), end_of_record):
            rec.redo_data = page[rs:re_]

        us, ue = client + undo_offset, client + undo_offset + undo_length
        if undo_length and ue <= min(len(page), end_of_record):
            rec.undo_data = page[us:ue]

        return rec

    except Exception:
        return None


# Filename extraction

def _index_entry_filename(payload: bytes) -> Optional[tuple]:
    """Decode an INDEX_ENTRY: (mft_ref, $FILE_NAME)."""
    if len(payload) < INDEX_ENTRY_FILENAME_OFFSET + ntfs.FILE_NAME_MIN_LEN:
        return None
    mft_ref = ntfs.u64(payload, 0)
    fn = ntfs.parse_file_name(payload[INDEX_ENTRY_FILENAME_OFFSET:], validate=True)
    if fn is None:
        return None
    return mft_ref, fn


def carve_file_names(blob: bytes, step: int = 8) -> List[FileNameAttr]:
    """Scan a payload for $FILE_NAME structures."""
    found: List[FileNameAttr] = []
    seen = set()
    limit = len(blob) - ntfs.FILE_NAME_MIN_LEN

    for off in range(0, max(limit + 1, 0), step):
        fn = ntfs.parse_file_name(blob[off:], validate=True)
        if fn is None:
            continue
        key = (fn.name, fn.parent_record, fn.timestamps.created)
        if key in seen:
            continue
        seen.add(key)
        found.append(fn)

    return found


def _event_from_fn(rec: LogRecord, fn: FileNameAttr, source: str, mft_ref: Optional[int] = None) -> LogEvent:
    return LogEvent(
        lsn=rec.lsn,
        transaction_id=rec.transaction_id,
        redo_op=rec.redo_op_name,
        undo_op=rec.undo_op_name,
        action=ACTION_BY_OP.get(rec.redo_op, rec.redo_op_name),
        source=source,
        name=fn.name,
        parent_record=fn.parent_record,
        parent_sequence=fn.parent_sequence,
        mft_record=ntfs.ref_record(mft_ref) if mft_ref else None,
        mft_sequence=ntfs.ref_sequence(mft_ref) if mft_ref else None,
        created=fn.timestamps.created,
        modified=fn.timestamps.modified,
        mft_modified=fn.timestamps.mft_modified,
        accessed=fn.timestamps.accessed,
        real_size=fn.real_size,
        allocated_size=fn.allocated_size,
        file_attributes=fn.flags,
        namespace=fn.namespace,
        page_offset=rec.page_offset,
    )


def extract_events(rec: LogRecord, carve: bool = True) -> List[LogEvent]:
    events: List[LogEvent] = []
    structured_keys = set()

    for payload, is_redo in ((rec.redo_data, True), (rec.undo_data, False)):
        if not payload:
            continue

        op = rec.redo_op if is_redo else rec.undo_op

        if op in INDEX_OPS:
            decoded = _index_entry_filename(payload)
            if decoded:
                mft_ref, fn = decoded
                ev = _event_from_fn(rec, fn, "structured", mft_ref)
                ev.action = ACTION_BY_OP.get(op, ev.action)
                events.append(ev)
                structured_keys.add((fn.name, fn.parent_record))
                continue

        if op in FILE_CREATE_OPS | FILE_DELETE_OPS:
            # Payload is a copy of an MFT FILE record.
            for fn in _file_names_from_record_image(payload):
                ev = _event_from_fn(rec, fn, "structured")
                ev.action = ACTION_BY_OP.get(op, ev.action)
                events.append(ev)
                structured_keys.add((fn.name, fn.parent_record))

    if carve:
        for payload in (rec.redo_data, rec.undo_data):
            if not payload:
                continue
            for fn in carve_file_names(payload):
                if (fn.name, fn.parent_record) in structured_keys:
                    continue
                structured_keys.add((fn.name, fn.parent_record))
                events.append(_event_from_fn(rec, fn, "carved"))

    return events


def _file_names_from_record_image(payload: bytes) -> List[FileNameAttr]:
    """Pull $FILE_NAME attributes out of an embedded FILE record image."""
    names: List[FileNameAttr] = []
    if len(payload) < 48 or payload[0:4] not in (b"FILE", b"BAAD"):
        return names
    try:
        first = ntfs.u16(payload, 20)
        if first < 42 or first >= len(payload):
            return names
        for attr in ntfs.iter_attributes(payload, first):
            if attr.type_id == ntfs.ATTR_FILE_NAME and attr.content:
                fn = ntfs.parse_file_name(attr.content)
                if fn:
                    names.append(fn)
    except Exception:
        pass
    return names


# Top level

def parse_logfile(path: Path, page_size: Optional[int] = None, carve: bool = True, progress=None) -> Iterator[LogEvent]:
    """Stream LogEvents out of a $LogFile. Memory use stays flat per page."""
    page_size = page_size or detect_page_size(path)
    total_pages = max(path.stat().st_size // page_size, 1)

    with path.open("rb") as fh:
        index = 0
        carry = None
        while True:
            offset = index * page_size
            page = fh.read(page_size)
            if len(page) < page_size:
                break
            index += 1

            if progress and index % 2000 == 0:
                if progress(index, total_pages) is False:
                    break

            if page[0:4] != RECORD_MAGIC:
                carry = None
                continue

            fixed = ntfs.apply_fixup(page, page_size).data
            start = None

            # A record that ran past the previous page continues right after
            # this page's header, and only on a page marked as a continuation.
            if carry is not None:
                buf, remaining, rec_offset = carry
                carry = None
                if _page_position(fixed) >= 2:
                    first = _records_start(fixed)
                    piece = fixed[first:first + remaining]
                    buf += piece
                    if len(piece) < remaining:
                        carry = (buf, remaining - len(piece), rec_offset)
                        continue
                    rec = _read_record(buf, 0, rec_offset)
                    if rec is not None and rec.redo_op in OPCODES and rec.undo_op in OPCODES:
                        for event in extract_events(rec, carve=carve):
                            yield event
                    start = (first + remaining + 7) & ~7

            records, carry = parse_page_records(fixed, page_size, offset, start)
            for rec in records:
                for event in extract_events(rec, carve=carve):
                    yield event

    if progress:
        progress(total_pages, total_pages)


def resolve_event_paths(events: List[LogEvent], mft_entries: Dict[int, object]) -> None:
    """Attach directory context to $LogFile events using a parsed $MFT."""
    for event in events:
        event.path, event.path_source = resolve_child_path(
            mft_entries.get(event.parent_record), event.name,
            event.parent_record, event.parent_sequence,
        )
