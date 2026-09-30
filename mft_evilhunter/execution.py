"""
Evidence of execution, derived from Prefetch filenames.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .paths import is_noise, normalize_path

# Prefetch keeps at most 29 characters of the image name.
PREFETCH_IMAGE_MAX = 29
PREFETCH_DIR = "\\windows\\prefetch\\"

# <NAME>-<8 hex>.pf
PREFETCH_NAME = re.compile(r"^(?P<image>.+?)-(?P<hash>[0-9A-F]{7,8})\.pf$", re.IGNORECASE)

# Living-off-the-land binaries and administrative tools that are unremarkable on
# disk but meaningful when they have actually run.
LOLBIN_CATEGORIES: Dict[str, str] = {}


def _register(category: str, *names: str) -> None:
    for name in names:
        LOLBIN_CATEGORIES[name.upper()] = category


_register("ingress/download",
          "CERTUTIL", "BITSADMIN", "CURL", "FTP", "TFTP", "IEEXEC", "DESKTOPIMGDOWNLDR",
          "EXTRAC32", "ESENTUTL", "REPLACE", "HH", "PRINT")
_register("proxy execution",
          "MSHTA", "RUNDLL32", "REGSVR32", "CMSTP", "ODBCCONF", "INSTALLUTIL",
          "MSBUILD", "REGASM", "REGSVCS", "MSIEXEC", "PCALUA", "FORFILES",
          "SCRIPTRUNNER", "MAVINJECT", "PRESENTATIONHOST", "WMIC")
_register("scripting",
          "POWERSHELL", "PWSH", "CSCRIPT", "WSCRIPT", "CMD")
_register("uac bypass",
          "FODHELPER", "COMPUTERDEFAULTS", "SDCLT", "EVENTVWR", "SLUI", "WSRESET")
_register("remote execution",
          "PSEXEC", "PSEXESVC", "PAEXEC", "REMCOM", "CSEXEC", "WINRS", "WINEXESVC")
_register("persistence",
          "SCHTASKS", "AT", "SC", "REG", "REGEDIT")
_register("discovery",
          "WHOAMI", "NLTEST", "QUSER", "QWINSTA", "NETSTAT", "ARP", "ROUTE",
          "SYSTEMINFO", "TASKLIST", "IPCONFIG", "NBTSTAT", "DSQUERY", "ADFIND")
_register("lateral movement",
          "NET", "NET1", "NETSH", "MSTSC", "WMIPRVSE")
_register("defence evasion",
          "TASKKILL", "CIPHER", "FSUTIL", "ATTRIB", "TIMESTOMP", "SDELETE")
_register("impact",
          "VSSADMIN", "WBADMIN", "BCDEDIT", "DISKSHADOW", "WEVTUTIL")
_register("credential access",
          "MIMIKATZ", "PROCDUMP", "PROCDUMP64", "SECRETSDUMP", "LAZAGNE", "NANODUMP")
_register("exfiltration",
          "RCLONE", "MEGACMD", "MEGASYNC", "WINSCP", "PSCP", "PSFTP", "ROBOCOPY", "XCOPY")

CATEGORY_SEVERITY = {
    "credential access": "critical",
    "remote execution": "high",
    "uac bypass": "high",
    "ingress/download": "high",
    "impact": "high",
    "exfiltration": "high",
    "proxy execution": "medium",
    "defence evasion": "medium",
    "persistence": "medium",
    "lateral movement": "medium",
    "scripting": "medium",
    "discovery": "low",
}


@dataclass
class Execution:
    """One executable observed to have run, as reconstructed from Prefetch."""
    image: str # e.g. POWERSHELL.EXE
    path_hash: str
    prefetch_name: str
    prefetch_path: str
    first_seen: Optional[datetime.datetime] = None
    last_seen: Optional[datetime.datetime] = None
    prefetch_deleted: bool = False
    binary_paths: List[str] = field(default_factory=list)
    binary_present: bool = False
    binary_outside_windows: bool = False
    source: str = "$MFT"

    @property
    def stem(self) -> str:
        return self.image.rsplit(".", 1)[0].upper() if "." in self.image else self.image.upper()

    @property
    def lolbin_category(self) -> str:
        return LOLBIN_CATEGORIES.get(self.stem, "")

    @property
    def severity(self) -> str:
        category = self.lolbin_category
        if category:
            return CATEGORY_SEVERITY.get(category, "medium")
        if not self.binary_present:
            return "medium"
        if self.binary_outside_windows:
            return "low"
        return ""

    @property
    def notes(self) -> str:
        parts = []
        if not self.binary_present:
            parts.append("binary no longer on disk")
        if self.prefetch_deleted:
            parts.append("prefetch file deleted")
        if self.binary_outside_windows:
            parts.append("ran from outside \\Windows")
        return "; ".join(parts)


def parse_prefetch_name(name: str):
    """Split 'NOTEPAD.EXE-D8414F97.pf' into image and path hash."""
    match = PREFETCH_NAME.match(name)
    if not match:
        return None
    return match.group("image"), match.group("hash").upper()


def _index_binaries(entries) -> Dict[str, List]:
    index: Dict[str, List] = {}
    for entry in entries.values():
        if entry.is_directory or not entry.name:
            continue
        index.setdefault(entry.name.upper(), []).append(entry)
    return index


def build_execution_evidence(entries: Optional[dict], usn_records: Optional[Iterable] = None, log_events: Optional[Iterable] = None) -> List[Execution]:
    """Collect execution evidence from every artifact that mentions a prefetch file."""
    found: Dict[tuple, Execution] = {}
    binaries = _index_binaries(entries) if entries else {}

    def record(image: str, path_hash: str, prefetch_name: str, prefetch_path: str,
               source: str) -> Execution:
        key = (image.upper(), path_hash)
        existing = found.get(key)
        if existing is None:
            existing = Execution(
                image=image.upper(), path_hash=path_hash,
                prefetch_name=prefetch_name, prefetch_path=prefetch_path,
                source=source,
            )
            found[key] = existing
        return existing

    if entries:
        for entry in entries.values():
            if entry.is_directory:
                continue
            if not normalize_path(entry.path).startswith(PREFETCH_DIR):
                continue
            parsed = parse_prefetch_name(entry.name)
            if not parsed:
                continue
            image, path_hash = parsed
            item = record(image, path_hash, entry.name, entry.path, "$MFT")
            item.first_seen = entry.si.timestamps.created
            item.last_seen = entry.si.timestamps.modified or entry.si.timestamps.created
            item.prefetch_deleted = entry.is_deleted

    # Prefetch files that no longer have a live $MFT record.
    for source_name, records in (("$UsnJrnl", usn_records), ("$LogFile", log_events)):
        for change in records or ():
            name = getattr(change, "name", "")
            if not name.lower().endswith(".pf"):
                continue
            parsed = parse_prefetch_name(name)
            if not parsed:
                continue
            image, path_hash = parsed
            key = (image.upper(), path_hash)
            timestamp = getattr(change, "timestamp", None) or getattr(change, "created", None)
            if key in found:
                # The $MFT record is authoritative for presence and deletion,
                # but journal entries still widen the observed run window.
                item = found[key]
                if timestamp and item.source != "$MFT":
                    item.first_seen = min(item.first_seen or timestamp, timestamp)
                    item.last_seen = max(item.last_seen or timestamp, timestamp)
                continue
            item = record(image, path_hash, name,
                          getattr(change, "path", "") or PREFETCH_DIR + name,
                          source_name)
            item.prefetch_deleted = True
            if timestamp:
                item.first_seen = timestamp
                item.last_seen = timestamp

    # Correlate each executable against the file records on disk.
    for item in found.values():
        matches = binaries.get(item.image.upper(), [])
        if not matches and len(item.image) >= PREFETCH_IMAGE_MAX:
            # Prefetch truncates the image name, so match on the prefix.
            matches = [e for key, group in binaries.items()
                       if key.startswith(item.image.upper()) for e in group]
        live = [e for e in matches if not e.is_deleted]
        item.binary_present = bool(live)

        # Show the location it actually runs from first, not the servicing copies.
        candidates = sorted(live or matches, key=lambda e: (is_noise(e.path), e.path))
        item.binary_paths = [e.path for e in candidates][:4]
        item.binary_outside_windows = bool(live) and all(
            not normalize_path(e.path).startswith("\\windows\\") for e in live
        )

    return sorted(
        found.values(),
        key=lambda item: (item.first_seen or datetime.datetime.max.replace(
            tzinfo=datetime.timezone.utc), item.image),
    )
