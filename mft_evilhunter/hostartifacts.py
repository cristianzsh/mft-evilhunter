"""
Host level artifacts inferred from $MFT metadata alone.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import List, Optional

from .paths import normalize_path

EVENT_LOG_DIR = "\\windows\\system32\\winevt\\logs\\"
RDP_CACHE_MARKER = "\\terminal server client\\cache\\"

# Logs that exist from installation onward. Unlike the per-feature operational
# logs these are never created on first use, so a late creation time means the
# log was cleared.
CORE_EVENT_LOGS = frozenset({
    "security.evtx", "system.evtx", "application.evtx", "setup.evtx",
    "microsoft-windows-sysmon%4operational.evtx",
    "microsoft-windows-windows defender%4operational.evtx",
    "microsoft-windows-taskscheduler%4operational.evtx",
    "microsoft-windows-terminalservices-localsessionmanager%4operational.evtx",
})

# Profile directories Windows ships; not real user accounts.
BUILTIN_PROFILES = frozenset({
    "default", "default user", "public", "all users", "defaultuser0",
    "desktop.ini", "administrator",
})

# How far after the bulk of the log set a creation time has to sit before it
# counts as an outlier rather than ordinary provisioning jitter.
EVENT_LOG_OUTLIER_SECONDS = 2 * 3600


@dataclass
class HostArtifact:
    category: str
    name: str
    detail: str
    path: str
    timestamp: Optional[datetime.datetime] = None
    last_modified: Optional[datetime.datetime] = None
    size: int = 0
    severity: str = ""
    notes: str = ""


def _created(entry):
    return entry.si.timestamps.created


def _modified(entry):
    return entry.si.timestamps.modified


# Event logs

def event_log_artifacts(entries) -> List[HostArtifact]:
    logs = [
        entry for entry in entries.values()
        if entry.extension.lower() == ".evtx"
        and normalize_path(entry.path).startswith(EVENT_LOG_DIR)
        and not entry.is_directory
    ]
    if not logs:
        return []

    times = sorted(t for t in (_created(e) for e in logs) if t)
    if not times:
        return []
    median = times[len(times) // 2]

    artifacts: List[HostArtifact] = []
    for entry in logs:
        created = _created(entry)
        if not created:
            continue
        drift = (created - median).total_seconds()
        if drift <= EVENT_LOG_OUTLIER_SECONDS:
            continue

        core = entry.name.lower() in CORE_EVENT_LOGS
        if core:
            severity = "high"
            notes = ("core log: exists from installation onward, so a late "
                     "creation time means it was cleared and recreated")
        else:
            severity = "medium"
            notes = ("operational log: created either on first use of the "
                     "feature or by clearing -- the filesystem cannot "
                     "distinguish the two")

        artifacts.append(HostArtifact(
            category="Event log",
            name=entry.name,
            detail=f"created {drift / 3600:.1f}h after the rest of the log set",
            path=entry.path,
            timestamp=created,
            last_modified=_modified(entry),
            size=entry.logical_size,
            severity=severity,
            notes=notes,
        ))

    artifacts.sort(key=lambda a: a.timestamp or datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc))
    return artifacts


# User profiles

def user_profile_artifacts(entries, baseline=None) -> List[HostArtifact]:
    install_date = getattr(baseline, "install_date", None) if baseline else None

    artifacts: List[HostArtifact] = []
    for entry in entries.values():
        path = normalize_path(entry.path)
        if not entry.is_directory or path.count("\\") != 2:
            continue
        if not path.startswith("\\users\\"):
            continue
        name = entry.name
        if name.lower() in BUILTIN_PROFILES:
            continue

        # $FN creation is when the directory was written to this volume
        linked = entry.best_fn.timestamps.created if entry.best_fn else None
        created = _created(entry)
        effective = linked or created

        severity, notes = "", "profile present in the install image"
        if install_date and effective and effective.date() > install_date:
            severity = "medium"
            notes = ("profile directory created after the volume was imaged: "
                     "an account added on this host")

        artifacts.append(HostArtifact(
            category="User profile",
            name=name,
            detail=f"$SI {created:%Y-%m-%d %H:%M}" if created else "",
            path=entry.path,
            timestamp=effective,
            last_modified=_modified(entry),
            severity=severity,
            notes=notes,
        ))

    artifacts.sort(key=lambda a: a.timestamp or datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc))
    return artifacts


# RDP client

def rdp_client_artifacts(entries) -> List[HostArtifact]:
    """Evidence that this host connected out over RDP."""
    artifacts: List[HostArtifact] = []

    cache_total = 0
    cache_files = 0
    newest: Optional[datetime.datetime] = None
    oldest: Optional[datetime.datetime] = None
    owner = ""

    for entry in entries.values():
        path = normalize_path(entry.path)

        if RDP_CACHE_MARKER in path and not entry.is_directory:
            if entry.extension.lower() not in (".bmc", ".bin"):
                continue
            cache_files += 1
            cache_total += entry.logical_size
            modified = _modified(entry)
            if modified:
                newest = max(newest, modified) if newest else modified
                oldest = min(oldest, modified) if oldest else modified
            if not owner:
                parts = entry.path.split("\\")
                if len(parts) > 2:
                    owner = parts[2]

        elif entry.extension.lower() == ".rdp" and not entry.is_directory:
            artifacts.append(HostArtifact(
                category="RDP client",
                name=entry.name,
                detail="RDP connection profile",
                path=entry.path,
                timestamp=_created(entry),
                last_modified=_modified(entry),
                size=entry.logical_size,
                severity="low",
                notes="a saved or default connection profile; the file's "
                      "modification time tracks the last connection settings change",
            ))

    if cache_files:
        artifacts.insert(0, HostArtifact(
            category="RDP client",
            name=f"Bitmap cache ({owner or 'unknown profile'})",
            detail=f"{cache_files} file(s), {cache_total / 1048576:.1f} MB",
            path=f"\\Users\\{owner}\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache"
                 if owner else RDP_CACHE_MARKER,
            timestamp=oldest,
            last_modified=newest,
            size=cache_total,
            severity="medium",
            notes="the bitmap cache only exists if this host initiated RDP "
                  "sessions; its size is a rough measure of how much screen "
                  "content was received",
        ))

    return artifacts


def collect_host_artifacts(entries, baseline=None) -> List[HostArtifact]:
    if not entries:
        return []
    return (event_log_artifacts(entries)
            + user_profile_artifacts(entries, baseline)
            + rdp_client_artifacts(entries))
