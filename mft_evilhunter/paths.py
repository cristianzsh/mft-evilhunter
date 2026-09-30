"""
Path normalisation and noise suppression.
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence

# Paths that could not be reconstructed
UNRESOLVED_PREFIXES = (
    "\\$unknownparent", "\\$orphan", "\\$cycle", "\\$depthlimit", "\\$missingparent",
)

# Legitimate, high-volume directories
NOISE_PATHS: tuple = (
    # Windows servicing and component store, and the previous installation
    # left behind by an in place upgrade
    "\\windows.old\\",
    "\\$windows.~bt\\",
    "\\$windows.~ws\\",
    "\\windows\\winsxs\\",
    "\\windows\\servicing\\",
    "\\windows\\softwaredistribution\\",
    "\\windows\\installer\\",
    "\\windows\\assembly\\",
    "\\windows\\microsoft.net\\",
    "\\windows\\panther\\",
    "\\windows\\system32\\driverstore\\",
    "\\windows\\syswow64\\driverstore\\",
    "\\windows\\system32\\catroot\\",
    "\\windows\\system32\\catroot2\\",
    "\\windows\\system32\\dllstore\\",
    "\\windows\\system32\\wbem\\",
    "\\windows\\system32\\windowspowershell\\",
    "\\windows\\immersivecontrolpanel\\",
    "\\windows\\systemapps\\",
    "\\windows\\systemresources\\",
    "\\windows\\shellexperiences\\",
    "\\windows\\ime\\",
    "\\windows\\inf\\",
    "\\windows\\policydefinitions\\",

    # Installed software
    "\\program files\\",
    "\\program files (x86)\\",

    # ProgramData: almost entirely vendor state and one of the top false positive sources
    "\\programdata\\microsoft\\",
    "\\programdata\\package cache\\",
    "\\programdata\\packages\\",
    "\\programdata\\usoshared\\",
    "\\programdata\\windows\\",
    "\\programdata\\ni\\",
    "\\programdata\\intel\\",
    "\\programdata\\nvidia\\",
    "\\programdata\\nvidia corporation\\",
    "\\programdata\\adobe\\",
    "\\programdata\\vmware\\",
    "\\programdata\\chocolatey\\",
    "\\programdata\\anaconda3\\",
    "\\programdata\\docker\\",
    "\\programdata\\oracle\\",
    "\\programdata\\microsoft onedrive\\",
    # OEM updaters and security products, all of which keep executables here
    "\\programdata\\dell\\",
    "\\programdata\\hp\\",
    "\\programdata\\lenovo\\",
    "\\programdata\\logitech\\",
    "\\programdata\\realtek\\",
    "\\programdata\\kaspersky lab\\",
    "\\programdata\\eset\\",
    "\\programdata\\sophos\\",
    "\\programdata\\mcafee\\",
    "\\programdata\\symantec\\",
    "\\programdata\\crowdstrike\\",
    "\\programdata\\sentinel\\",
    "\\programdata\\carbonblack\\",
    "\\programdata\\malwarebytes\\",

    # User profile application state
    "\\appdata\\local\\microsoft\\",
    "\\appdata\\local\\packages\\",
    "\\appdata\\local\\google\\",
    "\\appdata\\local\\mozilla\\",
    "\\appdata\\local\\programs\\microsoft vs code\\",
    "\\appdata\\local\\slack\\",
    "\\appdata\\local\\discord\\",
    "\\appdata\\local\\jetbrains\\",
    "\\appdata\\local\\nvidia\\",
    "\\appdata\\local\\docker\\",
    "\\appdata\\roaming\\microsoft\\",
    "\\appdata\\roaming\\adobe\\",
    "\\appdata\\roaming\\code\\",
    "\\appdata\\roaming\\npm\\",
    "\\appdata\\roaming\\python\\",

    # Developer and runtime trees that contain thousands of scripts and binaries
    "\\node_modules\\",
    "\\site-packages\\",
    "\\.git\\",
    "\\.cache\\",
    "\\gradle\\",
    "\\.nuget\\",
    "\\windows\\temp\\mpcmdrun",

    # Task registration writes and immediately deletes entries under the
    # Microsoft tree; it dominates $UsnJrnl short-lived file analysis.
    "\\windows\\system32\\tasks\\microsoft\\",
    "\\windows\\security\\logs\\",
    "\\windows\\winsxs\\temp\\",
    "\\programdata\\usoprivate\\",
    "\\programdata\\usoshared\\",
    "\\temporary internet files\\",
)


_DRIVE_PREFIX = re.compile(r"^[a-z]:\\")


def normalize_path(path) -> str:
    """
    Normalise to a lowercase, backslash-separated, drive-less absolute path.

    Accepts the forms an analyst actually types: C:\\Users, C:/Users/, \\Users,
    Users.
    """
    if not path:
        return ""
    p = str(path).strip().strip("'\"").replace("/", "\\").lower()
    if _DRIVE_PREFIX.match(p):
        p = p[2:]
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    if p and not p.startswith("\\"):
        p = "\\" + p
    return p.rstrip("\\") or "\\"


def is_resolved(path: str) -> bool:
    """False for placeholder paths produced when reconstruction failed."""
    if not path:
        return False
    p = normalize_path(path)
    return not p.startswith(UNRESOLVED_PREFIXES)


def directory_of(path: str) -> str:
    p = normalize_path(path)
    head = p.rsplit("\\", 1)[0]
    return head or "\\"


def under_any(path: str, prefixes: Sequence[str]) -> bool:
    """True if path sits under any of the given directory prefixes."""
    return under_any_normalized(normalize_path(path),
                                [normalize_path(q) for q in prefixes])


def under_any_normalized(path: str, prefixes: Sequence[str]) -> bool:
    """As under_any, but both sides are already normalised."""
    for prefix in prefixes:
        if prefix == "\\":
            return True
        if path == prefix or path.startswith(prefix + "\\"):
            return True
    return False


def contains_any(path: str, markers: Iterable[str]) -> bool:
    p = normalize_path(path)
    return any(marker.lower() in p for marker in markers)


# Trees installed from the image or by a vendor
OS_MANAGED_PREFIXES = (
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\users\\default\\",
    "\\users\\default user\\",
    "\\system volume information\\",
)

# Writable scratch space that happens to sit under an OS-managed prefix
OS_MANAGED_EXCEPTIONS = (
    "\\windows\\temp\\",
    "\\windows\\tasks\\",
    "\\windows\\system32\\tasks\\",
    "\\windows\\debug\\",
    "\\windows\\tracing\\",
    "\\windows\\addins\\",
    "\\windows\\system32\\spool\\drivers\\color\\",
    "\\program files\\common files\\temp\\",
)

OS_MANAGED_MARKERS = (
    "\\appdata\\local\\packages\\",
    "\\appdata\\local\\microsoft\\",
    "\\appdata\\roaming\\microsoft\\",
    "\\winsxs\\",
    "\\assembly\\",
)

# Files Windows copies around wholesale, carrying their original timestamps.
OS_MANAGED_NAMES = ("desktop.ini", "thumbs.db", "ntuser.dat", "ntuser.ini")
OS_MANAGED_SUFFIXES = (".library-ms", ".searchconnector-ms")

# Volume-root entries created by Setup
OS_ROOT_ENTRIES = frozenset({
    "\\", "\\windows", "\\users", "\\perflogs", "\\programdata",
    "\\program files", "\\program files (x86)", "\\$recycle.bin",
    "\\recovery", "\\system volume information", "\\boot",
    "\\documents and settings", "\\users\\all users", "\\users\\default",
    "\\users\\default user", "\\users\\public",
})

# BITS (Background Intelligent Transfer Service) writes its temporary download
# files with programmatically-set timestamps, which mimics timestomping.
_BITS_TEMP = re.compile(r"(?i)^BIT[0-9A-F]{1,8}\.tmp$")


# NTFS reserved metadata records. Named streams there are the file format,
# not an attacker hiding data.
NTFS_RESERVED_RECORDS = 27


def is_ntfs_metadata(path: str, record_number: int = -1, name: str = "") -> bool:
    """True for NTFS's own metadata files."""
    p = normalize_path(path)
    if p.startswith("\\$extend"):
        return True
    if 0 <= record_number < NTFS_RESERVED_RECORDS:
        leaf = (name or p.rsplit("\\", 1)[-1])
        return leaf.startswith("$") or p == "\\"
    return False


# Timestamp heuristics need a wider exclusion than name heuristics. ProgramData
# and Users\Public are attacker writable, so an odd name there matters, but they
# are also full of installer output carrying source media timestamps.
INSTALL_MANAGED_PREFIXES = OS_MANAGED_PREFIXES + (
    "\\programdata\\",
    "\\users\\public\\",
    "\\users\\all users\\",
)


def is_install_managed(path: str, name: str = "") -> bool:
    """True where files are written by Setup, Windows itself, or a vendor installer."""
    p = normalize_path(path)
    if not is_resolved(p):
        return False
    if p in OS_ROOT_ENTRIES:
        return True
    if name:
        lowered = name.lower()
        if (lowered in OS_MANAGED_NAMES or lowered.endswith(OS_MANAGED_SUFFIXES)
                or _BITS_TEMP.match(name)):
            return True
    if under_any(p, INSTALL_MANAGED_PREFIXES):
        return True
    return any(marker in p for marker in OS_MANAGED_MARKERS)


def is_programmatic_timestamp_source(path: str, name: str = "") -> bool:
    """
    True for files whose timestamps are set programmatically by a Windows
    component, producing the same low-precision signature as timestomping.
    """
    if name and _BITS_TEMP.match(name):
        return True
    p = normalize_path(path)
    return "\\appdata\\local\\temp\\edge_bits_" in p or "\\bits\\" in p


def is_os_managed(path: str, name: str = "") -> bool:
    """True if the file is installed and maintained by Windows or a vendor."""
    p = normalize_path(path)
    if not is_resolved(p):
        return False
    if p in OS_ROOT_ENTRIES:
        return True
    if name:
        lowered = name.lower()
        if (lowered in OS_MANAGED_NAMES or lowered.endswith(OS_MANAGED_SUFFIXES)
                or _BITS_TEMP.match(name)):
            return True
    if under_any(p, OS_MANAGED_EXCEPTIONS):
        return False
    if under_any(p, OS_MANAGED_PREFIXES):
        return True
    return any(marker in p for marker in OS_MANAGED_MARKERS)


def is_noise(path: str, extra: Sequence[str] = ()) -> bool:
    """True if the path lives in a known-legitimate, high-volume directory."""
    return is_noise_normalized(normalize_path(path),
                               [m.lower().replace("/", "\\") for m in extra])


def is_noise_normalized(path: str, extra: Sequence[str] = ()) -> bool:
    """As is_noise, for a path that has already been normalised."""
    if not path or path.startswith(UNRESOLVED_PREFIXES):
        return False
    for marker in NOISE_PATHS:
        if marker in path:
            return True
    return any(marker in path for marker in extra)


def resolve_child_path(parent, name: str, parent_record: int, parent_sequence: int = 0):
    """
    Build a child path from a parent $MFT entry and say how much to trust it.
    Shared by the $LogFile and $UsnJrnl resolvers.
    """
    if parent is None:
        return f"\\$UnknownParent-{parent_record}\\{name}", "parent not in $MFT"

    base = getattr(parent, "path", "") or ""
    base = "" if base == "\\" else base.rstrip("\\")
    path = f"{base}\\{name}"

    sequence = getattr(parent, "sequence_number", 0)
    deleted_parent = False
    if parent_sequence and sequence != parent_sequence:
        if not getattr(parent, "in_use", True) and sequence == parent_sequence + 1:
            deleted_parent = True
        else:
            return path, (f"unreliable: parent sequence {parent_sequence} != {sequence}")
    if not getattr(parent, "is_directory", True):
        # Either the record has been reused, or the journal and the $MFT came
        # from different volumes. Either way the path is meaningless.
        return path, "unreliable: parent record is not a directory"
    if not getattr(parent, "path_reliable", True):
        return path, "unreliable: parent path itself unreliable"
    if deleted_parent:
        return path, "resolved: parent directory deleted"
    return path, "resolved"


def is_resolved_source(source: str) -> bool:
    """True for path_source values that mean the path can be trusted."""
    return source.startswith("resolved")
