"""
Heuristic detections that do not fit the declarative rule model.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from typing import List

from .filetypes import (
    EXECUTABLE_EXTENSIONS, SYSTEM_BINARY_LOCATIONS, SYSWOW64_ALIASES, content_mismatch,
    is_known_extension,
)
from .ntfs import subsecond_is_zero
from .usnjrnl import USN_REASON_FILE_CREATE
from .paths import (
    NTFS_RESERVED_RECORDS,
    is_noise,
    is_ntfs_metadata,
    is_install_managed,
    is_os_managed,
    is_programmatic_timestamp_source,
    is_resolved,
    normalize_path,
    under_any_normalized,
)

# Sub-second component of a FILETIME is the value modulo 10,000,000 (100-ns ticks per second).
TICKS_PER_SECOND = 10_000_000

# Directories holding legitimate copies of system binaries.
SERVICING_STORES = (
    "\\windows\\winsxs", "\\windows\\servicing", "\\windows\\softwaredistribution",
    "\\windows\\installer", "\\windows\\systemapps", "\\windows.old",
    "\\$windows.~bt", "\\$windows.~ws", "\\windows\\system32\\driverstore",
    "\\windows\\system32\\dllstore", "\\programdata\\microsoft\\windows\\containers",
)

# Names that are one edit away from a real system binary.
TYPOSQUAT_TARGETS = [
    "svchost", "lsass", "csrss", "winlogon", "services", "smss",
    "spoolsv", "explorer", "taskhostw", "dllhost", "conhost", "rundll32",
]

BENIGN_ADS = {
    "zone.identifier", "wofcompresseddata", "encryptable", "smartscreen",
    "favicon", "afp_afpinfo", "afp_resource",
}

COMMON_WORD_STEMS = {
    "setup", "install", "installer", "uninstall", "update", "updater", "chrome",
    "firefox", "edge", "teams", "office", "adobe", "reader", "java", "python",
    "node", "git", "notepad", "driver", "service", "client", "server", "agent",
    "helper", "launcher", "manager", "config", "system", "windows", "microsoft",
    "runtime", "library", "package", "component", "framework", "redist",
}


@dataclass
class Finding:
    kind: str
    detail: str
    severity: str = "medium"


# Timestomping

def _subsecond_ticks(raw: int) -> int:
    return raw % TICKS_PER_SECOND if raw else 0


# Weighted signals
REPORT_THRESHOLD = 3

WEIGHT_SUBSECOND_ZEROED = 4
WEIGHT_SI_PREDATES_FN = 3
WEIGHT_FLATTENED = 2
WEIGHT_SUBSECOND_MOSTLY = 3
WEIGHT_SUBSECOND_PARTIAL = 1
WEIGHT_MFT_BEFORE_MODIFIED = 1
WEIGHT_CREATED_AFTER_MODIFIED = 1


def detect_timestomping(entry, threshold_seconds: int = 3600, baseline=None) -> List[Finding]:
    """Score based timestomping detection."""
    findings: List[Finding] = []
    si = entry.si
    fn = entry.best_fn
    score = 0

    # A junction or symlink reports the timestamps of whatever it points at
    if entry.has_reparse_point:
        return []

    # BITS and similar components set download timestamps programmatically,
    # producing the zeroed sub-second signature without any tampering.
    if is_programmatic_timestamp_source(entry.path, entry.name):
        return []

    fn_has_precision = bool(
        fn and any(t is not None and t.microsecond for t in fn.timestamps.as_list()))

    # 1. Sub-second precision. The strongest single indicator.
    si_values = si.timestamps.as_list()
    if all(t is not None for t in si_values):
        zeroed = [i for i, t in enumerate(si_values) if subsecond_is_zero(t)]
        if len(zeroed) == 4 and fn_has_precision:
            score += WEIGHT_SUBSECOND_ZEROED
            findings.append(Finding(
                "si_subsecond_zeroed",
                "all four $SI timestamps have a zeroed sub-second component while "
                "$FN retains full precision",
                "high",
            ))
        elif len(zeroed) == 3 and fn_has_precision:
            score += WEIGHT_SUBSECOND_MOSTLY
            findings.append(Finding(
                "si_subsecond_mostly_zeroed",
                "3 of 4 $SI timestamps have a zeroed sub-second component while "
                "$FN retains full precision",
                "high",
            ))
        elif len(zeroed) == 2 and fn_has_precision:
            score += WEIGHT_SUBSECOND_PARTIAL
            findings.append(Finding(
                "si_subsecond_partial",
                f"{len(zeroed)} of 4 $SI timestamps have zeroed sub-seconds while "
                f"$FN retains full precision",
                "low",
            ))

    if not fn:
        return findings if score >= REPORT_THRESHOLD else []

    fn_ts = fn.timestamps
    # Wider scope than the name heuristics use
    os_managed = is_install_managed(entry.path, entry.name)

    # The baseline adds to the directory list, never replaces it.
    if baseline is not None and baseline.available:
        os_managed = os_managed or baseline.is_epoch(si.timestamps.created)

    # 2. $SI created predating $FN created.
    if (not os_managed and si.timestamps.created and fn_ts.created
            and si.timestamps.created < fn_ts.created):
        delta = (fn_ts.created - si.timestamps.created).total_seconds()
        if delta > max(threshold_seconds, 3600):
            score += WEIGHT_SI_PREDATES_FN
            findings.append(Finding(
                "si_predates_fn_creation",
                f"$SI creation is {int(delta):,}s earlier than $FN creation, "
                f"outside an OS-managed directory",
                "high",
            ))

    # 3. All four $SI values identical and diverging from $FN.
    si_list = si.timestamps.as_list()
    si_values = set(si_list) if all(si_list) else set()
    if (len(si_values) == 1 and fn_ts.created and si.timestamps.created
            and abs((si.timestamps.created - fn_ts.created).total_seconds())
            > threshold_seconds):
        score += WEIGHT_FLATTENED
        findings.append(Finding(
            "si_flattened",
            "all four $SI timestamps are identical and diverge from $FN",
            "medium",
        ))

    # 4. Internally inconsistent ordering.
    if (si.timestamps.mft_modified and si.timestamps.modified
            and (si.timestamps.modified - si.timestamps.mft_modified).total_seconds() > 60):
        score += WEIGHT_MFT_BEFORE_MODIFIED
        findings.append(Finding(
            "si_mft_before_modified",
            "$SI MFT-changed is earlier than $SI modified",
            "low",
        ))

    if (si.timestamps.created and si.timestamps.modified
            and (si.timestamps.created - si.timestamps.modified).total_seconds()
            > threshold_seconds):
        score += WEIGHT_CREATED_AFTER_MODIFIED
        findings.append(Finding(
            "si_created_after_modified",
            "$SI created is later than $SI modified (also normal for a copied file)",
            "low",
        ))

    if score < REPORT_THRESHOLD:
        return []

    confidence = "high" if score >= 6 else "medium" if score >= 4 else "low"
    findings.append(Finding(
        "timestomp_score",
        f"combined timestomping score {score} "
        f"({', '.join(f.kind for f in findings)})",
        confidence,
    ))
    return findings


# Masquerading and naming

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())


def normalized_entropy(s: str) -> float:
    """Entropy divided by its maximum for that length, so lengths compare fairly."""
    if len(s) < 2:
        return 0.0
    return shannon_entropy(s) / math.log2(len(s))


def looks_random(stem: str) -> bool:
    """Heuristic for machine-generated names."""
    s = stem.strip().lower()
    if not (6 <= len(s) <= 20) or s in COMMON_WORD_STEMS:
        return False
    if not re.fullmatch(r"[a-z0-9_-]+", s):
        return False
    if any(word in s for word in COMMON_WORD_STEMS):
        return False

    letters = sum(ch.isalpha() for ch in s)
    if letters < 4:
        return False

    vowels = sum(ch in "aeiou" for ch in s)
    vowel_ratio = vowels / letters
    longest_consonant_run = max(
        (len(run) for run in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", s)), default=0
    )
    digits = sum(ch.isdigit() for ch in s)

    signals = 0
    if normalized_entropy(s) >= 0.92:
        signals += 1
    if vowel_ratio <= 0.22:
        signals += 1
    if longest_consonant_run >= 5:
        signals += 1
    if digits and 0.25 <= digits / len(s) <= 0.75:
        signals += 1

    return signals >= 2


def levenshtein_le_1(a: str, b: str) -> bool:
    """True if a and b differ by at most one edit."""
    if abs(len(a) - len(b)) > 1:
        return False
    if a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long = (a, b) if len(a) < len(b) else (b, a)
    i = j = diff = 0
    while i < len(short) and j < len(long):
        if short[i] != long[j]:
            diff += 1
            if diff > 1:
                return False
            j += 1
            continue
        i += 1
        j += 1
    return True


def detect_masquerading(entry) -> List[Finding]:
    """Naming and stream anomalies."""
    findings: List[Finding] = []
    if entry.is_directory:
        return findings

    # NTFS metadata files carry named streams as part of the format.
    if is_ntfs_metadata(entry.path, entry.record_number, entry.name):
        return findings
    if entry.is_extension_record and entry.base_record < NTFS_RESERVED_RECORDS:
        return findings

    name = entry.name.lower()
    stem, ext = os.path.splitext(name)
    path = normalize_path(entry.path)
    directory = path.rsplit("\\", 1)[0] or "\\"

    expected = SYSTEM_BINARY_LOCATIONS.get(name)
    checked = directory
    for alias in SYSWOW64_ALIASES:
        if checked == alias or checked.startswith(alias + "\\"):
            checked = "\\windows\\syswow64" + checked[len(alias):]
    if (expected and checked not in expected and entry.path_reliable
            and is_resolved(path) and not under_any_normalized(path, SERVICING_STORES)):
        findings.append(Finding(
            "system_binary_wrong_path",
            f"{name} found in {directory}, expected {' or '.join(expected)}",
            "high",
        ))

    if is_noise(path):
        return findings

    if ext == ".exe":
        for target in TYPOSQUAT_TARGETS:
            if levenshtein_le_1(stem, target):
                findings.append(Finding(
                    "system_binary_typosquat",
                    f"filename is one edit from the system binary {target}.exe",
                    "high",
                ))
                break

    # Name shape heuristics only outside OS trees
    if not is_os_managed(path, entry.name):
        if ext in EXECUTABLE_EXTENSIONS and looks_random(stem):
            findings.append(Finding(
                "random_executable_name",
                f"machine-generated-looking executable name '{stem}'",
                "medium",
            ))

        if ext == ".exe" and len(stem) <= 2 and stem.isalnum():
            findings.append(Finding(
                "very_short_executable_name",
                f"single/double character executable name '{stem}'",
                "medium",
            ))

    # Resident content that disagrees with the extension.
    if entry.resident_data:
        label = content_mismatch(entry.resident_data, ext)
        if label:
            findings.append(Finding(
                "content_extension_mismatch",
                f"resident content is {label} but the extension is "
                f"{ext or '(none)'}",
                "high" if label in ("PE executable", "ELF executable") else "medium",
            ))

    for ads in entry.ads_names:
        if ads.lower() not in BENIGN_ADS:
            findings.append(Finding(
                "suspicious_ads",
                f"alternate data stream '{ads}' on {entry.name}",
                "high",
            ))

    if entry.has_reparse_point and ext in EXECUTABLE_EXTENSIONS:
        findings.append(Finding(
            "executable_reparse_point",
            "executable carries a reparse point",
            "low",
        ))

    return findings


# Mass extension change

MASS_EXTENSION_MIN_FILES = 25
MASS_EXTENSION_WINDOW_HOURS = 4


def detect_mass_extension_change(entries, min_files: int = MASS_EXTENSION_MIN_FILES, window_hours: int = MASS_EXTENSION_WINDOW_HOURS):
    """Novel extensions that suddenly appeared across many files."""
    buckets = {}
    for entry in entries.values() if hasattr(entries, "values") else entries:
        if entry.is_directory:
            continue
        extension = entry.extension.lower()
        if is_known_extension(extension):
            continue

        when = entry.si.timestamps.modified or entry.si.timestamps.created
        if when is None:
            continue
        buckets.setdefault(extension, []).append((when, entry))

    results = []
    window = window_hours * 3600
    for extension, items in buckets.items():
        if len(items) < min_files:
            continue
        items.sort(key=lambda pair: pair[0])
        times = [pair[0] for pair in items]

        best = (0, None, None)
        start = 0
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > window:
                start += 1
            count = end - start + 1
            if count > best[0]:
                best = (count, times[start], times[end])
        if best[0] >= min_files:
            records = [entry for when, entry in items if best[1] <= when <= best[2]]
            results.append((extension, records, best[1], best[2]))

    results.sort(key=lambda item: -len(item[1]))
    return results


# Ransom note fan out

NOTE_FANOUT_MIN_DIRS = 20
NOTE_FANOUT_WINDOW_SECONDS = 600
NOTE_FANOUT_EXTENSIONS = {".txt", ".hta", ".html", ".htm", ".rtf", ".pdf", ".url"}

# Names that many installers and tools write into every directory they touch.
NOTE_FANOUT_IGNORE = {
    "desktop.ini", "thumbs.db", "folder.htm", "index.html", "index.htm", "readme.md",
    "license.txt", "license", "copying.txt", "notice.txt", "changelog.txt", "version.txt",
    "manifest.txt", "package.json", "web.config", "robots.txt", "placeholder.txt",
    "__init__.py", "empty.txt", "dummy.txt", "readme.txt", "read_me.txt", "readme.htm",
    "license.rtf", "eula.rtf", "eula.txt", "thirdpartynotices.txt", "credits.txt",
}
NOTE_FANOUT_IGNORE_RE = re.compile(r"(^|[-_.])(license|eula)\.(rtf|txt)$|\.filtertrie\.intermediate\.txt$")


def detect_note_fanout(records, min_dirs: int = NOTE_FANOUT_MIN_DIRS, window_seconds: int = NOTE_FANOUT_WINDOW_SECONDS):
    """The same file name created in many directories within minutes."""
    buckets = {}
    for record in records:
        if not record.reason & USN_REASON_FILE_CREATE or record.is_directory:
            continue
        name = record.name.lower()
        if record.extension not in NOTE_FANOUT_EXTENSIONS or record.timestamp is None:
            continue
        if record.path and is_noise(record.path):
            continue

        if record.path_source and not record.path_source.startswith("resolved"):
            continue
        if NOTE_FANOUT_IGNORE_RE.search(name):
            continue
        buckets.setdefault(name, []).append((record.timestamp, record.parent_record, record))

    results = []
    for name, items in buckets.items():
        if len({parent for _, parent, _ in items}) < min_dirs:
            continue
        items.sort(key=lambda item: item[0])
        best = (0, 0, 0)
        start = 0
        seen = {}
        for end, (when, parent, _) in enumerate(items):
            seen[parent] = seen.get(parent, 0) + 1
            while (when - items[start][0]).total_seconds() > window_seconds:
                old = items[start][1]
                seen[old] -= 1
                if not seen[old]:
                    del seen[old]
                start += 1
            if len(seen) > best[0]:
                best = (len(seen), start, end)
        count, start, end = best
        if count < min_dirs:
            continue
        # Installer names need a burst several times larger to count.
        if name in NOTE_FANOUT_IGNORE and count < min_dirs * 10:
            continue
        chosen = [record for _, _, record in items[start:end + 1]]
        results.append((name, count, chosen, items[start][0], items[end][0]))

    results.sort(key=lambda item: -item[1])
    return results
