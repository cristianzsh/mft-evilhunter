"""
Hunt presets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Sequence, Tuple

from ..filetypes import DOWNLOAD_CONTAINER_EXTENSIONS, EXECUTABLE_EXTENSIONS
from .dataset import SEVERITY_ORDER, Dataset

# Logical field accessors

def rule_names(ds: Dataset, row: Sequence[str]) -> str:
    return ds.value(row, "rules") or ds.value(row, "rule")


def categories(ds: Dataset, row: Sequence[str]) -> str:
    return (ds.value(row, "categories") or ds.value(row, "category")).replace(" ", "_")


def finding_kinds(ds: Dataset, row: Sequence[str]) -> str:
    return ds.value(row, "findings") or ds.value(row, "finding")


def severity(ds: Dataset, row: Sequence[str]) -> str:
    return ds.value(row, "severity")


def path_of(ds: Dataset, row: Sequence[str]) -> str:
    return ds.value(row, "path")


def name_of(ds: Dataset, row: Sequence[str]) -> str:
    return ds.value(row, "name")


HAS_RULES = ("rules", "rule")
HAS_CATEGORY = ("categories", "category")
HAS_FINDINGS = ("findings", "finding")


@dataclass
class Hunt:
    key: str
    title: str
    group: str
    description: str
    predicate: Callable[[Dataset, Sequence[str]], bool]
    # Each entry is a tuple of alternatives; the dataset must have at least one
    # of each tuple for the hunt to be meaningful on that tab.
    requires: Tuple[Tuple[str, ...], ...] = field(default_factory=tuple)

    def applies_to(self, ds: Dataset) -> bool:
        return all(any(ds.has(c) for c in group) for group in self.requires)

    def matches(self, ds: Dataset, row: Sequence[str]) -> bool:
        try:
            return self.predicate(ds, row)
        except Exception:
            return False


# Predicate helpers

def _any_token(text: str, tokens: Sequence[str]) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in tokens)


def _min_severity(value: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(value, 0) >= SEVERITY_ORDER.get(floor, 0)


def _in_users_folder(path: str) -> bool:
    p = path.lower().replace("/", "\\")
    return p.startswith("\\users\\") or "\\users\\" in p


TEMP_MARKERS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\temp\\", "\\tmp\\",
    "\\users\\public\\", "\\programdata\\", "\\perflogs\\", "\\$recycle.bin\\",
)

MASQUERADE_FINDINGS = (
    "system_binary_wrong_path", "system_binary_typosquat", "random_executable_name",
    "very_short_executable_name",
)

MASQUERADE_RULES = (
    "double_extension_executable", "rtlo_filename", "system_binary_wrong_location",
    "explorer_wrong_location", "trailing_space_or_dot_name", "cobalt_strike_beacon_names",
)


# Hunt definitions

def _psexec(ds, row):
    text = " ".join((rule_names(ds, row), name_of(ds, row), ds.value(row, "image"))).lower()
    return _any_token(text, ("psexec", "psexesvc", "paexec", "remcom", "csexec"))


def _psexec_source_hosts(ds, row):
    return "source_host=" in ds.value(row, "extracted")


def _lateral_movement(ds, row):
    cats = categories(ds, row)
    return "lateral_movement" in cats or "remote_execution" in cats


def _ransomware(ds, row):
    if "impact" in categories(ds, row):
        return True
    return _any_token(rule_names(ds, row), ("ransom", "encrypted_extension"))


def _suspicious_names(ds, row):
    if _any_token(finding_kinds(ds, row), MASQUERADE_FINDINGS):
        return True
    return _any_token(rule_names(ds, row), MASQUERADE_RULES)


def _timestomping(ds, row):
    return "si_" in finding_kinds(ds, row) or "record_order_anomaly" in finding_kinds(ds, row)


def _timestomping_in_users(ds, row):
    return _timestomping(ds, row) and _in_users_folder(path_of(ds, row))


def _high_confidence_timestomping(ds, row):
    kinds = finding_kinds(ds, row)
    return "si_subsecond_zeroed" in kinds or "si_predates_fn_creation" in kinds \
        or "si_flattened" in kinds


def _executables_in_writable_dirs(ds, row):
    ext = ds.value(row, "extension").lower()
    if ext not in EXECUTABLE_EXTENSIONS:
        return False
    return _any_token(path_of(ds, row), TEMP_MARKERS)


def _alternate_data_streams(ds, row):
    streams = [s.strip().lower() for s in ds.value(row, "ads_names").split("|") if s.strip()]
    if any(s != "zone.identifier" for s in streams):
        return True
    return "suspicious_ads" in finding_kinds(ds, row)


def _deleted_executables(ds, row):
    if ds.value(row, "extension").lower() not in EXECUTABLE_EXTENSIONS:
        return False
    if ds.has("deleted"):
        # Short-lived files are deleted by definition.
        return True
    if ds.value(row, "is_deleted").lower() == "true":
        return True
    action = ds.value(row, "action")
    return (action in ("FileNameRemoved", "FileRecordDeleted", "FileDelete")
            or "FILE_DELETE" in ds.value(row, "reason"))


def _downloaded(ds, row):
    """Anything carrying Mark-of-the-Web."""
    return bool(ds.value(row, "zone_id"))


def _downloaded_from_internet(ds, row):
    return ds.value(row, "zone_id") in ("3", "4")


def _downloaded_executable(ds, row):
    return (_downloaded_from_internet(ds, row)
            and ds.value(row, "extension").lower() in EXECUTABLE_EXTENSIONS)


def _downloaded_container(ds, row):
    return (_downloaded_from_internet(ds, row)
            and ds.value(row, "extension").lower() in DOWNLOAD_CONTAINER_EXTENSIONS)


def _has_download_url(ds, row):
    return bool(ds.value(row, "download_url") or ds.value(row, "download_referrer"))


def _downloaded_outside_user_dirs(ds, row):
    if not _downloaded_from_internet(ds, row):
        return False
    path = path_of(ds, row).lower()
    return not (path.startswith("\\users\\") and "\\downloads\\" in path)


# renames

def _rename_flagged(ds, row):
    return bool(ds.value(row, "severity"))


def _rename_onto_system_binary(ds, row):
    return "system binary name" in ds.value(row, "notes")


def _rename_became_executable(ds, row):
    return "became executable" in ds.value(row, "notes")


def _rename_all_real(ds, row):
    """Every rename outside ordinary system housekeeping."""
    return ds.value(row, "os_churn") != "true"


# host artifacts

def _host_event_logs(ds, row):
    return ds.value(row, "category") == "Event log"


def _host_profiles(ds, row):
    return ds.value(row, "category") == "User profile"


def _host_rdp(ds, row):
    return ds.value(row, "category") == "RDP client"


def _host_flagged(ds, row):
    return ds.value(row, "severity") in ("medium", "high", "critical")


# execution

def _executed_lolbin(ds, row):
    return bool(ds.value(row, "category"))


def _executed_binary_missing(ds, row):
    return ds.value(row, "binary_present").lower() == "false"


def _executed_outside_windows(ds, row):
    return ds.value(row, "outside_windows").lower() == "true"


def _executed_prefetch_deleted(ds, row):
    return ds.value(row, "prefetch_deleted").lower() == "true"


def _executed_credential_or_impact(ds, row):
    return ds.value(row, "category") in ("credential access", "impact",
                                         "exfiltration", "remote execution")


# journal

def _seconds(ds, row) -> float:
    raw = ds.value(row, "seconds")
    try:
        return float(raw)
    except ValueError:
        return float("inf")


def _is_churn(ds, row) -> bool:
    return ds.value(row, "os_churn") == "true"


def _short_lived(ds, row):
    """Created and deleted inside a minute."""
    return _seconds(ds, row) <= 60 and not _is_churn(ds, row)


def _very_short_lived(ds, row):
    return _seconds(ds, row) <= 10 and not _is_churn(ds, row)


def _short_lived_including_churn(ds, row):
    return _seconds(ds, row) <= 60


def _short_lived_executable(ds, row):
    return _short_lived(ds, row) and ds.value(row, "extension").lower() in EXECUTABLE_EXTENSIONS


def _journal_deletions(ds, row):
    action = ds.value(row, "action")
    return action == "FileDelete" or "FILE_DELETE" in ds.value(row, "reason")


def _journal_renames(ds, row):
    reason = ds.value(row, "reason")
    return "RENAME_OLD_NAME" in reason or "RENAME_NEW_NAME" in reason


def _journal_stream_writes(ds, row):
    """Named-stream activity: ADS being written, including Zone.Identifier."""
    reason = ds.value(row, "reason")
    return "NAMED_DATA" in reason or "STREAM_CHANGE" in reason


def _journal_executable_creates(ds, row):
    return ("FILE_CREATE" in ds.value(row, "reason")
            and ds.value(row, "extension").lower() in EXECUTABLE_EXTENSIONS)


def _credential_access(ds, row):
    return "credential_access" in categories(ds, row)


def _persistence(ds, row):
    return "persistence" in categories(ds, row)


def _exfiltration(ds, row):
    cats = categories(ds, row)
    return "exfiltration" in cats or "collection" in cats or "command_and_control" in cats


def _discovery_and_tampering(ds, row):
    if "discovery" in categories(ds, row):
        return True
    return _any_token(rule_names(ds, row), ("edr_killer_tooling", "vulnerable_driver_name"))


def _critical_and_high(ds, row):
    return _min_severity(severity(ds, row), "high")


def _anything_flagged(ds, row):
    return bool(rule_names(ds, row) or finding_kinds(ds, row)
                or _min_severity(severity(ds, row), "low"))


def _unreliable_paths(ds, row):
    if ds.has("path_reliable"):
        return ds.value(row, "path_reliable").lower() == "false"
    source = ds.value(row, "path_source")
    return bool(source) and not source.startswith("resolved")


def _carved_only(ds, row):
    return ds.value(row, "source") == "carved"


def _parse_errors(ds, row):
    return bool(ds.value(row, "parse_error"))


HUNTS: List[Hunt] = [
    # lateral movement
    Hunt("psexec", "PsExec & clones", "Lateral movement",
         "PsExec .key files, PSEXESVC, and equivalents (PAExec, RemCom, CSExec).",
         _psexec, (("rules", "rule", "image"),)),
    Hunt("psexec_hosts", "Source hostnames only", "Lateral movement",
         "Rows where a source hostname was extracted. These name the machines "
         "the operator connected FROM.",
         _psexec_source_hosts, (("extracted",),)),
    Hunt("lateral", "All lateral movement", "Lateral movement",
         "Everything in the lateral_movement category, including Impacket staging files.",
         _lateral_movement, (HAS_CATEGORY,)),

    # malware
    Hunt("suspicious_names", "Suspicious file names", "Suspicious files",
         "Masquerading system binaries, typosquats, double extensions, RTLO "
         "trickery and machine-generated names.",
         _suspicious_names, (HAS_RULES,)),
    Hunt("exec_writable", "Executables in temp & writable dirs", "Suspicious files",
         "Executable or script content under Temp, Public, ProgramData, PerfLogs "
         "or the Recycle Bin.",
         _executables_in_writable_dirs, (("extension",), ("path",))),
    Hunt("ads", "Alternate data streams", "Suspicious files",
         "Files carrying a named $DATA stream, excluding the ordinary "
         "Zone.Identifier one.",
         _alternate_data_streams, ()),
    Hunt("deleted_exec", "Deleted executables", "Suspicious files",
         "Executable content that has been unlinked or whose record is free.",
         _deleted_executables, (("extension",),)),

    # ransomware
    Hunt("ransomware", "Ransomware indicators", "Ransomware",
         "Family extensions, generic encryption suffixes and ransom note names.",
         _ransomware, (HAS_CATEGORY,)),

    # timestomping
    Hunt("timestomp", "All timestomping findings", "Timestomping",
         "Any $SI/$FN divergence or precision anomaly.",
         _timestomping, (HAS_FINDINGS,)),
    Hunt("timestomp_users", "Timestomping in \\Users", "Timestomping",
         "Timestomping findings restricted to user profile directories.",
         _timestomping_in_users, (HAS_FINDINGS, ("path",))),
    Hunt("timestomp_strong", "High-confidence timestomping only", "Timestomping",
         "Zeroed sub-second precision, backdated $SI, or flattened $SI timestamps.",
         _high_confidence_timestomping, (HAS_FINDINGS,)),

    # downloads
    Hunt("downloaded", "Everything downloaded from the internet", "Downloads",
         "Files carrying Mark-of-the-Web (ZoneId 3 or 4). The download_url and "
         "download_referrer columns show where each one came from.",
         _downloaded_from_internet, (("zone_id",),)),
    Hunt("downloaded_exec", "Downloaded executables", "Downloads",
         "Executable or script content that arrived from the internet. Check the "
         "recorded URL against known delivery infrastructure.",
         _downloaded_executable, (("zone_id",), ("extension",))),
    Hunt("downloaded_container", "Downloaded archives & disk images", "Downloads",
         "ZIP, RAR, ISO and IMG containers. ISO and IMG are used specifically "
         "because Mark-of-the-Web does not propagate to their contents.",
         _downloaded_container, (("zone_id",), ("extension",))),
    Hunt("downloaded_outside_downloads", "Downloaded, but not into Downloads",
         "Downloads",
         "Mark-of-the-Web on a file that did not land in a browser download "
         "directory - something fetched it straight to that location.",
         _downloaded_outside_user_dirs, (("zone_id",), ("path",))),
    Hunt("has_download_url", "Any recorded download URL", "Downloads",
         "Rows where a HostUrl or ReferrerUrl survived in the Zone.Identifier "
         "stream, whatever the zone.",
         _has_download_url, (("download_url",),)),

    # renames
    Hunt("rename_flagged", "Notable renames", "Renames",
         "Renames that changed what a file is, not just where it lives: onto a "
         "system binary name, or into an executable extension.",
         _rename_flagged, (("old_name",), ("severity",))),
    Hunt("rename_masquerade", "Renamed onto a system binary name", "Renames",
         "The $MFT only shows a file's final name. This shows a payload "
         "arriving under one name and being renamed onto svchost.exe.",
         _rename_onto_system_binary, (("old_name",), ("notes",))),
    Hunt("rename_became_exec", "Became executable", "Renames",
         "A non-executable renamed into an executable extension -- including "
         "the browser's own .crdownload completion, which dates a download to "
         "the second.",
         _rename_became_executable, (("old_name",), ("notes",))),
    Hunt("rename_all_real", "All renames except system housekeeping", "Renames",
         "Excludes database log rotation and installer temp-file patterns, "
         "which are the overwhelming majority.",
         _rename_all_real, (("old_name",), ("os_churn",))),

    # host artifacts
    Hunt("host_flagged", "Notable host artifacts", "Host",
         "Everything the host-artifact pass rated medium or above.",
         _host_flagged, (("category",), ("detail",))),
    Hunt("host_event_logs", "Event logs created or cleared", "Host",
         "Logs whose creation time sits well after the rest of the set. For a "
         "core log that means clearing; for an operational log it may mean "
         "first use of the feature.",
         _host_event_logs, (("category",), ("detail",))),
    Hunt("host_profiles", "User profiles", "Host",
         "Profile directories, and whether each appeared after the volume was "
         "imaged.",
         _host_profiles, (("category",), ("detail",))),
    Hunt("host_rdp", "Outbound RDP evidence", "Host",
         "Terminal Server Client bitmap cache and saved connection profiles: "
         "evidence this host connected OUT, which its own Security log cannot "
         "show.",
         _host_rdp, (("category",), ("detail",))),

    # execution
    Hunt("exec_lolbin", "LOLBins and attacker tooling that ran", "Execution",
         "Executables with a Prefetch record whose name matches a "
         "living-off-the-land binary or known tool. These are unremarkable on "
         "disk; what matters is that they ran, and when.",
         _executed_lolbin, (("image",), ("category",))),
    Hunt("exec_high_value", "High-value tooling only", "Execution",
         "Credential access, remote execution, exfiltration and destructive "
         "categories.",
         _executed_credential_or_impact, (("image",), ("category",))),
    Hunt("exec_missing_binary", "Ran, but the binary is gone", "Execution",
         "Prefetch survives but no live file record does -- the executable was "
         "deleted after use.",
         _executed_binary_missing, (("image",), ("binary_present",))),
    Hunt("exec_outside_windows", "Ran from outside \\Windows", "Execution",
         "Execution from a user profile, ProgramData or removable media rather "
         "than a system directory.",
         _executed_outside_windows, (("image",), ("outside_windows",))),
    Hunt("exec_prefetch_deleted", "Prefetch file itself was deleted", "Execution",
         "Prefetch removal is an anti-forensic step; the record survives only in "
         "$UsnJrnl or $LogFile.",
         _executed_prefetch_deleted, (("image",), ("prefetch_deleted",))),

    # journal
    Hunt("short_lived", "Created and deleted within a minute", "Journal",
         "Files the journal saw appear and disappear inside 60 seconds. Tooling "
         "that cleans up after itself lands here: PsExec key files, Impacket "
         "output, dropped payloads.",
         _short_lived, (("seconds",),)),
    Hunt("very_short_lived", "Created and deleted within 10 seconds", "Journal",
         "The tightest window. Almost nothing legitimate lives this briefly.",
         _very_short_lived, (("seconds",),)),
    Hunt("short_lived_exec", "Short-lived executables", "Journal",
         "Executable or script content that existed for under a minute.",
         _short_lived_executable, (("seconds",), ("extension",))),
    Hunt("short_lived_all", "Short-lived, including OS churn", "Journal",
         "The unfiltered view. Browser component updates and task registration "
         "dominate it, which is why the other hunts exclude them.",
         _short_lived_including_churn, (("seconds",),)),
    Hunt("journal_exec_created", "Executables created", "Journal",
         "FILE_CREATE records for executable and script content.",
         _journal_executable_creates, (("reason",), ("extension",))),
    Hunt("journal_deletions", "Deletions", "Journal",
         "Every FILE_DELETE record in the journal.",
         _journal_deletions, (("reason",),)),
    Hunt("journal_renames", "Renames", "Journal",
         "RENAME_OLD_NAME / RENAME_NEW_NAME pairs. Renaming a payload onto a "
         "system binary name shows up here even when the $MFT keeps only the "
         "final name.",
         _journal_renames, (("reason",),)),
    Hunt("journal_streams", "Alternate data stream writes", "Journal",
         "Named-stream activity, including Mark-of-the-Web being applied.",
         _journal_stream_writes, (("reason",),)),

    # tradecraft
    Hunt("credentials", "Credential access", "Attacker tradecraft",
         "LSASS dumps, credential tooling, and hive copies outside their normal path.",
         _credential_access, (HAS_CATEGORY,)),
    Hunt("persistence", "Persistence", "Attacker tradecraft",
         "Startup folder content, web shells and scheduled task definitions.",
         _persistence, (HAS_CATEGORY,)),
    Hunt("exfil", "Collection, C2 & exfiltration", "Attacker tradecraft",
         "Staged archives, RMM tooling, tunnels and exfiltration utilities.",
         _exfiltration, (HAS_CATEGORY,)),
    Hunt("discovery", "Discovery & security tampering", "Attacker tradecraft",
         "Network scanners, AD enumeration tooling, EDR killers and the drivers they load.",
         _discovery_and_tampering, (HAS_CATEGORY, HAS_RULES)),

    # triage
    Hunt("crit_high", "Critical & high severity only", "Triage",
         "Everything the rule set rated high or above.",
         _critical_and_high, (("severity",),)),
    Hunt("flagged", "Anything flagged at all", "Triage",
         "Any row with a rule hit or a heuristic finding.",
         _anything_flagged, ()),

    # data quality
    Hunt("unreliable", "Unreliable paths", "Evidence quality",
         "Rows whose reconstructed path depends on a reused, missing or cyclic "
         "parent record. Verify before quoting these in a report.",
         _unreliable_paths, (("path_reliable", "path_source"),)),
    Hunt("carved", "Carved $LogFile events only", "Evidence quality",
         "$LogFile events recovered by signature carving rather than structured "
         "opcode decoding.",
         _carved_only, (("source",),)),
    Hunt("parse_errors", "Records with parse errors", "Evidence quality",
         "Records that were damaged but still yielded data.",
         _parse_errors, (("parse_error",),)),
]

HUNTS_BY_KEY = {h.key: h for h in HUNTS}


def groups() -> List[str]:
    seen: List[str] = []
    for hunt in HUNTS:
        if hunt.group not in seen:
            seen.append(hunt.group)
    return seen


def hunts_in_group(group: str) -> List[Hunt]:
    return [h for h in HUNTS if h.group == group]


def apply_hunt(hunt: Hunt, ds: Dataset) -> List[int]:
    """Return the source row indices a hunt selects."""
    if not hunt.applies_to(ds):
        return []
    return [i for i, row in enumerate(ds.rows) if hunt.matches(ds, row)]
