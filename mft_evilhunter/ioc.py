"""
IOC rule engine.

One declarative JSON rule pack is matched against $MFT entries, $LogFile events
and $UsnJrnl records.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .paths import (
    is_noise_normalized,
    is_resolved,
    normalize_path,
    under_any_normalized,
)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A regex that already sets its own flags, such as (?s) or (?-i:...), is left alone.
_INLINE_FLAGS = re.compile(r"^\(\?[aiLmsux]+\)")


@dataclass
class Subject:
    """Normalised view of an artifact, so rules do not care where it came from."""
    name: str
    path: str
    extension: str
    size: int = 0
    is_deleted: bool = False
    is_directory: bool = False
    artifact: str = "$MFT"
    zone_id: str = ""
    download_url: str = ""
    path_reliable: bool = True

    def __post_init__(self):
        self._path_norm = normalize_path(self.path)
        # A $LogFile event whose parent directory no longer exists still carries
        # a real filename. Path conditions must be skipped for it. The same goes
        # for a path built through a reused parent record: the name is real,
        # the directory is not.
        self.path_known = self.path_reliable and is_resolved(self._path_norm)

    @property
    def name_lower(self) -> str:
        return self.name.lower()

    @property
    def path_lower(self) -> str:
        return self._path_norm


@dataclass
class Match:
    rule_name: str
    title: str
    severity: str
    category: str
    mitre: List[str] = field(default_factory=list)
    extracted: Dict[str, str] = field(default_factory=dict)
    evidence: str = ""

    @property
    def extracted_str(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in sorted(self.extracted.items()))


@dataclass
class Rule:
    name: str
    title: str = ""
    description: str = ""
    severity: str = "medium"
    category: str = "generic"
    mitre: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    enabled: bool = True

    name_regex: Optional[str] = None
    path_regex: Optional[str] = None
    name_contains: List[str] = field(default_factory=list)
    path_contains: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    name_equals: List[str] = field(default_factory=list)

    # Where the artifact actually lives
    path_prefix: List[str] = field(default_factory=list)
    path_not_prefix: List[str] = field(default_factory=list)
    path_not_contains: List[str] = field(default_factory=list)
    path_not_regex: Optional[str] = None

    # Skip the shared noise list for rules where location is not what makes the
    # artifact suspicious.
    noise_filter: bool = True
    # For rules where an unexpected location is the whole signal. Without a
    # reconstructed path there is nothing to judge, so they stay silent.
    requires_path: bool = False
    extra_noise: List[str] = field(default_factory=list)

    zone_ids: List[str] = field(default_factory=list)

    min_size: Optional[int] = None
    max_size: Optional[int] = None
    deleted_only: bool = False
    files_only: bool = True

    _name_re: Optional[re.Pattern] = None
    _path_re: Optional[re.Pattern] = None
    _path_not_re: Optional[re.Pattern] = None
    _path_prefix_norm: List[str] = field(default_factory=list)
    _path_not_prefix_norm: List[str] = field(default_factory=list)
    _extra_noise_norm: List[str] = field(default_factory=list)

    def compile(self) -> "Rule":
        if self.name_regex:
            self._name_re = re.compile(self.name_regex)
        if self.path_regex:
            self._path_re = re.compile(self.path_regex)
        if self.path_not_regex:
            self._path_not_re = re.compile(self.path_not_regex)
        self.zone_ids = [str(z) for z in self.zone_ids]
        if not self.title:
            self.title = self.name
        self.extensions = [e.lower() if e.startswith(".") else "." + e.lower()
                           for e in self.extensions]
        self.name_contains = [s.lower() for s in self.name_contains]
        self.path_contains = [s.lower() for s in self.path_contains]
        self.name_equals = [s.lower() for s in self.name_equals]
        self.path_not_contains = [s.lower().replace("/", "\\")
                                  for s in self.path_not_contains]
        # Prefixes and noise markers are constant, so normalise them once here
        # rather than on every subject.
        self._path_prefix_norm = [normalize_path(p) for p in self.path_prefix]
        self._path_not_prefix_norm = [normalize_path(p) for p in self.path_not_prefix]
        self._extra_noise_norm = [m.lower().replace("/", "\\")
                                  for m in self.extra_noise]
        return self

    @property
    def has_non_path_condition(self) -> bool:
        return bool(self.name_regex or self.name_contains or self.name_equals
                    or self.extensions or self.zone_ids)

    @property
    def identifies_by_name(self) -> bool:
        """An extension alone identifies nothing; a name or zone does."""
        return bool(self.name_regex or self.name_contains or self.name_equals
                    or self.zone_ids)

    @property
    def depends_on_location(self) -> bool:
        return bool(self.path_prefix or self.path_not_prefix or self.path_contains
                    or self.path_not_contains or self.path_regex or self.path_not_regex)

    def match(self, subject: Subject) -> Optional[Match]:
        if not self.enabled:
            return None

        if not subject.path_known:
            if self.requires_path or not self.has_non_path_condition:
                return None
            if self.depends_on_location and not self.identifies_by_name:
                return None
        if self.files_only and subject.is_directory:
            return None
        if self.deleted_only and not subject.is_deleted:
            return None
        if self.min_size is not None and subject.size < self.min_size:
            return None
        if self.max_size is not None and subject.size > self.max_size:
            return None
        if self.extensions and subject.extension.lower() not in self.extensions:
            return None
        if self.name_equals and subject.name_lower not in self.name_equals:
            return None
        if self.name_contains and not any(s in subject.name_lower for s in self.name_contains):
            return None
        if self.zone_ids and str(subject.zone_id) not in self.zone_ids:
            return None

        # Path conditions apply only when the path was actually reconstructed.
        if subject.path_known:
            if self.path_contains and not any(
                s in subject.path_lower for s in self.path_contains
            ):
                return None
            if self._path_prefix_norm and not under_any_normalized(
                    subject.path_lower, self._path_prefix_norm):
                return None
            if self._path_not_prefix_norm and under_any_normalized(
                    subject.path_lower, self._path_not_prefix_norm):
                return None
            if any(s in subject.path_lower for s in self.path_not_contains):
                return None
            if self._path_not_re and self._path_not_re.search(subject.path_lower):
                return None
            if self.noise_filter and is_noise_normalized(
                    subject.path_lower, self._extra_noise_norm):
                return None

        extracted: Dict[str, str] = {}
        evidence = subject.name

        if self._name_re is not None:
            m = self._name_re.search(subject.name)
            if not m:
                return None
            extracted.update({k: v for k, v in (m.groupdict() or {}).items() if v})
            evidence = m.group(0) or subject.name

        if self._path_re is not None:
            if not subject.path_known:
                return None
            m = self._path_re.search(subject.path_lower)
            if not m:
                return None
            extracted.update({k: v for k, v in (m.groupdict() or {}).items() if v})

        # A rule with no positive condition would match everything; refuse it.
        if not any([self._name_re, self._path_re, self.name_contains, self.path_contains,
                    self.extensions, self.name_equals, self.path_prefix, self.zone_ids]):
            return None

        return Match(
            rule_name=self.name,
            title=self.title,
            severity=self.severity,
            category=self.category,
            mitre=list(self.mitre),
            extracted=extracted,
            evidence=evidence,
        )


class RuleSet:
    """A rule pack with an extension index over it."""

    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules: List[Rule] = rules or []
        self._index: Optional[Dict[str, List[Rule]]] = None
        self._agnostic: List[Rule] = []

    def __len__(self) -> int:
        return len(self.rules)

    def add(self, rule: Rule) -> None:
        self.rules.append(rule.compile())
        self._index = None

    def _build_index(self) -> None:
        index: Dict[str, List[Rule]] = {}
        agnostic: List[Rule] = []
        for rule in self.rules:
            if rule.extensions:
                for extension in rule.extensions:
                    index.setdefault(extension, []).append(rule)
            else:
                agnostic.append(rule)
        self._index, self._agnostic = index, agnostic

    def candidates(self, subject: Subject) -> List[Rule]:
        if self._index is None:
            self._build_index()
        specific = self._index.get(subject.extension.lower())
        return self._agnostic + specific if specific else self._agnostic

    def match(self, subject: Subject) -> List[Match]:
        out = []
        for rule in self.candidates(subject):
            m = rule.match(subject)
            if m:
                out.append(m)
        return sorted(out, key=lambda m: -SEVERITY_ORDER.get(m.severity, 0))

    def filter_categories(self, categories: List[str]) -> "RuleSet":
        wanted = {c.lower() for c in categories}
        return RuleSet([r for r in self.rules if r.category.lower() in wanted])

    def min_severity(self, severity: str) -> "RuleSet":
        floor = SEVERITY_ORDER.get(severity.lower(), 0)
        return RuleSet([r for r in self.rules
                        if SEVERITY_ORDER.get(r.severity, 0) >= floor])

    # loading

    @classmethod
    def from_dicts(cls, items: List[dict]) -> "RuleSet":
        rs = cls()
        valid = {f for f in Rule.__dataclass_fields__ if not f.startswith("_")}
        for item in items:
            unknown = set(item) - valid
            if unknown:
                raise ValueError(
                    f"rule '{item.get('name', '?')}' has unknown field(s): "
                    f"{', '.join(sorted(unknown))}"
                )
            if "name" not in item:
                raise ValueError("every rule needs a 'name'")
            rs.add(Rule(**item))
        return rs

    @classmethod
    def load(cls, path: Path, noise_filter: bool = True) -> "RuleSet":
        """Load a JSON or YAML pack. noise_filter is the default for rules that do not set it."""
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml # optional
            except ImportError as exc:
                raise RuntimeError(
                    "YAML rule files need PyYAML installed (pip install pyyaml), or convert the file to JSON."
                ) from exc
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)

        if isinstance(data, dict):
            data = data.get("rules", [])
        if not noise_filter:
            data = [dict(item, noise_filter=item.get("noise_filter", False))
                    if isinstance(item, dict) else item for item in data]
        return cls.from_dicts(data)

    @classmethod
    def load_custom(cls, path: Path) -> "RuleSet":
        """
        Load an analyst supplied pack or IOC list. The indicators come from
        the case, so the shared noise list does not apply unless a rule asks
        for it.
        """
        if path.suffix.lower() == ".txt":
            return cls.from_ioc_list(path)
        return cls.load(path, noise_filter=False)

    @classmethod
    def builtin(cls) -> "RuleSet":
        return cls.load(Path(__file__).parent / "rules" / "default.json")

    @classmethod
    def from_ioc_list(cls, path: Path, severity: str = "high") -> "RuleSet":
        """Build rules from a plain list of indicators, one per line."""
        rs = cls()

        for lineno, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            base = dict(
                name=f"ioc_{path.stem}_{lineno}",
                title=f"IOC list hit: {line}",
                severity=severity,
                category="ioc_list",
                noise_filter=False,
            )
            if line.startswith("/") and line.endswith("/") and len(line) > 2:
                pattern = line[1:-1]
                base["name_regex"] = pattern if _INLINE_FLAGS.match(pattern) else "(?i)" + pattern
            elif "\\" in line or "/" in line:
                base["path_contains"] = [line.replace("/", "\\")]
            else:
                base["name_equals"] = [line]
            try:
                rs.add(Rule(**base))
            except re.error as exc:
                raise ValueError(f"{path.name} line {lineno}: invalid regex: {exc}") from exc
        return rs

    def extend(self, other: "RuleSet") -> "RuleSet":
        return RuleSet(self.rules + other.rules)
