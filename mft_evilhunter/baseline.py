"""
Per-volume install baseline.
"""

from __future__ import annotations

import datetime
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

EPOCH_MIN_SHARE = 0.02
EPOCH_MIN_RECORDS = 500
MAX_EPOCHS = 8


@dataclass
class Baseline:
    """Install epochs and activity window derived from a parsed $MFT."""
    epochs: Dict[datetime.date, int] = field(default_factory=dict)
    total: int = 0
    volume_created: Optional[datetime.datetime] = None
    earliest_activity: Optional[datetime.datetime] = None
    latest_activity: Optional[datetime.datetime] = None

    @property
    def available(self) -> bool:
        return bool(self.epochs)

    @property
    def install_date(self) -> Optional[datetime.date]:
        """The earliest epoch: the original image the volume was laid down from."""
        return min(self.epochs) if self.epochs else None

    def is_epoch(self, when: Optional[datetime.datetime]) -> bool:
        return bool(when) and when.date() in self.epochs

    def share(self, when: Optional[datetime.datetime]) -> float:
        if not when or not self.total:
            return 0.0
        return self.epochs.get(when.date(), 0) / self.total

    def describe(self) -> str:
        if not self.epochs:
            return "no install baseline could be derived"
        parts = [
            f"{date} ({count / self.total * 100:.1f}%)"
            for date, count in sorted(self.epochs.items())
        ]
        return "install epochs: " + ", ".join(parts)


def derive_baseline(entries) -> Baseline:
    """Find the creation-time spikes that mean installation rather than use."""
    baseline = Baseline()
    if not entries:
        return baseline

    values = entries.values() if hasattr(entries, "values") else entries

    si_dates: Counter = Counter()
    fn_times: List[datetime.datetime] = []
    total = 0

    for entry in values:
        created = entry.si.timestamps.created
        if created:
            si_dates[created.date()] += 1
            total += 1
        best = getattr(entry, "best_fn", None)
        if best is not None and best.timestamps.created:
            fn_times.append(best.timestamps.created)

    baseline.total = total
    if not total:
        return baseline

    floor = max(EPOCH_MIN_RECORDS, total * EPOCH_MIN_SHARE)
    baseline.epochs = {
        date: count
        for date, count in si_dates.most_common(MAX_EPOCHS)
        if count >= floor
    }

    root = entries.get(5) if hasattr(entries, "get") else None
    if root is not None:
        baseline.volume_created = root.si.timestamps.created

    if fn_times:
        fn_times.sort()
        # Trim the extremes so a few odd records cannot define the window.
        edge = min(len(fn_times) // 1000, len(fn_times) - 1)
        baseline.earliest_activity = fn_times[edge]
        baseline.latest_activity = fn_times[-1 - edge]

    return baseline
