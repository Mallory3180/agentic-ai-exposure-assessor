"""Risk scoring.

risk_score = likelihood * impact * confidence  (each 1..5, so range 1..125)

Severity is derived from the risk score with fixed thresholds so that severity stays
consistent across the whole tool. Aggregate helpers compute per-agent and per-run totals.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Lower-bound thresholds (inclusive) on risk_score for each severity.
_SEVERITY_THRESHOLDS: list[tuple[int, str]] = [
    (75, "critical"),
    (45, "high"),
    (20, "medium"),
    (8, "low"),
    (0, "info"),
]


def clamp(value: int, low: int = 1, high: int = 5) -> int:
    """Clamp an integer into the inclusive [low, high] range."""
    return max(low, min(high, value))


def risk_score(likelihood: int, impact: int, confidence: int) -> int:
    """Compute a finding's risk score from its 1..5 component values."""
    return clamp(likelihood) * clamp(impact) * clamp(confidence)


def severity_for(score: int) -> str:
    """Map a numeric risk score to a severity label."""
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


def severity_rank(severity: str) -> int:
    """Return a sortable rank for a severity label (higher = worse)."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def aggregate_agent_scores(findings: Iterable[object]) -> dict[str, int]:
    """Sum risk scores per affected agent. ``findings`` must expose
    ``affected_agent`` and ``risk_score`` attributes."""
    scores: dict[str, int] = defaultdict(int)
    for finding in findings:
        agent = getattr(finding, "affected_agent", "") or "(unattributed)"
        scores[agent] += int(getattr(finding, "risk_score", 0))
    return dict(scores)


def aggregate_run_score(findings: Iterable[object]) -> int:
    """Total risk score for an assessment run."""
    return sum(int(getattr(f, "risk_score", 0)) for f in findings)


def severity_counts(findings: Iterable[object]) -> dict[str, int]:
    """Count findings by severity label, in canonical order."""
    counts = {label: 0 for label in SEVERITY_ORDER}
    for finding in findings:
        sev = getattr(finding, "severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
