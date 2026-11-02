"""
Scan diff engine.

Compares two stored scans of the same target and classifies every finding as
new, resolved, or persisting. Findings are matched by check ID when one is
present (the live SSH assessor always sets one) and fall back to a normalized
title for older or imported records that only carry a title.
"""

from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}


def normalize_severity(value: Any) -> str:
    """Map stored severity strings ("CRITICAL", "critical", "Critical") to one form."""
    text = str(value or "").strip().capitalize()
    return text if text in _SEVERITY_RANK else "Info"


def _findings_of(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Stored scans use "vulnerabilities"; live results use "findings"."""
    findings = scan.get("vulnerabilities")
    if findings is None:
        findings = scan.get("findings", [])
    return [f for f in findings if isinstance(f, dict)]


def finding_key(finding: Dict[str, Any]) -> Tuple[str, str]:
    """Stable identity for a finding across scans."""
    check_id = str(finding.get("id") or "").strip()
    if check_id:
        return ("id", check_id)
    title = " ".join(str(finding.get("title") or "").lower().split())
    return ("title", title)


def _index(findings: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    indexed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for finding in findings:
        key = finding_key(finding)
        # Keep the most severe instance if a check reports more than once.
        current = indexed.get(key)
        if current is None or _rank(finding) < _rank(current):
            indexed[key] = finding
    return indexed


def _rank(finding: Dict[str, Any]) -> int:
    return _SEVERITY_RANK[normalize_severity(finding.get("severity"))]


def _summarize(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(finding.get("id") or ""),
        "title": str(finding.get("title") or ""),
        "severity": normalize_severity(finding.get("severity")),
        "category": str(finding.get("category") or ""),
        "remediation": str(finding.get("remediation") or ""),
    }


def _by_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: (_SEVERITY_RANK[f["severity"]], f["title"]))


def _counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def diff_scans(
    base: Dict[str, Any],
    head: Dict[str, Any],
    base_id: Optional[int] = None,
    head_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Compare a baseline scan with a later scan.

    Returns new, resolved, and persisting findings plus the risk score delta.
    Persisting findings whose severity changed are reported with both values.
    """
    base_index = _index(_findings_of(base))
    head_index = _index(_findings_of(head))

    new = [_summarize(head_index[k]) for k in head_index if k not in base_index]
    resolved = [_summarize(base_index[k]) for k in base_index if k not in head_index]

    persisting = []
    for key in head_index:
        if key not in base_index:
            continue
        entry = _summarize(head_index[key])
        before = normalize_severity(base_index[key].get("severity"))
        entry["previous_severity"] = before
        entry["severity_changed"] = before != entry["severity"]
        persisting.append(entry)

    base_score = float(base.get("risk_score") or 0.0)
    head_score = float(head.get("risk_score") or 0.0)

    return {
        "base": {
            "id": base_id,
            "target": base.get("target", ""),
            "scan_timestamp": base.get("scan_timestamp", ""),
            "risk_score": round(base_score, 2),
            "finding_count": len(base_index),
        },
        "head": {
            "id": head_id,
            "target": head.get("target", ""),
            "scan_timestamp": head.get("scan_timestamp", ""),
            "risk_score": round(head_score, 2),
            "finding_count": len(head_index),
        },
        "risk_delta": round(head_score - base_score, 2),
        "new": _by_severity(new),
        "resolved": _by_severity(resolved),
        "persisting": _by_severity(persisting),
        "summary": {
            "new": len(new),
            "resolved": len(resolved),
            "persisting": len(persisting),
            "severity_changed": sum(1 for f in persisting if f["severity_changed"]),
            "new_by_severity": _counts(new),
            "resolved_by_severity": _counts(resolved),
        },
    }
