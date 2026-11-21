"""
Risk Scorer.

Calculates security risk scores based on scan findings.
"""

from typing import Any, Dict, List


# Severity weight mapping
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}

# Risk level thresholds
RISK_LEVELS = [
    (0, 10, "Minimal", "🟢"),
    (10, 30, "Low", "🟡"),
    (30, 55, "Medium", "🟠"),
    (55, 80, "High", "🔴"),
    (80, 101, "Critical", "⛔"),
]


def calculate_risk_score(findings: List[Dict[str, Any]]) -> float:
    """
    Calculate a risk score (0-100) from a list of findings.
    
    Each finding must have a 'severity' key.
    """
    if not findings:
        return 0.0

    score = 0
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        score += SEVERITY_WEIGHTS.get(severity, 0)

    return min(100.0, float(score))


def get_risk_level(score: float) -> Dict[str, str]:
    """Get the risk level label and icon for a given score."""
    for low, high, label, icon in RISK_LEVELS:
        if low <= score < high:
            return {"score": score, "level": label, "icon": icon}
    return {"score": score, "level": "Unknown", "icon": "❓"}


def aggregate_findings(
    all_findings: List[List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """
    Aggregate findings from multiple scans into a summary.
    
    Args:
        all_findings: List of finding lists from different scans.
    
    Returns:
        Aggregated summary with counts, score, and all findings.
    """
    combined = []
    for findings in all_findings:
        combined.extend(findings)

    counts = {}
    for f in combined:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    score = calculate_risk_score(combined)
    risk_level = get_risk_level(score)

    return {
        "total_findings": len(combined),
        "by_severity": counts,
        "risk_score": score,
        "risk_level": risk_level["level"],
        "risk_icon": risk_level["icon"],
        "findings": combined,
    }


def generate_recommendations(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Generate prioritized security recommendations from findings.
    
    Returns recommendations sorted by severity (critical first).
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    recommendations = []
    seen = set()

    for finding in sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "info"), 5),
    ):
        rec = finding.get("recommendation")
        if rec and rec not in seen:
            seen.add(rec)
            recommendations.append({
                "priority": finding.get("severity", "info"),
                "category": finding.get("category", "General"),
                "recommendation": rec,
                "related_finding": finding.get("title", ""),
            })

    return recommendations
