"""RedPulse - Delta Scan Tracking Engine.

Compares current scan results against previous engagement baseline.
Classifies assets/findings as NEW, RESOLVED, PERSISTENT and generates alert logs.
Controlled, deterministic, no destructive scans.
"""

from typing import List, Dict, Any, Tuple, Set
import datetime
import logging

logger = logging.getLogger(__name__)

# Delta status constants
NEW = "NEW"
RESOLVED = "RESOLVED"
PERSISTENT = "PERSISTENT"


def _key_for_finding(f: Dict[str, Any]) -> str:
    """Stable key for finding dedup: fingerprint or host|template_id|location."""
    if f.get("fingerprint"):
        return f"fp:{f['fingerprint']}"
    return f"{f.get('host','')}|{f.get('template_id','')}|{f.get('location','')}"


def _key_for_asset(a: Dict[str, Any]) -> str:
    """Stable key for asset: hostname or ip."""
    return a.get("hostname") or a.get("host") or a.get("ip") or str(a)


def calculate_delta(
    previous_findings: List[Dict[str, Any]],
    current_findings: List[Dict[str, Any]],
    previous_assets: List[Dict[str, Any]] = None,
    current_assets: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compare previous vs current and classify.

    Returns:
        {
          "findings": {"new": [...], "resolved": [...], "persistent": [...]},
          "assets": {"new": [...], "resolved": [...], "persistent": [...]},
          "metrics": {"new": N, "resolved": M, "persistent": P, "total_current": T},
          "delta_log": [alert, ...]
        }
    """
    prev_findings = previous_findings or []
    curr_findings = current_findings or []
    prev_assets = previous_assets or []
    curr_assets = current_assets or []

    # Findings delta via fingerprint
    prev_keys: Set[str] = {_key_for_finding(f) for f in prev_findings}
    curr_keys: Set[str] = {_key_for_finding(f) for f in curr_findings}
    prev_map = {_key_for_finding(f): f for f in prev_findings}
    curr_map = {_key_for_finding(f): f for f in curr_findings}

    new_findings = [curr_map[k] for k in curr_keys - prev_keys]
    resolved_findings = [prev_map[k] for k in prev_keys - curr_keys]
    persistent_findings = [curr_map[k] for k in curr_keys & prev_keys]

    # Assets delta
    prev_a_keys = {_key_for_asset(a) for a in prev_assets}
    curr_a_keys = {_key_for_asset(a) for a in curr_assets}
    prev_a_map = {_key_for_asset(a): a for a in prev_assets}
    curr_a_map = {_key_for_asset(a): a for a in curr_assets}
    new_assets = [curr_a_map[k] for k in curr_a_keys - prev_a_keys]
    resolved_assets = [prev_a_map[k] for k in prev_a_keys - curr_a_keys]
    persistent_assets = [curr_a_map[k] for k in curr_a_keys & prev_a_keys]

    metrics = {
        "findings": {"new": len(new_findings), "resolved": len(resolved_findings), "persistent": len(persistent_findings), "total_current": len(curr_findings)},
        "assets": {"new": len(new_assets), "resolved": len(resolved_assets), "persistent": len(persistent_assets), "total_current": len(curr_assets)},
        "new": len(new_findings) + len(new_assets),
        "resolved": len(resolved_findings) + len(resolved_assets),
        "persistent": len(persistent_findings) + len(persistent_assets),
    }

    delta_log = generate_delta_alerts(new_findings, resolved_findings, new_assets, resolved_assets)

    return {
        "findings": {"new": new_findings, "resolved": resolved_findings, "persistent": persistent_findings},
        "assets": {"new": new_assets, "resolved": resolved_assets, "persistent": persistent_assets},
        "metrics": metrics,
        "delta_log": delta_log,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
    }


def generate_delta_alerts(
    new_findings: List[Dict[str, Any]],
    resolved_findings: List[Dict[str, Any]],
    new_assets: List[Dict[str, Any]] = None,
    resolved_assets: List[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Generate automated alert logs for delta."""
    alerts = []
    now = datetime.datetime.utcnow().isoformat() + "Z"
    for f in new_findings or []:
        alerts.append({
            "type": "NEW_FINDING",
            "severity": f.get("severity", "UNKNOWN"),
            "message": f"New finding {f.get('template_id','unknown')} on {f.get('host','unknown')}",
            "fingerprint": f.get("fingerprint"),
            "timestamp": now,
        })
        logger.info(f"Delta NEW finding: {f.get('template_id')} on {f.get('host')}")
    for f in resolved_findings or []:
        alerts.append({
            "type": "RESOLVED_FINDING",
            "severity": f.get("severity", "UNKNOWN"),
            "message": f"Resolved finding {f.get('template_id','unknown')} on {f.get('host','unknown')}",
            "fingerprint": f.get("fingerprint"),
            "timestamp": now,
        })
        logger.info(f"Delta RESOLVED finding: {f.get('template_id')} on {f.get('host')}")
    for a in new_assets or []:
        alerts.append({"type": "NEW_ASSET", "message": f"New asset { _key_for_asset(a)}", "timestamp": now})
    for a in resolved_assets or []:
        alerts.append({"type": "RESOLVED_ASSET", "message": f"Resolved asset {_key_for_asset(a)}", "timestamp": now})
    return alerts


def summarize_delta(delta: Dict[str, Any]) -> str:
    """Human summary for reports."""
    m = delta.get("metrics", {})
    f = m.get("findings", {})
    a = m.get("assets", {})
    return (f"Delta: {f.get('new',0)} new / {f.get('resolved',0)} resolved / {f.get('persistent',0)} persistent findings; "
            f"{a.get('new',0)} new / {a.get('resolved',0)} resolved assets. Total current: {f.get('total_current',0)} findings.")
