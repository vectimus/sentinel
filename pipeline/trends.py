"""Trends computation — aggregate incident stats into the trends table."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)


def compute_and_store_trends(d1_client, date: str | None = None) -> dict:
    """Compute aggregate stats from incidents and store in trends table.

    Args:
        d1_client: D1Client instance
        date: Date string (YYYY-MM-DD). Defaults to today UTC.

    Returns:
        The trend record that was stored.
    """
    if date is None:
        date = datetime.now(UTC).strftime("%Y-%m-%d")

    # Total incidents
    total_result = d1_client.execute("SELECT COUNT(*) as cnt FROM incidents")
    total_incidents = total_result[0]["cnt"] if total_result else 0

    # Incidents in last 30 days
    thirty_days_ago = (datetime.strptime(date, "%Y-%m-%d") - timedelta(days=30)).strftime(
        "%Y-%m-%d"
    )
    recent_result = d1_client.execute(
        "SELECT COUNT(*) as cnt FROM incidents WHERE discovered_at >= ?",
        [thirty_days_ago],
    )
    incidents_30d = recent_result[0]["cnt"] if recent_result else 0

    # Incidents by category
    category_result = d1_client.execute(
        "SELECT owasp_category, COUNT(*) as cnt FROM incidents "
        "GROUP BY owasp_category ORDER BY cnt DESC"
    )
    incidents_by_category = {row["owasp_category"]: row["cnt"] for row in category_result}

    # Incidents by severity
    severity_result = d1_client.execute(
        "SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity ORDER BY severity DESC"
    )
    incidents_by_severity = {str(row["severity"]): row["cnt"] for row in severity_result}

    # Coverage rate
    coverage_result = d1_client.execute(
        "SELECT coverage_status, COUNT(*) as cnt FROM incidents GROUP BY coverage_status"
    )
    coverage_counts = {row["coverage_status"]: row["cnt"] for row in coverage_result}
    covered = coverage_counts.get("covered", 0)
    partial = coverage_counts.get("partial", 0)
    total_with_status = sum(coverage_counts.values()) or 1
    coverage_rate = (covered + partial * 0.5) / total_with_status
    gap_rate = coverage_counts.get("policy_pending", 0) / total_with_status

    # Policy counts (from policy_meta if available, otherwise 0)
    try:
        policies_meta = d1_client.execute(
            "SELECT value FROM policy_meta WHERE key = 'total_policies'"
        )
        policies_total = int(policies_meta[0]["value"]) if policies_meta else 0
    except Exception:
        policies_total = 0

    try:
        rules_meta = d1_client.execute("SELECT value FROM policy_meta WHERE key = 'total_rules'")
        rules_total = int(rules_meta[0]["value"]) if rules_meta else 0
    except Exception:
        rules_total = 0

    trend = {
        "date": date,
        "total_incidents": total_incidents,
        "incidents_30d": incidents_30d,
        "incidents_by_category": json.dumps(incidents_by_category),
        "incidents_by_severity": json.dumps(incidents_by_severity),
        "coverage_rate": round(coverage_rate, 4),
        "gap_rate": round(gap_rate, 4),
        "policies_total": policies_total,
        "rules_total": rules_total,
    }

    d1_client.upsert_trend(trend)
    logger.info(
        "Stored trend for %s: %d incidents, %.1f%% coverage",
        date,
        total_incidents,
        coverage_rate * 100,
    )

    return trend
