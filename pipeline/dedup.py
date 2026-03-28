"""Deterministic deduplication for Threat Hunter findings.

Runs after agent output, before D1 writes. Three match strategies:
- CVE overlap: finding's cve_ids intersects existing cve_ids
- Title similarity: difflib.SequenceMatcher > 0.7 on normalized titles
- Tool+date proximity: same tools_involved AND incident_date within 7 days
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from difflib import SequenceMatcher
from typing import Any

logger = logging.getLogger(__name__)

TITLE_SIMILARITY_THRESHOLD = 0.7
DATE_PROXIMITY_DAYS = 7


def _normalize_title(title: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    title = title.lower()
    title = re.sub(r"[^\w\s]", "", title)
    title = re.sub(r"\s+", " ", title).strip()
    return title


def _parse_json_field(value: Any) -> list[str]:
    """Parse a JSON-encoded list field from D1 (stored as string)."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _parse_date(date_str: str | None) -> datetime | None:
    """Parse a date string (YYYY-MM-DD or ISO 8601) into a datetime."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.split("T")[0])
    except (ValueError, AttributeError):
        return None


def _check_cve_overlap(finding_cves: list[str], existing_cves: list[str]) -> bool:
    """Return True if any CVE IDs overlap (case-insensitive)."""
    if not finding_cves or not existing_cves:
        return False
    normalized_finding = {cve.upper().strip() for cve in finding_cves}
    normalized_existing = {cve.upper().strip() for cve in existing_cves}
    return bool(normalized_finding & normalized_existing)


def _check_title_similarity(title_a: str, title_b: str) -> float:
    """Return SequenceMatcher ratio between normalized titles."""
    norm_a = _normalize_title(title_a)
    norm_b = _normalize_title(title_b)
    return SequenceMatcher(None, norm_a, norm_b).ratio()


def _check_tool_date_proximity(
    finding_tools: list[str],
    finding_date: str | None,
    existing_tools: list[str],
    existing_date: str | None,
) -> bool:
    """Return True if same tools AND dates within DATE_PROXIMITY_DAYS."""
    if not finding_tools or not existing_tools:
        return False
    # Normalize tool names for comparison
    f_tools = {t.lower().strip() for t in finding_tools}
    e_tools = {t.lower().strip() for t in existing_tools}
    if not f_tools & e_tools:
        return False

    f_date = _parse_date(finding_date)
    e_date = _parse_date(existing_date)
    if f_date is None or e_date is None:
        return False

    return abs((f_date - e_date).days) <= DATE_PROXIMITY_DAYS


def deduplicate(
    findings: list[dict], existing_incidents: list[dict]
) -> tuple[list[dict], list[tuple[dict, str]]]:
    """Deduplicate findings against existing incidents.

    Returns:
        (unique_findings, duplicates) where duplicates is a list of
        (finding, match_reason) tuples.
    """
    unique: list[dict] = []
    duplicates: list[tuple[dict, str]] = []

    for finding in findings:
        finding_cves = finding.get("cve_ids", [])
        finding_title = finding.get("title", "")
        finding_tools = finding.get("tools_involved", [])
        finding_date = finding.get("incident_date")
        match_found = False

        for existing in existing_incidents:
            existing_cves = _parse_json_field(existing.get("cve_ids"))
            existing_title = existing.get("title", "")
            existing_tools = _parse_json_field(existing.get("tools_involved"))
            existing_date = existing.get("incident_date")
            existing_id = existing.get("vtms_id", "unknown")

            # Strategy 1: CVE overlap
            if _check_cve_overlap(finding_cves, existing_cves):
                reason = f"CVE overlap with {existing_id}: {set(finding_cves) & set(existing_cves)}"
                duplicates.append((finding, reason))
                match_found = True
                logger.info("Dedup: %s — %s", finding.get("vtms_id", "?"), reason)
                break

            # Strategy 2: Title similarity
            similarity = _check_title_similarity(finding_title, existing_title)
            if similarity > TITLE_SIMILARITY_THRESHOLD:
                reason = f"Title similarity {similarity:.2f} with {existing_id}: {existing_title!r}"
                duplicates.append((finding, reason))
                match_found = True
                logger.info("Dedup: %s — %s", finding.get("vtms_id", "?"), reason)
                break

            # Strategy 3: Tool+date proximity
            if _check_tool_date_proximity(
                finding_tools, finding_date, existing_tools, existing_date
            ):
                reason = (
                    f"Tool+date proximity with {existing_id}: "
                    f"tools={existing_tools}, date={existing_date}"
                )
                duplicates.append((finding, reason))
                match_found = True
                logger.info("Dedup: %s — %s", finding.get("vtms_id", "?"), reason)
                break

        if not match_found:
            unique.append(finding)

    logger.info(
        "Deduplication: %d unique, %d duplicates from %d findings",
        len(unique),
        len(duplicates),
        len(findings),
    )
    return unique, duplicates
