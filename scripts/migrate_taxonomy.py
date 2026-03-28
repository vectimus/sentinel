"""One-time D1 migration: fix OWASP taxonomy (LLM → ASI) and remove duplicates.

Usage:
    python scripts/migrate_taxonomy.py --dry-run    # preview changes
    python scripts/migrate_taxonomy.py              # apply changes

Requires env vars: CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN, D1_DATABASE_ID
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys

# Add parent to path so we can import pipeline modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.tools.d1_client import D1Client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Mapping from old LLM categories to new ASI categories
LLM_TO_ASI = {
    "LLM01": "ASI01: Goal Hijacking",
    "LLM02": "ASI05: Unsafe Code Execution",
    "LLM03": "ASI03: Identity and Privilege Abuse",
    "LLM04": "ASI08: Cascading Failures",
    "LLM05": "ASI03: Identity and Privilege Abuse",
    "LLM06": "ASI08: Cascading Failures",
    "LLM07": "ASI01: Goal Hijacking",
    "LLM08": "ASI09: Trust Boundary Violations",
    "LLM09": "ASI02: Tool Misuse",
    "LLM10": "ASI04: Supply Chain Vulnerabilities",
}


def map_owasp_category(old_category: str | None) -> str | None:
    """Map an LLM-prefixed OWASP category to ASI prefix."""
    if not old_category:
        return old_category

    # Extract prefix (e.g., "LLM09" from "LLM09: Insecure Tool Use")
    match = re.match(r"(LLM\d{2})", old_category)
    if not match:
        return old_category  # Already ASI or uncategorised

    prefix = match.group(1)
    return LLM_TO_ASI.get(prefix, old_category)


def run_migration(dry_run: bool = True) -> None:
    d1 = D1Client(
        os.environ["CLOUDFLARE_ACCOUNT_ID"],
        os.environ["CLOUDFLARE_API_TOKEN"],
        os.environ["D1_DATABASE_ID"],
    )

    try:
        # Fetch all incidents
        incidents = d1.execute("SELECT * FROM incidents ORDER BY vtms_id")
        logger.info("Found %d incidents in D1", len(incidents))

        # Phase 1: Fix taxonomy
        taxonomy_updates = 0
        for inc in incidents:
            old_cat = inc.get("owasp_category")
            new_cat = map_owasp_category(old_cat)
            if new_cat != old_cat:
                logger.info("  %s: %s → %s", inc["vtms_id"], old_cat, new_cat)
                if not dry_run:
                    d1.execute(
                        "UPDATE incidents SET owasp_category = ? WHERE vtms_id = ?",
                        [new_cat, inc["vtms_id"]],
                    )
                taxonomy_updates += 1

        logger.info("Taxonomy updates: %d", taxonomy_updates)

        # Phase 2: Find duplicates
        # Re-fetch with updated categories if not dry run
        if not dry_run and taxonomy_updates > 0:
            incidents = d1.execute("SELECT * FROM incidents ORDER BY vtms_id")

        # Use dedup logic to find duplicate pairs
        # We compare each incident against all others
        all_dupes: list[tuple[str, str, str]] = []  # (keep_id, remove_id, reason)
        seen = set()

        for i, inc_a in enumerate(incidents):
            if inc_a["vtms_id"] in seen:
                continue
            for inc_b in incidents[i + 1 :]:
                if inc_b["vtms_id"] in seen:
                    continue

                # Check title similarity
                from pipeline.dedup import (
                    _check_cve_overlap,
                    _check_title_similarity,
                    _parse_json_field,
                )

                similarity = _check_title_similarity(inc_a.get("title", ""), inc_b.get("title", ""))

                cve_overlap = _check_cve_overlap(
                    _parse_json_field(inc_a.get("cve_ids")),
                    _parse_json_field(inc_b.get("cve_ids")),
                )

                if similarity > 0.7 or cve_overlap:
                    # Keep the one with more data (longer summary, more fields filled)
                    a_score = len(inc_a.get("summary") or "") + len(
                        inc_a.get("coverage_detail") or ""
                    )
                    b_score = len(inc_b.get("summary") or "") + len(
                        inc_b.get("coverage_detail") or ""
                    )

                    if a_score >= b_score:
                        keep, remove = inc_a["vtms_id"], inc_b["vtms_id"]
                    else:
                        keep, remove = inc_b["vtms_id"], inc_a["vtms_id"]

                    reason = f"title_sim={similarity:.2f}" if similarity > 0.7 else "cve_overlap"
                    all_dupes.append((keep, remove, reason))
                    seen.add(remove)
                    logger.info("  Duplicate: keep %s, remove %s (%s)", keep, remove, reason)

        logger.info("Duplicates found: %d", len(all_dupes))

        if not dry_run and all_dupes:
            for keep, remove, reason in all_dupes:
                d1.execute("DELETE FROM incidents WHERE vtms_id = ?", [remove])
                logger.info("  Deleted %s (kept %s)", remove, keep)

        # Summary
        print("\n--- Migration Summary ---")
        print(f"Taxonomy updates: {taxonomy_updates}")
        print(f"Duplicates removed: {len(all_dupes)}")
        if dry_run:
            print("\n(DRY RUN — no changes applied)")
        else:
            print("\nChanges applied successfully.")

    finally:
        d1.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate D1 taxonomy and remove duplicates")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    args = parser.parse_args()
    run_migration(dry_run=args.dry_run)
