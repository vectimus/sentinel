"""Coverage re-evaluation on policy merge.

When new policies are merged in the policies repo, this module re-tests
incidents that have stored replay requests against the updated policy set.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def reevaluate_coverage(d1_client, policies_dir: str) -> dict:
    """Re-evaluate coverage for incidents with replay_request data.

    Args:
        d1_client: D1Client instance
        policies_dir: Path to checked-out policies repo

    Returns:
        Summary dict with counts of updated incidents.
    """
    try:
        import cedarpy
    except ImportError:
        logger.error("cedarpy not installed — cannot re-evaluate coverage")
        return {"error": "cedarpy not installed", "updated": 0, "skipped": 0}

    # Load current policy set
    policies_path = Path(policies_dir)
    policy_sources = []
    for cedar_file in sorted(policies_path.rglob("*.cedar")):
        policy_sources.append(cedar_file.read_text())

    if not policy_sources:
        logger.warning("No Cedar policy files found in %s", policies_dir)
        return {"error": "no policies found", "updated": 0, "skipped": 0}

    policy_set = "\n".join(policy_sources)
    logger.info("Loaded %d policy files from %s", len(policy_sources), policies_dir)

    # Fetch incidents that could be re-evaluated
    incidents = d1_client.execute(
        "SELECT vtms_id, coverage_status, enforcement_scope, replay_request "
        "FROM incidents "
        "WHERE coverage_status IN ('policy_pending', 'partial') "
        "AND replay_request IS NOT NULL"
    )

    updated = 0
    skipped = 0
    now = datetime.now(timezone.utc).isoformat()

    for incident in incidents:
        vtms_id = incident["vtms_id"]

        # Skip out-of-scope incidents
        if incident.get("enforcement_scope") == "out_of_scope":
            logger.info("Skipping %s — out_of_scope", vtms_id)
            skipped += 1
            continue

        try:
            replay = json.loads(incident["replay_request"])
        except (json.JSONDecodeError, TypeError):
            logger.warning("Invalid replay_request for %s — skipping", vtms_id)
            skipped += 1
            continue

        # Validate replay request structure
        if not isinstance(replay, dict):
            logger.warning("replay_request for %s is not a dict — skipping", vtms_id)
            skipped += 1
            continue
        if "principal" not in replay or "action" not in replay or "resource" not in replay:
            logger.warning("replay_request for %s missing required fields — skipping", vtms_id)
            skipped += 1
            continue

        try:
            # Run Cedar authorization with the updated policy set
            decision = cedarpy.is_authorized(
                request=replay,
                policies=policy_set,
                entities=replay.get("entities", []),
            )

            # If the new policies now DENY what was previously pending,
            # the incident is now covered
            if decision.decision == "Deny":
                old_status = incident["coverage_status"]
                d1_client.execute(
                    "UPDATE incidents SET coverage_status = 'covered', "
                    "coverage_detail = ?, updated_at = ? "
                    "WHERE vtms_id = ?",
                    [
                        f"Re-evaluated: policies now deny this request (was {old_status})",
                        now,
                        vtms_id,
                    ],
                )
                updated += 1
                logger.info(
                    "Updated %s: %s → covered (policies now deny)", vtms_id, old_status
                )
            else:
                logger.info("No change for %s — still allowed by policies", vtms_id)

        except Exception as e:
            logger.warning("Cedar evaluation failed for %s: %s", vtms_id, e)
            skipped += 1

    summary = {"updated": updated, "skipped": skipped, "total_checked": len(incidents)}
    logger.info("Coverage re-evaluation complete: %s", summary)
    return summary


if __name__ == "__main__":
    import argparse
    import os
    from pipeline.tools.d1_client import D1Client

    parser = argparse.ArgumentParser(description="Re-evaluate incident coverage")
    parser.add_argument("--policies-dir", required=True, help="Path to policies repo")
    parser.add_argument("--dry-run", action="store_true", help="Log changes without writing")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

    d1 = D1Client(
        os.environ["CLOUDFLARE_ACCOUNT_ID"],
        os.environ["CLOUDFLARE_API_TOKEN"],
        os.environ["D1_DATABASE_ID"],
    )
    try:
        result = reevaluate_coverage(d1, args.policies_dir)
        print(json.dumps(result, indent=2))
    finally:
        d1.close()
