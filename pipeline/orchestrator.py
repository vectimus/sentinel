"""Sentinel pipeline orchestrator.

Coordinates three agents in a staged, sequential pipeline:
1. Threat Hunter — discover and classify incidents
2. Security Engineer — draft policies, sandbox verify, open PRs
3. Threat Analyst — write advisories using verified policy and sandbox results
4. Notification digest
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.config import Config
from pipeline.agents.threat_hunter import run_threat_hunter
from pipeline.agents.security_engineer import run_security_engineer
from pipeline.agents.threat_analyst import run_threat_analyst
from pipeline.tools.pushover_client import PushoverClient
from pipeline.tracing import init_tracing, export_traces, shutdown as shutdown_tracing

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("sentinel")


def _build_digest(
    date: str,
    findings_path: Path,
    engineer_result: dict | None,
    analyst_result: dict | None,
    elapsed: float,
    errors: list[str],
) -> str:
    """Build the daily digest notification text."""
    findings = json.loads(findings_path.read_text()) if findings_path.exists() else []

    lines = [f"Vectimus Sentinel — {date}", ""]

    lines.append(f"New incidents: {len(findings)}")
    for f in findings:
        severity_label = {1: "THEORETICAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}.get(
            f.get("severity", 0), "UNKNOWN"
        )
        lines.append(f"  {f['vtms_id']} [{severity_label}] {f['title'][:60]}")

    lines.append("")

    if engineer_result:
        lines.append(f"Policy PRs: {engineer_result['prs_created']} (vectimus/policies)")
    if analyst_result:
        lines.append(f"Content PRs: {analyst_result['prs_created']} (vectimus/vectimus-website)")

    gaps = sum(1 for f in findings if f.get("coverage_status") == "gap")
    if gaps:
        lines.append(f"Gaps found: {gaps}")

    if errors:
        lines.append("")
        lines.append("Errors:")
        for err in errors:
            lines.append(f"  {err}")

    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    lines.append("")
    lines.append(f"Run time: {minutes}m {seconds}s")

    return "\n".join(lines)


def _write_github_summary(digest: str) -> None:
    """Write to GitHub Actions job summary if available."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(f"```\n{digest}\n```\n")


async def main() -> None:
    start = time.monotonic()
    config = Config.from_env()
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    errors: list[str] = []

    # Start observability tracing
    init_tracing(project_name=f"sentinel-{date}")

    logger.info("Sentinel pipeline starting for %s", date)

    # Stage 1: Threat Hunter
    logger.info("Stage 1: Running Threat Hunter")
    try:
        findings_path = await run_threat_hunter(config, date)
        logger.info("Threat Hunter complete: %s", findings_path)
    except Exception as e:
        logger.error("Threat Hunter failed: %s", e)
        pushover = PushoverClient(config.pushover_user_key, config.pushover_app_token)
        try:
            pushover.send(
                message=f"Threat Hunter failed: {e}",
                title="Sentinel Pipeline Error",
                priority=1,
            )
        finally:
            pushover.close()
        sys.exit(1)

    # Validate findings before passing to downstream agents
    try:
        from pipeline.validation import validate_findings

        raw_findings = findings_path.read_text()
        validated = validate_findings(raw_findings)
        logger.info(
            "Findings validation: %d finding(s) validated for downstream agents",
            len(validated),
        )
    except Exception as e:
        logger.warning("Findings validation failed in orchestrator: %s", e)
        errors.append(f"Findings validation: {e}")

    # Stage 2: Security Engineer (sequential — Threat Analyst needs its output)
    logger.info("Stage 2: Running Security Engineer")
    engineer_result = None
    try:
        engineer_result = await run_security_engineer(config, findings_path)
        logger.info("Security Engineer complete: %d PRs created", engineer_result["prs_created"])
    except Exception as e:
        logger.error("Security Engineer failed: %s", e)
        errors.append(f"Security Engineer: {e}")

    # Stage 3: Threat Analyst (sequential — uses Security Engineer's sandbox results and PRs)
    logger.info("Stage 3: Running Threat Analyst")
    analyst_result = None
    try:
        analyst_result = await run_threat_analyst(config, findings_path)
        logger.info("Threat Analyst complete: %d PRs created", analyst_result["prs_created"])
    except Exception as e:
        logger.error("Threat Analyst failed: %s", e)
        errors.append(f"Threat Analyst: {e}")

    # Stage 4: Notification digest
    logger.info("Stage 4: Sending notifications")
    elapsed = time.monotonic() - start
    digest = _build_digest(date, findings_path, engineer_result, analyst_result, elapsed, errors)

    logger.info("Digest:\n%s", digest)

    pushover = PushoverClient(config.pushover_user_key, config.pushover_app_token)
    try:
        pushover.send_digest(digest)
    except Exception as e:
        logger.error("Failed to send digest: %s", e)
    finally:
        pushover.close()

    _write_github_summary(digest)

    # Export traces and shut down Phoenix
    trace_file = export_traces(date)
    if trace_file:
        logger.info("Traces exported to %s", trace_file)
    shutdown_tracing()

    if errors:
        logger.warning("Pipeline completed with errors: %s", errors)
    else:
        logger.info("Pipeline completed successfully in %.1fs", elapsed)


if __name__ == "__main__":
    asyncio.run(main())


# Allow `python -m pipeline.orchestrator`
def _entry() -> None:
    asyncio.run(main())
