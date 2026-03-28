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
from pipeline.safe_path import safe_open_for_append
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

    pending = sum(1 for f in findings if f.get("coverage_status") == "policy_pending")
    if pending:
        lines.append(f"Policy pending: {pending}")

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
        with safe_open_for_append(summary_path) as f:
            f.write(f"```\n{digest}\n```\n")


async def main() -> None:
    start = time.monotonic()

    # Ensure Claude Code session vars are cleaned (entry points do this,
    # but guard here too for programmatic callers).
    # Also clean OTEL vars from parent sessions to prevent gRPC fork issues.
    for key in list(os.environ):
        if key.startswith("CLAUDE_CODE_") and key != "CLAUDE_CODE_OAUTH_TOKEN":
            os.environ.pop(key)
        if key.startswith("OTEL_"):
            os.environ.pop(key)
    os.environ.pop("CLAUDECODE", None)
    os.environ.setdefault("SENTINEL_PYTHON", sys.executable)

    # Remove empty ANTHROPIC_API_KEY (e.g. from .env template) — the CLI
    # treats an empty string as an invalid key rather than falling through
    # to OAuth. Do NOT set ANTHROPIC_API_KEY to an OAuth token — the CLI
    # rejects OAuth tokens in that env var.
    if not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ.pop("ANTHROPIC_API_KEY", None)

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
        if config.pushover_user_key and config.pushover_app_token:
            pushover = PushoverClient(config.pushover_user_key, config.pushover_app_token)
            try:
                pushover.send(
                    message=f"Threat Hunter failed: {e}",
                    title="Sentinel Pipeline Error",
                    priority=1,
                )
            finally:
                pushover.close()
        else:
            logger.warning("Pushover not configured — skipping error alert")
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

    # Post-processing: scrub internal policy_pending items from D1
    # The Threat Hunter prompt instructs the agent not to write internal
    # policy_pending findings (enforcement_scope!=out_of_scope) to D1. This
    # is a safety net in case the agent writes them anyway.
    try:
        from pipeline.tools.d1_client import D1Client as _D1

        d1_scrub = _D1(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)
        try:
            internal_pending = d1_scrub.execute(
                "SELECT vtms_id FROM incidents "
                "WHERE coverage_status = 'policy_pending' AND "
                "(enforcement_scope IS NULL OR enforcement_scope != 'out_of_scope')"
            )
            for row in internal_pending:
                vtms_id = row.get("vtms_id")
                if vtms_id:
                    d1_scrub.execute(
                        "DELETE FROM incidents WHERE vtms_id = ?", [vtms_id]
                    )
                    logger.info("Removed internal policy_pending %s from D1", vtms_id)
        finally:
            d1_scrub.close()
    except Exception as e:
        logger.warning("D1 policy_pending scrub failed (non-fatal): %s", e)

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

    # Compute and store trends
    logger.info("Computing trends")
    try:
        from pipeline.trends import compute_and_store_trends
        from pipeline.tools.d1_client import D1Client

        d1 = D1Client(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)
        try:
            trend = compute_and_store_trends(d1, date)
            logger.info("Trends computed: %s", trend)
        finally:
            d1.close()
    except Exception as e:
        logger.error("Failed to compute trends: %s", e)
        errors.append(f"Trends: {e}")

    # Stage 4: Notification digest
    logger.info("Stage 4: Sending notifications")
    elapsed = time.monotonic() - start
    digest = _build_digest(date, findings_path, engineer_result, analyst_result, elapsed, errors)

    logger.info("Digest:\n%s", digest)

    if config.pushover_user_key and config.pushover_app_token:
        pushover = PushoverClient(config.pushover_user_key, config.pushover_app_token)
        try:
            pushover.send_digest(digest)
        except Exception as e:
            logger.error("Failed to send digest: %s", e)
        finally:
            pushover.close()
    else:
        logger.info("Pushover not configured — digest printed to log only")

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


def _entry() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    # When run directly, clean Claude Code session vars first
    _oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
    for _key in list(os.environ):
        if _key.startswith("CLAUDE_CODE_") or _key == "CLAUDECODE":
            os.environ.pop(_key)
    if _oauth:
        os.environ["CLAUDE_CODE_OAUTH_TOKEN"] = _oauth
    os.environ.setdefault("SENTINEL_PYTHON", sys.executable)
    _entry()
