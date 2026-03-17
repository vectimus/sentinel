"""Individual pipeline stage runners for GitHub Actions HITL workflow.

Each function is a self-contained stage that can run independently,
reading inputs from / writing outputs to the filesystem (GitHub Actions
artifacts bridge the gap between jobs).
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
from pipeline.tracing import init_tracing, export_traces, shutdown as shutdown_tracing

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("sentinel")


def _clean_env() -> None:
    """Clean Claude Code / OTEL env vars before agent work."""
    _oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
    for key in list(os.environ):
        if key.startswith("CLAUDE_CODE_") or key == "CLAUDECODE" or key.startswith("OTEL_"):
            os.environ.pop(key)
    if _oauth:
        os.environ["CLAUDE_CODE_OAUTH_TOKEN"] = _oauth
    if not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ.pop("ANTHROPIC_API_KEY", None)
    os.environ.setdefault("SENTINEL_PYTHON", sys.executable)


def _write_github_summary(text: str) -> None:
    """Append text to GitHub Actions job summary."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(text)


# ---------------------------------------------------------------------------
# Stage: discover
# ---------------------------------------------------------------------------

async def _discover_async() -> None:
    """Run Threat Hunter, validate findings, scrub D1, write summary."""
    _clean_env()
    config = Config.from_env()
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    init_tracing(project_name=f"sentinel-discover-{date}")
    logger.info("Discover stage starting for %s", date)

    from pipeline.agents.threat_hunter import run_threat_hunter

    findings_path = await run_threat_hunter(config, date)
    logger.info("Threat Hunter complete: %s", findings_path)

    # Validate findings
    try:
        from pipeline.validation import validate_findings
        validated = validate_findings(findings_path.read_text())
        logger.info("Validated %d finding(s)", len(validated))
    except Exception as e:
        logger.warning("Findings validation issue: %s", e)

    # Scrub internal gaps from D1
    try:
        from pipeline.tools.d1_client import D1Client
        d1 = D1Client(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)
        try:
            rows = d1.execute(
                "SELECT vtms_id FROM incidents "
                "WHERE coverage_status = 'gap' AND "
                "(enforcement_scope IS NULL OR enforcement_scope != 'out_of_scope')"
            )
            for row in rows:
                vtms_id = row.get("vtms_id")
                if vtms_id:
                    d1.execute("DELETE FROM incidents WHERE vtms_id = ?", [vtms_id])
                    logger.info("Scrubbed internal gap %s from D1", vtms_id)
        finally:
            d1.close()
    except Exception as e:
        logger.warning("D1 gap scrub failed (non-fatal): %s", e)

    # Write human-readable summary for HITL review
    findings = json.loads(findings_path.read_text()) if findings_path.exists() else []
    severity_map = {1: "THEORETICAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}

    summary_lines = [
        f"## Sentinel Discover — {date}",
        "",
        f"**{len(findings)} finding(s)** discovered.",
        "",
        "| ID | Severity | Category | Scope | Action | Title |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        sev = severity_map.get(f.get("severity", 0), "?")
        summary_lines.append(
            f"| {f['vtms_id']} | {sev} | {f.get('owasp_category', '?')} "
            f"| {f.get('enforcement_scope', '?')} | {f.get('recommended_action', '?')} "
            f"| {f['title'][:80]} |"
        )

    actionable = [f for f in findings if f.get("recommended_action") != "no_change"]
    content_worthy = [
        f for f in findings
        if f.get("content_worthy") and f.get("enforcement_scope") != "out_of_scope"
    ]
    gaps = [
        f for f in findings
        if f.get("coverage_status") == "gap"
        and f.get("enforcement_scope") != "out_of_scope"
    ]

    summary_lines.extend([
        "",
        f"**Actionable (policy work):** {len(actionable)}  ",
        f"**Content-worthy (advisories):** {len(content_worthy)}  ",
        f"**Gaps:** {len(gaps)}  ",
        "",
        "### What happens next",
        "",
        "Approving this gate will:",
        f"- Run the **Security Engineer** on {len(actionable)} actionable finding(s) → policy PRs",
        f"- Run the **Threat Analyst** on {len(content_worthy)} content-worthy finding(s) → advisory PRs",
        "- Compute trends and send digest notification",
    ])

    summary_md = "\n".join(summary_lines)
    _write_github_summary(summary_md + "\n")
    logger.info("Discover summary:\n%s", summary_md)

    trace_file = export_traces(date)
    if trace_file:
        logger.info("Traces exported to %s", trace_file)
    shutdown_tracing()


def discover() -> None:
    """Entry point for the discover stage."""
    asyncio.run(_discover_async())


# ---------------------------------------------------------------------------
# Stage: engineer
# ---------------------------------------------------------------------------

async def _engineer_async() -> None:
    """Run Security Engineer on findings."""
    _clean_env()
    config = Config.from_env()
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    init_tracing(project_name=f"sentinel-engineer-{date}")
    logger.info("Engineer stage starting")

    findings_path = Path(os.environ.get("FINDINGS_PATH", f"findings/{date}.json"))
    if not findings_path.exists():
        logger.error("Findings file not found: %s", findings_path)
        sys.exit(1)

    from pipeline.agents.security_engineer import run_security_engineer
    result = await run_security_engineer(config, findings_path)
    logger.info("Security Engineer complete: %d PRs created", result["prs_created"])

    # Write result for downstream consumption
    result_path = Path("stage-outputs/engineer.json")
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2))

    _write_github_summary(f"```\nSecurity Engineer: {result['prs_created']} PR(s) created\n```\n")

    trace_file = export_traces(date)
    if trace_file:
        logger.info("Traces exported to %s", trace_file)
    shutdown_tracing()


def engineer() -> None:
    """Entry point for the engineer stage."""
    asyncio.run(_engineer_async())


# ---------------------------------------------------------------------------
# Stage: analyst
# ---------------------------------------------------------------------------

async def _analyst_async() -> None:
    """Run Threat Analyst on findings."""
    _clean_env()
    config = Config.from_env()
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    init_tracing(project_name=f"sentinel-analyst-{date}")
    logger.info("Analyst stage starting")

    findings_path = Path(os.environ.get("FINDINGS_PATH", f"findings/{date}.json"))
    if not findings_path.exists():
        logger.error("Findings file not found: %s", findings_path)
        sys.exit(1)

    from pipeline.agents.threat_analyst import run_threat_analyst
    result = await run_threat_analyst(config, findings_path)
    logger.info("Threat Analyst complete: %d PRs created", result["prs_created"])

    # Write result for downstream consumption
    result_path = Path("stage-outputs/analyst.json")
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2))

    _write_github_summary(f"```\nThreat Analyst: {result['prs_created']} PR(s) created\n```\n")

    trace_file = export_traces(date)
    if trace_file:
        logger.info("Traces exported to %s", trace_file)
    shutdown_tracing()


def analyst() -> None:
    """Entry point for the analyst stage."""
    asyncio.run(_analyst_async())


# ---------------------------------------------------------------------------
# Stage: publish (trends + digest)
# ---------------------------------------------------------------------------

async def _publish_async() -> None:
    """Compute trends and send notification digest."""
    _clean_env()
    config = Config.from_env()
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    start = time.monotonic()
    errors: list[str] = []

    logger.info("Publish stage starting")

    findings_path = Path(os.environ.get("FINDINGS_PATH", f"findings/{date}.json"))

    # Load engineer/analyst results if available
    engineer_result = None
    analyst_result = None
    for name, var in [("engineer", "engineer_result"), ("analyst", "analyst_result")]:
        path = Path(f"stage-outputs/{name}.json")
        if path.exists():
            data = json.loads(path.read_text())
            if name == "engineer":
                engineer_result = data
            else:
                analyst_result = data

    # Compute trends
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

    # Build and send digest
    from pipeline.orchestrator import _build_digest
    from pipeline.tools.pushover_client import PushoverClient

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

    _write_github_summary(f"```\n{digest}\n```\n")


def publish() -> None:
    """Entry point for the publish stage."""
    asyncio.run(_publish_async())
