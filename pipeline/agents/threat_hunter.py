"""Threat Hunter agent — discovers and classifies agentic AI security incidents."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from claude_agent_sdk import Agent

from pipeline.config import Config
from pipeline.tools.d1_client import D1Client

logger = logging.getLogger(__name__)


def _load_system_prompt(spec_path: str) -> str:
    """Load agent system prompt from AGENTS.md."""
    return Path(spec_path).read_text()


async def run_threat_hunter(config: Config, date: str) -> Path:
    """Run the Threat Hunter agent for a given date.

    Returns the path to the findings JSON file.
    """
    now = datetime.now(timezone.utc)
    year = now.year
    findings_path = Path(f"findings/{date}.json")

    system_prompt = _load_system_prompt(config.threat_hunter_spec)

    d1 = D1Client(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)

    try:
        last_id = d1.get_max_vtms_sequence(year)
        total_incidents = len(d1.execute("SELECT COUNT(*) as cnt FROM incidents"))

        user_message = (
            f"Execute your daily research cycle for {date}.  "
            f"Current VTMS sequence: VTMS-{year}-{last_id:04d}.  "
            f"{total_incidents} existing incidents in database.\n\n"
            f"Write your findings JSON array to findings/{date}.json using the Write tool."
        )

        agent = Agent(
            model=config.model,
            prompt=f"{system_prompt}\n\n{user_message}",
            allowed_tools=[
                "WebSearch",
                "WebFetch",
                "Read",
                "Write",
                "Bash",
                "mcp__sentinel__d1_query",
                "mcp__sentinel__d1_write",
                "mcp__sentinel__r2_put",
                "mcp__sentinel__pushover_alert",
            ],
        )
        result = agent.run()
        logger.info("Threat Hunter agent completed: %s", result[:200] if result else "no output")

        if not findings_path.exists():
            logger.warning("Threat Hunter did not write findings file; creating empty one")
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text("[]")

        # Post-processing: validate findings output via Guardrails AI
        try:
            from pipeline.validation import validate_findings

            raw_json = findings_path.read_text()
            validated = validate_findings(raw_json)
            # Write back the validated (potentially cleaned) findings
            findings_path.write_text(json.dumps(validated, indent=2))
            logger.info("Findings validation passed: %d finding(s) validated", len(validated))
        except Exception as e:
            # Don't crash on validation failure -- findings may be partially valid
            logger.warning("Findings validation failed (continuing with raw output): %s", e)

        return findings_path

    finally:
        d1.close()
