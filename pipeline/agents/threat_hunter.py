"""Threat Hunter agent — discovers and classifies agentic AI security incidents."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage

from pipeline.config import Config
from pipeline.tools.d1_client import D1Client

logger = logging.getLogger(__name__)

# Mapping from deprecated LLM Top 10 codes to ASI Top 10 for Agentic Applications
_LLM_TO_ASI = {
    "LLM01": "ASI01",  # Prompt Injection → Goal Hijacking
    "LLM02": "ASI02",  # Insecure Output Handling → Tool Misuse
    "LLM03": "ASI03",  # Training Data Poisoning → Identity and Privilege Abuse
    "LLM04": "ASI04",  # Model Denial of Service → Supply Chain Vulnerabilities
    "LLM05": "ASI05",  # Supply Chain Vulnerabilities → Unsafe Code Execution
    "LLM06": "ASI06",  # Sensitive Information Disclosure → Memory Poisoning
    "LLM07": "ASI07",  # Insecure Plugin Design → Inter-Agent Exploitation
    "LLM08": "ASI08",  # Excessive Agency → Cascading Failures
    "LLM09": "ASI09",  # Overreliance → Trust Boundary Violations
    "LLM10": "ASI10",  # Model Theft → Rogue Agents
}


def _remap_owasp_categories(findings: list[dict]) -> int:
    """Auto-remap LLM-prefixed OWASP categories to ASI equivalents.

    Mutates findings in place. Returns number of remapped findings.
    """
    import re
    remapped = 0
    for finding in findings:
        cat = finding.get("owasp_category", "")
        if not cat:
            continue
        # Match "LLM01" or "LLM01: Some Description"
        match = re.match(r"^(LLM\d{2})", cat)
        if match:
            old_prefix = match.group(1)
            new_prefix = _LLM_TO_ASI.get(old_prefix)
            if new_prefix:
                finding["owasp_category"] = cat.replace(old_prefix, new_prefix, 1)
                remapped += 1
                logger.info(
                    "Remapped %s OWASP category: %s → %s",
                    finding.get("vtms_id", "?"),
                    old_prefix,
                    new_prefix,
                )
    return remapped


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

        # Fetch recent incidents for dedup context
        recent_incidents = d1.list_incidents(limit=200)
        dedup_digest = "\n".join(
            f"- {inc['vtms_id']}: {inc['title']} (CVEs: {inc.get('cve_ids', '[]')})"
            for inc in recent_incidents
        )

        user_message = (
            f"Execute your daily research cycle for {date}.  "
            f"Current VTMS sequence: VTMS-{year}-{last_id:04d}.  "
            f"{total_incidents} existing incidents in database.  "
            f"Focus on incidents from the last 30 days.  "
            f"Do not report incidents older than 90 days unless newly disclosed or newly assigned a CVE.\n\n"
            f"## Existing incidents (DO NOT re-discover these):\n{dedup_digest}\n\n"
            f"Write your findings JSON array to findings/{date}.json using the Write tool."
        )

        options = ClaudeAgentOptions(
            model=config.model,
            system_prompt=system_prompt,
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
            permission_mode="bypassPermissions",
            max_turns=30,
            mcp_servers=config.mcp_server_config,
            stderr=lambda line: logger.warning("CLI stderr: %s", line),
        )

        result_text = ""
        async for message in query(prompt=user_message, options=options):
            if isinstance(message, ResultMessage):
                result_text = message.result if hasattr(message, "result") else str(message)

        logger.info("Threat Hunter agent completed: %s", result_text[:200] if result_text else "no output")

        if not findings_path.exists():
            logger.warning("Threat Hunter did not write findings file; creating empty one")
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text("[]")

        # Post-processing: auto-remap LLM→ASI taxonomy before validation
        try:
            raw_data = json.loads(findings_path.read_text())
            remapped = _remap_owasp_categories(raw_data)
            if remapped:
                logger.info("Auto-remapped %d finding(s) from LLM→ASI taxonomy", remapped)
                findings_path.write_text(json.dumps(raw_data, indent=2))
        except Exception as e:
            logger.warning("OWASP remap failed (continuing): %s", e)

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

        # Post-processing: deduplicate against existing incidents
        try:
            from pipeline.dedup import deduplicate

            findings_data = json.loads(findings_path.read_text())
            if findings_data and recent_incidents:
                unique, dupes = deduplicate(findings_data, recent_incidents)
                if dupes:
                    logger.info(
                        "Dedup removed %d duplicate(s): %s",
                        len(dupes),
                        ", ".join(f[0].get("vtms_id", "?") for f in dupes),
                    )
                    findings_path.write_text(json.dumps(unique, indent=2))
        except Exception as e:
            logger.warning("Deduplication failed (continuing with all findings): %s", e)

        return findings_path

    finally:
        d1.close()
