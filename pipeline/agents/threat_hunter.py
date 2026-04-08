"""Threat Hunter agent — discovers and classifies agentic AI security incidents.

Decomposes the monolithic threat hunt into three sub-agent phases:
1. Research Scout — discover raw incident candidates via web search
2. Threat Classifier — classify each candidate (fanned out in parallel)
3. Publisher — write findings to D1, R2, send alerts
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from pipeline.config import Config
from pipeline.schemas.raw_candidate import RawCandidate
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

_STAGE_OUTPUTS = Path("stage-outputs")


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
    """Load agent system prompt from a markdown spec file."""
    return Path(spec_path).read_text()


async def _run_sub_agent(
    *,
    name: str,
    config: Config,
    system_prompt: str,
    user_message: str,
    allowed_tools: list[str],
    max_turns: int,
) -> str:
    """Run a sub-agent query and return the result text."""
    options = ClaudeAgentOptions(
        model=config.model,
        system_prompt=system_prompt,
        allowed_tools=allowed_tools,
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        mcp_servers=config.mcp_server_config,
        stderr=lambda line: logger.warning("[%s] CLI stderr: %s", name, line),
    )

    logger.info("[%s] Starting (max_turns=%d)", name, max_turns)

    result_text = ""
    turn_count = 0
    try:
        async for message in query(prompt=user_message, options=options):
            turn_count += 1
            if isinstance(message, ResultMessage):
                result_text = message.result if hasattr(message, "result") else str(message)
    except Exception as e:
        logger.error("[%s] Agent SDK query failed after %d turns: %s", name, turn_count, e)
        raise

    logger.info("[%s] Completed in %d turns", name, turn_count)
    return result_text


async def _run_research_scout(
    config: Config, date: str, dedup_digest: str
) -> list[dict]:
    """Phase 1: Discover raw incident candidates via web search."""
    system_prompt = _load_system_prompt(config.threat_hunter_research_spec)

    output_path = _STAGE_OUTPUTS / "research-raw.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    user_message = (
        f"Execute your research cycle for {date}. "
        f"Focus on incidents from the last 30 days. "
        f"Do not report incidents older than 90 days unless newly disclosed or newly assigned a CVE.\n\n"
        f"## Existing incidents (DO NOT re-discover these):\n{dedup_digest}\n\n"
        f"Write your output JSON array to {output_path}"
    )

    await _run_sub_agent(
        name="research-scout",
        config=config,
        system_prompt=system_prompt,
        user_message=user_message,
        allowed_tools=[
            "WebSearch",
            "WebFetch",
            "Read",
            "Write",
            "Bash",
            "mcp__sentinel__r2_put",
        ],
        max_turns=20,
    )

    if not output_path.exists():
        logger.warning("Research Scout did not write output file; returning empty list")
        return []

    raw_data = json.loads(output_path.read_text())
    if not isinstance(raw_data, list):
        logger.warning("Research Scout output is not a list; returning empty list")
        return []

    # Validate candidates
    validated = []
    for i, item in enumerate(raw_data):
        try:
            candidate = RawCandidate.model_validate(item)
            validated.append(candidate.model_dump())
        except Exception as e:
            logger.warning("Raw candidate[%d] failed validation (skipping): %s", i, e)
            validated.append(item)  # Keep partially valid candidates

    logger.info("Research Scout found %d candidate(s)", len(validated))
    return validated


async def _run_threat_classifier(
    config: Config,
    candidate: dict,
    vtms_id: str,
    year: int,
    candidate_index: int,
) -> dict | None:
    """Phase 2: Classify a single raw candidate into a full Finding."""
    system_prompt = _load_system_prompt(config.threat_hunter_classifier_spec)

    output_path = _STAGE_OUTPUTS / f"classified-{candidate_index}.json"

    user_message = (
        f"Classify the following raw incident candidate.\n\n"
        f"Your pre-assigned VTMS identifier: {vtms_id}\n"
        f"Current year: {year}\n\n"
        f"## Raw candidate\n```json\n{json.dumps(candidate, indent=2)}\n```\n\n"
        f"Write the classified Finding JSON object to {output_path}"
    )

    try:
        await _run_sub_agent(
            name=f"classifier-{candidate_index}",
            config=config,
            system_prompt=system_prompt,
            user_message=user_message,
            allowed_tools=[
                "Read",
                "Write",
                "Bash",
                "mcp__sentinel__d1_query",
            ],
            max_turns=20,
        )
    except Exception as e:
        logger.error("Classifier for candidate %d failed: %s", candidate_index, e)
        return None

    if not output_path.exists():
        logger.warning("Classifier %d did not write output file", candidate_index)
        return None

    try:
        return json.loads(output_path.read_text())
    except json.JSONDecodeError as e:
        logger.warning("Classifier %d output is not valid JSON: %s", candidate_index, e)
        return None


async def _run_publisher(
    config: Config, date: str, findings: list[dict]
) -> Path:
    """Phase 3: Write findings to D1, R2 and send alerts."""
    system_prompt = _load_system_prompt(config.threat_hunter_publisher_spec)
    findings_path = Path(f"findings/{date}.json")

    user_message = (
        f"Publish the following classified findings for {date}.\n\n"
        f"## Classified findings\n```json\n{json.dumps(findings, indent=2)}\n```\n\n"
        f"Write the findings JSON array to {findings_path}\n"
        f"Then write eligible records to D1 and send Pushover alerts for severity 4-5."
    )

    await _run_sub_agent(
        name="publisher",
        config=config,
        system_prompt=system_prompt,
        user_message=user_message,
        allowed_tools=[
            "Read",
            "Write",
            "mcp__sentinel__d1_write",
            "mcp__sentinel__r2_put",
            "mcp__sentinel__pushover_alert",
        ],
        max_turns=15,
    )

    return findings_path


async def run_threat_hunter(config: Config, date: str) -> Path:
    """Run the Threat Hunter pipeline for a given date.

    Orchestrates three sub-agent phases:
    1. Research Scout — discover raw candidates
    2. Threat Classifiers — classify each candidate (fan-out, parallel)
    3. Publisher — write to D1/R2, send alerts

    Returns the path to the findings JSON file.
    """
    now = datetime.now(UTC)
    year = now.year
    findings_path = Path(f"findings/{date}.json")

    _STAGE_OUTPUTS.mkdir(parents=True, exist_ok=True)

    d1 = D1Client(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)

    try:
        last_id = d1.get_max_vtms_sequence(year)
        total_incidents = d1.execute("SELECT COUNT(*) as cnt FROM incidents")[0]["cnt"]

        # Fetch recent incidents for dedup context
        recent_incidents = d1.list_incidents(limit=200)
        dedup_digest = "\n".join(
            f"- {inc['vtms_id']}: {inc['title']} (CVEs: {inc.get('cve_ids', '[]')})"
            for inc in recent_incidents
        )

        logger.info(
            "Starting threat hunter pipeline: %d existing incidents, last ID VTMS-%d-%04d",
            total_incidents, year, last_id,
        )

        # --- Phase 1: Research Scout ---
        candidates = await _run_research_scout(config, date, dedup_digest)

        if not candidates:
            logger.info("No new candidates found; writing empty findings file")
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text("[]")
            return findings_path

        # --- Phase 2: Fan-out Threat Classifiers ---
        # Pre-assign VTMS IDs so parallel classifiers don't collide
        classifier_tasks = []
        for i, candidate in enumerate(candidates):
            vtms_id = f"VTMS-{year}-{last_id + 1 + i:04d}"
            classifier_tasks.append(
                _run_threat_classifier(config, candidate, vtms_id, year, i)
            )

        logger.info("Fanning out %d classifier(s) in parallel", len(classifier_tasks))
        classifier_results = await asyncio.gather(*classifier_tasks, return_exceptions=True)

        # Collect successful classifications
        classified_findings = []
        for i, result in enumerate(classifier_results):
            if isinstance(result, Exception):
                logger.error("Classifier %d raised exception: %s", i, result)
            elif result is not None:
                classified_findings.append(result)
            else:
                logger.warning("Classifier %d returned no output", i)

        logger.info(
            "Classification complete: %d/%d candidates classified",
            len(classified_findings), len(candidates),
        )

        if not classified_findings:
            logger.warning("All classifiers failed; writing empty findings file")
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text("[]")
            return findings_path

        # --- Phase 3: Publisher ---
        findings_path = await _run_publisher(config, date, classified_findings)

        if not findings_path.exists():
            logger.warning("Publisher did not write findings file; writing classified output directly")
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text(json.dumps(classified_findings, indent=2))

        # --- Post-processing (same as before) ---

        # Auto-remap LLM→ASI taxonomy
        try:
            raw_data = json.loads(findings_path.read_text())
            remapped = _remap_owasp_categories(raw_data)
            if remapped:
                logger.info("Auto-remapped %d finding(s) from LLM→ASI taxonomy", remapped)
                findings_path.write_text(json.dumps(raw_data, indent=2))
        except Exception as e:
            logger.warning("OWASP remap failed (continuing): %s", e)

        # Validate findings via Guardrails AI
        try:
            from pipeline.validation import validate_findings

            raw_json = findings_path.read_text()
            validated = validate_findings(raw_json)
            findings_path.write_text(json.dumps(validated, indent=2))
            logger.info("Findings validation passed: %d finding(s) validated", len(validated))
        except Exception as e:
            logger.warning("Findings validation failed (continuing with raw output): %s", e)

        # Deduplicate against existing incidents
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
