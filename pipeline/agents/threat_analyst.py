"""Threat Analyst agent — produces incident analysis content."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage

from pipeline.config import Config

logger = logging.getLogger(__name__)


def _load_system_prompt(spec_path: str) -> str:
    return Path(spec_path).read_text()


def _extract_pr_urls(text: str) -> list[str]:
    """Extract GitHub PR URLs from agent output text."""
    return re.findall(r"https://github\.com/[^\s)\"']+/pull/\d+", text or "")


async def run_threat_analyst(config: Config, findings_path: Path) -> dict:
    """Run the Threat Analyst on content-worthy findings.

    Returns a summary dict with PR URLs and stats.
    """
    findings = json.loads(findings_path.read_text())
    content_worthy = [
        f for f in findings
        if f.get("content_worthy") and f.get("enforcement_scope") != "out_of_scope"
    ]

    if not content_worthy:
        logger.info("No content-worthy findings for Threat Analyst")
        return {"prs_created": 0, "pr_urls": []}

    system_prompt = _load_system_prompt(config.threat_analyst_spec)

    user_message = (
        f"Process these content-worthy findings:\n\n"
        f"```json\n{json.dumps(content_worthy, indent=2)}\n```\n\n"
        f"Write blog posts and incident briefs.  Open PRs in the website repo ({config.website_repo}).\n\n"
        f"Use the Write tool to create blog post files at content/blog/<filename>.md "
        f"and briefs at content/briefs/<vtms-id>.md.\n\n"
        f"Use mcp__sentinel__github_create_branch to create branches in {config.website_repo}.  "
        f"Use mcp__sentinel__github_push_file to push files to the branch.  "
        f"Use mcp__sentinel__github_create_pr to open PRs.  "
        f"Use mcp__sentinel__github_get_pr to check Security Engineer PRs in {config.policies_repo}.  "
        f"Use mcp__sentinel__d1_query and mcp__sentinel__d1_write for database operations.  "
        f"Use mcp__sentinel__r2_get to read archived source material."
    )

    options = ClaudeAgentOptions(
        model=config.model,
        system_prompt=system_prompt,
        allowed_tools=[
            "Read",
            "Write",
            "Bash",
            "mcp__sentinel__d1_query",
            "mcp__sentinel__d1_write",
            "mcp__sentinel__r2_get",
            "mcp__sentinel__github_create_branch",
            "mcp__sentinel__github_push_file",
            "mcp__sentinel__github_create_pr",
            "mcp__sentinel__github_get_pr",
        ],
        permission_mode="bypassPermissions",
        max_turns=40,
        mcp_servers=config.mcp_server_config,
        stderr=lambda line: logger.debug("CLI: %s", line),
    )

    result_text = ""
    async for message in query(prompt=user_message, options=options):
        if isinstance(message, ResultMessage):
            result_text = message.result if hasattr(message, "result") else str(message)

    logger.info("Threat Analyst agent completed: %s", result_text[:200] if result_text else "no output")

    pr_urls = _extract_pr_urls(result_text)
    return {"prs_created": len(pr_urls), "pr_urls": pr_urls}
