"""Security Engineer agent — drafts Cedar policies with sandbox-verified test cases."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from claude_agent_sdk import Agent

from pipeline.config import Config

logger = logging.getLogger(__name__)


def _load_system_prompt(spec_path: str) -> str:
    return Path(spec_path).read_text()


def _extract_pr_urls(text: str) -> list[str]:
    """Extract GitHub PR URLs from agent output text."""
    return re.findall(r"https://github\.com/[^\s)\"']+/pull/\d+", text or "")


async def run_security_engineer(config: Config, findings_path: Path) -> dict:
    """Run the Security Engineer on findings that need policy changes.

    Returns a summary dict with PR URLs and stats.
    """
    findings = json.loads(findings_path.read_text())
    actionable = [f for f in findings if f.get("recommended_action") != "no_change"]

    if not actionable:
        logger.info("No actionable findings for Security Engineer")
        return {"prs_created": 0, "pr_urls": []}

    system_prompt = _load_system_prompt(config.security_engineer_spec)
    policies_path = Path(config.policies_repo_path).resolve()

    user_message = (
        f"Process these findings that require policy changes:\n\n"
        f"```json\n{json.dumps(actionable, indent=2)}\n```\n\n"
        f"The policies repo is at {policies_path}.  "
        f"Read existing policies, draft new ones, run sandbox replay, and open PRs.\n\n"
        f"Use the Read/Write/Glob tools for file operations on the policies repo.  "
        f"Use Bash for git commands (checkout, branch, add, commit, push, status, log, diff only).  "
        f"Use the mcp__sentinel__cedar_authorize and mcp__sentinel__cedar_validate tools for Cedar sandbox testing.  "
        f"Use mcp__sentinel__github_create_pr to open PRs in {config.policies_repo}.  "
        f"Use mcp__sentinel__d1_query and mcp__sentinel__d1_write for database operations.  "
        f"Use mcp__sentinel__r2_get to read archived source material."
    )

    agent = Agent(
        model=config.model,
        prompt=f"{system_prompt}\n\n{user_message}",
        allowed_tools=[
            "Read",
            "Write",
            "Glob",
            "Bash",
            "mcp__sentinel__d1_query",
            "mcp__sentinel__d1_write",
            "mcp__sentinel__r2_get",
            "mcp__sentinel__cedar_authorize",
            "mcp__sentinel__cedar_validate",
            "mcp__sentinel__github_create_pr",
        ],
    )
    result = agent.run()
    logger.info("Security Engineer agent completed: %s", result[:200] if result else "no output")

    pr_urls = _extract_pr_urls(result)
    return {"prs_created": len(pr_urls), "pr_urls": pr_urls}
