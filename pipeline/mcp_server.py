"""Sentinel MCP server — domain-specific tools for the Sentinel pipeline agents.

Exposes D1, R2, Cedar, GitHub and Pushover operations as MCP tools.
Runs as a subprocess managed by the Claude Agent SDK via .claude/settings.json.
"""

from __future__ import annotations

import json
import os

from fastmcp import FastMCP

from pipeline.tools.cedar_sandbox import CedarSandbox
from pipeline.tools.d1_client import D1Client
from pipeline.tools.github_client import GitHubClient
from pipeline.tools.pushover_client import PushoverClient
from pipeline.tools.r2_client import R2Client

mcp = FastMCP("sentinel-tools")

# --- Lazy-initialised clients (created on first use) ---

_d1: D1Client | None = None
_r2: R2Client | None = None
_gh: GitHubClient | None = None
_pushover: PushoverClient | None = None
_cedar: CedarSandbox | None = None


def _get_d1() -> D1Client:
    global _d1
    if _d1 is None:
        _d1 = D1Client(
            os.environ["CLOUDFLARE_ACCOUNT_ID"],
            os.environ["CLOUDFLARE_API_TOKEN"],
            os.environ.get("D1_DATABASE_ID", ""),
        )
    return _d1


def _get_r2() -> R2Client:
    global _r2
    if _r2 is None:
        _r2 = R2Client(
            os.environ["R2_ACCESS_KEY_ID"],
            os.environ["R2_SECRET_ACCESS_KEY"],
            os.environ["R2_ENDPOINT_URL"],
            os.environ.get("R2_BUCKET_NAME", "vectimus-research-archive"),
        )
    return _r2


def _get_gh() -> GitHubClient:
    global _gh
    if _gh is None:
        _gh = GitHubClient(os.environ["BOT_GITHUB_TOKEN"])
    return _gh


def _get_pushover() -> PushoverClient:
    global _pushover
    if _pushover is None:
        _pushover = PushoverClient(
            os.environ["PUSHOVER_USER_KEY"],
            os.environ["PUSHOVER_APP_TOKEN"],
        )
    return _pushover


def _get_cedar() -> CedarSandbox:
    global _cedar
    if _cedar is None:
        _cedar = CedarSandbox()
    return _cedar


# --- D1 tools ---


@mcp.tool()
def d1_query(sql: str) -> str:
    """Execute a read-only SQL query against the D1 incidents database."""
    rows = _get_d1().execute(sql)
    return json.dumps(rows, indent=2)


@mcp.tool()
def d1_write(sql: str, params: list | None = None) -> str:
    """Insert or update a record in the D1 incidents database."""
    _get_d1().execute(sql, params if params else None)
    return "OK"


# --- R2 tools ---


@mcp.tool()
def r2_get(key: str) -> str:
    """Read an object from R2 storage. Returns the content as a string (truncated to 10K chars)."""
    content = _get_r2().get(key)
    return content[:10000]


@mcp.tool()
def r2_put(key: str, content: str, content_type: str = "text/plain") -> str:
    """Upload an object to R2 storage."""
    _get_r2().put(key, content, content_type)
    return f"Archived to {key}"


# --- Cedar tools ---


@mcp.tool()
def cedar_authorize(
    policies_dir: str,
    entities: list[dict],
    request: dict,
) -> str:
    """Run cedar authorize against a policies directory with given entities and request.

    Args:
        policies_dir: Path to directory containing .cedar policy files
        entities: List of entity objects
        request: Dict with principal, action, resource (and optional context) keys
    """
    result = _get_cedar().authorize(policies_dir, entities, request)
    return f"Decision: {result.decision}\n{result.diagnostics}"


@mcp.tool()
def cedar_validate(policies_dir: str, schema_path: str | None = None) -> str:
    """Run cedar validate against the policies directory and schema.

    Args:
        policies_dir: Path to directory containing .cedar policy files
        schema_path: Path to Cedar schema file. If not provided, looks for schema.cedarschema or schema.json in policies_dir.
    """
    from pathlib import Path

    pd = Path(policies_dir)
    if schema_path is None:
        sp = pd / "schema.cedarschema"
        if not sp.exists():
            sp = pd / "schema.json"
        if not sp.exists():
            return "No schema file found"
    else:
        sp = Path(schema_path)

    result = _get_cedar().validate(pd, sp)
    if result.valid:
        return "Validation passed"
    return "Validation errors:\n" + "\n".join(result.errors)


# --- Pushover tools ---


@mcp.tool()
def pushover_alert(vtms_id: str, title: str, summary: str) -> str:
    """Send a high-priority Pushover alert for critical/high severity incidents (severity 4-5)."""
    _get_pushover().send_critical_alert(vtms_id, title, summary)
    return "Alert sent"


# --- GitHub tools ---


@mcp.tool()
def github_create_pr(
    repo_name: str,
    title: str,
    body: str,
    branch: str,
    labels: list[str] | None = None,
    reviewers: list[str] | None = None,
) -> str:
    """Create a pull request in a GitHub repo. Returns the PR URL.

    Args:
        repo_name: Full repo name (e.g. "vectimus/policies")
        title: PR title
        body: PR body markdown
        branch: Head branch name
        labels: Optional list of label names
        reviewers: Optional list of reviewer usernames
    """
    url = _get_gh().create_pr(
        repo_name=repo_name,
        title=title,
        body=body,
        head=branch,
        labels=labels,
        reviewers=reviewers or ["joe-vectimus"],
    )
    return f"PR created: {url}"


@mcp.tool()
def github_create_branch(
    repo_name: str,
    branch_name: str,
    from_branch: str = "main",
) -> str:
    """Create a new branch in a GitHub repo.

    Args:
        repo_name: Full repo name (e.g. "vectimus/vectimus-website")
        branch_name: New branch name
        from_branch: Source branch to branch from (default: main)
    """
    _get_gh().create_branch(repo_name, branch_name, from_branch)
    return f"Branch '{branch_name}' created from '{from_branch}'"


@mcp.tool()
def github_push_file(
    repo_name: str,
    branch: str,
    path: str,
    content: str,
    message: str,
) -> str:
    """Create or update a file on a branch in a GitHub repo.

    Args:
        repo_name: Full repo name
        branch: Target branch
        path: File path within the repo
        content: File content
        message: Commit message
    """
    _get_gh().push_file(repo_name, branch, path, content, message)
    return f"Pushed {path} to {branch}"


@mcp.tool()
def github_get_pr(repo_name: str, branch: str) -> str:
    """Find an open PR by head branch name. Returns PR details as JSON or a not-found message.

    Args:
        repo_name: Full repo name (e.g. "vectimus/policies")
        branch: Head branch name to search for
    """
    pr = _get_gh().get_pr_by_branch(repo_name, branch)
    if pr:
        return json.dumps(pr, indent=2)
    return "No PR found for that branch"


if __name__ == "__main__":
    mcp.run()
