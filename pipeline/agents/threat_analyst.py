"""Threat Analyst agent — produces incident analysis content."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import anthropic

from pipeline.config import Config
from pipeline.tools.d1_client import D1Client
from pipeline.tools.github_client import GitHubClient
from pipeline.tools.r2_client import R2Client

logger = logging.getLogger(__name__)


def _load_system_prompt(spec_path: str) -> str:
    return Path(spec_path).read_text()


def _build_tools() -> list[dict]:
    """Define the tools available to the Threat Analyst."""
    return [
        {
            "name": "read_d1",
            "description": "Execute a read-only SQL query against the D1 incidents database.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string"},
                },
                "required": ["sql"],
            },
        },
        {
            "name": "write_d1",
            "description": "Insert or update a record in D1.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string"},
                    "params": {"type": "array", "items": {}},
                },
                "required": ["sql"],
            },
        },
        {
            "name": "read_r2",
            "description": "Read archived source material from R2.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                },
                "required": ["key"],
            },
        },
        {
            "name": "write_blog_post",
            "description": "Write a blog post markdown file.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Filename (e.g. VTMS-2026-0042-supply-chain-mcp.md)"},
                    "content": {"type": "string", "description": "Full markdown content"},
                },
                "required": ["filename", "content"],
            },
        },
        {
            "name": "write_brief",
            "description": "Write an incident brief markdown file.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "vtms_id": {"type": "string"},
                    "content": {"type": "string", "description": "Full markdown content"},
                },
                "required": ["vtms_id", "content"],
            },
        },
        {
            "name": "create_pr",
            "description": "Create a pull request in the website repo.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "branch": {"type": "string"},
                    "labels": {"type": "array", "items": {"type": "string"}},
                    "files": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"},
                            },
                        },
                        "description": "Files to push to the branch before creating the PR",
                    },
                },
                "required": ["title", "body", "branch"],
            },
        },
        {
            "name": "read_github_pr",
            "description": "Read a GitHub PR by URL or branch name from the policies repo.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "branch": {"type": "string", "description": "Branch name to search for"},
                },
                "required": ["branch"],
            },
        },
    ]


def _handle_tool_call(
    tool_name: str,
    tool_input: dict,
    *,
    d1: D1Client,
    r2: R2Client,
    gh: GitHubClient,
    config: Config,
) -> str:
    try:
        if tool_name == "read_d1":
            rows = d1.execute(tool_input["sql"])
            return json.dumps(rows, indent=2)

        elif tool_name == "write_d1":
            d1.execute(tool_input["sql"], tool_input.get("params"))
            return "OK"

        elif tool_name == "read_r2":
            content = r2.get(tool_input["key"])
            return content[:10000]

        elif tool_name == "write_blog_post":
            blog_path = Path("content/blog") / tool_input["filename"]
            blog_path.parent.mkdir(parents=True, exist_ok=True)
            blog_path.write_text(tool_input["content"])
            return f"Written: {blog_path}"

        elif tool_name == "write_brief":
            brief_path = Path("content/briefs") / f"{tool_input['vtms_id']}.md"
            brief_path.parent.mkdir(parents=True, exist_ok=True)
            brief_path.write_text(tool_input["content"])
            return f"Written: {brief_path}"

        elif tool_name == "create_pr":
            # Push files to branch first if provided
            files = tool_input.get("files", [])
            branch = tool_input["branch"]

            try:
                gh.create_branch(config.website_repo, branch)
            except Exception:
                pass  # Branch may already exist

            for file_info in files:
                gh.push_file(
                    repo_name=config.website_repo,
                    branch=branch,
                    path=file_info["path"],
                    content=file_info["content"],
                    message=f"Add {file_info['path']}",
                )

            url = gh.create_pr(
                repo_name=config.website_repo,
                title=tool_input["title"],
                body=tool_input["body"],
                head=branch,
                labels=tool_input.get("labels"),
                reviewers=["joe-vectimus"],
            )
            return f"PR created: {url}"

        elif tool_name == "read_github_pr":
            pr = gh.get_pr_by_branch(config.policies_repo, tool_input["branch"])
            if pr:
                return json.dumps(pr, indent=2)
            return "No PR found for that branch"

        else:
            return f"Unknown tool: {tool_name}"

    except Exception as e:
        logger.error("Tool %s failed: %s", tool_name, e)
        return f"Error: {e}"


async def run_threat_analyst(config: Config, findings_path: Path) -> dict:
    """Run the Threat Analyst on content-worthy findings.

    Returns a summary dict with PR URLs and stats.
    """
    findings = json.loads(findings_path.read_text())
    content_worthy = [f for f in findings if f.get("content_worthy")]

    if not content_worthy:
        logger.info("No content-worthy findings for Threat Analyst")
        return {"prs_created": 0, "pr_urls": []}

    system_prompt = _load_system_prompt(config.threat_analyst_spec)

    d1 = D1Client(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)
    r2 = R2Client(config.r2_access_key_id, config.r2_secret_access_key, config.r2_endpoint_url)
    gh = GitHubClient(config.bot_github_token)
    client = anthropic.Anthropic(api_key=config.anthropic_api_key)

    pr_urls = []

    try:
        user_message = (
            f"Process these content-worthy findings:\n\n"
            f"```json\n{json.dumps(content_worthy, indent=2)}\n```\n\n"
            f"Write blog posts and incident briefs. Open PRs in the website repo."
        )

        messages = [{"role": "user", "content": user_message}]
        tools = _build_tools()

        max_iterations = 40
        for _ in range(max_iterations):
            response = client.messages.create(
                model=config.model,
                max_tokens=8192,
                system=system_prompt,
                tools=tools,
                messages=messages,
            )

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                break

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        result = _handle_tool_call(
                            block.name,
                            block.input,
                            d1=d1,
                            r2=r2,
                            gh=gh,
                            config=config,
                        )
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })
                        if "PR created:" in result:
                            pr_urls.append(result.split("PR created: ")[1])

                messages.append({"role": "user", "content": tool_results})
            else:
                break

        return {"prs_created": len(pr_urls), "pr_urls": pr_urls}

    finally:
        d1.close()
        gh.close()
