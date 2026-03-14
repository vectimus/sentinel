"""Security Engineer agent — drafts Cedar policies with sandbox-verified test cases."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

import anthropic

from pipeline.config import Config
from pipeline.tools.cedar_sandbox import CedarSandbox
from pipeline.tools.d1_client import D1Client
from pipeline.tools.github_client import GitHubClient
from pipeline.tools.r2_client import R2Client

logger = logging.getLogger(__name__)


def _load_system_prompt(spec_path: str) -> str:
    return Path(spec_path).read_text()


def _build_tools() -> list[dict]:
    """Define the tools available to the Security Engineer."""
    return [
        {
            "name": "read_file",
            "description": "Read a file from the policies repo working directory.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path within the policies repo"},
                },
                "required": ["path"],
            },
        },
        {
            "name": "write_file",
            "description": "Write a file to the policies repo working directory.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path within the policies repo"},
                    "content": {"type": "string", "description": "File content"},
                },
                "required": ["path", "content"],
            },
        },
        {
            "name": "list_files",
            "description": "List files in a directory of the policies repo.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative directory path", "default": "."},
                },
                "required": [],
            },
        },
        {
            "name": "cedar_authorize",
            "description": "Run cedar authorize against the policies directory with given entities and request.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "entities": {"type": "array", "items": {"type": "object"}, "description": "Entity objects"},
                    "request": {"type": "object", "description": "Authorization request with principal, action, resource"},
                },
                "required": ["entities", "request"],
            },
        },
        {
            "name": "cedar_validate",
            "description": "Run cedar validate against the policies directory and schema.",
            "input_schema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
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
                    "key": {"type": "string", "description": "R2 object key"},
                },
                "required": ["key"],
            },
        },
        {
            "name": "create_pr",
            "description": "Create a pull request in the policies repo.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "branch": {"type": "string"},
                    "labels": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title", "body", "branch"],
            },
        },
        {
            "name": "git_command",
            "description": "Run a git command in the policies repo working directory.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Git command arguments (e.g. ['checkout', '-b', 'branch-name'])"},
                },
                "required": ["args"],
            },
        },
    ]


def _handle_tool_call(
    tool_name: str,
    tool_input: dict,
    *,
    policies_path: Path,
    cedar: CedarSandbox,
    d1: D1Client,
    r2: R2Client,
    gh: GitHubClient,
    config: Config,
) -> str:
    try:
        if tool_name == "read_file":
            file_path = policies_path / tool_input["path"]
            if not file_path.exists():
                return f"File not found: {tool_input['path']}"
            return file_path.read_text()

        elif tool_name == "write_file":
            file_path = policies_path / tool_input["path"]
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(tool_input["content"])
            return f"Written: {tool_input['path']}"

        elif tool_name == "list_files":
            dir_path = policies_path / tool_input.get("path", ".")
            if not dir_path.exists():
                return "Directory not found"
            entries = []
            for p in sorted(dir_path.rglob("*")):
                if p.is_file():
                    entries.append(str(p.relative_to(policies_path)))
            return "\n".join(entries[:200])

        elif tool_name == "cedar_authorize":
            result = cedar.authorize(
                policies_path,
                tool_input["entities"],
                tool_input["request"],
            )
            return f"Decision: {result.decision}\n{result.diagnostics}"

        elif tool_name == "cedar_validate":
            schema_path = policies_path / "schema.cedarschema"
            if not schema_path.exists():
                schema_path = policies_path / "schema.json"
            if not schema_path.exists():
                return "No schema file found"
            result = cedar.validate(policies_path, schema_path)
            if result.valid:
                return "Validation passed"
            return f"Validation errors:\n" + "\n".join(result.errors)

        elif tool_name == "read_d1":
            rows = d1.execute(tool_input["sql"])
            return json.dumps(rows, indent=2)

        elif tool_name == "write_d1":
            d1.execute(tool_input["sql"], tool_input.get("params"))
            return "OK"

        elif tool_name == "read_r2":
            content = r2.get(tool_input["key"])
            return content[:10000]

        elif tool_name == "create_pr":
            url = gh.create_pr(
                repo_name=config.policies_repo,
                title=tool_input["title"],
                body=tool_input["body"],
                head=tool_input["branch"],
                labels=tool_input.get("labels"),
                reviewers=["joe-vectimus"],
            )
            return f"PR created: {url}"

        elif tool_name == "git_command":
            # Only allow safe git commands
            allowed_commands = {"checkout", "branch", "add", "commit", "push", "status", "log", "diff"}
            if tool_input["args"] and tool_input["args"][0] not in allowed_commands:
                return f"Git command '{tool_input['args'][0]}' not allowed"

            result = subprocess.run(
                ["git"] + tool_input["args"],
                cwd=str(policies_path),
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout + result.stderr

        else:
            return f"Unknown tool: {tool_name}"

    except Exception as e:
        logger.error("Tool %s failed: %s", tool_name, e)
        return f"Error: {e}"


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

    d1 = D1Client(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)
    r2 = R2Client(config.r2_access_key_id, config.r2_secret_access_key, config.r2_endpoint_url)
    gh = GitHubClient(config.bot_github_token)
    cedar = CedarSandbox()
    client = anthropic.Anthropic(api_key=config.anthropic_api_key)

    pr_urls = []

    try:
        user_message = (
            f"Process these findings that require policy changes:\n\n"
            f"```json\n{json.dumps(actionable, indent=2)}\n```\n\n"
            f"The policies repo is available at the current working directory. "
            f"Read existing policies, draft new ones, run sandbox replay, and open PRs."
        )

        messages = [{"role": "user", "content": user_message}]
        tools = _build_tools()

        max_iterations = 50
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
                            policies_path=policies_path,
                            cedar=cedar,
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
