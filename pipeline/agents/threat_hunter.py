"""Threat Hunter agent — discovers and classifies agentic AI security incidents."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import anthropic

from pipeline.config import Config
from pipeline.tools.d1_client import D1Client
from pipeline.tools.pushover_client import PushoverClient
from pipeline.tools.r2_client import R2Client

logger = logging.getLogger(__name__)


def _load_system_prompt(spec_path: str) -> str:
    """Load agent system prompt from AGENTS.md."""
    return Path(spec_path).read_text()


def _build_tools() -> list[dict]:
    """Define the tools available to the Threat Hunter."""
    return [
        {
            "name": "search_web",
            "description": "Search the web for agentic AI security incidents, vulnerabilities and threat intelligence.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
        {
            "name": "fetch_url",
            "description": "Fetch the full text content of a URL.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                },
                "required": ["url"],
            },
        },
        {
            "name": "read_d1",
            "description": "Execute a read-only SQL query against the D1 incidents database.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SELECT SQL query"},
                },
                "required": ["sql"],
            },
        },
        {
            "name": "write_d1",
            "description": "Insert or update a record in the D1 incidents database.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "INSERT/UPDATE SQL"},
                    "params": {
                        "type": "array",
                        "items": {},
                        "description": "Query parameters",
                    },
                },
                "required": ["sql"],
            },
        },
        {
            "name": "archive_to_r2",
            "description": "Archive source material to R2 storage.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "R2 object key (e.g. sources/VTMS-2026-0042/article-001.txt)"},
                    "content": {"type": "string", "description": "Content to archive"},
                },
                "required": ["key", "content"],
            },
        },
        {
            "name": "send_alert",
            "description": "Send a Pushover alert for critical/high severity incidents.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "vtms_id": {"type": "string"},
                    "title": {"type": "string"},
                    "summary": {"type": "string"},
                },
                "required": ["vtms_id", "title", "summary"],
            },
        },
        {
            "name": "write_findings",
            "description": "Write the findings JSON array to the findings output file.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Array of finding objects matching the output contract",
                    },
                },
                "required": ["findings"],
            },
        },
    ]


def _handle_tool_call(
    tool_name: str,
    tool_input: dict,
    *,
    d1: D1Client,
    r2: R2Client,
    pushover: PushoverClient,
    anthropic_client: anthropic.Anthropic,
    findings_path: Path,
) -> str:
    """Execute a tool call and return the result as a string."""
    try:
        if tool_name == "search_web":
            # Use Anthropic's web search via a separate messages call
            response = anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                tools=[{"type": "web_search_20250305", "name": "web_search", "max_uses": 3}],
                messages=[{"role": "user", "content": f"Search for: {tool_input['query']}. Return the key findings as a summary with URLs."}],
            )
            result_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    result_text += block.text
            return result_text or "No results found."

        elif tool_name == "fetch_url":
            import httpx
            resp = httpx.get(tool_input["url"], follow_redirects=True, timeout=20.0)
            resp.raise_for_status()
            # Simple HTML to text extraction
            text = resp.text
            # Strip HTML tags roughly
            import re
            text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
            text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            return text[:10000]  # Limit to 10K chars

        elif tool_name == "read_d1":
            rows = d1.execute(tool_input["sql"])
            return json.dumps(rows, indent=2)

        elif tool_name == "write_d1":
            params = tool_input.get("params", [])
            d1.execute(tool_input["sql"], params if params else None)
            return "OK"

        elif tool_name == "archive_to_r2":
            r2.put(tool_input["key"], tool_input["content"])
            return f"Archived to {tool_input['key']}"

        elif tool_name == "send_alert":
            pushover.send_critical_alert(
                tool_input["vtms_id"],
                tool_input["title"],
                tool_input["summary"],
            )
            return "Alert sent"

        elif tool_name == "write_findings":
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text(json.dumps(tool_input["findings"], indent=2))
            return f"Wrote {len(tool_input['findings'])} findings to {findings_path}"

        else:
            return f"Unknown tool: {tool_name}"

    except Exception as e:
        logger.error("Tool %s failed: %s", tool_name, e)
        return f"Error: {e}"


async def run_threat_hunter(config: Config, date: str) -> Path:
    """Run the Threat Hunter agent for a given date.

    Returns the path to the findings JSON file.
    """
    now = datetime.now(timezone.utc)
    year = now.year
    findings_path = Path(f"findings/{date}.json")

    system_prompt = _load_system_prompt(config.threat_hunter_spec)

    d1 = D1Client(config.cloudflare_account_id, config.cloudflare_api_token, config.d1_database_id)
    r2 = R2Client(config.r2_access_key_id, config.r2_secret_access_key, config.r2_endpoint_url)
    pushover = PushoverClient(config.pushover_user_key, config.pushover_app_token)
    client = anthropic.Anthropic(api_key=config.anthropic_api_key)

    try:
        # Get current state
        last_id = d1.get_max_vtms_sequence(year)
        incidents = d1.list_incidents(limit=1)
        total_incidents = len(d1.execute("SELECT COUNT(*) as cnt FROM incidents"))

        user_message = (
            f"Execute your daily research cycle for {date}.  "
            f"Current VTMS sequence: VTMS-{year}-{last_id:04d}.  "
            f"{total_incidents} existing incidents in database."
        )

        messages = [{"role": "user", "content": user_message}]
        tools = _build_tools()

        # Agentic loop
        max_iterations = 30
        for _ in range(max_iterations):
            response = client.messages.create(
                model=config.model,
                max_tokens=8192,
                system=system_prompt,
                tools=tools,
                messages=messages,
            )

            # Collect response
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
                            pushover=pushover,
                            anthropic_client=client,
                            findings_path=findings_path,
                        )
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })

                messages.append({"role": "user", "content": tool_results})
            else:
                break

        if not findings_path.exists():
            logger.warning("Threat Hunter did not write findings file; creating empty one")
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text("[]")

        return findings_path

    finally:
        d1.close()
        pushover.close()
