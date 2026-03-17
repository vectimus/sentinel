"""HITL review issue management for the Sentinel pipeline.

Creates a GitHub Issue with per-finding checkboxes after the discover
stage, then reads the issue after gate approval to filter findings
down to only those the reviewer approved.

Usage (called from GitHub Actions):
    python pipeline/hitl_issue.py create   # after discover
    python pipeline/hitl_issue.py filter   # after review-gate approval
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_MAP = {1: "THEORETICAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
REPO = os.environ.get("GITHUB_REPOSITORY", "vectimus/sentinel")


def _gh(*args: str) -> str:
    """Run a gh CLI command and return stdout."""
    result = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _find_findings_file() -> Path:
    """Locate today's findings JSON file."""
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = Path(f"findings/{date}.json")
    if path.exists():
        return path
    # Fallback: find the most recent file in findings/
    findings_dir = Path("findings")
    if findings_dir.exists():
        files = sorted(findings_dir.glob("*.json"), reverse=True)
        if files:
            return files[0]
    raise FileNotFoundError("No findings file found")


def _build_issue_body(findings: list[dict]) -> str:
    """Build the issue body with a checkbox per finding.

    All checkboxes default to checked. Uncheck to skip a finding.
    """
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_url = (
        f"https://github.com/{REPO}/actions/runs/"
        f"{os.environ.get('GITHUB_RUN_ID', '?')}"
    )

    lines = [
        f"## Sentinel Review — {date}",
        "",
        f"[Pipeline run]({run_url})",
        "",
        "**Uncheck any findings you want to skip.** "
        "Checked findings will be sent to the Security Engineer and Threat Analyst.",
        "",
    ]

    for f in findings:
        vtms_id = f["vtms_id"]
        sev = SEVERITY_MAP.get(f.get("severity", 0), "?")
        scope = f.get("enforcement_scope", "?")
        action = f.get("recommended_action", "?")
        title = f["title"][:100]

        lines.append(f"- [x] **{vtms_id}** ({sev} | {scope} | {action})")
        lines.append(f"  {title}")
        lines.append("")

    # Summary stats
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

    lines.extend([
        "---",
        "",
        f"**Actionable (policy work):** {len(actionable)}  ",
        f"**Content-worthy (advisories):** {len(content_worthy)}  ",
        f"**Gaps:** {len(gaps)}  ",
    ])

    return "\n".join(lines)


def create() -> None:
    """Create a review issue and output the issue number for the workflow."""
    findings_path = _find_findings_file()
    findings = json.loads(findings_path.read_text())

    if not findings:
        print("No findings to review, skipping issue creation")
        _set_output("issue_number", "")
        return

    body = _build_issue_body(findings)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    issue_number = _gh(
        "issue", "create",
        "--repo", REPO,
        "--title", f"Sentinel Review — {date}",
        "--label", "sentinel-review",
        "--body", body,
    )
    # gh issue create returns the URL, extract the number
    number = issue_number.rstrip("/").split("/")[-1]
    print(f"Created review issue #{number}: {issue_number}")

    _set_output("issue_number", number)

    # Also add the issue link to the job summary
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(f"\n**Review issue:** {issue_number}\n")


def filter() -> None:
    """Read the review issue, parse checkboxes, write approved findings."""
    issue_number = os.environ.get("REVIEW_ISSUE", "")
    if not issue_number:
        print("No review issue number, passing all findings through")
        _copy_all_findings()
        return

    # Fetch issue body
    body = _gh(
        "issue", "view", issue_number,
        "--repo", REPO,
        "--json", "body",
        "--jq", ".body",
    )

    # Parse checked VTMS IDs from checkboxes
    # Matches: - [x] **VTMS-2026-0016** (...)
    checked_pattern = re.compile(r"- \[x\] \*\*([A-Z]+-\d{4}-\d{4,})\*\*")
    unchecked_pattern = re.compile(r"- \[ \] \*\*([A-Z]+-\d{4}-\d{4,})\*\*")

    approved_ids = set(checked_pattern.findall(body))
    skipped_ids = set(unchecked_pattern.findall(body))

    print(f"Approved: {sorted(approved_ids)}")
    if skipped_ids:
        print(f"Skipped:  {sorted(skipped_ids)}")

    # Load raw findings and filter
    findings_path = _find_findings_file()
    findings = json.loads(findings_path.read_text())

    approved = [f for f in findings if f["vtms_id"] in approved_ids]
    print(f"Filtered {len(findings)} findings down to {len(approved)} approved")

    # Write approved findings
    out_dir = Path("approved-findings")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / findings_path.name
    out_path.write_text(json.dumps(approved, indent=2))
    print(f"Wrote approved findings to {out_path}")

    # Close the issue
    try:
        _gh(
            "issue", "close", issue_number,
            "--repo", REPO,
            "--comment", f"Approved {len(approved)}/{len(findings)} findings. Pipeline proceeding.",
        )
    except Exception as e:
        print(f"Warning: could not close issue: {e}")


def _copy_all_findings() -> None:
    """Fallback: copy all findings to approved-findings/ unfiltered."""
    findings_path = _find_findings_file()
    out_dir = Path("approved-findings")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / findings_path.name
    out_path.write_text(findings_path.read_text())
    print(f"Copied all findings to {out_path} (no issue to filter against)")


def _set_output(name: str, value: str) -> None:
    """Set a GitHub Actions output variable."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pipeline/hitl_issue.py <create|filter>")
        sys.exit(1)

    command = sys.argv[1]
    if command == "create":
        create()
    elif command == "filter":
        filter()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
