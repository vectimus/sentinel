"""Tests for pipeline.validation — Guardrails AI output validators."""

import json

import pytest

from pipeline.validation import (
    AI_BUZZWORDS,
    REQUIRED_BLOG_SECTIONS,
    REQUIRED_FRONTMATTER_FIELDS,
    ValidBlogPost,
    ValidCedarPolicy,
    ValidFindingJson,
    validate_blog_post,
    validate_cedar_policy,
    validate_findings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> dict:
    """Return a minimal valid finding dict, with optional overrides."""
    base = {
        "vtms_id": "VTMS-2026-0042",
        "title": "Test incident",
        "discovered_at": "2026-03-14T08:00:00Z",
        "severity": 4,
        "owasp_category": "ASI02: Tool Misuse",
        "coverage_status": "covered",
        "coverage_detail": "Covered by MCP-001",
        "existing_policy_ids": ["MCP-001"],
        "summary": "A test incident summary.",
        "recommended_action": "no_change",
    }
    base.update(overrides)
    return base


def _make_blog_post(**overrides) -> str:
    """Return a minimal valid blog post markdown."""
    frontmatter_fields = {
        "vtms_id": "VTMS-2026-0042",
        "title": '"Test post"',
        "date": "2026-03-14",
        "author": "Vectimus Research",
        "category": "incident-analysis",
        "owasp_category": '"ASI02: Tool Misuse"',
        "severity": "4",
        "tags": "[mcp, test]",
    }
    frontmatter_fields.update(overrides.get("frontmatter", {}))

    fm_lines = "\n".join(f"{k}: {v}" for k, v in frontmatter_fields.items())

    body = overrides.get(
        "body",
        (
            "## What happened\n\nSomething happened.\n\n"
            "## Why it matters\n\nIt matters.\n\n"
            "## Root cause\n\nRoot cause here.\n\n"
            "## How Vectimus responds\n\nVectimus responds.\n\n"
            "## What you can do\n\nDo this.\n"
        ),
    )

    return f"---\n{fm_lines}\n---\n\n{body}"


VALID_CEDAR_POLICY = """\
// VTMS-2026-0042 | OWASP: ASI02 | SOC 2: CC6.1 | NIST: GV-1
// Blocks agent-initiated npm publish commands
forbid (
  principal,
  action == Action::"shell_command",
  resource
)
when {
  resource.command like "*npm publish*"
};
"""


# ---------------------------------------------------------------------------
# ValidFindingJson
# ---------------------------------------------------------------------------


class TestValidFindingJson:
    def test_valid_findings_array(self):
        data = json.dumps([_make_finding()])
        result = ValidFindingJson().validate(data)
        assert hasattr(result, "error_message") is False or result.error_message is None

    def test_empty_array_is_valid(self):
        result = ValidFindingJson().validate("[]")
        assert hasattr(result, "error_message") is False or result.error_message is None

    def test_invalid_json_fails(self):
        result = ValidFindingJson().validate("{not valid json")
        assert result.error_message is not None
        assert "Invalid JSON" in result.error_message

    def test_not_array_fails(self):
        result = ValidFindingJson().validate('{"key": "value"}')
        assert result.error_message is not None
        assert "JSON array" in result.error_message

    def test_invalid_finding_schema_fails(self):
        bad = _make_finding(vtms_id="BAD-ID")
        result = ValidFindingJson().validate(json.dumps([bad]))
        assert result.error_message is not None
        assert "Schema validation failed" in result.error_message

    def test_invalid_severity_fails(self):
        bad = _make_finding(severity=99)
        result = ValidFindingJson().validate(json.dumps([bad]))
        assert result.error_message is not None


# ---------------------------------------------------------------------------
# ValidCedarPolicy
# ---------------------------------------------------------------------------


class TestValidCedarPolicy:
    def test_valid_policy_passes(self):
        result = ValidCedarPolicy().validate(VALID_CEDAR_POLICY)
        assert hasattr(result, "error_message") is False or result.error_message is None

    def test_missing_vtms_id_fails(self):
        policy = VALID_CEDAR_POLICY.replace("VTMS-2026-0042", "some-id")
        result = ValidCedarPolicy().validate(policy)
        assert result.error_message is not None
        assert "VTMS incident ID" in result.error_message

    def test_missing_owasp_fails(self):
        policy = VALID_CEDAR_POLICY.replace("OWASP: ASI02", "Category: 9")
        result = ValidCedarPolicy().validate(policy)
        assert result.error_message is not None
        assert "OWASP" in result.error_message

    def test_missing_policy_statement_fails(self):
        policy = "// VTMS-2026-0042 | OWASP: ASI02\n// Just a comment, no policy\n"
        result = ValidCedarPolicy().validate(policy)
        assert result.error_message is not None
        assert "forbid or permit" in result.error_message

    def test_empty_string_fails(self):
        result = ValidCedarPolicy().validate("")
        assert result.error_message is not None
        assert "empty" in result.error_message


# ---------------------------------------------------------------------------
# ValidBlogPost
# ---------------------------------------------------------------------------


class TestValidBlogPost:
    def test_valid_post_passes(self):
        post = _make_blog_post()
        result = ValidBlogPost().validate(post)
        assert hasattr(result, "error_message") is False or result.error_message is None

    def test_missing_frontmatter_fails(self):
        result = ValidBlogPost().validate("## What happened\n\nNo frontmatter here.")
        assert result.error_message is not None
        assert "frontmatter" in result.error_message.lower()

    def test_missing_section_fails(self):
        post = _make_blog_post(body="## What happened\n\nOnly one section.\n")
        result = ValidBlogPost().validate(post)
        assert result.error_message is not None
        assert "Why it matters" in result.error_message

    def test_em_dash_fails(self):
        body = (
            "## What happened\n\nSomething happened \u2014 badly.\n\n"
            "## Why it matters\n\nIt matters.\n\n"
            "## Root cause\n\nRoot cause.\n\n"
            "## How Vectimus responds\n\nVectimus responds.\n\n"
            "## What you can do\n\nDo this.\n"
        )
        post = _make_blog_post(body=body)
        result = ValidBlogPost().validate(post)
        assert result.error_message is not None
        assert "em dash" in result.error_message.lower()

    def test_ai_buzzword_fails(self):
        body = (
            "## What happened\n\nThis revolutionary attack occurred.\n\n"
            "## Why it matters\n\nIt matters.\n\n"
            "## Root cause\n\nRoot cause.\n\n"
            "## How Vectimus responds\n\nVectimus responds.\n\n"
            "## What you can do\n\nDo this.\n"
        )
        post = _make_blog_post(body=body)
        result = ValidBlogPost().validate(post)
        assert result.error_message is not None
        assert "buzzword" in result.error_message.lower()

    def test_missing_frontmatter_field_fails(self):
        post = _make_blog_post(frontmatter={"author": None})
        # Remove the author line entirely
        post = post.replace("author: None\n", "")
        result = ValidBlogPost().validate(post)
        assert result.error_message is not None
        assert "author" in result.error_message

    def test_empty_string_fails(self):
        result = ValidBlogPost().validate("")
        assert result.error_message is not None
        assert "empty" in result.error_message.lower()


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


class TestValidateFindings:
    def test_valid_findings_returns_list(self):
        data = json.dumps([_make_finding()])
        result = validate_findings(data)
        assert len(result) == 1
        assert result[0]["vtms_id"] == "VTMS-2026-0042"

    def test_empty_array_returns_empty(self):
        result = validate_findings("[]")
        assert result == []

    def test_invalid_json_raises(self):
        with pytest.raises(Exception):
            validate_findings("not json")

    def test_partially_valid_preserves_all(self):
        good = _make_finding()
        bad = _make_finding(vtms_id="BAD")
        # validate_findings should still return both (bad one as raw dict)
        # but it will raise because the guard uses EXCEPTION on_fail
        with pytest.raises(Exception):
            validate_findings(json.dumps([good, bad]))


class TestValidateCedarPolicy:
    def test_valid_policy_returns_text(self):
        result = validate_cedar_policy(VALID_CEDAR_POLICY)
        assert result == VALID_CEDAR_POLICY

    def test_invalid_policy_raises(self):
        with pytest.raises(Exception):
            validate_cedar_policy("// no policy here")


class TestValidateBlogPost:
    def test_valid_post_returns_markdown(self):
        post = _make_blog_post()
        result = validate_blog_post(post)
        assert result == post

    def test_invalid_post_raises(self):
        with pytest.raises(Exception):
            validate_blog_post("no frontmatter, no sections")
