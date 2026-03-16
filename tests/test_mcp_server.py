"""Tests for MCP server tool functions by mocking the lazy-initialized clients."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from pipeline import mcp_server


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset module-level client singletons before each test."""
    mcp_server._d1 = None
    mcp_server._r2 = None
    mcp_server._gh = None
    mcp_server._pushover = None
    mcp_server._cedar = None
    yield
    mcp_server._d1 = None
    mcp_server._r2 = None
    mcp_server._gh = None
    mcp_server._pushover = None
    mcp_server._cedar = None


@pytest.fixture
def mock_d1():
    mock = MagicMock()
    with patch.object(mcp_server, "_get_d1", return_value=mock):
        yield mock


@pytest.fixture
def mock_r2():
    mock = MagicMock()
    with patch.object(mcp_server, "_get_r2", return_value=mock):
        yield mock


@pytest.fixture
def mock_gh():
    mock = MagicMock()
    with patch.object(mcp_server, "_get_gh", return_value=mock):
        yield mock


@pytest.fixture
def mock_pushover():
    mock = MagicMock()
    with patch.object(mcp_server, "_get_pushover", return_value=mock):
        yield mock


@pytest.fixture
def mock_cedar():
    mock = MagicMock()
    with patch.object(mcp_server, "_get_cedar", return_value=mock):
        yield mock


class TestD1Query:

    def test_returns_json_string(self, mock_d1):
        rows = [{"vtms_id": "VTMS-2026-0001", "title": "Test"}]
        mock_d1.execute.return_value = rows

        result = mcp_server.d1_query("SELECT * FROM incidents")

        assert json.loads(result) == rows
        mock_d1.execute.assert_called_once_with("SELECT * FROM incidents")


class TestD1Write:

    def test_returns_ok(self, mock_d1):
        mock_d1.execute.return_value = []

        result = mcp_server.d1_write("INSERT INTO incidents VALUES (?)", ["test"])

        assert result == "OK"
        mock_d1.execute.assert_called_once_with("INSERT INTO incidents VALUES (?)", ["test"])

    def test_passes_none_when_no_params(self, mock_d1):
        mock_d1.execute.return_value = []

        mcp_server.d1_write("INSERT INTO incidents (vtms_id) VALUES ('test')")

        mock_d1.execute.assert_called_once_with("INSERT INTO incidents (vtms_id) VALUES ('test')", None)


class TestR2Get:

    def test_truncates_to_10k_chars(self, mock_r2):
        long_content = "x" * 20000
        mock_r2.get.return_value = long_content

        result = mcp_server.r2_get("reports/long.txt")

        assert len(result) == 10000
        mock_r2.get.assert_called_once_with("reports/long.txt")

    def test_returns_full_content_when_under_limit(self, mock_r2):
        mock_r2.get.return_value = "short content"

        result = mcp_server.r2_get("reports/short.txt")

        assert result == "short content"


class TestR2Put:

    def test_calls_client_put(self, mock_r2):
        result = mcp_server.r2_put("sources/test.txt", "content here", "text/plain")

        mock_r2.put.assert_called_once_with("sources/test.txt", "content here", "text/plain")
        assert "sources/test.txt" in result


class TestPushoverAlert:

    def test_calls_send_critical_alert(self, mock_pushover):
        result = mcp_server.pushover_alert(
            vtms_id="VTMS-2026-0001",
            title="Critical Vuln",
            summary="Bad things happened",
        )

        mock_pushover.send_critical_alert.assert_called_once_with(
            "VTMS-2026-0001", "Critical Vuln", "Bad things happened"
        )
        assert result == "Alert sent"


class TestGitHubCreatePr:

    def test_returns_pr_url_string(self, mock_gh):
        mock_gh.create_pr.return_value = "https://github.com/vectimus/policies/pull/42"

        result = mcp_server.github_create_pr(
            repo_name="vectimus/policies",
            title="Add policy",
            body="New policy",
            branch="vtms-2026-0001/policy",
        )

        assert "https://github.com/vectimus/policies/pull/42" in result
        mock_gh.create_pr.assert_called_once()


class TestGitHubCreateBranch:

    def test_returns_success_message(self, mock_gh):
        result = mcp_server.github_create_branch(
            repo_name="vectimus/policies",
            branch_name="vtms-2026-0001/policy",
            from_branch="main",
        )

        mock_gh.create_branch.assert_called_once_with(
            "vectimus/policies", "vtms-2026-0001/policy", "main"
        )
        assert "vtms-2026-0001/policy" in result
        assert "created" in result.lower()


class TestGitHubPushFile:

    def test_returns_success_message(self, mock_gh):
        result = mcp_server.github_push_file(
            repo_name="vectimus/policies",
            branch="sentinel/vtms-2026-0001-policy",
            path="policies/test.cedar",
            content="permit(...);",
            message="Add test policy",
        )

        mock_gh.push_file.assert_called_once_with(
            "vectimus/policies",
            "sentinel/vtms-2026-0001-policy",
            "policies/test.cedar",
            "permit(...);",
            "Add test policy",
        )
        assert "policies/test.cedar" in result


class TestGitHubGetPr:

    def test_returns_json_when_found(self, mock_gh):
        mock_gh.get_pr_by_branch.return_value = {
            "url": "https://github.com/vectimus/policies/pull/42",
            "title": "Add policy",
            "body": "PR body",
            "number": 42,
        }

        result = mcp_server.github_get_pr("vectimus/policies", "vtms-2026-0001/policy")

        parsed = json.loads(result)
        assert parsed["number"] == 42
        assert parsed["url"] == "https://github.com/vectimus/policies/pull/42"

    def test_returns_message_when_not_found(self, mock_gh):
        mock_gh.get_pr_by_branch.return_value = None

        result = mcp_server.github_get_pr("vectimus/policies", "nonexistent-branch")

        assert "No PR found" in result
