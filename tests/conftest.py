"""Shared fixtures for Sentinel tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.config import Config


@pytest.fixture
def sample_finding() -> dict:
    """Return a valid Finding dict matching the schema exactly."""
    return {
        "vtms_id": "VTMS-2026-0001",
        "title": "Test Incident: Prompt Injection via Markdown",
        "discovered_at": "2026-03-14T12:00:00Z",
        "incident_date": "2026-03-13",
        "severity": 4,
        "owasp_category": "LLM01: Prompt Injection",
        "nist_ai_rmf": "GV-1",
        "cis_controls": ["CIS-3.1"],
        "cve_ids": ["CVE-2026-12345"],
        "coverage_status": "gap",
        "coverage_detail": "No existing policy covers markdown-based prompt injection",
        "existing_policy_ids": [],
        "gap_description": "Markdown rendering in LLM output can embed hidden instructions",
        "sources": [
            {
                "url": "https://example.com/vuln-report",
                "title": "Vulnerability Report",
                "r2_key": "sources/2026-03-14/report.html",
            }
        ],
        "tools_involved": ["ChatGPT", "Claude"],
        "summary": "Attackers can embed hidden prompt injection payloads in markdown.",
        "recommended_action": "new_policy",
        "recommended_policy_description": "Policy to sanitize markdown output from LLMs",
        "content_worthy": True,
        "content_angle": "new_policy_needed",
    }


@pytest.fixture
def sample_incident() -> dict:
    """Return a valid Incident dict matching the schema exactly."""
    return {
        "vtms_id": "VTMS-2026-0001",
        "title": "Test Incident: Prompt Injection via Markdown",
        "summary": "Attackers can embed hidden prompt injection payloads in markdown.",
        "discovered_at": "2026-03-14T12:00:00Z",
        "incident_date": "2026-03-13",
        "severity": 4,
        "owasp_category": "LLM01: Prompt Injection",
        "nist_ai_rmf": "GV-1",
        "cis_controls": '["CIS-3.1"]',
        "cve_ids": '["CVE-2026-12345"]',
        "coverage_status": "gap",
        "coverage_detail": "No existing policy covers markdown-based prompt injection",
        "existing_policy_ids": "[]",
        "gap_description": "Markdown rendering can embed hidden instructions",
        "tools_involved": '["ChatGPT", "Claude"]',
        "sources": '[{"url": "https://example.com", "title": "Report"}]',
        "policy_pr_url": None,
        "content_pr_url": None,
        "policy_status": "na",
        "content_status": "na",
        "recommended_action": "new_policy",
        "content_angle": "new_policy_needed",
        "created_at": "2026-03-14T12:00:00Z",
        "updated_at": "2026-03-14T12:00:00Z",
    }


@pytest.fixture
def sample_config() -> Config:
    """Return a Config with fake test values."""
    return Config(
        anthropic_api_key="test-key-anthropic",
        model="claude-sonnet-4-20250514",
        cloudflare_account_id="test-account-id",
        cloudflare_api_token="test-cf-token",
        d1_database_id="test-db-id",
        r2_access_key_id="test-r2-key",
        r2_secret_access_key="test-r2-secret",
        r2_endpoint_url="https://test.r2.cloudflarestorage.com",
        r2_bucket_name="test-bucket",
        pushover_user_key="test-pushover-user",
        pushover_app_token="test-pushover-token",
        bot_github_token="test-github-token",
    )


@pytest.fixture
def mock_d1_client() -> MagicMock:
    """Return a MagicMock of D1Client with execute() returning empty list."""
    mock = MagicMock()
    mock.execute.return_value = []
    return mock


@pytest.fixture
def mock_r2_client() -> MagicMock:
    """Return a MagicMock of R2Client."""
    mock = MagicMock()
    mock.get.return_value = ""
    mock.put.return_value = None
    mock.list_keys.return_value = []
    mock.exists.return_value = False
    return mock


@pytest.fixture
def mock_github_client() -> MagicMock:
    """Return a MagicMock of GitHubClient."""
    mock = MagicMock()
    mock.create_pr.return_value = "https://github.com/vectimus/policies/pull/1"
    mock.create_branch.return_value = None
    mock.push_file.return_value = None
    mock.get_pr_by_branch.return_value = None
    return mock


@pytest.fixture
def mock_pushover_client() -> MagicMock:
    """Return a MagicMock of PushoverClient."""
    mock = MagicMock()
    mock.send.return_value = None
    mock.send_critical_alert.return_value = None
    mock.send_digest.return_value = None
    return mock
