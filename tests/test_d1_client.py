"""Tests for D1Client with mocked httpx using respx."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from pipeline.tools.d1_client import D1Client

ACCOUNT_ID = "test-account-id"
API_TOKEN = "test-api-token"
DATABASE_ID = "test-db-id"
D1_URL = (
    f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/d1/database/{DATABASE_ID}/query"
)


@pytest.fixture
def d1_client():
    """Create a D1Client instance."""
    return D1Client(ACCOUNT_ID, API_TOKEN, DATABASE_ID)


class TestExecute:
    @respx.mock
    def test_successful_query_returns_rows(self, d1_client):
        rows = [{"vtms_id": "VTMS-2026-0001", "title": "Test"}]
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": True,
                    "result": [{"results": rows}],
                },
            )
        )

        result = d1_client.execute("SELECT * FROM incidents")
        assert result == rows

    @respx.mock
    def test_error_response_raises_runtime_error(self, d1_client):
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": False,
                    "errors": [{"message": "syntax error"}],
                },
            )
        )

        with pytest.raises(RuntimeError, match="D1 query failed"):
            d1_client.execute("INVALID SQL")

    @respx.mock
    def test_empty_result_returns_empty_list(self, d1_client):
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": True,
                    "result": [],
                },
            )
        )

        result = d1_client.execute("SELECT * FROM incidents WHERE 1=0")
        assert result == []


class TestGetMaxVtmsSequence:
    @respx.mock
    def test_no_rows_returns_zero(self, d1_client):
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "result": [{"results": []}]},
            )
        )

        result = d1_client.get_max_vtms_sequence(2026)
        assert result == 0

    @respx.mock
    def test_existing_rows_returns_correct_sequence(self, d1_client):
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": True,
                    "result": [{"results": [{"vtms_id": "VTMS-2026-0042"}]}],
                },
            )
        )

        result = d1_client.get_max_vtms_sequence(2026)
        assert result == 42


class TestInsertIncident:
    @respx.mock
    def test_builds_correct_sql(self, d1_client):
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "result": []},
            )
        )

        incident = {
            "vtms_id": "VTMS-2026-0001",
            "title": "Test",
            "severity": 3,
            "sources": [{"url": "https://example.com"}],
        }
        d1_client.insert_incident(incident)

        request = respx.calls.last.request
        body = json.loads(request.content)
        assert "INSERT OR REPLACE INTO incidents" in body["sql"]
        assert "vtms_id" in body["sql"]
        assert len(body["params"]) == 4
        # sources (a list) should be JSON-serialized
        assert body["params"][3] == json.dumps([{"url": "https://example.com"}])


class TestUpdateIncidentField:
    @respx.mock
    def test_rejects_disallowed_field(self, d1_client):
        with pytest.raises(ValueError, match="not in allowed update fields"):
            d1_client.update_incident_field("VTMS-2026-0001", "severity", 5)

    @respx.mock
    def test_accepts_allowed_field(self, d1_client):
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "result": []},
            )
        )

        d1_client.update_incident_field(
            "VTMS-2026-0001", "policy_pr_url", "https://github.com/pr/1"
        )

        request = respx.calls.last.request
        body = json.loads(request.content)
        assert "UPDATE incidents SET policy_pr_url" in body["sql"]

    @respx.mock
    def test_accepts_coverage_status_field(self, d1_client):
        respx.post(D1_URL).mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "result": []},
            )
        )

        d1_client.update_incident_field("VTMS-2026-0001", "coverage_status", "covered")

        request = respx.calls.last.request
        body = json.loads(request.content)
        assert "UPDATE incidents SET coverage_status" in body["sql"]
