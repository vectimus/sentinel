"""Tests for PushoverClient with mocked httpx using respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from pipeline.tools.pushover_client import PushoverClient

API_URL = "https://api.pushover.net/1/messages.json"


@pytest.fixture
def pushover_client():
    """Create a PushoverClient instance."""
    return PushoverClient(user_key="test-user-key", app_token="test-app-token")


class TestSend:

    @respx.mock
    def test_posts_correct_payload(self, pushover_client):
        route = respx.post(API_URL).mock(
            return_value=httpx.Response(200, json={"status": 1})
        )

        pushover_client.send(message="Test message", title="Test Title", priority=0)

        assert route.called
        request = respx.calls.last.request
        body = request.content.decode("utf-8")
        assert "token=test-app-token" in body
        assert "user=test-user-key" in body
        assert "message=Test+message" in body or "message=Test%20message" in body

    @respx.mock
    def test_priority_2_adds_retry_and_expire(self, pushover_client):
        respx.post(API_URL).mock(
            return_value=httpx.Response(200, json={"status": 1})
        )

        pushover_client.send(message="Emergency!", priority=2)

        request = respx.calls.last.request
        body = request.content.decode("utf-8")
        assert "retry=300" in body
        assert "expire=3600" in body

    @respx.mock
    def test_priority_0_does_not_add_retry(self, pushover_client):
        respx.post(API_URL).mock(
            return_value=httpx.Response(200, json={"status": 1})
        )

        pushover_client.send(message="Normal", priority=0)

        request = respx.calls.last.request
        body = request.content.decode("utf-8")
        assert "retry" not in body
        assert "expire" not in body

    @respx.mock
    def test_includes_url_when_provided(self, pushover_client):
        respx.post(API_URL).mock(
            return_value=httpx.Response(200, json={"status": 1})
        )

        pushover_client.send(
            message="Check this",
            url="https://example.com/report",
            url_title="View Report",
        )

        request = respx.calls.last.request
        body = request.content.decode("utf-8")
        assert "url=" in body
        assert "url_title=" in body


class TestSendCriticalAlert:

    @respx.mock
    def test_sets_priority_1(self, pushover_client):
        respx.post(API_URL).mock(
            return_value=httpx.Response(200, json={"status": 1})
        )

        pushover_client.send_critical_alert(
            vtms_id="VTMS-2026-0001",
            title="Prompt Injection",
            summary="Critical vulnerability found",
        )

        request = respx.calls.last.request
        body = request.content.decode("utf-8")
        assert "priority=1" in body
        assert "VTMS-2026-0001" in body


class TestSendDigest:

    @respx.mock
    def test_sets_priority_0(self, pushover_client):
        respx.post(API_URL).mock(
            return_value=httpx.Response(200, json={"status": 1})
        )

        pushover_client.send_digest("Daily digest: 3 incidents processed")

        request = respx.calls.last.request
        body = request.content.decode("utf-8")
        assert "priority=0" in body
        assert "Daily+Digest" in body or "Daily%20Digest" in body or "Sentinel" in body
