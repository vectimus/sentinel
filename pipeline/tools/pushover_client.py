"""Pushover notification client."""

from __future__ import annotations

import httpx


class PushoverClient:
    """Client for sending Pushover notifications."""

    API_URL = "https://api.pushover.net/1/messages.json"

    def __init__(self, user_key: str, app_token: str) -> None:
        self.user_key = user_key
        self.app_token = app_token
        self._client = httpx.Client(timeout=15.0)

    def send(
        self,
        message: str,
        title: str = "Vectimus Sentinel",
        priority: int = 0,
        url: str | None = None,
        url_title: str | None = None,
    ) -> None:
        """Send a Pushover notification.

        Priority levels:
            -2: no notification
            -1: quiet
             0: normal
             1: high priority (bypass quiet hours)
             2: emergency (requires acknowledgement)
        """
        payload = {
            "token": self.app_token,
            "user": self.user_key,
            "message": message,
            "title": title,
            "priority": priority,
            "html": 1,
        }
        if url:
            payload["url"] = url
            if url_title:
                payload["url_title"] = url_title

        # Emergency priority requires retry and expire params
        if priority == 2:
            payload["retry"] = 300
            payload["expire"] = 3600

        response = self._client.post(self.API_URL, data=payload)
        response.raise_for_status()

    def send_critical_alert(self, vtms_id: str, title: str, summary: str) -> None:
        """Send a high-priority alert for severity 4-5 incidents."""
        message = f"<b>{vtms_id}</b>\n{summary}"
        self.send(message=message, title=f"CRITICAL: {title}", priority=1)

    def send_digest(self, digest_text: str) -> None:
        """Send the daily pipeline digest."""
        self.send(message=digest_text, title="Vectimus Sentinel — Daily Digest", priority=0)

    def close(self) -> None:
        self._client.close()
