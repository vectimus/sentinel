"""Cloudflare D1 REST API client.

Uses the Cloudflare API (not Workers bindings) since the pipeline runs in
GitHub Actions, not inside a Worker.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class D1Client:
    """Client for Cloudflare D1 database operations."""

    BASE_URL = "https://api.cloudflare.com/client/v4"

    # Allowed column names for each table — prevents SQL injection via dict keys
    _INCIDENT_COLUMNS = frozenset(
        {
            "vtms_id",
            "title",
            "summary",
            "discovered_at",
            "incident_date",
            "severity",
            "owasp_category",
            "nist_ai_rmf",
            "cis_controls",
            "cve_ids",
            "coverage_status",
            "coverage_detail",
            "existing_policy_ids",
            "gap_description",
            "tools_involved",
            "sources",
            "policy_pr_url",
            "content_pr_url",
            "policy_status",
            "content_status",
            "recommended_action",
            "content_angle",
            "replay_request",
            "enforcement_scope",
            "created_at",
            "updated_at",
        }
    )

    _TREND_COLUMNS = frozenset(
        {
            "date",
            "total_incidents",
            "incidents_30d",
            "incidents_by_category",
            "incidents_by_severity",
            "coverage_rate",
            "gap_rate",
            "policies_total",
            "rules_total",
        }
    )

    _CONTENT_COLUMNS = frozenset(
        {
            "id",
            "vtms_id",
            "content_type",
            "title",
            "slug",
            "status",
            "pr_url",
            "published_url",
            "created_at",
            "updated_at",
        }
    )

    def __init__(self, account_id: str, api_token: str, database_id: str) -> None:
        self.account_id = account_id
        self.database_id = database_id
        self._client = httpx.Client(
            base_url=self.BASE_URL,
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    @property
    def _db_url(self) -> str:
        return f"/accounts/{self.account_id}/d1/database/{self.database_id}/query"

    def execute(self, sql: str, params: list[Any] | None = None) -> list[dict]:
        """Execute a SQL statement and return result rows."""
        payload: dict[str, Any] = {"sql": sql}
        if params:
            payload["params"] = params

        response = self._client.post(self._db_url, json=payload)
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise RuntimeError(f"D1 query failed: {errors}")

        results = data.get("result", [])
        if results and "results" in results[0]:
            return results[0]["results"]
        return []

    def insert_incident(self, incident: dict) -> None:
        """Insert or replace an incident record."""
        # Validate column names to prevent SQL injection
        invalid_cols = set(incident.keys()) - self._INCIDENT_COLUMNS
        if invalid_cols:
            raise ValueError(f"Invalid column names for incidents table: {invalid_cols}")
        cols = list(incident.keys())
        placeholders = ", ".join(["?"] * len(cols))
        col_names = ", ".join(cols)
        values = []
        for v in incident.values():
            if isinstance(v, (list, dict)):
                values.append(json.dumps(v))
            else:
                values.append(v)

        sql = f"INSERT OR REPLACE INTO incidents ({col_names}) VALUES ({placeholders})"
        self.execute(
            sql, values
        )  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

    def get_incident(self, vtms_id: str) -> dict | None:
        """Fetch a single incident by VTMS ID."""
        rows = self.execute("SELECT * FROM incidents WHERE vtms_id = ?", [vtms_id])
        return rows[0] if rows else None

    def list_incidents(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """List incidents ordered by discovery date descending."""
        return self.execute(
            "SELECT * FROM incidents ORDER BY discovered_at DESC LIMIT ? OFFSET ?",
            [limit, offset],
        )

    def get_max_vtms_sequence(self, year: int) -> int:
        """Get the current maximum VTMS sequence number for a given year."""
        rows = self.execute(
            "SELECT vtms_id FROM incidents WHERE vtms_id LIKE ? ORDER BY vtms_id DESC LIMIT 1",
            [f"VTMS-{year}-%"],
        )
        if not rows:
            return 0
        vtms_id = rows[0]["vtms_id"]
        return int(vtms_id.split("-")[-1])

    def update_incident_field(self, vtms_id: str, field: str, value: Any) -> None:
        """Update a single field on an incident."""
        allowed_fields = {
            "policy_pr_url",
            "content_pr_url",
            "policy_status",
            "content_status",
            "coverage_status",
            "coverage_detail",
            "updated_at",
            "replay_request",
            "enforcement_scope",
        }
        if field not in allowed_fields:
            raise ValueError(f"Field {field!r} not in allowed update fields")
        self.execute(
            f"UPDATE incidents SET {field} = ? WHERE vtms_id = ?", [value, vtms_id]
        )  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

    def upsert_trend(self, trend: dict) -> None:
        """Insert or replace a trend record."""
        # Validate column names to prevent SQL injection
        invalid_cols = set(trend.keys()) - self._TREND_COLUMNS
        if invalid_cols:
            raise ValueError(f"Invalid column names for trends table: {invalid_cols}")
        cols = list(trend.keys())
        placeholders = ", ".join(["?"] * len(cols))
        col_names = ", ".join(cols)
        values = []
        for v in trend.values():
            if isinstance(v, (list, dict)):
                values.append(json.dumps(v))
            else:
                values.append(v)
        sql = f"INSERT OR REPLACE INTO trends ({col_names}) VALUES ({placeholders})"
        self.execute(
            sql, values
        )  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

    def insert_content(self, content: dict) -> None:
        """Insert or replace a content record."""
        # Validate column names to prevent SQL injection
        invalid_cols = set(content.keys()) - self._CONTENT_COLUMNS
        if invalid_cols:
            raise ValueError(f"Invalid column names for content table: {invalid_cols}")
        cols = list(content.keys())
        placeholders = ", ".join(["?"] * len(cols))
        col_names = ", ".join(cols)
        values = list(content.values())
        sql = f"INSERT OR REPLACE INTO content ({col_names}) VALUES ({placeholders})"
        self.execute(
            sql, values
        )  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

    def close(self) -> None:
        self._client.close()
