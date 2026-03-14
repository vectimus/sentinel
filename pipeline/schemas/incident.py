"""Incident schema — D1 database record."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Incident(BaseModel):
    vtms_id: str
    title: str
    summary: str | None = None
    discovered_at: str
    incident_date: str | None = None
    severity: int = Field(ge=1, le=5)
    owasp_category: str | None = None
    nist_ai_rmf: str | None = None
    cis_controls: str | None = None  # JSON-encoded list
    cve_ids: str | None = None  # JSON-encoded list
    coverage_status: str
    coverage_detail: str | None = None
    existing_policy_ids: str | None = None  # JSON-encoded list
    gap_description: str | None = None
    tools_involved: str | None = None  # JSON-encoded list
    sources: str | None = None  # JSON-encoded list
    policy_pr_url: str | None = None
    content_pr_url: str | None = None
    policy_status: str = "na"
    content_status: str = "na"
    recommended_action: str | None = None
    content_angle: str | None = None
    created_at: str = ""
    updated_at: str = ""
