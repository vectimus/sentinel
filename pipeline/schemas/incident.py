"""Incident schema — D1 database record."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

VALID_ASI_CATEGORIES = [
    "ASI01",
    "ASI02",
    "ASI03",
    "ASI04",
    "ASI05",
    "ASI06",
    "ASI07",
    "ASI08",
    "ASI09",
    "ASI10",
]


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
    coverage_status: Literal["covered", "partial", "policy_pending"]
    coverage_detail: str | None = None
    existing_policy_ids: str | None = None  # JSON-encoded list
    gap_description: str | None = None
    tools_involved: str | None = None  # JSON-encoded list
    sources: str | None = None  # JSON-encoded list
    policy_pr_url: str | None = None
    content_pr_url: str | None = None
    policy_status: Literal["na", "draft", "merged", "closed"] = "na"
    content_status: Literal["na", "draft", "published", "archived"] = "na"
    recommended_action: str | None = None
    content_angle: str | None = None
    replay_request: str | None = None
    enforcement_scope: str | None = Field(default="full")
    created_at: str = ""
    updated_at: str = ""

    @field_validator("vtms_id")
    @classmethod
    def validate_vtms_id(cls, v: str) -> str:
        if not re.match(r"^VTMS-\d{4}-\d{4}$", v):
            raise ValueError("vtms_id must match VTMS-YYYY-NNNN format")
        return v

    @field_validator("owasp_category")
    @classmethod
    def validate_owasp_category(cls, v: str | None) -> str | None:
        if v is None:
            return v
        prefix = v.split(":")[0].strip()
        if prefix.startswith("LLM"):
            raise ValueError(f"LLM prefix is deprecated; use ASI01-ASI10. Got: {v}")
        if prefix not in VALID_ASI_CATEGORIES and prefix != "uncategorised":
            raise ValueError(
                f"owasp_category prefix must be one of {VALID_ASI_CATEGORIES} or 'uncategorised'. Got: {prefix}"
            )
        return v

    @model_validator(mode="after")
    def validate_severity_range(self) -> Incident:
        if not (1 <= self.severity <= 5):
            raise ValueError("severity must be between 1 and 5")
        return self
