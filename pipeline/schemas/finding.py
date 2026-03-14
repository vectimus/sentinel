"""Finding schema — output from Threat Hunter, input to other agents."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class Source(BaseModel):
    url: str
    title: str
    r2_key: str | None = None


class Finding(BaseModel):
    vtms_id: str = Field(description="VTMS-YYYY-NNNN identifier")
    title: str
    discovered_at: str
    incident_date: str | None = None
    severity: int = Field(ge=1, le=5)
    owasp_category: str
    nist_ai_rmf: str | None = Field(default=None, description="NIST AI RMF function (e.g. GV-1, MP-2)")
    cis_controls: list[str] = Field(default_factory=list, description="Relevant CIS Controls")
    cve_ids: list[str] = Field(default_factory=list, description="Linked CVE identifiers")
    coverage_status: Literal["covered", "partial", "gap"] = Field(description="covered | partial | gap")
    coverage_detail: str | None = None
    existing_policy_ids: list[str] = Field(default_factory=list)
    gap_description: str | None = None
    sources: list[Source] = Field(default_factory=list)
    tools_involved: list[str] = Field(default_factory=list)
    summary: str
    recommended_action: Literal["no_change", "update_existing", "new_policy"] = Field(
        description="no_change | update_existing | new_policy",
    )
    recommended_policy_description: str | None = None
    content_worthy: bool = False
    content_angle: Literal["covered_by_vectimus", "new_policy_needed", "trend_piece"] | None = Field(
        default=None,
        description="covered_by_vectimus | new_policy_needed | trend_piece",
    )

    @field_validator("vtms_id")
    @classmethod
    def validate_vtms_id(cls, v: str) -> str:
        if not re.match(r"^VTMS-\d{4}-\d{4}$", v):
            raise ValueError("vtms_id must match VTMS-YYYY-NNNN format")
        return v

    @field_validator("discovered_at")
    @classmethod
    def validate_discovered_at(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError("discovered_at must be in ISO 8601 format")
        return v

    @model_validator(mode="after")
    def validate_severity_range(self) -> Finding:
        if not (1 <= self.severity <= 5):
            raise ValueError("severity must be between 1 and 5")
        return self

    @model_validator(mode="after")
    def validate_gap_requires_description(self) -> Finding:
        if self.coverage_status == "gap" and not self.gap_description:
            raise ValueError("gap_description is required when coverage_status is 'gap'")
        return self

    @model_validator(mode="after")
    def validate_new_policy_requires_description(self) -> Finding:
        if self.recommended_action == "new_policy" and not self.recommended_policy_description:
            raise ValueError(
                "recommended_policy_description is required when recommended_action is 'new_policy'"
            )
        return self
