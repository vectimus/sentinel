"""Finding schema — output from Threat Hunter, input to other agents."""

from __future__ import annotations

import re
from datetime import datetime
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


class Source(BaseModel):
    url: str
    title: str
    r2_key: str | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("https://", "http://")):
            raise ValueError(f"Source URL must use http(s) scheme. Got: {v!r}")
        return v


class Finding(BaseModel):
    vtms_id: str = Field(description="VTMS-YYYY-NNNN identifier")
    title: str
    discovered_at: str
    incident_date: str | None = None
    severity: int = Field(ge=1, le=5)
    owasp_category: str
    nist_ai_rmf: str | None = Field(
        default=None, description="NIST AI RMF function (e.g. GV-1, MP-2)"
    )
    cis_controls: list[str] = Field(default_factory=list, description="Relevant CIS Controls")
    cve_ids: list[str] = Field(default_factory=list, description="Linked CVE identifiers")
    coverage_status: Literal["covered", "partial", "policy_pending"] = Field(
        description="covered | partial | policy_pending"
    )
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
    content_angle: Literal["covered_by_vectimus", "new_policy_needed", "trend_piece"] | None = (
        Field(
            default=None,
            description="covered_by_vectimus | new_policy_needed | trend_piece",
        )
    )
    enforcement_scope: Literal["full", "tool_calling_only", "out_of_scope"] = Field(
        default="full",
        description="full | tool_calling_only | out_of_scope",
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

    @field_validator("cve_ids")
    @classmethod
    def validate_cve_ids(cls, v: list[str]) -> list[str]:
        cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
        for cve in v:
            if not cve_pattern.match(cve):
                raise ValueError(f"Invalid CVE ID format: {cve!r}. Expected CVE-YYYY-NNNN+")
        return v

    @field_validator("owasp_category")
    @classmethod
    def validate_owasp_category(cls, v: str) -> str:
        prefix = v.split(":")[0].strip()
        if prefix.startswith("LLM"):
            raise ValueError(f"LLM prefix is deprecated; use ASI01-ASI10. Got: {v}")
        if prefix not in VALID_ASI_CATEGORIES and prefix != "uncategorised":
            raise ValueError(
                f"owasp_category prefix must be one of {VALID_ASI_CATEGORIES} or 'uncategorised'. Got: {prefix}"
            )
        return v

    @model_validator(mode="after")
    def validate_severity_range(self) -> Finding:
        if not (1 <= self.severity <= 5):
            raise ValueError("severity must be between 1 and 5")
        return self

    @model_validator(mode="after")
    def validate_gap_requires_description(self) -> Finding:
        if self.coverage_status == "policy_pending" and not self.gap_description:
            raise ValueError("gap_description is required when coverage_status is 'policy_pending'")
        return self

    @model_validator(mode="after")
    def validate_new_policy_requires_description(self) -> Finding:
        if self.recommended_action == "new_policy" and not self.recommended_policy_description:
            raise ValueError(
                "recommended_policy_description is required when recommended_action is 'new_policy'"
            )
        return self

    @model_validator(mode="after")
    def validate_new_policy_requires_full_scope(self) -> Finding:
        if self.recommended_action == "new_policy" and self.enforcement_scope != "full":
            raise ValueError(
                f"recommended_action 'new_policy' requires enforcement_scope 'full', "
                f"got '{self.enforcement_scope}'. Cedar policies can only address incidents "
                f"within the tool-call enforcement boundary."
            )
        return self

    @model_validator(mode="after")
    def validate_out_of_scope_no_policy(self) -> Finding:
        if self.enforcement_scope == "out_of_scope" and self.recommended_action != "no_change":
            raise ValueError(
                f"enforcement_scope 'out_of_scope' requires recommended_action 'no_change', "
                f"got '{self.recommended_action}'. Out-of-scope incidents cannot be addressed "
                f"with Cedar policy."
            )
        return self

    @model_validator(mode="after")
    def validate_content_angle_scope(self) -> Finding:
        if self.content_angle == "new_policy_needed" and self.enforcement_scope != "full":
            raise ValueError(
                f"content_angle 'new_policy_needed' requires enforcement_scope 'full', "
                f"got '{self.enforcement_scope}'. Cannot publish content claiming a new policy "
                f"is needed for an out-of-scope incident."
            )
        return self

    @model_validator(mode="after")
    def validate_coverage_detail_required(self) -> Finding:
        if not self.coverage_detail:
            raise ValueError(
                "coverage_detail is required for all findings. Describe what is and isn't "
                "covered, even for gaps."
            )
        return self
