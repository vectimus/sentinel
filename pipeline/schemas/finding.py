"""Finding schema — output from Threat Hunter, input to other agents."""

from __future__ import annotations

from pydantic import BaseModel, Field


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
    coverage_status: str = Field(description="covered | partial | gap")
    coverage_detail: str | None = None
    existing_policy_ids: list[str] = Field(default_factory=list)
    gap_description: str | None = None
    sources: list[Source] = Field(default_factory=list)
    tools_involved: list[str] = Field(default_factory=list)
    summary: str
    recommended_action: str = Field(description="no_change | update_existing | new_policy")
    recommended_policy_description: str | None = None
    content_worthy: bool = False
    content_angle: str | None = Field(
        default=None,
        description="covered_by_vectimus | new_policy_needed | trend_piece",
    )
