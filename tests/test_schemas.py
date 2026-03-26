"""Tests for Pydantic schema models: Finding, Incident, Content."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pipeline.schemas.finding import Finding
from pipeline.schemas.incident import Incident
from pipeline.schemas.content import Content


# ── Finding ──────────────────────────────────────────────────────────────


class TestFindingValidation:

    def test_valid_finding_passes_validation(self, sample_finding):
        finding = Finding(**sample_finding)
        assert finding.vtms_id == "VTMS-2026-0001"
        assert finding.severity == 4
        assert finding.coverage_status == "policy_pending"

    def test_invalid_vtms_id_rejected(self, sample_finding):
        sample_finding["vtms_id"] = "VTMS-26-1"
        with pytest.raises(ValidationError, match="vtms_id must match VTMS-YYYY-NNNN"):
            Finding(**sample_finding)

    def test_vtms_id_missing_prefix_rejected(self, sample_finding):
        sample_finding["vtms_id"] = "2026-0001"
        with pytest.raises(ValidationError, match="vtms_id must match VTMS-YYYY-NNNN"):
            Finding(**sample_finding)

    def test_severity_below_minimum_rejected(self, sample_finding):
        sample_finding["severity"] = 0
        with pytest.raises(ValidationError):
            Finding(**sample_finding)

    def test_severity_above_maximum_rejected(self, sample_finding):
        sample_finding["severity"] = 6
        with pytest.raises(ValidationError):
            Finding(**sample_finding)

    def test_invalid_coverage_status_rejected(self, sample_finding):
        sample_finding["coverage_status"] = "unknown"
        with pytest.raises(ValidationError):
            Finding(**sample_finding)

    def test_coverage_status_covered_accepted(self, sample_finding):
        sample_finding["coverage_status"] = "covered"
        sample_finding["gap_description"] = None
        sample_finding["recommended_action"] = "no_change"
        sample_finding["recommended_policy_description"] = None
        finding = Finding(**sample_finding)
        assert finding.coverage_status == "covered"

    def test_coverage_status_partial_accepted(self, sample_finding):
        sample_finding["coverage_status"] = "partial"
        sample_finding["gap_description"] = None
        sample_finding["recommended_action"] = "update_existing"
        sample_finding["recommended_policy_description"] = None
        finding = Finding(**sample_finding)
        assert finding.coverage_status == "partial"

    def test_gap_description_required_when_policy_pending(self, sample_finding):
        sample_finding["coverage_status"] = "policy_pending"
        sample_finding["gap_description"] = None
        with pytest.raises(ValidationError, match="gap_description is required"):
            Finding(**sample_finding)

    def test_gap_description_not_required_when_covered(self, sample_finding):
        sample_finding["coverage_status"] = "covered"
        sample_finding["gap_description"] = None
        sample_finding["recommended_action"] = "no_change"
        sample_finding["recommended_policy_description"] = None
        finding = Finding(**sample_finding)
        assert finding.gap_description is None

    def test_invalid_recommended_action_rejected(self, sample_finding):
        sample_finding["recommended_action"] = "delete_all"
        with pytest.raises(ValidationError):
            Finding(**sample_finding)

    def test_recommended_policy_description_required_when_new_policy(self, sample_finding):
        sample_finding["recommended_action"] = "new_policy"
        sample_finding["recommended_policy_description"] = None
        with pytest.raises(ValidationError, match="recommended_policy_description is required"):
            Finding(**sample_finding)

    def test_recommended_policy_description_not_required_when_no_change(self, sample_finding):
        sample_finding["recommended_action"] = "no_change"
        sample_finding["recommended_policy_description"] = None
        sample_finding["coverage_status"] = "covered"
        sample_finding["gap_description"] = None
        finding = Finding(**sample_finding)
        assert finding.recommended_policy_description is None

    def test_invalid_content_angle_rejected(self, sample_finding):
        sample_finding["content_angle"] = "random_value"
        with pytest.raises(ValidationError):
            Finding(**sample_finding)

    def test_content_angle_none_accepted(self, sample_finding):
        sample_finding["content_angle"] = None
        finding = Finding(**sample_finding)
        assert finding.content_angle is None

    def test_content_angle_covered_by_vectimus_accepted(self, sample_finding):
        sample_finding["content_angle"] = "covered_by_vectimus"
        finding = Finding(**sample_finding)
        assert finding.content_angle == "covered_by_vectimus"

    def test_content_angle_trend_piece_accepted(self, sample_finding):
        sample_finding["content_angle"] = "trend_piece"
        finding = Finding(**sample_finding)
        assert finding.content_angle == "trend_piece"


# ── Incident ─────────────────────────────────────────────────────────────


class TestIncidentValidation:

    def test_valid_incident_passes_validation(self, sample_incident):
        incident = Incident(**sample_incident)
        assert incident.vtms_id == "VTMS-2026-0001"
        assert incident.severity == 4

    def test_invalid_vtms_id_rejected(self, sample_incident):
        sample_incident["vtms_id"] = "VTMS-26-1"
        with pytest.raises(ValidationError, match="vtms_id must match VTMS-YYYY-NNNN"):
            Incident(**sample_incident)

    def test_severity_below_minimum_rejected(self, sample_incident):
        sample_incident["severity"] = 0
        with pytest.raises(ValidationError):
            Incident(**sample_incident)

    def test_severity_above_maximum_rejected(self, sample_incident):
        sample_incident["severity"] = 6
        with pytest.raises(ValidationError):
            Incident(**sample_incident)

    def test_invalid_coverage_status_rejected(self, sample_incident):
        sample_incident["coverage_status"] = "unknown"
        with pytest.raises(ValidationError):
            Incident(**sample_incident)

    def test_invalid_policy_status_rejected(self, sample_incident):
        sample_incident["policy_status"] = "invalid"
        with pytest.raises(ValidationError):
            Incident(**sample_incident)

    def test_invalid_content_status_rejected(self, sample_incident):
        sample_incident["content_status"] = "invalid"
        with pytest.raises(ValidationError):
            Incident(**sample_incident)


# ── Content ──────────────────────────────────────────────────────────────


class TestContentValidation:

    def test_valid_content_passes_validation(self):
        content = Content(
            id="content-001",
            vtms_id="VTMS-2026-0001",
            content_type="blog_post",
            title="Understanding Prompt Injection",
            slug="understanding-prompt-injection",
            status="draft",
            created_at="2026-03-14T12:00:00Z",
            updated_at="2026-03-14T12:00:00Z",
        )
        assert content.content_type == "blog_post"
        assert content.status == "draft"

    def test_invalid_content_type_rejected(self):
        with pytest.raises(ValidationError):
            Content(
                id="content-001",
                vtms_id="VTMS-2026-0001",
                content_type="whitepaper",
                title="Test",
            )

    def test_content_type_incident_brief_accepted(self):
        content = Content(
            id="content-002",
            vtms_id="VTMS-2026-0002",
            content_type="incident_brief",
        )
        assert content.content_type == "incident_brief"

    def test_invalid_vtms_id_rejected(self):
        with pytest.raises(ValidationError, match="vtms_id must match VTMS-YYYY-NNNN"):
            Content(
                id="content-001",
                vtms_id="BAD-ID",
                content_type="blog_post",
            )

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            Content(
                id="content-001",
                vtms_id="VTMS-2026-0001",
                content_type="blog_post",
                status="deleted",
            )
