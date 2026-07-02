"""Tests for the HITL review-gate classification logic.

The pipeline should only block on the human review gate when the threat-hunter
surfaced something worth reviewing. A run that is all out-of-scope / no_change
noise must NOT wait for an approval that never comes.
"""

from __future__ import annotations

from pipeline.hitl_issue import _classify


def _finding(**overrides: object) -> dict:
    base = {
        "vtms_id": "VTMS-2026-0001",
        "title": "Example",
        "severity": 3,
        "enforcement_scope": "full",
        "recommended_action": "no_change",
        "content_worthy": False,
    }
    base.update(overrides)
    return base


def test_actionable_when_policy_change_and_in_scope() -> None:
    actionable, content = _classify([_finding(recommended_action="new_policy")])
    assert len(actionable) == 1
    assert content == []


def test_out_of_scope_never_actionable() -> None:
    # Even a policy-changing recommendation is not actionable if out of scope.
    actionable, content = _classify(
        [_finding(enforcement_scope="out_of_scope", recommended_action="new_policy")]
    )
    assert actionable == []
    assert content == []


def test_content_worthy_in_scope_is_flagged() -> None:
    actionable, content = _classify([_finding(content_worthy=True)])
    assert actionable == []
    assert len(content) == 1


def test_out_of_scope_content_worthy_is_ignored() -> None:
    actionable, content = _classify(
        [_finding(enforcement_scope="out_of_scope", content_worthy=True)]
    )
    assert content == []


def test_all_noise_needs_no_review() -> None:
    # The scenario that used to strand runs "waiting" for a week: every finding
    # is out-of-scope / no_change. Nothing actionable, nothing content-worthy.
    findings = [
        _finding(vtms_id="VTMS-2026-0100", enforcement_scope="out_of_scope"),
        _finding(vtms_id="VTMS-2026-0101", enforcement_scope="tool_calling_only"),
    ]
    actionable, content = _classify(findings)
    assert not actionable and not content  # -> workflow sets skip_review=true


def test_mixed_run_needs_review() -> None:
    findings = [
        _finding(vtms_id="VTMS-2026-0100", enforcement_scope="out_of_scope"),
        _finding(vtms_id="VTMS-2026-0101", recommended_action="new_policy"),
    ]
    actionable, content = _classify(findings)
    assert len(actionable) == 1
