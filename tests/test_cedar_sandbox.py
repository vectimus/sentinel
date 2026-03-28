"""Tests for CedarSandbox with REAL cedarpy (no mocking)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.tools.cedar_sandbox import CedarSandbox


@pytest.fixture
def cedar() -> CedarSandbox:
    return CedarSandbox()


@pytest.fixture
def deny_policy_dir(tmp_path: Path) -> Path:
    """Create a temp dir with a Cedar policy that forbids a specific action."""
    policy = """
    forbid(
        principal,
        action == Action::"execute",
        resource == Resource::"dangerous_tool"
    );
    """
    (tmp_path / "deny.cedar").write_text(policy)
    return tmp_path


@pytest.fixture
def allow_policy_dir(tmp_path: Path) -> Path:
    """Create a temp dir with a Cedar policy that allows a specific action."""
    policy = """
    permit(
        principal == User::"admin",
        action == Action::"read",
        resource == Resource::"safe_report"
    );
    """
    (tmp_path / "allow.cedar").write_text(policy)
    return tmp_path


class TestAuthorize:
    def test_returns_deny_for_forbidden_request(self, cedar, deny_policy_dir):
        request = {
            "principal": 'User::"attacker"',
            "action": 'Action::"execute"',
            "resource": 'Resource::"dangerous_tool"',
            "context": {},
        }
        entities = []

        result = cedar.authorize(deny_policy_dir, entities, request)

        assert result.decision == "DENY"

    def test_returns_allow_for_permitted_request(self, cedar, allow_policy_dir):
        request = {
            "principal": 'User::"admin"',
            "action": 'Action::"read"',
            "resource": 'Resource::"safe_report"',
            "context": {},
        }
        entities = []

        result = cedar.authorize(allow_policy_dir, entities, request)

        assert result.decision == "ALLOW"

    def test_returns_deny_when_no_matching_permit(self, cedar, allow_policy_dir):
        request = {
            "principal": 'User::"guest"',
            "action": 'Action::"read"',
            "resource": 'Resource::"safe_report"',
            "context": {},
        }
        entities = []

        result = cedar.authorize(allow_policy_dir, entities, request)

        # Default deny — no permit matches for guest
        assert result.decision == "DENY"


class TestValidate:
    def test_valid_policy_returns_valid(self, cedar, tmp_path):
        policy = """
        permit(
            principal,
            action == Action::"read",
            resource
        );
        """
        (tmp_path / "valid.cedar").write_text(policy)

        schema = json.dumps(
            {
                "": {
                    "entityTypes": {
                        "User": {
                            "memberOfTypes": [],
                            "shape": {"type": "Record", "attributes": {}},
                        }
                    },
                    "actions": {
                        "read": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["User"],
                            }
                        }
                    },
                }
            }
        )
        schema_path = tmp_path / "schema.json"
        schema_path.write_text(schema)

        result = cedar.validate(tmp_path, schema_path)

        assert result.valid is True
        assert result.errors == []

    def test_invalid_policy_returns_invalid(self, cedar, tmp_path):
        # Policy references an action not in the schema
        policy = """
        permit(
            principal,
            action == Action::"nonexistent_action",
            resource
        );
        """
        (tmp_path / "invalid.cedar").write_text(policy)

        schema = json.dumps(
            {
                "": {
                    "entityTypes": {
                        "User": {
                            "memberOfTypes": [],
                            "shape": {"type": "Record", "attributes": {}},
                        }
                    },
                    "actions": {
                        "read": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["User"],
                            }
                        }
                    },
                }
            }
        )
        schema_path = tmp_path / "schema.json"
        schema_path.write_text(schema)

        result = cedar.validate(tmp_path, schema_path)

        assert result.valid is False
        assert len(result.errors) > 0
