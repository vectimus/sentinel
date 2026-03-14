"""Cedar sandbox for policy validation and authorization testing.

Uses cedarpy (pure Python) instead of the Cedar CLI binary — no Rust toolchain needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cedarpy


@dataclass
class AuthzResult:
    decision: str  # ALLOW or DENY
    diagnostics: str


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]


class CedarSandbox:
    """Cedar policy testing via cedarpy."""

    def authorize(
        self,
        policies_dir: str | Path,
        entities: list[dict],
        request: dict,
    ) -> AuthzResult:
        """Run cedar authorize against a policies directory.

        Args:
            policies_dir: Path to directory containing .cedar policy files
            entities: List of entity objects
            request: Dict with principal, action, resource, context keys
        """
        policies_dir = Path(policies_dir)

        # Load all .cedar policy files
        policies = ""
        for cedar_file in sorted(policies_dir.glob("**/*.cedar")):
            policies += cedar_file.read_text() + "\n"

        response = cedarpy.is_authorized(
            {
                "principal": request["principal"],
                "action": request["action"],
                "resource": request["resource"],
                "context": request.get("context", {}),
            },
            policies,
            entities,
        )

        decision = "ALLOW" if response.decision == cedarpy.Decision.Allow else "DENY"
        diagnostics_parts = []
        if response.diagnostics.reasons:
            diagnostics_parts.append(f"Reasons: {', '.join(response.diagnostics.reasons)}")
        if response.diagnostics.errors:
            diagnostics_parts.append(f"Errors: {', '.join(response.diagnostics.errors)}")

        return AuthzResult(
            decision=decision,
            diagnostics="\n".join(diagnostics_parts) if diagnostics_parts else "",
        )

    def validate(
        self,
        policies_dir: str | Path,
        schema_path: str | Path,
    ) -> ValidationResult:
        """Validate policies against a Cedar schema.

        Args:
            policies_dir: Path to directory containing .cedar policy files
            schema_path: Path to Cedar schema file (.cedarschema or .json)
        """
        policies_dir = Path(policies_dir)
        schema_path = Path(schema_path)

        policies = ""
        for cedar_file in sorted(policies_dir.glob("**/*.cedar")):
            policies += cedar_file.read_text() + "\n"

        schema = schema_path.read_text()

        result = cedarpy.validate_policies(policies, schema)
        if result.validation_passed:
            return ValidationResult(valid=True, errors=[])
        return ValidationResult(
            valid=False,
            errors=[str(e) for e in result.errors],
        )
