"""Cedar CLI sandbox wrapper for policy validation and authorization testing."""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AuthzResult:
    decision: str  # ALLOW or DENY
    diagnostics: str


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]


class CedarSandbox:
    """Wraps the Cedar CLI binary for policy testing."""

    def __init__(self, cedar_bin: str = "cedar") -> None:
        self.cedar_bin = cedar_bin

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

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as entities_file:
            json.dump(entities, entities_file)
            entities_path = entities_file.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as request_file:
            json.dump(request, request_file)
            request_path = request_file.name

        cmd = [
            self.cedar_bin,
            "authorize",
            "--policies", str(policies_dir),
            "--entities", entities_path,
            "--principal", request["principal"],
            "--action", request["action"],
            "--resource", request["resource"],
        ]

        if "context" in request:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as ctx_file:
                json.dump(request["context"], ctx_file)
                cmd.extend(["--context", ctx_file.name])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        decision = "ALLOW" if result.returncode == 0 else "DENY"
        diagnostics = result.stdout + result.stderr

        return AuthzResult(decision=decision, diagnostics=diagnostics.strip())

    def validate(
        self,
        policies_dir: str | Path,
        schema_path: str | Path,
    ) -> ValidationResult:
        """Run cedar validate against a schema.

        Args:
            policies_dir: Path to directory containing .cedar policy files
            schema_path: Path to Cedar schema file
        """
        cmd = [
            self.cedar_bin,
            "validate",
            "--policies", str(policies_dir),
            "--schema", str(schema_path),
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return ValidationResult(valid=True, errors=[])

        errors = [
            line.strip()
            for line in (result.stdout + result.stderr).splitlines()
            if line.strip()
        ]
        return ValidationResult(valid=False, errors=errors)
