"""Output validation for the Sentinel pipeline.

Provides validation functions that the orchestrator calls on agent outputs.
Custom validators perform structural checks; Pydantic models enforce schema
conformance on findings.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from pipeline.schemas.finding import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Minimal validator framework
#
# Previously these classes wrapped `guardrails-ai`. That package was removed
# from PyPI, so we provide the small surface we actually used: a Validator
# base with a `validate(value)` method that returns Pass/FailResult.
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    error_message: str | None = None


@dataclass
class PassResult(ValidationResult):
    error_message: str | None = None


@dataclass
class FailResult(ValidationResult):
    error_message: str = ""


class Validator:
    def validate(self, value: Any, metadata: dict | None = None) -> ValidationResult:
        raise NotImplementedError


def _run(validator: Validator, value: Any) -> None:
    result = validator.validate(value)
    if isinstance(result, FailResult):
        raise ValueError(result.error_message)


AI_BUZZWORDS = [
    "cutting-edge",
    "revolutionary",
    "game-changing",
    "innovative",
    "seamlessly",
    "leverage",
    "harness",
    "unlock",
    "empower",
    "holistic",
    "synergy",
    "paradigm",
]

REQUIRED_BLOG_SECTIONS = [
    "## What happened",
    "## Why it matters",
    "## Root cause",
    "## How Vectimus responds",
    "## What you can do",
]

REQUIRED_FRONTMATTER_FIELDS = [
    "vtms_id",
    "title",
    "date",
    "author",
    "category",
    "owasp_category",
    "severity",
    "tags",
]


class ValidFindingJson(Validator):
    """Validate that a JSON string is a valid array of Finding objects."""

    def validate(self, value: Any, metadata: dict | None = None) -> ValidationResult:
        try:
            data = json.loads(value) if isinstance(value, str) else value
        except (json.JSONDecodeError, TypeError) as e:
            return FailResult(error_message=f"Invalid JSON: {e}")

        if not isinstance(data, list):
            return FailResult(error_message="Findings must be a JSON array")

        errors: list[str] = []
        for i, item in enumerate(data):
            try:
                Finding.model_validate(item)
            except ValidationError as e:
                errors.append(f"Finding[{i}]: {e}")

        if errors:
            return FailResult(
                error_message=f"Schema validation failed for {len(errors)} finding(s):\n"
                + "\n".join(errors)
            )

        return PassResult()


class ValidCedarPolicy(Validator):
    """Validate Cedar policy syntax and required annotations."""

    VTMS_ID_PATTERN = re.compile(r"VTMS-\d{4}-\d{4}")
    OWASP_PATTERN = re.compile(r"OWASP:\s*ASI\d{2}")
    POLICY_STATEMENT_PATTERN = re.compile(r"\b(forbid|permit)\s*\(")
    SEMICOLON_CLOSE_PATTERN = re.compile(r";\s*$", re.MULTILINE)

    def validate(self, value: Any, metadata: dict | None = None) -> ValidationResult:
        if not isinstance(value, str) or not value.strip():
            return FailResult(error_message="Cedar policy text is empty")

        errors: list[str] = []

        if not self.VTMS_ID_PATTERN.search(value):
            errors.append("Missing VTMS incident ID annotation (e.g. VTMS-2026-0042)")

        if not self.OWASP_PATTERN.search(value):
            errors.append("Missing OWASP category annotation (e.g. OWASP: ASI01)")

        if not self.POLICY_STATEMENT_PATTERN.search(value):
            errors.append("No forbid or permit statement found")

        if self.POLICY_STATEMENT_PATTERN.search(value) and not self.SEMICOLON_CLOSE_PATTERN.search(
            value
        ):
            errors.append("Policy statement may be missing closing semicolon")

        if errors:
            return FailResult(
                error_message="Cedar policy validation failed:\n"
                + "\n".join(f"  - {e}" for e in errors)
            )

        return PassResult()


class ValidBlogPost(Validator):
    """Validate blog post against template and humaniser rules."""

    EM_DASH = "—"
    OXFORD_COMMA_PATTERN = re.compile(r",\s+(and|or)\s+", re.IGNORECASE)

    def validate(self, value: Any, metadata: dict | None = None) -> ValidationResult:
        if not isinstance(value, str) or not value.strip():
            return FailResult(error_message="Blog post content is empty")

        errors: list[str] = []

        if not value.startswith("---"):
            errors.append("Missing frontmatter (must start with ---)")
        else:
            parts = value.split("---", 2)
            if len(parts) < 3:
                errors.append("Malformed frontmatter (missing closing ---)")
            else:
                frontmatter = parts[1]
                for field in REQUIRED_FRONTMATTER_FIELDS:
                    if f"{field}:" not in frontmatter:
                        errors.append(f"Missing required frontmatter field: {field}")

        for section in REQUIRED_BLOG_SECTIONS:
            if section not in value:
                errors.append(f"Missing required section: {section}")

        if self.EM_DASH in value:
            count = value.count(self.EM_DASH)
            errors.append(
                f"Contains {count} em dash(es) (U+2014). "
                "Use commas, full stops or restructure sentences instead."
            )

        value_lower = value.lower()
        found_buzzwords = [bw for bw in AI_BUZZWORDS if bw in value_lower]
        if found_buzzwords:
            errors.append(f"Contains AI buzzwords: {', '.join(found_buzzwords)}")

        content_body = value.split("---", 2)[-1] if "---" in value else value
        oxford_matches = self.OXFORD_COMMA_PATTERN.findall(content_body)
        if oxford_matches:
            errors.append(
                f"Potential Oxford comma(s) detected ({len(oxford_matches)} instance(s)). "
                "Use 'red, white and blue' not 'red, white, and blue'."
            )

        if errors:
            return FailResult(
                error_message="Blog post validation failed:\n"
                + "\n".join(f"  - {e}" for e in errors)
            )

        return PassResult()


# ---------------------------------------------------------------------------
# Public validation functions
# ---------------------------------------------------------------------------


def validate_findings(findings_json: str) -> list[dict]:
    """Validate findings JSON and return clean dicts.

    Raises ValueError on structural validation failure.
    Logs (but does not raise) per-finding Pydantic errors; partially valid
    findings are returned as raw dicts so downstream agents still get input.
    """
    _run(ValidFindingJson(), findings_json)

    data = json.loads(findings_json)
    validated: list[dict] = []
    errors: list[str] = []

    for i, item in enumerate(data):
        try:
            finding = Finding.model_validate(item)
            validated.append(finding.model_dump())
        except ValidationError as e:
            errors.append(f"Finding[{i}] ({item.get('vtms_id', 'unknown')}): {e}")
            logger.warning("Finding[%d] failed Pydantic validation: %s", i, e)
            validated.append(item)

    if errors:
        logger.warning(
            "Findings validation completed with %d error(s) out of %d finding(s)",
            len(errors),
            len(data),
        )

    return validated


def validate_cedar_policy(policy_text: str) -> str:
    """Validate Cedar policy syntax. Raises ValueError on failure."""
    _run(ValidCedarPolicy(), policy_text)
    return policy_text


def validate_blog_post(markdown: str) -> str:
    """Validate blog post template and humaniser rules. Raises ValueError on failure."""
    _run(ValidBlogPost(), markdown)
    return markdown
