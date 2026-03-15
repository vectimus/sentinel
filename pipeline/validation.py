"""Guardrails AI output validation for the Sentinel pipeline.

Provides validation functions that the orchestrator calls on agent outputs.
Uses Guardrails AI validators for structural checks and Pydantic models
for schema conformance.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from guardrails import Guard, OnFailAction
from guardrails.validators import register_validator, Validator, ValidationResult, PassResult, FailResult
from pydantic import ValidationError

from pipeline.schemas.finding import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom validators
# ---------------------------------------------------------------------------

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


@register_validator(name="sentinel/valid-finding-json", data_type="string")
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


@register_validator(name="sentinel/valid-cedar-policy", data_type="string")
class ValidCedarPolicy(Validator):
    """Validate Cedar policy syntax and required annotations."""

    # Required annotation patterns in Cedar policy comments
    VTMS_ID_PATTERN = re.compile(r"VTMS-\d{4}-\d{4}")
    OWASP_PATTERN = re.compile(r"OWASP:\s*ASI\d{2}")
    POLICY_STATEMENT_PATTERN = re.compile(r"\b(forbid|permit)\s*\(")
    SEMICOLON_CLOSE_PATTERN = re.compile(r";\s*$", re.MULTILINE)

    def validate(self, value: Any, metadata: dict | None = None) -> ValidationResult:
        if not isinstance(value, str) or not value.strip():
            return FailResult(error_message="Cedar policy text is empty")

        errors: list[str] = []

        # Check for required VTMS ID annotation
        if not self.VTMS_ID_PATTERN.search(value):
            errors.append("Missing VTMS incident ID annotation (e.g. VTMS-2026-0042)")

        # Check for required OWASP category annotation
        if not self.OWASP_PATTERN.search(value):
            errors.append("Missing OWASP category annotation (e.g. OWASP: ASI01)")

        # Check for at least one policy statement (forbid or permit)
        if not self.POLICY_STATEMENT_PATTERN.search(value):
            errors.append("No forbid or permit statement found")

        # Check that policy statements end with semicolons
        if self.POLICY_STATEMENT_PATTERN.search(value) and not self.SEMICOLON_CLOSE_PATTERN.search(value):
            errors.append("Policy statement may be missing closing semicolon")

        if errors:
            return FailResult(
                error_message="Cedar policy validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            )

        return PassResult()


@register_validator(name="sentinel/valid-blog-post", data_type="string")
class ValidBlogPost(Validator):
    """Validate blog post against template and humaniser rules."""

    EM_DASH = "\u2014"
    # Oxford comma: comma before "and" or "or" preceded by a comma-separated list
    OXFORD_COMMA_PATTERN = re.compile(r",\s+(and|or)\s+", re.IGNORECASE)

    def validate(self, value: Any, metadata: dict | None = None) -> ValidationResult:
        if not isinstance(value, str) or not value.strip():
            return FailResult(error_message="Blog post content is empty")

        errors: list[str] = []

        # --- Template conformance ---

        # Check frontmatter
        if not value.startswith("---"):
            errors.append("Missing frontmatter (must start with ---)")
        else:
            # Extract frontmatter block
            parts = value.split("---", 2)
            if len(parts) < 3:
                errors.append("Malformed frontmatter (missing closing ---)")
            else:
                frontmatter = parts[1]
                for field in REQUIRED_FRONTMATTER_FIELDS:
                    if f"{field}:" not in frontmatter:
                        errors.append(f"Missing required frontmatter field: {field}")

        # Check required sections
        for section in REQUIRED_BLOG_SECTIONS:
            if section not in value:
                errors.append(f"Missing required section: {section}")

        # --- Humaniser rules ---

        # No em dashes
        if self.EM_DASH in value:
            count = value.count(self.EM_DASH)
            errors.append(
                f"Contains {count} em dash(es) (U+2014). "
                "Use commas, full stops or restructure sentences instead."
            )

        # No AI buzzwords (case-insensitive check)
        value_lower = value.lower()
        found_buzzwords = [bw for bw in AI_BUZZWORDS if bw in value_lower]
        if found_buzzwords:
            errors.append(f"Contains AI buzzwords: {', '.join(found_buzzwords)}")

        # No Oxford commas (heuristic: comma before "and"/"or" in list context)
        # Only flag outside of frontmatter
        content_body = value.split("---", 2)[-1] if "---" in value else value
        oxford_matches = self.OXFORD_COMMA_PATTERN.findall(content_body)
        if oxford_matches:
            errors.append(
                f"Potential Oxford comma(s) detected ({len(oxford_matches)} instance(s)). "
                "Use 'red, white and blue' not 'red, white, and blue'."
            )

        if errors:
            return FailResult(
                error_message="Blog post validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            )

        return PassResult()


# ---------------------------------------------------------------------------
# Public validation functions
# ---------------------------------------------------------------------------

def validate_findings(findings_json: str) -> list[dict]:
    """Validate and optionally auto-correct findings JSON.

    Uses Guardrails AI to validate against the Finding schema.
    Falls back to Pydantic validation if Guardrails AI passes.
    Returns validated findings list.
    Raises ValidationError if unfixable.
    """
    guard = Guard().use(ValidFindingJson(on_fail=OnFailAction.EXCEPTION))

    # Run the Guardrails AI validation
    guard.validate(findings_json)

    # If we get here, the JSON is structurally valid.
    # Parse through Pydantic for full schema validation and return clean dicts.
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
            # Include partially valid findings (raw dict) so downstream agents
            # still get something to work with
            validated.append(item)

    if errors:
        logger.warning(
            "Findings validation completed with %d error(s) out of %d finding(s)",
            len(errors),
            len(data),
        )

    return validated


def validate_cedar_policy(policy_text: str) -> str:
    """Validate Cedar policy syntax.

    Checks for required annotations (VTMS ID, OWASP category).
    Returns validated policy text.
    Raises guardrails.ValidationError if validation fails.
    """
    guard = Guard().use(ValidCedarPolicy(on_fail=OnFailAction.EXCEPTION))
    guard.validate(policy_text)
    return policy_text


def validate_blog_post(markdown: str) -> str:
    """Validate blog post against template and humaniser rules.

    Checks: frontmatter present, required sections exist,
    no em dashes, no Oxford commas, no AI buzzwords.
    Returns validated markdown.
    Raises guardrails.ValidationError if validation fails.
    """
    guard = Guard().use(ValidBlogPost(on_fail=OnFailAction.EXCEPTION))
    guard.validate(markdown)
    return markdown
