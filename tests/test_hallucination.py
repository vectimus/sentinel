"""Hallucination detection tests using DeepEval.

These tests validate that agent outputs are faithful to their source
material and don't fabricate VTMS IDs, CVE references, policy names,
or incident details.

Runs with: pytest tests/test_hallucination.py -v
Requires: ANTHROPIC_API_KEY (or OPENAI_API_KEY) for the grader LLM.
Skip with: pytest -m "not deepeval" to skip when no API key is set.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# Skip entire module if no LLM API key is available
pytestmark = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"),
    reason="Hallucination tests require an LLM API key (ANTHROPIC_API_KEY or OPENAI_API_KEY)",
)

from deepeval import assert_test
from deepeval.metrics import FaithfulnessMetric, HallucinationMetric
from deepeval.test_case import LLMTestCase


# ---------------------------------------------------------------------------
# Fixtures — sample agent outputs and their source contexts
# ---------------------------------------------------------------------------

EXAMPLE_FINDING_PATH = Path("shared/examples/incidents/example-finding.json")


@pytest.fixture
def example_finding() -> dict:
    return json.loads(EXAMPLE_FINDING_PATH.read_text())


@pytest.fixture
def faithfulness_metric() -> FaithfulnessMetric:
    return FaithfulnessMetric(threshold=0.7, include_reason=True)


@pytest.fixture
def hallucination_metric() -> HallucinationMetric:
    return HallucinationMetric(threshold=0.7, include_reason=True)


# ---------------------------------------------------------------------------
# Threat Hunter — findings must be faithful to source material
# ---------------------------------------------------------------------------


class TestThreatHunterFaithfulness:
    def test_finding_summary_faithful_to_context(
        self, example_finding, faithfulness_metric
    ):
        """The finding summary should be derivable from the source context."""
        context = [
            f"Incident: {example_finding['title']}",
            f"VTMS ID: {example_finding['vtms_id']}",
            f"Severity: {example_finding['severity']}",
            f"OWASP: {example_finding['owasp_category']}",
            f"Coverage: {example_finding['coverage_status']} - {example_finding['coverage_detail']}",
        ]

        test_case = LLMTestCase(
            input=f"Classify this incident: {example_finding['title']}",
            actual_output=example_finding["summary"],
            retrieval_context=context,
        )
        assert_test(test_case, [faithfulness_metric])

    def test_coverage_assessment_not_hallucinated(
        self, example_finding, hallucination_metric
    ):
        """Coverage status and policy references should match the context."""
        context = [
            f"Policy IDs in the Vectimus set: {example_finding['existing_policy_ids']}",
            f"Coverage detail: {example_finding['coverage_detail']}",
            f"Coverage status: {example_finding['coverage_status']}",
        ]

        test_case = LLMTestCase(
            input="What is the coverage status for this incident?",
            actual_output=(
                f"Coverage status: {example_finding['coverage_status']}. "
                f"{example_finding['coverage_detail']}"
            ),
            context=context,
        )
        assert_test(test_case, [hallucination_metric])


# ---------------------------------------------------------------------------
# Security Engineer — Cedar policy annotations must match source
# ---------------------------------------------------------------------------


class TestSecurityEngineerFaithfulness:
    def test_cedar_policy_annotations_faithful(self, faithfulness_metric):
        """Cedar policy annotations must reference real VTMS IDs and OWASP categories."""
        cedar_output = (
            "// VTMS-2026-0042 | OWASP: ASI02 | SOC 2: CC6.1 | NIST: GV-1\n"
            "// Blocks agent-initiated npm publish commands\n"
            "forbid (\n"
            '  principal,\n'
            '  action == Action::"shell_command",\n'
            "  resource\n"
            ")\n"
            "when {\n"
            '  resource.command like "*npm publish*"\n'
            "};"
        )

        context = [
            "Finding VTMS-2026-0042: Supply chain attack via malicious MCP server",
            "OWASP category: ASI02: Insecure Tool Use",
            "Recommended action: new_policy",
            "The incident involved agent-initiated npm publish commands",
        ]

        test_case = LLMTestCase(
            input="Write a Cedar policy for VTMS-2026-0042",
            actual_output=cedar_output,
            retrieval_context=context,
        )
        assert_test(test_case, [faithfulness_metric])


# ---------------------------------------------------------------------------
# Threat Analyst — blog post claims must be grounded
# ---------------------------------------------------------------------------


class TestThreatAnalystFaithfulness:
    def test_blog_post_faithful_to_finding(self, faithfulness_metric):
        """Blog post content must be faithful to the finding data."""
        blog_excerpt = (
            "## What happened\n\n"
            "A malicious MCP server distributed via a popular registry instructed "
            "AI coding agents to publish backdoored npm packages. Approximately "
            "4,000 developers were affected. The incident was first reported in "
            "February 2026.\n\n"
            "## Why it matters\n\n"
            "This incident demonstrates that MCP servers represent a significant "
            "supply chain attack vector. Organisations running AI coding agents "
            "without MCP governance policies are exposed to this class of attack."
        )

        context = [
            "VTMS-2026-0042: Supply chain attack via malicious MCP server publishing backdoored npm packages",
            "Severity: 4 (widespread exploitation)",
            "Approximately 4,000 developers were affected",
            "First reported February 2026",
            "OWASP: ASI02 Insecure Tool Use",
            "Coverage: covered by MCP-001 and SC-003",
        ]

        test_case = LLMTestCase(
            input="Write a blog post about VTMS-2026-0042",
            actual_output=blog_excerpt,
            retrieval_context=context,
        )
        assert_test(test_case, [faithfulness_metric])

    def test_blog_does_not_hallucinate_statistics(self, hallucination_metric):
        """Blog post should not fabricate numbers not in the source material."""
        # Intentionally includes a hallucinated statistic
        hallucinated_blog = (
            "The attack affected over 50,000 developers worldwide and caused "
            "an estimated $2.3 million in damages. The vulnerability was assigned "
            "CVE-2026-99999."
        )

        context = [
            "Approximately 4,000 developers were affected",
            "No CVE has been assigned to this incident",
            "Financial impact has not been quantified",
        ]

        test_case = LLMTestCase(
            input="Write about the impact of this incident",
            actual_output=hallucinated_blog,
            context=context,
        )

        # This SHOULD fail — the output contains hallucinated numbers
        metric = HallucinationMetric(threshold=0.7)
        metric.measure(test_case)
        assert metric.score < 0.7, (
            f"Expected hallucination detection to flag fabricated statistics, "
            f"but got score {metric.score}"
        )
