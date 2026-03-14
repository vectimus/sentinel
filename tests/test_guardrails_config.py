"""Tests for NeMo Guardrails configuration files.

Validates that all config.yml, prompts.yml and rails.co files exist,
parse correctly and contain the expected structure.
"""

from pathlib import Path

import pytest
import yaml

GUARDRAILS_DIR = Path(__file__).parent.parent / "guardrails"

AGENTS = ["threat-hunter", "security-engineer", "threat-analyst"]


class TestConfigFiles:
    @pytest.mark.parametrize("agent", AGENTS)
    def test_config_yml_exists(self, agent: str):
        config_path = GUARDRAILS_DIR / agent / "config.yml"
        assert config_path.exists(), f"Missing config.yml for {agent}"

    @pytest.mark.parametrize("agent", AGENTS)
    def test_config_yml_parses(self, agent: str):
        config_path = GUARDRAILS_DIR / agent / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        assert isinstance(config, dict)

    @pytest.mark.parametrize("agent", AGENTS)
    def test_config_has_models(self, agent: str):
        config_path = GUARDRAILS_DIR / agent / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        assert "models" in config
        assert len(config["models"]) > 0

    @pytest.mark.parametrize("agent", AGENTS)
    def test_config_uses_correct_model(self, agent: str):
        config_path = GUARDRAILS_DIR / agent / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        model = config["models"][0]
        assert model["engine"] == "anthropic"
        assert model["model"] == "claude-sonnet-4-6"

    @pytest.mark.parametrize("agent", AGENTS)
    def test_config_has_rails(self, agent: str):
        config_path = GUARDRAILS_DIR / agent / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        assert "rails" in config
        rails = config["rails"]
        assert "input" in rails
        assert "output" in rails

    @pytest.mark.parametrize("agent", AGENTS)
    def test_config_has_prompt_injection_input_rail(self, agent: str):
        config_path = GUARDRAILS_DIR / agent / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        input_flows = config["rails"]["input"]["flows"]
        assert "check prompt injection" in input_flows


class TestPromptFiles:
    @pytest.mark.parametrize("agent", AGENTS)
    def test_prompts_yml_exists(self, agent: str):
        prompts_path = GUARDRAILS_DIR / agent / "prompts.yml"
        assert prompts_path.exists(), f"Missing prompts.yml for {agent}"

    @pytest.mark.parametrize("agent", AGENTS)
    def test_prompts_yml_parses(self, agent: str):
        prompts_path = GUARDRAILS_DIR / agent / "prompts.yml"
        prompts = yaml.safe_load(prompts_path.read_text())
        assert isinstance(prompts, dict)
        assert "prompts" in prompts

    @pytest.mark.parametrize("agent", AGENTS)
    def test_prompts_has_self_check_input(self, agent: str):
        prompts_path = GUARDRAILS_DIR / agent / "prompts.yml"
        prompts = yaml.safe_load(prompts_path.read_text())
        tasks = [p["task"] for p in prompts["prompts"]]
        assert "self_check_input" in tasks

    @pytest.mark.parametrize("agent", AGENTS)
    def test_prompts_has_self_check_output(self, agent: str):
        prompts_path = GUARDRAILS_DIR / agent / "prompts.yml"
        prompts = yaml.safe_load(prompts_path.read_text())
        tasks = [p["task"] for p in prompts["prompts"]]
        assert "self_check_output" in tasks


class TestRailsFiles:
    @pytest.mark.parametrize("agent", AGENTS)
    def test_rails_co_exists(self, agent: str):
        rails_path = GUARDRAILS_DIR / agent / "rails.co"
        assert rails_path.exists(), f"Missing rails.co for {agent}"

    @pytest.mark.parametrize("agent", AGENTS)
    def test_rails_co_not_empty(self, agent: str):
        rails_path = GUARDRAILS_DIR / agent / "rails.co"
        content = rails_path.read_text()
        assert len(content.strip()) > 0

    @pytest.mark.parametrize("agent", AGENTS)
    def test_rails_defines_prompt_injection_flow(self, agent: str):
        rails_path = GUARDRAILS_DIR / agent / "rails.co"
        content = rails_path.read_text()
        assert "check prompt injection" in content

    @pytest.mark.parametrize("agent", AGENTS)
    def test_rails_defines_output_safety_flow(self, agent: str):
        rails_path = GUARDRAILS_DIR / agent / "rails.co"
        content = rails_path.read_text()
        assert "check output safety" in content or "check humaniser rules" in content


class TestAgentSpecificRails:
    def test_threat_hunter_blocks_pr_creation(self):
        rails_path = GUARDRAILS_DIR / "threat-hunter" / "rails.co"
        content = rails_path.read_text()
        assert "github_create_pr" in content

    def test_threat_hunter_enforces_findings_boundary(self):
        rails_path = GUARDRAILS_DIR / "threat-hunter" / "rails.co"
        content = rails_path.read_text()
        assert "findings/" in content

    def test_security_engineer_checks_cedar_syntax(self):
        config_path = GUARDRAILS_DIR / "security-engineer" / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        output_flows = config["rails"]["output"]["flows"]
        assert "check cedar syntax" in output_flows

    def test_threat_analyst_checks_humaniser_rules(self):
        config_path = GUARDRAILS_DIR / "threat-analyst" / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        output_flows = config["rails"]["output"]["flows"]
        assert "check humaniser rules" in output_flows

    def test_threat_analyst_checks_blog_template(self):
        config_path = GUARDRAILS_DIR / "threat-analyst" / "config.yml"
        config = yaml.safe_load(config_path.read_text())
        output_flows = config["rails"]["output"]["flows"]
        assert "check blog template conformance" in output_flows
