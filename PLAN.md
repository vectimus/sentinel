# Sentinel Hardening Plan

Status: In progress
Last updated: 2026-03-14

---

## Context

Sentinel is a security product with zero tests, empty example fixtures, no input/output validation, and no CI security scanning.  This plan addresses those gaps in priority order.

All repos are public.  All tools listed below are free and open source.

---

## Tier 1 — Before next `workflow_dispatch`

### 1.1 Example fixtures
- [ ] Real finding JSON (`shared/examples/incidents/example-finding.json`)
- [ ] Real incident record (`shared/examples/incidents/example-incident.json`)
- [ ] Real blog post (`shared/examples/blog_posts/example-blog-post.md`)
- [ ] Real incident brief (`shared/examples/blog_posts/example-brief.md`)
- [ ] Cedar test fixture pair — should-block + should-allow (`tests/fixtures/cedar/`)

### 1.2 Schema validation
- [ ] Add enums to Pydantic schemas: `coverage_status`, `recommended_action`, `content_angle`, `owasp_category`, `content_type`, `policy_status`, `content_status`
- [ ] Add datetime validation to `discovered_at`, `incident_date` fields
- [ ] Add VTMS ID format validation (`VTMS-YYYY-NNNN` regex)
- [ ] Add cross-field validation: `gap_description` required when `coverage_status == "gap"`
- [ ] Validate findings against schema in `run_threat_hunter()` before returning
- [ ] Validate findings in `run_security_engineer()` and `run_threat_analyst()` on load

### 1.3 Test infrastructure
- [ ] `pytest.ini` or `pyproject.toml` [tool.pytest] config
- [ ] `tests/conftest.py` with shared fixtures (mock D1, mock R2, mock GitHub, sample findings)
- [ ] `tests/test_schemas.py` — Pydantic models accept valid data, reject invalid data
- [ ] `tests/test_d1_client.py` — D1Client methods with mocked httpx
- [ ] `tests/test_r2_client.py` — R2Client methods with mocked boto3
- [ ] `tests/test_github_client.py` — GitHubClient methods with mocked PyGithub
- [ ] `tests/test_pushover_client.py` — PushoverClient with mocked httpx
- [ ] `tests/test_cedar_sandbox.py` — CedarSandbox with real cedarpy (no mocking needed)
- [ ] `tests/test_mcp_server.py` — MCP tool functions with mocked clients
- [ ] `tests/test_orchestrator.py` — Orchestrator with mocked agent runners
- [ ] Add `pytest` step to GitHub Actions workflow (before pipeline run)

### 1.4 Gitleaks
- [ ] Add `.gitleaks.toml` config
- [ ] Add Gitleaks pre-commit hook
- [ ] Add Gitleaks step to GitHub Actions workflow

---

## Tier 2 — Credible security product

### 2.1 Guardrailing
- [ ] Integrate **NeMo Guardrails** (`nemoguardrails`, Apache 2.0) as primary guardrailing layer
  - Input rails: scan web-fetched content for prompt injection before agent context
  - Execution rails: monitor tool call inputs/outputs (complements Cedar policies)
  - Output rails: validate agent responses before they reach D1/GitHub
  - Colang dialogue policies: enforce agent role boundaries and workflow constraints
  - Config per agent: `guardrails/threat-hunter/`, `guardrails/security-engineer/`, `guardrails/threat-analyst/`
- [ ] Integrate **Guardrails AI** (`guardrails-ai`, Apache 2.0) for structured output validation
  - Validate findings JSON against schema with auto-retry on malformed output
  - Validate Cedar policy syntax before PR creation
  - Validate blog post/brief structure against templates

### 2.2 SAST in CI
- [ ] Add Semgrep to GitHub Actions (`semgrep/semgrep-action`)
  - 166+ Python security rules
  - Custom rules for agent-specific patterns (unsanitised tool params, missing validation)
- [ ] Add Bandit to GitHub Actions (`pip install bandit`)
  - Python-specific: SQL injection, hardcoded passwords, subprocess calls
  - Fast, good for pre-commit too

### 2.3 Dependency management
- [ ] Enable Dependabot on all Vectimus repos
  - Auto-PRs for security updates
  - Configure auto-merge for patch updates
- [ ] Pin exact versions in `requirements.txt` (currently uses `>=` — reproducibility risk)

### 2.4 Agent evaluation
- [x] Promptfoo eval suite (MIT, CLI tool)
  - Test: prompt injection resistance (8 adversarial test cases)
  - Test: role boundary enforcement (8 cross-agent violation tests)
  - Test: output quality (blog template, humaniser rules, Cedar annotations, OWASP classification)
  - Declarative YAML configs, runs in CI (manual dispatch — costs LLM tokens)
- [x] Cisco MCP Scanner (`pip install cisco-ai-mcp-scanner`)
  - Static YARA scan of all 11 MCP tool definitions
  - CI workflow runs on push to pipeline/agents/guardrails/evals paths
  - Export script generates tool JSON from FastMCP server without env vars

---

## Tier 3 — Production hardening

### 3.1 Observability
- [x] Arize Phoenix (ELv2, in-process) — replaced Langfuse for zero-infra simplicity
  - Auto-instruments Claude Agent SDK via OpenInference
  - Traces every LLM call, tool call, agent span with full parent-child nesting
  - Exports traces as JSON artifacts on each pipeline run (90-day retention)
  - Disable via `SENTINEL_DISABLE_TRACING=1` env var
- [x] OpenTelemetry instrumentation via `openinference-instrumentation-claude-agent-sdk`

### 3.2 Deep analysis
- [ ] CodeQL on PRs (free for public repos via `github/codeql-action`)
  - Custom queries for agent-specific security patterns
- [ ] Trivy for dependency + container scanning (`aquasecurity/trivy-action`)

### 3.3 Hallucination detection
- [ ] DeepEval faithfulness metrics (Apache 2.0)
  - Verify agents aren't fabricating CVE IDs, VTMS references, policy names
  - Pytest plugin, runs alongside unit tests
- [ ] Inspect AI sandboxed evals (MIT, UK AISI)
  - Cybersecurity evaluation suite
  - Sandboxed execution (Docker) for safe agent testing

### 3.4 Red-teaming
- [ ] Augustus (Apache 2.0, Praetorian)
  - 210+ adversarial probes across 47 attack categories
  - Single Go binary, run against each agent's system prompt
- [ ] DeepTeam (open source, Confident AI)
  - 50+ vulnerability types, 20+ automated attack methods
  - Python package, scheduled CI runs

---

## Recommended CI Pipeline

```
Pre-commit:   Bandit + Gitleaks
PR checks:    pytest + Semgrep + CodeQL + schema validation
Merge:        Trivy (deps)
Scheduled:    Dependabot + full Trivy scan + Cisco MCP Scanner
Pipeline run: LLM Guard (I/O) → Agent → Pydantic validation → D1
```

---

## Tool Reference

| Tool | License | Cost | Install |
|---|---|---|---|
| Gitleaks | MIT | Free | `brew install gitleaks` / Go binary |
| Semgrep | LGPL | Free (community) | `pip install semgrep` |
| Bandit | Apache 2.0 | Free | `pip install bandit` |
| CodeQL | MIT | Free (public repos) | `github/codeql-action` |
| Trivy | Apache 2.0 | Free | `aquasecurity/trivy-action` |
| Dependabot | GitHub | Free | GitHub native |
| LLM Guard | MIT | Free (CPU cost) | `pip install llm-guard` |
| LlamaFirewall | Meta OSS | Free (+ LLM call) | `pip install llamafirewall` |
| Promptfoo | MIT | Free (+ LLM calls) | `npx promptfoo@latest` |
| DeepEval | Apache 2.0 | Free (+ LLM calls) | `pip install deepeval` |
| Inspect AI | MIT | Free | `pip install inspect-ai` |
| Langfuse | MIT | Free (self-host) | Docker / docker-compose |
| Cisco MCP Scanner | Apache 2.0 | Free | `pip install cisco-ai-mcp-scanner` |
| Augustus | Apache 2.0 | Free | Go binary |
| DeepTeam | OSS | Free (+ LLM calls) | `pip install deepteam` |

---

## Files to create / modify

### Tier 1

| File | Action |
|---|---|
| `shared/examples/incidents/example-finding.json` | Create |
| `shared/examples/incidents/example-incident.json` | Create |
| `shared/examples/blog_posts/example-blog-post.md` | Create |
| `shared/examples/blog_posts/example-brief.md` | Create |
| `tests/fixtures/cedar/should-block.json` | Create |
| `tests/fixtures/cedar/should-allow.json` | Create |
| `pipeline/schemas/finding.py` | Modify — add enums, validators |
| `pipeline/schemas/incident.py` | Modify — add enums, validators |
| `pipeline/schemas/content.py` | Modify — add enums |
| `pipeline/agents/threat_hunter.py` | Modify — validate output |
| `pipeline/agents/security_engineer.py` | Modify — validate input |
| `pipeline/agents/threat_analyst.py` | Modify — validate input |
| `pyproject.toml` | Create — pytest config |
| `tests/conftest.py` | Create |
| `tests/test_schemas.py` | Create |
| `tests/test_d1_client.py` | Create |
| `tests/test_r2_client.py` | Create |
| `tests/test_github_client.py` | Create |
| `tests/test_pushover_client.py` | Create |
| `tests/test_cedar_sandbox.py` | Create |
| `tests/test_mcp_server.py` | Create |
| `tests/test_orchestrator.py` | Create |
| `.gitleaks.toml` | Create |
| `.github/workflows/sentinel-pipeline.yml` | Modify — add pytest + gitleaks steps |
