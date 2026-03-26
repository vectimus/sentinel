# Vectimus Sentinel

**Autonomous threat-to-policy pipeline. Three AI agents discover agentic AI security threats, write Cedar policies, prove them in a sandbox, then open PRs for human review.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Your policies stay current without you reading CVE feeds. Sentinel runs daily at 07:00 UTC and produces auditable, testable output. Every finding, every policy draft, every advisory is public.

The agents that write governance rules operate under the same governance system.

---

## Why

- **Agentic AI security moves fast.** New MCP vulnerabilities, tool poisoning techniques and agent exploitation methods appear weekly.
- **Policy libraries fall behind.** A library that only updates when a human reads threat feeds goes stale within days.
- **Manual research doesn't scale.** Sentinel does what a dedicated security research team would do, but runs every morning and ships machine-verifiable output.

---

## The three agents

Named after standard SOC roles. Each stage depends on the output of the one before it.

### Threat Hunter

Scans sources across the agentic AI security landscape: coding agents, agentic frameworks, MCP servers, tool-calling infrastructure. Discovers incidents, classifies them against OWASP Agentic Top 10, NIST AI RMF and CIS Controls, scores severity, links CVEs and assigns VTMS identifiers (`VTMS-YYYY-NNNN`).

**Output:** `findings/<date>.json`

### Security Engineer

Drafts Cedar policies for each finding. Reconstructs the incident scenario and replays it in the Vectimus policy evaluation sandbox. The sandbox runs the full Cedar authorization path: entity construction, context assembly and policy evaluation. If the policy doesn't catch the attack, it doesn't ship.

**Output:** PRs to [`vectimus/policies`](https://github.com/vectimus/policies) with replay scenarios and evaluation results attached.

### Threat Analyst

Writes incident analysis and advisories using the verified policy and sandbox results. Produces structured content with multi-framework classification annotations.

**Output:** PRs to [`vectimus/vectimus-website`](https://github.com/vectimus/vectimus-website)

---

## What makes this different

- **Sandbox verification, not vibes.** Every policy is proven against a reconstructed attack scenario before it reaches a PR. The sandbox runs real Cedar evaluation, not string matching.
- **Recursive governance.** Sentinel's own tool calls are governed by Vectimus Cedar policies. Live dogfooding, not a claim in a pitch deck.
- **Open threat intelligence.** Every VTMS advisory and finding is public. The JSON feed is machine-readable. No login wall, no gated content.
- **VTMS identifiers.** Every incident gets a canonical ID (`VTMS-YYYY-NNNN`). Citable, searchable, trackable across policies, audit logs and advisory content.
- **Multi-framework classification.** Findings map to OWASP Agentic Top 10, NIST AI RMF, CIS Controls and linked CVEs. Structured annotations trace policies back to compliance standards.
- **Human-in-the-loop.** Agents open PRs. Humans review and merge. Automation handles discovery and drafting. Humans own the decision.

---

## Pipeline

```
GitHub Actions (daily 07:00 UTC)
│
├─ Stage 1: Threat Hunter
│  ├─ Scan sources, classify incidents
│  └─ Output: findings/<date>.json
│
├─ Stage 2: Security Engineer
│  ├─ Draft Cedar policies
│  ├─ Replay in sandbox → verify deny/allow
│  └─ Output: PRs → vectimus/policies
│
├─ Stage 3: Threat Analyst
│  ├─ Write advisories and analysis
│  └─ Output: PRs → vectimus/vectimus-website
│
└─ Digest: Pushover notification + GitHub Actions summary
```

---

## Dashboard and API

Live threat intelligence at [vectimus.com/threats](https://vectimus.com/threats).

| Endpoint | What it returns |
|----------|-----------------|
| `GET /api/incidents` | Paginated, filterable incident list |
| `GET /api/incidents/:vtms_id` | Single incident detail |
| `GET /api/trends` | Trend data with deltas |
| `GET /api/coverage` | Policy coverage by OWASP category |
| `GET /api/feed.json` | JSON Feed for programmatic consumption |

All endpoints are public. No authentication required.

Read published advisories and incident analysis at [vectimus.com/blog](https://vectimus.com/blog).

---

## Cross-repo architecture

| Repo | Purpose | Sentinel writes to |
|------|---------|-------------------|
| [`vectimus/sentinel`](https://github.com/vectimus/sentinel) | Pipeline code, agent specs, findings | Threat Hunter commits findings |
| [`vectimus/vectimus`](https://github.com/vectimus/vectimus) | Core policy engine, Cedar evaluation, CLI | Sentinel operates under its policies |
| [`vectimus/policies`](https://github.com/vectimus/policies) | Cedar policies, test fixtures | Security Engineer opens PRs |
| [`vectimus/vectimus-website`](https://github.com/vectimus/vectimus-website) | Blog posts, advisories, threat dashboard | Threat Analyst opens PRs |

---

## Quick start

```bash
git clone https://github.com/vectimus/sentinel.git
cd sentinel

pip install -r pipeline/requirements.txt

# Copy .env.example and fill in your keys
export ANTHROPIC_API_KEY=...
export CLOUDFLARE_ACCOUNT_ID=...

# Run the full pipeline
python -m pipeline.orchestrator
```

See `HANDOVER.md` for the full environment variable reference.

---

## Project structure

```
sentinel/
├── agents/              # Agent specifications and prompts
│   ├── threat-hunter/
│   ├── security-engineer/
│   └── threat-analyst/
├── pipeline/            # Orchestrator, tools, schemas, config
├── _sandbox/            # Policy evaluation sandbox
├── findings/            # Threat Hunter output (JSON)
├── guardrails/          # Vectimus policies governing Sentinel itself
├── evals/               # Pipeline evaluation suite
├── tests/               # Test suite
└── scripts/             # Utility scripts
```

---

## Contributing

Sentinel is Apache 2.0. Contributions welcome across the pipeline:

- **New threat sources** for the Threat Hunter
- **Sandbox replay improvements** for the Security Engineer
- **Advisory templates** for the Threat Analyst
- **Pipeline tooling** and orchestration enhancements

Open an issue or submit a PR. The pipeline itself runs on GitHub Actions with Anthropic Claude.

---

## License

[Apache 2.0](LICENSE)
