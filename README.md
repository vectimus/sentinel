# Vectimus Sentinel

**Three AI agents that discover agentic AI security threats, write Cedar policies to stop them, then prove the policies work in a replay sandbox.  The pipeline is governed by Vectimus.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Sentinel is an agentic AI workflow built from three specialised agents, each named after a standard SOC role.  Threat Hunter scans for emerging incidents across the agentic AI security landscape: coding agents, agentic frameworks, MCP servers and tool-calling infrastructure.  Security Engineer drafts Cedar policies and replays the incident in the Vectimus policy evaluation sandbox to verify the policy catches it.  If it does, Threat Analyst writes the advisory and incident analysis.  All three open PRs.  A human reviews.  The policy ships.

The entire pipeline is governed by Vectimus Cedar policies.  The agents that write governance rules are themselves governed by the same system.

Every PR, every finding, every policy draft is public.  The full pipeline, its source and its output are open for anyone to inspect.

<!-- TODO: Add demo GIF showing pipeline discovering an incident, drafting a policy, and sandbox replay proving it works -->

---

## Why this exists

Agentic AI security moves fast.  New MCP vulnerabilities, tool poisoning techniques and agent exploitation methods appear weekly.  A policy library that only updates when a human finds time to read CVE feeds falls behind within days.

Sentinel keeps the [Vectimus policy library](https://github.com/vectimus/policies) current by doing what a dedicated security research team would do, but running daily at 07:00 UTC and producing auditable, testable output.

Sentinel does not limit itself to tools and frameworks that Vectimus currently supports.  An incident on a non-supported agent or framework may reveal an attack pattern that affects supported ones.  The threat landscape is the scope, not the integration list.

When the [Trivy/LiteLLM supply chain cascade](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack) hit in March 2026, it affected 5 ecosystems and 36% of cloud environments within days.  A manually maintained policy library cannot respond at that speed.  Sentinel can.

## What makes this different

**Policy evaluation sandbox.**  Sentinel doesn't just draft Cedar policies.  The Security Engineer agent reconstructs the incident scenario and replays it against the new policy in the Vectimus evaluation sandbox.  The sandbox runs the full Cedar authorization path: entity construction, context assembly and policy evaluation, proving the policy produces the correct deny decision for the attack and the correct allow decision for legitimate use.  If the policy doesn't catch the attack, it doesn't ship.  Every PR includes the replay scenario and the evaluation result.

**Recursive governance.**  Sentinel's own tool calls are governed by Vectimus Cedar policies.  The agents that write governance rules operate under the same governance system.  This is live dogfooding, not a claim in a pitch deck.

**Open threat intelligence.**  Every VTMS advisory, every finding, every policy PR is public and auditable.  The JSON feed at `/api/feed.json` is machine-readable so security teams can consume it programmatically.  No login wall, no gated content.  The pipeline source itself is Apache 2.0.

**Multi-framework classification.**  Incidents are classified against OWASP Agentic Top 10, NIST AI RMF, CIS Controls and linked to relevant CVEs where they exist.  Each VTMS advisory carries structured annotations so policies can be traced back to the standards that matter to your compliance team.

**VTMS identifiers.**  Every incident gets a canonical ID (`VTMS-YYYY-NNNN`).  Structured identifiers make incidents citable, searchable and trackable across policies, audit logs and advisory content.

---

## How it works

Three AI agents execute in a staged, sequential pipeline.  Each stage depends on the output of the one before it.

1. **Threat Hunter** scans sources across the agentic AI security landscape, discovers incidents, classifies against OWASP Agentic Top 10, NIST AI RMF and CIS Controls, scores severity, links CVEs and assigns VTMS identifiers
2. **Security Engineer** drafts Cedar policies, runs the incident through the Vectimus policy evaluation sandbox to prove the policy catches it, opens PRs to [`vectimus/policies`](https://github.com/vectimus/policies)
3. **Threat Analyst** writes incident analysis blog posts and advisories using the verified policy and sandbox results, opens PRs to the website

The pipeline finishes with a Pushover digest and GitHub Actions summary.  Currently runs on GitHub Actions with Anthropic Claude.  The pipeline is designed to be provider and platform-portable.

```
GitHub Actions (daily 07:00 UTC)
│
├── Stage 1: Threat Hunter
│   └── Output: findings/<date>.json
│
├── Stage 2: Security Engineer
│   └── Sandbox verification → PRs → vectimus/policies
│
├── Stage 3: Threat Analyst
│   └── Advisory content → PRs → website
│
└── Stage 4: Pushover digest + GitHub Actions summary
```

---

## Dashboard and API

Live threat intelligence: [vectimus.com/threats](https://vectimus.com/threats)

| Endpoint | Description |
|----------|-------------|
| `GET /api/incidents` | Paginated, filterable incident list |
| `GET /api/incidents/:vtms_id` | Single incident detail |
| `GET /api/trends` | Trend data with deltas |
| `GET /api/coverage` | Policy coverage by OWASP category |
| `GET /api/feed.json` | JSON Feed for programmatic consumption |

---

## Cross-repo architecture

| Repo | Purpose | Sentinel writes |
|------|---------|-----------------|
| [`vectimus/sentinel`](https://github.com/vectimus/sentinel) | Pipeline code, agent specs, findings | Threat Hunter commits findings |
| [`vectimus/policies`](https://github.com/vectimus/policies) | Cedar policies, test fixtures | Security Engineer opens PRs |
| [vectimus.com](https://vectimus.com) | Blog posts, advisories, threat dashboard | Threat Analyst opens PRs |

---

## Quickstart

```bash
git clone https://github.com/vectimus/sentinel.git
cd sentinel

pip install -r pipeline/requirements.txt

# Set environment variables (see .env.example and HANDOVER.md for full list)
export ANTHROPIC_API_KEY=...
export CLOUDFLARE_ACCOUNT_ID=...

python -m pipeline.orchestrator
```

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

Sentinel is Apache 2.0.  Contributions welcome across the pipeline:

- **New threat sources** for the Threat Hunter
- **Sandbox replay improvements** for the Security Engineer
- **Advisory templates** for the Threat Analyst
- **Pipeline tooling** and orchestration enhancements

Open an issue or submit a PR.

---

## License

[Apache 2.0](LICENSE)
