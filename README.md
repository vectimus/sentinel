# Vectimus Sentinel

**Automated threat intelligence for agentic AI security.**

Sentinel monitors threats targeting Claude Code, Cursor, GitHub Copilot, LangGraph, Google ADK and Claude Agent SDK.  It discovers incidents, assesses Cedar policy coverage, drafts new policies with sandbox-verified test cases, and produces incident analysis content.  Runs daily via GitHub Actions.

<!-- TODO: Add demo GIF showing pipeline discovering an incident, drafting a policy, and sandbox replay proving it works -->

## How it works

Three AI agents execute in a staged pipeline, each named after a standard SOC role:

1. **Threat Hunter** scans sources, discovers incidents, classifies by OWASP Agentic Top 10, scores severity, assigns VTMS identifiers
2. **Security Engineer** drafts Cedar policies, runs incident replay sandbox to prove they work, opens PRs in [`vectimus/policies`](https://github.com/vectimus/policies)
3. **Threat Analyst** writes incident analysis blog posts and briefs, opens PRs for the website

The pipeline runs through Vectimus itself.  Recursive governance: the governance tool's own research pipeline is governed by its own Cedar policies.

## VTMS Identifiers

Every incident gets a canonical ID: VTMS-YYYY-NNNN.  Structured identifiers make incidents citable, searchable and trackable across policies, audit logs and advisory content.

## Quickstart

```bash
# Clone the repo
git clone https://github.com/vectimus/sentinel.git
cd sentinel

# Install dependencies
pip install -r pipeline/requirements.txt

# Set environment variables (see .env.example)
export ANTHROPIC_API_KEY=...
export CLOUDFLARE_ACCOUNT_ID=...
# ... (see HANDOVER.md for full list)

# Run the pipeline
python -m pipeline.orchestrator
```

## Architecture

```
GitHub Actions (daily 07:00 UTC)
│
├── Stage 1: Threat Hunter (sequential)
│   └── Output: findings/<date>.json → D1, R2
│
├── Stage 2a: Security Engineer (parallel)
│   └── PRs → vectimus/policies
│
├── Stage 2b: Threat Analyst (parallel)
│   └── PRs → vectimus/vectimus-website
│
└── Stage 3: Pushover digest + GitHub Actions summary
```

## Dashboard

Live threat intelligence dashboard: [vectimus.com/threats](https://vectimus.com/threats)

API endpoints:
- `GET /api/incidents` — paginated, filterable
- `GET /api/incidents/:vtms_id` — single incident
- `GET /api/trends` — trend data with deltas
- `GET /api/coverage` — policy coverage by OWASP category
- `GET /api/feed.json` — JSON Feed

## Cross-Repo Architecture

| Repo | What | Writes |
|------|------|--------|
| `vectimus/sentinel` | Pipeline code, agent specs, findings | Threat Hunter commits findings |
| `vectimus/policies` | Cedar policies, test fixtures | Security Engineer opens PRs |
| `vectimus/vectimus-website` | Blog posts, incident briefs | Threat Analyst opens PRs |

## License

Apache 2.0
