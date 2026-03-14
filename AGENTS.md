# AGENTS.md — Vectimus Sentinel

## Overview

Vectimus Sentinel is an automated threat intelligence pipeline for agentic AI security.  It discovers incidents, assesses Cedar policy coverage, drafts new policies with sandbox-verified test cases, and produces incident analysis content.  It runs daily via GitHub Actions.

Three agents execute in a staged pipeline.  Each is named after a standard SOC (Security Operations Centre) role: Threat Hunter, Security Engineer, Threat Analyst.  These aren't invented names.  They're the same roles found in every professional security operation.

## Agents

Each agent has its own directory and self-contained `AGENTS.md`.  At runtime, each agent receives only its own spec.  No agent sees another agent's instructions.

| Agent | Directory | SOC Role | Responsibility |
|-------|-----------|----------|----------------|
| Threat Hunter | `agents/threat-hunter/` | Proactive threat discovery | Scans sources, discovers incidents, classifies, scores severity, assigns VTMS identifiers |
| Security Engineer | `agents/security-engineer/` | Control design and validation | Drafts Cedar policies, runs incident replay sandbox, manages policy versioning, opens PRs in `vectimus/policies` |
| Threat Analyst | `agents/threat-analyst/` | Intelligence reporting | Writes incident analysis blog posts, briefs and social content for vectimus.com |

## Pipeline Architecture

Three agents execute in a staged, sequential pipeline.  Each stage depends on the output of the one before it.

```
┌──────────────────────────────────────────────────────────────┐
│                  GitHub Actions (daily cron)                  │
│                  Repo: vectimus/sentinel                      │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              STAGE 1: Threat Hunter                     │  │
│  │                                                        │  │
│  │  Output: findings/<date>.json                          │  │
│  │  Writes: D1 incidents table, R2 source archive         │  │
│  └───────────────────────┬────────────────────────────────┘  │
│                          │                                    │
│                 findings/<date>.json                          │
│                          │                                    │
│  ┌───────────────────────┴────────────────────────────────┐  │
│  │              STAGE 2: Security Engineer                  │  │
│  │                                                        │  │
│  │  Sandbox verification → PRs → vectimus/policies        │  │
│  │  Updates: D1 (policy status, VERSION, CHANGELOG)       │  │
│  └───────────────────────┬────────────────────────────────┘  │
│                          │                                    │
│              sandbox results + policy PRs                     │
│                          │                                    │
│  ┌───────────────────────┴────────────────────────────────┐  │
│  │              STAGE 3: Threat Analyst                     │  │
│  │                                                        │  │
│  │  Uses verified policy and sandbox results               │  │
│  │  Advisory content → PRs → vectimus/vectimus-website    │  │
│  │  Updates: D1 (content links), R2 (draft archive)       │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              STAGE 4: Notification                      │  │
│  │                                                        │  │
│  │  Pushover digest + critical alerts                     │  │
│  │  GitHub Actions job summary                            │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Policy Release Flow

When Security Engineer PRs are merged in `vectimus/policies`:

1. You review and merge the policy PR.
2. A release workflow in `vectimus/policies` tags the new semver version.
3. `notify-consumers.yml` dispatches repository events to consuming repos.
4. `vectimus/vectimus` and `vectimus/openclaw` receive automated sync PRs.
5. You review and merge the sync PRs.
6. Next `pip install vectimus` / `npm install` picks up the new policies.

### Cloudflare Infrastructure

| Service | Name | Purpose |
|---------|------|---------|
| D1 | `vectimus-incidents` | Incident database, trends, content metadata |
| R2 | `vectimus-research-archive` | Raw source articles, findings, content drafts |
| Workers | `vectimus-api` | Public API and dashboard at vectimus.com/threats |

Worker endpoints: `/api/incidents`, `/api/incidents/:id`, `/api/trends`, `/api/coverage`, `/api/feed.json`

## Cross-Repo Architecture

| Repo | Visibility | Who writes | What |
|------|-----------|------------|------|
| `vectimus/sentinel` | Public | Pipeline code lives here.  Threat Hunter commits findings per run. | Agent specs, orchestrator, Cloudflare Worker, findings, pipeline config |
| `vectimus/policies` | Public | Security Engineer raises PRs | Cedar policies, test fixtures, CHANGELOG, VERSION, manifest.json |
| `vectimus/vectimus-website` | Private (for now) | Threat Analyst raises PRs | Blog posts, incident briefs, dashboard page content |
| `vectimus/vectimus` | Public | Automated sync PRs from policies repo | Python package, engine, integrations |

The `vectimus-sentinel` bot account needs write access to `sentinel`, `policies` and `vectimus-website`.

## VTMS Identifier Scheme

Every incident gets a canonical ID: `VTMS-YYYY-NNNN` (discovery year, zero-padded sequential number).  Sequence maintained in D1.

These appear in: Cedar policy annotations, test fixtures, blog posts, PR titles, the public API, the dashboard, CHANGELOG entries.

The goal is to establish VTMS as the standard reference for agentic AI security incidents, analogous to CVE for software vulnerabilities.

## Governance

The pipeline runs through Vectimus.  The `.vectimus/` config governs all three agents' tool calls via Cedar policies on the GitHub Actions runner.  Recursive governance: the governance tool's own research pipeline is governed by itself.

## Notification Design

### Severity Routing

| Severity | PR? | Pushover? | Timing |
|----------|-----|-----------|--------|
| 5 (critical) | Yes | Immediate alert | During Threat Hunter phase |
| 4 (high) | Yes | In digest | After pipeline completes |
| 3 (medium) | If policy change needed | Digest only | After pipeline completes |
| 2 (low) | If policy change needed | Digest only | After pipeline completes |
| 1 (theoretical) | No | Digest only | After pipeline completes |

### PR Conventions

Policy PRs (in `vectimus/policies`): `[VTMS-2026-NNNN] [SEVERITY] <action>: <description>`
Content PRs (in `vectimus/vectimus-website`): `[VTMS-2026-NNNN] [CONTENT] <title>`

Branch naming: `sentinel/policy/<vtms-id>` or `sentinel/content/<vtms-id>`

Labels: `policy-draft` or `content-draft` plus severity label.

Reviewer: `joe@vectimus.com` GitHub account.

Bot author: `vectimus-sentinel` (write access, not admin).

### Daily Digest

```
Vectimus Sentinel — 2026-03-14

Scanned: 47 sources
New incidents: 3
  VTMS-2026-0042 [HIGH] Supply chain attack via MCP
  VTMS-2026-0043 [MEDIUM] Cursor config override via .cursorrules
  VTMS-2026-0044 [LOW] Agent hallucinated API endpoint

Policy PRs: 2 (vectimus/policies)
Content PRs: 1 (vectimus/sentinel)
Gaps found: 1
Policy set version: 1.14.0 → 1.15.0 (proposed)

Run time: 4m 32s
```

## Security Considerations

### Benefits of public visibility

The entire pipeline is public.  This is deliberate.  Transparency builds trust for a governance tool.  Users can audit the methodology, the incident classification, the Cedar policies, the sandbox replay results.  Contributors can submit incidents, suggest policies, challenge classifications.

### Attack surfaces and mitigations

**Prompt injection via source material.**  The Threat Hunter fetches articles from the web.  A malicious page could inject instructions into the agent's context.  Mitigation: Vectimus governs the agent's tool calls via Cedar policies.  Even if reasoning is compromised, destructive actions are blocked.  The bot account can open PRs but cannot merge.  Human review is the final gate.

**Workflow manipulation.**  The GitHub Actions YAML is public.  Someone could PR a workflow change to exfiltrate secrets.  Mitigation: require approval before workflows from outside collaborators run.  Secrets are never exposed to fork PRs (GitHub default behaviour).

**Policy poisoning.**  A contributed PR could contain a subtly flawed Cedar policy (e.g., a regex bypass).  Mitigation: human review on all policy merges.  Sandbox replay results in the PR body surface obvious failures.  Over time, adversarial test fixtures can be added to catch bypass attempts.

**Coverage gap intelligence.**  The public incident database shows what Vectimus does and doesn't cover.  An attacker could target uncovered patterns.  Mitigation: gap details stay in draft PRs until the fix is ready.  The dashboard shows coverage percentages without revealing specific gap mechanics.  This is responsible disclosure applied to our own framework.

**D1/R2 access.**  Cloudflare API tokens are in GitHub secrets.  Runner compromise could expose them.  Mitigation: use least-privilege API tokens (D1 write to specific database only, R2 write to specific bucket only).  Rotate tokens quarterly.

## Directory Structure

```
vectimus/sentinel/
├── AGENTS.md                          # This file
├── README.md                          # Public-facing README (demo, quickstart, badges)
├── agents/
│   ├── threat-hunter/
│   │   └── AGENTS.md                  # Threat Hunter spec (AIM + RPI)
│   ├── security-engineer/
│   │   └── AGENTS.md                  # Security Engineer spec (AIM + RPI)
│   └── threat-analyst/
│       └── AGENTS.md                  # Threat Analyst spec (AIM + RPI)
├── shared/
│   ├── schemas/
│   │   ├── d1_schema.sql              # D1 table definitions
│   │   ├── finding_schema.json        # Finding JSON schema
│   │   └── cedar_conventions.md       # Cedar policy writing guide
│   ├── examples/
│   │   ├── incidents/                 # Example incidents with policies
│   │   ├── fixtures/                  # Example test fixtures
│   │   └── blog_posts/               # Example blog posts
│   └── templates/
│       ├── blog_post.md               # Blog post template
│       ├── incident_brief.md          # Brief template
│       └── pr_body.md                 # PR description template
├── pipeline/
│   ├── orchestrator.py                # Runs agents in sequence/parallel
│   ├── agents/                        # Agent runner implementations
│   ├── tools/                         # D1, R2, Pushover, GitHub, Cedar clients
│   ├── prompts/                       # System prompts (generated from agent AGENTS.md)
│   ├── schemas/                       # Python dataclasses
│   └── config.py                      # Pipeline configuration
├── findings/                          # Per-run research output
├── content/
│   ├── blog/                          # Blog post drafts
│   └── briefs/                        # Incident briefs
├── cloudflare/
│   ├── wrangler.toml                  # Worker + D1 + R2 config
│   ├── src/                           # Worker API code
│   └── dashboard/                     # Threats dashboard
├── .claude/
│   └── CLAUDE.md                      # Points to AGENTS.md
├── .vectimus/                         # Vectimus config (recursive governance)
├── .github/
│   └── workflows/
│       └── sentinel-pipeline.yml      # Daily cron
├── thoughts/                          # Agent working memory
└── tests/
    └── fixtures/                      # Cedar test fixtures
```
