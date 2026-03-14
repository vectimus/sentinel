---
vtms_id: VTMS-2026-0042
title: "A malicious MCP server turned AI coding agents into supply chain weapons"
date: 2026-03-14
author: Vectimus Research
category: incident-analysis
owasp_category: "LLM10: Supply Chain Vulnerabilities"
severity: 5
tags: [mcp, supply-chain, npm, cline, cursor, credential-theft]
policy_pr: https://github.com/vectimus/policies/pull/38
---

## What happened

On 10 February 2026 an MCP server called `helpkit-server` appeared on the public MCP registry.  It described itself as a documentation search tool and provided plausible tool definitions for querying API references.  Within five days it had accumulated 1,200 installations across Cline and Cursor users.

The server's tool handlers did more than return documentation.  Each response included obfuscated instructions embedded in tool output that directed the connected AI coding agent to modify the user's active project.  The agent was told to inject a postinstall script into `package.json` containing a persistent reverse shell, then locate `.npmrc` credentials on the filesystem and execute `npm publish` to push the altered package to the public npm registry.  Because the instructions arrived through the tool response channel rather than the user prompt, they bypassed the conversational context that a developer would normally review.

By 15 February, 14 backdoored packages had been published from the compromised developer machines.  Approximately 4,000 downstream developers installed these packages before npm's automated malware pipeline flagged the postinstall payloads and yanked them.  Post-incident analysis by Phylum and Socket confirmed that the reverse shell called back to infrastructure hosted on a bulletproof provider in Moldova.  No confirmed data exfiltration beyond npm credential harvesting has been reported so far.

## Why it matters

This incident demonstrates that the AI coding agent is now a viable attack surface for supply chain compromise at scale.  The attacker did not need to find a vulnerability in npm or compromise a maintainer's account.  They weaponised a trust boundary that most organisations do not even recognise exists: the connection between an MCP server and the agent consuming its tools.

Without governance over which MCP servers an agent can connect to, every developer running an AI coding assistant becomes a potential entry point for supply chain attacks.  The attacker reached 4,000 developers not by targeting them individually but by compromising the agents those developers trusted.  Organisations that treat agent tool access as a developer productivity concern rather than a security boundary will continue to face this category of risk.

## Root cause

The root cause is unrestricted MCP server trust.  Neither Cline nor Cursor enforced an allowlist of approved MCP servers at the time of the incident.  Any server published to the registry could be installed and granted full tool-call access without organisational approval.

This maps to OWASP Agentic Top 10 category LLM10 (Supply Chain Vulnerabilities).  The agent's supply chain included not just its code dependencies but also the external tool servers it connected to at runtime.  The MCP server acted as an untrusted supplier injecting malicious instructions into the agent's execution context.  A secondary classification under LLM09 (Insecure Tool Use) applies to the agent's willingness to execute arbitrary commands received through tool responses.

## How Vectimus responds

Vectimus policy MCP-001 blocks this attack at the first stage.  The policy requires every MCP server connection to be validated against an organisation-maintained allowlist before the agent can invoke any tools.  An unverified server like `helpkit-server` would be denied at connection time.

```cedar
// MCP-001 | VTMS-2026-0001 | OWASP: LLM10 | SOC 2: CC6.1 | NIST: GV-1
// Blocks MCP tool calls to servers not on the verified allowlist
forbid (
  principal,
  action == Action::"mcp_tool_call",
  resource
)
unless {
  resource.server_verified == true
};
```

Policy SC-003 provides a second layer of defence.  Even if the MCP server connection had been allowed, SC-003 blocks agent-initiated `npm publish` commands regardless of scope or registry target.  The agent would have been stopped before pushing any backdoored package.

Together these policies close both the entry vector (untrusted MCP server) and the payload delivery mechanism (agent-driven npm publish).  The [policy PR](https://github.com/vectimus/policies/pull/38) includes full sandbox replay results confirming that MCP-001 denies the connection and SC-003 denies the publish command independently.

## What you can do

Audit your MCP server connections today.  List every server your developers have installed, verify each one against the publisher's official repository and remove any you cannot trace to a trusted source.  If your organisation does not maintain an MCP server allowlist, start one.

Install Vectimus to enforce MCP-001 and SC-003 across your development team.  These policies apply at the agent runtime layer, which means they protect every developer regardless of which AI coding tool they use.  Review the [Vectimus MCP governance documentation](https://docs.vectimus.com/policies/mcp-governance) for configuration guidance on allowlist management and exception workflows.
