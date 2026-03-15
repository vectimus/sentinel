// AI agent marketplace extension safety -- block connections to marketplace-sourced
// MCP extensions that have not passed automated integrity verification, and block
// connections to MCP servers bound to all interfaces (0.0.0.0).
//
// Motivation: VTMS-2026-0029 — OpenClaw's ClawHub marketplace contained 820+ confirmed
// malicious skills (out of 10,700) delivering the Atomic Stealer macOS info-stealer.
// Separately, 21,000 OpenClaw instances were exposed on 0.0.0.0 (not localhost-only),
// making them accessible from the local network and Internet.
//
// MKTPL-001 enforces that any marketplace extension must be hash-verified, at least
// 30 days old with 1,000+ installs, and absent from threat intelligence feeds before
// being permitted as an approved server (vectimus-mcp-001 allowlist prerequisite).
//
// DEPLOY-002 blocks MCP tool calls to servers whose gateway is bound to 0.0.0.0.

// VTMS-2026-0029 | OWASP: LLM10 Supply Chain | SOC 2: CC6.8 | NIST AI RMF: GV-6 | EU AI Act: Art.14
// OpenClaw ClawHub: 820+ malicious skills delivering Atomic Stealer, January 2026
// Blocks mcp_tool calls to marketplace extensions not verified by automated integrity check
@id("MKTPL-001")
@description("Block MCP tool calls to marketplace extensions lacking automated hash and threat-intel verification")
@incident("VTMS-2026-0029: OpenClaw ClawHub 820–1184 malicious skills delivering Atomic Stealer, January 2026")
@controls("OWASP-LLM10, SOC2-CC6.8, NIST-AI-GV-6, EU-AI-14, CIS-2.5, CIS-2.7, CIS-16.1, CIS-16.4")
@suggested_alternative("Verify the marketplace extension before use: vectimus mcp verify <server-name>. Requirements: hash verified against publisher registry, age >= 30 days, installs >= 1000, absent from threat-intel feeds.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    (context has "mcp_source") &&
    context.mcp_source == "marketplace" &&
    (!(context has "marketplace_verified") || context.marketplace_verified != true)
};
// Override: run 'vectimus mcp verify <server>' to perform automated checks.
// On pass, the server is added to the allowlist with a verified = true flag.
// Manual override by a human administrator: set context.marketplace_verified = true
// with a supporting audit record in context.verification_ref.

// VTMS-2026-0029 | OWASP: LLM10 Supply Chain | SOC 2: CC6.1 | NIST AI RMF: GV-6 | EU AI Act: Art.14
// 21,000 OpenClaw instances exposed on 0.0.0.0 — default binding misconfiguration
// Blocks mcp_tool calls to server gateways bound to all network interfaces
@id("DEPLOY-002")
@description("Block MCP tool calls to server gateways not restricted to localhost (127.0.0.1) binding")
@incident("VTMS-2026-0029: 21,000 OpenClaw instances exposed on 0.0.0.0 due to default binding, January 2026")
@controls("OWASP-LLM10, SOC2-CC6.1, NIST-AI-GV-6, CIS-2.7, CIS-12.1")
@suggested_alternative("Restart the MCP server with --host 127.0.0.1. MCP gateway servers must bind to 127.0.0.1, not 0.0.0.0. Add to allowlist prerequisite checklist.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    (context has "mcp_server_host") &&
    context.mcp_server_host == "0.0.0.0"
};
// Override: reconfigure the MCP server to bind to 127.0.0.1.
// There is no safe override for servers bound to 0.0.0.0 on production systems.
