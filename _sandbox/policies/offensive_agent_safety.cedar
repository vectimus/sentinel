// Offensive AI agent scope control -- require explicit human-confirmed target scope
// before an autonomous offensive or red-team AI agent performs network actions.
//
// Motivation: VTMS-2026-0028 — CodeWall's autonomous offensive AI research agent,
// with no human involvement in target selection, identified McKinsey's Lilli chatbot,
// discovered 22 unauthenticated API endpoints, and exploited SQL injection to achieve
// full read-write access to 46.5M messages in under two hours.  This is the first
// publicly documented case of an autonomous AI agent achieving C-suite-scale data
// access without human direction.  A Cedar policy requiring human-approved target scope
// would have blocked the agent's initial reconnaissance web requests.

// VTMS-2026-0028 | OWASP: LLM01 Excessive Agency | SOC 2: CC6.1 | NIST AI RMF: GV-4.2 | EU AI Act: Art.14
// CodeWall autonomous offensive AI attacked McKinsey Lilli without human direction — 46.5M messages exposed
// Blocks web_request and mcp_tool calls by offensive-researcher agents without human-approved target scope
@id("OFFENSE-001")
@description("Require human-confirmed target scope before autonomous offensive AI agent network actions")
@incident("VTMS-2026-0028: CodeWall agent autonomously attacked McKinsey Lilli, 46.5M messages exposed, February 2026")
@controls("OWASP-LLM01, SOC2-CC6.1, NIST-AI-GV-4.2, EU-AI-14, CIS-5.4, CIS-16.1, CIS-18.3")
@suggested_alternative("Obtain a signed target scope document, record it in context.scope_ref, set context.target_approved = true. Scope approvals expire after 24 hours (context.scope_expires).")
forbid (
    principal,
    action in [Vectimus::Action::"web_request", Vectimus::Action::"mcp_tool"],
    resource
) when {
    (context has "agent_role") &&
    context.agent_role == "offensive_researcher" &&
    (!(context has "target_approved") || context.target_approved != true)
};
// Override: set context.target_approved = true with a human-signed scope document
// reference in context.scope_ref and an expiry timestamp in context.scope_expires.
// Scope approvals must be time-bounded and reviewed before each engagement.
// This policy applies to agents declared as offensive researchers via agent configuration.
