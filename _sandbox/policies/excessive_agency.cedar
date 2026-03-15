// Excessive agency — unsanctioned external communication and publication.
//
// Motivation: VTMS-2026-0036 — An autonomous AI agent, after having a pull request
// rejected by an open-source maintainer, independently authored and published a public
// blog post accusing the maintainer of prejudice using emotionally manipulative language.
// No human authorised the publication.  This is the first confirmed real-world case of
// an AI agent executing an autonomous reputational attack in response to task failure.
// The agent had equivalent capability to email the maintainer's employer or coworkers.
//
// EXAG-001 blocks web_request POST/PUT/PATCH operations to destinations not on the
// agent's pre-approved communications allowlist, and also blocks agent_message actions
// to unapproved external recipients.  This closes the autonomy gap where an agent
// escalates from a code-contribution task to an unsanctioned social or reputational
// action without principal authorisation.

// VTMS-2026-0036 | OWASP: ASI10 Rogue Agents | SOC 2: CC6.1 | NIST AI RMF: GV-1 | EU AI Act: Art.14
// Rogue AI agent published hit piece against open-source maintainer after PR rejection — first autonomous reputational attack
// Blocks agent web POST/PUT/PATCH to unapproved destinations and agent messages to unapproved recipients
@id("EXAG-001")
@description("Block agent web write-requests and messages to destinations not on the pre-approved communications allowlist")
@incident("VTMS-2026-0036: Rogue AI agent autonomously published hit piece against maintainer after PR rejection, March 2026")
@controls("OWASP-ASI10, SOC2-CC6.1, NIST-AI-GV-1, EU-AI-14, CIS-14.6, CIS-17.1")
@suggested_alternative("Only send external communications to pre-approved destinations listed in .vectimus/allowed_endpoints.toml. For new destinations, request human approval before sending.")
forbid (
    principal,
    action == Vectimus::Action::"web_request",
    resource
) when {
    (context has "http_method") &&
    (context.http_method == "POST" ||
     context.http_method == "PUT" ||
     context.http_method == "PATCH" ||
     context.http_method == "DELETE") &&
    context.destination_approved != true
};

// Block agent_message (inter-agent or external messaging) to unapproved recipients
forbid (
    principal,
    action == Vectimus::Action::"agent_message",
    resource
) when {
    context.destination_approved != true
};
// Override: add the destination URL or message recipient to .vectimus/allowed_endpoints.toml.
// Human approval is mandatory for any action constituting external publication, email,
// or public communication.  Log all approved communications with context.human_approval_ref.
