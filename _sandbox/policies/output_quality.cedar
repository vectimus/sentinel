// AI-generated code output quality gate -- require a verified SAST clean scan
// before an AI agent's git commits or pushes reach protected branches.
//
// Motivation: VTMS-2026-0035 — DryRun Security found that 26 of 30 PRs (87%) generated
// by Claude Code (Sonnet 4.6), OpenAI Codex (GPT 5.2), and Google Gemini (2.5 Pro)
// contained at least one security vulnerability (143 total issues): broken access
// control, hardcoded JWT fallback secrets, OAuth missing state parameters, WebSocket
// authentication bypass, absent rate limiting.  Cedar cannot inspect generated code
// content, but it CAN gate the git operation that commits or pushes that code by
// requiring the resource to carry a SAST-verified flag set by an approved scanner.

// VTMS-2026-0035 | OWASP: ASI02 Tool Misuse | SOC 2: CC8.1 | NIST AI RMF: MS-2.6 | EU AI Act: Art.14
// DryRun Security: 87% of AI-generated PRs from Claude, Codex and Gemini contain security vulnerabilities
// Blocks AI-agent git push and commit operations that lack a verified SAST clean scan
@id("OUTPUT-001")
@description("Block AI-agent git push and commit without a verified SAST clean scan on the working tree")
@incident("VTMS-2026-0035: DryRun Security, 87% of AI-generated PRs contain vulnerabilities, March 2026")
@controls("OWASP-ASI02, SOC2-CC8.1, NIST-AI-MS-2.6, EU-AI-14, CIS-16.2, CIS-16.3, CIS-16.12")
@suggested_alternative("Run an approved SAST scan first: vectimus scan --sast. The resulting token (context.sast_verified = true) is valid for 60 minutes. Re-run after expiry.")
forbid (
    principal,
    action == Vectimus::Action::"git_operation",
    resource
) when {
    (context.command like "*git push*" || context.command like "*git commit*") &&
    (!(context has "sast_verified") || context.sast_verified != true)
};
// Override: context.sast_verified must be set to true by an approved SAST tool
// registered with Vectimus (see vectimus scan --register).
// context.sast_expires_at contains the expiry timestamp; re-run after expiry.
// Human developers may override per-session via: vectimus scan --override --reason "..."
