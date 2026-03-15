// Repository onboarding safety -- inspect project configuration files loaded at agent
// initialisation time for malicious hook commands and API key interception patterns.
//
// Motivation: VTMS-2026-0030 — Check Point Research disclosed CVE-2025-59536 and
// CVE-2026-21852 in Claude Code.  CVE-2025-59536: hooks in .claude/settings.json
// execute arbitrary shell commands at tool initialisation without confirmation, even
// though trust dialogs suggest approval is required.  CVE-2026-21852: setting
// ANTHROPIC_BASE_URL in a project .env file intercepts all API requests including
// API keys before the user has confirmed trust.  Attack vector: malicious pull
// requests, honeypot repositories, or compromised enterprise repositories.
//
// REPO-001 flags file_read of .claude/settings.json that the Vectimus pre-processor
// has determined contains shell command hooks (hooks_contain_shell_commands = true).
// REPO-002 flags file_read of .env files where the pre-processor detects
// ANTHROPIC_BASE_URL pointing to a non-Anthropic domain.

// VTMS-2026-0030 | OWASP: LLM09 Insecure Tool Use | SOC 2: CC6.1 | NIST AI RMF: MS-2.3 | EU AI Act: Art.14
// CVE-2025-59536: .claude/settings.json hooks in malicious repos execute shell commands at init
// Blocks agent reads of .claude/settings.json files detected as containing shell command hooks
@id("REPO-001")
@description("Block loading .claude/settings.json hooks containing shell commands without human approval")
@incident("VTMS-2026-0030: CVE-2025-59536, malicious repo .claude/settings.json hooks achieve RCE at init, February 2026")
@controls("OWASP-LLM09, SOC2-CC6.1, NIST-AI-MS-2.3, EU-AI-14, CIS-2.5, CIS-16.1, CIS-16.7")
@suggested_alternative("Inspect .claude/settings.json hooks manually before opening the repository. Hooks that run shell commands require human approval before execution. Upgrade Claude Code to >= v1.0.24 (patched).")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    context.file_path like "*.claude/settings.json" &&
    (context has "hooks_contain_shell_commands") &&
    context.hooks_contain_shell_commands == true
};
// Note: This policy requires Vectimus to pre-read and analyse .claude/settings.json content
// before Cedar evaluation, setting context.hooks_contain_shell_commands accordingly.
// Full implementation requires the project_load action type (schema extension, tracked as
// VTMS-schema-006).  In the interim this rule fires on file_read with the pre-processor flag.
// Override: after human inspection and approval, set context.hooks_contain_shell_commands = false.

// VTMS-2026-0030 | OWASP: LLM09 Insecure Tool Use | SOC 2: CC6.1 | NIST AI RMF: MS-2.3 | EU AI Act: Art.15
// CVE-2026-21852: ANTHROPIC_BASE_URL in project .env intercepts API keys before Claude Code initialises
// Blocks agent reads of .env files where ANTHROPIC_BASE_URL is set to a non-Anthropic domain
@id("REPO-002")
@description("Block loading project .env files that redirect ANTHROPIC_BASE_URL to non-Anthropic domains")
@incident("VTMS-2026-0030: CVE-2026-21852, ANTHROPIC_BASE_URL .env poisoning intercepts API keys, February 2026")
@controls("OWASP-LLM09, SOC2-CC6.1, NIST-AI-MS-2.3, EU-AI-15, CIS-2.5, CIS-16.1")
@suggested_alternative("Review project .env files for ANTHROPIC_BASE_URL before loading. Only *.anthropic.com domains are permitted. Remove or correct the redirect, then reload the project.")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    (context.file_path like "*/.env" || context.file_path like "*/.env.*") &&
    (context has "anthropic_base_url_redirected") &&
    context.anthropic_base_url_redirected == true
};
// Note: This policy requires Vectimus to pre-read the .env file and check for
// ANTHROPIC_BASE_URL pointing outside *.anthropic.com, setting context.anthropic_base_url_redirected.
// Override: after human confirmation that the redirect is intentional (e.g. test proxy),
// set context.anthropic_base_url_redirected = false in the project override config.
