// Credential enumeration via shell -- block shell commands that enumerate all
// environment variables, a common first step in credential harvesting attacks.
//
// Motivation: VTMS-2026-0034 — UNC6426/QUIETVAULT exploited a Pwn Request in the nx
// npm package to deploy the QUIETVAULT credential stealer.  QUIETVAULT uniquely
// weaponised an LLM tool already installed on the developer endpoint by issuing it
// natural-language instructions to run 'env', 'printenv', and 'export -p' to enumerate
// all environment variables including GitHub-to-AWS OIDC tokens.  This is the first
// confirmed in-the-wild use of an agentic AI tool as a credential harvesting payload.
// Existing policies (vectimus-secrets-001 through -004) block reads of named credential
// files but do not block shell-based environment variable enumeration.

// VTMS-2026-0034 | OWASP: ASI04 Supply Chain Vulnerabilities | SOC 2: CC6.1 | NIST AI RMF: GV-1 | EU AI Act: Art.15
// UNC6426/QUIETVAULT: weaponised LLM tool to enumerate env vars and steal OIDC tokens — AWS admin access in 72h
// Blocks shell commands that enumerate all environment variables (credential harvesting pattern)
@id("vectimus-secrets-005")
@description("Block shell commands that enumerate all environment variables to prevent credential harvesting")
@incident("VTMS-2026-0034: UNC6426/QUIETVAULT used LLM tool to enumerate env vars and steal OIDC tokens, March 2026")
@controls("OWASP-ASI04, SOC2-CC6.1, NIST-AI-GV-1, EU-AI-15, CIS-2.7, CIS-12.2, CIS-16.1")
@suggested_alternative("Access specific named environment variables directly (e.g. echo $MY_VAR or $env:MY_VAR in PowerShell) instead of enumerating all environment variables.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS -- bare env enumerates ALL environment variables
    context.command == "env" ||
    context.command like "env | *" ||
    context.command like "env |*" ||
    context.command like "*; env" ||
    context.command like "*; env |*" ||
    context.command like "*&& env" ||
    context.command like "*&& env |*" ||
    context.command like "*`env`*" ||
    // Unix/macOS -- printenv without arguments enumerates ALL environment variables
    context.command == "printenv" ||
    context.command like "printenv | *" ||
    context.command like "printenv|*" ||
    context.command like "*; printenv" ||
    context.command like "*; printenv |*" ||
    context.command like "*&& printenv" ||
    context.command like "*&& printenv |*" ||
    // Unix/macOS -- export -p dumps all exported variables
    context.command like "*export -p*" ||
    // Windows PowerShell -- enumerate all environment variables
    context.command like "*Get-ChildItem Env:*" ||
    context.command like "*Get-ChildItem env:*" ||
    context.command like "*Get-Item Env:*" ||
    context.command like "*ls Env:*" ||
    context.command like "*ls env:*" ||
    context.command like "*dir Env:*" ||
    context.command like "*dir env:*" ||
    context.command like "*[System.Environment]::GetEnvironmentVariables*"
};
// Override: legitimate use of env/printenv for debugging should be done by the
// developer directly.  Agents that need a specific environment variable should
// reference it by name ($MY_VAR) rather than dumping all variables.
