// Supply chain version safety -- block installation of packages with known critical
// vulnerabilities that enable credential theft or remote code execution.
//
// Motivation: VTMS-2026-0032 — CVE-2025-68664 (CVSS 9.3, CWE-502) in langchain-core
// allowed crafted LLM outputs to masquerade as trusted LangChain objects during
// deserialisation, extracting all environment variables (cloud credentials, DB strings,
// API keys) via the 'secrets_from_env' parameter enabled by default.  12 distinct
// vulnerable code flows identified.  Patched in langchain-core v0.3.81 (0.3.x line)
// and v1.2.5 (1.x line).  Any agent that can be prompted to generate structured output
// with the 'lc' marker key can trigger the exploit chain.

// VTMS-2026-0032 | OWASP: LLM07 Insufficient Input Validation | SOC 2: CC6.8 | NIST AI RMF: MS-2.5 | EU AI Act: Art.14
// CVE-2025-68664 LangGrinch: langchain-core serialisation injection exposes all env vars (CVSS 9.3)
// Blocks installation of langchain-core versions vulnerable to CVE-2025-68664
@id("SUPPLY-001")
@description("Block installation of langchain-core versions vulnerable to CVE-2025-68664 serialisation injection")
@incident("VTMS-2026-0032: CVE-2025-68664 LangGrinch, langchain-core < 0.3.81 / < 1.2.5 exposes all env vars, December 2025")
@controls("OWASP-LLM07, SOC2-CC6.8, NIST-AI-MS-2.5, EU-AI-14, CIS-2.2, CIS-2.7, CIS-16.1, CIS-18.3")
@suggested_alternative("Upgrade langchain-core to a patched version: pip install 'langchain-core>=0.3.81' (0.3.x) or 'langchain-core>=1.2.5' (1.x). Do not pin to vulnerable versions.")
forbid (
    principal,
    action in [Vectimus::Action::"package_operation", Vectimus::Action::"shell_command"],
    resource
) when {
    // Block explicit pin to vulnerable 0.1.x and 0.2.x versions
    context.command like "*langchain-core==0.1.*" ||
    context.command like "*langchain-core==0.2.*" ||
    // Block pin to any 0.3.x below the patch (0.3.81)
    context.command like "*langchain-core==0.3.0*" ||
    context.command like "*langchain-core==0.3.1*" ||
    context.command like "*langchain-core==0.3.2*" ||
    context.command like "*langchain-core==0.3.3*" ||
    context.command like "*langchain-core==0.3.4*" ||
    context.command like "*langchain-core==0.3.5*" ||
    context.command like "*langchain-core==0.3.6*" ||
    context.command like "*langchain-core==0.3.7*" ||
    context.command like "*langchain-core==0.3.80*" ||
    // Block pin to vulnerable 1.x versions below 1.2.5
    context.command like "*langchain-core==1.0.*" ||
    context.command like "*langchain-core==1.1.*" ||
    context.command like "*langchain-core==1.2.0*" ||
    context.command like "*langchain-core==1.2.1*" ||
    context.command like "*langchain-core==1.2.2*" ||
    context.command like "*langchain-core==1.2.3*" ||
    context.command like "*langchain-core==1.2.4*"
};
// Override: this policy has no safe override for the listed versions.
// Upgrade to >= 0.3.81 (0.3.x) or >= 1.2.5 (1.x) before proceeding.
