// Package operations -- block dangerous package management commands that
// could publish malicious packages or install from untrusted sources.

@id("vectimus-supchain-001")
@description("Block npm publish to prevent supply-chain attacks")
@incident("Clinejection: malicious npm packages published by compromised AI agent, February 2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15")
@suggested_alternative("Use npm pack to create a tarball for review, then request human approval before publishing.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm publish*"
};

@id("vectimus-supchain-002")
@description("Block pip install from non-standard indexes")
@incident("Dependency confusion attacks via private index spoofing, 2024-2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15")
@suggested_alternative("Install packages from the default PyPI index, or request human approval for custom indexes.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*pip install*--index-url*" ||
    context.command like "*pip install*-i *"
};

@id("vectimus-supchain-003")
@description("Block npm install with URL sources instead of registry packages")
@incident("Trojanised packages installed via direct URL bypassing registry checks, 2025")
@controls("SLSA-L2, SOC2-CC6.8, EU-AI-15")
@suggested_alternative("Install packages from the npm registry by name instead of using direct URLs.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install http:*"
};

@id("vectimus-supchain-004")
@description("Block global npm installs which affect the system-wide environment")
@incident("Global npm install of compromised package affected all projects on developer machine, 2025")
@controls("SOC2-CC6.8, EU-AI-15")
@suggested_alternative("Install packages locally to the project with npm install (no -g flag) to limit blast radius.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install -g*"
};

// VTMS-2026-0034 | OWASP: ASI04 Supply Chain Vulnerabilities | SOC 2: CC6.8 | NIST AI RMF: GV-1 | EU AI Act: Art.14
// UNC6426/QUIETVAULT: QUIETVAULT credential stealer delivered via poisoned nx npm postinstall script
// Blocks npm package operations for packages not on an approved hash-verified allowlist
@id("vectimus-supchain-010")
@description("Block npm package installs for packages not verified against an approved hash allowlist")
@incident("VTMS-2026-0034: UNC6426/QUIETVAULT credential stealer via poisoned nx npm postinstall, March 2026")
@controls("OWASP-ASI04, SOC2-CC6.8, NIST-AI-GV-1, EU-AI-14, CIS-2.7, CIS-12.2, CIS-16.1")
@suggested_alternative("Add the package to the approved allowlist with hash verification: vectimus supply allow <package>@<version> --hash <sha256>. The allowlist is checked against npm registry integrity hashes.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install*" &&
    (!(context has "npm_package_verified") || context.npm_package_verified != true)
};
// Override: context.npm_package_verified must be set to true by the Vectimus supply-chain
// checker after validating the package integrity hash against the npm registry.
// Run 'vectimus supply verify <package>@<version>' to populate the verified flag.
// For internal packages: register the expected hash in .vectimus/supply-allowlist.toml.
