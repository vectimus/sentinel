# Cedar Policy Conventions

## Policy ID Format

`<CATEGORY>-<NNN>` where category is one of:

| Category | Scope |
|----------|-------|
| `DESTR` | Destructive commands (rm, drop, destroy, reset) |
| `CRED` | Credential and secret access (.env, keys, tokens) |
| `SC` | Supply chain (publish, release, registry) |
| `MCP` | MCP server governance (connections, tool calls) |
| `GIT` | Git operations (force push, rebase, reset) |
| `FILE` | File access controls (sensitive paths, system files) |
| `WEB` | Web access controls (fetch, download, upload) |
| `COMP` | Compliance (audit trail, logging, approval) |

## Required Annotations

Every policy must include comment annotations:

```cedar
// VTMS-YYYY-NNNN | OWASP: <category> | SOC 2: <control> | NIST: <function>
// <One-line incident description>
// <Brief explanation of what this policy blocks and why>
```

## Scope Precision

Block the specific dangerous pattern, not a broad category.

Good: `resource.command like "*terraform destroy*"`
Bad: `resource.command like "*terraform*"`

## Allowlist Guidance

Every forbid policy must include a comment explaining how to legitimately override:

```cedar
// Override: <description of how to allow this action when legitimate>
```

## Test Fixtures

Every policy ships with at minimum:
- One "should block" fixture (expected: DENY)
- One "should allow" fixture (expected: ALLOW)

Place fixtures in `tests/<vtms-id>/` with:
- `entities.json` — entity definitions
- `request_block.json` — request that should be denied
- `request_allow.json` — request that should be allowed
