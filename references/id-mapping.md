# Vectimus Rule ID Mapping

## Current Rule ID Prefixes

| Prefix | Pack | Description |
|--------|------|-------------|
| `vectimus-destops-*` | core | Destructive operations — rm -rf, drop table, terraform destroy, reset --hard |
| `vectimus-secrets-*` | core | Secret/credential protection — .env reads, key file access, token exposure |
| `vectimus-supchain-*` | core | Supply chain integrity — npm publish, pip upload, registry pushes |
| `vectimus-infra-*` | core | Infrastructure and privilege escalation — sudo, chmod, iptables, systemctl |
| `vectimus-codexec-*` | core | Code execution and RCE — eval, exec, python -c, subprocess shells |
| `vectimus-exfil-*` | core | Data exfiltration — curl uploads, scp, base64-encoded transfers |
| `vectimus-fileint-*` | core | File integrity — writes to system paths, config overwrites, binary replacement |
| `vectimus-db-*` | core | Database safety — drop, truncate, alter, migration pushes |
| `vectimus-git-*` | core | Git safety — force push, history rewrite, hook injection |
| `vectimus-mcp-*` | agentic | MCP tool governance — unapproved servers, tool call filtering |
| `vectimus-agentgov-*` | agentic | Agent governance — delegation limits, recursion depth, rogue detection |

## Legacy ID Mapping

The following old-style IDs appear in existing agent specs and Cedar conventions. They map to the new prefixes:

| Legacy ID | New Prefix | Example |
|-----------|-----------|---------|
| `DESTR-NNN` | `vectimus-destops-*` | DESTR-001 → vectimus-destops-001 |
| `CRED-NNN` | `vectimus-secrets-*` | CRED-001 → vectimus-secrets-001 |
| `SC-NNN` | `vectimus-supchain-*` | SC-003 → vectimus-supchain-003 |
| `MCP-NNN` | `vectimus-mcp-*` | MCP-001 → vectimus-mcp-001 |
| `GIT-NNN` | `vectimus-git-*` | GIT-001 → vectimus-git-001 |
| `FILE-NNN` | `vectimus-fileint-*` | FILE-001 → vectimus-fileint-001 |
| `WEB-NNN` | `vectimus-exfil-*` | WEB-001 → vectimus-exfil-001 |
| `COMP-NNN` | `vectimus-agentgov-*` | COMP-001 → vectimus-agentgov-001 |
