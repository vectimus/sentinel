#!/usr/bin/env bash
# Run Cisco MCP Scanner against the Sentinel MCP server tool definitions.
#
# Uses static mode (no live server needed) with YARA rules only (free, no API key).
# For LLM-as-judge analysis, set MCP_SCANNER_LLM_API_KEY or ANTHROPIC_API_KEY.
#
# Usage: ./evals/run_mcp_scan.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "==> Exporting MCP tool definitions..."
python -m evals.export_mcp_tools > evals/mcp-tools.json

ANALYZERS="yara"

# Use LLM analyzer if API key is available
if [ -n "${MCP_SCANNER_LLM_API_KEY:-}" ] || [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    export MCP_SCANNER_LLM_API_KEY="${MCP_SCANNER_LLM_API_KEY:-$ANTHROPIC_API_KEY}"
    ANALYZERS="yara,llm"
    echo "==> LLM analyzer enabled"
fi

echo "==> Running MCP Scanner (static mode, analyzers: $ANALYZERS)..."
mcp-scanner \
    --analyzers "$ANALYZERS" \
    --format table \
    --output evals/mcp-scan-results.json \
    static \
    --tools evals/mcp-tools.json

EXIT_CODE=$?

echo ""
echo "==> Results saved to evals/mcp-scan-results.json"

# Fail CI if high-severity findings
if [ -f evals/mcp-scan-results.json ]; then
    HIGH_COUNT=$(python -c "
import json, sys
try:
    data = json.load(open('evals/mcp-scan-results.json'))
    findings = data if isinstance(data, list) else data.get('findings', data.get('results', []))
    high = [f for f in findings if isinstance(f, dict) and f.get('severity', '').lower() == 'high']
    print(len(high))
except Exception:
    print(0)
")
    if [ "$HIGH_COUNT" -gt 0 ]; then
        echo "ERROR: $HIGH_COUNT high-severity finding(s) detected!"
        exit 1
    fi
fi

exit $EXIT_CODE
