"""Allow running with `python -m pipeline` or `python -m pipeline <stage>`.

Stages:
    (none)           — run full orchestrator (legacy, local dev)
    threat-hunter    — Threat Hunter + validation + D1 scrub
    policy-engineer  — Security Engineer (needs findings artifact)
    threat-analyst   — Threat Analyst (needs findings artifact)
    publish          — Trends + digest notification
"""

import os
import sys

# Clean Claude Code session vars BEFORE importing anything else.
# The Claude Agent SDK's subprocess transport inherits os.environ;
# leftover CLAUDE_CODE_* vars (especially SSE_PORT, ENTRYPOINT)
# cause the bundled CLI to crash with exit-code 1.
_oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
for _key in list(os.environ):
    if _key.startswith("CLAUDE_CODE_") or _key == "CLAUDECODE" or _key.startswith("OTEL_"):
        os.environ.pop(_key)
if _oauth:
    os.environ["CLAUDE_CODE_OAUTH_TOKEN"] = _oauth

# Remove empty ANTHROPIC_API_KEY — the CLI treats "" as invalid
if not os.environ.get("ANTHROPIC_API_KEY"):
    os.environ.pop("ANTHROPIC_API_KEY", None)

os.environ.setdefault("SENTINEL_PYTHON", sys.executable)

STAGES = {
    "threat-hunter": "pipeline.stages:threat_hunter",
    "policy-engineer": "pipeline.stages:policy_engineer",
    "threat-analyst": "pipeline.stages:threat_analyst",
    "publish": "pipeline.stages:publish",
}

stage = sys.argv[1] if len(sys.argv) > 1 else None

if stage is None:
    # Full pipeline (legacy / local dev)
    from pipeline.orchestrator import _entry  # noqa: E402
    _entry()
elif stage in STAGES:
    module_path, func_name = STAGES[stage].rsplit(":", 1)
    import importlib
    mod = importlib.import_module(module_path)  # nosemgrep: non-literal-import
    getattr(mod, func_name)()
else:
    print(f"Unknown stage: {stage!r}")
    print(f"Available stages: {', '.join(STAGES)}")
    print("Run with no arguments for the full pipeline.")
    sys.exit(1)
