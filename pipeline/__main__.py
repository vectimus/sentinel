"""Allow running with `python -m pipeline`."""

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

from pipeline.orchestrator import _entry  # noqa: E402

_entry()
