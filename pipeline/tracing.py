"""Phoenix observability for the Sentinel pipeline.

Starts a local Phoenix instance, registers OpenTelemetry auto-instrumentation
for the Claude Agent SDK, and exports traces to a JSON file on shutdown.

Usage:
    from pipeline.tracing import init_tracing, export_traces

    init_tracing()        # Call once at pipeline start
    # ... run agents ...
    export_traces(date)   # Call at pipeline end
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_phoenix_session = None


def init_tracing(project_name: str = "sentinel") -> None:
    """Start Phoenix and register auto-instrumentation.

    Safe to call even if Phoenix is not installed — logs a warning and
    continues without tracing.
    """
    global _phoenix_session

    if os.environ.get("SENTINEL_DISABLE_TRACING", "").lower() in ("1", "true"):
        logger.info("Tracing disabled via SENTINEL_DISABLE_TRACING")
        return

    try:
        import phoenix as px
        from phoenix.otel import register

        _phoenix_session = px.launch_app()
        logger.info("Phoenix started at %s", _phoenix_session.url)

        register(project_name=project_name, auto_instrument=True)
        logger.info("OpenTelemetry auto-instrumentation registered")

    except ImportError as e:
        logger.warning("Tracing not available (missing dependency: %s)", e)
    except Exception as e:
        logger.warning("Failed to start tracing: %s", e)


def export_traces(date: str, output_dir: str = "traces") -> Path | None:
    """Export all collected traces to a JSON file.

    Returns the path to the exported file, or None if tracing is not active.
    """
    if _phoenix_session is None:
        return None

    try:
        import phoenix as px

        client = px.Client()
        df = client.get_spans_dataframe()

        if df is None or df.empty:
            logger.info("No traces to export")
            return None

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        trace_file = out_path / f"{date}.json"

        # Convert to records, handling non-serializable types
        records = json.loads(df.to_json(orient="records", date_format="iso"))
        trace_file.write_text(json.dumps(records, indent=2))

        logger.info(
            "Exported %d spans to %s (%.1f KB)",
            len(records),
            trace_file,
            trace_file.stat().st_size / 1024,
        )
        return trace_file

    except Exception as e:
        logger.warning("Failed to export traces: %s", e)
        return None


def shutdown() -> None:
    """Shut down the Phoenix session."""
    global _phoenix_session

    if _phoenix_session is None:
        return

    try:
        _phoenix_session.close()
        logger.info("Phoenix session closed")
    except Exception:
        pass
    finally:
        _phoenix_session = None
