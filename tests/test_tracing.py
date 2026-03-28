"""Tests for pipeline.tracing — Phoenix observability module."""

import json
import os
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

import pipeline.tracing as tracing_mod
from pipeline.tracing import export_traces, init_tracing, shutdown


@pytest.fixture(autouse=True)
def _reset_session():
    """Reset the global session before each test."""
    tracing_mod._phoenix_session = None
    yield
    tracing_mod._phoenix_session = None


class TestInitTracing:
    def test_disabled_via_env_var(self):
        with patch.dict(os.environ, {"SENTINEL_DISABLE_TRACING": "1"}):
            init_tracing()
        assert tracing_mod._phoenix_session is None

    def test_disabled_via_true_string(self):
        with patch.dict(os.environ, {"SENTINEL_DISABLE_TRACING": "true"}):
            init_tracing()
        assert tracing_mod._phoenix_session is None

    def test_graceful_when_phoenix_not_installed(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SENTINEL_DISABLE_TRACING", None)
            with patch.dict("sys.modules", {"phoenix": None, "phoenix.otel": None}):
                init_tracing()
        assert tracing_mod._phoenix_session is None


class TestExportTraces:
    def test_returns_none_when_no_session(self):
        result = export_traces("2026-03-14")
        assert result is None

    def test_exports_to_json(self, tmp_path):
        tracing_mod._phoenix_session = MagicMock()

        mock_df = pd.DataFrame(
            [
                {"name": "llm_call", "duration_ms": 1200, "status": "OK"},
                {"name": "tool_call", "duration_ms": 300, "status": "OK"},
            ]
        )

        mock_px = MagicMock()
        mock_px.Client.return_value.get_spans_dataframe.return_value = mock_df

        with patch.dict("sys.modules", {"phoenix": mock_px}):
            result = export_traces("2026-03-14", output_dir=str(tmp_path))

        assert result is not None
        assert result.exists()
        assert result.name == "2026-03-14.json"

        data = json.loads(result.read_text())
        assert len(data) == 2
        assert data[0]["name"] == "llm_call"

    def test_returns_none_on_empty_dataframe(self):
        tracing_mod._phoenix_session = MagicMock()

        mock_px = MagicMock()
        mock_px.Client.return_value.get_spans_dataframe.return_value = pd.DataFrame()

        with patch.dict("sys.modules", {"phoenix": mock_px}):
            result = export_traces("2026-03-14")

        assert result is None


class TestShutdown:
    def test_closes_session(self):
        mock_session = MagicMock()
        tracing_mod._phoenix_session = mock_session

        shutdown()

        mock_session.close.assert_called_once()
        assert tracing_mod._phoenix_session is None

    def test_noop_when_no_session(self):
        shutdown()
        assert tracing_mod._phoenix_session is None
