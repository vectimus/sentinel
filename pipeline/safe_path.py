"""Path validation utilities to prevent path traversal (CWE-23)."""

from __future__ import annotations

from pathlib import Path


def validate_path(path: str | Path, *, allowed_bases: list[str | Path] | None = None) -> Path:
    """Resolve *path* and verify it lives under an allowed base directory.

    Parameters
    ----------
    path:
        The raw (potentially untrusted) path string or Path object.
    allowed_bases:
        Directories the resolved path must fall under.  When *None* the
        current working directory is used as the sole allowed base.

    Returns
    -------
    Path
        The resolved, validated ``pathlib.Path``.

    Raises
    ------
    ValueError
        If the resolved path escapes every allowed base directory.
    """
    resolved = Path(path).resolve()

    if allowed_bases is None:
        allowed_bases = [Path.cwd()]

    for base in allowed_bases:
        base_resolved = Path(base).resolve()
        try:
            resolved.relative_to(base_resolved)
            return resolved
        except ValueError:
            continue

    raise ValueError(
        f"Path {resolved} is outside allowed directories: "
        f"{[str(Path(b).resolve()) for b in allowed_bases]}"
    )


def safe_open_for_append(path: str | Path, *, allowed_bases: list[str | Path] | None = None):
    """Open a validated path for appending.

    This is a convenience wrapper for the common GitHub Actions pattern of
    appending to ``GITHUB_STEP_SUMMARY`` or ``GITHUB_OUTPUT``.
    """
    validated = validate_path(path, allowed_bases=allowed_bases)
    return open(validated, "a")  # noqa: SIM115
