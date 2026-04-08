"""Raw candidate schema — output from Research Scout, input to Threat Classifier."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class RawCandidate(BaseModel):
    working_title: str
    source_urls: list[str] = Field(min_length=1)
    r2_keys: list[str] = Field(default_factory=list)
    raw_summary: str
    tools_mentioned: list[str] = Field(default_factory=list)
    approximate_date: str | None = None
    dedup_notes: str = ""

    @field_validator("source_urls")
    @classmethod
    def validate_urls(cls, v: list[str]) -> list[str]:
        for url in v:
            if not url.startswith(("https://", "http://")):
                raise ValueError(f"Source URL must use http(s) scheme. Got: {url!r}")
        return v
