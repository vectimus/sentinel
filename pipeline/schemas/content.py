"""Content schema — D1 content table record."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, field_validator


class Content(BaseModel):
    id: str
    vtms_id: str
    content_type: Literal["blog_post", "incident_brief"]  # blog_post | incident_brief
    title: str | None = None
    slug: str | None = None
    status: Literal["draft", "published", "archived"] = "draft"
    pr_url: str | None = None
    published_url: str | None = None
    created_at: str = ""
    updated_at: str = ""

    @field_validator("vtms_id")
    @classmethod
    def validate_vtms_id(cls, v: str) -> str:
        if not re.match(r"^VTMS-\d{4}-\d{4}$", v):
            raise ValueError("vtms_id must match VTMS-YYYY-NNNN format")
        return v
