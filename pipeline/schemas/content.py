"""Content schema — D1 content table record."""

from __future__ import annotations

from pydantic import BaseModel


class Content(BaseModel):
    id: str
    vtms_id: str
    content_type: str  # blog_post | incident_brief
    title: str | None = None
    slug: str | None = None
    status: str = "draft"
    pr_url: str | None = None
    published_url: str | None = None
    created_at: str = ""
    updated_at: str = ""
