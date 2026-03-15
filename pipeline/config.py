"""Pipeline configuration loaded from environment variables."""

import os
import sys
from dataclasses import dataclass, field


@dataclass
class Config:
    """Sentinel pipeline configuration."""

    # Anthropic
    anthropic_api_key: str = ""
    model: str = "claude-sonnet-4-6"

    # Cloudflare D1
    cloudflare_account_id: str = ""
    cloudflare_api_token: str = ""
    d1_database_id: str = ""

    # Cloudflare R2
    r2_access_key_id: str = ""
    r2_secret_access_key: str = ""
    r2_endpoint_url: str = ""
    r2_bucket_name: str = "vectimus-research-archive"

    # Pushover
    pushover_user_key: str = ""
    pushover_app_token: str = ""

    # GitHub
    bot_github_token: str = ""
    policies_repo: str = "vectimus/policies"
    website_repo: str = "vectimus/vectimus-website"
    sentinel_repo: str = "vectimus/sentinel"
    policies_repo_path: str = ""

    # Agent AGENTS.md paths
    threat_hunter_spec: str = "agents/threat-hunter/AGENTS.md"
    security_engineer_spec: str = "agents/security-engineer/AGENTS.md"
    threat_analyst_spec: str = "agents/threat-analyst/AGENTS.md"

    @property
    def mcp_server_config(self) -> dict:
        """Return MCP server config for the Claude Agent SDK."""
        return {
            "sentinel": {
                "type": "stdio",
                "command": sys.executable,
                "args": ["-m", "pipeline.mcp_server"],
            }
        }

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            anthropic_api_key=(
                os.environ.get("ANTHROPIC_API_KEY")
                or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
                or ""
            ),
            model=os.environ.get("SENTINEL_MODEL", "claude-sonnet-4-6"),
            cloudflare_account_id=os.environ["CLOUDFLARE_ACCOUNT_ID"],
            cloudflare_api_token=os.environ["CLOUDFLARE_API_TOKEN"],
            d1_database_id=os.environ.get("D1_DATABASE_ID", ""),
            r2_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
            r2_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
            r2_endpoint_url=os.environ["R2_ENDPOINT_URL"],
            r2_bucket_name=os.environ.get("R2_BUCKET_NAME", "vectimus-research-archive"),
            pushover_user_key=os.environ.get("PUSHOVER_USER_KEY", ""),
            pushover_app_token=os.environ.get("PUSHOVER_APP_TOKEN", ""),
            bot_github_token=os.environ["BOT_GITHUB_TOKEN"],
            policies_repo_path=os.environ.get("POLICIES_REPO_PATH", "_policies"),
        )
