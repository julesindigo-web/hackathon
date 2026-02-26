"""
SecurAI Guardian - Configuration Management
Environment-based configuration with validation
"""

import os
from typing import List, Optional
from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings from environment variables"""

    # GitLab Configuration
    gitlab_url: str = Field(
        default="https://gitlab.com",
        description="GitLab instance URL"
    )
    gitlab_token: str = Field(
        ...,
        description="GitLab personal access token or CI_JOB_TOKEN"
    )
    gitlab_project_id: Optional[int] = Field(
        None,
        description="GitLab project ID (optional, can be inferred from CI)"
    )

    # Anthropic Claude Configuration
    anthropic_api_key: str = Field(
        ...,
        description="Anthropic API key for Claude"
    )
    anthropic_model: str = Field(
        default="claude-3-5-sonnet-20241022",
        description="Claude model to use"
    )
    anthropic_max_tokens: int = Field(
        default=4096,
        description="Max tokens for Claude responses"
    )

    # Database Configuration
    database_url: str = Field(
        default="postgresql://postgres:password@localhost:5432/securi_guardian",
        description="PostgreSQL connection URL"
    )

    # Redis Configuration
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )

    # Agent Configuration
    agent_enabled: bool = Field(
        default=True,
        description="Enable/disable agent processing"
    )
    auto_fix_enabled: bool = Field(
        default=True,
        description="Enable automatic vulnerability fixes"
    )
    auto_fix_confidence_threshold: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Confidence threshold for auto-fix"
    )
    auto_fix_severity_threshold: str = Field(
        default="high",
        description="Minimum severity for auto-fix"
    )
    max_auto_fix_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Max retry attempts for fix generation"
    )
    require_human_approval: bool = Field(
        default=False,
        description="Require manual approval before auto-fix MR"
    )

    # Compliance Configuration
    compliance_frameworks: List[str] = Field(
        default=["SOX", "HIPAA", "GDPR", "PCI-DSS", "ISO27001"],
        description="Enabled compliance frameworks"
    )

    # Notification Configuration
    slack_webhook_url: Optional[str] = Field(
        None,
        description="Slack webhook for alerts"
    )
    pagerduty_routing_key: Optional[str] = Field(
        None,
        description="PagerDuty integration key"
    )
    email_smtp_host: Optional[str] = Field(
        None,
        description="SMTP host for email notifications"
    )
    email_from: Optional[str] = Field(
        None,
        description="From email address"
    )
    email_to: List[str] = Field(
        default=[],
        description="Recipient email addresses"
    )

    # Logging Configuration
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )
    log_format: str = Field(
        default="json",
        description="Log format (json or text)"
    )

    # Performance Configuration
    batch_size: int = Field(
        default=100,
        ge=1,
        description="Batch size for processing vulnerabilities"
    )
    max_concurrent_agents: int = Field(
        default=10,
        ge=1,
        description="Max concurrent agent executions"
    )
    cache_ttl_seconds: int = Field(
        default=300,
        ge=0,
        description="Cache TTL in seconds"
    )

    # Security Configuration
    audit_log_retention_days: int = Field(
        default=365,
        ge=1,
        description="Audit log retention period"
    )
    immutable_audit_trail: bool = Field(
        default=True,
        description="Enable immutable audit trail (WORM)"
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @validator("gitlab_url")
    def validate_gitlab_url(cls, v):
        """Ensure GitLab URL has proper scheme"""
        if not v.startswith(("http://", "https://")):
            raise ValueError("gitlab_url must start with http:// or https://")
        return v.rstrip("/")

    @validator("auto_fix_severity_threshold")
    def validate_severity_threshold(cls, v):
        """Validate severity threshold is valid"""
        allowed = ["critical", "high", "medium", "low", "info"]
        if v.lower() not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return v.lower()


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings (dependency injection helper)"""
    return settings
