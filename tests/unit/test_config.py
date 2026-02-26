"""
Unit tests for core configuration management.

Tests environment variable loading, validation, defaults, and edge cases.
Ensures configuration is properly loaded and validated across all environments.
"""

import pytest
from pydantic import ValidationError
from core.config import Settings, get_settings


class TestSettingsLoading:
    """Test Settings model loading from environment."""

    def test_default_settings(self):
        """Test default configuration values."""
        # Clear environment to test defaults
        import os
        env_vars_to_clear = [
            'SECURAI_ENV', 'SECURAI_DEBUG', 'SECURAI_LOG_LEVEL',
            'GITLAB_URL', 'GITLAB_TOKEN', 'GITLAB_PROJECT_ID',
            'ANTHROPIC_API_KEY', 'DATABASE_URL', 'REDIS_URL',
            'AGENT_AUTO_FIX_ENABLED', 'AGENT_CONFIDENCE_THRESHOLD',
            'COMPLIANCE_FRAMEWORKS', 'NOTIFICATION_CHANNELS'
        ]

        # Store original values
        original = {}
        for var in env_vars_to_clear:
            original[var] = os.environ.get(var)
            if var in os.environ:
                del os.environ[var]

        try:
            settings = Settings()

            # Check defaults
            assert settings.securi_env == "production"
            assert settings.debug is False
            assert settings.log_level == "INFO"
            assert settings.gitlab_url is None  # Required, should raise if not set
            assert settings.agent_confidence_threshold == 0.85
            assert settings.agent_severity_threshold == "medium"
            assert settings.compliance_frameworks == ["sox", "hipaa", "gdpr", "pci_dss", "iso27001", "nist"]
            assert settings.notification_channels == []
            assert settings.audit_log_retention_days == 365
            assert settings.max_concurrent_agents == 5
            assert settings.batch_size == 50
            assert settings.cache_ttl == 300

        finally:
            # Restore original environment
            for var, value in original.items():
                if value is not None:
                    os.environ[var] = value

    def test_development_environment(self):
        """Test development environment settings."""
        import os
        os.environ['SECURAI_ENV'] = 'development'
        os.environ['SECURAI_DEBUG'] = 'true'
        os.environ['LOG_LEVEL'] = 'DEBUG'

        settings = Settings()

        assert settings.securi_env == "development"
        assert settings.debug is True
        assert settings.log_level == "DEBUG"

    def test_test_environment(self):
        """Test test environment settings."""
        import os
        os.environ['SECURAI_ENV'] = 'test'

        settings = Settings()

        assert settings.securi_env == "test"
        assert settings.debug is True  # Test implies debug

    def test_staging_environment(self):
        """Test staging environment settings."""
        import os
        os.environ['SECURAI_ENV'] = 'staging'

        settings = Settings()

        assert settings.securi_env == "staging"
        assert settings.debug is False

    def test_production_environment(self):
        """Test production environment settings."""
        import os
        os.environ['SECURAI_ENV'] = 'production'

        settings = Settings()

        assert settings.securi_env == "production"
        assert settings.debug is False


class TestRequiredFields:
    """Test required configuration fields."""

    def test_missing_gitlab_url_raises(self):
        """Test that missing GitLab URL raises validation error."""
        import os
        # Ensure GitLab URL is not set
        if 'GITLAB_URL' in os.environ:
            del os.environ['GITLAB_URL']

        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "gitlab_url" in str(exc_info.value)

    def test_missing_gitlab_token_raises(self):
        """Test that missing GitLab token raises validation error."""
        import os
        if 'GITLAB_TOKEN' in os.environ:
            del os.environ['GITLAB_TOKEN']
        if 'GITLAB_URL' not in os.environ:
            os.environ['GITLAB_URL'] = 'https://gitlab.com'

        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "gitlab_token" in str(exc_info.value)

    def test_missing_anthropic_api_key_raises(self):
        """Test that missing Anthropic API key raises validation error."""
        import os
        if 'ANTHROPIC_API_KEY' in os.environ:
            del os.environ['ANTHROPIC_API_KEY']
        if 'GITLAB_URL' not in os.environ:
            os.environ['GITLAB_URL'] = 'https://gitlab.com'
        if 'GITLAB_TOKEN' not in os.environ:
            os.environ['GITLAB_TOKEN'] = 'test-token'

        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "anthropic_api_key" in str(exc_info.value)

    def test_missing_database_url_raises(self):
        """Test that missing database URL raises validation error."""
        import os
        if 'DATABASE_URL' in os.environ:
            del os.environ['DATABASE_URL']
        if 'GITLAB_URL' not in os.environ:
            os.environ['GITLAB_URL'] = 'https://gitlab.com'
        if 'GITLAB_TOKEN' not in os.environ:
            os.environ['GITLAB_TOKEN'] = 'test-token'
        if 'ANTHROPIC_API_KEY' not in os.environ:
            os.environ['ANTHROPIC_API_KEY'] = 'test-key'

        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "database_url" in str(exc_info.value)


class TestOptionalFields:
    """Test optional configuration fields with valid values."""

    def test_redis_url_optional(self):
        """Test Redis URL is optional."""
        import os
        # Set required fields
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        # Ensure Redis URL is not set
        if 'REDIS_URL' in os.environ:
            del os.environ['REDIS_URL']

        settings = Settings()
        assert settings.redis_url is None

    def test_redis_url_custom(self):
        """Test custom Redis URL."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'
        os.environ['REDIS_URL'] = 'redis://localhost:6380'

        settings = Settings()
        assert settings.redis_url == 'redis://localhost:6380'

    def test_notification_channels_list(self):
        """Test notification channels configuration."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'
        os.environ['NOTIFICATION_CHANNELS'] = 'slack,pagerduty,email'

        settings = Settings()
        assert settings.notification_channels == ["slack", "pagerduty", "email"]

    def test_notification_channels_empty(self):
        """Test empty notification channels."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'
        os.environ['NOTIFICATION_CHANNELS'] = ''

        settings = Settings()
        assert settings.notification_channels == []


class TestAgentConfiguration:
    """Test agent-specific configuration."""

    def test_agent_auto_fix_enabled(self):
        """Test auto-fix enabled flag."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        os.environ['AGENT_AUTO_FIX_ENABLED'] = 'true'
        settings = Settings()
        assert settings.agent_auto_fix_enabled is True

        os.environ['AGENT_AUTO_FIX_ENABLED'] = 'false'
        settings = Settings()
        assert settings.agent_auto_fix_enabled is False

    def test_agent_confidence_threshold_bounds(self):
        """Test confidence threshold is between 0 and 1."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        # Valid thresholds
        for threshold in [0.0, 0.5, 0.85, 1.0]:
            os.environ['AGENT_CONFIDENCE_THRESHOLD'] = str(threshold)
            settings = Settings()
            assert 0 <= settings.agent_confidence_threshold <= 1

        # Invalid threshold
        os.environ['AGENT_CONFIDENCE_THRESHOLD'] = '1.5'
        with pytest.raises(ValidationError):
            Settings()

    def test_agent_severity_threshold(self):
        """Test severity threshold accepts valid values."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        valid_thresholds = ["low", "medium", "high", "critical"]

        for threshold in valid_thresholds:
            os.environ['AGENT_SEVERITY_THRESHOLD'] = threshold
            settings = Settings()
            assert settings.agent_severity_threshold == threshold

    def test_agent_max_concurrent_agents(self):
        """Test max concurrent agents configuration."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        os.environ['MAX_CONCURRENT_AGENTS'] = '10'
        settings = Settings()
        assert settings.max_concurrent_agents == 10

        # Test minimum
        os.environ['MAX_CONCURRENT_AGENTS'] = '1'
        settings = Settings()
        assert settings.max_concurrent_agents == 1

        # Test invalid (0)
        os.environ['MAX_CONCURRENT_AGENTS'] = '0'
        with pytest.raises(ValidationError):
            Settings()


class TestComplianceConfiguration:
    """Test compliance framework configuration."""

    def test_default_compliance_frameworks(self):
        """Test default compliance frameworks list."""
        import os
        # Set required fields
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        settings = Settings()
        expected = ["sox", "hipaa", "gdpr", "pci_dss", "iso27001", "nist"]
        assert settings.compliance_frameworks == expected

    def test_custom_compliance_frameworks(self):
        """Test custom compliance frameworks list."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'
        os.environ['COMPLIANCE_FRAMEWORKS'] = 'hipaa,gdpr'

        settings = Settings()
        assert settings.compliance_frameworks == ["hipaa", "gdpr"]

    def test_invalid_compliance_framework_ignored(self):
        """Test that invalid framework names are filtered out."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'
        os.environ['COMPLIANCE_FRAMEWORKS'] = 'hipaa,invalid,gdpr'

        settings = Settings()
        # Only valid frameworks should be included
        assert "hipaa" in settings.compliance_frameworks
        assert "gdpr" in settings.compliance_frameworks
        assert "invalid" not in settings.compliance_frameworks


class TestPerformanceConfiguration:
    """Test performance-related configuration."""

    def test_batch_size_validation(self):
        """Test batch size must be positive."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        os.environ['BATCH_SIZE'] = '100'
        settings = Settings()
        assert settings.batch_size == 100

        # Invalid: negative
        os.environ['BATCH_SIZE'] = '-10'
        with pytest.raises(ValidationError):
            Settings()

    def test_cache_ttl_validation(self):
        """Test cache TTL must be non-negative."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        os.environ['CACHE_TTL'] = '600'
        settings = Settings()
        assert settings.cache_ttl == 600

        # Zero is valid (disabled cache)
        os.environ['CACHE_TTL'] = '0'
        settings = Settings()
        assert settings.cache_ttl == 0


class TestSecurityConfiguration:
    """Test security-related configuration."""

    def test_audit_log_retention_days(self):
        """Test audit log retention period."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        os.environ['AUDIT_LOG_RETENTION_DAYS'] = '90'
        settings = Settings()
        assert settings.audit_log_retention_days == 90

        # Default is 365
        if 'AUDIT_LOG_RETENTION_DAYS' in os.environ:
            del os.environ['AUDIT_LOG_RETENTION_DAYS']
        settings = Settings()
        assert settings.audit_log_retention_days == 365

    def test_immutable_audit_trail_default(self):
        """Test immutable audit trail is enabled by default."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        if 'IMMUTABLE_AUDIT_TRAIL' in os.environ:
            del os.environ['IMMUTABLE_AUDIT_TRAIL']

        settings = Settings()
        assert settings.immutable_audit_trail is True


class TestGetSettingsSingleton:
    """Test get_settings singleton function."""

    def test_get_settings_returns_same_instance(self):
        """Test that get_settings returns cached instance."""
        import os
        # Ensure clean state
        if 'GITLAB_URL' in os.environ:
            del os.environ['GITLAB_URL']
        if 'GITLAB_TOKEN' in os.environ:
            del os.environ['GITLAB_TOKEN']
        if 'ANTHROPIC_API_KEY' in os.environ:
            del os.environ['ANTHROPIC_API_KEY']
        if 'DATABASE_URL' in os.environ:
            del os.environ['DATABASE_URL']

        # Set required fields
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        # Clear the global cache
        from core.config import _settings
        import core.config
        core.config._settings = None

        settings1 = get_settings()
        settings2 = get_settings()

        assert settings1 is settings2  # Same instance

    def test_get_settings_loads_from_env(self):
        """Test that get_settings loads from environment."""
        import os
        # Clear cache
        import core.config
        core.config._settings = None

        # Set required fields
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        settings = get_settings()
        assert settings.gitlab_url == 'https://gitlab.com'
        assert settings.gitlab_token == 'test-token'


class TestConfigurationEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string_handling(self):
        """Test handling of empty string environment variables."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        # Empty optional fields should be treated as None/empty
        os.environ['NOTIFICATION_CHANNELS'] = ''
        settings = Settings()
        assert settings.notification_channels == []

    def test_whitespace_in_lists(self):
        """Test that whitespace in comma-separated lists is trimmed."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'
        os.environ['COMPLIANCE_FRAMEWORKS'] = ' hipaa , gdpr , pci_dss '

        settings = Settings()
        assert all(not f.startswith(' ') and not f.endswith(' ') for f in settings.compliance_frameworks)
        assert "hipaa" in settings.compliance_frameworks
        assert "gdpr" in settings.compliance_frameworks
        assert "pci_dss" in settings.compliance_frameworks

    def test_case_sensitivity(self):
        """Test that environment variable names are case-sensitive."""
        import os
        os.environ['GITLAB_URL'] = 'https://gitlab.com'
        os.environ['GITLAB_TOKEN'] = 'test-token'
        os.environ['ANTHROPIC_API_KEY'] = 'test-key'
        os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost/db'

        # Lowercase should work
        os.environ['securi_env'] = 'development'
        settings = Settings()
        # Pydantic settings are case-insensitive by default for env vars
        # But the field name is 'securi_env', so it should work
        assert settings.securi_env == 'development'
