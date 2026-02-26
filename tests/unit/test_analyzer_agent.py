"""
Comprehensive test suite for AnalyzerAgent.
Target: 100% coverage of analyzer_agent.py
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from agents.analyzer_agent import AnalyzerAgent, AnalyzedVulnerability
from core.models import Vulnerability, Severity, VulnerabilitySource
from core.config import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.anthropic_api_key = "test-key"
    settings.anthropic_model = "claude-3.5-sonnet"
    settings.analyzer_confidence_threshold = 0.85
    settings.analyzer_max_tokens = 4000
    settings.analyzer_temperature = 0.1
    return settings


@pytest.fixture
def mock_gitlab_client():
    """Create mock GitLab client."""
    client = AsyncMock()
    client.get_repository_file.return_value = "def vulnerable_function():\n    sql = 'SELECT * FROM users WHERE id = ' + user_input\n    cursor.execute(sql)"
    return client


@pytest.fixture
def mock_knowledge_graph():
    """Create mock knowledge graph."""
    kg = AsyncMock()
    kg.get_historical_patterns.return_value = {
        "vulnerability_type": "SQL_INJECTION",
        "common_fix_pattern": "Use parameterized queries",
        "avg_remediation_time": 2.5,
        "success_rate": 0.92
    }
    return kg


@pytest.fixture
def analyzer_agent(mock_settings, mock_gitlab_client, mock_knowledge_graph):
    """Create AnalyzerAgent instance with mocked dependencies."""
    agent = AnalyzerAgent(
        settings=mock_settings,
        gitlab_client=mock_gitlab_client,
        knowledge_graph=mock_knowledge_graph
    )
    return agent


class TestAnalyzerAgentInitialization:
    """Test AnalyzerAgent initialization and configuration."""

    def test_init_with_all_dependencies(self, analyzer_agent):
        """Test successful initialization with all dependencies."""
        assert analyzer_agent.settings is not None
        assert analyzer_agent.gitlab_client is not None
        assert analyzer_agent.knowledge_graph is not None
        assert analyzer_agent.anthropic_client is None  # Lazy loaded
        assert analyzer_agent.rate_limiter is None  # Lazy loaded

    def test_lazy_anthropic_client_creation(self, analyzer_agent):
        """Test that Anthropic client is created lazily."""
        assert analyzer_agent.anthropic_client is None
        client = analyzer_agent._get_anthropic_client()
        assert client is not None
        # Second call should return cached client
        client2 = analyzer_agent._get_anthropic_client()
        assert client is client2

    def test_rate_limiter_creation(self, analyzer_agent):
        """Test that rate limiter is created."""
        assert analyzer_agent.rate_limiter is None
        analyzer_agent._ensure_rate_limiter()
        assert analyzer_agent.rate_limiter is not None


class TestAnalyzerAgentPromptConstruction:
    """Test system prompt and user prompt construction."""

    def test_system_prompt_contains_security_expertise(self, analyzer_agent):
        """Test system prompt defines expert security analyst."""
        system_prompt = analyzer_agent._get_system_prompt()
        assert "expert security analyst" in system_prompt.lower()
        assert "cvss" in system_prompt.lower()
        assert "owasp" in system_prompt.lower()

    def test_system_prompt_includes_frameworks(self, analyzer_agent):
        """Test system prompt mentions security frameworks."""
        system_prompt = analyzer_agent._get_system_prompt()
        assert "MITRE ATT&CK" in system_prompt
        assert "SANS" in system_prompt or "CWE" in system_prompt

    def test_system_prompt_requires_json_output(self, analyzer_agent):
        """Test system prompt requires JSON output format."""
        system_prompt = analyzer_agent._get_system_prompt()
        assert "JSON" in system_prompt
        assert "valid JSON" in system_prompt.lower()

    def test_build_user_prompt_includes_vulnerability_data(self, analyzer_agent):
        """Test user prompt includes all vulnerability details."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="User input not sanitized",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            file_path="app/main.py",
            line_number=42,
            code_snippet="sql = 'SELECT * FROM users WHERE id = ' + user_input",
            cwe_id="CWE-89",
            confidence=0.9
        )
        code_context = "def vulnerable_function():\n    sql = 'SELECT * FROM users WHERE id = ' + user_input\n    cursor.execute(sql)"
        mr_context = {
            "project_path": "mygroup/myproject",
            "mr_title": "Add user search feature",
            "mr_description": "This MR adds search functionality"
        }

        prompt = analyzer_agent._build_user_prompt(vuln, code_context, mr_context)

        assert vuln.title in prompt
        assert vuln.description in prompt
        assert vuln.file_path in prompt
        assert code_context in prompt
        assert mr_context["project_path"] in prompt

    def test_build_user_prompt_includes_historical_patterns(self, analyzer_agent):
        """Test user prompt includes historical patterns from knowledge graph."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="Test",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST
        )
        code_context = "test code"
        mr_context = {}

        historical = {
            "vulnerability_type": "SQL_INJECTION",
            "common_fix_pattern": "Use parameterized queries",
            "avg_remediation_time": 2.5,
            "success_rate": 0.92
        }

        prompt = analyzer_agent._build_user_prompt(vuln, code_context, mr_context, historical)

        assert "SQL_INJECTION" in prompt
        assert "parameterized queries" in prompt
        assert "2.5" in prompt  # avg time

    def test_build_user_prompt_without_historical_data(self, analyzer_agent):
        """Test user prompt works without historical patterns."""
        vuln = Vulnerability(
            id="VULN-001",
            title="XSS",
            description="Test",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST
        )
        prompt = analyzer_agent._build_user_prompt(vuln, "code", {})
        assert "XSS" in prompt
        assert "No historical data available" in prompt


class TestAnalyzerAgentResponseParsing:
    """Test response parsing from Claude API."""

    def test_parse_json_response_success(self, analyzer_agent):
        """Test parsing successful JSON response."""
        response_text = """
        {
            "analysis": {
                "root_cause": "Unsanitized user input in SQL query",
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "Required",
                "scope": "Unchanged",
                "impact": "High - Database compromise"
            },
            "false_positive_probability": 0.05,
            "confidence": 0.95,
            "priority_score": 0.87,
            "remediation_effort": 3.5,
            "suggested_fix": "Use parameterized queries with placeholders"
        }
        """
        result = analyzer_agent._parse_analysis_response(response_text)

        assert result["analysis"]["root_cause"] == "Unsanitized user input in SQL query"
        assert result["false_positive_probability"] == 0.05
        assert result["confidence"] == 0.95
        assert result["priority_score"] == 0.87
        assert result["remediation_effort"] == 3.5

    def test_parse_json_response_with_markdown_code_block(self, analyzer_agent):
        """Test parsing JSON wrapped in markdown code block."""
        response_text = """
        ```json
        {
            "analysis": {
                "root_cause": "Test cause"
            },
            "confidence": 0.9
        }
        ```
        """
        result = analyzer_agent._parse_analysis_response(response_text)
        assert result["analysis"]["root_cause"] == "Test cause"
        assert result["confidence"] == 0.9

    def test_parse_json_response_with_trailing_text(self, analyzer_agent):
        """Test parsing JSON with trailing explanatory text."""
        response_text = """
        {
            "analysis": {"root_cause": "Test"},
            "confidence": 0.85
        }
        I hope this analysis helps!
        """
        result = analyzer_agent._parse_analysis_response(response_text)
        assert result["confidence"] == 0.85

    def test_parse_fallback_text_response(self, analyzer_agent):
        """Test fallback parsing for non-JSON responses."""
        response_text = """
        Analysis:
        Root cause: Unsanitized input in SQL query
        Confidence: High (0.9)
        Priority: Critical
        False positive probability: Low (0.05)
        """
        result = analyzer_agent._parse_analysis_response(response_text)

        assert "root_cause" in result["analysis"]
        assert result["analysis"]["root_cause"] == "Unsanitized input in SQL query"
        assert result["confidence"] == 0.9
        assert result["false_positive_probability"] == 0.05

    def test_parse_response_with_malformed_json(self, analyzer_agent):
        """Test parsing gracefully handles malformed JSON."""
        response_text = """
        {
            "analysis": {"root_cause": "Test"},
            "confidence": 0.9,
            malformed_json
        """
        result = analyzer_agent._parse_analysis_response(response_text)
        # Should fall back to text parsing
        assert "analysis" in result
        assert "confidence" in result

    def test_parse_response_empty(self, analyzer_agent):
        """Test parsing empty response."""
        result = analyzer_agent._parse_analysis_response("")
        assert result["analysis"]["root_cause"] == "Unable to parse analysis"
        assert result["confidence"] == 0.5


class TestAnalyzerAgentScoring:
    """Test priority score calculation and CVSS scoring."""

    def test_calculate_priority_score_basic(self, analyzer_agent):
        """Test basic priority score calculation."""
        score = analyzer_agent._calculate_priority_score(
            severity_weight=1.0,
            exploitability=0.8,
            impact_factor=0.9,
            remediation_effort=2.0
        )
        # Formula: severity_weight * exploitability * impact_factor / (remediation_effort + 1)
        expected = 1.0 * 0.8 * 0.9 / (2.0 + 1)
        assert abs(score - expected) < 0.001

    def test_calculate_priority_score_high_severity(self, analyzer_agent):
        """Test priority score with critical severity."""
        score = analyzer_agent._calculate_priority_score(
            severity_weight=1.2,  # Critical
            exploitability=0.9,
            impact_factor=1.0,
            remediation_effort=1.0
        )
        assert score > 0.9

    def test_calculate_priority_score_low_exploitability(self, analyzer_agent):
        """Test priority score with low exploitability."""
        score = analyzer_agent._calculate_priority_score(
            severity_weight=1.0,
            exploitability=0.2,
            impact_factor=0.5,
            remediation_effort=3.0
        )
        assert score < 0.2

    def test_extract_cvss_components_from_analysis(self, analyzer_agent):
        """Test extraction of CVSS components from analysis."""
        analysis = {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "Required",
            "scope": "Unchanged",
            "impact": "High"
        }
        cvss = analyzer_agent._extract_cvss_components(analysis)

        assert cvss["attack_vector"] == "Network"
        assert cvss["attack_complexity"] == "Low"
        assert cvss["privileges_required"] == "None"
        assert cvss["user_interaction"] == "Required"
        assert cvss["scope"] == "Unchanged"
        assert cvss["impact"] == "High"

    def test_extract_cvss_components_with_defaults(self, analyzer_agent):
        """Test CVSS extraction with missing fields uses defaults."""
        analysis = {"impact": "High"}
        cvss = analyzer_agent._extract_cvss_components(analysis)

        assert cvss["attack_vector"] == "Local"  # Default
        assert cvss["attack_complexity"] == "Low"  # Default
        assert cvss["privileges_required"] == "None"  # Default
        assert cvss["user_interaction"] == "None"  # Default
        assert cvss["scope"] == "Unchanged"  # Default
        assert cvss["impact"] == "High"


class TestAnalyzerAgentCodeContext:
    """Test code context fetching and extraction."""

    @pytest.mark.asyncio
    async def test_fetch_code_context_success(self, analyzer_agent, mock_gitlab_client):
        """Test successful code context fetching."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/main.py",
            line_number=42
        )

        context = await analyzer_agent._fetch_code_context(vuln, "project-123", "main")

        assert context is not None
        assert "vulnerable_function" in context
        mock_gitlab_client.get_repository_file.assert_called_once_with(
            "project-123", "main", "app/main.py"
        )

    @pytest.mark.asyncio
    async def test_fetch_code_context_file_not_found(self, analyzer_agent, mock_gitlab_client):
        """Test code context fetching when file doesn't exist."""
        mock_gitlab_client.get_repository_file.return_value = None
        vuln = Vulnerability(
            id="VULN-001",
            file_path="nonexistent.py",
            line_number=1
        )

        context = await analyzer_agent._fetch_code_context(vuln, "project-123", "main")

        assert context is None

    @pytest.mark.asyncio
    async def test_fetch_code_context_uses_default_branch(self, analyzer_agent, mock_gitlab_client):
        """Test code context uses default branch when branch not specified."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/main.py",
            line_number=42
        )

        await analyzer_agent._fetch_code_context(vuln, "project-123")

        mock_gitlab_client.get_repository_file.assert_called_once()
        call_args = mock_gitlab_client.get_repository_file.call_args
        assert call_args[0][2] is None  # branch parameter is None

    def test_extract_surrounding_code(self, analyzer_agent):
        """Test extraction of surrounding code context."""
        code = """line1
line2
line3
line4
line5"""
        context = analyzer_agent._extract_surrounding_code(code, target_line=3, context_lines=2)

        expected = "line1\nline2\nline3\nline4\nline5"
        assert context == expected

    def test_extract_surrounding_code_at_start(self, analyzer_agent):
        """Test surrounding code extraction at file start."""
        code = "line1\nline2\nline3"
        context = analyzer_agent._extract_surrounding_code(code, target_line=1, context_lines=2)
        assert "line1" in context
        assert "line2" in context

    def test_extract_surrounding_code_at_end(self, analyzer_agent):
        """Test surrounding code extraction at file end."""
        code = "line1\nline2\nline3"
        context = analyzer_agent._extract_surrounding_code(code, target_line=3, context_lines=2)
        assert "line2" in context
        assert "line3" in context


class TestAnalyzerAgentAnalysis:
    """Test main analysis functionality."""

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_success(self, analyzer_agent, mock_gitlab_client):
        """Test successful vulnerability analysis."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="User input not sanitized",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            file_path="app/main.py",
            line_number=42,
            code_snippet="sql = 'SELECT * FROM users WHERE id = ' + user_input",
            cwe_id="CWE-89",
            confidence=0.9
        )

        # Mock Anthropic response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="""
        {
            "analysis": {
                "root_cause": "String concatenation with user input",
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "Required",
                "scope": "Unchanged",
                "impact": "High - Complete database access"
            },
            "false_positive_probability": 0.05,
            "confidence": 0.95,
            "priority_score": 0.87,
            "remediation_effort": 2.0,
            "suggested_fix": "Use parameterized queries with ? placeholders"
        }
        """)]

        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.return_value = mock_response

        result = await analyzer_agent.analyze_vulnerability(
            vuln, "project-123", "main", "mr-456"
        )

        assert isinstance(result, AnalyzedVulnerability)
        assert result.vulnerability_id == "VULN-001"
        assert result.confidence == 0.95
        assert result.priority_score == 0.87
        assert result.false_positive_probability == 0.05
        assert result.remediation_effort == 2.0
        assert "parameterized queries" in result.suggested_fix

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_with_historical_patterns(self, analyzer_agent, mock_gitlab_client):
        """Test analysis includes historical patterns."""
        vuln = Vulnerability(
            id="VULN-002",
            title="XSS",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST
        )

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="""
        {
            "analysis": {"root_cause": "Unescaped user input"},
            "confidence": 0.9,
            "priority_score": 0.7
        }
        """)]

        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.return_value = mock_response

        # Mock knowledge graph to return historical data
        analyzer_agent.knowledge_graph.get_historical_patterns.return_value = {
            "vulnerability_type": "XSS",
            "common_fix_pattern": "HTML escape output",
            "avg_remediation_time": 1.5,
            "success_rate": 0.88
        }

        result = await analyzer_agent.analyze_vulnerability(vuln, "project-123")

        # Verify historical patterns were fetched
        analyzer_agent.knowledge_graph.get_historical_patterns.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_anthropic_error(self, analyzer_agent, mock_gitlab_client):
        """Test analysis handles Anthropic API errors gracefully."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST
        )

        # Simulate API error
        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.side_effect = Exception("API Error")

        result = await analyzer_agent.analyze_vulnerability(vuln, "project-123")

        # Should return failed analysis with default values
        assert result.vulnerability_id == "VULN-001"
        assert result.confidence == 0.5  # Default
        assert result.false_positive_probability == 0.3  # Default
        assert "error" in result.analysis["root_cause"].lower()

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_low_confidence(self, analyzer_agent, mock_gitlab_client):
        """Test analysis with low confidence result."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST
        )

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="""
        {
            "analysis": {"root_cause": "Potential issue"},
            "confidence": 0.4,
            "false_positive_probability": 0.6
        }
        """)]

        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.return_value = mock_response

        result = await analyzer_agent.analyze_vulnerability(vuln, "project-123")

        assert result.confidence == 0.4
        assert result.false_positive_probability == 0.6

    @pytest.mark.asyncio
    async def test_analyze_batch_empty_list(self, analyzer_agent):
        """Test batch analysis with empty list."""
        results = await analyzer_agent.analyze_batch([], "project-123")
        assert results == []

    @pytest.mark.asyncio
    async def test_analyze_batch_concurrent_limit(self, analyzer_agent, mock_gitlab_client):
        """Test batch analysis respects concurrency limits."""
        vulns = [
            Vulnerability(id=f"VULN-{i}", title=f"Test {i}", severity=Severity.MEDIUM, source=VulnerabilitySource.SAST)
            for i in range(10)
        ]

        # Mock slow API responses
        async def slow_api_call(*args, **kwargs):
            import asyncio
            await asyncio.sleep(0.1)
            mock_response = MagicMock()
            mock_response.content = [MagicMock(text='{"analysis": {}, "confidence": 0.9}')]
            return mock_response

        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.side_effect = slow_api_call

        results = await analyzer_agent.analyze_batch(vulns, "project-123", max_concurrent=3)

        assert len(results) == 10
        assert all(r.confidence == 0.9 for r in results)

    @pytest.mark.asyncio
    async def test_analyze_batch_prioritization(self, analyzer_agent, mock_gitlab_client):
        """Test batch analysis prioritizes high-severity vulnerabilities."""
        vulns = [
            Vulnerability(id="VULN-LOW", title="Low", severity=Severity.LOW, source=VulnerabilitySource.SAST),
            Vulnerability(id="VULN-CRITICAL", title="Critical", severity=Severity.CRITICAL, source=VulnerabilitySource.SAST),
            Vulnerability(id="VULN-MEDIUM", title="Medium", severity=Severity.MEDIUM, source=VulnerabilitySource.SAST),
        ]

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"analysis": {}, "confidence": 0.9}')]
        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.return_value = mock_response

        results = await analyzer_agent.analyze_batch(vulns, "project-123")

        # Should analyze all (no filtering in batch - filtering happens in orchestrator)
        assert len(results) == 3


class TestAnalyzerAgentPrioritization:
    """Test vulnerability prioritization logic."""

    def test_should_prioritize_high_severity(self, analyzer_agent):
        """Test high severity vulnerabilities are prioritized."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Critical SQL Injection",
            severity=Severity.CRITICAL,
            source=VulnerabilitySource.SAST,
            confidence=0.9
        )
        analyzed = AnalyzedVulnerability(
            vulnerability_id=vuln.id,
            confidence=0.95,
            false_positive_probability=0.1,
            priority_score=0.9
        )

        assert analyzer_agent._should_prioritize(vuln, analyzed) is True

    def test_should_prioritize_high_confidence(self, analyzer_agent):
        """Test high confidence vulnerabilities are prioritized."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Medium Issue",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST,
            confidence=0.95
        )
        analyzed = AnalyzedVulnerability(
            vulnerability_id=vuln.id,
            confidence=0.98,
            false_positive_probability=0.05,
            priority_score=0.7
        )

        assert analyzer_agent._should_prioritize(vuln, analyzed) is True

    def test_should_not_prioritize_low_confidence(self, analyzer_agent):
        """Test low confidence vulnerabilities are not prioritized."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Low Confidence",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST,
            confidence=0.3
        )
        analyzed = AnalyzedVulnerability(
            vulnerability_id=vuln.id,
            confidence=0.4,
            false_positive_probability=0.5,
            priority_score=0.3
        )

        assert analyzer_agent._should_prioritize(vuln, analyzed) is False

    def test_should_not_prioritize_high_false_positive(self, analyzer_agent):
        """Test high false positive probability excludes prioritization."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Potential FP",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            confidence=0.8
        )
        analyzed = AnalyzedVulnerability(
            vulnerability_id=vuln.id,
            confidence=0.8,
            false_positive_probability=0.6,  # High FP probability
            priority_score=0.8
        )

        assert analyzer_agent._should_prioritize(vuln, analyzed) is False

    def test_prioritization_thresholds_configurable(self, mock_settings):
        """Test prioritization thresholds are configurable."""
        mock_settings.analyzer_confidence_threshold = 0.9
        mock_settings.analyzer_fp_threshold = 0.15

        agent = AnalyzerAgent(
            settings=mock_settings,
            gitlab_client=AsyncMock(),
            knowledge_graph=AsyncMock()
        )

        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            confidence=0.85  # Below 0.9 threshold
        )
        analyzed = AnalyzedVulnerability(
            vulnerability_id=vuln.id,
            confidence=0.85,
            false_positive_probability=0.1,
            priority_score=0.8
        )

        assert agent._should_prioritize(vuln, analyzed) is False


class TestAnalyzerAgentHealth:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_all_healthy(self, analyzer_agent):
        """Test health check when all components are healthy."""
        health = await analyzer_agent.health_check()

        assert health["status"] == "healthy"
        assert health["anthropic_client"] is True
        assert health["rate_limiter"] is True
        assert health["knowledge_graph"] is True

    @pytest.mark.asyncio
    async def test_health_check_anthropic_failure(self, analyzer_agent):
        """Test health check when Anthropic API fails."""
        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.side_effect = Exception("API Down")

        health = await analyzer_agent.health_check()

        assert health["status"] == "degraded"
        assert health["anthropic_client"] is False

    @pytest.mark.asyncio
    async def test_health_check_rate_limiter_error(self, analyzer_agent):
        """Test health check when rate limiter fails."""
        analyzer_agent.rate_limiter = MagicMock()
        analyzer_agent.rate_limiter.check.side_effect = Exception("Rate limiter error")

        health = await analyzer_agent.health_check()

        assert health["status"] == "degraded"
        assert health["rate_limiter"] is False


class TestAnalyzerAgentStatistics:
    """Test statistics tracking."""

    def test_get_statistics_initial(self, analyzer_agent):
        """Test statistics on fresh agent."""
        stats = analyzer_agent.get_statistics()

        assert stats["analyses_completed"] == 0
        assert stats["analyses_failed"] == 0
        assert stats["api_calls"] == 0
        assert stats["cache_hits"] == 0
        assert stats["avg_analysis_time_ms"] == 0

    def test_statistics_after_analyses(self, analyzer_agent):
        """Test statistics after some analyses."""
        # Simulate some activity
        analyzer_agent._analyses_completed = 10
        analyzer_agent._analyses_failed = 2
        analyzer_agent._api_calls = 15
        analyzer_agent._cache_hits = 5
        analyzer_agent._total_analysis_time = 5000  # ms

        stats = analyzer_agent.get_statistics()

        assert stats["analyses_completed"] == 10
        assert stats["analyses_failed"] == 2
        assert stats["api_calls"] == 15
        assert stats["cache_hits"] == 5
        assert stats["avg_analysis_time_ms"] == 500.0  # 5000/10
        assert stats["success_rate"] == pytest.approx(10 / (10 + 2))


class TestAnalyzerAgentErrorHandling:
    """Test error handling and resilience."""

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_with_missing_data(self, analyzer_agent):
        """Test analysis with minimal vulnerability data."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.UNKNOWN,
            source=VulnerabilitySource.SAST
        )

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"analysis": {}, "confidence": 0.5}')]
        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.return_value = mock_response

        result = await analyzer_agent.analyze_vulnerability(vuln, "project-123")

        # Should still succeed with defaults
        assert result.vulnerability_id == "VULN-001"
        assert result.confidence >= 0

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_network_error(self, analyzer_agent):
        """Test analysis handles network errors."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST
        )

        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.side_effect = ConnectionError("Network down")

        result = await analyzer_agent.analyze_vulnerability(vuln, "project-123")

        # Should return failed analysis
        assert result.confidence == 0.5
        assert "error" in result.analysis["root_cause"].lower()

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_timeout(self, analyzer_agent):
        """Test analysis handles timeouts."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST
        )

        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.side_effect = TimeoutError("Timeout")

        result = await analyzer_agent.analyze_vulnerability(vuln, "project-123")

        assert result.confidence == 0.5
        assert "timeout" in result.analysis["root_cause"].lower()


class TestAnalyzerAgentIntegration:
    """Integration tests with orchestrator."""

    @pytest.mark.asyncio
    async def test_full_analysis_workflow(self, analyzer_agent, mock_gitlab_client):
        """Test complete analysis workflow from vulnerability to analyzed result."""
        # Create realistic vulnerability
        vuln = Vulnerability(
            id="SECUREAI-2024-001",
            title="SQL Injection in User Search",
            description="The user search feature constructs SQL queries using string concatenation, allowing attackers to inject arbitrary SQL commands.",
            severity=Severity.CRITICAL,
            source=VulnerabilitySource.SAST,
            file_path="app/views.py",
            line_number=156,
            code_snippet="query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''",
            cwe_id="CWE-89",
            confidence=0.92,
            scanner_id="bandit-1.7.5"
        )

        # Mock code context
        mock_gitlab_client.get_repository_file.return_value = """
        def search_users(username):
            query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''
            cursor.execute(query)
            return cursor.fetchall()
        """

        # Mock Claude response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="""
        {
            "analysis": {
                "root_cause": "SQL query constructed via string concatenation with unsanitized user input",
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "impact": "Complete database compromise, data exfiltration, privilege escalation"
            },
            "false_positive_probability": 0.02,
            "confidence": 0.98,
            "priority_score": 0.95,
            "remediation_effort": 1.5,
            "suggested_fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
        }
        """)]

        analyzer_agent.anthropic_client = MagicMock()
        analyzer_agent.anthropic_client.messages.create.return_value = mock_response

        # Execute analysis
        result = await analyzer_agent.analyze_vulnerability(vuln, "secureai-demo", "main")

        # Verify comprehensive result
        assert isinstance(result, AnalyzedVulnerability)
        assert result.vulnerability_id == "SECUREAI-2024-001"
        assert result.confidence == 0.98
        assert result.priority_score == 0.95
        assert result.false_positive_probability == 0.02
        assert result.remediation_effort == 1.5
        assert "parameterized queries" in result.suggested_fix
        assert result.analysis["attack_vector"] == "Network"
        assert result.analysis["impact"] == "Complete database compromise, data exfiltration, privilege escalation"

        # Verify API was called correctly
        analyzer_agent.anthropic_client.messages.create.assert_called_once()
        call_kwargs = analyzer_agent.anthropic_client.messages.create.call_args[1]
        assert call_kwargs["model"] == "claude-3.5-sonnet"
        assert "system" in call_kwargs
        assert "user" in call_kwargs
