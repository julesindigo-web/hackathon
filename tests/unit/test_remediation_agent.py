"""
Comprehensive test suite for RemediationAgent.
Target: 100% coverage of remediation_agent.py
"""

import pytest
import tempfile
import os
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from agents.remediation_agent import RemediationAgent, FixPattern, AppliedFix
from core.models import Vulnerability, AnalyzedVulnerability, Severity, VulnerabilitySource
from core.config import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.remediation_auto_apply = False
    settings.remediation_confidence_threshold = 0.85
    settings.remediation_max_fixes_per_batch = 10
    settings.gitlab_username = "test-user"
    return settings


@pytest.fixture
def mock_gitlab_client():
    """Create mock GitLab client."""
    client = AsyncMock()
    client.get_repository_file.return_value = "def vulnerable_func():\n    sql = 'SELECT * FROM users WHERE id = ' + user_input\n    cursor.execute(sql)"
    client.create_merge_request.return_value = MagicMock(
        iid=123,
        web_url="https://gitlab.com/project/mr/123"
    )
    client.add_merge_request_note.return_value = MagicMock()
    return client


@pytest.fixture
def mock_knowledge_graph():
    """Create mock knowledge graph."""
    kg = AsyncMock()
    kg.store_remediation.return_value = True
    kg.get_fix_pattern_success_rate.return_value = 0.92
    kg.record_developer_expertise.return_value = None
    return kg


@pytest.fixture
def remediation_agent(mock_settings, mock_gitlab_client, mock_knowledge_graph):
    """Create RemediationAgent instance with mocked dependencies."""
    agent = RemediationAgent(
        settings=mock_settings,
        gitlab_client=mock_gitlab_client,
        knowledge_graph=mock_knowledge_graph
    )
    return agent


class TestRemediationAgentInitialization:
    """Test RemediationAgent initialization."""

    def test_init_with_dependencies(self, remediation_agent):
        """Test successful initialization."""
        assert remediation_agent.settings is not None
        assert remediation_agent.gitlab_client is not None
        assert remediation_agent.knowledge_graph is not None
        assert len(remediation_agent.fix_patterns) > 0

    def test_fix_patterns_loaded(self, remediation_agent):
        """Test that all 15 fix patterns are loaded."""
        patterns = remediation_agent.fix_patterns
        assert len(patterns) == 15

        # Check pattern types
        pattern_types = [p.vulnerability_type for p in patterns]
        expected_types = [
            "SQL_INJECTION", "SQL_INJECTION", "XSS", "XSS", "COMMAND_INJECTION",
            "COMMAND_INJECTION", "PATH_TRAVERSAL", "SECRET_DETECTION", "SECRET_DETECTION",
            "INSECURE_DESERIALIZATION", "XXE", "SSRF", "WEAK_CRYPTO", "AUTH_BYPASS", "INSECURE_CONFIG"
        ]
        for expected in expected_types:
            assert expected in pattern_types

    def test_fix_patterns_have_required_fields(self, remediation_agent):
        """Test all fix patterns have required fields."""
        for pattern in remediation_agent.fix_patterns:
            assert pattern.id
            assert pattern.vulnerability_type
            assert pattern.name
            assert pattern.description
            assert pattern.pattern is not None
            assert pattern.confidence_threshold >= 0
            assert pattern.confidence_threshold <= 1
            assert isinstance(pattern.requires_context, bool)
            assert isinstance(pattern.creates_mr, bool)


class TestRemediationAgentPatternMatching:
    """Test fix pattern matching logic."""

    def test_match_sql_injection_pattern(self, remediation_agent):
        """Test matching SQL injection vulnerability."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection in search",
            description="User input directly concatenated in SQL query",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-89"
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is not None
        assert pattern.vulnerability_type == "SQL_INJECTION"

    def test_match_xss_pattern(self, remediation_agent):
        """Test matching XSS vulnerability."""
        vuln = Vulnerability(
            id="VULN-002",
            title="Reflected XSS",
            description="User input rendered without escaping",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-79"
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is not None
        assert pattern.vulnerability_type == "XSS"

    def test_match_command_injection(self, remediation_agent):
        """Test matching command injection."""
        vuln = Vulnerability(
            id="VULN-003",
            title="Command Injection in ping",
            description="User input passed to shell command",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-78"
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is not None
        assert pattern.vulnerability_type == "COMMAND_INJECTION"

    def test_match_path_traversal(self, remediation_agent):
        """Test matching path traversal."""
        vuln = Vulnerability(
            id="VULN-004",
            title="Path Traversal in file read",
            description="User input used in file path without validation",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-22"
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is not None
        assert pattern.vulnerability_type == "PATH_TRAVERSAL"

    def test_match_secret_detection(self, remediation_agent):
        """Test matching secret detection."""
        vuln = Vulnerability(
            id="VULN-005",
            title="Hardcoded AWS Key",
            description="AWS secret access key found in code",
            severity=Severity.CRITICAL,
            source=VulnerabilitySource.SECRET_DETECTION
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is not None
        assert pattern.vulnerability_type == "SECRET_DETECTION"

    def test_no_match_for_unknown_type(self, remediation_agent):
        """Test no pattern matched for unknown vulnerability type."""
        vuln = Vulnerability(
            id="VULN-999",
            title="Unknown Issue",
            description="Some unknown vulnerability",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-999"
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is None

    def test_match_by_cwe_id_fallback(self, remediation_agent):
        """Test matching using CWE ID when title/description don't match."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Database Query Issue",
            description="Potential SQL problem",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-89"  # SQL Injection
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is not None
        assert pattern.vulnerability_type == "SQL_INJECTION"

    def test_match_weak_crypto(self, remediation_agent):
        """Test matching weak cryptography."""
        vuln = Vulnerability(
            id="VULN-006",
            title="MD5 hash used",
            description="Weak hashing algorithm detected",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-327"
        )

        pattern = remediation_agent._find_matching_pattern(vuln)
        assert pattern is not None
        assert pattern.vulnerability_type == "WEAK_CRYPTO"


class TestRemediationAgentFixApplication:
    """Test fix application logic."""

    def test_apply_sql_injection_fix(self, remediation_agent):
        """Test applying SQL injection fix pattern."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=10,
            code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id"
        )

        pattern = remediation_agent.fix_patterns[0]  # SQL_INJECTION_01
        assert pattern.vulnerability_type == "SQL_INJECTION"

        # Mock file content
        file_content = """def get_user(user_id):
    query = 'SELECT * FROM users WHERE id = ' + user_id
    cursor.execute(query)
    return cursor.fetchone()"""

        fixed_content = remediation_agent._apply_fix_pattern(file_content, vuln, pattern)

        assert fixed_content is not None
        assert "parameterized" in fixed_content.lower() or "?" in fixed_content
        assert "query = 'SELECT * FROM users WHERE id = ' + user_id" not in fixed_content

    def test_apply_xss_fix(self, remediation_agent):
        """Test applying XSS fix pattern."""
        vuln = Vulnerability(
            id="VULN-002",
            file_path="app/template.html",
            line_number=5,
            code_snippet="<div>{{ user_input }}</div>"
        )

        pattern = remediation_agent.fix_patterns[2]  # XSS_01

        file_content = """<html>
<body>
<div>{{ user_input }}</div>
</body>
</html>"""

        fixed_content = remediation_agent._apply_fix_pattern(file_content, vuln, pattern)

        assert fixed_content is not None
        assert "escape" in fixed_content.lower() or "safe" in fixed_content.lower()

    def test_apply_command_injection_fix(self, remediation_agent):
        """Test applying command injection fix."""
        vuln = Vulnerability(
            id="VULN-003",
            file_path="app/utils.py",
            line_number=20,
            code_snippet="os.system('ping ' + hostname)"
        )

        pattern = remediation_agent.fix_patterns[4]  # CMDI_01

        file_content = """import os
def ping_host(hostname):
    os.system('ping ' + hostname)"""

        fixed_content = remediation_agent._apply_fix_pattern(file_content, vuln, pattern)

        assert fixed_content is not None
        assert "subprocess" in fixed_content.lower()
        assert "shell=False" in fixed_content or "check=True" in fixed_content

    def test_apply_secret_detection_fix(self, remediation_agent):
        """Test applying secret detection fix."""
        vuln = Vulnerability(
            id="VULN-004",
            file_path=".env",
            line_number=1,
            code_snippet="AWS_SECRET_ACCESS_KEY=sk_test_123456789"
        )

        pattern = remediation_agent.fix_patterns[7]  # SECRET_01

        file_content = """AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=sk_test_123456789
DATABASE_URL=postgresql://localhost/db"""

        fixed_content = remediation_agent._apply_fix_pattern(file_content, vuln, pattern)

        assert fixed_content is not None
        assert "REMOVED" in fixed_content or "***" in fixed_content or "environment variable" in fixed_content.lower()

    def test_apply_fix_with_no_changes(self, remediation_agent):
        """Test applying fix when pattern makes no changes (should return None)."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/test.py",
            line_number=1
        )

        # Pattern that doesn't match anything
        pattern = FixPattern(
            id="TEST_01",
            vulnerability_type="SQL_INJECTION",
            name="Test Pattern",
            description="Test",
            pattern=r"NOTHING_TO_MATCH_HERE",
            confidence_threshold=0.8,
            requires_context=False,
            creates_mr=False
        )

        file_content = "def test():\n    return 'hello'"
        fixed_content = remediation_agent._apply_fix_pattern(file_content, vuln, pattern)

        assert fixed_content is None

    def test_apply_fix_preserves_other_code(self, remediation_agent):
        """Test that fix application preserves unrelated code."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=5,
            code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id"
        )

        pattern = remediation_agent.fix_patterns[0]  # SQL_INJECTION_01

        file_content = """import os
import sys
from db import connect

def get_user(user_id):
    query = 'SELECT * FROM users WHERE id = ' + user_id
    cursor.execute(query)
    return cursor.fetchone()

def list_users():
    return get_all_users()

class UserHandler:
    pass"""

        fixed_content = remediation_agent._apply_fix_pattern(file_content, vuln, pattern)

        # Should preserve imports, other functions, classes
        assert "import os" in fixed_content
        assert "import sys" in fixed_content
        assert "def list_users" in fixed_content
        assert "class UserHandler" in fixed_content


class TestRemediationAgentSyntaxValidation:
    """Test syntax validation after fix."""

    def test_validate_python_syntax_valid(self, remediation_agent):
        """Test validation of valid Python code."""
        code = """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
"""
        is_valid, error = remediation_agent._validate_syntax(code, "python")
        assert is_valid is True
        assert error is None

    def test_validate_python_syntax_invalid(self, remediation_agent):
        """Test validation of invalid Python code."""
        code = """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,)
    return cursor.fetchone()
"""  # Missing closing parenthesis

        is_valid, error = remediation_agent._validate_syntax(code, "python")
        assert is_valid is False
        assert error is not None

    def test_validate_javascript_syntax(self, remediation_agent):
        """Test JavaScript syntax validation (basic check)."""
        code = """
function getUser(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return executeQuery(query);
}
"""
        is_valid, error = remediation_agent._validate_syntax(code, "javascript")
        # Basic check just verifies it's not Python
        assert is_valid is True  # No Python syntax errors
        assert error is None

    def test_validate_unknown_language(self, remediation_agent):
        """Test validation of unknown language skips check."""
        code = "some random code"
        is_valid, error = remediation_agent._validate_syntax(code, "unknown")
        assert is_valid is True
        assert error is None


class TestRemediationAgentVulnerabilityVerification:
    """Test vulnerability verification after fix."""

    @pytest.mark.asyncio
    async def test_verify_fix_success(self, remediation_agent, mock_gitlab_client):
        """Test successful fix verification."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=10
        )

        # Mock GitLab to return no vulnerabilities after fix
        mock_gitlab_client.get_security_vulnerabilities.return_value = []

        verified = await remediation_agent._verify_fix(vuln, "project-123", "main")

        assert verified is True
        mock_gitlab_client.get_security_vulnerabilities.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_fix_still_vulnerable(self, remediation_agent, mock_gitlab_client):
        """Test verification when vulnerability still exists."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=10
        )

        # Mock GitLab to return same vulnerability
        mock_vuln = MagicMock(spec=Vulnerability)
        mock_vuln.id = "VULN-001"
        mock_gitlab_client.get_security_vulnerabilities.return_value = [mock_vuln]

        verified = await remediation_agent._verify_fix(vuln, "project-123", "main")

        assert verified is False

    @pytest.mark.asyncio
    async def test_verify_fix_api_error(self, remediation_agent, mock_gitlab_client):
        """Test verification handles API errors."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=10
        )

        mock_gitlab_client.get_security_vulnerabilities.side_effect = Exception("API Error")

        # Should still return True (can't verify, assume fixed)
        verified = await remediation_agent._verify_fix(vuln, "project-123", "main")
        assert verified is True


class TestRemediationAgentMRCreation:
    """Test merge request creation."""

    @pytest.mark.asyncio
    async def test_create_fix_mr_success(self, remediation_agent, mock_gitlab_client):
        """Test successful MR creation."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection in search",
            severity=Severity.HIGH,
            file_path="app/views.py",
            line_number=10
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.95,
            false_positive_probability=0.05,
            priority_score=0.9,
            suggested_fix="Use parameterized queries with placeholders"
        )

        fixed_files = [{
            "file_path": "app/views.py",
            "original_content": "query = 'SELECT * FROM users WHERE id = ' + user_id",
            "fixed_content": "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))"
        }]

        mr_url = await remediation_agent._create_fix_mr(
            vuln, analyzed, fixed_files, "project-123", "main"
        )

        assert mr_url is not None
        assert "gitlab.com" in mr_url
        mock_gitlab_client.create_merge_request.assert_called_once()

        # Verify MR parameters
        call_kwargs = mock_gitlab_client.create_merge_request.call_args[1]
        assert call_kwargs["title"] == "security: fix SQL Injection in search (VULN-001)"
        assert "VULN-001" in call_kwargs["description"]
        assert "SQL Injection" in call_kwargs["description"]
        assert call_kwargs["target_branch"] == "main"
        assert call_kwargs["source_branch"] == "security/fix-VULN-001"

    @pytest.mark.asyncio
    async def test_create_fix_mr_with_multiple_files(self, remediation_agent, mock_gitlab_client):
        """Test MR creation with multiple fixed files."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Multiple file vulnerability",
            severity=Severity.HIGH,
            file_path="app/views.py"
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.05,
            priority_score=0.85,
            suggested_fix="Apply fix to all affected files"
        )

        fixed_files = [
            {
                "file_path": "app/views.py",
                "original_content": "vulnerable code 1",
                "fixed_content": "fixed code 1"
            },
            {
                "file_path": "app/models.py",
                "original_content": "vulnerable code 2",
                "fixed_content": "fixed code 2"
            }
        ]

        mr_url = await remediation_agent._create_fix_mr(
            vuln, analyzed, fixed_files, "project-123", "main"
        )

        assert mr_url is not None
        # Verify commit message includes all files
        call_kwargs = mock_gitlab_client.create_merge_request.call_args[1]
        assert "app/views.py" in call_kwargs["commits"][0]["message"]
        assert "app/models.py" in call_kwargs["commits"][0]["message"]

    @pytest.mark.asyncio
    async def test_create_fix_mr_api_failure(self, remediation_agent, mock_gitlab_client):
        """Test MR creation handles API failures."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.HIGH,
            file_path="app/test.py"
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.05,
            priority_score=0.8
        )

        fixed_files = [{
            "file_path": "app/test.py",
            "original_content": "test",
            "fixed_content": "fixed"
        }]

        mock_gitlab_client.create_merge_request.side_effect = Exception("API Error")

        mr_url = await remediation_agent._create_fix_mr(
            vuln, analyzed, fixed_files, "project-123", "main"
        )

        assert mr_url is None


class TestRemediationAgentMainRemediation:
    """Test main remediation workflow."""

    @pytest.mark.asyncio
    async def test_remediate_vulnerability_success(self, remediation_agent, mock_gitlab_client):
        """Test successful vulnerability remediation."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="User input not sanitized",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            file_path="app/views.py",
            line_number=10,
            code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
            cwe_id="CWE-89",
            confidence=0.9
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.95,
            false_positive_probability=0.05,
            priority_score=0.9,
            remediation_effort=2.0,
            suggested_fix="Use parameterized queries"
        )

        # Mock file content
        mock_gitlab_client.get_repository_file.return_value = """def get_user(user_id):
    query = 'SELECT * FROM users WHERE id = ' + user_id
    cursor.execute(query)
    return cursor.fetchone()"""

        # Mock successful verification
        mock_gitlab_client.get_security_vulnerabilities.return_value = []

        result = await remediation_agent.remediate_vulnerability(
            vuln, analyzed, "project-123", "main"
        )

        assert isinstance(result, AppliedFix)
        assert result.vulnerability_id == "VULN-001"
        assert result.success is True
        assert result.fixed_files is not None
        assert len(result.fixed_files) > 0
        assert result.mr_url is not None
        assert result.verification_passed is True

    @pytest.mark.asyncio
    async def test_remediate_vulnerability_no_pattern_match(self, remediation_agent):
        """Test remediation when no fix pattern matches."""
        vuln = Vulnerability(
            id="VULN-999",
            title="Unknown vulnerability",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-999",
            confidence=0.8,
            false_positive_probability=0.1,
            priority_score=0.5
        )

        result = await remediation_agent.remediate_vulnerability(
            vuln, analyzed, "project-123", "main"
        )

        assert result.success is False
        assert "no fix pattern available" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_remediate_vulnerability_low_confidence(self, remediation_agent):
        """Test remediation with low confidence pattern."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            confidence=0.6  # Below threshold
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.05,
            priority_score=0.8
        )

        # Pattern should not be applied due to low confidence
        result = await remediation_agent.remediate_vulnerability(
            vuln, analyzed, "project-123", "main"
        )

        assert result.success is False
        assert "confidence" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_remediate_vulnerability_auto_apply_disabled(self, mock_settings, mock_gitlab_client, mock_knowledge_graph):
        """Test remediation when auto_apply is disabled."""
        mock_settings.remediation_auto_apply = False

        agent = RemediationAgent(
            settings=mock_settings,
            gitlab_client=mock_gitlab_client,
            knowledge_graph=mock_knowledge_graph
        )

        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.95,
            false_positive_probability=0.05,
            priority_score=0.9
        )

        result = await agent.remediate_vulnerability(vuln, analyzed, "project-123", "main")

        # Should not create MR when auto_apply is False
        mock_gitlab_client.create_merge_request.assert_not_called()
        assert result.success is False
        assert "auto-apply disabled" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_remediate_batch_empty(self, remediation_agent):
        """Test batch remediation with empty list."""
        results = await remediation_agent.remediate_batch([], "project-123", "main")
        assert results == []

    @pytest.mark.asyncio
    async def test_remediate_batch_multiple_vulnerabilities(self, remediation_agent, mock_gitlab_client):
        """Test batch remediation with multiple vulnerabilities."""
        vulns = [
            Vulnerability(
                id=f"VULN-{i}",
                title=f"Test {i}",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/test.py",
                line_number=10,
                code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
                cwe_id="CWE-89"
            )
            for i in range(3)
        ]

        analyzed_list = [
            AnalyzedVulnerability(
                vulnerability_id=v.id,
                confidence=0.95,
                false_positive_probability=0.05,
                priority_score=0.9,
                suggested_fix="Use parameterized queries"
            )
            for v in vulns
        ]

        # Mock file content
        mock_gitlab_client.get_repository_file.return_value = "vulnerable code"
        mock_gitlab_client.get_security_vulnerabilities.return_value = []  # Verification passes

        results = await remediation_agent.remediate_batch(
            vulns, analyzed_list, "project-123", "main"
        )

        assert len(results) == 3
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_remediate_batch_max_fixes_limit(self, mock_settings, mock_gitlab_client, mock_knowledge_graph):
        """Test batch remediation respects max_fixes limit."""
        mock_settings.remediation_max_fixes_per_batch = 2

        agent = RemediationAgent(
            settings=mock_settings,
            gitlab_client=mock_gitlab_client,
            knowledge_graph=mock_knowledge_graph
        )

        vulns = [
            Vulnerability(
                id=f"VULN-{i}",
                title=f"Test {i}",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/test.py",
                line_number=10,
                code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
                cwe_id="CWE-89"
            )
            for i in range(5)
        ]

        analyzed_list = [
            AnalyzedVulnerability(
                vulnerability_id=v.id,
                confidence=0.95,
                false_positive_probability=0.05,
                priority_score=0.9
            )
            for v in vulns
        ]

        mock_gitlab_client.get_repository_file.return_value = "vulnerable code"
        mock_gitlab_client.get_security_vulnerabilities.return_value = []

        results = await agent.remediate_batch(vulns, analyzed_list, "project-123", "main")

        # Should only fix first 2 (highest priority by orchestrator)
        assert len(results) <= 2


class TestRemediationAgentStatistics:
    """Test statistics tracking."""

    def test_get_statistics_initial(self, remediation_agent):
        """Test statistics on fresh agent."""
        stats = remediation_agent.get_statistics()

        assert stats["fixes_applied"] == 0
        assert stats["fixes_failed"] == 0
        assert stats["mrs_created"] == 0
        assert stats["verification_passed"] == 0
        assert stats["verification_failed"] == 0
        assert stats["avg_fix_time_ms"] == 0
        assert stats["success_rate"] == 0

    def test_statistics_after_remediations(self, remediation_agent):
        """Test statistics after some remediations."""
        remediation_agent._fixes_applied = 10
        remediation_agent._fixes_failed = 2
        remediation_agent._mrs_created = 8
        remediation_agent._verification_passed = 9
        remediation_agent._verification_failed = 1
        remediation_agent._total_fix_time = 3000  # ms

        stats = remediation_agent.get_statistics()

        assert stats["fixes_applied"] == 10
        assert stats["fixes_failed"] == 2
        assert stats["mrs_created"] == 8
        assert stats["verification_passed"] == 9
        assert stats["verification_failed"] == 1
        assert stats["avg_fix_time_ms"] == 300.0
        assert stats["success_rate"] == pytest.approx(10 / 12)
        assert stats["verification_rate"] == pytest.approx(9 / 10)


class TestRemediationAgentHealth:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, remediation_agent):
        """Test health check when all components healthy."""
        health = await remediation_agent.health_check()

        assert health["status"] == "healthy"
        assert health["gitlab_client"] is True
        assert health["knowledge_graph"] is True
        assert health["patterns_loaded"] is True
        assert len(health["patterns"]) == 15

    @pytest.mark.asyncio
    async def test_health_check_degraded(self, remediation_agent):
        """Test health check when component fails."""
        remediation_agent.gitlab_client = MagicMock()
        remediation_agent.gitlab_client.check_connectivity.side_effect = Exception("Connection lost")

        health = await remediation_agent.health_check()

        assert health["status"] == "degraded"
        assert health["gitlab_client"] is False


class TestRemediationAgentErrorHandling:
    """Test error handling and resilience."""

    @pytest.mark.asyncio
    async def test_remediate_with_missing_file(self, remediation_agent, mock_gitlab_client):
        """Test remediation when file doesn't exist in repository."""
        mock_gitlab_client.get_repository_file.return_value = None

        vuln = Vulnerability(
            id="VULN-001",
            file_path="nonexistent.py",
            line_number=1
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.05,
            priority_score=0.8
        )

        result = await remediation_agent.remediate_vulnerability(
            vuln, analyzed, "project-123", "main"
        )

        assert result.success is False
        assert "file not found" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_remediate_with_syntax_error_in_fix(self, remediation_agent, mock_gitlab_client):
        """Test remediation when fix introduces syntax error."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=10,
            code_snippet="query = 'SELECT * FROM users'",
            cwe_id="CWE-89"
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.05,
            priority_score=0.8
        )

        # Mock file content
        mock_gitlab_client.get_repository_file.return_value = "def test():\n    pass"

        # Mock fix pattern that produces invalid Python
        pattern = FixPattern(
            id="BROKEN_01",
            vulnerability_type="SQL_INJECTION",
            name="Broken Fix",
            description="Produces syntax error",
            pattern=r"INVALID_PYTHON_CODE_$$$",
            confidence_threshold=0.8,
            requires_context=False,
            creates_mr=False
        )

        # Patch _find_matching_pattern to return broken pattern
        with patch.object(remediation_agent, '_find_matching_pattern', return_value=pattern):
            result = await remediation_agent.remediate_vulnerability(
                vuln, analyzed, "project-123", "main"
            )

        # Should fail due to syntax validation
        assert result.success is False
        assert "syntax" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_remediate_with_verification_failure(self, remediation_agent, mock_gitlab_client):
        """Test remediation when verification fails."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=10
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.05,
            priority_score=0.8
        )

        mock_gitlab_client.get_repository_file.return_value = "vulnerable code"
        # Verification fails - same vulnerability still present
        mock_gitlab_client.get_security_vulnerabilities.return_value = [vuln]

        result = await remediation_agent.remediate_vulnerability(
            vuln, analyzed, "project-123", "main"
        )

        # Should still succeed (we attempted fix) but verification_passed=False
        assert result.success is True
        assert result.verification_passed is False

    @pytest.mark.asyncio
    async def test_remediate_with_partial_file_fetch_failure(self, remediation_agent, mock_gitlab_client):
        """Test remediation when some files can't be fetched."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/exists.py",
            line_number=10
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.05,
            priority_score=0.8
        )

        # First call returns file, second call (for another file) returns None
        mock_gitlab_client.get_repository_file.side_effect = ["file content", None]

        # Pattern that tries to fix multiple files
        pattern = FixPattern(
            id="MULTI_01",
            vulnerability_type="SQL_INJECTION",
            name="Multi-file fix",
            description="Fixes multiple files",
            pattern=r"query.*=.*\+",
            confidence_threshold=0.8,
            requires_context=False,
            creates_mr=False,
            file_paths=["app/exists.py", "app/missing.py"]
        )

        with patch.object(remediation_agent, '_find_matching_pattern', return_value=pattern):
            result = await remediation_agent.remediate_vulnerability(
                vuln, analyzed, "project-123", "main"
            )

        # Should partially succeed with one file fixed
        assert result.success is True
        assert len(result.fixed_files) == 1
        assert result.fixed_files[0]["file_path"] == "app/exists.py"


class TestRemediationAgentKnowledgeGraphIntegration:
    """Test knowledge graph integration."""

    @pytest.mark.asyncio
    async def test_store_remediation_success(self, remediation_agent, mock_knowledge_graph):
        """Test storing remediation in knowledge graph."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            severity=Severity.HIGH,
            cwe_id="CWE-89"
        )

        applied_fix = AppliedFix(
            vulnerability_id="VULN-001",
            success=True,
            fixed_files=[{"file_path": "app/views.py"}],
            mr_url="https://gitlab.com/mr/123"
        )

        result = await remediation_agent._store_remediation(vuln, applied_fix, "project-123")
        assert result is True
        mock_knowledge_graph.store_remediation.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_remediation_failure(self, remediation_agent, mock_knowledge_graph):
        """Test handling knowledge graph storage failure."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            severity=Severity.LOW
        )

        applied_fix = AppliedFix(
            vulnerability_id="VULN-001",
            success=True,
            fixed_files=[]
        )

        mock_knowledge_graph.store_remediation.side_effect = Exception("DB Error")

        result = await remediation_agent._store_remediation(vuln, applied_fix, "project-123")
        assert result is False

    @pytest.mark.asyncio
    async def test_record_developer_expertise(self, remediation_agent, mock_knowledge_graph):
        """Test recording developer expertise after successful fix."""
        vuln = Vulnerability(
            id="VULN-001",
            file_path="app/views.py",
            line_number=10
        )

        applied_fix = AppliedFix(
            vulnerability_id="VULN-001",
            success=True,
            fixed_files=[{"file_path": "app/views.py"}],
            fix_pattern_id="SQL_INJECTION_01"
        )

        await remediation_agent._record_developer_expertise(vuln, applied_fix, "developer-123")

        mock_knowledge_graph.record_developer_expertise.assert_called_once()
        call_kwargs = mock_knowledge_graph.record_developer_expertise.call_args[1]
        assert call_kwargs["developer_id"] == "developer-123"
        assert call_kwargs["vulnerability_type"] == "SQL_INJECTION"
        assert call_kwargs["success"] is True


class TestRemediationAgentIntegration:
    """Integration tests with full workflow."""

    @pytest.mark.asyncio
    async def test_full_remediation_workflow(self, remediation_agent, mock_gitlab_client):
        """Test complete remediation workflow from vulnerability to MR."""
        vuln = Vulnerability(
            id="SECUREAI-2024-001",
            title="SQL Injection in User Search",
            description="The search endpoint constructs SQL queries using string concatenation, allowing attackers to inject arbitrary SQL commands and gain unauthorized database access.",
            severity=Severity.CRITICAL,
            source=VulnerabilitySource.SAST,
            file_path="app/views.py",
            line_number=156,
            code_snippet="query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''",
            cwe_id="CWE-89",
            confidence=0.92,
            scanner_id="bandit-1.7.5"
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="SECUREAI-2024-001",
            confidence=0.98,
            false_positive_probability=0.02,
            priority_score=0.95,
            remediation_effort=1.5,
            suggested_fix="Use parameterized queries with placeholders to separate SQL code from data",
            analysis={
                "root_cause": "String concatenation in SQL query construction",
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "impact": "Complete database compromise, data exfiltration, privilege escalation"
            }
        )

        # Mock repository file
        mock_gitlab_client.get_repository_file.return_value = """from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/search')
def search_users():
    username = request.args.get('username', '')
    query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    return {'users': results}

if __name__ == '__main__':
    app.run(debug=True)"""

        # Mock verification - no vulnerabilities after fix
        mock_gitlab_client.get_security_vulnerabilities.return_value = []

        # Mock MR creation
        mock_gitlab_client.create_merge_request.return_value = MagicMock(
            iid=42,
            web_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/42"
        )

        result = await remediation_agent.remediate_vulnerability(
            vuln, analyzed, "secureai-demo", "main", auto_apply=True
        )

        # Verify comprehensive result
        assert result.success is True
        assert result.vulnerability_id == "SECUREAI-2024-001"
        assert result.fixed_files is not None
        assert len(result.fixed_files) == 1
        assert result.fixed_files[0]["file_path"] == "app/views.py"
        assert "parameterized" in result.fixed_files[0]["fixed_content"].lower()
        assert result.mr_url is not None
        assert "merge_requests/42" in result.mr_url
        assert result.verification_passed is True
        assert result.fix_pattern_id == "SQL_INJECTION_01"

        # Verify GitLab API calls
        mock_gitlab_client.get_repository_file.assert_called_once_with(
            "secureai-demo", "main", "app/views.py"
        )
        mock_gitlab_client.create_merge_request.assert_called_once()
        mock_gitlab_client.get_security_vulnerabilities.assert_called_once()

        # Verify knowledge graph storage
        mock_knowledge_graph.store_remediation.assert_called_once()
        mock_knowledge_graph.record_developer_expertise.assert_called_once()
