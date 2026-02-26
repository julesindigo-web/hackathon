"""
Comprehensive test suite for GitLabClient.
Target: 100% coverage of gitlab_client.py
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from core.gitlab_client import GitLabClient
from core.models import Vulnerability, Severity, VulnerabilitySource
from core.config import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.gitlab_url = "https://gitlab.com"
    settings.gitlab_token = "test-token"
    settings.gitlab_project = "test-project"
    settings.gitlab_retry_attempts = 3
    settings.gitlab_retry_backoff = 1.0
    settings.gitlab_timeout = 30
    return settings


@pytest.fixture
def gitlab_client(mock_settings):
    """Create GitLabClient instance with mocked settings."""
    with patch('core.gitlab_client.gitlab') as mock_gitlab:
        mock_gitlab.Gitlab.return_value = MagicMock()
        client = GitLabClient(settings=mock_settings)
        return client


class TestGitLabClientInitialization:
    """Test GitLabClient initialization."""

    def test_init_with_settings(self, gitlab_client, mock_settings):
        """Test successful initialization with settings."""
        assert gitlab_client.settings == mock_settings
        assert gitlab_client.client is not None
        assert gitlab_client.project is None  # Not loaded yet

    def test_gitlab_instance_created(self, gitlab_client):
        """Test GitLab instance is created."""
        assert gitlab_client.client is not None

    def test_lazy_project_load(self, gitlab_client):
        """Test project is loaded lazily."""
        assert gitlab_client.project is None


class TestGitLabClientProjectOperations:
    """Test project-related operations."""

    def test_get_project_success(self, gitlab_client):
        """Test successful project retrieval."""
        mock_project = MagicMock()
        mock_project.id = 123
        mock_project.path = "test-project"
        gitlab_client.client.projects.get.return_value = mock_project

        project = gitlab_client.get_project()

        assert project is not None
        assert project.id == 123
        gitlab_client.client.projects.get.assert_called_once_with("test-project")

    def test_get_project_cached(self, gitlab_client):
        """Test project is cached after first retrieval."""
        mock_project = MagicMock()
        mock_project.id = 123
        gitlab_client.client.projects.get.return_value = mock_project

        # First call
        project1 = gitlab_client.get_project()
        # Second call should use cache
        project2 = gitlab_client.get_project()

        assert project1 is project2
        gitlab_client.client.projects.get.assert_called_once()

    def test_get_project_failure(self, gitlab_client):
        """Test project retrieval failure."""
        gitlab_client.client.projects.get.side_effect = Exception("Project not found")

        with pytest.raises(Exception):
            gitlab_client.get_project()


class TestGitLabClientMergeRequestOperations:
    """Test merge request operations."""

    @pytest.fixture
    def mock_mr(self):
        """Create mock merge request."""
        mr = MagicMock()
        mr.iid = 42
        mr.web_url = "https://gitlab.com/project/mr/42"
        mr.state = "opened"
        mr.title = "Test MR"
        mr.description = "Test description"
        return mr

    def test_get_merge_request_success(self, gitlab_client, mock_mr):
        """Test successful merge request retrieval."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.mergerequests.get.return_value = mock_mr

        mr = gitlab_client.get_merge_request(42)

        assert mr is not None
        assert mr.iid == 42
        gitlab_client.project.mergerequests.get.assert_called_once_with(42)

    def test_get_merge_request_not_found(self, gitlab_client):
        """Test merge request not found."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.mergerequests.get.side_effect = Exception("Not found")

        with pytest.raises(Exception):
            gitlab_client.get_merge_request(999)

    def test_create_merge_request_success(self, gitlab_client, mock_mr):
        """Test successful merge request creation."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.mergerequests.create.return_value = mock_mr

        mr = gitlab_client.create_merge_request(
            source_branch="feature/test",
            target_branch="main",
            title="Test MR",
            description="Test description"
        )

        assert mr is not None
        gitlab_client.project.mergerequests.create.assert_called_once()
        call_kwargs = gitlab_client.project.mergerequests.create.call_args[1]
        assert call_kwargs["source_branch"] == "feature/test"
        assert call_kwargs["target_branch"] == "main"
        assert call_kwargs["title"] == "Test MR"

    def test_create_merge_request_with_labels(self, gitlab_client, mock_mr):
        """Test merge request creation with labels."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.mergerequests.create.return_value = mock_mr

        mr = gitlab_client.create_merge_request(
            source_branch="feature/test",
            target_branch="main",
            title="Test MR",
            description="Test",
            labels=["security", "auto-fix"]
        )

        call_kwargs = gitlab_client.project.mergerequests.create.call_args[1]
        assert call_kwargs["labels"] == ["security", "auto-fix"]

    def test_add_merge_request_note_success(self, gitlab_client):
        """Test adding note to merge request."""
        gitlab_client.project = MagicMock()
        mock_note = MagicMock()
        gitlab_client.project.mergerequests.notes.create.return_value = mock_note

        note = gitlab_client.add_merge_request_note(mr_iid=42, body="Test note")

        assert note is not None
        gitlab_client.project.mergerequests.notes.create.assert_called_once_with(
            mr_iid=42, body="Test note"
        )

    def test_get_merge_request_commits(self, gitlab_client):
        """Test getting merge request commits."""
        gitlab_client.project = MagicMock()
        mock_commits = [MagicMock(), MagicMock()]
        gitlab_client.project.mergerequests.get.return_value = MagicMock(commits=mock_commits)

        commits = gitlab_client.get_merge_request_commits(42)

        assert len(commits) == 2


class TestGitLabClientSecurityOperations:
    """Test security-related operations."""

    def test_get_security_vulnerabilities_success(self, gitlab_client):
        """Test successful retrieval of security vulnerabilities."""
        gitlab_client.project = MagicMock()
        mock_vulns = [
            MagicMock(
                id=1,
                title="SQL Injection",
                severity="critical",
                description="Test",
                cve="CVE-2024-1234"
            ),
            MagicMock(
                id=2,
                title="XSS",
                severity="high",
                description="Test XSS"
            )
        ]
        gitlab_client.project.security_vulnerabilities.list.return_value = mock_vulns

        vulns = gitlab_client.get_security_vulnerabilities()

        assert len(vulns) == 2
        assert vulns[0].title == "SQL Injection"

    def test_get_security_vulnerabilities_empty(self, gitlab_client):
        """Test retrieval when no security vulnerabilities."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.security_vulnerabilities.list.return_value = []

        vulns = gitlab_client.get_security_vulnerabilities()

        assert len(vulns) == 0

    def test_update_vulnerability_status(self, gitlab_client):
        """Test updating vulnerability status."""
        gitlab_client.project = MagicMock()
        mock_vuln = MagicMock()
        gitlab_client.project.security_vulnerabilities.get.return_value = mock_vuln

        result = gitlab_client.update_vulnerability_status(
            vulnerability_id=1,
            status="resolved"
        )

        assert result is True
        gitlab_client.project.security_vulnerabilities.get.assert_called_once_with(1)
        mock_vuln.save.assert_called_once()

    def test_get_security_dashboard(self, gitlab_client):
        """Test getting security dashboard data."""
        gitlab_client.project = MagicMock()
        mock_dashboard = MagicMock(
            overview={"total": 10, "critical": 2},
            recent_vulnerabilities=[MagicMock(), MagicMock()]
        )
        gitlab_client.project.security_dashboard.get.return_value = mock_dashboard

        dashboard = gitlab_client.get_security_dashboard()

        assert dashboard is not None
        assert "overview" in dashboard


class TestGitLabClientCICDOperations:
    """Test CI/CD operations."""

    def test_get_pipeline_success(self, gitlab_client):
        """Test successful pipeline retrieval."""
        gitlab_client.project = MagicMock()
        mock_pipeline = MagicMock(
            id=123,
            status="success",
            sha="abc123"
        )
        gitlab_client.project.pipelines.get.return_value = mock_pipeline

        pipeline = gitlab_client.get_pipeline(123)

        assert pipeline is not None
        assert pipeline.id == 123
        gitlab_client.project.pipelines.get.assert_called_once_with(123)

    def test_get_pipeline_artifacts_success(self, gitlab_client):
        """Test successful pipeline artifacts retrieval."""
        gitlab_client.project = MagicMock()
        mock_pipeline = MagicMock()
        mock_artifact = MagicMock(
            name="security-scan.json",
            file_type="json",
            size=1024
        )
        mock_pipeline.artifacts = [mock_artifact]
        gitlab_client.project.pipelines.get.return_value = mock_pipeline

        artifacts = gitlab_client.get_pipeline_artifacts(123)

        assert len(artifacts) == 1
        assert artifacts[0].name == "security-scan.json"

    def test_trigger_pipeline_success(self, gitlab_client):
        """Test successful pipeline trigger."""
        gitlab_client.project = MagicMock()
        mock_pipeline = MagicMock(id=124)
        gitlab_client.project.pipelines.create.return_value = mock_pipeline

        pipeline = gitlab_client.trigger_pipeline(ref="main")

        assert pipeline is not None
        gitlab_client.project.pipelines.create.assert_called_once_with(
            ref="main",
            variables={}
        )

    def test_trigger_pipeline_with_variables(self, gitlab_client):
        """Test pipeline trigger with variables."""
        gitlab_client.project = MagicMock()
        mock_pipeline = MagicMock()
        gitlab_client.project.pipelines.create.return_value = mock_pipeline

        pipeline = gitlab_client.trigger_pipeline(
            ref="main",
            variables={"SECURITY_SCAN": "true", "ENVIRONMENT": "production"}
        )

        call_kwargs = gitlab_client.project.pipelines.create.call_args[1]
        assert call_kwargs["variables"] == {
            "SECURITY_SCAN": "true",
            "ENVIRONMENT": "production"
        }

    def test_get_ci_artifacts_success(self, gitlab_client):
        """Test getting CI artifacts from latest pipeline."""
        gitlab_client.project = MagicMock()
        mock_pipeline = MagicMock()
        mock_artifact = MagicMock(name="sast-report.json")
        mock_pipeline.artifacts = [mock_artifact]
        gitlab_client.project.pipelines.list.return_value = [mock_pipeline]

        artifacts = gitlab_client.get_ci_artifacts(job_name="security_scan")

        assert len(artifacts) >= 1


class TestGitLabClientRepositoryOperations:
    """Test repository operations."""

    def test_get_repository_file_success(self, gitlab_client):
        """Test successful file retrieval."""
        gitlab_client.project = MagicMock()
        mock_file = MagicMock(
            file_path="app/main.py",
            content="dGVzdA=="  # base64 encoded "test"
        )
        gitlab_client.project.files.get.return_value = mock_file

        content = gitlab_client.get_repository_file(
            file_path="app/main.py",
            ref="main"
        )

        assert content == "test"
        gitlab_client.project.files.get.assert_called_once_with(
            file_path="app/main.py",
            ref="main"
        )

    def test_get_repository_file_not_found(self, gitlab_client):
        """Test file not found."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.files.get.side_effect = Exception("404 Not Found")

        content = gitlab_client.get_repository_file(
            file_path="nonexistent.py",
            ref="main"
        )

        assert content is None

    def test_create_repository_file_success(self, gitlab_client):
        """Test successful file creation."""
        gitlab_client.project = MagicMock()
        mock_file = MagicMock()
        gitlab_client.project.files.create.return_value = mock_file

        result = gitlab_client.create_repository_file(
            file_path="app/new.py",
            content="print('hello')",
            commit_message="Add new file",
            branch="main"
        )

        assert result is True
        gitlab_client.project.files.create.assert_called_once()

    def test_update_repository_file_success(self, gitlab_client):
        """Test successful file update."""
        gitlab_client.project = MagicMock()
        mock_file = MagicMock()
        gitlab_client.project.files.update.return_value = mock_file

        result = gitlab_client.update_repository_file(
            file_path="app/existing.py",
            content="updated content",
            commit_message="Update file",
            branch="main",
            last_commit_sha="abc123"
        )

        assert result is True
        gitlab_client.project.files.update.assert_called_once()

    def test_delete_repository_file_success(self, gitlab_client):
        """Test successful file deletion."""
        gitlab_client.project = MagicMock()
        mock_file = MagicMock()
        gitlab_client.project.files.delete.return_value = mock_file

        result = gitlab_client.delete_repository_file(
            file_path="app/old.py",
            commit_message="Delete file",
            branch="main",
            last_commit_sha="abc123"
        )

        assert result is True
        gitlab_client.project.files.delete.assert_called_once()

    def test_get_commit_history_success(self, gitlab_client):
        """Test getting commit history."""
        gitlab_client.project = MagicMock()
        mock_commits = [
            MagicMock(id=1, message="First commit", created_at=datetime.utcnow()),
            MagicMock(id=2, message="Second commit", created_at=datetime.utcnow())
        ]
        gitlab_client.project.commits.list.return_value = mock_commits

        commits = gitlab_client.get_commit_history(
            ref="main",
            limit=10
        )

        assert len(commits) == 2
        gitlab_client.project.commits.list.assert_called_once()


class TestGitLabClientRetryLogic:
    """Test retry logic and error handling."""

    def test_retry_on_network_error(self, gitlab_client):
        """Test retry logic handles transient network errors."""
        gitlab_client.project = MagicMock()
        # Fail twice, succeed on third try
        gitlab_client.project.files.get.side_effect = [
            Exception("Connection error"),
            Exception("Timeout"),
            MagicMock(file_path="test", content="test")
        ]

        content = gitlab_client.get_repository_file("test.py", "main")

        assert content == "test"
        assert gitlab_client.project.files.get.call_count == 3

    def test_retry_exhaustion(self, gitlab_client):
        """Test retry exhaustion raises error."""
        gitlab_client.project = MagicMock()
        # Always fail
        gitlab_client.project.files.get.side_effect = Exception("Connection error")

        with pytest.raises(Exception):
            gitlab_client.get_repository_file("test.py", "main")

        # Should retry configured number of times
        assert gitlab_client.project.files.get.call_count == 3

    def test_no_retry_on_404(self, gitlab_client):
        """Test 404 errors are not retried."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.files.get.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception):
            gitlab_client.get_repository_file("test.py", "main")

        # Should not retry on 404
        assert gitlab_client.project.files.get.call_count == 1

    def test_backoff_timing(self, gitlab_client):
        """Test exponential backoff between retries."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.files.get.side_effect = [
            Exception("Error 1"),
            Exception("Error 2"),
            MagicMock(file_path="test", content="test")
        ]

        with patch('time.sleep') as mock_sleep:
            content = gitlab_client.get_repository_file("test.py", "main")

        assert content == "test"
        # Should have slept twice (between retries)
        assert mock_sleep.call_count == 2
        # First sleep should be 1.0s, second should be 2.0s (exponential)
        assert mock_sleep.call_args_list[0][0][0] == 1.0
        assert mock_sleep.call_args_list[1][0][0] == 2.0


class TestGitLabClientVulnerabilityNormalization:
    """Test vulnerability data normalization."""

    def test_normalize_security_vulnerability(self, gitlab_client):
        """Test normalization of GitLab security vulnerability."""
        gitlab_client.project = MagicMock()
        mock_vuln = MagicMock(
            id=123,
            title="SQL Injection in login",
            description="User input not sanitized",
            severity="critical",
            cve="CVE-2024-1234",
            cwe="CWE-89",
            discovered_at="2024-01-15T10:30:00.000Z",
            project_id=456,
            web_url="https://gitlab.com/project/-/vulnerabilities/123"
        )

        vuln = gitlab_client._normalize_vulnerability(mock_vuln)

        assert vuln.id == "SECUREAI-123"
        assert vuln.title == "SQL Injection in login"
        assert vuln.severity == Severity.CRITICAL
        assert vuln.cwe_id == "CWE-89"
        assert vuln.source == VulnerabilitySource.GITLAB_SECURITY

    def test_normalize_sast_finding(self, gitlab_client):
        """Test normalization of SAST finding."""
        gitlab_client.project = MagicMock()
        mock_finding = MagicMock(
            id=456,
            name="Potential SQL injection",
            description="String concatenation in SQL query",
            severity="high",
            location={"file": "app/auth.py", "line": 42}
        )

        # Simulate from CI artifact
        finding_data = {
            "id": 456,
            "name": "Potential SQL injection",
            "description": "String concatenation in SQL query",
            "severity": "high",
            "location": {"file": "app/auth.py", "line": 42}
        }

        vuln = gitlab_client._normalize_sast_finding(finding_data)

        assert vuln.id == "SECUREAI-456"
        assert vuln.severity == Severity.HIGH
        assert vuln.file_path == "app/auth.py"
        assert vuln.line_number == 42

    def test_normalize_dast_finding(self, gitlab_client):
        """Test normalization of DAST finding."""
        dast_data = {
            "id": 789,
            "type": "xss",
            "description": "Reflected XSS vulnerability",
            "severity": "medium",
            "url": "https://example.com/page?param=<script>alert()</script>",
            "cwe": "CWE-79"
        }

        vuln = gitlab_client._normalize_dast_finding(dast_data)

        assert vuln.id == "SECUREAI-789"
        assert vuln.source == VulnerabilitySource.DAST
        assert vuln.severity == Severity.MEDIUM
        assert vuln.cwe_id == "CWE-79"

    def test_normalize_secret_detection(self, gitlab_client):
        """Test normalization of secret detection finding."""
        secret_data = {
            "id": 101,
            "type": "aws_access_key_id",
            "description": "AWS Access Key ID detected",
            "severity": "critical",
            "file": ".env",
            "line": 1,
            "value": "AKIAIOSFODNN7EXAMPLE"
        }

        vuln = gitlab_client._normalize_secret_detection(secret_data)

        assert vuln.id == "SECUREAI-101"
        assert vuln.source == VulnerabilitySource.SECRET_DETECTION
        assert vuln.severity == Severity.CRITICAL
        assert "AWS" in vuln.title


class TestGitLabClientErrorHandling:
    """Test error handling and resilience."""

    @pytest.mark.asyncio
    async def test_handle_rate_limit(self, gitlab_client):
        """Test handling of rate limit errors."""
        gitlab_client.project = MagicMock()
        # Simulate rate limit error
        gitlab_client.project.files.get.side_effect = [
            Exception("429 Too Many Requests"),
            MagicMock(file_path="test", content="test")
        ]

        # With retry, should eventually succeed
        content = gitlab_client.get_repository_file("test.py", "main")
        assert content == "test"

    @pytest.mark.asyncio
    async def test_handle_server_error(self, gitlab_client):
        """Test handling of server errors."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.files.get.side_effect = [
            Exception("500 Internal Server Error"),
            MagicMock(file_path="test", content="test")
        ]

        content = gitlab_client.get_repository_file("test.py", "main")
        assert content == "test"

    def test_handle_authentication_error(self, gitlab_client):
        """Test handling of authentication errors."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.files.get.side_effect = Exception("401 Unauthorized")

        with pytest.raises(Exception):
            gitlab_client.get_repository_file("test.py", "main")

        # Should not retry on auth error
        assert gitlab_client.project.files.get.call_count == 1

    def test_handle_forbidden_error(self, gitlab_client):
        """Test handling of forbidden errors."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.files.get.side_effect = Exception("403 Forbidden")

        with pytest.raises(Exception):
            gitlab_client.get_repository_file("test.py", "main")

        # Should not retry on forbidden
        assert gitlab_client.project.files.get.call_count == 1


class TestGitLabClientIntegration:
    """Integration tests with realistic scenarios."""

    @pytest.mark.asyncio
    async def test_full_vulnerability_scan_workflow(self, gitlab_client):
        """Test complete vulnerability scan workflow."""
        # Mock project
        gitlab_client.project = MagicMock()
        gitlab_client.project.id = 123
        gitlab_client.project.path = "test-project"

        # Mock security vulnerabilities
        mock_vulns = [
            MagicMock(
                id=1,
                title="SQL Injection",
                severity="critical",
                description="SQL injection in auth",
                cve="CVE-2024-001",
                cwe="CWE-89",
                discovered_at=datetime.utcnow().isoformat()
            )
        ]
        gitlab_client.project.security_vulnerabilities.list.return_value = mock_vulns

        # Get vulnerabilities
        vulns = gitlab_client.get_security_vulnerabilities()

        assert len(vulns) == 1
        assert vulns[0].title == "SQL Injection"

    @pytest.mark.asyncio
    async def test_ci_artifact_retrieval_workflow(self, gitlab_client):
        """Test CI artifact retrieval workflow."""
        gitlab_client.project = MagicMock()

        # Mock pipelines
        mock_pipeline = MagicMock(
            id=100,
            status="success",
            sha="abc123",
            ref="main",
            created_at=datetime.utcnow()
        )
        gitlab_client.project.pipelines.list.return_value = [mock_pipeline]

        # Mock artifacts
        mock_artifact = MagicMock(
            name="sast-report.json",
            file_type="json",
            size=2048,
            download_url="https://gitlab.com/artifacts/download"
        )
        mock_pipeline.artifacts = [mock_artifact]

        artifacts = gitlab_client.get_ci_artifacts(job_name="sast")

        assert len(artifacts) >= 1
        assert any(a.name == "sast-report.json" for a in artifacts)

    @pytest.mark.asyncio
    async def test_merge_request_creation_workflow(self, gitlab_client):
        """Test merge request creation with all features."""
        gitlab_client.project = MagicMock()
        mock_mr = MagicMock(
            iid=42,
            web_url="https://gitlab.com/project/merge_requests/42",
            state="opened",
            created_at=datetime.utcnow()
        )
        gitlab_client.project.mergerequests.create.return_value = mock_mr

        mr = gitlab_client.create_merge_request(
            source_branch="security/fix-vuln-1",
            target_branch="main",
            title="security: fix SQL injection vulnerability",
            description="This MR fixes a critical SQL injection vulnerability...",
            assignee_id=123,
            labels=["security", "critical", "auto-fix"],
            remove_source_branch=True,
            squash=True
        )

        assert mr is not None
        call_kwargs = gitlab_client.project.mergerequests.create.call_args[1]
        assert call_kwargs["source_branch"] == "security/fix-vuln-1"
        assert call_kwargs["target_branch"] == "main"
        assert call_kwargs["labels"] == ["security", "critical", "auto-fix"]
        assert call_kwargs["remove_source_branch"] is True
        assert call_kwargs["squash"] is True

    @pytest.mark.asyncio
    async def test_file_operations_workflow(self, gitlab_client):
        """Test complete file operations workflow."""
        gitlab_client.project = MagicMock()
        mock_file = MagicMock(file_path="test.py", content="test")

        # Create file
        gitlab_client.project.files.create.return_value = mock_file
        result = gitlab_client.create_repository_file(
            file_path="app/new.py",
            content="print('hello')",
            commit_message="Add new file",
            branch="main"
        )
        assert result is True

        # Update file
        gitlab_client.project.files.update.return_value = mock_file
        result = gitlab_client.update_repository_file(
            file_path="app/new.py",
            content="print('updated')",
            commit_message="Update file",
            branch="main",
            last_commit_sha="abc123"
        )
        assert result is True

        # Get file
        gitlab_client.project.files.get.return_value = mock_file
        content = gitlab_client.get_repository_file("app/new.py", "main")
        assert content == "test"

        # Delete file
        gitlab_client.project.files.delete.return_value = mock_file
        result = gitlab_client.delete_repository_file(
            file_path="app/new.py",
            commit_message="Delete file",
            branch="main",
            last_commit_sha="def456"
        )
        assert result is True


class TestGitLabClientPerformance:
    """Test performance characteristics."""

    @pytest.mark.asyncio
    async def test_batch_vulnerability_fetching(self, gitlab_client):
        """Test fetching multiple vulnerabilities efficiently."""
        gitlab_client.project = MagicMock()
        # Simulate many vulnerabilities
        mock_vulns = [
            MagicMock(
                id=i,
                title=f"Vulnerability {i}",
                severity="high" if i % 2 == 0 else "medium",
                description=f"Test vulnerability {i}"
            )
            for i in range(1, 101)
        ]
        gitlab_client.project.security_vulnerabilities.list.return_value = mock_vulns

        vulns = gitlab_client.get_security_vulnerabilities()

        # Should fetch all in one call (pagination not implemented for simplicity)
        assert len(vulns) == 100
        gitlab_client.project.security_vulnerabilities.list.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_requests_handling(self, gitlab_client):
        """Test handling of concurrent requests."""
        gitlab_client.project = MagicMock()
        gitlab_client.project.files.get.return_value = MagicMock(content="test")

        # Simulate multiple concurrent requests
        import asyncio
        tasks = [
            gitlab_client.get_repository_file(f"file{i}.py", "main")
            for i in range(10)
        ]

        results = await asyncio.gather(*tasks)

        assert len(results) == 10
        assert all(r == "test" for r in results)
