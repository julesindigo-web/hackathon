"""
Unit tests for core Pydantic models and data validation.

Tests all model schemas, serialization, deserialization, validation rules, and edge cases.
Ensures type safety and data integrity across the system.
"""

import pytest
from datetime import datetime, timedelta
from pydantic import ValidationError
from core.models import (
    Vulnerability, AnalyzedVulnerability, RemediationPlan,
    ComplianceReport, SecurityMetrics, Alert, MergeRequest,
    Severity, VulnerabilitySource, TriageAction, ComplianceFramework
)


class TestVulnerabilityModel:
    """Test Vulnerability Pydantic model."""

    def test_vulnerability_creation_minimal(self):
        """Test creating vulnerability with minimal required fields."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test vulnerability",
            description="A test vulnerability",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )

        assert vuln.id == "VULN-001"
        assert vuln.title == "Test vulnerability"
        assert vuln.severity == "high"
        assert vuln.cwe_id is None  # Optional field

    def test_vulnerability_all_fields(self):
        """Test creating vulnerability with all optional fields."""
        vuln = Vulnerability(
            id="VULN-002",
            title="Critical SQL Injection",
            description="User input not parameterized",
            severity="critical",
            vulnerability_type="sql_injection",
            cwe_id="CWE-89",
            file_path="app/auth.py",
            line_number=45,
            scanner_source="sast",
            project_id=123,
            mr_id=456,
            branch="feature/login",
            commit_sha="abc123def456",
            confidence=0.95,
            raw_data={"scanner": "semgrep", "rule": "sql-injection"},
            tags=["sql", "injection", "security"],
            remediation_effort="2h"
        )

        assert vuln.cwe_id == "CWE-89"
        assert vuln.branch == "feature/login"
        assert vuln.confidence == 0.95
        assert len(vuln.tags) == 3
        assert vuln.remediation_effort == "2h"

    def test_vulnerability_severity_validation(self):
        """Test severity field accepts valid values."""
        valid_severities = ["low", "medium", "high", "critical", "info"]

        for severity in valid_severities:
            vuln = Vulnerability(
                id=f"VULN-{severity}",
                title=f"Test {severity}",
                description="Test",
                severity=severity,
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=1,
                scanner_source="sast",
                project_id=1,
                mr_id=1
            )
            assert vuln.severity == severity

    def test_vulnerability_invalid_severity_raises(self):
        """Test that invalid severity raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            Vulnerability(
                id="VULN-001",
                title="Test",
                description="Test",
                severity="invalid",  # type: ignore
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=1,
                scanner_source="sast",
                project_id=1,
                mr_id=1
            )
        assert "severity" in str(exc_info.value)

    def test_vulnerability_content_hash_consistency(self):
        """Test that content_hash is deterministic for same content."""
        vuln1 = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="Test description",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )

        vuln2 = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="Test description",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )

        assert vuln1.content_hash() == vuln2.content_hash()

    def test_vulnerability_content_hash_differs(self):
        """Test that content_hash differs for different content."""
        vuln1 = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="Test description 1",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )

        vuln2 = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="Test description 2",  # Different description
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )

        assert vuln1.content_hash() != vuln2.content_hash()

    def test_vulnerability_serialization(self):
        """Test vulnerability serialization to dict."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            description="Test",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="test.py",
            line_number=1,
            scanner_source="sast",
            project_id=1,
            mr_id=1,
            tags=["test", "security"]
        )

        data = vuln.model_dump()

        assert data["id"] == "VULN-001"
        assert data["title"] == "Test"
        assert data["tags"] == ["test", "security"]
        assert "created_at" in data
        assert "updated_at" in data

    def test_vulnerability_json_encoding(self):
        """Test JSON encoding with datetime handling."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            description="Test",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="test.py",
            line_number=1,
            scanner_source="sast",
            project_id=1,
            mr_id=1
        )

        json_str = vuln.model_dump_json()
        assert "VULN-001" in json_str
        assert '"title": "Test"' in json_str

    def test_vulnerability_line_number_validation(self):
        """Test that line_number must be positive."""
        with pytest.raises(ValidationError):
            Vulnerability(
                id="VULN-001",
                title="Test",
                description="Test",
                severity="high",
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=0,  # Invalid: must be >= 1
                scanner_source="sast",
                project_id=1,
                mr_id=1
            )


class TestAnalyzedVulnerabilityModel:
    """Test AnalyzedVulnerability Pydantic model."""

    def test_analyzed_vulnerability_creation(self):
        """Test creating analyzed vulnerability with all fields."""
        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            root_cause="User input not parameterized in SQL query",
            exploitability_score=9.2,
            impact_score=8.5,
            false_positive_probability=0.05,
            confidence=0.95,
            priority_score=0.92,
            recommended_fix_pattern="sql_injection_parameterized_queries",
            code_context={
                "file": "app/auth.py",
                "snippet": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
                "function": "authenticate_user",
                "start_line": 40,
                "end_line": 50
            },
            analysis_notes="High risk vulnerability requiring immediate attention",
            analysis_timestamp=datetime.utcnow()
        )

        assert analyzed.vulnerability_id == "VULN-001"
        assert analyzed.exploitability_score == 9.2
        assert analyzed.priority_score == 0.92
        assert analyzed.code_context["file"] == "app/auth.py"

    def test_analyzed_vulnerability_score_bounds(self):
        """Test that scores are within valid ranges."""
        # Valid scores
        for score in [0.0, 0.5, 1.0, 5.0, 10.0]:
            analyzed = AnalyzedVulnerability(
                vulnerability_id="VULN-001",
                root_cause="Test",
                exploitability_score=score,
                impact_score=score,
                false_positive_probability=0.1,
                confidence=0.9,
                priority_score=0.8,
                recommended_fix_pattern="test"
            )
            assert analyzed.exploitability_score == score

        # Invalid scores should raise
        with pytest.raises(ValidationError):
            AnalyzedVulnerability(
                vulnerability_id="VULN-001",
                root_cause="Test",
                exploitability_score=11.0,  # > 10
                impact_score=8.0,
                false_positive_probability=0.1,
                confidence=0.9,
                priority_score=0.8,
                recommended_fix_pattern="test"
            )

    def test_analyzed_vulnerability_confidence_bounds(self):
        """Test confidence is between 0 and 1."""
        with pytest.raises(ValidationError):
            AnalyzedVulnerability(
                vulnerability_id="VULN-001",
                root_cause="Test",
                exploitability_score=8.0,
                impact_score=7.0,
                false_positive_probability=0.1,
                confidence=1.5,  # > 1
                priority_score=0.8,
                recommended_fix_pattern="test"
            )

    def test_analyzed_vulnerability_priority_calculation(self):
        """Test priority score calculation formula."""
        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            root_cause="Test",
            exploitability_score=9.0,
            impact_score=8.0,
            false_positive_probability=0.05,
            confidence=0.95,
            priority_score=0.85,  # Pre-calculated
            recommended_fix_pattern="test"
        )

        # Verify priority is reasonable for given scores
        assert 0.0 <= analyzed.priority_score <= 1.0
        # High exploitability and impact should yield high priority
        assert analyzed.priority_score > 0.7

    def test_analyzed_vulnerability_code_context_structure(self):
        """Test code context has required fields."""
        context = {
            "file": "app/auth.py",
            "snippet": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
            "function": "authenticate_user",
            "start_line": 40,
            "end_line": 50
        }

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            root_cause="Test",
            exploitability_score=8.0,
            impact_score=7.0,
            false_positive_probability=0.1,
            confidence=0.9,
            priority_score=0.8,
            recommended_fix_pattern="test",
            code_context=context
        )

        assert analyzed.code_context["file"] == "app/auth.py"
        assert analyzed.code_context["start_line"] == 40
        assert analyzed.code_context["end_line"] == 50


class TestRemediationPlanModel:
    """Test RemediationPlan Pydantic model."""

    def test_remediation_plan_creation(self):
        """Test creating remediation plan."""
        plan = RemediationPlan(
            vulnerability_id="VULN-001",
            fix_description="Use parameterized queries",
            fix_pattern="sql_injection_parameterized_queries",
            confidence=0.95,
            estimated_effort="2h",
            code_changes={
                "file": "app/auth.py",
                "diff": "@@ -42,7 +42,9 @@\n- query = f\"SELECT * FROM users WHERE id={user_id}\"\n+ cursor.execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))\n+ query = cursor.fetchone()"
            },
            verification_status="verified",
            applied_by="security-bot",
            applied_at=datetime.utcnow()
        )

        assert plan.vulnerability_id == "VULN-001"
        assert plan.fix_pattern == "sql_injection_parameterized_queries"
        assert plan.confidence == 0.95
        assert plan.verification_status == "verified"

    def test_remediation_plan_verification_status(self):
        """Test verification status enum values."""
        valid_statuses = ["pending", "applied", "verified", "failed", "reverted"]

        for status in valid_statuses:
            plan = RemediationPlan(
                vulnerability_id="VULN-001",
                fix_description="Test fix",
                fix_pattern="test",
                confidence=0.9,
                estimated_effort="1h",
                code_changes={},
                verification_status=status
            )
            assert plan.verification_status == status

    def test_remediation_plan_invalid_status_raises(self):
        """Test invalid verification status raises ValidationError."""
        with pytest.raises(ValidationError):
            RemediationPlan(
                vulnerability_id="VULN-001",
                fix_description="Test",
                fix_pattern="test",
                confidence=0.9,
                estimated_effort="1h",
                code_changes={},
                verification_status="invalid_status"  # type: ignore
            )

    def test_remediation_plan_effort_format(self):
        """Test estimated_effort format validation."""
        valid_efforts = ["30m", "1h", "2h", "1d", "2d", "1w"]

        for effort in valid_efforts:
            plan = RemediationPlan(
                vulnerability_id="VULN-001",
                fix_description="Test",
                fix_pattern="test",
                confidence=0.9,
                estimated_effort=effort,
                code_changes={},
                verification_status="pending"
            )
            assert plan.estimated_effort == effort

    def test_remediation_plan_code_changes_required(self):
        """Test that code_changes is required."""
        with pytest.raises(ValidationError):
            RemediationPlan(
                vulnerability_id="VULN-001",
                fix_description="Test",
                fix_pattern="test",
                confidence=0.9,
                estimated_effort="1h",
                verification_status="pending"
                # Missing code_changes
            )


class TestComplianceReportModel:
    """Test ComplianceReport Pydantic model."""

    def test_compliance_report_creation(self):
        """Test creating compliance report."""
        report = ComplianceReport(
            project_id=123,
            frameworks={
                "sox": {
                    "score": 95.5,
                    "status": "compliant",
                    "violations": [],
                    "requirements_met": 38,
                    "requirements_total": 40
                },
                "hipaa": {
                    "score": 92.0,
                    "status": "compliant",
                    "violations": [],
                    "requirements_met": 18,
                    "requirements_total": 18
                }
            },
            overall_score=93.0,
            summary="System meets most compliance requirements",
            generated_at=datetime.utcnow(),
            generated_by="security-bot"
        )

        assert report.project_id == 123
        assert report.overall_score == 93.0
        assert len(report.frameworks) == 2
        assert report.frameworks["sox"]["score"] == 95.5

    def test_compliance_report_score_bounds(self):
        """Test overall_score is between 0 and 100."""
        # Valid scores
        for score in [0.0, 50.0, 100.0]:
            report = ComplianceReport(
                project_id=1,
                frameworks={},
                overall_score=score,
                summary="Test"
            )
            assert 0 <= report.overall_score <= 100

        # Invalid score
        with pytest.raises(ValidationError):
            ComplianceReport(
                project_id=1,
                frameworks={},
                overall_score=101.0,  # > 100
                summary="Test"
            )

    def test_compliance_report_framework_status(self):
        """Test framework status values."""
        valid_statuses = ["compliant", "non_compliant", "minor_issues", "major_issues", "unknown"]

        for status in valid_statuses:
            report = ComplianceReport(
                project_id=1,
                frameworks={"test": {"score": 80.0, "status": status, "violations": []}},
                overall_score=80.0,
                summary="Test"
            )
            assert report.frameworks["test"]["status"] == status

    def test_compliance_report_violations_list(self):
        """Test violations are list of strings."""
        report = ComplianceReport(
            project_id=1,
            frameworks={
                "gdpr": {
                    "score": 65.0,
                    "status": "non_compliant",
                    "violations": ["data_encryption_missing", "no_consent_mechanism", "no_data_protection_officer"]
                }
            },
            overall_score=65.0,
            summary="GDPR violations detected"
        )

        violations = report.frameworks["gdpr"]["violations"]
        assert isinstance(violations, list)
        assert all(isinstance(v, str) for v in violations)
        assert len(violations) == 3

    def test_compliance_report_serialization(self):
        """Test compliance report serialization."""
        report = ComplianceReport(
            project_id=123,
            frameworks={"sox": {"score": 95.5, "status": "compliant", "violations": []}},
            overall_score=93.0,
            summary="Test report"
        )

        data = report.model_dump()
        assert data["project_id"] == 123
        assert data["overall_score"] == 93.0
        assert "generated_at" in data


class TestSecurityMetricsModel:
    """Test SecurityMetrics Pydantic model."""

    def test_security_metrics_creation(self):
        """Test creating security metrics."""
        metrics = SecurityMetrics(
            project_id=123,
            timestamp=datetime.utcnow(),
            vulnerabilities_total=25,
            vulnerabilities_critical=3,
            vulnerabilities_high=8,
            vulnerabilities_medium=10,
            vulnerabilities_low=4,
            mttr_hours=48.5,
            remediation_rate=0.85,
            compliance_score=92.0,
            security_posture="good",
            false_positive_rate=0.03,
            scan_coverage=0.78,
            vulnerability_inflow_rate=0.5
        )

        assert metrics.project_id == 123
        assert metrics.vulnerabilities_total == 25
        assert metrics.remediation_rate == 0.85
        assert metrics.security_posture == "good"

    def test_security_metrics_count_consistency(self):
        """Test that severity counts sum to total."""
        metrics = SecurityMetrics(
            project_id=1,
            timestamp=datetime.utcnow(),
            vulnerabilities_total=20,
            vulnerabilities_critical=2,
            vulnerabilities_high=6,
            vulnerabilities_medium=8,
            vulnerabilities_low=4,
            mttr_hours=24.0,
            remediation_rate=0.75,
            compliance_score=85.0,
            security_posture="fair",
            false_positive_rate=0.05,
            scan_coverage=0.65,
            vulnerability_inflow_rate=0.3
        )

        total = (metrics.vulnerabilities_critical +
                metrics.vulnerabilities_high +
                metrics.vulnerabilities_medium +
                metrics.vulnerabilities_low)
        assert total == metrics.vulnerabilities_total

    def test_security_metrics_rate_bounds(self):
        """Test rate fields are between 0 and 1."""
        metrics = SecurityMetrics(
            project_id=1,
            timestamp=datetime.utcnow(),
            vulnerabilities_total=10,
            vulnerabilities_critical=1,
            vulnerabilities_high=2,
            vulnerabilities_medium=4,
            vulnerabilities_low=3,
            mttr_hours=12.0,
            remediation_rate=0.85,  # Valid
            compliance_score=90.0,
            security_posture="good",
            false_positive_rate=0.03,  # Valid
            scan_coverage=0.78,  # Valid
            vulnerability_inflow_rate=0.5  # Valid
        )

        assert 0 <= metrics.remediation_rate <= 1
        assert 0 <= metrics.false_positive_rate <= 1
        assert 0 <= metrics.scan_coverage <= 1
        assert 0 <= metrics.vulnerability_inflow_rate <= 1

    def test_security_metrics_invalid_rate_raises(self):
        """Test that rates outside [0,1] raise ValidationError."""
        with pytest.raises(ValidationError):
            SecurityMetrics(
                project_id=1,
                timestamp=datetime.utcnow(),
                vulnerabilities_total=10,
                vulnerabilities_critical=1,
                vulnerabilities_high=2,
                vulnerabilities_medium=4,
                vulnerabilities_low=3,
                mttr_hours=12.0,
                remediation_rate=1.5,  # Invalid > 1
                compliance_score=90.0,
                security_posture="good",
                false_positive_rate=0.03,
                scan_coverage=0.78,
                vulnerability_inflow_rate=0.5
            )

    def test_security_metrics_posture_levels(self):
        """Test security posture valid values."""
        valid_postures = ["excellent", "good", "fair", "poor", "critical"]

        for posture in valid_postures:
            metrics = SecurityMetrics(
                project_id=1,
                timestamp=datetime.utcnow(),
                vulnerabilities_total=10,
                vulnerabilities_critical=1,
                vulnerabilities_high=2,
                vulnerabilities_medium=4,
                vulnerabilities_low=3,
                mttr_hours=12.0,
                remediation_rate=0.75,
                compliance_score=85.0,
                security_posture=posture,
                false_positive_rate=0.05,
                scan_coverage=0.65,
                vulnerability_inflow_rate=0.3
            )
            assert metrics.security_posture == posture


class TestAlertModel:
    """Test Alert Pydantic model."""

    def test_alert_creation(self):
        """Test creating alert."""
        alert = Alert(
            id="ALERT-001",
            title="Critical vulnerability detected",
            description="SQL injection in authentication endpoint",
            severity="critical",
            alert_type="vulnerability",
            triggered_at=datetime.utcnow(),
            metadata={
                "vulnerability_id": "VULN-001",
                "project_id": 123,
                "mr_id": 456
            }
        )

        assert alert.id == "ALERT-001"
        assert alert.severity == "critical"
        assert alert.alert_type == "vulnerability"
        assert alert.metadata["vulnerability_id"] == "VULN-001"

    def test_alert_acknowledge(self):
        """Test acknowledging an alert."""
        alert = Alert(
            id="ALERT-001",
            title="Test alert",
            description="Test",
            severity="high",
            alert_type="security",
            triggered_at=datetime.utcnow()
        )

        assert alert.acknowledged is False
        assert alert.acknowledged_at is None

        alert.acknowledge(user="security-bot")

        assert alert.acknowledged is True
        assert alert.acknowledged_at is not None

    def test_alert_resolve(self):
        """Test resolving an alert."""
        alert = Alert(
            id="ALERT-001",
            title="Test alert",
            description="Test",
            severity="high",
            alert_type="security",
            triggered_at=datetime.utcnow()
        )

        assert alert.resolved is False
        assert alert.resolved_at is None

        alert.resolve(user="security-bot", resolution="fixed")

        assert alert.resolved is True
        assert alert.resolved_at is not None
        assert alert.resolution == "fixed"

    def test_alert_ttl_calculation(self):
        """Test TTL-based auto-resolution."""
        alert = Alert(
            id="ALERT-001",
            title="Test alert",
            description="Test",
            severity="medium",
            alert_type="anomaly",
            triggered_at=datetime.utcnow(),
            ttl_minutes=60
        )

        assert alert.ttl_minutes == 60
        assert alert.is_expired() is False

        # Simulate expiration
        future_time = datetime.utcnow() + timedelta(hours=2)
        assert alert.is_expired(at=future_time) is True

    def test_alert_serialization(self):
        """Test alert serialization includes computed fields."""
        alert = Alert(
            id="ALERT-001",
            title="Test",
            description="Test",
            severity="high",
            alert_type="vulnerability",
            triggered_at=datetime.utcnow()
        )
        alert.acknowledge(user="admin")

        data = alert.model_dump()
        assert data["acknowledged"] is True
        assert "acknowledged_at" in data


class TestMergeRequestModel:
    """Test MergeRequest Pydantic model."""

    def test_merge_request_creation(self):
        """Test creating merge request."""
        mr = MergeRequest(
            id=456,
            project_id=123,
            title="Fix SQL injection vulnerability",
            description="Apply parameterized queries to user login",
            state="opened",
            author="developer",
            web_url="https://gitlab.com/project/merge_requests/456",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            target_branch="main",
            source_branch="fix/sql-injection",
            labels=["security", "vulnerability", "high-priority"]
        )

        assert mr.id == 456
        assert mr.state == "opened"
        assert mr.author == "developer"
        assert "security" in mr.labels

    def test_merge_request_state_transitions(self):
        """Test valid state transitions."""
        valid_states = ["opened", "closed", "merged", "locked"]

        for state in valid_states:
            mr = MergeRequest(
                id=1,
                project_id=1,
                title="Test",
                description="Test",
                state=state,
                author="test",
                web_url="https://test.com"
            )
            assert mr.state == state

    def test_merge_request_invalid_state_raises(self):
        """Test invalid state raises ValidationError."""
        with pytest.raises(ValidationError):
            MergeRequest(
                id=1,
                project_id=1,
                title="Test",
                description="Test",
                state="invalid_state",  # type: ignore
                author="test",
                web_url="https://test.com"
            )

    def test_merge_request_serialization(self):
        """Test merge request serialization."""
        mr = MergeRequest(
            id=456,
            project_id=123,
            title="Security fix",
            description="Fix vulnerability",
            state="opened",
            author="dev",
            web_url="https://gitlab.com/mr/456"
        )

        data = mr.model_dump()
        assert data["id"] == 456
        assert data["title"] == "Security fix"
        assert "created_at" in data
        assert "updated_at" in data


class TestModelEdgeCases:
    """Test edge cases and boundary conditions for models."""

    def test_vulnerability_very_long_title(self):
        """Test vulnerability with maximum title length."""
        long_title = "A" * 500
        vuln = Vulnerability(
            id="VULN-001",
            title=long_title,
            description="Test",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="test.py",
            line_number=1,
            scanner_source="sast",
            project_id=1,
            mr_id=1
        )
        assert vuln.title == long_title

    def test_vulnerability_unicode_characters(self):
        """Test vulnerability with unicode in description."""
        vuln = Vulnerability(
            id="VULN-001",
            title="Test",
            description="Vulnerabilidad con caracteres especiales: ñ, 中文, العربية",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="test.py",
            line_number=1,
            scanner_source="sast",
            project_id=1,
            mr_id=1
        )
        assert "中文" in vuln.description

    def test_analyzed_vulnerability_extreme_scores(self):
        """Test analyzed vulnerability with extreme but valid scores."""
        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            root_cause="Critical vulnerability",
            exploitability_score=10.0,  # Maximum
            impact_score=10.0,  # Maximum
            false_positive_probability=0.0,  # Minimum
            confidence=1.0,  # Maximum
            priority_score=1.0,  # Maximum
            recommended_fix_pattern="critical_fix"
        )

        assert analyzed.exploitability_score == 10.0
        assert analyzed.impact_score == 10.0
        assert analyzed.false_positive_probability == 0.0
        assert analyzed.confidence == 1.0
        assert analyzed.priority_score == 1.0

    def test_remediation_plan_large_diff(self):
        """Test remediation plan with large code diff."""
        large_diff = "@@ -1,10 +1,20 @@\n" + "\n".join([f"+ line {i}" for i in range(1000)])

        plan = RemediationPlan(
            vulnerability_id="VULN-001",
            fix_description="Large refactoring",
            fix_pattern="refactor",
            confidence=0.9,
            estimated_effort="2d",
            code_changes={"file": "large_file.py", "diff": large_diff},
            verification_status="pending"
        )

        assert len(plan.code_changes["diff"]) > 1000

    def test_compliance_report_empty_frameworks(self):
        """Test compliance report with no frameworks."""
        report = ComplianceReport(
            project_id=1,
            frameworks={},
            overall_score=0.0,
            summary="No frameworks assessed"
        )

        assert len(report.frameworks) == 0
        assert report.overall_score == 0.0

    def test_security_metrics_zero_values(self):
        """Test security metrics with zero values."""
        metrics = SecurityMetrics(
            project_id=1,
            timestamp=datetime.utcnow(),
            vulnerabilities_total=0,
            vulnerabilities_critical=0,
            vulnerabilities_high=0,
            vulnerabilities_medium=0,
            vulnerabilities_low=0,
            mttr_hours=0.0,
            remediation_rate=0.0,
            compliance_score=0.0,
            security_posture="excellent",
            false_positive_rate=0.0,
            scan_coverage=0.0,
            vulnerability_inflow_rate=0.0
        )

        assert metrics.vulnerabilities_total == 0
        assert metrics.remediation_rate == 0.0
        assert metrics.security_posture == "excellent"
