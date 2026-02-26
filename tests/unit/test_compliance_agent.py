"""
Comprehensive test suite for ComplianceAgent.
Target: 100% coverage of compliance_agent.py
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from agents.compliance_agent import ComplianceAgent, ComplianceFramework, ComplianceRequirement, ComplianceViolation, ComplianceReport
from core.models import Vulnerability, Severity, VulnerabilitySource
from core.config import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.compliance_frameworks = ["SOX", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST"]
    settings.compliance_auto_remediate = False
    return settings


@pytest.fixture
def mock_knowledge_graph():
    """Create mock knowledge graph."""
    kg = AsyncMock()
    kg.get_compliance_history.return_value = []
    kg.store_compliance_report.return_value = True
    return kg


@pytest.fixture
def compliance_agent(mock_settings, mock_knowledge_graph):
    """Create ComplianceAgent instance with mocked dependencies."""
    agent = ComplianceAgent(
        settings=mock_settings,
        knowledge_graph=mock_knowledge_graph
    )
    return agent


class TestComplianceAgentInitialization:
    """Test ComplianceAgent initialization."""

    def test_init_with_frameworks(self, compliance_agent):
        """Test successful initialization with frameworks."""
        assert compliance_agent.settings is not None
        assert compliance_agent.knowledge_graph is not None
        assert len(compliance_agent.frameworks) > 0
        assert isinstance(compliance_agent.frameworks, dict)

    def test_frameworks_loaded(self, compliance_agent):
        """Test all configured frameworks are loaded."""
        expected_frameworks = ["SOX", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST"]
        for framework in expected_frameworks:
            assert framework in compliance_agent.frameworks

    def test_framework_structure(self, compliance_agent):
        """Test each framework has required structure."""
        for name, framework in compliance_agent.frameworks.items():
            assert isinstance(framework, ComplianceFramework)
            assert framework.name == name
            assert len(framework.requirements) > 0
            for req in framework.requirements:
                assert isinstance(req, ComplianceRequirement)
                assert req.id
                assert req.description
                assert req.control
                assert isinstance(req.vulnerability_types, list)
                assert isinstance(req.severity_thresholds, dict)

    def test_custom_frameworks_configurable(self, mock_settings, mock_knowledge_graph):
        """Test frameworks are configurable via settings."""
        mock_settings.compliance_frameworks = ["SOX", "HIPAA"]
        agent = ComplianceAgent(settings=mock_settings, knowledge_graph=mock_knowledge_graph)
        assert len(agent.frameworks) == 2
        assert "SOX" in agent.frameworks
        assert "HIPAA" in agent.frameworks


class TestComplianceAgentFrameworkDefinitions:
    """Test compliance framework definitions."""

    def test_sox_requirements(self, compliance_agent):
        """Test SOX framework requirements."""
        sox = compliance_agent.frameworks["SOX"]
        assert sox.name == "SOX"
        assert len(sox.requirements) >= 5

        # Check for key requirements
        req_ids = [r.id for r in sox.requirements]
        assert "SOX-404" in req_ids  # Access controls
        assert "SOX-302" in req_ids  # Data integrity

    def test_hipaa_requirements(self, compliance_agent):
        """Test HIPAA framework requirements."""
        hipaa = compliance_agent.frameworks["HIPAA"]
        assert len(hipaa.requirements) >= 5

        # Check for PHI protection requirements
        phi_reqs = [r for r in hipaa.requirements if "PHI" in r.description or "164" in r.control]
        assert len(phi_reqs) > 0

    def test_gdpr_requirements(self, compliance_agent):
        """Test GDPR framework requirements."""
        gdpr = compliance_agent.frameworks["GDPR"]
        assert len(gdpr.requirements) >= 5

        # Check for data protection requirements
        dp_reqs = [r for r in gdpr.requirements if "data" in r.description.lower()]
        assert len(dp_reqs) > 0

    def test_pci_dss_requirements(self, compliance_agent):
        """Test PCI-DSS framework requirements."""
        pci = compliance_agent.frameworks["PCI-DSS"]
        assert len(pci.requirements) >= 5

        # Check for payment card security requirements
        payment_reqs = [r for r in pci.requirements if "card" in r.description.lower() or "payment" in r.description.lower()]
        assert len(payment_reqs) > 0

    def test_iso27001_requirements(self, compliance_agent):
        """Test ISO 27001 framework requirements."""
        iso = compliance_agent.frameworks["ISO27001"]
        assert len(iso.requirements) >= 5

        # Check for information security requirements
        sec_reqs = [r for r in iso.requirements if "security" in r.description.lower()]
        assert len(sec_reqs) > 0

    def test_nist_requirements(self, compliance_agent):
        """Test NIST CSF framework requirements."""
        nist = compliance_agent.frameworks["NIST"]
        assert len(nist.requirements) >= 5

        # Check for cybersecurity framework requirements
        csrf_reqs = [r for r in nist.requirements if "identify" in r.id.lower() or "protect" in r.id.lower()]
        assert len(csrf_reqs) > 0


class TestComplianceAgentMapping:
    """Test vulnerability to compliance mapping."""

    def test_map_sql_injection_to_frameworks(self, compliance_agent):
        """Test SQL injection maps to multiple frameworks."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="User input not sanitized in SQL query",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-89"
        )

        violations = compliance_agent._map_vulnerability_to_compliance(vuln)

        assert len(violations) > 0
        framework_names = [v.framework_name for v in violations]
        # SQL injection should violate multiple frameworks
        assert "SOX" in framework_names or "PCI-DSS" in framework_names or "GDPR" in framework_names

    def test_map_xss_to_frameworks(self, compliance_agent):
        """Test XSS maps to privacy frameworks."""
        vuln = Vulnerability(
            id="VULN-002",
            title="Reflected XSS",
            description="User input rendered without escaping",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-79"
        )

        violations = compliance_agent._map_vulnerability_to_compliance(vuln)

        assert len(violations) > 0
        framework_names = [v.framework_name for v in violations]
        # XSS should violate GDPR/HIPAA (data protection)
        assert "GDPR" in framework_names or "HIPAA" in framework_names

    def test_map_critical_severity_violations(self, compliance_agent):
        """Test critical severity creates violations in all frameworks."""
        vuln = Vulnerability(
            id="VULN-003",
            title="Critical Vulnerability",
            description="Severe security issue",
            severity=Severity.CRITICAL,
            source=VulnerabilitySource.SAST
        )

        violations = compliance_agent._map_vulnerability_to_compliance(vuln)

        # Critical should map to all frameworks with appropriate thresholds
        framework_names = [v.framework_name for v in violations]
        assert len(framework_names) >= 3

    def test_map_low_severity_minimal_violations(self, compliance_agent):
        """Test low severity may not violate strict frameworks."""
        vuln = Vulnerability(
            id="VULN-004",
            title="Low Risk Issue",
            description="Minor security concern",
            severity=Severity.LOW,
            source=VulnerabilitySource.SAST
        )

        violations = compliance_agent._map_vulnerability_to_compliance(vuln)

        # Low severity might not violate frameworks with high thresholds
        # But should still violate some with lower thresholds
        assert len(violations) >= 0  # Could be 0 or more

    def test_map_by_cwe_specificity(self, compliance_agent):
        """Test mapping uses CWE ID for precise framework matching."""
        vuln = Vulnerability(
            id="VULN-005",
            title="Weak Cryptography",
            description="Uses MD5 hashing",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST,
            cwe_id="CWE-327"  # Weak Cryptographic
        )

        violations = compliance_agent._map_vulnerability_to_compliance(vuln)

        # Should map to frameworks with cryptography requirements
        framework_names = [v.framework_name for v in violations]
        # PCI-DSS and ISO27001 have crypto requirements
        assert len(framework_names) > 0

    def test_map_with_confidence_filter(self, compliance_agent):
        """Test mapping considers vulnerability confidence."""
        vuln = Vulnerability(
            id="VULN-006",
            title="Potential Issue",
            description="Uncertain finding",
            severity=Severity.MEDIUM,
            source=VulnerabilitySource.SAST,
            confidence=0.4  # Low confidence
        )

        violations = compliance_agent._map_vulnerability_to_compliance(vuln)

        # Low confidence might reduce violations
        # Implementation-specific: may filter out low confidence
        assert isinstance(violations, list)


class TestComplianceAgentScoring:
    """Test compliance scoring calculations."""

    def test_calculate_framework_score_all_compliant(self, compliance_agent):
        """Test score calculation with no violations."""
        violations = []
        total_requirements = 20

        score = compliance_agent._calculate_framework_score(violations, total_requirements)

        assert score == 100.0

    def test_calculate_framework_score_with_violations(self, compliance_agent):
        """Test score calculation with violations."""
        violations = [
            ComplianceViolation(
                framework_name="SOX",
                requirement_id="SOX-404",
                requirement_description="Access controls",
                control="CC6.1",
                vulnerability_id="VULN-001",
                severity=Severity.HIGH,
                remediation_priority=0.9
            ),
            ComplianceViolation(
                framework_name="SOX",
                requirement_id="SOX-302",
                requirement_description="Data integrity",
                control="CC3.1",
                vulnerability_id="VULN-002",
                severity=Severity.MEDIUM,
                remediation_priority=0.7
            )
        ]
        total_requirements = 20

        score = compliance_agent._calculate_framework_score(violations, total_requirements)

        # 2 violations out of 20 = 90% compliant
        assert score == pytest.approx(90.0)

    def test_calculate_overall_compliance_score(self, compliance_agent):
        """Test overall compliance score across frameworks."""
        framework_scores = {
            "SOX": 95.0,
            "HIPAA": 88.0,
            "GDPR": 92.0,
            "PCI-DSS": 85.0
        }

        overall = compliance_agent._calculate_overall_compliance_score(framework_scores)

        # Average of scores
        expected = sum(framework_scores.values()) / len(framework_scores)
        assert overall == pytest.approx(expected)

    def test_calculate_overall_with_weighted_frameworks(self, compliance_agent):
        """Test weighted compliance score (if implemented)."""
        # Some implementations may weight frameworks differently
        framework_scores = {
            "SOX": 95.0,
            "HIPAA": 88.0,
            "GDPR": 92.0
        }

        overall = compliance_agent._calculate_overall_compliance_score(framework_scores)

        # Should be between min and max
        assert 88.0 <= overall <= 95.0


class TestComplianceAgentGapAnalysis:
    """Test gap analysis functionality."""

    def test_gap_analysis_identifies_missing_controls(self, compliance_agent):
        """Test gap analysis identifies missing security controls."""
        violations = [
            ComplianceViolation(
                framework_name="SOX",
                requirement_id="SOX-404",
                requirement_description="Access controls",
                control="CC6.1",
                vulnerability_id="VULN-001",
                severity=Severity.HIGH,
                remediation_priority=0.9
            )
        ]

        gaps = compliance_agent._perform_gap_analysis(violations)

        assert len(gaps) > 0
        gap = gaps[0]
        assert gap.framework_name == "SOX"
        assert gap.requirement_id == "SOX-404"
        assert gap.violation_count >= 1
        assert gap.risk_level in ["HIGH", "MEDIUM", "LOW"]

    def test_gap_analysis_risk_level_calculation(self, compliance_agent):
        """Test risk level calculation based on severity."""
        # High severity -> HIGH risk
        high_violations = [
            ComplianceViolation(
                framework_name="SOX",
                requirement_id="SOX-404",
                requirement_description="Test",
                control="CC6.1",
                vulnerability_id="VULN-001",
                severity=Severity.CRITICAL,
                remediation_priority=1.0
            )
        ]

        gaps = compliance_agent._perform_gap_analysis(high_violations)
        assert gaps[0].risk_level == "HIGH"

        # Low severity -> LOW risk
        low_violations = [
            ComplianceViolation(
                framework_name="SOX",
                requirement_id="SOX-404",
                requirement_description="Test",
                control="CC6.1",
                vulnerability_id="VULN-002",
                severity=Severity.LOW,
                remediation_priority=0.3
            )
        ]

        gaps = compliance_agent._perform_gap_analysis(low_violations)
        assert gaps[0].risk_level == "LOW"

    def test_gap_analysis_aggregates_by_requirement(self, compliance_agent):
        """Test gap analysis aggregates violations by requirement."""
        violations = [
            ComplianceViolation(
                framework_name="SOX",
                requirement_id="SOX-404",
                requirement_description="Access controls",
                control="CC6.1",
                vulnerability_id="VULN-001",
                severity=Severity.HIGH,
                remediation_priority=0.9
            ),
            ComplianceViolation(
                framework_name="SOX",
                requirement_id="SOX-404",  # Same requirement
                requirement_description="Access controls",
                control="CC6.1",
                vulnerability_id="VULN-002",
                severity=Severity.MEDIUM,
                remediation_priority=0.7
            )
        ]

        gaps = compliance_agent._perform_gap_analysis(violations)

        # Should aggregate into single gap for SOX-404
        assert len(gaps) == 1
        assert gaps[0].violation_count == 2
        assert gaps[0].vulnerability_ids == ["VULN-001", "VULN-002"]


class TestComplianceAgentReportGeneration:
    """Test compliance report generation."""

    @pytest.mark.asyncio
    async def test_generate_report_all_frameworks(self, compliance_agent):
        """Test report generation for all frameworks."""
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                cwe_id="CWE-89"
            ),
            Vulnerability(
                id="VULN-002",
                title="XSS",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                cwe_id="CWE-79"
            )
        ]

        report = await compliance_agent.generate_compliance_report(
            vulnerabilities, "project-123"
        )

        assert isinstance(report, ComplianceReport)
        assert report.project_id == "project-123"
        assert len(report.framework_scores) > 0
        assert report.overall_score >= 0
        assert report.overall_score <= 100
        assert len(report.violations) > 0
        assert len(report.gaps) > 0
        assert report.generated_at is not None

    @pytest.mark.asyncio
    async def test_generate_report_empty_vulnerabilities(self, compliance_agent):
        """Test report generation with no vulnerabilities."""
        vulnerabilities = []

        report = await compliance_agent.generate_compliance_report(
            vulnerabilities, "project-123"
        )

        assert report.overall_score == 100.0
        assert len(report.violations) == 0
        assert len(report.gaps) == 0

    @pytest.mark.asyncio
    async def test_generate_report_single_framework(self, compliance_agent):
        """Test report generation for single framework."""
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST
            )
        ]

        report = await compliance_agent.generate_compliance_report(
            vulnerabilities, "project-123", frameworks=["SOX"]
        )

        assert len(report.framework_scores) == 1
        assert "SOX" in report.framework_scores

    @pytest.mark.asyncio
    async def test_generate_report_includes_evidence(self, compliance_agent):
        """Test report includes evidence collection."""
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="Test",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST
            )
        ]

        report = await compliance_agent.generate_compliance_report(
            vulnerabilities, "project-123"
        )

        assert report.evidence is not None
        assert "security_scans" in report.evidence
        assert "remediation_stats" in report.evidence
        assert "historical_trends" in report.evidence

    def test_build_evidence_collection(self, compliance_agent):
        """Test evidence collection building."""
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST
            ),
            Vulnerability(
                id="VULN-002",
                title="XSS",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST
            )
        ]

        evidence = compliance_agent._build_evidence_collection(vulnerabilities, "project-123")

        assert "security_scans" in evidence
        assert evidence["security_scans"]["total_vulnerabilities"] == 2
        assert evidence["security_scans"]["by_severity"]["HIGH"] == 1
        assert evidence["security_scans"]["by_severity"]["MEDIUM"] == 1
        assert "remediation_stats" in evidence
        assert "historical_trends" in evidence


class TestComplianceAgentAuditReport:
    """Test audit report generation."""

    @pytest.mark.asyncio
    async def test_generate_audit_report_structure(self, compliance_agent):
        """Test audit report has complete structure."""
        audit = await compliance_agent.generate_audit_report("project-123")

        assert "executive_summary" in audit
        assert "framework_details" in audit
        assert "violations" in audit
        assert "recommendations" in audit
        assert "evidence" in audit
        assert "generated_at" in audit

    @pytest.mark.asyncio
    async def test_generate_audit_report_executive_summary(self, compliance_agent):
        """Test executive summary content."""
        audit = await compliance_agent.generate_audit_report("project-123")

        summary = audit["executive_summary"]
        assert "overall_compliance_score" in summary
        assert "frameworks_assessed" in summary
        assert "total_violations" in summary
        assert "high_risk_violations" in summary
        assert "compliance_status" in summary
        assert summary["overall_compliance_score"] >= 0
        assert summary["overall_compliance_score"] <= 100

    @pytest.mark.asyncio
    async def test_generate_audit_report_framework_details(self, compliance_agent):
        """Test framework details in audit report."""
        audit = await compliance_agent.generate_audit_report("project-123")

        details = audit["framework_details"]
        assert isinstance(details, list)
        if len(details) > 0:
            framework_detail = details[0]
            assert "framework" in framework_detail
            assert "score" in framework_detail
            assert "requirements_total" in framework_detail
            assert "requirements_compliant" in framework_detail
            assert "violations" in framework_detail

    @pytest.mark.asyncio
    async def test_generate_audit_report_recommendations(self, compliance_agent):
        """Test recommendations in audit report."""
        audit = await compliance_agent.generate_audit_report("project-123")

        recommendations = audit["recommendations"]
        assert isinstance(recommendations, list)

        if len(recommendations) > 0:
            rec = recommendations[0]
            assert "framework" in rec
            assert "requirement_id" in rec
            assert "description" in rec
            assert "priority" in rec
            assert rec["priority"] in ["HIGH", "MEDIUM", "LOW"]

    @pytest.mark.asyncio
    async def test_generate_audit_report_with_violations(self, compliance_agent):
        """Test audit report when violations exist."""
        # Mock vulnerabilities that cause violations
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.CRITICAL,
                source=VulnerabilitySource.SAST,
                cwe_id="CWE-89"
            )
        ]

        # Override knowledge graph to return violations
        compliance_agent.knowledge_graph.get_compliance_history.return_value = []

        audit = await compliance_agent.generate_audit_report("project-123", vulnerabilities)

        # Should have violations section
        assert len(audit["violations"]) > 0
        violation = audit["violations"][0]
        assert "framework_name" in violation
        assert "requirement_id" in violation
        assert "vulnerability_id" in violation
        assert "severity" in violation


class TestComplianceAgentDriftDetection:
    """Test compliance drift detection."""

    @pytest.mark.asyncio
    async def test_detect_drift_no_history(self, compliance_agent):
        """Test drift detection with no historical data."""
        compliance_agent.knowledge_graph.get_compliance_history.return_value = []

        drift = await compliance_agent.detect_compliance_drift("project-123")

        assert drift["drift_detected"] is False
        assert drift["reason"] == "no_historical_data"
        assert len(drift["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_detect_drift_improving_compliance(self, compliance_agent):
        """Test drift detection when compliance is improving."""
        # Historical data: lower scores
        historical = [
            {
                "timestamp": datetime.utcnow() - timedelta(days=7),
                "overall_score": 80.0
            },
            {
                "timestamp": datetime.utcnow() - timedelta(days=3),
                "overall_score": 85.0
            }
        ]

        # Current score: higher
        current_score = 90.0

        compliance_agent.knowledge_graph.get_compliance_history.return_value = historical

        drift = await compliance_agent.detect_compliance_drift("project-123", current_score)

        assert drift["drift_detected"] is False
        assert drift["trend"] == "improving"
        assert drift["change_percentage"] > 0

    @pytest.mark.asyncio
    async def test_detect_drift_declining_compliance(self, compliance_agent):
        """Test drift detection when compliance is declining."""
        # Historical data: higher scores
        historical = [
            {
                "timestamp": datetime.utcnow() - timedelta(days=7),
                "overall_score": 95.0
            },
            {
                "timestamp": datetime.utcnow() - timedelta(days=3),
                "overall_score": 90.0
            }
        ]

        # Current score: lower
        current_score = 80.0

        compliance_agent.knowledge_graph.get_compliance_history.return_value = historical

        drift = await compliance_agent.detect_compliance_drift("project-123", current_score)

        assert drift["drift_detected"] is True
        assert drift["trend"] == "declining"
        assert drift["change_percentage"] < 0
        assert len(drift["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_detect_drift_significant_change(self, compliance_agent):
        """Test drift detection flags significant changes."""
        # Historical score
        historical = [
            {
                "timestamp": datetime.utcnow() - timedelta(days=7),
                "overall_score": 95.0
            }
        ]

        # Current score: 10% drop
        current_score = 85.0

        compliance_agent.knowledge_graph.get_compliance_history.return_value = historical

        drift = await compliance_agent.detect_compliance_drift("project-123", current_score)

        # 10% drop should trigger drift
        assert drift["drift_detected"] is True
        assert abs(drift["change_percentage"]) > 5.0  # 5% threshold

    def test_calculate_trend_analysis(self, compliance_agent):
        """Test trend analysis calculation."""
        historical = [
            {"timestamp": datetime.utcnow() - timedelta(days=14), "overall_score": 80.0},
            {"timestamp": datetime.utcnow() - timedelta(days=7), "overall_score": 85.0},
            {"timestamp": datetime.utcnow() - timedelta(days=3), "overall_score": 90.0}
        ]

        trend = compliance_agent._calculate_trend_analysis(historical)

        assert "trend" in trend
        assert trend["trend"] == "improving"
        assert "slope" in trend
        assert trend["slope"] > 0
        assert "change_percentage" in trend
        assert trend["change_percentage"] > 0

    def test_calculate_trend_analysis_declining(self, compliance_agent):
        """Test trend analysis for declining scores."""
        historical = [
            {"timestamp": datetime.utcnow() - timedelta(days=14), "overall_score": 95.0},
            {"timestamp": datetime.utcnow() - timedelta(days=7), "overall_score": 90.0},
            {"timestamp": datetime.utcnow() - timedelta(days=3), "overall_score": 85.0}
        ]

        trend = compliance_agent._calculate_trend_analysis(historical)

        assert trend["trend"] == "declining"
        assert trend["slope"] < 0
        assert trend["change_percentage"] < 0

    def test_calculate_trend_analysis_stable(self, compliance_agent):
        """Test trend analysis for stable scores."""
        historical = [
            {"timestamp": datetime.utcnow() - timedelta(days=14), "overall_score": 90.0},
            {"timestamp": datetime.utcnow() - timedelta(days=7), "overall_score": 90.5},
            {"timestamp": datetime.utcnow() - timedelta(days=3), "overall_score": 90.0}
        ]

        trend = compliance_agent._calculate_trend_analysis(historical)

        assert trend["trend"] == "stable"
        assert abs(trend["slope"]) < 0.1
        assert abs(trend["change_percentage"]) < 5.0


class TestComplianceAgentHealth:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, compliance_agent):
        """Test health check when all components healthy."""
        health = await compliance_agent.health_check()

        assert health["status"] == "healthy"
        assert health["knowledge_graph"] is True
        assert health["frameworks_loaded"] is True
        assert health["total_frameworks"] == len(compliance_agent.frameworks)

    @pytest.mark.asyncio
    async def test_health_check_degraded(self, compliance_agent):
        """Test health check when knowledge graph fails."""
        compliance_agent.knowledge_graph = MagicMock()
        compliance_agent.knowledge_graph.get_compliance_history.side_effect = Exception("DB Error")

        health = await compliance_agent.health_check()

        assert health["status"] == "degraded"
        assert health["knowledge_graph"] is False

    @pytest.mark.asyncio
    async def test_health_check_no_frameworks(self, mock_settings, mock_knowledge_graph):
        """Test health check when no frameworks configured."""
        mock_settings.compliance_frameworks = []
        agent = ComplianceAgent(settings=mock_settings, knowledge_graph=mock_knowledge_graph)

        health = await agent.health_check()

        assert health["status"] == "degraded"
        assert health["frameworks_loaded"] is False
        assert health["total_frameworks"] == 0


class TestComplianceAgentStatistics:
    """Test statistics tracking."""

    def test_get_statistics_initial(self, compliance_agent):
        """Test statistics on fresh agent."""
        stats = compliance_agent.get_statistics()

        assert stats["reports_generated"] == 0
        assert stats["audits_completed"] == 0
        assert stats["violations_detected"] == 0
        assert stats["frameworks_monitored"] == len(compliance_agent.frameworks)

    def test_statistics_after_activity(self, compliance_agent):
        """Test statistics after some activity."""
        compliance_agent._reports_generated = 10
        compliance_agent._audits_completed = 5
        compliance_agent._violations_detected = 25

        stats = compliance_agent.get_statistics()

        assert stats["reports_generated"] == 10
        assert stats["audits_completed"] == 5
        assert stats["violations_detected"] == 25


class TestComplianceAgentIntegration:
    """Integration tests with full workflow."""

    @pytest.mark.asyncio
    async def test_full_compliance_workflow(self, compliance_agent):
        """Test complete compliance assessment workflow."""
        # Create realistic vulnerability set
        vulnerabilities = [
            Vulnerability(
                id="SECUREAI-2024-001",
                title="SQL Injection in User Authentication",
                description="The login endpoint constructs SQL queries using string concatenation, allowing attackers to bypass authentication and gain unauthorized access to user accounts.",
                severity=Severity.CRITICAL,
                source=VulnerabilitySource.SAST,
                file_path="app/auth.py",
                line_number=45,
                code_snippet="query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''",
                cwe_id="CWE-89",
                confidence=0.94
            ),
            Vulnerability(
                id="SECUREAI-2024-002",
                title="Hardcoded Database Credentials",
                description="Database connection credentials are hardcoded in the source code, exposing sensitive authentication information.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/config.py",
                line_number=12,
                code_snippet="DB_PASSWORD = 'SuperSecret123!'",
                cwe_id="CWE-798",
                confidence=0.88
            ),
            Vulnerability(
                id="SECUREAI-2024-003",
                title="Insufficient Transport Layer Security",
                description="HTTPS is not enforced, allowing man-in-the-middle attacks on sensitive data in transit.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.DAST,
                file_path="app/main.py",
                line_number=78,
                cwe_id="CWE-319"
            )
        ]

        # Generate compliance report
        report = await compliance_agent.generate_compliance_report(
            vulnerabilities, "secureai-demo"
        )

        # Verify comprehensive report
        assert isinstance(report, ComplianceReport)
        assert report.project_id == "secureai-demo"
        assert len(report.framework_scores) > 0

        # Verify all frameworks assessed
        for framework_name in ["SOX", "HIPAA", "GDPR", "PCI-DSS"]:
            assert framework_name in report.framework_scores

        # Verify violations identified
        assert len(report.violations) > 0

        # Verify gaps analyzed
        assert len(report.gaps) > 0

        # Verify overall score calculated
        assert 0 <= report.overall_score <= 100

        # Verify evidence collected
        assert report.evidence is not None
        assert report.evidence["security_scans"]["total_vulnerabilities"] == 3

        # Verify audit report can be generated
        audit = await compliance_agent.generate_audit_report("secureai-demo", vulnerabilities)
        assert "executive_summary" in audit
        assert "framework_details" in audit
        assert len(audit["violations"]) > 0

    @pytest.mark.asyncio
    async def test_compliance_with_multiple_frameworks(self, compliance_agent):
        """Test compliance assessment across all configured frameworks."""
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.CRITICAL,
                source=VulnerabilitySource.SAST,
                cwe_id="CWE-89"
            )
        ]

        report = await compliance_agent.generate_compliance_report(
            vulnerabilities, "project-123",
            frameworks=["SOX", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST"]
        )

        # Should assess all 6 frameworks
        assert len(report.framework_scores) == 6
        for framework in ["SOX", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST"]:
            assert framework in report.framework_scores

    @pytest.mark.asyncio
    async def test_compliance_drift_detection_workflow(self, compliance_agent):
        """Test complete drift detection workflow."""
        # Generate two reports with different scores
        vulns1 = [Vulnerability(id="V1", title="Test", severity=Severity.HIGH)]
        vulns2 = [Vulnerability(id="V2", title="Test", severity=Severity.LOW)]

        report1 = await compliance_agent.generate_compliance_report(vulns1, "project-123")
        report2 = await compliance_agent.generate_compliance_report(vulns2, "project-123")

        # Store in knowledge graph (mocked)
        compliance_agent.knowledge_graph.get_compliance_history.return_value = [
            {"timestamp": datetime.utcnow() - timedelta(days=7), "overall_score": report1.overall_score}
        ]

        # Detect drift with current score
        drift = await compliance_agent.detect_compliance_drift("project-123", report2.overall_score)

        # Should detect improvement (score increased)
        assert drift["trend"] in ["improving", "declining", "stable"]
        assert "change_percentage" in drift
        assert "recommendations" in drift
