"""
Integration tests for complete SecurAI Guardian pipeline.
Tests end-to-end workflow across all 6 agents.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from app.orchestrator import SecurityOrchestrator
from core.models import Vulnerability, Severity, VulnerabilitySource
from agents.scanner_agent import ScannerAgent
from agents.analyzer_agent import AnalyzerAgent, AnalyzedVulnerability
from agents.remediation_agent import RemediationAgent, AppliedFix
from agents.compliance_agent import ComplianceAgent, ComplianceReport
from agents.monitoring_agent import MonitoringAgent, SecurityMetrics
from agents.knowledge_graph_agent import KnowledgeGraphAgent
from core.config import Settings


@pytest.fixture
def mock_all_agents():
    """Create all agents with realistic mock implementations."""
    settings = MagicMock(spec=Settings)
    settings.anthropic_api_key = "test-key"
    settings.anthropic_model = "claude-3.5-sonnet"
    settings.remediation_auto_apply = True
    settings.remediation_confidence_threshold = 0.85
    settings.compliance_frameworks = ["SOX", "HIPAA", "GDPR"]
    settings.monitoring_retention_days = 30

    # Scanner Agent
    scanner = ScannerAgent(
        settings=settings,
        gitlab_client=AsyncMock(),
        knowledge_graph=AsyncMock()
    )

    # Analyzer Agent
    analyzer = AnalyzerAgent(
        settings=settings,
        gitlab_client=AsyncMock(),
        knowledge_graph=AsyncMock()
    )

    # Remediation Agent
    remediation = RemediationAgent(
        settings=settings,
        gitlab_client=AsyncMock(),
        knowledge_graph=AsyncMock()
    )

    # Compliance Agent
    compliance = ComplianceAgent(
        settings=settings,
        knowledge_graph=AsyncMock()
    )

    # Monitoring Agent
    monitoring = MonitoringAgent(
        settings=settings,
        knowledge_graph=AsyncMock()
    )

    # Knowledge Graph Agent
    knowledge_graph = KnowledgeGraphAgent(
        settings=settings,
        knowledge_graph=AsyncMock()
    )

    return {
        "scanner": scanner,
        "analyzer": analyzer,
        "remediation": remediation,
        "compliance": compliance,
        "monitoring": monitoring,
        "knowledge_graph": knowledge_graph,
        "settings": settings
    }


@pytest.fixture
def orchestrator(mock_all_agents):
    """Create orchestrator with all mocked agents."""
    return SecurityOrchestrator(
        scanner_agent=mock_all_agents["scanner"],
        analyzer_agent=mock_all_agents["analyzer"],
        remediation_agent=mock_all_agents["remediation"],
        compliance_agent=mock_all_agents["compliance"],
        monitoring_agent=mock_all_agents["monitoring"],
        knowledge_graph_agent=mock_all_agents["knowledge_graph"]
    )


class TestFullPipelineIntegration:
    """Test complete end-to-end security pipeline."""

    @pytest.mark.asyncio
    async def test_complete_scan_remediate_compliance_workflow(self, orchestrator, mock_all_agents):
        """Test full pipeline: scan → analyze → remediate → compliance → monitoring → knowledge."""
        # Arrange: realistic vulnerability set from a secureai-demo project
        vulnerabilities = [
            Vulnerability(
                id="SECUREAI-2024-001",
                title="SQL Injection in User Authentication",
                description="The login endpoint constructs SQL queries using string concatenation, allowing attackers to bypass authentication and gain unauthorized access to user accounts. This vulnerability affects the core authentication flow and could lead to complete database compromise.",
                severity=Severity.CRITICAL,
                source=VulnerabilitySource.SAST,
                file_path="app/auth.py",
                line_number=45,
                code_snippet="query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''",
                cwe_id="CWE-89",
                confidence=0.94,
                discovered_at=datetime.utcnow() - timedelta(hours=2)
            ),
            Vulnerability(
                id="SECUREAI-2024-002",
                title="Hardcoded Database Credentials",
                description="Database connection credentials are hardcoded in the source code, exposing sensitive authentication information. This is a critical security flaw that could lead to unauthorized database access.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/config.py",
                line_number=12,
                code_snippet="DB_PASSWORD = 'SuperSecret123!'",
                cwe_id="CWE-798",
                confidence=0.88,
                discovered_at=datetime.utcnow() - timedelta(hours=1)
            ),
            Vulnerability(
                id="SECUREAI-2024-003",
                title="Reflected Cross-Site Scripting (XSS)",
                description="User input is rendered without proper escaping in the user profile page, allowing attackers to inject malicious scripts that execute in victims' browsers. This can lead to session hijacking and credential theft.",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                file_path="app/views.py",
                line_number=78,
                code_snippet="return f'<div>{user_input}</div>'",
                cwe_id="CWE-79",
                confidence=0.85,
                discovered_at=datetime.utcnow() - timedelta(minutes=30)
            ),
            Vulnerability(
                id="SECUREAI-2024-004",
                title="Missing HTTPS Enforcement",
                description="The application does not enforce HTTPS, allowing man-in-the-middle attacks on sensitive data in transit. This violates security best practices and compliance requirements.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.DAST,
                file_path="app/main.py",
                line_number=102,
                cwe_id="CWE-319",
                confidence=0.91,
                discovered_at=datetime.utcnow() - timedelta(minutes=15)
            )
        ]

        # Mock scanner to return these vulnerabilities
        mock_all_agents["scanner"].scan.return_value = vulnerabilities

        # Mock analyzer with detailed analysis for each
        analyzed_results = [
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-2024-001",
                confidence=0.98,
                false_positive_probability=0.02,
                priority_score=0.95,
                remediation_effort=1.5,
                suggested_fix="Use parameterized queries with placeholders to separate SQL code from data. Example: cursor.execute('SELECT * FROM users WHERE username = %s', (username,))",
                analysis={
                    "root_cause": "String concatenation in SQL query construction at auth.py:45",
                    "attack_vector": "Network",
                    "attack_complexity": "Low",
                    "privileges_required": "None",
                    "user_interaction": "None",
                    "scope": "Unchanged",
                    "impact": "Complete database compromise, data exfiltration, privilege escalation, potential for ransomware deployment",
                    "cvss_base_score": 9.1,
                    "exploitability_metrics": {
                        "attack_vector": "Network",
                        "attack_complexity": "Low",
                        "privileges_required": "None",
                        "user_interaction": "None",
                        "scope": "Unchanged"
                    }
                }
            ),
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-2024-002",
                confidence=0.92,
                false_positive_probability=0.05,
                priority_score=0.88,
                remediation_effort=0.5,
                suggested_fix="Remove hardcoded credentials immediately. Use environment variables or a secrets management solution like HashiCorp Vault or AWS Secrets Manager. Rotate the exposed credential.",
                analysis={
                    "root_cause": "Hardcoded database password in config.py:12",
                    "impact": "Complete database compromise if code is exposed",
                    "data_classification": "CRITICAL",
                    "compliance_impact": ["PCI-DSS", "SOC2", "GDPR"]
                }
            ),
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-2024-003",
                confidence=0.87,
                false_positive_probability=0.08,
                priority_score=0.72,
                remediation_effort=2.0,
                suggested_fix="Use HTML auto-escaping in templates. In Flask/Jinja2, use {{ user_input|e }} or enable autoescaping. For raw HTML, use a sanitization library like Bleach.",
                analysis={
                    "root_cause": "Unescaped user input in HTML output at views.py:78",
                    "impact": "Session hijacking, credential theft, malware distribution",
                    "affected_users": "All users viewing profiles"
                }
            ),
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-2024-004",
                confidence=0.90,
                false_positive_probability=0.03,
                priority_score=0.80,
                remediation_effort=1.0,
                suggested_fix="Enforce HTTPS using Flask-TLS or configure web server to redirect all HTTP to HTTPS. Set HSTS header with long max-age.",
                analysis={
                    "root_cause": "No HTTPS enforcement in main.py:102",
                    "impact": "Man-in-the-middle attacks, credential interception",
                    "compliance_impact": ["PCI-DSS", "HIPAA", "GDPR"]
                }
            )
        ]
        mock_all_agents["analyzer"].analyze_batch.return_value = analyzed_results

        # Mock remediation with successful fixes and MR creation
        remediation_results = [
            AppliedFix(
                vulnerability_id="SECUREAI-2024-001",
                success=True,
                fixed_files=[
                    {
                        "file_path": "app/auth.py",
                        "original_content": "query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''",
                        "fixed_content": "query = 'SELECT * FROM users WHERE username = %s'\ncursor.execute(query, (username,))",
                        "changes_applied": 2,
                        "lines_added": 1,
                        "lines_removed": 1
                    }
                ],
                mr_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/42",
                verification_passed=True,
                fix_pattern_id="SQL_INJECTION_01",
                fix_description="Applied parameterized query pattern"
            ),
            AppliedFix(
                vulnerability_id="SECUREAI-2024-002",
                success=True,
                fixed_files=[
                    {
                        "file_path": "app/config.py",
                        "original_content": "DB_PASSWORD = 'SuperSecret123!'",
                        "fixed_content": "# Credentials moved to environment variables\nimport os\nDB_PASSWORD = os.environ.get('DB_PASSWORD', '')  # Set via environment",
                        "changes_applied": 1,
                        "lines_added": 2,
                        "lines_removed": 1
                    }
                ],
                mr_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/43",
                verification_passed=True,
                fix_pattern_id="SECRET_01",
                fix_description="Removed hardcoded credentials, using environment variables"
            ),
            AppliedFix(
                vulnerability_id="SECUREAI-2024-003",
                success=True,
                fixed_files=[
                    {
                        "file_path": "app/views.py",
                        "original_content": "return f'<div>{user_input}</div>'",
                        "fixed_content": "from markupsafe import escape\n\nreturn f'<div>{escape(user_input)}</div>'",
                        "changes_applied": 1,
                        "lines_added": 1,
                        "lines_removed": 1
                    }
                ],
                mr_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/44",
                verification_passed=True,
                fix_pattern_id="XSS_01",
                fix_description="Applied HTML escaping to user input"
            ),
            AppliedFix(
                vulnerability_id="SECUREAI-2024-004",
                success=True,
                fixed_files=[
                    {
                        "file_path": "app/main.py",
                        "original_content": "app.run(debug=True)",
                        "fixed_content": "from flask_talisman import Talisman\n\nTalisman(app)\napp.run(debug=False)",  # Simplified fix
                        "changes_applied": 1,
                        "lines_added": 2,
                        "lines_removed": 1
                    }
                ],
                mr_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/45",
                verification_passed=True,
                fix_pattern_id="AUTH_01",
                fix_description="Added HTTPS enforcement with Flask-Talisman"
            )
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = remediation_results

        # Mock compliance report
        compliance_report = ComplianceReport(
            project_id="secureai-demo",
            framework_scores={
                "SOX": 95.0,
                "HIPAA": 92.0,
                "GDPR": 94.0,
                "PCI-DSS": 88.0
            },
            overall_score=92.25,
            violations=[
                {
                    "framework_name": "PCI-DSS",
                    "requirement_id": "PCI-DSS-6.5.1",
                    "description": "Injection vulnerabilities",
                    "vulnerability_ids": ["SECUREAI-2024-001"],
                    "severity": "CRITICAL",
                    "remediation_priority": 0.95
                }
            ],
            gaps=[
                {
                    "framework_name": "PCI-DSS",
                    "requirement_id": "PCI-DSS-6.5.1",
                    "description": "Injection vulnerabilities",
                    "violation_count": 1,
                    "risk_level": "HIGH"
                }
            ],
            evidence={
                "security_scans": {
                    "total_vulnerabilities": 4,
                    "by_severity": {
                        "CRITICAL": 1,
                        "HIGH": 2,
                        "MEDIUM": 1,
                        "LOW": 0
                    }
                },
                "remediation_stats": {
                    "total_fixes": 4,
                    "successful": 4,
                    "failed": 0,
                    "success_rate": 1.0
                },
                "historical_trends": {
                    "compliance_score_30d": [85.0, 88.0, 90.0, 92.25],
                    "vulnerability_trend": "decreasing"
                }
            },
            generated_at=datetime.utcnow()
        )
        mock_all_agents["compliance"].generate_compliance_report.return_value = compliance_report

        # Mock monitoring metrics
        monitoring_metrics = SecurityMetrics(
            vulnerabilities_total=4,
            vulnerabilities_critical=1,
            vulnerabilities_high=2,
            vulnerabilities_medium=1,
            vulnerabilities_low=0,
            mttr_hours=2.5,
            remediation_rate_percent=100.0,  # All fixed
            compliance_score_percent=92.25,
            false_positive_rate_percent=3.0,
            scan_coverage_percent=98.0,
            vulnerability_inflow_rate=0.5,
            agent_health_score=100.0
        )
        mock_all_agents["monitoring"].collect_metrics.return_value = monitoring_metrics

        # Mock dashboard data
        mock_all_agents["monitoring"].get_dashboard_data.return_value = {
            "current_metrics": {
                "vulnerabilities_total": 4,
                "vulnerabilities_critical": 1,
                "compliance_score_percent": 92.25
            },
            "posture": {
                "level": "good",
                "score": 85.0,
                "trend": "improving"
            },
            "alerts": {
                "active_alerts": [],
                "critical_count": 0,
                "warning_count": 0
            },
            "trends": {
                "vulnerabilities_total": {"direction": "decreasing", "slope": -0.5},
                "compliance_score_percent": {"direction": "increasing", "slope": 1.2}
            },
            "recommendations": [
                {"area": "compliance", "priority": "HIGH", "action": "Address PCI-DSS violation"},
                {"area": "monitoring", "priority": "MEDIUM", "action": "Maintain scan coverage >95%"}
            ],
            "generated_at": datetime.utcnow()
        }

        # Mock knowledge graph operations
        mock_all_agents["knowledge_graph"].store_vulnerability.return_value = True
        mock_all_agents["knowledge_graph"].store_analysis.return_value = True
        mock_all_agents["knowledge_graph"].store_remediation.return_value = True
        mock_all_agents["knowledge_graph"].store_compliance_report.return_value = True
        mock_all_agents["knowledge_graph"].store_metrics.return_value = True
        mock_all_agents["knowledge_graph"].get_project_context.return_value = MagicMock(
            project_id="secureai-demo",
            total_vulnerabilities=4,
            remediation_rate=1.0
        )

        # Act: Execute full pipeline
        result = await orchestrator.execute_scan_pipeline(
            project_id="secureai-demo",
            branch="main",
            auto_remediate=True,
            vulnerability_filters={"min_severity": "MEDIUM"}
        )

        # Assert: Pipeline completed successfully
        assert result["status"] == "completed"
        assert result["scan_id"] is not None
        assert result["vulnerabilities_found"] == 4
        assert result["vulnerabilities_analyzed"] == 4  # All meet min severity
        assert result["remediations_applied"] == 4  # All auto-remediated
        assert result["compliance_score"] == 92.25

        # Verify all agents called in correct sequence
        mock_all_agents["scanner"].scan.assert_called_once_with(
            project_id="secureai-demo",
            branch="main"
        )
        mock_all_agents["analyzer"].analyze_batch.assert_called_once()
        mock_all_agents["remediation"].remediate_batch.assert_called_once_with(
            vulnerabilities=analyzed_results,
            auto_apply=True
        )
        mock_all_agents["compliance"].generate_compliance_report.assert_called_once()
        mock_all_agents["monitoring"].collect_metrics.assert_called_once()
        mock_all_agents["monitoring"].get_dashboard_data.assert_called_once()

        # Verify knowledge graph storage
        assert mock_all_agents["knowledge_graph"].store_vulnerability.call_count >= 4
        assert mock_all_agents["knowledge_graph"].store_analysis.call_count >= 4
        assert mock_all_agents["knowledge_graph"].store_remediation.call_count >= 4
        assert mock_all_agents["knowledge_graph"].store_compliance_report.call_count >= 1
        assert mock_all_agents["knowledge_graph"].store_metrics.call_count >= 1

        # Verify statistics updated
        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["successful_scans"] == 1
        assert stats["failed_scans"] == 0
        assert stats["total_vulnerabilities_processed"] == 4

    @pytest.mark.asyncio
    async def test_pipeline_with_partial_failures(self, orchestrator, mock_all_agents):
        """Test pipeline resilience when some agents fail."""
        vulnerabilities = [
            Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(
                vulnerability_id="VULN-001",
                confidence=0.9,
                false_positive_probability=0.1,
                priority_score=0.8
            )
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(
                vulnerability_id="VULN-001",
                success=True
            )
        ]

        # Simulate compliance agent failure
        mock_all_agents["compliance"].generate_compliance_report.side_effect = Exception("Database connection error")

        # Pipeline should still complete
        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        assert result["status"] == "completed"
        assert "compliance_score" in result  # May be None or partial

    @pytest.mark.asyncio
    async def test_pipeline_with_no_remediations(self, orchestrator, mock_all_agents):
        """Test pipeline when no vulnerabilities qualify for remediation."""
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="Low Confidence Finding",
                severity=Severity.LOW,
                confidence=0.3  # Below threshold
            )
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(
                vulnerability_id="VULN-001",
                confidence=0.4,
                false_positive_probability=0.6,
                priority_score=0.2
            )
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(
                vulnerability_id="VULN-001",
                success=False,
                error_message="Confidence below threshold"
            )
        ]

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        assert result["status"] == "completed"
        assert result["remediations_applied"] == 0

    @pytest.mark.asyncio
    async def test_pipeline_with_filters(self, orchestrator, mock_all_agents):
        """Test pipeline respects vulnerability filters."""
        vulnerabilities = [
            Vulnerability(id="V1", title="SQLi", severity=Severity.HIGH, cwe_id="CWE-89"),
            Vulnerability(id="V2", title="XSS", severity=Severity.MEDIUM, cwe_id="CWE-79"),
            Vulnerability(id="V3", title="Path Traversal", severity=Severity.HIGH, cwe_id="CWE-22")
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(vulnerability_id=v.id, confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
            for v in vulnerabilities
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id=v.id, success=True) for v in vulnerabilities
        ]

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main",
            vulnerability_filters={"cwe_ids": ["CWE-89", "CWE-22"]}
        )

        # Should only analyze 2 vulnerabilities
        analyzed_call = mock_all_agents["analyzer"].analyze_batch.call_args[0][0]
        assert len(analyzed_call) == 2
        analyzed_ids = [v.id for v in analyzed_call]
        assert "V1" in analyzed_ids
        assert "V2" not in analyzed_ids
        assert "V3" in analyzed_ids

    @pytest.mark.asyncio
    async def test_pipeline_performance_tracking(self, orchestrator, mock_all_agents):
        """Test pipeline tracks performance metrics."""
        vulnerabilities = [
            Vulnerability(id="V1", title="Test", severity=Severity.HIGH)
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(vulnerability_id="V1", confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id="V1", success=True)
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="project-123",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        # Check performance metrics in result
        assert "duration_seconds" in result
        assert result["duration_seconds"] >= 0
        assert "vulnerabilities_per_second" in result

    @pytest.mark.asyncio
    async def test_concurrent_scan_isolation(self, orchestrator, mock_all_agents):
        """Test that concurrent scans on different projects are isolated."""
        # Set up two different project scans
        vulnerabilities_p1 = [Vulnerability(id="V1", title="Project1", severity=Severity.HIGH)]
        vulnerabilities_p2 = [Vulnerability(id="V2", title="Project2", severity=Severity.HIGH)]

        mock_all_agents["scanner"].scan.side_effect = [vulnerabilities_p1, vulnerabilities_p2]
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(vulnerability_id="V1", confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id="V1", success=True)
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="p1",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        # Run two scans concurrently
        task1 = orchestrator.execute_scan_pipeline(project_id="project-1", branch="main")
        task2 = orchestrator.execute_scan_pipeline(project_id="project-2", branch="main")

        results = await asyncio.gather(task1, task2)

        # Both should succeed with correct project IDs
        assert results[0]["status"] == "completed"
        assert results[1]["status"] == "completed"

        # Verify knowledge graph stored with correct project IDs
        kg_calls = mock_all_agents["knowledge_graph"].store_vulnerability.call_args_list
        assert len(kg_calls) >= 2


class TestDataFlowConsistency:
    """Test data consistency across pipeline stages."""

    @pytest.mark.asyncio
    async def test_vulnerability_id_propagation(self, orchestrator, mock_all_agents):
        """Test vulnerability IDs are preserved across all stages."""
        vulnerabilities = [
            Vulnerability(id="SECUREAI-TEST-123", title="Test", severity=Severity.HIGH)
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-TEST-123",
                confidence=0.9,
                false_positive_probability=0.1,
                priority_score=0.8
            )
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id="SECUREAI-TEST-123", success=True)
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="project-123",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        await orchestrator.execute_scan_pipeline(project_id="project-123", branch="main")

        # Verify ID propagated through all stages
        analyzer_call = mock_all_agents["analyzer"].analyze_batch.call_args[0][0]
        assert analyzer_call[0].id == "SECUREAI-TEST-123"

        remediation_call = mock_all_agents["remediation"].remediate_batch.call_args[0][0]
        assert remediation_call[0].id == "SECUREAI-TEST-123"

    @pytest.mark.asyncio
    async def test_project_id_consistency(self, orchestrator, mock_all_agents):
        """Test project ID is consistent across all stages."""
        project_id = "secureai-demo"
        vulnerabilities = [Vulnerability(id="V1", title="Test", severity=Severity.HIGH)]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(vulnerability_id="V1", confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id="V1", success=True)
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id=project_id,
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        await orchestrator.execute_scan_pipeline(project_id=project_id, branch="main")

        # Verify project ID passed to all agents
        mock_all_agents["scanner"].scan.assert_called_with(project_id=project_id, branch="main")

        # Knowledge graph storage should include project ID
        kg_calls = mock_all_agents["knowledge_graph"].store_vulnerability.call_args_list
        for call in kg_calls:
            node = call[0][0]
            assert node.project_id == project_id


class TestErrorRecoveryAndResilience:
    """Test system resilience and error recovery."""

    @pytest.mark.asyncio
    async def test_partial_agent_failure_continues_pipeline(self, orchestrator, mock_all_agents):
        """Test pipeline continues when non-critical agents fail."""
        vulnerabilities = [Vulnerability(id="V1", title="Test", severity=Severity.HIGH)]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(vulnerability_id="V1", confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id="V1", success=True)
        ]

        # Monitoring agent fails
        mock_all_agents["monitoring"].collect_metrics.side_effect = Exception("Monitoring DB error")
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="project-123",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        result = await orchestrator.execute_scan_pipeline(project_id="project-123", branch="main")

        # Should still complete
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_retry_logic_for_transient_failures(self, orchestrator, mock_all_agents):
        """Test retry logic handles transient failures."""
        vulnerabilities = [Vulnerability(id="V1", title="Test", severity=Severity.HIGH)]

        # Scanner fails first time, succeeds second time
        mock_all_agents["scanner"].scan.side_effect = [
            Exception("Temporary network error"),
            vulnerabilities
        ]
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(vulnerability_id="V1", confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id="V1", success=True)
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="project-123",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        # With retry logic, should eventually succeed
        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main",
            retry_attempts=3
        )

        assert result["status"] == "completed"
        assert mock_all_agents["scanner"].scan.call_count == 2

    @pytest.mark.asyncio
    async def test_timeout_handling(self, orchestrator, mock_all_agents):
        """Test timeout handling for long-running operations."""
        vulnerabilities = [Vulnerability(id="V1", title="Test", severity=Severity.HIGH)]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.side_effect = asyncio.TimeoutError("Analysis timeout")
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id="V1", success=True)
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="project-123",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main",
            timeout_seconds=5
        )

        # Should handle timeout gracefully
        assert result["status"] == "completed"
        # Analyzer would have failed, but pipeline continues


class TestPerformanceAndScalability:
    """Test performance characteristics and scalability."""

    @pytest.mark.asyncio
    async def test_large_vulnerability_set(self, orchestrator, mock_all_agents):
        """Test pipeline with large number of vulnerabilities."""
        # Create 100 vulnerabilities
        vulnerabilities = [
            Vulnerability(
                id=f"VULN-{i}",
                title=f"Test Vulnerability {i}",
                severity=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                confidence=0.8
            )
            for i in range(100)
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(
                vulnerability_id=v.id,
                confidence=0.9,
                false_positive_probability=0.1,
                priority_score=0.8
            )
            for v in vulnerabilities
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id=v.id, success=True) for v in vulnerabilities
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="project-123",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        assert result["status"] == "completed"
        assert result["vulnerabilities_found"] == 100
        assert result["vulnerabilities_analyzed"] == 100
        assert result["remediations_applied"] == 100

    @pytest.mark.asyncio
    async def test_batch_processing_efficiency(self, orchestrator, mock_all_agents):
        """Test that batch processing is efficient."""
        vulnerabilities = [
            Vulnerability(id=f"V{i}", title=f"Test {i}", severity=Severity.HIGH)
            for i in range(50)
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities
        mock_all_agents["analyzer"].analyze_batch.return_value = [
            AnalyzedVulnerability(vulnerability_id=v.id, confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
            for v in vulnerabilities
        ]
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(vulnerability_id=v.id, success=True) for v in vulnerabilities
        ]
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="project-123",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        )

        start_time = datetime.utcnow()
        result = await orchestrator.execute_scan_pipeline(project_id="project-123", branch="main")
        end_time = datetime.utcnow()

        duration = (end_time - start_time).total_seconds()

        # Should process 50 vulnerabilities in reasonable time (< 5 seconds in mock)
        assert duration < 5.0
        assert result["vulnerabilities_processed_per_second"] > 10

    @pytest.mark.asyncio
    async def test_memory_usage_constant(self, orchestrator, mock_all_agents):
        """Test memory usage remains constant with increasing vulnerabilities."""
        # This is a simplified test - in real scenario would use memory profiling
        for size in [10, 50, 100]:
            vulnerabilities = [
                Vulnerability(id=f"V{i}", title=f"Test {i}", severity=Severity.HIGH)
                for i in range(size)
            ]

            mock_all_agents["scanner"].scan.return_value = vulnerabilities
            mock_all_agents["analyzer"].analyze_batch.return_value = [
                AnalyzedVulnerability(vulnerability_id=v.id, confidence=0.9, false_positive_probability=0.1, priority_score=0.8)
                for v in vulnerabilities
            ]
            mock_all_agents["remediation"].remediate_batch.return_value = [
                AppliedFix(vulnerability_id=v.id, success=True) for v in vulnerabilities
            ]
            mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
                project_id="project-123",
                framework_scores={},
                overall_score=100.0,
                violations=[],
                gaps=[],
                evidence={},
                generated_at=datetime.utcnow()
            )

            result = await orchestrator.execute_scan_pipeline(project_id="project-123", branch="main")
            assert result["status"] == "completed"


class TestRealWorldScenario:
    """Test realistic scenarios from the blueprint."""

    @pytest.mark.asyncio
    async def test_secureai_demo_project_scan(self, orchestrator, mock_all_agents):
        """Test scanning the SecureAI Demo project as specified in blueprint."""
        # Simulate SecureAI Demo project vulnerabilities
        vulnerabilities = [
            Vulnerability(
                id="SECUREAI-2024-001",
                title="SQL Injection in User Authentication",
                description="The login endpoint at /api/auth/login constructs SQL queries using string concatenation with unsanitized user input. This allows attackers to bypass authentication by injecting SQL code.",
                severity=Severity.CRITICAL,
                source=VulnerabilitySource.SAST,
                file_path="app/auth.py",
                line_number=45,
                code_snippet="query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''",
                cwe_id="CWE-89",
                confidence=0.94,
                scanner_id="bandit-1.7.5"
            ),
            Vulnerability(
                id="SECUREAI-2024-002",
                title="Hardcoded AWS Credentials",
                description="AWS access key and secret key are hardcoded in configuration file. This exposes critical cloud infrastructure credentials.",
                severity=Severity.CRITICAL,
                source=VulnerabilitySource.SECRET_DETECTION,
                file_path="app/aws_config.py",
                line_number=5,
                code_snippet="AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\nAWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
                cwe_id="CWE-798",
                confidence=0.99
            ),
            Vulnerability(
                id="SECUREAI-2024-003",
                title="Command Injection in System Utilities",
                description="User-provided hostname is passed directly to os.system() without validation, allowing arbitrary command execution.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/utils.py",
                line_number=23,
                code_snippet="os.system('ping -c 4 ' + hostname)",
                cwe_id="CWE-78",
                confidence=0.91
            ),
            Vulnerability(
                id="SECUREAI-2024-004",
                title="Insecure Deserialization",
                description="User-supplied pickle data is deserialized without validation, enabling arbitrary code execution attacks.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/serialization.py",
                line_number=34,
                code_snippet="data = pickle.loads(user_data)",
                cwe_id="CWE-502",
                confidence=0.88
            ),
            Vulnerability(
                id="SECUREAI-2024-005",
                title="Path Traversal in File Operations",
                description="User input is used directly in file path without validation, allowing directory traversal attacks.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/files.py",
                line_number=56,
                code_snippet="file_path = '/var/data/uploads/' + filename",
                cwe_id="CWE-22",
                confidence=0.90
            ),
            Vulnerability(
                id="SECUREAI-2024-006",
                title="Cross-Site Scripting (XSS) in User Profile",
                description="User profile data is rendered without HTML escaping, enabling stored XSS attacks.",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                file_path="app/views.py",
                line_number=102,
                code_snippet="<div>{{ user.bio }}</div>",
                cwe_id="CWE-79",
                confidence=0.85
            ),
            Vulnerability(
                id="SECUREAI-2024-007",
                title="Weak Cryptography - MD5 Hashing",
                description="MD5 cryptographic hash is used for password storage, which is vulnerable to rainbow table attacks.",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                file_path="app/auth.py",
                line_number=89,
                code_snippet="password_hash = hashlib.md5(password.encode()).hexdigest()",
                cwe_id="CWE-327",
                confidence=0.92
            ),
            Vulnerability(
                id="SECUREAI-2024-008",
                title="XML External Entity (XXE) Injection",
                description="XML parser is configured to process external entities, allowing XXE attacks.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/xml_processor.py",
                line_number=12,
                code_snippet="parser = etree.XMLParser(resolve_entities=True)",
                cwe_id="CWE-611",
                confidence=0.87
            ),
            Vulnerability(
                id="SECUREAI-2024-009",
                title="Server-Side Request Forgery (SSRF)",
                description="User-provided URL is fetched by server without validation, enabling SSRF attacks.",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                file_path="app/api.py",
                line_number=67,
                code_snippet="response = requests.get(user_url)",
                cwe_id="CWE-918",
                confidence=0.89
            ),
            Vulnerability(
                id="SECUREAI-2024-010",
                title="Missing Rate Limiting",
                description="Authentication endpoint lacks rate limiting, enabling brute force attacks.",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                file_path="app/auth.py",
                line_number=123,
                code_snippet="@app.route('/login', methods=['POST'])\ndef login():\n    # No rate limiting\n    pass",
                cwe_id="CWE-770",
                confidence=0.83
            )
        ]

        mock_all_agents["scanner"].scan.return_value = vulnerabilities

        # Analyzer returns detailed analysis for each
        analyzed_results = [
            AnalyzedVulnerability(
                vulnerability_id=v.id,
                confidence=v.confidence + 0.05,
                false_positive_probability=0.02 if v.severity in [Severity.CRITICAL, Severity.HIGH] else 0.08,
                priority_score=0.95 if v.severity == Severity.CRITICAL else 0.8,
                remediation_effort=1.0 if v.severity == Severity.CRITICAL else 2.0,
                suggested_fix=f"Apply fix pattern for {v.cwe_id}",
                analysis={
                    "root_cause": f"Detailed analysis for {v.title}",
                    "impact": "High impact on security posture",
                    "attack_vector": "Network" if v.severity in [Severity.CRITICAL, Severity.HIGH] else "Local"
                }
            )
            for v in vulnerabilities
        ]
        mock_all_agents["analyzer"].analyze_batch.return_value = analyzed_results

        # All remediations succeed
        mock_all_agents["remediation"].remediate_batch.return_value = [
            AppliedFix(
                vulnerability_id=v.id,
                success=True,
                fixed_files=[{"file_path": v.file_path or "app/unknown.py"}],
                mr_url=f"https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/{i+1}",
                verification_passed=True
            )
            for i, v in enumerate(vulnerabilities)
        ]

        # High compliance score after remediation
        mock_all_agents["compliance"].generate_compliance_report.return_value = ComplianceReport(
            project_id="secureai-demo",
            framework_scores={
                "SOX": 98.0,
                "HIPAA": 96.0,
                "GDPR": 97.0,
                "PCI-DSS": 94.0,
                "ISO27001": 95.0,
                "NIST": 96.0
            },
            overall_score=96.0,
            violations=[],
            gaps=[],
            evidence={
                "security_scans": {
                    "total_vulnerabilities": 10,
                    "by_severity": {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 3, "LOW": 0}
                },
                "remediation_stats": {
                    "total_fixes": 10,
                    "successful": 10,
                    "failed": 0,
                    "success_rate": 1.0
                }
            },
            generated_at=datetime.utcnow()
        )

        # Excellent monitoring metrics after remediation
        mock_all_agents["monitoring"].collect_metrics.return_value = SecurityMetrics(
            vulnerabilities_total=0,  # All fixed
            vulnerabilities_critical=0,
            vulnerabilities_high=0,
            vulnerabilities_medium=0,
            vulnerabilities_low=0,
            mttr_hours=1.5,
            remediation_rate_percent=100.0,
            compliance_score_percent=96.0,
            false_positive_rate_percent=2.0,
            scan_coverage_percent=100.0
        )

        mock_all_agents["monitoring"].get_dashboard_data.return_value = {
            "current_metrics": {
                "vulnerabilities_total": 0,
                "compliance_score_percent": 96.0
            },
            "posture": {
                "level": "excellent",
                "score": 96.0,
                "trend": "improving"
            },
            "alerts": {"active_alerts": []},
            "trends": {},
            "recommendations": [],
            "generated_at": datetime.utcnow()
        }

        mock_all_agents["knowledge_graph"].store_vulnerability.return_value = True
        mock_all_agents["knowledge_graph"].store_analysis.return_value = True
        mock_all_agents["knowledge_graph"].store_remediation.return_value = True
        mock_all_agents["knowledge_graph"].store_compliance_report.return_value = True
        mock_all_agents["knowledge_graph"].store_metrics.return_value = True
        mock_all_agents["knowledge_graph"].get_project_context.return_value = MagicMock(
            project_id="secureai-demo",
            total_vulnerabilities=10,
            remediation_rate=1.0,
            security_posture="excellent"
        )

        # Execute pipeline
        result = await orchestrator.execute_scan_pipeline(
            project_id="secureai-demo",
            branch="main",
            auto_remediate=True
        )

        # Assertions for winning project criteria
        assert result["status"] == "completed"
        assert result["vulnerabilities_found"] == 10
        assert result["vulnerabilities_analyzed"] == 10
        assert result["remediations_applied"] == 10  # All fixed
        assert result["compliance_score"] >= 95.0  # Excellent compliance

        # Verify all critical vulnerabilities were prioritized
        analyzer_call = mock_all_agents["analyzer"].analyze_batch.call_args[0][0]
        assert len(analyzer_call) == 10

        # Verify all were auto-remediated
        remediation_call = mock_all_agents["remediation"].remediate_batch.call_args
        assert remediation_call[1].get("auto_apply") is True

        # Verify knowledge graph stored everything
        assert mock_all_agents["knowledge_graph"].store_vulnerability.call_count >= 10
        assert mock_all_agents["knowledge_graph"].store_analysis.call_count >= 10
        assert mock_all_agents["knowledge_graph"].store_remediation.call_count >= 10

        # Verify statistics
        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["successful_scans"] == 1
        assert stats["total_vulnerabilities_processed"] == 10
        assert stats["success_rate"] == 1.0
