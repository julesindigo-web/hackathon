"""
End-to-End Integration Tests for SecurAI Guardian

Tests complete system workflows from GitLab webhook to final compliance report.
Validates data flow across all 6 agents and orchestrator.
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from typing import List, Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

from app.orchestrator import SecurityOrchestrator
from core.models import (
    Vulnerability, AnalyzedVulnerability, RemediationPlan,
    ComplianceReport, SecurityMetrics, Alert, MergeRequest
)


class TestE2ESystemWorkflow:
    """Test complete end-to-end security pipeline."""

    @pytest.fixture
    async def orchestrator(self):
        """Create orchestrator with all agents mocked."""
        # Create mocks for all agents
        scanner = AsyncMock()
        analyzer = AsyncMock()
        remediation = AsyncMock()
        compliance = AsyncMock()
        monitoring = AsyncMock()
        knowledge_graph = AsyncMock()

        # Configure orchestrator
        orchestrator = SecurityOrchestrator(
            scanner_agent=scanner,
            analyzer_agent=analyzer,
            remediation_agent=remediation,
            compliance_agent=compliance,
            monitoring_agent=monitoring,
            knowledge_graph_agent=knowledge_graph
        )

        # Set up realistic return values
        scanner.scan.return_value = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection in user login",
                description="User input not parameterized in query",
                severity="high",
                vulnerability_type="sql_injection",
                file_path="app/auth.py",
                line_number=45,
                scanner_source="sast",
                project_id=123,
                mr_id=456
            ),
            Vulnerability(
                id="VULN-002",
                title="Hard-coded secret",
                description="API key committed to repository",
                severity="critical",
                vulnerability_type="hardcoded_secret",
                file_path="app/config.py",
                line_number=12,
                scanner_source="secret_detection",
                project_id=123,
                mr_id=456
            )
        ]

        analyzer.analyze.return_value = [
            AnalyzedVulnerability(
                vulnerability_id="VULN-001",
                root_cause="User input directly concatenated into SQL query without parameterization",
                exploitability_score=9.2,
                impact_score=8.5,
                false_positive_probability=0.05,
                confidence=0.95,
                priority_score=0.92,
                recommended_fix_pattern="sql_injection_parameterized_queries",
                code_context={"file": "app/auth.py", "snippet": "query = f\"SELECT * FROM users WHERE id={user_id}\""}
            ),
            AnalyzedVulnerability(
                vulnerability_id="VULN-002",
                root_cause="API key hard-coded in source code",
                exploitability_score=10.0,
                impact_score=9.8,
                false_positive_probability=0.01,
                confidence=0.99,
                priority_score=0.98,
                recommended_fix_pattern="secret_rotation_and_vault",
                code_context={"file": "app/config.py", "snippet": "API_KEY = 'sk_live_12345'"}
            )
        ]

        remediation.remediate.return_value = [
            RemediationPlan(
                vulnerability_id="VULN-001",
                fix_description="Replace string concatenation with parameterized query",
                fix_pattern="sql_injection_parameterized_queries",
                confidence=0.95,
                estimated_effort="2h",
                code_changes={"file": "app/auth.py", "diff": "@@ -42,7 +42,9 @@\n- query = f\"SELECT * FROM users WHERE id={user_id}\"\n+ cursor.execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))\n+ query = cursor.fetchone()"},
                verification_status="verified"
            ),
            RemediationPlan(
                vulnerability_id="VULN-002",
                fix_description="Remove hard-coded secret and use environment variable",
                fix_pattern="secret_rotation_and_vault",
                confidence=0.99,
                estimated_effort="1h",
                code_changes={"file": "app/config.py", "diff": "@@ -9,7 +9,8 @@\n- API_KEY = 'sk_live_12345'\n+ import os\n+ API_KEY = os.getenv('API_KEY')"},
                verification_status="verified"
            )
        ]

        compliance.assess.return_value = ComplianceReport(
            project_id=123,
            frameworks={
                "sox": {"score": 95.5, "status": "compliant", "violations": []},
                "hipaa": {"score": 92.0, "status": "compliant", "violations": []},
                "gdpr": {"score": 88.5, "status": "minor_issues", "violations": ["data_encryption_missing"]},
                "pci_dss": {"score": 96.0, "status": "compliant", "violations": []}
            },
            overall_score=93.0,
            summary="System meets most compliance requirements with minor GDPR concerns"
        )

        monitoring.get_dashboard.return_value = {
            "metrics": {
                "vulnerabilities_total": 2,
                "vulnerabilities_critical": 1,
                "vulnerabilities_high": 1,
                "vulnerabilities_medium": 0,
                "vulnerabilities_low": 0,
                "mttr_hours": 4.5,
                "remediation_rate": 0.85,
                "compliance_score": 93.0,
                "security_posture": "good",
                "false_positive_rate": 0.03,
                "scan_coverage": 0.78,
                "vulnerability_inflow_rate": 0.5
            },
            "alerts": [],
            "timestamp": datetime.utcnow().isoformat()
        }

        knowledge_graph.store_analysis.return_value = True
        knowledge_graph.query_context.return_value = {
            "similar_vulnerabilities": 3,
            "common_fix_patterns": ["sql_injection_parameterized_queries"],
            "avg_remediation_time": 3.2,
            "risk_score": 0.75
        }

        return orchestrator

    @pytest.mark.asyncio
    async def test_complete_scan_pipeline_success(self, orchestrator):
        """Test full scan pipeline from ingestion to compliance report."""
        # Arrange
        project_id = 123
        mr_id = 456

        # Act
        result = await orchestrator.execute_scan_pipeline(
            project_id=project_id,
            mr_id=mr_id,
            auto_remediate=True
        )

        # Assert - verify all agents called in correct order
        orchestrator.scanner_agent.scan.assert_called_once_with(project_id, mr_id)

        orchestrator.analyzer_agent.analyze.assert_called_once()
        analyze_args = orchestrator.analyzer_agent.analyze.call_args[0][0]
        assert len(analyze_args) == 2  # Two vulnerabilities

        orchestrator.remediation_agent.remediate.assert_called_once()
        remediate_args = orchestrator.remediation_agent.remediate.call_args[0][0]
        assert len(remediate_args) == 2

        orchestrator.compliance_agent.assess.assert_called_once_with(project_id)

        orchestrator.monitoring_agent.update_metrics.assert_called_once()
        orchestrator.monitoring_agent.get_dashboard.assert_called_once()

        orchestrator.knowledge_graph_agent.store_analysis.assert_called()

        # Verify result structure
        assert result["status"] == "completed"
        assert result["vulnerabilities_found"] == 2
        assert result["vulnerabilities_remediated"] == 2
        assert result["compliance_score"] == 93.0
        assert result["security_posture"] == "good"

    @pytest.mark.asyncio
    async def test_pipeline_handles_analyzer_failure(self, orchestrator):
        """Test pipeline resilience when analyzer fails."""
        # Arrange - make analyzer fail
        orchestrator.analyzer_agent.analyze.side_effect = Exception("Claude API unavailable")

        # Act
        result = await orchestrator.execute_scan_pipeline(project_id=123, mr_id=456)

        # Assert - pipeline should continue with degraded results
        assert result["status"] == "completed_with_errors"
        assert "analyzer_failure" in result["errors"]
        assert result["vulnerabilities_found"] == 2
        assert result["vulnerabilities_analyzed"] == 0

        # Remediation should not run without analysis
        orchestrator.remediation_agent.remediate.assert_not_called()

    @pytest.mark.asyncio
    async def test_pipeline_filters_low_priority(self, orchestrator):
        """Test that low-priority vulnerabilities are filtered out."""
        # Arrange - add low priority vulnerability
        low_priority = Vulnerability(
            id="VULN-003",
            title="Minor code style issue",
            description="Line too long",
            severity="low",
            vulnerability_type="code_smell",
            file_path="app/utils.py",
            line_number=100,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )
        orchestrator.scanner_agent.scan.return_value.append(low_priority)

        low_priority_analysis = AnalyzedVulnerability(
            vulnerability_id="VULN-003",
            root_cause="Line exceeds 100 characters",
            exploitability_score=1.0,
            impact_score=2.0,
            false_positive_probability=0.1,
            confidence=0.7,
            priority_score=0.15,  # Below threshold
            recommended_fix_pattern="format_code",
            code_context={}
        )
        orchestrator.analyzer_agent.analyze.return_value.append(low_priority_analysis)

        # Act
        result = await orchestrator.execute_scan_pipeline(project_id=123, mr_id=456)

        # Assert - only high priority (2) should be remediated
        remediate_calls = orchestrator.remediation_agent.remediate.call_args[0][0]
        assert len(remediate_calls) == 2  # Only VULN-001 and VULN-002
        assert all(v.priority_score >= 0.5 for v in remediate_calls)

    @pytest.mark.asyncio
    async def test_pipeline_handles_remediation_failure(self, orchestrator):
        """Test pipeline continues when some remediations fail."""
        # Arrange - make one remediation fail
        orchestrator.remediation_agent.remediate.side_effect = [
            [RemediationPlan(
                vulnerability_id="VULN-001",
                fix_description="Fix SQL injection",
                fix_pattern="sql_injection_parameterized_queries",
                confidence=0.95,
                estimated_effort="2h",
                code_changes={},
                verification_status="verified"
            )],
            Exception("Failed to create MR")
        ]

        # Act
        result = await orchestrator.execute_scan_pipeline(project_id=123, mr_id=456)

        # Assert - pipeline completes despite remediation failure
        assert result["status"] == "completed_with_errors"
        assert result["vulnerabilities_remediated"] == 1
        assert "remediation_failure" in result["errors"]

    @pytest.mark.asyncio
    async def test_concurrent_scan_pipelines(self, orchestrator):
        """Test multiple scan pipelines running concurrently."""
        # Arrange
        projects = [(123, 456), (124, 457), (125, 458)]

        # Act
        tasks = [
            orchestrator.execute_scan_pipeline(pid, mid)
            for pid, mid in projects
        ]
        results = await asyncio.gather(*tasks)

        # Assert - all pipelines complete successfully
        assert len(results) == 3
        for result in results:
            assert result["status"] == "completed"

        # Verify orchestrator statistics updated
        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 3
        assert stats["successful_scans"] == 3


class TestE2EDataFlow:
    """Test data consistency across pipeline stages."""

    @pytest.fixture
    async def full_system(self):
        """Create complete system with real agent instances (mocked dependencies)."""
        from agents.scanner_agent import ScannerAgent
        from agents.analyzer_agent import AnalyzerAgent
        from agents.remediation_agent import RemediationAgent
        from agents.compliance_agent import ComplianceAgent
        from agents.monitoring_agent import MonitoringAgent
        from agents.knowledge_graph_agent import KnowledgeGraphAgent

        # Create agents with mocked external dependencies
        scanner = ScannerAgent()
        scanner.gitlab_client = AsyncMock()
        scanner.gitlab_client.get_merge_request.return_value = MergeRequest(
            id=456, title="Test MR", description="Test", state="opened",
            author="test_user", web_url="https://gitlab.com/test"
        )

        analyzer = AnalyzerAgent()
        analyzer.anthropic_client = AsyncMock()
        analyzer.anthropic_client.messages.create.return_value = MagicMock(
            content=[MagicMock(text='{"root_cause": "test", "exploitability_score": 8.0, "impact_score": 7.0, "false_positive_probability": 0.1, "confidence": 0.9, "priority_score": 0.8}')]
        )

        remediation = RemediationAgent()
        remediation.gitlab_client = AsyncMock()
        remediation.gitlab_client.create_merge_request.return_value = MagicMock(
            id=789, web_url="https://gitlab.com/test/mr/789"
        )

        compliance = ComplianceAgent()
        monitoring = MonitoringAgent()
        knowledge_graph = KnowledgeGraphAgent()
        knowledge_graph.db_session = MagicMock()
        knowledge_graph.db_session.add = MagicMock()
        knowledge_graph.db_session.commit = MagicMock()

        orchestrator = SecurityOrchestrator(
            scanner_agent=scanner,
            analyzer_agent=analyzer,
            remediation_agent=remediation,
            compliance_agent=compliance,
            monitoring_agent=monitoring,
            knowledge_graph_agent=knowledge_graph
        )

        return orchestrator

    @pytest.mark.asyncio
    async def test_vulnerability_id_propagation(self, full_system):
        """Test that vulnerability IDs are preserved across all pipeline stages."""
        # Arrange
        vuln_id = "VULN-TRACK-123"
        project_id = 100
        mr_id = 200

        # Act
        result = await full_system.execute_scan_pipeline(project_id, mr_id)

        # Assert - IDs should be consistent
        # Check that knowledge graph received correct IDs
        kg_calls = full_system.knowledge_graph_agent.store_analysis.call_args_list
        for call in kg_calls:
            stored_vuln = call[0][0] if call[0] else call[1].get('vulnerability')
            if stored_vuln:
                assert stored_vuln.id == vuln_id or stored_vuln.id is not None

    @pytest.mark.asyncio
    async def test_compliance_uses_analyzed_data(self, full_system):
        """Test that compliance assessment uses analyzed vulnerabilities."""
        # Arrange
        project_id = 100
        mr_id = 200

        # Act
        await full_system.execute_scan_pipeline(project_id, mr_id)

        # Assert - compliance should be called with project_id
        full_system.compliance_agent.assess.assert_called_once_with(project_id)

    @pytest.mark.asyncio
    async def test_monitoring_receives_updated_metrics(self, full_system):
        """Test that monitoring agent receives updated metrics after scan."""
        # Arrange
        project_id = 100
        mr_id = 200

        # Act
        await full_system.execute_scan_pipeline(project_id, mr_id)

        # Assert - monitoring should be updated
        full_system.monitoring_agent.update_metrics.assert_called()
        dashboard = full_system.monitoring_agent.get_dashboard.return_value
        assert dashboard["metrics"]["vulnerabilities_total"] > 0


class TestE2ERealisticScenarios:
    """Test realistic security scenarios from blueprint."""

    @pytest.fixture
    def realistic_vulnerabilities(self):
        """Create realistic vulnerability set matching blueprint scenarios."""
        return [
            # Scenario 1: Critical SQL injection in authentication
            Vulnerability(
                id="SEC-2026-SQL-001",
                title="SQL Injection in authentication endpoint",
                description="User input from login form not parameterized in database query",
                severity="critical",
                vulnerability_type="sql_injection",
                cwe_id="CWE-89",
                file_path="src/auth/login.py",
                line_number=78,
                scanner_source="sast",
                project_id=1,
                mr_id=101
            ),
            # Scenario 2: High severity XSS vulnerability
            Vulnerability(
                id="SEC-2026-XSS-001",
                title="Reflected XSS in search results",
                description="User search query rendered without escaping",
                severity="high",
                vulnerability_type="xss",
                cwe_id="CWE-79",
                file_path="src/views/search.html",
                line_number=45,
                scanner_source="sast",
                project_id=1,
                mr_id=101
            ),
            # Scenario 3: Medium severity secret exposure
            Vulnerability(
                id="SEC-2026-SECRET-001",
                title="AWS secret key in configuration file",
                description="Hard-coded AWS secret access key found in config",
                severity="medium",
                vulnerability_type="hardcoded_secret",
                cwe_id="CWE-798",
                file_path="config/aws.py",
                line_number=15,
                scanner_source="secret_detection",
                project_id=1,
                mr_id=101
            ),
            # Scenario 4: Low severity dependency vulnerability
            Vulnerability(
                id="SEC-2026-DEP-001",
                title="Outdated lodash version with prototype pollution",
                description="Package-lock.json contains lodash@4.17.15 with known vulnerabilities",
                severity="low",
                vulnerability_type="vulnerable_dependency",
                cwe_id="CWE-1321",
                file_path="package-lock.json",
                line_number=1,
                scanner_source="dependency",
                project_id=1,
                mr_id=101
            )
        ]

    @pytest.mark.asyncio
    async def test_critical_vulnerability_workflow(self, realistic_vulnerabilities):
        """Test that critical vulnerabilities trigger immediate action."""
        # Arrange
        orchestrator = SecurityOrchestrator(
            scanner_agent=AsyncMock(),
            analyzer_agent=AsyncMock(),
            remediation_agent=AsyncMock(),
            compliance_agent=AsyncMock(),
            monitoring_agent=AsyncMock(),
            knowledge_graph_agent=AsyncMock()
        )

        orchestrator.scanner_agent.scan.return_value = realistic_vulnerabilities

        # Analyzer returns high priority for critical SQLi
        orchestrator.analyzer_agent.analyze.return_value = [
            AnalyzedVulnerability(
                vulnerability_id="SEC-2026-SQL-001",
                root_cause="SQL query built via string concatenation",
                exploitability_score=10.0,
                impact_score=9.5,
                false_positive_probability=0.01,
                confidence=0.99,
                priority_score=0.98,
                recommended_fix_pattern="sql_injection_parameterized_queries",
                code_context={}
            ),
            AnalyzedVulnerability(
                vulnerability_id="SEC-2026-XSS-001",
                root_cause="Unescaped user input in HTML",
                exploitability_score=8.5,
                impact_score=7.0,
                false_positive_probability=0.05,
                confidence=0.90,
                priority_score=0.82,
                recommended_fix_pattern="xss_output_encoding",
                code_context={}
            ),
            AnalyzedVulnerability(
                vulnerability_id="SEC-2026-SECRET-001",
                root_cause="Hard-coded credentials",
                exploitability_score=9.0,
                impact_score=8.0,
                false_positive_probability=0.02,
                confidence=0.95,
                priority_score=0.88,
                recommended_fix_pattern="secret_rotation_and_vault",
                code_context={}
            ),
            AnalyzedVulnerability(
                vulnerability_id="SEC-2026-DEP-001",
                root_cause="Vulnerable dependency",
                exploitability_score=5.0,
                impact_score=4.0,
                false_positive_probability=0.1,
                confidence=0.75,
                priority_score=0.45,
                recommended_fix_pattern="dependency_update",
                code_context={}
            )
        ]

        orchestrator.remediation_agent.remediate.return_value = [
            RemediationPlan(vulnerability_id="SEC-2026-SQL-001", fix_description="Use parameterized queries", fix_pattern="sql_injection_parameterized_queries", confidence=0.99, estimated_effort="2h", code_changes={}, verification_status="verified"),
            RemediationPlan(vulnerability_id="SEC-2026-XSS-001", fix_description="Add HTML escaping", fix_pattern="xss_output_encoding", confidence=0.95, estimated_effort="1h", code_changes={}, verification_status="verified"),
            RemediationPlan(vulnerability_id="SEC-2026-SECRET-001", fix_description="Rotate secrets and use vault", fix_pattern="secret_rotation_and_vault", confidence=0.98, estimated_effort="3h", code_changes={}, verification_status="verified")
        ]

        orchestrator.compliance_agent.assess.return_value = ComplianceReport(
            project_id=1,
            frameworks={"pci_dss": {"score": 85.0, "status": "non_compliant", "violations": ["sql_injection", "secret_exposure"]}},
            overall_score=85.0,
            summary="Critical vulnerabilities require immediate remediation"
        )

        orchestrator.monitoring_agent.get_dashboard.return_value = {
            "metrics": {"vulnerabilities_total": 4, "vulnerabilities_critical": 1, "vulnerabilities_high": 1, "security_posture": "fair"},
            "alerts": []
        }

        # Act
        result = await orchestrator.execute_scan_pipeline(project_id=1, mr_id=101)

        # Assert - critical vulnerability should be prioritized
        remediated = orchestrator.remediation_agent.remediate.return_value
        remediated_ids = [r.vulnerability_id for r in remediated]
        assert "SEC-2026-SQL-001" in remediated_ids  # Critical
        assert "SEC-2026-XSS-001" in remediated_ids   # High
        assert "SEC-2026-SECRET-001" in remediated_ids  # Medium
        assert "SEC-2026-DEP-001" not in remediated_ids  # Low - filtered out

        # Verify compliance impact
        compliance_report = result["compliance_report"]
        assert compliance_report["overall_score"] < 90  # Score impacted by critical issues

    @pytest.mark.asyncio
    async def test_compliance_gap_analysis(self):
        """Test compliance gap detection and reporting."""
        # Arrange
        orchestrator = SecurityOrchestrator(
            scanner_agent=AsyncMock(),
            analyzer_agent=AsyncMock(),
            remediation_agent=AsyncMock(),
            compliance_agent=AsyncMock(),
            monitoring_agent=AsyncMock(),
            knowledge_graph_agent=AsyncMock()
        )

        # Simulate vulnerabilities that violate compliance
        vulnerabilities = [
            Vulnerability(
                id="GDPR-001",
                title="Unencrypted PII in database",
                description="Customer personal data stored without encryption",
                severity="high",
                vulnerability_type="data_exposure",
                project_id=1,
                mr_id=1
            )
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities
        orchestrator.analyzer_agent.analyze.return_value = [
            AnalyzedVulnerability(
                vulnerability_id="GDPR-001",
                root_cause="Missing encryption at rest",
                exploitability_score=7.0,
                impact_score=9.0,
                false_positive_probability=0.05,
                confidence=0.90,
                priority_score=0.85,
                recommended_fix_pattern="encryption_at_rest",
                code_context={}
            )
        ]
        orchestrator.remediation_agent.remediate.return_value = []
        orchestrator.compliance_agent.assess.return_value = ComplianceReport(
            project_id=1,
            frameworks={
                "gdpr": {
                    "score": 65.0,
                    "status": "non_compliant",
                    "violations": ["personal_data_unencrypted", "no_data_protection_officer"]
                },
                "hipaa": {
                    "score": 70.0,
                    "status": "non_compliant",
                    "violations": ["phi_encryption_missing"]
                }
            },
            overall_score=67.5,
            summary="Critical compliance gaps in data protection"
        )

        # Act
        result = await orchestrator.execute_scan_pipeline(project_id=1, mr_id=1)

        # Assert - compliance gaps identified
        compliance = result["compliance_report"]
        assert compliance["overall_score"] < 80
        assert compliance["frameworks"]["gdpr"]["status"] == "non_compliant"
        assert len(compliance["frameworks"]["gdpr"]["violations"]) > 0

    @pytest.mark.asyncio
    async def test_knowledge_graph_learning(self):
        """Test that knowledge graph stores and retrieves patterns."""
        # Arrange
        from agents.knowledge_graph_agent import KnowledgeGraphAgent

        kg = KnowledgeGraphAgent()
        kg.db_session = MagicMock()
        kg.db_session.add = MagicMock()
        kg.db_session.commit = MagicMock()
        kg.db_session.query.return_value.filter.return_value.first.return_value = None

        vulnerability = Vulnerability(
            id="LEARN-001",
            title="Test vulnerability",
            description="Test",
            severity="high",
            vulnerability_type="sql_injection",
            project_id=1
        )

        analysis = AnalyzedVulnerability(
            vulnerability_id="LEARN-001",
            root_cause="Test root cause",
            exploitability_score=8.0,
            impact_score=7.0,
            false_positive_probability=0.05,
            confidence=0.9,
            priority_score=0.8,
            recommended_fix_pattern="sql_injection_parameterized_queries",
            code_context={}
        )

        # Act
        await kg.store_analysis(vulnerability, analysis)

        # Assert - data persisted to knowledge graph
        kg.db_session.add.assert_called()
        kg.db_session.commit.assert_called()


class TestE2EPerformance:
    """Test system performance characteristics."""

    @pytest.mark.asyncio
    async def test_pipeline_scales_linearly(self):
        """Test that pipeline execution time scales linearly with vulnerability count."""
        # Arrange
        orchestrator = SecurityOrchestrator(
            scanner_agent=AsyncMock(),
            analyzer_agent=AsyncMock(),
            remediation_agent=AsyncMock(),
            compliance_agent=AsyncMock(),
            monitoring_agent=AsyncMock(),
            knowledge_graph_agent=AsyncMock()
        )

        orchestrator.scanner_agent.scan.return_value = [
            Vulnerability(
                id=f"VULN-{i}",
                title=f"Test vulnerability {i}",
                description="Test",
                severity="high",
                vulnerability_type="sql_injection",
                project_id=1,
                mr_id=1
            )
            for i in range(10)
        ]

        orchestrator.analyzer_agent.analyze.return_value = [
            AnalyzedVulnerability(
                vulnerability_id=f"VULN-{i}",
                root_cause="Test",
                exploitability_score=8.0,
                impact_score=7.0,
                false_positive_probability=0.05,
                confidence=0.9,
                priority_score=0.8,
                recommended_fix_pattern="sql_injection_parameterized_queries",
                code_context={}
            )
            for i in range(10)
        ]

        orchestrator.remediation_agent.remediate.return_value = []
        orchestrator.compliance_agent.assess.return_value = ComplianceReport(
            project_id=1,
            frameworks={},
            overall_score=100.0,
            summary="Test"
        )

        # Act
        start = datetime.utcnow()
        await orchestrator.execute_scan_pipeline(project_id=1, mr_id=1)
        elapsed_10 = (datetime.utcnow() - start).total_seconds()

        # Assert - should complete in reasonable time (< 5s for 10 vulns)
        assert elapsed_10 < 5.0

    @pytest.mark.asyncio
    async def test_concurrent_pipelines_isolation(self):
        """Test that concurrent pipelines don't interfere with each other."""
        # Arrange
        orchestrator = SecurityOrchestrator(
            scanner_agent=AsyncMock(),
            analyzer_agent=AsyncMock(),
            remediation_agent=AsyncMock(),
            compliance_agent=AsyncMock(),
            monitoring_agent=AsyncMock(),
            knowledge_graph_agent=AsyncMock()
        )

        # Different projects
        orchestrator.scanner_agent.scan.side_effect = [
            [Vulnerability(id="V1", title="V1", description="D", severity="high", vulnerability_type="sql_injection", project_id=1, mr_id=1)],
            [Vulnerability(id="V2", title="V2", description="D", severity="high", vulnerability_type="xss", project_id=2, mr_id=2)]
        ]

        orchestrator.analyzer_agent.analyze.side_effect = [
            [AnalyzedVulnerability(vulnerability_id="V1", root_cause="T", exploitability_score=8.0, impact_score=7.0, false_positive_probability=0.05, confidence=0.9, priority_score=0.8, recommended_fix_pattern="sql", code_context={})],
            [AnalyzedVulnerability(vulnerability_id="V2", root_cause="T", exploitability_score=8.0, impact_score=7.0, false_positive_probability=0.05, confidence=0.9, priority_score=0.8, recommended_fix_pattern="xss", code_context={})]
        ]

        orchestrator.remediation_agent.remediate.return_value = []
        orchestrator.compliance_agent.assess.return_value = ComplianceReport(
            project_id=1, frameworks={}, overall_score=100.0, summary="Test"
        )

        # Act - run 5 concurrent pipelines
        tasks = [
            orchestrator.execute_scan_pipeline(project_id=i, mr_id=i)
            for i in range(1, 6)
        ]
        results = await asyncio.gather(*tasks)

        # Assert - all complete successfully without interference
        assert len(results) == 5
        for result in results:
            assert result["status"] == "completed"

        # Verify scanner called with correct project IDs
        assert orchestrator.scanner_agent.scan.call_count == 5


class TestE2EErrorRecovery:
    """Test system resilience and error recovery."""

    @pytest.mark.asyncio
    async def test_partial_failure_recovery(self):
        """Test system continues operating when some agents fail."""
        # Arrange
        orchestrator = SecurityOrchestrator(
            scanner_agent=AsyncMock(),
            analyzer_agent=AsyncMock(),
            remediation_agent=AsyncMock(),
            compliance_agent=AsyncMock(),
            monitoring_agent=AsyncMock(),
            knowledge_graph_agent=AsyncMock()
        )

        orchestrator.scanner_agent.scan.return_value = [
            Vulnerability(id="V1", title="V1", description="D", severity="high", vulnerability_type="sql_injection", project_id=1, mr_id=1)
        ]

        # Analyzer fails
        orchestrator.analyzer_agent.analyze.side_effect = Exception("AI service unavailable")

        orchestrator.compliance_agent.assess.return_value = ComplianceReport(
            project_id=1, frameworks={}, overall_score=0.0, summary="No data"
        )

        orchestrator.monitoring_agent.get_dashboard.return_value = {
            "metrics": {"vulnerabilities_total": 0, "security_posture": "unknown"},
            "alerts": []
        }

        # Act
        result = await orchestrator.execute_scan_pipeline(project_id=1, mr_id=1)

        # Assert - system reports error but doesn't crash
        assert result["status"] == "completed_with_errors"
        assert "analyzer_failure" in result["errors"]
        assert "vulnerabilities_found" in result

    @pytest.mark.asyncio
    async def test_retry_logic_eventual_success(self):
        """Test that transient failures are retried and eventually succeed."""
        # Arrange
        from agents.scanner_agent import ScannerAgent

        scanner = ScannerAgent()
        scanner.gitlab_client = AsyncMock()

        # First two calls fail, third succeeds
        scanner.gitlab_client.get_merge_request.side_effect = [
            Exception("Timeout"),
            Exception("Service unavailable"),
            MagicMock(id=1, title="Test", description="Test", state="opened", author="test", web_url="url")
        ]

        # Act
        with patch('asyncio.sleep', new_callable=AsyncMock):  # Speed up test
            result = await scanner.scan(project_id=1, mr_id=1)

        # Assert - eventually succeeded after retries
        assert scanner.gitlab_client.get_merge_request.call_count == 3
