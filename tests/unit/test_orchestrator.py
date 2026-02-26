"""
Comprehensive test suite for SecurityOrchestrator.
Target: 100% coverage of orchestrator.py
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.orchestrator import SecurityOrchestrator
from core.models import Vulnerability, Severity, VulnerabilitySource
from agents.scanner_agent import ScannerAgent
from agents.analyzer_agent import AnalyzerAgent, AnalyzedVulnerability
from agents.remediation_agent import RemediationAgent, AppliedFix
from agents.compliance_agent import ComplianceAgent, ComplianceReport
from agents.monitoring_agent import MonitoringAgent, SecurityMetrics
from agents.knowledge_graph_agent import KnowledgeGraphAgent


@pytest.fixture
def mock_scanner_agent():
    """Create mock ScannerAgent."""
    agent = AsyncMock(spec=ScannerAgent)
    agent.health_check.return_value = {"status": "healthy"}
    agent.get_statistics.return_value = {"scans_completed": 10}
    return agent


@pytest.fixture
def mock_analyzer_agent():
    """Create mock AnalyzerAgent."""
    agent = AsyncMock(spec=AnalyzerAgent)
    agent.health_check.return_value = {"status": "healthy"}
    agent.get_statistics.return_value = {"analyses_completed": 50}
    agent.analyze_batch.return_value = [
        AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.95,
            false_positive_probability=0.05,
            priority_score=0.9,
            remediation_effort=2.0,
            suggested_fix="Use parameterized queries"
        )
    ]
    return agent


@pytest.fixture
def mock_remediation_agent():
    """Create mock RemediationAgent."""
    agent = AsyncMock(spec=RemediationAgent)
    agent.health_check.return_value = {"status": "healthy"}
    agent.get_statistics.return_value = {"fixes_applied": 20}
    agent.remediate_batch.return_value = [
        AppliedFix(
            vulnerability_id="VULN-001",
            success=True,
            fixed_files=[{"file_path": "app/views.py"}],
            mr_url="https://gitlab.com/mr/123",
            verification_passed=True
        )
    ]
    return agent


@pytest.fixture
def mock_compliance_agent():
    """Create mock ComplianceAgent."""
    agent = AsyncMock(spec=ComplianceAgent)
    agent.health_check.return_value = {"status": "healthy"}
    agent.get_statistics.return_value = {"reports_generated": 5}
    agent.generate_compliance_report.return_value = ComplianceReport(
        project_id="project-123",
        framework_scores={"SOX": 95.0, "HIPAA": 90.0},
        overall_score=92.5,
        violations=[],
        gaps=[],
        evidence={},
        generated_at=datetime.utcnow()
    )
    return agent


@pytest.fixture
def mock_monitoring_agent():
    """Create mock MonitoringAgent."""
    agent = AsyncMock(spec=MonitoringAgent)
    agent.health_check.return_value = {"status": "healthy"}
    agent.get_statistics.return_value = {"metrics_collected": 100}
    agent.collect_metrics.return_value = SecurityMetrics(
        vulnerabilities_total=10,
        vulnerabilities_critical=1,
        vulnerabilities_high=2,
        vulnerabilities_medium=3,
        vulnerabilities_low=4,
        mttr_hours=8.0,
        remediation_rate_percent=75.0,
        compliance_score_percent=90.0,
        false_positive_rate_percent=5.0,
        scan_coverage_percent=95.0
    )
    return agent


@pytest.fixture
def mock_knowledge_graph_agent():
    """Create mock KnowledgeGraphAgent."""
    agent = AsyncMock(spec=KnowledgeGraphAgent)
    agent.health_check.return_value = {"status": "healthy"}
    agent.get_statistics.return_value = {"nodes_stored": 100}
    agent.store_vulnerability.return_value = True
    agent.store_analysis.return_value = True
    agent.store_remediation.return_value = True
    agent.store_compliance_report.return_value = True
    agent.store_metrics.return_value = True
    agent.run_maintenance.return_value = {"integrity_ok": True}
    return agent


@pytest.fixture
def orchestrator(
    mock_scanner_agent,
    mock_analyzer_agent,
    mock_remediation_agent,
    mock_compliance_agent,
    mock_monitoring_agent,
    mock_knowledge_graph_agent
):
    """Create SecurityOrchestrator with all mocked agents."""
    return SecurityOrchestrator(
        scanner_agent=mock_scanner_agent,
        analyzer_agent=mock_analyzer_agent,
        remediation_agent=mock_remediation_agent,
        compliance_agent=mock_compliance_agent,
        monitoring_agent=mock_monitoring_agent,
        knowledge_graph_agent=mock_knowledge_graph_agent
    )


class TestSecurityOrchestratorInitialization:
    """Test orchestrator initialization."""

    def test_init_with_all_agents(self, orchestrator):
        """Test successful initialization with all agents."""
        assert orchestrator.scanner_agent is not None
        assert orchestrator.analyzer_agent is not None
        assert orchestrator.remediation_agent is not None
        assert orchestrator.compliance_agent is not None
        assert orchestrator.monitoring_agent is not None
        assert orchestrator.knowledge_graph_agent is not None

    def test_statistics_initialized(self, orchestrator):
        """Test statistics counters initialized to zero."""
        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 0
        assert stats["successful_scans"] == 0
        assert stats["failed_scans"] == 0
        assert stats["total_vulnerabilities_processed"] == 0

    def test_auto_remediate_flag(self, orchestrator):
        """Test auto_remediate flag defaults to False."""
        assert orchestrator.auto_remediate is False


class TestSecurityOrchestratorPipeline:
    """Test complete scan pipeline."""

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_success(self, orchestrator):
        """Test successful execution of full scan pipeline."""
        # Mock vulnerabilities from scanner
        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                confidence=0.9
            ),
            Vulnerability(
                id="VULN-002",
                title="XSS",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                confidence=0.8
            )
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        # Execute pipeline
        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        # Verify pipeline executed
        assert result is not None
        assert "scan_id" in result
        assert result["status"] == "completed"
        assert result["vulnerabilities_found"] == 2
        assert result["vulnerabilities_analyzed"] == 2
        assert result["remediations_applied"] == 1  # Only high priority
        assert result["compliance_score"] == 92.5

        # Verify all agents were called
        orchestrator.scanner_agent.scan.assert_called_once()
        orchestrator.analyzer_agent.analyze_batch.assert_called_once()
        orchestrator.remediation_agent.remediate_batch.assert_called_once()
        orchestrator.compliance_agent.generate_compliance_report.assert_called_once()
        orchestrator.monitoring_agent.collect_metrics.assert_called_once()
        orchestrator.knowledge_graph_agent.store_vulnerability.assert_called()
        orchestrator.knowledge_graph_agent.store_analysis.assert_called()
        orchestrator.knowledge_graph_agent.store_remediation.assert_called()
        orchestrator.knowledge_graph_agent.store_compliance_report.assert_called()
        orchestrator.knowledge_graph_agent.store_metrics.assert_called()

        # Verify statistics updated
        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["successful_scans"] == 1
        assert stats["total_vulnerabilities_processed"] == 2

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_with_auto_remediate(self, orchestrator):
        """Test pipeline with auto_remediate enabled."""
        orchestrator.auto_remediate = True

        vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                confidence=0.9
            )
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        assert result["remediations_applied"] == 1
        # Verify remediation was called with auto_apply=True
        call_kwargs = orchestrator.remediation_agent.remediate_batch.call_args[1]
        assert call_kwargs.get("auto_apply") is True

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_no_vulnerabilities(self, orchestrator):
        """Test pipeline when no vulnerabilities found."""
        orchestrator.scanner_agent.scan.return_value = []

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        assert result["status"] == "completed"
        assert result["vulnerabilities_found"] == 0
        assert result["vulnerabilities_analyzed"] == 0
        assert result["remediations_applied"] == 0

        # Analyzer should not be called
        orchestrator.analyzer_agent.analyze_batch.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_scanner_failure(self, orchestrator):
        """Test pipeline handles scanner failure."""
        orchestrator.scanner_agent.scan.side_effect = Exception("Scanner failed")

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        assert result["status"] == "failed"
        assert "Scanner failed" in result["error"]

        # Statistics should record failure
        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["failed_scans"] == 1

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_analyzer_failure(self, orchestrator):
        """Test pipeline handles analyzer failure."""
        orchestrator.scanner_agent.scan.return_value = [
            Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)
        ]
        orchestrator.analyzer_agent.analyze_batch.side_effect = Exception("Analyzer failed")

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        assert result["status"] == "failed"
        assert "Analyzer failed" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_with_prioritization(self, orchestrator):
        """Test pipeline prioritizes high-severity vulnerabilities."""
        # Mix of severities
        vulnerabilities = [
            Vulnerability(id="VULN-LOW", title="Low", severity=Severity.LOW, confidence=0.5),
            Vulnerability(id="VULN-CRITICAL", title="Critical", severity=Severity.CRITICAL, confidence=0.95),
            Vulnerability(id="VULN-MEDIUM", title="Medium", severity=Severity.MEDIUM, confidence=0.7),
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        # Analyzer returns all analyzed
        analyzed = [
            AnalyzedVulnerability(
                vulnerability_id=v.id,
                confidence=v.confidence or 0.8,
                false_positive_probability=0.1,
                priority_score=1.0 if v.severity == Severity.CRITICAL else 0.5
            )
            for v in vulnerabilities
        ]
        orchestrator.analyzer_agent.analyze_batch.return_value = analyzed

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main",
            prioritize=True
        )

        # Should analyze all (prioritization happens in remediation)
        assert result["vulnerabilities_analyzed"] == 3

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_skips_low_confidence(self, orchestrator):
        """Test pipeline skips low confidence analyses."""
        vulnerabilities = [
            Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH, confidence=0.4)
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        # Analyzer returns low confidence
        analyzed = [
            AnalyzedVulnerability(
                vulnerability_id="VULN-001",
                confidence=0.4,
                false_positive_probability=0.6,
                priority_score=0.3
            )
        ]
        orchestrator.analyzer_agent.analyze_batch.return_value = analyzed

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        # Should not remediate low confidence
        assert result["remediations_applied"] == 0

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_with_custom_filters(self, orchestrator):
        """Test pipeline with custom vulnerability filters."""
        vulnerabilities = [
            Vulnerability(id="VULN-001", title="SQL Injection", severity=Severity.HIGH, cwe_id="CWE-89"),
            Vulnerability(id="VULN-002", title="XSS", severity=Severity.MEDIUM, cwe_id="CWE-79"),
            Vulnerability(id="VULN-003", title="Path Traversal", severity=Severity.HIGH, cwe_id="CWE-22")
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main",
            vulnerability_filters={"cwe_ids": ["CWE-89", "CWE-22"]}  # Only SQLi and Path Traversal
        )

        # Should only analyze filtered vulnerabilities
        analyzed_calls = orchestrator.analyzer_agent.analyze_batch.call_args[0][0]
        assert len(analyzed_calls) == 2  # Only SQLi and Path Traversal
        analyzed_ids = [v.id for v in analyzed_calls]
        assert "VULN-001" in analyzed_ids
        assert "VULN-002" not in analyzed_ids  # XSS filtered out
        assert "VULN-003" in analyzed_ids

    @pytest.mark.asyncio
    async def test_execute_scan_pipeline_knowledge_storage(self, orchestrator):
        """Test that all results are stored in knowledge graph."""
        vulnerabilities = [
            Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        # Verify all storage operations
        orchestrator.knowledge_graph_agent.store_vulnerability.assert_called_once()
        orchestrator.knowledge_graph_agent.store_analysis.assert_called_once()
        orchestrator.knowledge_graph_agent.store_remediation.assert_called_once()
        orchestrator.knowledge_graph_agent.store_compliance_report.assert_called_once()
        orchestrator.knowledge_graph_agent.store_metrics.assert_called_once()


class TestSecurityOrchestratorAgentCoordination:
    """Test agent coordination and error handling."""

    @pytest.mark.asyncio
    async def test_agent_health_checks(self, orchestrator):
        """Test health checks for all agents."""
        health = await orchestrator.health_check()

        assert "overall_status" in health
        assert health["overall_status"] == "healthy"
        assert "agents" in health
        assert len(health["agents"]) == 6

        for agent_name, agent_health in health["agents"].items():
            assert "status" in agent_health
            assert agent_health["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_check_with_degraded_agent(self, orchestrator):
        """Test health check when one agent is degraded."""
        orchestrator.scanner_agent.health_check.return_value = {"status": "degraded"}

        health = await orchestrator.health_check()

        assert health["overall_status"] == "degraded"
        assert health["agents"]["scanner_agent"]["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_agent_failure_graceful_degradation(self, orchestrator):
        """Test graceful degradation when agent fails."""
        vulnerabilities = [Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)]
        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        # Simulate compliance agent failure
        orchestrator.compliance_agent.generate_compliance_report.side_effect = Exception("Compliance DB error")

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main"
        )

        # Pipeline should still complete but mark compliance as failed
        assert result["status"] == "completed"
        assert "compliance_score" in result  # May be None or partial

    @pytest.mark.asyncio
    async def test_parallel_agent_execution(self, orchestrator):
        """Test that agents execute in correct sequence (not parallel)."""
        # Track execution order
        execution_order = []

        def track_call(agent_name):
            async def wrapper(*args, **kwargs):
                execution_order.append(agent_name)
                if agent_name == "scanner":
                    return [Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)]
                elif agent_name == "analyzer":
                    return [AnalyzedVulnerability(
                        vulnerability_id="VULN-001",
                        confidence=0.9,
                        false_positive_probability=0.1,
                        priority_score=0.8
                    )]
                elif agent_name == "remediation":
                    return [AppliedFix(vulnerability_id="VULN-001", success=True)]
                elif agent_name == "compliance":
                    return ComplianceReport(
                        project_id="project-123",
                        framework_scores={},
                        overall_score=100.0,
                        violations=[],
                        gaps=[],
                        evidence={},
                        generated_at=datetime.utcnow()
                    )
                elif agent_name == "monitoring":
                    return SecurityMetrics(
                        vulnerabilities_total=1,
                        vulnerabilities_critical=0,
                        vulnerabilities_high=1,
                        vulnerabilities_medium=0,
                        vulnerabilities_low=0,
                        mttr_hours=0,
                        remediation_rate_percent=100.0,
                        compliance_score_percent=100.0,
                        false_positive_rate_percent=0.0,
                        scan_coverage_percent=100.0
                    )
                elif agent_name == "knowledge_graph":
                    return True
                return None
            return wrapper

        # Mock all agents with tracking
        orchestrator.scanner_agent.scan = track_call("scanner")
        orchestrator.analyzer_agent.analyze_batch = track_call("analyzer")
        orchestrator.remediation_agent.remediate_batch = track_call("remediation")
        orchestrator.compliance_agent.generate_compliance_report = track_call("compliance")
        orchestrator.monitoring_agent.collect_metrics = track_call("monitoring")
        orchestrator.knowledge_graph_agent.store_vulnerability = track_call("knowledge_graph")

        await orchestrator.execute_scan_pipeline(project_id="project-123", branch="main")

        # Verify correct sequence
        expected_order = ["scanner", "analyzer", "remediation", "compliance", "monitoring", "knowledge_graph"]
        assert execution_order == expected_order


class TestSecurityOrchestratorVulnerabilityManagement:
    """Test vulnerability management operations."""

    @pytest.mark.asyncio
    async def test_list_vulnerabilities(self, orchestrator):
        """Test listing vulnerabilities from knowledge graph."""
        vulnerabilities = [
            Vulnerability(id="VULN-001", title="Test 1", severity=Severity.HIGH),
            Vulnerability(id="VULN-002", title="Test 2", severity=Severity.MEDIUM)
        ]

        # Mock knowledge graph query
        orchestrator.knowledge_graph_agent.query_context.return_value = {
            "nodes": [
                MagicMock(
                    node_type="VULNERABILITY",
                    external_id="VULN-001",
                    properties={"title": "Test 1", "severity": "HIGH"}
                ),
                MagicMock(
                    node_type="VULNERABILITY",
                    external_id="VULN-002",
                    properties={"title": "Test 2", "severity": "MEDIUM"}
                )
            ],
            "total": 2
        }

        result = await orchestrator.list_vulnerabilities(
            project_id="project-123",
            severity_filter=[Severity.HIGH]
        )

        assert len(result) == 2
        assert result[0]["id"] == "VULN-001"
        assert result[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_get_vulnerability(self, orchestrator):
        """Test getting single vulnerability."""
        # Mock project context with vulnerability
        context = MagicMock(
            vulnerability_types={},
            total_vulnerabilities=1
        )
        orchestrator.knowledge_graph_agent.get_project_context.return_value = context

        # Mock query to return the vulnerability
        orchestrator.knowledge_graph_agent.query_context.return_value = {
            "nodes": [
                MagicMock(
                    node_type="VULNERABILITY",
                    external_id="VULN-001",
                    properties={
                        "title": "SQL Injection",
                        "description": "Test",
                        "severity": "HIGH",
                        "cwe_id": "CWE-89"
                    }
                )
            ],
            "total": 1
        }

        result = await orchestrator.get_vulnerability("VULN-001", "project-123")

        assert result is not None
        assert result["id"] == "VULN-001"
        assert result["title"] == "SQL Injection"

    @pytest.mark.asyncio
    async def test_get_vulnerability_not_found(self, orchestrator):
        """Test getting non-existent vulnerability."""
        orchestrator.knowledge_graph_agent.get_project_context.return_value = None

        result = await orchestrator.get_vulnerability("NONEXISTENT", "project-123")

        assert result is None

    @pytest.mark.asyncio
    async def test_remediate_vulnerability(self, orchestrator):
        """Test manual vulnerability remediation."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            severity=Severity.HIGH,
            file_path="app/views.py"
        )

        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.95,
            false_positive_probability=0.05,
            priority_score=0.9,
            suggested_fix="Use parameterized queries"
        )

        # Mock remediation
        applied_fix = AppliedFix(
            vulnerability_id="VULN-001",
            success=True,
            fixed_files=[{"file_path": "app/views.py"}],
            mr_url="https://gitlab.com/mr/123"
        )
        orchestrator.remediation_agent.remediate_vulnerability.return_value = applied_fix

        result = await orchestrator.remediate_vulnerability(
            vuln, analyzed, "project-123", "main"
        )

        assert result.success is True
        assert result.vulnerability_id == "VULN-001"
        assert result.mr_url is not None

        orchestrator.remediation_agent.remediate_vulnerability.assert_called_once()

    @pytest.mark.asyncio
    async def test_remediate_vulnerability_failure(self, orchestrator):
        """Test remediation failure handling."""
        vuln = Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)
        analyzed = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.9,
            false_positive_probability=0.1,
            priority_score=0.8
        )

        orchestrator.remediation_agent.remediate_vulnerability.return_value = AppliedFix(
            vulnerability_id="VULN-001",
            success=False,
            error_message="Fix failed"
        )

        result = await orchestrator.remediate_vulnerability(vuln, analyzed, "project-123", "main")

        assert result.success is False
        assert result.error_message == "Fix failed"


class TestSecurityOrchestratorCompliance:
    """Test compliance operations."""

    @pytest.mark.asyncio
    async def test_get_compliance_report(self, orchestrator):
        """Test getting compliance report."""
        vulnerabilities = [
            Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)
        ]

        report = await orchestrator.get_compliance_report(
            project_id="project-123",
            vulnerabilities=vulnerabilities,
            frameworks=["SOX", "HIPAA"]
        )

        assert isinstance(report, ComplianceReport)
        assert report.project_id == "project-123"
        assert "SOX" in report.framework_scores
        assert "HIPAA" in report.framework_scores

        orchestrator.compliance_agent.generate_compliance_report.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_audit_report(self, orchestrator):
        """Test getting full audit report."""
        audit = await orchestrator.get_audit_report("project-123")

        assert "executive_summary" in audit
        assert "framework_details" in audit
        assert "violations" in audit
        assert "recommendations" in audit

        orchestrator.compliance_agent.generate_audit_report.assert_called_once()


class TestSecurityOrchestratorMonitoring:
    """Test monitoring operations."""

    @pytest.mark.asyncio
    async def test_get_dashboard_data(self, orchestrator):
        """Test getting monitoring dashboard."""
        dashboard = await orchestrator.get_dashboard_data("project-123")

        assert "current_metrics" in dashboard
        assert "posture" in dashboard
        assert "alerts" in dashboard
        assert "trends" in dashboard
        assert "recommendations" in dashboard

        orchestrator.monitoring_agent.collect_metrics.assert_called()
        orchestrator.monitoring_agent.get_dashboard_data.assert_called()

    @pytest.mark.asyncio
    async def test_get_active_alerts(self, orchestrator):
        """Test getting active alerts."""
        alerts = await orchestrator.get_active_alerts(severity_filter="CRITICAL")

        assert isinstance(alerts, list)
        orchestrator.monitoring_agent.get_active_alerts.assert_called()

    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, orchestrator):
        """Test acknowledging alert."""
        await orchestrator.acknowledge_alert("alert-123")

        orchestrator.monitoring_agent.acknowledge_alert.assert_called_once_with("alert-123")

    @pytest.mark.asyncio
    async def test_resolve_alert(self, orchestrator):
        """Test resolving alert."""
        await orchestrator.resolve_alert("alert-123")

        orchestrator.monitoring_agent.resolve_alert.assert_called_once_with("alert-123")


class TestSecurityOrchestratorKnowledgeGraph:
    """Test knowledge graph operations."""

    @pytest.mark.asyncio
    async def test_query_knowledge(self, orchestrator):
        """Test querying knowledge graph."""
        results = await orchestrator.query_knowledge(
            query="SQL injection vulnerabilities",
            project_id="project-123",
            node_types=["VULNERABILITY", "ANALYSIS"]
        )

        assert "nodes" in results
        assert "total" in results
        orchestrator.knowledge_graph_agent.query_context.assert_called_once()

    @pytest.mark.asyncio
    async def test_find_similar_vulnerabilities(self, orchestrator):
        """Test finding similar vulnerabilities."""
        similar = await orchestrator.find_similar_vulnerabilities(
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                description="User input not sanitized",
                cwe_id="CWE-89"
            ),
            "project-123",
            threshold=0.7
        )

        assert isinstance(similar, list)
        orchestrator.knowledge_graph_agent.find_similar_vulnerabilities.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_historical_patterns(self, orchestrator):
        """Test getting historical patterns."""
        patterns = await orchestrator.get_historical_patterns(
            vulnerability_type="SQL_INJECTION",
            project_id="project-123"
        )

        assert isinstance(patterns, dict)
        orchestrator.knowledge_graph_agent.get_historical_patterns.assert_called_once()

    @pytest.mark.asyncio
    async def test_estimate_remediation_effort(self, orchestrator):
        """Test estimating remediation effort."""
        effort = await orchestrator.estimate_remediation_effort(
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                cwe_id="CWE-89"
            ),
            "project-123"
        )

        assert "mean_days" in effort
        assert "median_days" in effort
        orchestrator.knowledge_graph_agent.estimate_remediation_effort.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_project_context(self, orchestrator):
        """Test getting project context."""
        context = await orchestrator.get_project_context("project-123")

        assert context is not None
        orchestrator.knowledge_graph_agent.get_project_context.assert_called_once()


class TestSecurityOrchestratorStatistics:
    """Test statistics and reporting."""

    def test_get_statistics(self, orchestrator):
        """Test getting orchestrator statistics."""
        # Simulate some activity
        orchestrator._total_scans = 10
        orchestrator._successful_scans = 9
        orchestrator._failed_scans = 1
        orchestrator._total_vulnerabilities_processed = 100

        stats = orchestrator.get_statistics()

        assert stats["total_scans"] == 10
        assert stats["successful_scans"] == 9
        assert stats["failed_scans"] == 1
        assert stats["total_vulnerabilities_processed"] == 100
        assert stats["success_rate"] == pytest.approx(0.9)

    def test_get_agent_statistics(self, orchestrator):
        """Test getting individual agent statistics."""
        agent_stats = orchestrator.get_agent_statistics()

        assert "scanner_agent" in agent_stats
        assert "analyzer_agent" in agent_stats
        assert "remediation_agent" in agent_stats
        assert "compliance_agent" in agent_stats
        assert "monitoring_agent" in agent_stats
        assert "knowledge_graph_agent" in agent_stats

        # Each agent should have health and stats
        for agent_name, stats in agent_stats.items():
            assert "health" in stats
            assert "statistics" in stats


class TestSecurityOrchestratorMaintenance:
    """Test maintenance operations."""

    @pytest.mark.asyncio
    async def test_run_maintenance(self, orchestrator):
        """Test running maintenance tasks."""
        result = await orchestrator.run_maintenance()

        assert "knowledge_graph" in result
        assert result["knowledge_graph"]["integrity_ok"] is True

        orchestrator.knowledge_graph_agent.run_maintenance.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_maintenance_with_errors(self, orchestrator):
        """Test maintenance handles errors gracefully."""
        orchestrator.knowledge_graph_agent.run_maintenance.side_effect = Exception("Maintenance failed")

        result = await orchestrator.run_maintenance()

        # Should still return partial results
        assert "error" in result or "knowledge_graph" in result


class TestSecurityOrchestratorIntegration:
    """Integration tests with realistic workflows."""

    @pytest.mark.asyncio
    async def test_full_scan_and_remediate_workflow(self, orchestrator):
        """Test complete end-to-end workflow."""
        # Realistic vulnerability set
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
                confidence=0.94,
                discovered_at=datetime.utcnow()
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
                title="Reflected Cross-Site Scripting (XSS)",
                description="User input is rendered without proper escaping, allowing attackers to inject malicious scripts.",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                file_path="app/views.py",
                line_number=78,
                code_snippet="return f'<div>{user_input}</div>'",
                cwe_id="CWE-79",
                confidence=0.85
            )
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        # Analyzer returns detailed analysis
        analyzed = [
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-2024-001",
                confidence=0.98,
                false_positive_probability=0.02,
                priority_score=0.95,
                remediation_effort=1.5,
                suggested_fix="Use parameterized queries with placeholders",
                analysis={
                    "root_cause": "String concatenation in SQL query construction",
                    "attack_vector": "Network",
                    "attack_complexity": "Low",
                    "privileges_required": "None",
                    "user_interaction": "None",
                    "scope": "Unchanged",
                    "impact": "Complete database compromise, data exfiltration, privilege escalation"
                }
            ),
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-2024-002",
                confidence=0.92,
                false_positive_probability=0.05,
                priority_score=0.85,
                remediation_effort=1.0,
                suggested_fix="Move credentials to environment variables or secret manager"
            ),
            AnalyzedVulnerability(
                vulnerability_id="SECUREAI-2024-003",
                confidence=0.88,
                false_positive_probability=0.08,
                priority_score=0.70,
                remediation_effort=2.0,
                suggested_fix="Use HTML escaping or template auto-escaping"
            )
        ]
        orchestrator.analyzer_agent.analyze_batch.return_value = analyzed

        # Remediation results
        applied_fixes = [
            AppliedFix(
                vulnerability_id="SECUREAI-2024-001",
                success=True,
                fixed_files=[{"file_path": "app/auth.py"}],
                mr_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/42",
                verification_passed=True,
                fix_pattern_id="SQL_INJECTION_01"
            ),
            AppliedFix(
                vulnerability_id="SECUREAI-2024-002",
                success=True,
                fixed_files=[{"file_path": "app/config.py"}],
                mr_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/43",
                verification_passed=True,
                fix_pattern_id="SECRET_01"
            ),
            AppliedFix(
                vulnerability_id="SECUREAI-2024-003",
                success=True,
                fixed_files=[{"file_path": "app/views.py"}],
                mr_url="https://gitlab.com/secureai-demo/secureai-platform/-/merge_requests/44",
                verification_passed=True,
                fix_pattern_id="XSS_01"
            )
        ]
        orchestrator.remediation_agent.remediate_batch.return_value = applied_fixes

        # Execute full pipeline
        result = await orchestrator.execute_scan_pipeline(
            project_id="secureai-demo",
            branch="main",
            auto_remediate=True
        )

        # Verify comprehensive result
        assert result["status"] == "completed"
        assert result["scan_id"] is not None
        assert result["vulnerabilities_found"] == 3
        assert result["vulnerabilities_analyzed"] == 3
        assert result["remediations_applied"] == 3  # All high/medium
        assert result["compliance_score"] >= 90.0

        # Verify all knowledge stored
        assert orchestrator.knowledge_graph_agent.store_vulnerability.call_count >= 3
        assert orchestrator.knowledge_graph_agent.store_analysis.call_count >= 3
        assert orchestrator.knowledge_graph_agent.store_remediation.call_count >= 3

        # Verify statistics
        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["successful_scans"] == 1
        assert stats["total_vulnerabilities_processed"] == 3

    @pytest.mark.asyncio
    async def test_scan_with_filters(self, orchestrator):
        """Test scan with vulnerability filters."""
        vulnerabilities = [
            Vulnerability(id="VULN-1", title="SQLi", severity=Severity.HIGH, cwe_id="CWE-89"),
            Vulnerability(id="VULN-2", title="XSS", severity=Severity.MEDIUM, cwe_id="CWE-79"),
            Vulnerability(id="VULN-3", title="Path Traversal", severity=Severity.HIGH, cwe_id="CWE-22")
        ]

        orchestrator.scanner_agent.scan.return_value = vulnerabilities

        result = await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="main",
            vulnerability_filters={
                "cwe_ids": ["CWE-89", "CWE-22"],  # Only SQLi and Path Traversal
                "min_severity": "HIGH"
            }
        )

        # Should filter to 2 vulnerabilities
        analyzed_call = orchestrator.analyzer_agent.analyze_batch.call_args[0][0]
        assert len(analyzed_call) == 2
        analyzed_ids = [v.id for v in analyzed_call]
        assert "VULN-1" in analyzed_ids
        assert "VULN-2" not in analyzed_ids  # XSS filtered by CWE
        assert "VULN-3" in analyzed_ids

    @pytest.mark.asyncio
    async def test_scan_with_custom_branch(self, orchestrator):
        """Test scan on specific branch."""
        await orchestrator.execute_scan_pipeline(
            project_id="project-123",
            branch="feature/security-fixes"
        )

        orchestrator.scanner_agent.scan.assert_called_with(
            project_id="project-123",
            branch="feature/security-fixes"
        )

    @pytest.mark.asyncio
    async def test_statistics_accumulation_across_scans(self, orchestrator):
        """Test statistics accumulate across multiple scans."""
        # First scan
        orchestrator.scanner_agent.scan.return_value = [
            Vulnerability(id="V1", title="Test", severity=Severity.HIGH)
        ]
        await orchestrator.execute_scan_pipeline("project-123", "main")
        orchestrator.reset_mock()

        # Second scan
        orchestrator.scanner_agent.scan.return_value = [
            Vulnerability(id="V2", title="Test", severity=Severity.HIGH)
        ]
        await orchestrator.execute_scan_pipeline("project-123", "main")

        stats = orchestrator.get_statistics()
        assert stats["total_scans"] == 2
        assert stats["successful_scans"] == 2
        assert stats["total_vulnerabilities_processed"] == 2
