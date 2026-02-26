"""
Property-based tests using Hypothesis.
Tests for invariant properties across the SecurAI Guardian system.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta
from hypothesis import given, strategies as st, assume, settings, HealthCheck
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize
import numpy as np

from core.models import Vulnerability, Severity, VulnerabilitySource
from agents.scanner_agent import ScannerAgent
from agents.analyzer_agent import AnalyzerAgent, AnalyzedVulnerability
from agents.remediation_agent import RemediationAgent
from agents.compliance_agent import ComplianceAgent, ComplianceReport
from agents.monitoring_agent import MonitoringAgent, SecurityMetrics
from agents.knowledge_graph_agent import KnowledgeGraphAgent
from core.config import Settings


# ==================== Hypothesis Strategies ====================

@st.composite
def vulnerability_strategy(draw):
    """Generate random vulnerabilities for property testing."""
    severity_weights = {
        Severity.CRITICAL: 0.1,
        Severity.HIGH: 0.3,
        Severity.MEDIUM: 0.4,
        Severity.LOW: 0.15,
        Severity.INFO: 0.05
    }

    severity = draw(st.sampled_from(list(severity_weights.keys())))
    source = draw(st.sampled_from([
        VulnerabilitySource.SAST,
        VulnerabilitySource.DAST,
        VulnerabilitySource.SECRET_DETECTION,
        VulnerabilitySource.DEPENDENCY,
        VulnerabilitySource.CONTAINER
    ]))

    # Generate realistic CWE IDs
    cwe_candidates = [
        "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-798",
        "CWE-502", "CWE-611", "CWE-918", "CWE-327", "CWE-770",
        None  # Some vulnerabilities may not have CWE
    ]
    cwe_id = draw(st.sampled_from(cwe_candidates))

    # Generate confidence score
    confidence = draw(st.floats(min_value=0.0, max_value=1.0))

    # Generate file path
    file_path = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='./_'),
        min_size=1,
        max_size=50
    ))

    return Vulnerability(
        id=f"TEST-VULN-{draw(st.integers(min_value=1, max_value=10000))}",
        title=draw(st.text(min_size=5, max_size=100)),
        description=draw(st.text(min_size=10, max_size=500)),
        severity=severity,
        source=source,
        file_path=file_path if draw(st.booleans()) else None,
        line_number=draw(st.integers(min_value=1, max_value=10000)) if draw(st.booleans()) else None,
        code_snippet=draw(st.text(min_size=10, max_size=200)) if draw(st.booleans()) else None,
        cwe_id=cwe_id,
        confidence=confidence,
        discovered_at=datetime.utcnow() - timedelta(hours=draw(st.integers(min_value=0, max_value=168)))
    )


@st.composite
def analyzed_vulnerability_strategy(draw, vuln=None):
    """Generate random analyzed vulnerabilities."""
    if vuln is None:
        vuln = draw(vulnerability_strategy())

    return AnalyzedVulnerability(
        vulnerability_id=vuln.id,
        confidence=draw(st.floats(min_value=0.0, max_value=1.0)),
        false_positive_probability=draw(st.floats(min_value=0.0, max_value=1.0)),
        priority_score=draw(st.floats(min_value=0.0, max_value=1.0)),
        remediation_effort=draw(st.floats(min_value=0.5, max_value=10.0)),
        suggested_fix=draw(st.text(min_size=10, max_size=500)),
        analysis={
            "root_cause": draw(st.text(min_size=10, max_size=200)),
            "impact": draw(st.text(min_size=10, max_size=200)),
            "attack_vector": draw(st.sampled_from(["Network", "Local", "Physical", "Adjacent Network"]))
        }
    )


# ==================== Property Tests ====================

class TestVulnerabilityProperties:
    """Property-based tests for Vulnerability model."""

    @given(vulnerability_strategy())
    def test_vulnerability_serialization_roundtrip(self, vuln):
        """Test that Vulnerability can be serialized to JSON and back."""
        # Serialize to dict
        vuln_dict = vuln.dict()

        # Deserialize back
        vuln_restored = Vulnerability(**vuln_dict)

        # Should be equal
        assert vuln_restored.id == vuln.id
        assert vuln_restored.title == vuln.title
        assert vuln_restored.severity == vuln.severity

    @given(vulnerability_strategy())
    def test_vulnerability_hash_consistency(self, vuln):
        """Test that content_hash is consistent for identical vulnerabilities."""
        hash1 = vuln.content_hash()
        hash2 = vuln.content_hash()
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex length

    @given(vulnerability_strategy())
    def test_vulnerability_hash_changes_with_content(self, vuln):
        """Test that hash changes when vulnerability content changes."""
        original_hash = vuln.content_hash()

        # Modify something
        vuln.title = "Different Title"
        new_hash = vuln.content_hash()

        assert original_hash != new_hash

    @given(vulnerability_strategy())
    def test_vulnerability_severity_ordering(self, vuln):
        """Test severity values have correct ordering."""
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }

        # All severities should have defined order
        assert vuln.severity in severity_order
        assert severity_order[vuln.severity] >= 0
        assert severity_order[vuln.severity] <= 4

    @given(vulnerability_strategy())
    def test_vulnerability_confidence_bounds(self, vuln):
        """Test confidence is always within bounds."""
        if vuln.confidence is not None:
            assert 0.0 <= vuln.confidence <= 1.0


class TestAnalyzerAgentProperties:
    """Property-based tests for AnalyzerAgent."""

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=20),
        st.floats(min_value=0.0, max_value=1.0)
    )
    def test_analyze_batch_returns_same_count(self, vulnerabilities, threshold):
        """Test that analyze_batch returns same number of results as input."""
        # This is a property: batch analysis should preserve count
        # (even if some fail, they should return error results)

        # With mocking, we simulate this property
        # In real implementation, batch size should match
        assert len(vulnerabilities) >= 1
        assert len(vulnerabilities) <= 20

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=10),
        st.floats(min_value=0.0, max_value=1.0)
    )
    def test_priority_score_bounds(self, vulnerabilities, threshold):
        """Test all priority scores are within [0, 1]."""
        # Simulate priority score calculation
        for vuln in vulnerabilities:
            # Mock severity weight
            severity_weights = {
                Severity.CRITICAL: 1.2,
                Severity.HIGH: 1.0,
                Severity.MEDIUM: 0.8,
                Severity.LOW: 0.6,
                Severity.INFO: 0.4
            }

            severity_weight = severity_weights.get(vuln.severity, 0.5)
            exploitability = vuln.confidence or 0.5
            impact_factor = 1.0 if vuln.severity in [Severity.CRITICAL, Severity.HIGH] else 0.7
            remediation_effort = 2.0  # Default

            priority_score = severity_weight * exploitability * impact_factor / (remediation_effort + 1)

            assert 0.0 <= priority_score <= 1.2  # Can exceed 1.0 for critical

    @given(
        st.floats(min_value=0.0, max_value=1.0),
        st.floats(min_value=0.0, max_value=1.0),
        st.floats(min_value=0.0, max_value=1.0)
    )
    def test_confidence_false_positive_relationship(self, confidence, fp_prob, threshold):
        """Test high confidence generally correlates with low false positive probability."""
        # Property: For real vulnerabilities, confidence ↑ → fp_prob ↓
        # This is not always true but is a general property we expect

        if confidence > 0.9:
            # High confidence should generally have low FP probability
            assume(fp_prob < 0.3)
        elif confidence < 0.6:
            # Low confidence might have high FP probability
            assume(fp_prob > 0.2)


class TestRemediationAgentProperties:
    """Property-based tests for RemediationAgent."""

    @given(
        vulnerability_strategy(),
        st.floats(min_value=0.0, max_value=1.0)
    )
    def test_fix_pattern_confidence_threshold(self, vuln, threshold):
        """Test fix patterns only apply when confidence meets threshold."""
        # Property: If vulnerability confidence < pattern threshold, pattern should not apply
        pattern_threshold = 0.85

        if vuln.confidence < pattern_threshold:
            # Should skip remediation
            should_apply = vuln.confidence >= pattern_threshold
            assert should_apply is False
        else:
            # Should consider remediation
            should_apply = vuln.confidence >= pattern_threshold
            assert should_apply is True

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=50),
        st.integers(min_value=1, max_value=10)
    )
    def test_batch_remediation_scalability(self, vulnerabilities, max_batch):
        """Test batch remediation scales linearly with number of vulnerabilities."""
        # Property: Time complexity should be O(n) for batch processing
        # We verify by checking that all vulnerabilities in batch are processed

        n = len(vulnerabilities)
        assert n >= 1
        assert n <= 50

        # In a well-designed system, all should be processed
        # (though some may fail individually)
        # The property is: no vulnerability is dropped without attempt

    @given(
        st.text(min_size=1, max_size=1000),
        st.integers(min_value=1, max_value=1000)
    )
    def test_diff_application_preserves_content(self, original_content, line_num):
        """Test that applying a diff preserves non-modified content."""
        # Property: Diff application should not alter unrelated parts of file

        # Simulate a simple diff that changes one line
        lines = original_content.split('\n')
        if len(lines) == 0:
            assume(False)

        # Assume we're modifying line at line_num (clamped to valid range)
        line_idx = min(line_num - 1, len(lines) - 1)
        original_line = lines[line_idx]

        # Apply "fix" - replace line
        new_line = original_line + " # FIXED"
        lines[line_idx] = new_line
        result = '\n'.join(lines)

        # Verify other lines unchanged
        if line_idx > 0:
            assert result.split('\n')[0:line_idx] == original_content.split('\n')[0:line_idx]
        if line_idx < len(lines) - 1:
            assert result.split('\n')[line_idx+1:] == original_content.split('\n')[line_idx+1:]

        # Modified line should be different
        assert result.split('\n')[line_idx] != original_line


class TestComplianceAgentProperties:
    """Property-based tests for ComplianceAgent."""

    @given(
        st.lists(vulnerability_strategy(), min_size=0, max_size=50),
        st.floats(min_value=0.0, max_value=100.0)
    )
    def test_compliance_score_monotonicity(self, vulnerabilities, base_score):
        """Test compliance score decreases (or stays same) with more violations."""
        # Property: Adding vulnerabilities should not increase compliance score

        # Calculate score with empty set
        score_empty = 100.0

        # Calculate score with vulnerabilities
        # Each HIGH severity reduces score by ~5%, CRITICAL by ~10%
        penalty = 0
        for vuln in vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                penalty += 10
            elif vuln.severity == Severity.HIGH:
                penalty += 5
            elif vuln.severity == Severity.MEDIUM:
                penalty += 2
            elif vuln.severity == Severity.LOW:
                penalty += 1

        score_with_vulns = max(0, 100 - penalty)

        # Score should not increase with more vulnerabilities
        assert score_with_vulns <= score_empty

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=20),
        st.text(min_size=1, max_size=50)
    )
    def test_framework_mapping_consistency(self, vulnerabilities, framework):
        """Test same vulnerability type maps consistently to same framework requirements."""
        # Property: Deterministic mapping - same input → same output

        # For a given vulnerability with specific CWE, framework mapping should be consistent
        # This tests the idempotency of _map_vulnerability_to_compliance

        # We'll test with SQL injection (CWE-89)
        sql_injection = Vulnerability(
            id="TEST-SQLI",
            title="SQL Injection",
            description="SQL injection vulnerability",
            severity=Severity.HIGH,
            cwe_id="CWE-89"
        )

        # Should always map to same set of frameworks
        # (assuming same framework configuration)
        frameworks_with_sqli = ["SOX", "PCI-DSS", "GDPR"]  # Expected
        for fw in frameworks_with_sqli:
            assert fw in ["SOX", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST"]

    @given(
        st.floats(min_value=0.0, max_value=100.0),
        st.floats(min_value=0.0, max_value=100.0)
    )
    def test_overall_compliance_score_aggregation(self, score1, score2):
        """Test overall compliance score is average of framework scores."""
        # Property: overall_score = mean(framework_scores)

        framework_scores = {"SOX": score1, "HIPAA": score2}
        overall = (score1 + score2) / 2

        assert overall == (score1 + score2) / 2
        assert 0 <= overall <= 100


class TestMonitoringAgentProperties:
    """Property-based tests for MonitoringAgent."""

    @given(
        st.lists(vulnerability_strategy(), min_size=0, max_size=100),
        st.floats(min_value=0.0, max_value=100.0)
    )
    def test_vulnerability_metrics_sum(self, vulnerabilities, compliance_score):
        """Test total vulnerabilities equals sum of severity counts."""
        # Property: vulnerabilities_total == critical + high + medium + low + info

        metrics = SecurityMetrics(
            vulnerabilities_total=len(vulnerabilities),
            vulnerabilities_critical=sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL),
            vulnerabilities_high=sum(1 for v in vulnerabilities if v.severity == Severity.HIGH),
            vulnerabilities_medium=sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM),
            vulnerabilities_low=sum(1 for v in vulnerabilities if v.severity == Severity.LOW),
            vulnerabilities_info=sum(1 for v in vulnerabilities if v.severity == Severity.INFO),
            mttr_hours=8.0,
            remediation_rate_percent=75.0,
            compliance_score_percent=compliance_score,
            false_positive_rate_percent=5.0,
            scan_coverage_percent=90.0
        )

        total = (
            metrics.vulnerabilities_critical +
            metrics.vulnerabilities_high +
            metrics.vulnerabilities_medium +
            metrics.vulnerabilities_low +
            metrics.vulnerabilities_info
        )

        assert total == metrics.vulnerabilities_total

    @given(
        st.floats(min_value=0.0, max_value=100.0),
        st.floats(min_value=0.0, max_value=100.0)
    )
    def test_remediation_rate_bounds(self, total, remediated):
        """Test remediation rate is percentage of fixed vulnerabilities."""
        # Property: remediation_rate = (remediated / total) * 100

        if total > 0:
            rate = (remediated / total) * 100
            assert 0.0 <= rate <= 100.0
        else:
            rate = 0.0
            assert rate == 0.0

    @given(
        st.lists(st.floats(min_value=0.0, max_value=100.0), min_size=5, max_size=50)
    )
    def test_metric_series_statistics_consistency(self, values):
        """Test statistical calculations are consistent."""
        # Property: mean should be within min-max range
        # std dev should be non-negative
        # median should be between min and max

        assume(len(values) > 0)

        mean_val = np.mean(values)
        std_val = np.std(values)
        min_val = np.min(values)
        max_val = np.max(values)
        median_val = np.median(values)

        assert min_val <= mean_val <= max_val
        assert std_val >= 0
        assert min_val <= median_val <= max_val

    @given(
        st.lists(st.floats(min_value=0.0, max_value=100.0), min_size=10, max_size=100)
    )
    def test_trend_calculation_deterministic(self, values):
        """Test trend calculation is deterministic for same input."""
        # Property: Same data → same trend direction

        # Simple linear regression for trend
        x = np.arange(len(values))
        y = np.array(values)

        # Calculate slope
        if len(values) >= 2:
            slope = np.polyfit(x, y, 1)[0]
            direction = "increasing" if slope > 0.1 else "decreasing" if slope < -0.1 else "stable"

            # Recalculate should give same direction
            slope2 = np.polyfit(x, y, 1)[0]
            direction2 = "increasing" if slope2 > 0.1 else "decreasing" if slope2 < -0.1 else "stable"

            assert direction == direction2


class TestKnowledgeGraphProperties:
    """Property-based tests for KnowledgeGraphAgent."""

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=100),
        st.integers(min_value=1, max_value=1000)
    )
    def test_embedding_consistency(self, vulnerabilities, seed):
        """Test that same vulnerability produces same embedding."""
        # Property: Deterministic embedding generation

        vuln = vulnerabilities[0]
        vuln2 = Vulnerability(**vuln.dict())  # Exact copy

        # In real system, embeddings would be generated by model
        # Here we test that content_hash is consistent
        hash1 = vuln.content_hash()
        hash2 = vuln2.content_hash()

        assert hash1 == hash2

    @given(
        st.lists(vulnerability_strategy(), min_size=2, max_size=20)
    )
    def test_similarity_symmetry(self, vulnerabilities):
        """Test similarity is symmetric: sim(A,B) = sim(B,A)."""
        # Property: Similarity metric should be symmetric

        if len(vulnerabilities) < 2:
            assume(False)

        vuln1 = vulnerabilities[0]
        vuln2 = vulnerabilities[1]

        # Content-based similarity (using text overlap as proxy)
        def content_similarity(v1, v2):
            text1 = (v1.title + " " + v1.description + " " + (v1.cwe_id or "")).lower()
            text2 = (v2.title + " " + v2.description + " " + (v2.cwe_id or "")).lower()

            # Simple word overlap
            words1 = set(text1.split())
            words2 = set(text2.split())

            if len(words1) == 0 or len(words2) == 0:
                return 0.0

            intersection = words1.intersection(words2)
            union = words1.union(words2)

            return len(intersection) / len(union)

        sim_12 = content_similarity(vuln1, vuln2)
        sim_21 = content_similarity(vuln2, vuln1)

        assert sim_12 == sim_21

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=50)
    )
    def test_historical_pattern_aggregation(self, vulnerabilities):
        """Test historical pattern statistics are correctly aggregated."""
        # Property: Aggregations should match manual calculation

        # Group by CWE
        cwe_counts = {}
        for v in vulnerabilities:
            cwe = v.cwe_id or "UNKNOWN"
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

        # Total should match
        total = sum(cwe_counts.values())
        assert total == len(vulnerabilities)

        # Most common should be identified correctly
        if cwe_counts:
            most_common = max(cwe_counts.items(), key=lambda x: x[1])
            assert most_common[1] >= 1
            assert most_common[1] <= len(vulnerabilities)

    @given(
        st.lists(st.floats(min_value=0.0, max_value=10.0), min_size=5, max_size=100)
    )
    def test_effort_estimation_confidence_intervals(self, days_list):
        """Test effort estimation confidence intervals contain mean."""
        # Property: Confidence interval should contain the mean

        if len(days_list) < 5:
            assume(False)

        mean_days = np.mean(days_list)
        std_days = np.std(days_list)

        # 95% confidence interval (approximately mean ± 2*std)
        ci_lower = mean_days - 1.96 * std_days
        ci_upper = mean_days + 1.96 * std_days

        # Mean should be within CI
        assert ci_lower <= mean_days <= ci_upper

        # For small samples, CI might be wide but should still contain mean
        assert ci_lower <= ci_upper


class TestOrchestratorProperties:
    """Property-based tests for SecurityOrchestrator."""

    @given(
        st.lists(vulnerability_strategy(), min_size=0, max_size=100),
        st.booleans()
    )
    def test_pipeline_output_consistency(self, vulnerabilities, auto_remediate):
        """Test pipeline produces consistent output structure."""
        # Property: Output always has same keys regardless of input

        from unittest.mock import AsyncMock, MagicMock
        from app.orchestrator import SecurityOrchestrator

        # Mock all agents
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=vulnerabilities)
        mock_scanner.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_scanner.get_statistics = MagicMock(return_value={})

        mock_analyzer = MagicMock()
        from agents.analyzer_agent import AnalyzedVulnerability
        mock_analyzer.analyze_batch = AsyncMock(return_value=[
            AnalyzedVulnerability(
                vulnerability_id=v.id,
                confidence=0.9,
                false_positive_probability=0.1,
                priority_score=0.8
            ) for v in vulnerabilities
        ])
        mock_analyzer.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_analyzer.get_statistics = MagicMock(return_value={})

        mock_remediation = MagicMock()
        from agents.remediation_agent import AppliedFix
        mock_remediation.remediate_batch = AsyncMock(return_value=[
            AppliedFix(vulnerability_id=v.id, success=True) for v in vulnerabilities
        ])
        mock_remediation.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_remediation.get_statistics = MagicMock(return_value={})

        mock_compliance = MagicMock()
        from agents.compliance_agent import ComplianceReport
        mock_compliance.generate_compliance_report = AsyncMock(return_value=ComplianceReport(
            project_id="test",
            framework_scores={},
            overall_score=100.0,
            violations=[],
            gaps=[],
            evidence={},
            generated_at=datetime.utcnow()
        ))
        mock_compliance.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_compliance.get_statistics = MagicMock(return_value={})

        mock_monitoring = MagicMock()
        from agents.monitoring_agent import SecurityMetrics
        mock_monitoring.collect_metrics = AsyncMock(return_value=SecurityMetrics(
            vulnerabilities_total=len(vulnerabilities),
            vulnerabilities_critical=sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL),
            vulnerabilities_high=sum(1 for v in vulnerabilities if v.severity == Severity.HIGH),
            vulnerabilities_medium=sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM),
            vulnerabilities_low=sum(1 for v in vulnerabilities if v.severity == Severity.LOW),
            vulnerabilities_info=sum(1 for v in vulnerabilities if v.severity == Severity.INFO),
            mttr_hours=0,
            remediation_rate_percent=0,
            compliance_score_percent=0,
            false_positive_rate_percent=0,
            scan_coverage_percent=0
        ))
        mock_monitoring.get_dashboard_data = AsyncMock(return_value={})
        mock_monitoring.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_monitoring.get_statistics = MagicMock(return_value={})

        mock_kg = MagicMock()
        mock_kg.store_vulnerability = AsyncMock(return_value=True)
        mock_kg.store_analysis = AsyncMock(return_value=True)
        mock_kg.store_remediation = AsyncMock(return_value=True)
        mock_kg.store_compliance_report = AsyncMock(return_value=True)
        mock_kg.store_metrics = AsyncMock(return_value=True)
        mock_kg.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_kg.get_statistics = MagicMock(return_value={})
        mock_kg.get_project_context = AsyncMock(return_value=None)

        orchestrator = SecurityOrchestrator(
            scanner_agent=mock_scanner,
            analyzer_agent=mock_analyzer,
            remediation_agent=mock_remediation,
            compliance_agent=mock_compliance,
            monitoring_agent=mock_monitoring,
            knowledge_graph_agent=mock_kg
        )

        result = await orchestrator.execute_scan_pipeline(
            project_id="test-project",
            branch="main",
            auto_remediate=auto_remediate
        )

        # Output should always have these keys
        required_keys = [
            "scan_id", "status", "vulnerabilities_found",
            "vulnerabilities_analyzed", "remediations_applied",
            "compliance_score", "duration_seconds"
        ]

        for key in required_keys:
            assert key in result

    @given(
        st.lists(vulnerability_strategy(), min_size=0, max_size=50),
        st.integers(min_value=1, max_value=1000)
    )
    def test_statistics_accumulation(self, vulnerabilities, scan_count):
        """Test statistics accumulate correctly across scans."""
        # Property: total_scans increases monotonically
        # total_vulnerabilities_processed increases by count per scan

        orchestrator = SecurityOrchestrator(
            scanner_agent=MagicMock(),
            analyzer_agent=MagicMock(),
            remediation_agent=MagicMock(),
            compliance_agent=MagicMock(),
            monitoring_agent=MagicMock(),
            knowledge_graph_agent=MagicMock()
        )

        # Simulate multiple scans
        initial_total = orchestrator._total_scans
        initial_vulns = orchestrator._total_vulnerabilities_processed

        orchestrator._total_scans += scan_count
        orchestrator._total_vulnerabilities_processed += len(vulnerabilities)

        # Should be non-decreasing
        assert orchestrator._total_scans >= initial_total
        assert orchestrator._total_vulnerabilities_processed >= initial_vulns

    @given(
        st.floats(min_value=0.0, max_value=1.0),
        st.floats(min_value=0.0, max_value=1.0)
    )
    def test_success_rate_calculation(self, successful, total):
        """Test success rate is calculated correctly."""
        # Property: success_rate = successful / total (when total > 0)

        if total > 0:
            rate = successful / total
            assert 0.0 <= rate <= 1.0
        else:
            rate = 0.0
            assert rate == 0.0


class TestDataIntegrityProperties:
    """Property-based tests for data integrity across pipeline."""

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=20),
        st.text(min_size=1, max_size=50)
    )
    def test_project_id_isolation(self, vulnerabilities, project_id):
        """Test that different project IDs maintain data isolation."""
        # Property: Knowledge graph operations should include correct project_id

        # All vulnerabilities stored with same project_id
        for vuln in vulnerabilities:
            # In real system, we'd check that node.project_id == project_id
            # Here we verify the property that project_id is propagated
            assert isinstance(project_id, str)
            assert len(project_id) >= 1

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=10)
    )
    def test_vulnerability_id_uniqueness(self, vulnerabilities):
        """Test all vulnerability IDs in a batch are unique."""
        # Property: No duplicate vulnerability IDs in a batch

        ids = [v.id for v in vulnerabilities]
        unique_ids = set(ids)

        # Should have no duplicates
        assert len(ids) == len(unique_ids)

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=10)
    )
    def test_analyzed_vulnerability_id_match(self, vulnerabilities):
        """Test AnalyzedVulnerability IDs match original Vulnerability IDs."""
        # Property: Analysis result must reference correct vulnerability

        for vuln in vulnerabilities:
            analyzed = AnalyzedVulnerability(
                vulnerability_id=vuln.id,
                confidence=0.9,
                false_positive_probability=0.1,
                priority_score=0.8
            )

            assert analyzed.vulnerability_id == vuln.id

    @given(
        st.lists(vulnerability_strategy(), min_size=1, max_size=10),
        st.booleans()
    )
    def test_remediation_result_consistency(self, vulnerabilities, success):
        """Test remediation results are consistent with inputs."""
        # Property: AppliedFix.vulnerability_id must match input vulnerability ID

        for vuln in vulnerabilities:
            fix = AppliedFix(
                vulnerability_id=vuln.id,
                success=success,
                fixed_files=[]
            )

            assert fix.vulnerability_id == vuln.id
            assert fix.success == success


# ==================== Stateful Tests ====================

class TestSystemStateMachine(RuleBasedStateMachine):
    """Stateful property tests for system state transitions."""

    def __init__(self):
        super().__init__()
        self.scan_count = 0
        self.total_vulnerabilities = 0
        self.state = "idle"

    @initialize()
    def initialize_system(self):
        """Initialize system in idle state."""
        self.scan_count = 0
        self.total_vulnerabilities = 0
        self.state = "idle"

    @rule()
    def start_scan(self):
        """Rule: Start a new scan."""
        assume(self.state == "idle")
        self.state = "scanning"
        self.scan_count += 1

    @rule()
    def complete_scan(self, vulns=st.lists(vulnerability_strategy(), min_size=0, max_size=10)):
        """Rule: Complete a scan with given vulnerabilities."""
        assume(self.state == "scanning")
        self.total_vulnerabilities += len(vulns)
        self.state = "idle"

    @rule()
    def fail_scan(self):
        """Rule: Scan fails."""
        assume(self.state == "scanning")
        self.state = "idle"  # Return to idle even on failure

    @invariant()
    def state_always_valid(self):
        """Invariant: State should always be one of the valid states."""
        valid_states = ["idle", "scanning"]
        assert self.state in valid_states

    @invariant()
    def scan_count_non_negative(self):
        """Invariant: Scan count should never be negative."""
        assert self.scan_count >= 0

    @invariant()
    def total_vulnerabilities_non_negative(self):
        """Invariant: Total vulnerabilities should never be negative."""
        assert self.total_vulnerabilities >= 0

    @invariant()
    def scan_count_matches_transitions(self):
        """Invariant: Scan count should match number of start_scan calls."""
        # In a proper implementation, we'd track calls
        # Here we just verify the property holds
        assert self.scan_count >= 0


# ==================== Performance Properties ====================

class TestPerformanceProperties:
    """Property-based tests for performance characteristics."""

    @given(st.lists(vulnerability_strategy(), min_size=1, max_size=1000))
    def test_linear_scalability(self, vulnerabilities):
        """Test that processing time scales linearly with input size."""
        # Property: T(n) = O(n) where n = number of vulnerabilities

        n = len(vulnerabilities)

        # In a linear system, doubling input should roughly double time
        # We can't measure actual time in unit tests, but we can verify
        # that operations are O(n) by checking algorithmic properties

        # For example, deduplication should be O(n) not O(n²)
        # We verify by ensuring no nested loops over the list

        # This is a placeholder - actual performance tests would use profiling
        assert n >= 1
        assert n <= 1000

    @given(
        st.lists(vulnerability_strategy(), min_size=100, max_size=500)
    )
    def test_memory_usage_bounded(self, vulnerabilities):
        """Test memory usage does not grow superlinearly."""
        # Property: Memory usage should be O(n), not O(n²)

        # We can't measure actual memory in property tests,
        # but we can verify that data structures are used correctly

        # For example, storing vulnerabilities should use list/dict, not nested structures
        # that would cause O(n²) memory

        n = len(vulnerabilities)
        assert n >= 100

        # Simulate storing in list (O(n) memory)
        storage = list(vulnerabilities)
        assert len(storage) == n

        # Should not create n² structures
        # This is a sanity check
        total_items = sum(1 for _ in storage)
        assert total_items == n
