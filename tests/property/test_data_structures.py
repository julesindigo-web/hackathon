"""
Property-based tests for core data structures and algorithms.

Tests invariants, serialization, hash consistency, and edge cases
using Hypothesis to generate random test data.
"""

import pytest
from datetime import datetime, timedelta
from hypothesis import given, strategies as st, assume, settings, HealthCheck
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant
import numpy as np

from core.models import (
    Vulnerability, AnalyzedVulnerability, RemediationPlan,
    ComplianceReport, SecurityMetrics, Alert, MergeRequest
)


# Custom strategies for generating test data

@st.composite
def vulnerability_strategy(draw):
    """Generate random Vulnerability instances."""
    severity_levels = ["low", "medium", "high", "critical", "info"]
    vulnerability_types = [
        "sql_injection", "xss", "csrf", "path_traversal",
        "hardcoded_secret", "vulnerable_dependency", "insecure_configuration"
    ]
    scanner_sources = ["sast", "dast", "dependency", "secret_detection", "container", "coverage"]

    return Vulnerability(
        id=draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')))).replace(" ", "-"),
        title=draw(st.text(min_size=1, max_size=200)),
        description=draw(st.text(min_size=1, max_size=1000)),
        severity=draw(st.sampled_from(severity_levels)),
        vulnerability_type=draw(st.sampled_from(vulnerability_types)),
        cwe_id=draw(st.text(min_size=4, max_size=10)) if draw(st.booleans()) else None,
        file_path=draw(st.text(min_size=1, max_size=500)),
        line_number=draw(st.integers(min_value=1, max_value=100000)),
        scanner_source=draw(st.sampled_from(scanner_sources)),
        project_id=draw(st.integers(min_value=1, max_value=1000000)),
        mr_id=draw(st.integers(min_value=1, max_value=1000000)) if draw(st.booleans()) else None,
        branch=draw(st.text(min_size=1, max_size=100)) if draw(st.booleans()) else None,
        commit_sha=draw(st.text(min_size=7, max_size=40)) if draw(st.booleans()) else None,
        confidence=draw(st.floats(min_value=0.0, max_value=1.0)) if draw(st.booleans()) else None,
        raw_data=draw(st.dictionaries(st.text(), st.text())) if draw(st.booleans()) else None,
        tags=draw(st.lists(st.text(min_size=1, max_size=50), max_size=10)) if draw(st.booleans()) else None,
        remediation_effort=draw(st.sampled_from(["30m", "1h", "2h", "4h", "1d", "2d", "1w"])) if draw(st.booleans()) else None
    )


@st.composite
def analyzed_vulnerability_strategy(draw):
    """Generate random AnalyzedVulnerability instances."""
    vuln = draw(vulnerability_strategy())

    return AnalyzedVulnerability(
        vulnerability_id=vuln.id,
        root_cause=draw(st.text(min_size=10, max_size=1000)),
        exploitability_score=draw(st.floats(min_value=0.0, max_value=10.0)),
        impact_score=draw(st.floats(min_value=0.0, max_value=10.0)),
        false_positive_probability=draw(st.floats(min_value=0.0, max_value=1.0)),
        confidence=draw(st.floats(min_value=0.0, max_value=1.0)),
        priority_score=draw(st.floats(min_value=0.0, max_value=1.0)),
        recommended_fix_pattern=draw(st.text(min_size=1, max_size=100)),
        code_context=draw(st.dictionaries(st.text(), st.text())) if draw(st.booleans()) else None,
        analysis_notes=draw(st.text(min_size=1, max_size=2000)) if draw(st.booleans()) else None,
        analysis_timestamp=draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime.utcnow()))
    )


class TestVulnerabilityProperties:
    """Property-based tests for Vulnerability model."""

    @given(vulnerability=vulnerability_strategy())
    def test_vulnerability_serialization_roundtrip(self, vulnerability):
        """Test that Vulnerability can be serialized and deserialized correctly."""
        # Serialize to dict
        data = vulnerability.model_dump()

        # Deserialize back
        restored = Vulnerability(**data)

        # Should be equal
        assert restored.id == vulnerability.id
        assert restored.title == vulnerability.title
        assert restored.description == vulnerability.description
        assert restored.severity == vulnerability.severity
        assert restored.vulnerability_type == vulnerability.vulnerability_type

    @given(vulnerability=vulnerability_strategy())
    def test_vulnerability_hash_consistency(self, vulnerability):
        """Test that content_hash is deterministic."""
        hash1 = vulnerability.content_hash()
        hash2 = vulnerability.content_hash()

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex

    @given(vuln1=vulnerability_strategy(), vuln2=vulnerability_strategy())
    def test_vulnerability_hash_uniqueness(self, vuln1, vuln2):
        """Test that different vulnerabilities have different hashes (with high probability)."""
        assume(vuln1.id != vuln2.id or vuln1.title != vuln2.title)

        hash1 = vuln1.content_hash()
        hash2 = vuln2.content_hash()

        # With extremely high probability, hashes should differ
        assert hash1 != hash2

    @given(vulnerability=vulnerability_strategy())
    def test_vulnerability_json_encoding(self, vulnerability):
        """Test JSON encoding doesn't raise errors."""
        json_str = vulnerability.model_dump_json()

        assert isinstance(json_str, str)
        assert len(json_str) > 0

    @given(vulnerability=vulnerability_strategy())
    def test_vulnerability_score_bounds(self, vulnerability):
        """Test that confidence (if present) is within [0, 1]."""
        if vulnerability.confidence is not None:
            assert 0.0 <= vulnerability.confidence <= 1.0


class TestAnalyzedVulnerabilityProperties:
    """Property-based tests for AnalyzedVulnerability model."""

    @given(analyzed=analyzed_vulnerability_strategy())
    def test_analyzed_vulnerability_serialization_roundtrip(self, analyzed):
        """Test serialization/deserialization."""
        data = analyzed.model_dump()
        restored = AnalyzedVulnerability(**data)

        assert restored.vulnerability_id == analyzed.vulnerability_id
        assert restored.root_cause == analyzed.root_cause
        assert restored.exploitability_score == analyzed.exploitability_score
        assert restored.impact_score == analyzed.impact_score

    @given(analyzed=analyzed_vulnerability_strategy())
    def test_analyzed_vulnerability_score_bounds(self, analyzed):
        """Test all scores are within valid ranges."""
        assert 0.0 <= analyzed.exploitability_score <= 10.0
        assert 0.0 <= analyzed.impact_score <= 10.0
        assert 0.0 <= analyzed.false_positive_probability <= 1.0
        assert 0.0 <= analyzed.confidence <= 1.0
        assert 0.0 <= analyzed.priority_score <= 1.0

    @given(analyzed=analyzed_vulnerability_strategy())
    def test_analyzed_vulnerability_priority_consistency(self, analyzed):
        """Test priority score is consistent with other scores."""
        # Priority should be higher when exploitability and impact are higher
        # and false positive probability is lower
        if analyzed.exploitability_score > 8.0 and analyzed.impact_score > 8.0:
            assert analyzed.priority_score > 0.7  # Should be high priority

        if analyzed.false_positive_probability < 0.1:
            assert analyzed.priority_score > 0.5  # Should be at least medium


class TestRemediationPlanProperties:
    """Property-based tests for RemediationPlan model."""

    @st.composite
    def remediation_plan_strategy(draw):
        """Generate random RemediationPlan instances."""
        vuln = draw(vulnerability_strategy())

        return RemediationPlan(
            vulnerability_id=vuln.id,
            fix_description=draw(st.text(min_size=10, max_size=500)),
            fix_pattern=draw(st.text(min_size=1, max_size=100)),
            confidence=draw(st.floats(min_value=0.0, max_value=1.0)),
            estimated_effort=draw(st.sampled_from(["30m", "1h", "2h", "4h", "1d", "2d", "1w"])),
            code_changes={
                "file": draw(st.text(min_size=1, max_size=500)),
                "diff": draw(st.text(min_size=1, max_size=5000))
            },
            verification_status=draw(st.sampled_from(["pending", "applied", "verified", "failed", "reverted"])),
            applied_by=draw(st.text(min_size=1, max_size=100)) if draw(st.booleans()) else None,
            applied_at=draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime.utcnow())) if draw(st.booleans()) else None
        )

    @given(plan=remediation_plan_strategy())
    def test_remediation_plan_serialization_roundtrip(self, plan):
        """Test serialization/deserialization."""
        data = plan.model_dump()
        restored = RemediationPlan(**data)

        assert restored.vulnerability_id == plan.vulnerability_id
        assert restored.fix_pattern == plan.fix_pattern
        assert restored.confidence == plan.confidence

    @given(plan=remediation_plan_strategy())
    def test_remediation_plan_confidence_bounds(self, plan):
        """Test confidence is within [0, 1]."""
        assert 0.0 <= plan.confidence <= 1.0


class TestComplianceReportProperties:
    """Property-based tests for ComplianceReport model."""

    @st.composite
    def compliance_report_strategy(draw):
        """Generate random ComplianceReport instances."""
        frameworks = ["sox", "hipaa", "gdpr", "pci_dss", "iso27001", "nist"]

        framework_data = {}
        for framework in draw(st.lists(st.sampled_from(frameworks), min_size=1, max_size=len(frameworks), unique=True)):
            framework_data[framework] = {
                "score": draw(st.floats(min_value=0.0, max_value=100.0)),
                "status": draw(st.sampled_from(["compliant", "non_compliant", "minor_issues", "major_issues", "unknown"])),
                "violations": draw(st.lists(st.text(min_size=1, max_size=200), max_size=20)),
                "requirements_met": draw(st.integers(min_value=0, max_value=100)),
                "requirements_total": draw(st.integers(min_value=1, max_value=100))
            }

        return ComplianceReport(
            project_id=draw(st.integers(min_value=1, max_value=1000000)),
            frameworks=framework_data,
            overall_score=draw(st.floats(min_value=0.0, max_value=100.0)),
            summary=draw(st.text(min_size=1, max_size=2000)),
            generated_at=draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime.utcnow())),
            generated_by=draw(st.text(min_size=1, max_size=100)) if draw(st.booleans()) else None
        )

    @given(report=compliance_report_strategy())
    def test_compliance_report_score_bounds(self, report):
        """Test overall_score is within [0, 100]."""
        assert 0.0 <= report.overall_score <= 100.0

    @given(report=compliance_report_strategy())
    def test_compliance_report_framework_scores_bounds(self, report):
        """Test all framework scores are within [0, 100]."""
        for framework_data in report.frameworks.values():
            assert 0.0 <= framework_data["score"] <= 100.0

    @given(report=compliance_report_strategy())
    def test_compliance_report_requirements_consistency(self, report):
        """Test requirements_met <= requirements_total for each framework."""
        for framework_data in report.frameworks.values():
            met = framework_data.get("requirements_met", 0)
            total = framework_data.get("requirements_total", 1)
            assert 0 <= met <= total


class TestSecurityMetricsProperties:
    """Property-based tests for SecurityMetrics model."""

    @st.composite
    def security_metrics_strategy(draw):
        """Generate random SecurityMetrics instances."""
        # Ensure counts are consistent
        critical = draw(st.integers(min_value=0, max_value=10))
        high = draw(st.integers(min_value=0, max_value=50))
        medium = draw(st.integers(min_value=0, max_value=100))
        low = draw(st.integers(min_value=0, max_value=200))
        total = critical + high + medium + low

        return SecurityMetrics(
            project_id=draw(st.integers(min_value=1, max_value=1000000)),
            timestamp=draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime.utcnow())),
            vulnerabilities_total=total,
            vulnerabilities_critical=critical,
            vulnerabilities_high=high,
            vulnerabilities_medium=medium,
            vulnerabilities_low=low,
            mttr_hours=draw(st.floats(min_value=0.0, max_value=1000.0)),
            remediation_rate=draw(st.floats(min_value=0.0, max_value=1.0)),
            compliance_score=draw(st.floats(min_value=0.0, max_value=100.0)),
            security_posture=draw(st.sampled_from(["excellent", "good", "fair", "poor", "critical"])),
            false_positive_rate=draw(st.floats(min_value=0.0, max_value=1.0)),
            scan_coverage=draw(st.floats(min_value=0.0, max_value=1.0)),
            vulnerability_inflow_rate=draw(st.floats(min_value=0.0, max_value=10.0))
        )

    @given(metrics=security_metrics_strategy())
    def test_security_metrics_count_consistency(self, metrics):
        """Test that severity counts sum to total."""
        total = (metrics.vulnerabilities_critical +
                metrics.vulnerabilities_high +
                metrics.vulnerabilities_medium +
                metrics.vulnerabilities_low)
        assert total == metrics.vulnerabilities_total

    @given(metrics=security_metrics_strategy())
    def test_security_metrics_rate_bounds(self, metrics):
        """Test all rate fields are within [0, 1]."""
        assert 0.0 <= metrics.remediation_rate <= 1.0
        assert 0.0 <= metrics.false_positive_rate <= 1.0
        assert 0.0 <= metrics.scan_coverage <= 1.0
        assert 0.0 <= metrics.vulnerability_inflow_rate <= 10.0  # Can be > 1

    @given(metrics=security_metrics_strategy())
    def test_security_metrics_serialization_roundtrip(self, metrics):
        """Test serialization/deserialization."""
        data = metrics.model_dump()
        restored = SecurityMetrics(**data)

        assert restored.project_id == metrics.project_id
        assert restored.vulnerabilities_total == metrics.vulnerabilities_total
        assert restored.remediation_rate == metrics.remediation_rate


class TestAlertProperties:
    """Property-based tests for Alert model."""

    @st.composite
    def alert_strategy(draw):
        """Generate random Alert instances."""
        return Alert(
            id=draw(st.text(min_size=1, max_size=50)),
            title=draw(st.text(min_size=1, max_size=200)),
            description=draw(st.text(min_size=1, max_size=1000)),
            severity=draw(st.sampled_from(["low", "medium", "high", "critical"])),
            alert_type=draw(st.sampled_from(["vulnerability", "anomaly", "system", "compliance"])),
            triggered_at=draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime.utcnow())),
            metadata=draw(st.dictionaries(st.text(), st.text())) if draw(st.booleans()) else None,
            ttl_minutes=draw(st.integers(min_value=1, max_value=1440)) if draw(st.booleans()) else None
        )

    @given(alert=alert_strategy())
    def test_alert_acknowledge_resolve_cycle(self, alert):
        """Test acknowledge and resolve operations."""
        # Initially not acknowledged or resolved
        assert alert.acknowledged is False
        assert alert.resolved is False

        # Acknowledge
        alert.acknowledge(user="test_user")
        assert alert.acknowledged is True
        assert alert.acknowledged_at is not None
        assert alert.acknowledged_by == "test_user"

        # Resolve
        alert.resolve(user="test_user", resolution="fixed")
        assert alert.resolved is True
        assert alert.resolved_at is not None
        assert alert.resolution == "fixed"

    @given(alert=alert_strategy())
    def test_alert_ttl_expiration(self, alert):
        """Test TTL-based expiration logic."""
        if alert.ttl_minutes is None:
            # No TTL, never expires
            assert alert.is_expired() is False
        else:
            # Check expiration at different times
            now = datetime.utcnow()
            assert alert.is_expired(at=now) is False

            # Expire after TTL
            future = now + timedelta(minutes=alert.ttl_minutes + 1)
            assert alert.is_expired(at=future) is True


class TestMergeRequestProperties:
    """Property-based tests for MergeRequest model."""

    @st.composite
    def merge_request_strategy(draw):
        """Generate random MergeRequest instances."""
        valid_states = ["opened", "closed", "merged", "locked"]

        return MergeRequest(
            id=draw(st.integers(min_value=1, max_value=1000000)),
            project_id=draw(st.integers(min_value=1, max_value=1000000)),
            title=draw(st.text(min_size=1, max_size=200)),
            description=draw(st.text(min_size=1, max_size=5000)),
            state=draw(st.sampled_from(valid_states)),
            author=draw(st.text(min_size=1, max_size=100)),
            web_url=draw(st.text(min_size=1, max_size=500)),
            created_at=draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime.utcnow())),
            updated_at=draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime.utcnow())),
            target_branch=draw(st.text(min_size=1, max_size=100)) if draw(st.booleans()) else None,
            source_branch=draw(st.text(min_size=1, max_size=100)) if draw(st.booleans()) else None,
            labels=draw(st.lists(st.text(min_size=1, max_size=50), max_size=10)) if draw(st.booleans()) else None
        )

    @given(mr=merge_request_strategy())
    def test_merge_request_serialization_roundtrip(self, mr):
        """Test serialization/deserialization."""
        data = mr.model_dump()
        restored = MergeRequest(**data)

        assert restored.id == mr.id
        assert restored.title == mr.title
        assert restored.state == mr.state

    @given(mr=merge_request_strategy())
    def test_merge_request_state_validity(self, mr):
        """Test state is one of valid values."""
        valid_states = ["opened", "closed", "merged", "locked"]
        assert mr.state in valid_states


class TestDataStructureInvariants:
    """Test invariants that should always hold."""

    @given(vuln=vulnerability_strategy())
    def test_vulnerability_id_non_empty(self, vuln):
        """Test vulnerability ID is never empty."""
        assert len(vuln.id) > 0

    @given(analyzed=analyzed_vulnerability_strategy())
    def test_analyzed_vulnerability_has_recommended_fix(self, analyzed):
        """Test analyzed vulnerability always has a recommended fix pattern."""
        assert len(analyzed.recommended_fix_pattern) > 0

    @given(plan=TestRemediationPlanProperties.remediation_plan_strategy())
    def test_remediation_plan_has_code_changes(self, plan):
        """Test remediation plan always has code changes."""
        assert "file" in plan.code_changes
        assert "diff" in plan.code_changes
        assert len(plan.code_changes["file"]) > 0
        assert len(plan.code_changes["diff"]) > 0

    @given(report=TestComplianceReportProperties.compliance_report_strategy())
    def test_compliance_report_has_frameworks(self, report):
        """Test compliance report always has at least one framework."""
        assert len(report.frameworks) > 0

    @given(metrics=TestSecurityMetricsProperties.security_metrics_strategy())
    def test_security_metrics_non_negative_counts(self, metrics):
        """Test all vulnerability counts are non-negative."""
        assert metrics.vulnerabilities_critical >= 0
        assert metrics.vulnerabilities_high >= 0
        assert metrics.vulnerabilities_medium >= 0
        assert metrics.vulnerabilities_low >= 0
        assert metrics.vulnerabilities_total >= 0


class TestEdgeCaseProperties:
    """Test edge cases with extreme values."""

    @given(
        st.text(min_size=1, max_size=1000),
        st.text(min_size=1, max_size=1000),
        st.sampled_from(["high", "critical"])
    )
    def test_vulnerability_with_long_text(self, title, description, severity):
        """Test vulnerability with very long title and description."""
        vuln = Vulnerability(
            id="TEST-LONG",
            title=title,
            description=description,
            severity=severity,
            vulnerability_type="sql_injection",
            file_path="test.py",
            line_number=1,
            scanner_source="sast",
            project_id=1,
            mr_id=1
        )

        # Should not raise errors
        data = vuln.model_dump()
        assert data["title"] == title
        assert data["description"] == description

    @given(
        st.floats(min_value=0.0, max_value=0.0),  # Zero
        st.floats(min_value=1.0, max_value=1.0),  # One
        st.floats(min_value=10.0, max_value=10.0)  # Max
    )
    def test_analyzed_vulnerability_extreme_scores(self, zero, one, max_score):
        """Test with extreme but valid score values."""
        analyzed = AnalyzedVulnerability(
            vulnerability_id="TEST",
            root_cause="Test",
            exploitability_score=max_score,
            impact_score=max_score,
            false_positive_probability=zero,
            confidence=one,
            priority_score=one,
            recommended_fix_pattern="test"
        )

        assert analyzed.exploitability_score == 10.0
        assert analyzed.impact_score == 10.0
        assert analyzed.false_positive_probability == 0.0
        assert analyzed.confidence == 1.0
        assert analyzed.priority_score == 1.0

    @given(
        st.integers(min_value=1, max_value=1),
        st.integers(min_value=999999, max_value=999999)
    )
    def test_vulnerability_boundary_line_numbers(self, min_line, max_line):
        """Test boundary line numbers."""
        for line in [min_line, max_line]:
            vuln = Vulnerability(
                id="TEST",
                title="Test",
                description="Test",
                severity="high",
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=line,
                scanner_source="sast",
                project_id=1,
                mr_id=1
            )
            assert vuln.line_number == line


class TestPerformanceProperties:
    """Test performance-related properties."""

    @settings(max_examples=10, deadline=1000)  # 1 second per example
    @given(st.lists(vulnerability_strategy(), min_size=1, max_size=100))
    def test_batch_serialization_performance(self, vulnerabilities):
        """Test that batch serialization is O(n) and fast."""
        import time

        start = time.time()
        for vuln in vulnerabilities:
            data = vuln.model_dump_json()
            assert len(data) > 0
        elapsed = time.time() - start

        # Should be linear and fast: < 1ms per vulnerability
        assert elapsed < len(vulnerabilities) * 0.001

    @settings(max_examples=10)
    @given(vulnerability=vulnerability_strategy())
    def test_hash_computation_performance(self, vulnerability):
        """Test hash computation is fast (O(1) after first call)."""
        import time

        # First call (may compute)
        start = time.time()
        hash1 = vulnerability.content_hash()
        time1 = time.time() - start

        # Second call (should be cached)
        start = time.time()
        hash2 = vulnerability.content_hash()
        time2 = time.time() - start

        assert hash1 == hash2
        # Cached call should be very fast (< 1ms)
        assert time2 < 0.001


# Stateful test for system consistency

class VulnerabilityStateMachine(RuleBasedStateMachine):
    """State machine to test vulnerability lifecycle consistency."""

    def __init__(self):
        super().__init__()
        self.vulnerabilities = {}
        self.analyses = {}
        self.remediations = {}

    @rule(vulnerability=vulnerability_strategy())
    def add_vulnerability(self, vulnerability):
        """Add a vulnerability to the system."""
        self.vulnerabilities[vulnerability.id] = vulnerability

    @rule(vuln_id=st.text(min_size=1, max_size=50), analysis=analyzed_vulnerability_strategy())
    def analyze_vulnerability(self, vuln_id, analysis):
        """Analyze a vulnerability."""
        assume(vuln_id in self.vulnerabilities)
        analysis.vulnerability_id = vuln_id
        self.analyses[vuln_id] = analysis

    @rule(vuln_id=st.text(min_size=1, max_size=50))
    def remove_vulnerability(self, vuln_id):
        """Remove a vulnerability and its associated data."""
        if vuln_id in self.vulnerabilities:
            del self.vulnerabilities[vuln_id]
        if vuln_id in self.analyses:
            del self.analyses[vuln_id]
        if vuln_id in self.remediations:
            del self.remediations[vuln_id]

    @invariant()
    def consistency_check(self):
        """Check system consistency."""
        # All analyses should reference existing vulnerabilities
        for vuln_id in self.analyses:
            assert vuln_id in self.vulnerabilities

        # All remediations should reference existing vulnerabilities
        for vuln_id in self.remediations:
            assert vuln_id in self.vulnerabilities


TestVulnerabilityStateMachine = VulnerabilityStateMachine.TestCase
