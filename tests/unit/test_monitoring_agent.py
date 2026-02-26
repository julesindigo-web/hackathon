"""
Comprehensive test suite for MonitoringAgent.
Target: 100% coverage of monitoring_agent.py
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from collections import deque

from agents.monitoring_agent import (
    MonitoringAgent, MetricSeries, Alert, AlertSeverity, AlertStatus,
    SecurityMetrics, SecurityPosture, SecurityPostureLevel
)
from core.models import Vulnerability, Severity, VulnerabilitySource
from core.config import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.monitoring_retention_days = 30
    settings.monitoring_alert_ttl_seconds = 3600
    settings.monitoring_collection_interval_seconds = 60
    settings.monitoring_anomaly_threshold = 3.0
    return settings


@pytest.fixture
def mock_knowledge_graph():
    """Create mock knowledge graph."""
    kg = AsyncMock()
    kg.get_metrics_history.return_value = []
    kg.store_metrics.return_value = True
    return kg


@pytest.fixture
def monitoring_agent(mock_settings, mock_knowledge_graph):
    """Create MonitoringAgent instance with mocked dependencies."""
    agent = MonitoringAgent(
        settings=mock_settings,
        knowledge_graph=mock_knowledge_graph
    )
    return agent


class TestMonitoringAgentInitialization:
    """Test MonitoringAgent initialization."""

    def test_init_with_dependencies(self, monitoring_agent):
        """Test successful initialization."""
        assert monitoring_agent.settings is not None
        assert monitoring_agent.knowledge_graph is not None
        assert monitoring_agent.metrics is not None
        assert monitoring_agent.alerts is not None
        assert monitoring_agent._collection_task is None

    def test_metrics_initialized(self, monitoring_agent):
        """Test metrics dictionary initialized."""
        assert isinstance(monitoring_agent.metrics, dict)
        assert len(monitoring_agent.metrics) > 0

        # Check all required metrics exist
        required_metrics = [
            "vulnerabilities_total", "vulnerabilities_critical", "vulnerabilities_high",
            "vulnerabilities_medium", "vulnerabilities_low", "vulnerabilities_info",
            "mttr_hours", "remediation_rate_percent", "compliance_score_percent",
            "security_posture", "false_positive_rate_percent", "scan_coverage_percent",
            "vulnerability_inflow_rate", "agent_health_score"
        ]
        for metric in required_metrics:
            assert metric in monitoring_agent.metrics

    def test_alerts_initialized(self, monitoring_agent):
        """Test alerts dictionary initialized."""
        assert isinstance(monitoring_agent.alerts, dict)
        assert len(monitoring_agent.alerts) > 0

        # Check all required alert types exist
        required_alerts = [
            "critical_vulnerabilities", "compliance_drift", "agent_failure",
            "remediation_stalled", "scan_failure", "posture_degradation"
        ]
        for alert_type in required_alerts:
            assert alert_type in monitoring_agent.alerts


class TestMonitoringAgentMetricSeries:
    """Test MetricSeries functionality."""

    def test_metric_series_init(self):
        """Test MetricSeries initialization."""
        series = MetricSeries("test_metric", max_points=100)
        assert series.name == "test_metric"
        assert series.max_points == 100
        assert len(series.data) == 0
        assert series.current_value is None

    def test_metric_series_add_point(self):
        """Test adding data point to series."""
        series = MetricSeries("test", max_points=10)
        series.add_point(1.0)
        assert len(series.data) == 1
        assert series.current_value == 1.0
        assert series.data[0] == (pytest.approx(datetime.utcnow()), 1.0)

    def test_metric_series_max_points_enforced(self):
        """Test max_points limit is enforced."""
        series = MetricSeries("test", max_points=3)
        series.add_point(1.0)
        series.add_point(2.0)
        series.add_point(3.0)
        series.add_point(4.0)  # Should drop oldest

        assert len(series.data) == 3
        # First point should be 2.0 (1.0 dropped)
        assert series.data[0][1] == pytest.approx(2.0)
        assert series.current_value == 4.0

    def test_metric_series_get_statistics(self):
        """Test statistical calculations."""
        series = MetricSeries("test", max_points=100)
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        for v in values:
            series.add_point(v)

        stats = series.get_statistics()

        assert stats["count"] == 5
        assert stats["mean"] == pytest.approx(3.0)
        assert stats["min"] == 1.0
        assert stats["max"] == 5.0
        assert stats["median"] == 3.0
        assert stats["std_dev"] == pytest.approx(1.414, rel=0.01)

    def test_metric_series_get_statistics_empty(self):
        """Test statistics on empty series."""
        series = MetricSeries("test", max_points=100)
        stats = series.get_statistics()

        assert stats["count"] == 0
        assert stats["mean"] is None
        assert stats["min"] is None
        assert stats["max"] is None

    def test_metric_series_get_trend(self):
        """Test trend calculation."""
        series = MetricSeries("test", max_points=100)
        # Increasing trend
        for i in range(10):
            series.add_point(float(i))

        trend = series.get_trend()
        assert trend["direction"] == "increasing"
        assert trend["slope"] > 0

    def test_metric_series_get_trend_decreasing(self):
        """Test decreasing trend."""
        series = MetricSeries("test", max_points=100)
        # Decreasing trend
        for i in range(10, 0, -1):
            series.add_point(float(i))

        trend = series.get_trend()
        assert trend["direction"] == "decreasing"
        assert trend["slope"] < 0

    def test_metric_series_get_trend_stable(self):
        """Test stable trend."""
        series = MetricSeries("test", max_points=100)
        # Stable values
        for _ in range(10):
            series.add_point(5.0)

        trend = series.get_trend()
        assert trend["direction"] == "stable"
        assert abs(trend["slope"]) < 0.01

    def test_metric_series_clear_old_data(self):
        """Test clearing old data points."""
        series = MetricSeries("test", max_points=100)
        old_time = datetime.utcnow() - timedelta(days=40)
        series.data.append((old_time, 1.0))
        series.data.append((datetime.utcnow(), 2.0))

        series.clear_old_data(retention_days=30)

        assert len(series.data) == 1
        assert series.data[0][1] == 2.0


class TestMonitoringAgentAlerts:
    """Test alert management functionality."""

    def test_create_alert(self, monitoring_agent):
        """Test alert creation."""
        alert = monitoring_agent._create_alert(
            alert_type="critical_vulnerabilities",
            severity=AlertSeverity.CRITICAL,
            title="High Critical Vulnerabilities",
            description="5 critical vulnerabilities detected",
            context={"count": 5}
        )

        assert isinstance(alert, Alert)
        assert alert.alert_type == "critical_vulnerabilities"
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.title == "High Critical Vulnerabilities"
        assert alert.description == "5 critical vulnerabilities detected"
        assert alert.context == {"count": 5}
        assert alert.status == AlertStatus.ACTIVE
        assert alert.created_at is not None

    def test_trigger_alert_new(self, monitoring_agent):
        """Test triggering a new alert."""
        monitoring_agent._trigger_alert(
            alert_type="test_alert",
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            description="Test description"
        )

        assert "test_alert" in monitoring_agent.alerts
        alert = monitoring_agent.alerts["test_alert"]
        assert isinstance(alert, Alert)
        assert alert.status == AlertStatus.ACTIVE

    def test_trigger_alert_updates_existing(self, monitoring_agent):
        """Test triggering alert updates existing one."""
        # Create existing alert
        existing_alert = Alert(
            alert_type="test_alert",
            severity=AlertSeverity.WARNING,
            title="Old Alert",
            description="Old description",
            created_at=datetime.utcnow()
        )
        monitoring_agent.alerts["test_alert"] = existing_alert

        # Trigger new alert with same type
        monitoring_agent._trigger_alert(
            alert_type="test_alert",
            severity=AlertSeverity.CRITICAL,
            title="New Alert",
            description="New description"
        )

        # Should update existing
        alert = monitoring_agent.alerts["test_alert"]
        assert alert.title == "New Alert"
        assert alert.description == "New description"
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.trigger_count > 1

    def test_acknowledge_alert(self, monitoring_agent):
        """Test acknowledging an alert."""
        alert = Alert(
            alert_type="test",
            severity=AlertSeverity.WARNING,
            title="Test",
            description="Test"
        )
        monitoring_agent.alerts["test"] = alert

        monitoring_agent.acknowledge_alert("test")

        assert monitoring_agent.alerts["test"].status == AlertStatus.ACKNOWLEDGED
        assert monitoring_agent.alerts["test"].acknowledged_at is not None

    def test_resolve_alert(self, monitoring_agent):
        """Test resolving an alert."""
        alert = Alert(
            alert_type="test",
            severity=AlertSeverity.WARNING,
            title="Test",
            description="Test"
        )
        monitoring_agent.alerts["test"] = alert

        monitoring_agent.resolve_alert("test")

        assert monitoring_agent.alerts["test"].status == AlertStatus.RESOLVED
        assert monitoring_agent.alerts["test"].resolved_at is not None

    def test_get_active_alerts(self, monitoring_agent):
        """Test getting active alerts."""
        # Create alerts with different statuses
        active_alert = Alert(
            alert_type="active1",
            severity=AlertSeverity.CRITICAL,
            title="Active",
            description="Active alert"
        )
        acked_alert = Alert(
            alert_type="acked1",
            severity=AlertSeverity.WARNING,
            title="Acked",
            description="Acknowledged alert"
        )
        acked_alert.status = AlertStatus.ACKNOWLEDGED

        monitoring_agent.alerts = {"active1": active_alert, "acked1": acked_alert}

        active = monitoring_agent.get_active_alerts()
        assert len(active) == 1
        assert active[0].alert_type == "active1"

    def test_get_active_alerts_by_severity(self, monitoring_agent):
        """Test filtering active alerts by severity."""
        critical_alert = Alert(
            alert_type="critical",
            severity=AlertSeverity.CRITICAL,
            title="Critical",
            description="Critical alert"
        )
        warning_alert = Alert(
            alert_type="warning",
            severity=AlertSeverity.WARNING,
            title="Warning",
            description="Warning alert"
        )

        monitoring_agent.alerts = {"critical": critical_alert, "warning": warning_alert}

        criticals = monitoring_agent.get_active_alerts(severity=AlertSeverity.CRITICAL)
        assert len(criticals) == 1
        assert criticals[0].alert_type == "critical"

    def test_alert_deduplication(self, monitoring_agent):
        """Test similar alerts are deduplicated."""
        # First alert
        monitoring_agent._trigger_alert(
            alert_type="vulnerability_spike",
            severity=AlertSeverity.WARNING,
            title="Vulnerability Spike",
            description="10 new vulnerabilities detected"
        )

        # Similar alert (same type, similar context)
        monitoring_agent._trigger_alert(
            alert_type="vulnerability_spike",
            severity=AlertSeverity.WARNING,
            title="Vulnerability Spike",
            description="12 new vulnerabilities detected"
        )

        # Should have only one alert (updated)
        assert len(monitoring_agent.alerts) == 1
        alert = monitoring_agent.alerts["vulnerability_spike"]
        assert "12 new vulnerabilities" in alert.description

    def test_alert_ttl_expired(self, monitoring_agent):
        """Test expired alerts are auto-resolved."""
        alert = Alert(
            alert_type="old_alert",
            severity=AlertSeverity.WARNING,
            title="Old",
            description="Should expire",
            created_at=datetime.utcnow() - timedelta(seconds=4000)  # 4000 seconds old
        )
        monitoring_agent.alerts["old_alert"] = alert
        monitoring_agent.settings.monitoring_alert_ttl_seconds = 3600

        # Trigger any alert to run cleanup
        monitoring_agent._trigger_alert(
            alert_type="test",
            severity=AlertSeverity.INFO,
            title="Test",
            description="Test"
        )

        # Old alert should be auto-resolved
        assert monitoring_agent.alerts["old_alert"].status == AlertStatus.RESOLVED


class TestMonitoringAgentMetricsCalculation:
    """Test metrics calculation functionality."""

    def test_calculate_vulnerability_metrics(self, monitoring_agent):
        """Test vulnerability metrics calculation."""
        vulnerabilities = [
            Vulnerability(id="1", title="Critical 1", severity=Severity.CRITICAL),
            Vulnerability(id="2", title="Critical 2", severity=Severity.CRITICAL),
            Vulnerability(id="3", title="High 1", severity=Severity.HIGH),
            Vulnerability(id="4", title="High 2", severity=Severity.HIGH),
            Vulnerability(id="5", title="High 3", severity=Severity.HIGH),
            Vulnerability(id="6", title="Medium 1", severity=Severity.MEDIUM),
            Vulnerability(id="7", title="Low 1", severity=Severity.LOW),
            Vulnerability(id="8", title="Info 1", severity=Severity.INFO)
        ]

        metrics = monitoring_agent._calculate_vulnerability_metrics(vulnerabilities)

        assert metrics["vulnerabilities_total"] == 8
        assert metrics["vulnerabilities_critical"] == 2
        assert metrics["vulnerabilities_high"] == 3
        assert metrics["vulnerabilities_medium"] == 1
        assert metrics["vulnerabilities_low"] == 1
        assert metrics["vulnerabilities_info"] == 1

    def test_calculate_vulnerability_metrics_empty(self, monitoring_agent):
        """Test metrics with no vulnerabilities."""
        metrics = monitoring_agent._calculate_vulnerability_metrics([])

        assert metrics["vulnerabilities_total"] == 0
        assert metrics["vulnerabilities_critical"] == 0
        assert metrics["vulnerabilities_high"] == 0
        assert metrics["vulnerabilities_medium"] == 0
        assert metrics["vulnerabilities_low"] == 0
        assert metrics["vulnerabilities_info"] == 0

    def test_calculate_remediation_rate(self, monitoring_agent):
        """Test remediation rate calculation."""
        # Mock metrics history
        monitoring_agent.metrics["vulnerabilities_total"].add_point(100)
        monitoring_agent.metrics["vulnerabilities_total"].add_point(110)

        # Simulate 80 remediated out of 100 total
        rate = monitoring_agent._calculate_remediation_rate(
            total_vulnerabilities=100,
            remediated_vulnerabilities=80
        )

        assert rate == pytest.approx(80.0)

    def test_calculate_remediation_rate_zero_total(self, monitoring_agent):
        """Test remediation rate with zero total."""
        rate = monitoring_agent._calculate_remediation_rate(0, 0)
        assert rate == 0.0

    def test_calculate_false_positive_rate(self, monitoring_agent):
        """Test false positive rate calculation."""
        fpr = monitoring_agent._calculate_false_positive_rate(
            total_findings=100,
            false_positives=10
        )
        assert fpr == pytest.approx(10.0)

    def test_calculate_false_positive_rate_zero_findings(self, monitoring_agent):
        """Test false positive rate with zero findings."""
        fpr = monitoring_agent._calculate_false_positive_rate(0, 0)
        assert fpr == 0.0

    def test_calculate_mttr(self, monitoring_agent):
        """Test MTTR calculation."""
        now = datetime.utcnow()
        discovered = [
            now - timedelta(hours=48),
            now - timedelta(hours=24),
            now - timedelta(hours=12),
            now - timedelta(hours=6)
        ]
        remediated = [
            now - timedelta(hours=24),  # 24h to remediate
            now - timedelta(hours=6),   # 18h to remediate
            now - timedelta(hours=2),   # 10h to remediate
            now                         # 6h to remediate (not yet)
        ]

        mttr = monitoring_agent._calculate_mttr(discovered, remediated)

        # Average of (24+18+10)/3 = 17.33 hours
        assert mttr == pytest.approx(17.33, rel=0.01)

    def test_calculate_mttr_no_remediated(self, monitoring_agent):
        """Test MTTR with no remediated vulnerabilities."""
        now = datetime.utcnow()
        discovered = [now - timedelta(hours=24)]
        remediated = []

        mttr = monitoring_agent._calculate_mttr(discovered, remediated)
        assert mttr == 0.0

    def test_calculate_scan_coverage(self, monitoring_agent):
        """Test scan coverage calculation."""
        coverage = monitoring_agent._calculate_scan_coverage(
            files_scanned=95,
            total_files=100
        )
        assert coverage == pytest.approx(95.0)

    def test_calculate_scan_coverage_zero_total(self, monitoring_agent):
        """Test scan coverage with zero total files."""
        coverage = monitoring_agent._calculate_scan_coverage(0, 0)
        assert coverage == 0.0


class TestMonitoringAgentPostureCalculation:
    """Test security posture calculation."""

    def test_calculate_posture_excellent(self, monitoring_agent):
        """Test excellent security posture."""
        metrics = SecurityMetrics(
            vulnerabilities_total=5,
            vulnerabilities_critical=0,
            vulnerabilities_high=1,
            vulnerabilities_medium=2,
            vulnerabilities_low=2,
            mttr_hours=2.0,
            remediation_rate_percent=95.0,
            compliance_score_percent=98.0,
            false_positive_rate_percent=1.0,
            scan_coverage_percent=100.0
        )

        posture = monitoring_agent._calculate_security_posture(metrics)

        assert isinstance(posture, SecurityPosture)
        assert posture.level == SecurityPostureLevel.EXCELLENT
        assert posture.score >= 90

    def test_calculate_posture_good(self, monitoring_agent):
        """Test good security posture."""
        metrics = SecurityMetrics(
            vulnerabilities_total=20,
            vulnerabilities_critical=0,
            vulnerabilities_high=2,
            vulnerabilities_medium=5,
            vulnerabilities_low=10,
            mttr_hours=8.0,
            remediation_rate_percent=75.0,
            compliance_score_percent=85.0,
            false_positive_rate_percent=5.0,
            scan_coverage_percent=90.0
        )

        posture = monitoring_agent._calculate_security_posture(metrics)

        assert posture.level == SecurityPostureLevel.GOOD
        assert 70 <= posture.score < 90

    def test_calculate_posture_fair(self, monitoring_agent):
        """Test fair security posture."""
        metrics = SecurityMetrics(
            vulnerabilities_total=50,
            vulnerabilities_critical=1,
            vulnerabilities_high=5,
            vulnerabilities_medium=15,
            vulnerabilities_low=25,
            mttr_hours=24.0,
            remediation_rate_percent=50.0,
            compliance_score_percent=70.0,
            false_positive_rate_percent=10.0,
            scan_coverage_percent=75.0
        )

        posture = monitoring_agent._calculate_security_posture(metrics)

        assert posture.level == SecurityPostureLevel.FAIR
        assert 50 <= posture.score < 70

    def test_calculate_posture_poor(self, monitoring_agent):
        """Test poor security posture."""
        metrics = SecurityMetrics(
            vulnerabilities_total=100,
            vulnerabilities_critical=5,
            vulnerabilities_high=20,
            vulnerabilities_medium=30,
            vulnerabilities_low=40,
            mttr_hours=168.0,  # 1 week
            remediation_rate_percent=20.0,
            compliance_score_percent=40.0,
            false_positive_rate_percent=20.0,
            scan_coverage_percent=50.0
        )

        posture = monitoring_agent._calculate_security_posture(metrics)

        assert posture.level == SecurityPostureLevel.POOR
        assert posture.score < 50

    def test_calculate_posture_critical(self, monitoring_agent):
        """Test critical security posture."""
        metrics = SecurityMetrics(
            vulnerabilities_total=200,
            vulnerabilities_critical=20,
            vulnerabilities_high=50,
            vulnerabilities_medium=60,
            vulnerabilities_low=50,
            mttr_hours=720.0,  # 30 days
            remediation_rate_percent=5.0,
            compliance_score_percent=20.0,
            false_positive_rate_percent=30.0,
            scan_coverage_percent=30.0
        )

        posture = monitoring_agent._calculate_security_posture(metrics)

        assert posture.level == SecurityPostureLevel.CRITICAL
        assert posture.score < 30


class TestMonitoringAgentAnomalyDetection:
    """Test anomaly detection functionality."""

    def test_detect_anomaly_above_threshold(self, monitoring_agent):
        """Test anomaly detection with value above threshold."""
        # Historical data: stable around 10
        historical = [9.0, 10.0, 11.0, 9.5, 10.5, 10.0, 9.0, 10.0]
        current = 25.0  # 2.5x normal

        is_anomaly, z_score = monitoring_agent._detect_anomaly(historical, current)

        assert is_anomaly is True
        assert z_score > 3.0  # 3 standard deviations

    def test_detect_anomaly_below_threshold(self, monitoring_agent):
        """Test anomaly detection with value below threshold."""
        historical = [90.0, 95.0, 92.0, 94.0, 93.0, 95.0, 91.0, 92.0]
        current = 60.0  # Much lower

        is_anomaly, z_score = monitoring_agent._detect_anomaly(historical, current)

        assert is_anomaly is True
        assert z_score < -3.0

    def test_detect_anomaly_normal_value(self, monitoring_agent):
        """Test anomaly detection with normal value."""
        historical = [10.0, 11.0, 9.0, 10.5, 9.5, 10.0, 11.0, 9.0]
        current = 10.2  # Within normal range

        is_anomaly, z_score = monitoring_agent._detect_anomaly(historical, current)

        assert is_anomaly is False
        assert abs(z_score) < 3.0

    def test_detect_anomaly_insufficient_data(self, monitoring_agent):
        """Test anomaly detection with insufficient historical data."""
        historical = [10.0, 11.0]  # Less than 5 points
        current = 50.0

        is_anomaly, z_score = monitoring_agent._detect_anomaly(historical, current)

        # Should not detect anomaly with insufficient data
        assert is_anomaly is False
        assert z_score == 0.0

    def test_detect_anomaly_zero_std_dev(self, monitoring_agent):
        """Test anomaly detection with zero standard deviation."""
        historical = [10.0, 10.0, 10.0, 10.0, 10.0]  # All same
        current = 11.0

        is_anomaly, z_score = monitoring_agent._detect_anomaly(historical, current)

        # With zero std dev, any change is anomaly
        assert is_anomaly is True


class TestMonitoringAgentThresholdChecking:
    """Test threshold checking for alerts."""

    def test_check_critical_vulnerabilities_threshold(self, monitoring_agent):
        """Test critical vulnerabilities threshold."""
        monitoring_agent.settings.monitoring_critical_vuln_threshold = 5

        # Below threshold
        assert monitoring_agent._check_threshold("vulnerabilities_critical", 3, 5) is False

        # At threshold
        assert monitoring_agent._check_threshold("vulnerabilities_critical", 5, 5) is True

        # Above threshold
        assert monitoring_agent._check_threshold("vulnerabilities_critical", 10, 5) is True

    def test_check_compliance_score_threshold(self, monitoring_agent):
        """Test compliance score threshold (inverted)."""
        monitoring_agent.settings.monitoring_compliance_min_threshold = 80.0

        # Below threshold (bad)
        assert monitoring_agent._check_threshold("compliance_score_percent", 70.0, 80.0, lower_is_bad=True) is True

        # At threshold
        assert monitoring_agent._check_threshold("compliance_score_percent", 80.0, 80.0, lower_is_bad=True) is False

        # Above threshold (good)
        assert monitoring_agent._check_threshold("compliance_score_percent", 90.0, 80.0, lower_is_bad=True) is False

    def test_check_mttr_threshold(self, monitoring_agent):
        """Test MTTR threshold (higher is worse)."""
        monitoring_agent.settings.monitoring_mttr_max_hours = 24.0

        # Below threshold (good)
        assert monitoring_agent._check_threshold("mttr_hours", 12.0, 24.0, higher_is_bad=True) is False

        # At threshold
        assert monitoring_agent._check_threshold("mttr_hours", 24.0, 24.0, higher_is_bad=True) is False

        # Above threshold (bad)
        assert monitoring_agent._check_threshold("mttr_hours", 48.0, 24.0, higher_is_bad=True) is True


class TestMonitoringAgentDataCollection:
    """Test data collection functionality."""

    @pytest.mark.asyncio
    async def test_collect_metrics_empty_vulnerabilities(self, monitoring_agent):
        """Test metrics collection with no vulnerabilities."""
        metrics = await monitoring_agent._collect_metrics([], [])

        assert isinstance(metrics, SecurityMetrics)
        assert metrics.vulnerabilities_total == 0
        assert metrics.vulnerabilities_critical == 0
        assert metrics.security_posture == SecurityPostureLevel.EXCELLENT

    @pytest.mark.asyncio
    async def test_collect_metrics_with_vulnerabilities(self, monitoring_agent):
        """Test metrics collection with vulnerabilities."""
        vulnerabilities = [
            Vulnerability(id="1", title="Critical", severity=Severity.CRITICAL),
            Vulnerability(id="2", title="High", severity=Severity.HIGH),
            Vulnerability(id="3", title="Medium", severity=Severity.MEDIUM)
        ]

        metrics = await monitoring_agent._collect_metrics(vulnerabilities, [])

        assert metrics.vulnerabilities_total == 3
        assert metrics.vulnerabilities_critical == 1
        assert metrics.vulnerabilities_high == 1
        assert metrics.vulnerabilities_medium == 1
        assert metrics.vulnerabilities_low == 0

    @pytest.mark.asyncio
    async def test_collect_metrics_with_analyses(self, monitoring_agent):
        """Test metrics collection with analyzed vulnerabilities."""
        vulnerabilities = [
            Vulnerability(id="1", title="Test", severity=Severity.HIGH, confidence=0.9),
            Vulnerability(id="2", title="Test", severity=Severity.MEDIUM, confidence=0.4),  # Low confidence
            Vulnerability(id="3", title="Test", severity=Severity.LOW, confidence=0.3)    # Low confidence
        ]

        analyses = [
            type('Analyzed', (), {
                'vulnerability_id': '1',
                'false_positive_probability': 0.05
            })(),
            type('Analyzed', (), {
                'vulnerability_id': '2',
                'false_positive_probability': 0.6  # High FP probability
            })(),
            type('Analyzed', (), {
                'vulnerability_id': '3',
                'false_positive_probability': 0.7  # High FP probability
            })()
        ]

        metrics = await monitoring_agent._collect_metrics(vulnerabilities, analyses)

        # Should have 1 high confidence, 2 low confidence (potential FP)
        assert metrics.vulnerabilities_total == 3
        assert metrics.false_positive_rate_percent == pytest.approx((2/3)*100, rel=0.01)

    @pytest.mark.asyncio
    async def test_collect_metrics_updates_series(self, monitoring_agent):
        """Test metrics collection updates time series."""
        vulnerabilities = [
            Vulnerability(id="1", title="Test", severity=Severity.HIGH)
        ]

        initial_count = len(monitoring_agent.metrics["vulnerabilities_total"].data)
        await monitoring_agent._collect_metrics(vulnerabilities, [])
        final_count = len(monitoring_agent.metrics["vulnerabilities_total"].data)

        assert final_count == initial_count + 1


class TestMonitoringAgentAlerting:
    """Test alert triggering logic."""

    @pytest.mark.asyncio
    async def test_check_alerts_critical_vulnerabilities(self, monitoring_agent):
        """Test alert on critical vulnerabilities."""
        monitoring_agent.settings.monitoring_critical_vuln_threshold = 3

        metrics = SecurityMetrics(
            vulnerabilities_total=10,
            vulnerabilities_critical=5,  # Above threshold
            vulnerabilities_high=3,
            vulnerabilities_medium=2,
            vulnerabilities_low=0,
            mttr_hours=10.0,
            remediation_rate_percent=80.0,
            compliance_score_percent=90.0,
            false_positive_rate_percent=5.0,
            scan_coverage_percent=95.0
        )

        await monitoring_agent._check_alerts(metrics)

        assert "critical_vulnerabilities" in monitoring_agent.alerts
        alert = monitoring_agent.alerts["critical_vulnerabilities"]
        assert alert.severity == AlertSeverity.CRITICAL
        assert "5 critical vulnerabilities" in alert.description

    @pytest.mark.asyncio
    async def test_check_alerts_compliance_drift(self, monitoring_agent):
        """Test alert on compliance drift."""
        metrics = SecurityMetrics(
            vulnerabilities_total=10,
            vulnerabilities_critical=0,
            vulnerabilities_high=2,
            vulnerabilities_medium=5,
            vulnerabilities_low=3,
            mttr_hours=10.0,
            remediation_rate_percent=80.0,
            compliance_score_percent=65.0,  # Below 80% threshold
            false_positive_rate_percent=5.0,
            scan_coverage_percent=95.0
        )

        await monitoring_agent._check_alerts(metrics)

        assert "compliance_drift" in monitoring_agent.alerts

    @pytest.mark.asyncio
    async def test_check_alerts_no_alerts_when_normal(self, monitoring_agent):
        """Test no alerts when all metrics normal."""
        metrics = SecurityMetrics(
            vulnerabilities_total=5,
            vulnerabilities_critical=0,
            vulnerabilities_high=1,
            vulnerabilities_medium=2,
            vulnerabilities_low=2,
            mttr_hours=8.0,
            remediation_rate_percent=85.0,
            compliance_score_percent=92.0,
            false_positive_rate_percent=3.0,
            scan_coverage_percent=98.0
        )

        # Clear existing alerts
        monitoring_agent.alerts.clear()

        await monitoring_agent._check_alerts(metrics)

        # Should not create new alerts
        assert len(monitoring_agent.alerts) == 0

    @pytest.mark.asyncio
    async def test_check_alerts_anomaly_detection(self, monitoring_agent):
        """Test alert on metric anomaly."""
        # Set up historical data
        for _ in range(10):
            monitoring_agent.metrics["vulnerability_inflow_rate"].add_point(5.0)

        metrics = SecurityMetrics(
            vulnerabilities_total=10,
            vulnerabilities_critical=0,
            vulnerabilities_high=2,
            vulnerabilities_medium=5,
            vulnerabilities_low=3,
            mttr_hours=10.0,
            remediation_rate_percent=80.0,
            compliance_score_percent=90.0,
            false_positive_rate_percent=5.0,
            scan_coverage_percent=95.0,
            vulnerability_inflow_rate=50.0  # 10x normal!
        )

        await monitoring_agent._check_alerts(metrics)

        # Should trigger anomaly alert
        assert any("anomaly" in alert_type for alert_type in monitoring_agent.alerts.keys())


class TestMonitoringAgentDashboard:
    """Test dashboard data generation."""

    @pytest.mark.asyncio
    async def test_get_dashboard_data_structure(self, monitoring_agent):
        """Test dashboard data has correct structure."""
        dashboard = await monitoring_agent.get_dashboard_data()

        assert "current_metrics" in dashboard
        assert "posture" in dashboard
        assert "alerts" in dashboard
        assert "trends" in dashboard
        assert "recommendations" in dashboard
        assert "generated_at" in dashboard

    @pytest.mark.asyncio
    async def test_get_dashboard_data_current_metrics(self, monitoring_agent):
        """Test current metrics in dashboard."""
        # Add some test data
        monitoring_agent.metrics["vulnerabilities_total"].add_point(42)
        monitoring_agent.metrics["compliance_score_percent"].add_point(88.5)

        dashboard = await monitoring_agent.get_dashboard_data()

        current = dashboard["current_metrics"]
        assert current["vulnerabilities_total"] == 42
        assert current["compliance_score_percent"] == 88.5

    @pytest.mark.asyncio
    async def test_get_dashboard_data_posture(self, monitoring_agent):
        """Test security posture in dashboard."""
        dashboard = await monitoring_agent.get_dashboard_data()

        posture = dashboard["posture"]
        assert "level" in posture
        assert "score" in posture
        assert posture["level"] in ["excellent", "good", "fair", "poor", "critical"]

    @pytest.mark.asyncio
    async def test_get_dashboard_data_alerts(self, monitoring_agent):
        """Test alerts in dashboard."""
        # Create an active alert
        monitoring_agent._trigger_alert(
            alert_type="test_alert",
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            description="Test"
        )

        dashboard = await monitoring_agent.get_dashboard_data()

        alerts = dashboard["alerts"]
        assert "active_alerts" in alerts
        assert "critical_count" in alerts
        assert "warning_count" in alerts
        assert "info_count" in alerts

    @pytest.mark.asyncio
    async def test_get_dashboard_data_trends(self, monitoring_agent):
        """Test trends in dashboard."""
        # Add historical data
        for i in range(10):
            monitoring_agent.metrics["vulnerabilities_total"].add_point(10 + i)

        dashboard = await monitoring_agent.get_dashboard_data()

        trends = dashboard["trends"]
        assert "vulnerabilities_total" in trends
        trend = trends["vulnerabilities_total"]
        assert "direction" in trend
        assert "slope" in trend
        assert trend["direction"] == "increasing"

    @pytest.mark.asyncio
    async def test_get_dashboard_data_recommendations(self, monitoring_agent):
        """Test recommendations in dashboard."""
        # Set up metrics that would trigger recommendations
        monitoring_agent.metrics["vulnerabilities_critical"].add_point(10)
        monitoring_agent.metrics["compliance_score_percent"].add_point(70.0)
        monitoring_agent.metrics["mttr_hours"].add_point(100.0)

        dashboard = await monitoring_agent.get_dashboard_data()

        recommendations = dashboard["recommendations"]
        assert isinstance(recommendations, list)
        # Should have recommendations for high critical vulns, low compliance, high MTTR
        assert len(recommendations) >= 3


class TestMonitoringAgentHealth:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, monitoring_agent):
        """Test health check when all components healthy."""
        health = await monitoring_agent.health_check()

        assert health["status"] == "healthy"
        assert health["knowledge_graph"] is True
        assert health["metrics_initialized"] is True
        assert health["alerts_initialized"] is True
        assert health["collection_task"] in ["stopped", "running"]

    @pytest.mark.asyncio
    async def test_health_check_degraded(self, monitoring_agent):
        """Test health check when knowledge graph fails."""
        monitoring_agent.knowledge_graph = MagicMock()
        monitoring_agent.knowledge_graph.get_metrics_history.side_effect = Exception("DB Error")

        health = await monitoring_agent.health_check()

        assert health["status"] == "degraded"
        assert health["knowledge_graph"] is False


class TestMonitoringAgentStatistics:
    """Test statistics tracking."""

    def test_get_statistics_initial(self, monitoring_agent):
        """Test statistics on fresh agent."""
        stats = monitoring_agent.get_statistics()

        assert stats["metrics_collected"] == 0
        assert stats["alerts_triggered"] == 0
        assert stats["alerts_acknowledged"] == 0
        assert stats["alerts_resolved"] == 0
        assert stats["dashboards_generated"] == 0

    def test_statistics_after_activity(self, monitoring_agent):
        """Test statistics after activity."""
        monitoring_agent._metrics_collected = 100
        monitoring_agent._alerts_triggered = 25
        monitoring_agent._alerts_acknowledged = 10
        monitoring_agent._alerts_resolved = 15
        monitoring_agent._dashboards_generated = 50

        stats = monitoring_agent.get_statistics()

        assert stats["metrics_collected"] == 100
        assert stats["alerts_triggered"] == 25
        assert stats["alerts_acknowledged"] == 10
        assert stats["alerts_resolved"] == 15
        assert stats["dashboards_generated"] == 50
        assert stats["alert_resolution_rate"] == pytest.approx(15/25)


class TestMonitoringAgentIntegration:
    """Integration tests with full workflow."""

    @pytest.mark.asyncio
    async def test_full_monitoring_workflow(self, monitoring_agent):
        """Test complete monitoring workflow."""
        # Create realistic vulnerability set
        vulnerabilities = [
            Vulnerability(
                id="SECUREAI-2024-001",
                title="SQL Injection in Authentication",
                severity=Severity.CRITICAL,
                source=VulnerabilitySource.SAST,
                discovered_at=datetime.utcnow() - timedelta(hours=48)
            ),
            Vulnerability(
                id="SECUREAI-2024-002",
                title="Hardcoded Credentials",
                severity=Severity.HIGH,
                source=VulnerabilitySource.SAST,
                discovered_at=datetime.utcnow() - timedelta(hours=24)
            ),
            Vulnerability(
                id="SECUREAI-2024-003",
                title="XSS Vulnerability",
                severity=Severity.MEDIUM,
                source=VulnerabilitySource.SAST,
                discovered_at=datetime.utcnow() - timedelta(hours=12)
            ),
            Vulnerability(
                id="SECUREAI-2024-004",
                title="Information Disclosure",
                severity=Severity.LOW,
                source=VulnerabilitySource.SAST,
                discovered_at=datetime.utcnow() - timedelta(hours=6)
            )
        ]

        # Collect metrics
        metrics = await monitoring_agent._collect_metrics(vulnerabilities, [])

        # Verify metrics calculated
        assert metrics.vulnerabilities_total == 4
        assert metrics.vulnerabilities_critical == 1
        assert metrics.vulnerabilities_high == 1
        assert metrics.vulnerabilities_medium == 1
        assert metrics.vulnerabilities_low == 1

        # Calculate posture
        posture = monitoring_agent._calculate_security_posture(metrics)
        assert posture.score > 0
        assert posture.level in ["excellent", "good", "fair", "poor", "critical"]

        # Check alerts
        await monitoring_agent._check_alerts(metrics)
        active_alerts = monitoring_agent.get_active_alerts()
        # Should have alerts for critical vulnerability
        assert len(active_alerts) > 0

        # Generate dashboard
        dashboard = await monitoring_agent.get_dashboard_data()
        assert dashboard["current_metrics"]["vulnerabilities_total"] == 4
        assert len(dashboard["alerts"]["active_alerts"]) >= 0
        assert len(dashboard["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_monitoring_with_historical_trends(self, monitoring_agent):
        """Test monitoring with historical trend analysis."""
        # Add historical data
        for i in range(30):
            monitoring_agent.metrics["vulnerabilities_total"].add_point(10 + i)
            monitoring_agent.metrics["compliance_score_percent"].add_point(90 - i*0.5)

        # Current metrics
        vulnerabilities = [
            Vulnerability(id="1", title="Test", severity=Severity.HIGH)
        ]

        metrics = await monitoring_agent._collect_metrics(vulnerabilities, [])
        dashboard = await monitoring_agent.get_dashboard_data()

        # Should have trend data
        trends = dashboard["trends"]
        assert "vulnerabilities_total" in trends
        assert trends["vulnerabilities_total"]["direction"] == "increasing"
        assert "compliance_score_percent" in trends
        assert trends["compliance_score_percent"]["direction"] == "decreasing"

        # Should have recommendations based on trends
        recommendations = dashboard["recommendations"]
        assert len(recommendations) > 0
        # Should recommend addressing increasing vulnerabilities
        assert any("vulnerability" in rec["area"].lower() for rec in recommendations)

    @pytest.mark.asyncio
    async def test_monitoring_alert_lifecycle(self, monitoring_agent):
        """Test complete alert lifecycle."""
        # Trigger alert
        monitoring_agent._trigger_alert(
            alert_type="test_alert",
            severity=AlertSeverity.CRITICAL,
            title="Test Alert",
            description="Test alert lifecycle"
        )

        assert len(monitoring_agent.alerts) == 1
        alert_id = list(monitoring_agent.alerts.keys())[0]

        # Acknowledge alert
        monitoring_agent.acknowledge_alert(alert_id)
        assert monitoring_agent.alerts[alert_id].status == AlertStatus.ACKNOWLEDGED

        # Resolve alert
        monitoring_agent.resolve_alert(alert_id)
        assert monitoring_agent.alerts[alert_id].status == AlertStatus.RESOLVED

        # Get active alerts should not include resolved
        active = monitoring_agent.get_active_alerts()
        assert alert_id not in [a.alert_type for a in active]
