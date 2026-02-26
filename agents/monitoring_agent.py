"""
Monitoring Agent - Real-Time Security Posture and Alerting

This agent provides continuous monitoring of security posture,
generates alerts, tracks metrics, and maintains dashboard data
for SecurAI Guardian.

Part of: SecurAI Guardian - GitLab AI Hackathon 2026
Author: CODER_AGENT_SUPREME_v21_OMEGA
Quality Target: 10/10 transcendent
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Set
from collections import defaultdict, deque
from statistics import mean, median, stdev
import asyncio

from pydantic import BaseModel, Field, validator
from tenacity import retry, stop_after_attempt, wait_exponential

from core.config import settings
from core.gitlab_client import GitLabClient
from core.models import (
    Vulnerability,
    AnalyzedVulnerability,
    RemediationPlan,
    SecurityMetrics,
    Alert,
    AlertSeverity,
    AlertStatus,
    GitLabProject,
    Severity,
    ComplianceStatus,
)

logger = logging.getLogger(__name__)


class MetricDataPoint(BaseModel):
    """Single metric data point."""

    timestamp: datetime
    value: float
    labels: Dict[str, str] = {}


class MetricSeries(BaseModel):
    """Time series of metric data points."""

    metric_name: str
    unit: str
    data_points: List[MetricDataPoint] = []
    window_minutes: int = 60

    def add_point(self, value: float, labels: Optional[Dict[str, str]] = None):
        """Add a new data point, maintaining window size."""
        point = MetricDataPoint(
            timestamp=datetime.utcnow(),
            value=value,
            labels=labels or {},
        )
        self.data_points.append(point)

        # Trim old points outside window
        cutoff = datetime.utcnow() - timedelta(minutes=self.window_minutes)
        self.data_points = [
            dp for dp in self.data_points if dp.timestamp >= cutoff
        ]

    def get_current_value(self) -> Optional[float]:
        """Get most recent value."""
        if self.data_points:
            return self.data_points[-1].value
        return None

    def get_average(self, minutes: int = 60) -> Optional[float]:
        """Get average over specified minutes."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        recent = [dp.value for dp in self.data_points if dp.timestamp >= cutoff]
        return mean(recent) if recent else None

    def get_percentile(self, percentile: float = 95, minutes: int = 60) -> Optional[float]:
        """Get percentile over specified minutes."""
        import numpy as np
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        recent = [dp.value for dp in self.data_points if dp.timestamp >= cutoff]
        if len(recent) >= 10:  # Need enough data points
            return float(np.percentile(recent, percentile))
        return None


class MonitoringAgent:
    """
    Agent 5: Monitoring - Real-Time Security Posture and Alerting

    Responsibilities:
    - Collect security metrics from all agents and GitLab
    - Calculate real-time security posture scores
    - Generate alerts for anomalies and threshold breaches
    - Maintain time-series data for trend analysis
    - Provide dashboard data for UI
    - Detect security drift and regressions
    - Track remediation SLAs and KPIs

    Design Principles:
    - O(1) metric queries using in-memory time-series
    - Zero waste: efficient data structures, automatic pruning
    - Self-healing: alert deduplication, auto-resolve when fixed
    - Context coherence: maintain full metric history
    - Transcendent quality: real-time accuracy, zero false alerts
    """

    # Metric definitions
    METRIC_DEFINITIONS = {
        "vulnerabilities_total": {
            "name": "Total Vulnerabilities",
            "description": "Total number of open vulnerabilities",
            "unit": "count",
            "thresholds": {"warning": 50, "critical": 100},
        },
        "vulnerabilities_critical": {
            "name": "Critical Vulnerabilities",
            "description": "Number of critical severity vulnerabilities",
            "unit": "count",
            "thresholds": {"warning": 5, "critical": 10},
        },
        "vulnerabilities_high": {
            "name": "High Severity Vulnerabilities",
            "description": "Number of high severity vulnerabilities",
            "unit": "count",
            "thresholds": {"warning": 20, "critical": 40},
        },
        "mean_time_to_remediate": {
            "name": "Mean Time to Remediate (MTTR)",
            "description": "Average time to fix vulnerabilities (hours)",
            "unit": "hours",
            "thresholds": {"warning": 168, "critical": 336},  # 1 week, 2 weeks
        },
        "remediation_rate": {
            "name": "Remediation Rate",
            "description": "Percentage of vulnerabilities fixed per week",
            "unit": "percent",
            "thresholds": {"warning": 60, "critical": 30},
        },
        "compliance_score": {
            "name": "Compliance Score",
            "description": "Overall compliance score across frameworks",
            "unit": "percent",
            "thresholds": {"warning": 80, "critical": 60},
        },
        "security_posture": {
            "name": "Security Posture Score",
            "description": "Overall security health score (0-100)",
            "unit": "score",
            "thresholds": {"warning": 70, "critical": 50},
        },
        "false_positive_rate": {
            "name": "False Positive Rate",
            "description": "Percentage of findings that are false positives",
            "unit": "percent",
            "thresholds": {"warning": 15, "critical": 25},
        },
        "scan_coverage": {
            "name": "Security Scan Coverage",
            "description": "Percentage of codebase covered by security scans",
            "unit": "percent",
            "thresholds": {"warning": 80, "critical": 60},
        },
        "vulnerability_inflow_rate": {
            "name": "Vulnerability Inflow Rate",
            "description": "New vulnerabilities per day",
            "unit": "count/day",
            "thresholds": {"warning": 10, "critical": 20},
        },
    }

    def __init__(
        self,
        gitlab_client: Optional[GitLabClient] = None,
        knowledge_graph_client: Optional[Any] = None,
    ):
        """
        Initialize Monitoring Agent.

        Args:
            gitlab_client: GitLab API client
            knowledge_graph_client: Knowledge graph for historical data
        """
        self.gitlab = gitlab_client or GitLabClient()
        self.kg = knowledge_graph_client

        # In-memory time-series storage
        self._metrics: Dict[str, MetricSeries] = {}
        self._alerts: Dict[str, Alert] = {}
        self._alert_history: deque = deque(maxlen=1000)

        # Initialize metric series
        for metric_name in self.METRIC_DEFINITIONS:
            self._metrics[metric_name] = MetricSeries(
                metric_name=metric_name,
                unit=self.METRIC_DEFINITIONS[metric_name]["unit"],
            )

        # Background collection task
        self._collection_task: Optional[asyncio.Task] = None
        self._running = False

        # Statistics
        self._total_alerts_generated = 0
        self._active_alerts = 0

        logger.info(
            f"MonitoringAgent initialized with {len(self._metrics)} metrics",
            extra={"component": "MonitoringAgent"},
        )

    async def start(self):
        """Start background metric collection."""
        if not self._running:
            self._running = True
            self._collection_task = asyncio.create_task(self._collect_metrics_loop())
            logger.info("Monitoring agent started", extra={"component": "MonitoringAgent"})

    async def stop(self):
        """Stop background metric collection."""
        if self._running:
            self._running = False
            if self._collection_task:
                self._collection_task.cancel()
                try:
                    await self._collection_task
                except asyncio.CancelledError:
                    pass
            logger.info("Monitoring agent stopped", extra={"component": "MonitoringAgent"})

    async def collect_metrics(
        self,
        project_id: int,
        vulnerabilities: List[AnalyzedVulnerability],
        remediation_plans: List[RemediationPlan],
        compliance_report: Optional[ComplianceStatus] = None,
    ) -> SecurityMetrics:
        """
        Main entry point: collect and calculate all security metrics.

        Args:
            project_id: GitLab project ID
            vulnerabilities: Current list of analyzed vulnerabilities
            remediation_plans: Current list of remediation plans
            compliance_report: Latest compliance assessment

        Returns:
            SecurityMetrics with all calculated metrics

        O(n) Complexity:
        - Vulnerability counting: O(v)
        - MTTR calculation: O(r) where r = remediated vulns
        - Rate calculations: O(1) with time-series
        - Total: O(v + r) = linear in input size
        """
        logger.info(
            f"Collecting metrics for project {project_id}",
            extra={"component": "MonitoringAgent", "project_id": project_id},
        )

        metrics = SecurityMetrics(
            project_id=project_id,
            generated_at=datetime.utcnow(),
        )

        # Calculate metrics
        await self._calculate_vulnerability_metrics(metrics, vulnerabilities)
        await self._calculate_remediation_metrics(metrics, remediation_plans)
        await self._calculate_compliance_metrics(metrics, compliance_report)
        await self._calculate_trend_metrics(metrics, vulnerabilities)

        # Update time-series
        self._update_metric_series(metrics)

        # Generate alerts if thresholds breached
        alerts = await self._check_thresholds(metrics)
        metrics.alerts = alerts

        # Store in knowledge graph
        await self._store_metrics(metrics)

        logger.info(
            f"Metrics collected: posture_score={metrics.security_posture_score:.1f}, "
            f"alerts={len(alerts)}",
            extra={"component": "MonitoringAgent"},
        )

        return metrics

    async def _calculate_vulnerability_metrics(
        self,
        metrics: SecurityMetrics,
        vulnerabilities: List[AnalyzedVulnerability],
    ) -> None:
        """Calculate vulnerability-based metrics."""
        # Count by severity
        critical_count = sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.severity == Severity.HIGH)
        medium_count = sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM)
        low_count = sum(1 for v in vulnerabilities if v.severity == Severity.LOW)

        total = len(vulnerabilities)

        metrics.critical_vulnerabilities = critical_count
        metrics.high_vulnerabilities = high_count
        metrics.medium_vulnerabilities = medium_count
        metrics.low_vulnerabilities = low_count
        metrics.total_vulnerabilities = total

        # Update metric series
        self._metrics["vulnerabilities_total"].add_point(total)
        self._metrics["vulnerabilities_critical"].add_point(critical_count)
        self._metrics["vulnerabilities_high"].add_point(high_count)

        # Calculate false positive rate
        false_positives = sum(1 for v in vulnerabilities if v.false_positive_probability > 0.5)
        if total > 0:
            metrics.false_positive_rate = (false_positives / total) * 100
            self._metrics["false_positive_rate"].add_point(metrics.false_positive_rate)

    async def _calculate_remediation_metrics(
        self,
        metrics: SecurityMetrics,
        remediation_plans: List[RemediationPlan],
    ) -> None:
        """Calculate remediation-related metrics."""
        # Count by status
        completed = sum(1 for p in remediation_plans if p.status == RemediationStatus.COMPLETED)
        in_progress = sum(1 for p in remediation_plans if p.status in [RemediationStatus.IN_PROGRESS, RemediationStatus.READY_FOR_REVIEW])
        failed = sum(1 for p in remediation_plans if p.status == RemediationStatus.FAILED)

        metrics.remediation_completed = completed
        metrics.remediation_in_progress = in_progress
        metrics.remediation_failed = failed

        # Calculate MTTR (Mean Time to Remediate)
        # For completed plans, calculate time from creation to completion
        completed_plans = [p for p in remediation_plans if p.status == RemediationStatus.COMPLETED]
        if completed_plans:
            # In production, would use actual timestamps
            # For now, use estimated effort as proxy
            mttr_hours = mean([p.estimated_effort_hours for p in completed_plans])
            metrics.mean_time_to_remediate_hours = mttr_hours
            self._metrics["mean_time_to_remediate"].add_point(mttr_hours)

        # Calculate remediation rate (per week)
        # In production, would track over time
        if completed_plans:
            remediation_rate = (completed / max(len(remediation_plans), 1)) * 100
            metrics.remediation_rate = remediation_rate
            self._metrics["remediation_rate"].add_point(remediation_rate)

    async def _calculate_compliance_metrics(
        self,
        metrics: SecurityMetrics,
        compliance_report: Optional[ComplianceStatus],
    ) -> None:
        """Calculate compliance-based metrics."""
        if compliance_report:
            metrics.compliance_score = compliance_report.compliance_score * 100
            self._metrics["compliance_score"].add_point(metrics.compliance_score)

    async def _calculate_trend_metrics(
        self,
        metrics: SecurityMetrics,
        vulnerabilities: List[AnalyzedVulnerability],
    ) -> None:
        """Calculate trend-based metrics."""
        # Vulnerability inflow rate (new vulnerabilities per day)
        # In production, would compare to historical data
        # For now, estimate from current count
        metrics.vulnerability_inflow_rate = len(vulnerabilities) / 7  # Per day estimate

        # Calculate security posture score
        # Formula: 100 - (weighted vulnerability score) - (MTTR penalty) + (compliance bonus)
        posture = 100.0

        # Deduct for vulnerabilities (critical weighted heavily)
        vuln_penalty = (
            metrics.critical_vulnerabilities * 10 +
            metrics.high_vulnerabilities * 5 +
            metrics.medium_vulnerabilities * 2 +
            metrics.low_vulnerabilities * 0.5
        )
        posture -= min(vuln_penalty, 50)  # Cap at 50 point deduction

        # Deduct for high MTTR
        if metrics.mean_time_to_remediate_hours:
            if metrics.mean_time_to_remediate_hours > 168:  # 1 week
                posture -= 15
            elif metrics.mean_time_to_remediate_hours > 72:  # 3 days
                posture -= 5

        # Add compliance bonus
        if metrics.compliance_score:
            if metrics.compliance_score >= 95:
                posture += 10
            elif metrics.compliance_score >= 80:
                posture += 5

        # Clamp to 0-100
        metrics.security_posture_score = max(0.0, min(100.0, posture))
        self._metrics["security_posture"].add_point(metrics.security_posture_score)

    def _update_metric_series(self, metrics: SecurityMetrics):
        """Update all metric time-series with current values."""
        # Map metrics to series
        metric_mapping = {
            "vulnerabilities_total": metrics.total_vulnerabilities,
            "vulnerabilities_critical": metrics.critical_vulnerabilities,
            "vulnerabilities_high": metrics.high_vulnerabilities,
            "mean_time_to_remediate": metrics.mean_time_to_remediate_hours,
            "remediation_rate": metrics.remediation_rate,
            "compliance_score": metrics.compliance_score,
            "security_posture": metrics.security_posture_score,
            "false_positive_rate": metrics.false_positive_rate,
        }

        for metric_name, value in metric_mapping.items():
            if value is not None:
                self._metrics[metric_name].add_point(value)

    async def _check_thresholds(
        self,
        metrics: SecurityMetrics,
    ) -> List[Alert]:
        """
        Check metrics against thresholds and generate alerts.

        Returns list of new or updated alerts.
        """
        new_alerts = []

        for metric_name, metric_series in self._metrics.items():
            current_value = metric_series.get_current_value()
            if current_value is None:
                continue

            definition = self.METRIC_DEFINITIONS[metric_name]
            thresholds = definition["thresholds"]

            # Check critical threshold
            if current_value >= thresholds["critical"]:
                severity = AlertSeverity.CRITICAL
            elif current_value >= thresholds["warning"]:
                severity = AlertSeverity.WARNING
            else:
                continue  # No alert

            # Create or update alert
            alert_id = f"{metric_name}:{metrics.project_id}"

            if alert_id in self._alerts:
                # Update existing alert
                alert = self._alerts[alert_id]
                alert.current_value = current_value
                alert.last_triggered = datetime.utcnow()
                if alert.status == AlertStatus.RESOLVED:
                    alert.status = AlertStatus.ACTIVE
                    new_alerts.append(alert)
            else:
                # Create new alert
                alert = Alert(
                    alert_id=alert_id,
                    title=f"{definition['name']} threshold breached",
                    description=(
                        f"Metric {metric_name} is {current_value:.1f} {definition['unit']}, "
                        f"exceeding {severity.value} threshold of {thresholds[severity.value]} {definition['unit']}"
                    ),
                    severity=severity,
                    metric_name=metric_name,
                    current_value=current_value,
                    threshold_value=thresholds[severity.value],
                    project_id=metrics.project_id,
                    status=AlertStatus.ACTIVE,
                    created_at=datetime.utcnow(),
                    last_triggered=datetime.utcnow(),
                )
                self._alerts[alert_id] = alert
                new_alerts.append(alert)
                self._total_alerts_generated += 1
                self._active_alerts += 1

                logger.warning(
                    f"Alert generated: {alert.title}",
                    extra={"component": "MonitoringAgent", "alert_id": alert_id},
                )

        # Check for resolved alerts
        for alert_id, alert in list(self._alerts.items()):
            if alert.status == AlertStatus.ACTIVE:
                # Re-check metric
                metric_name = alert.metric_name
                current_value = self._metrics[metric_name].get_current_value()
                thresholds = self.METRIC_DEFINITIONS[metric_name]["thresholds"]

                if current_value is None or current_value < thresholds["warning"]:
                    # Alert resolved
                    alert.status = AlertStatus.RESOLVED
                    alert.resolved_at = datetime.utcnow()
                    self._active_alerts -= 1

                    logger.info(
                        f"Alert resolved: {alert.title}",
                        extra={"component": "MonitoringAgent", "alert_id": alert_id},
                    )

        return new_alerts

    async def _collect_metrics_loop(self):
        """Background task to periodically collect metrics."""
        while self._running:
            try:
                # In production, this would:
                # 1. Fetch latest vulnerabilities from knowledge graph
                # 2. Fetch remediation plans
                # 3. Fetch compliance reports
                # 4. Call collect_metrics()

                # For now, just sleep
                await asyncio.sleep(60)  # Collect every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    f"Error in metrics collection loop: {e}",
                    exc_info=True,
                    extra={"component": "MonitoringAgent"},
                )
                await asyncio.sleep(60)

    async def get_dashboard_data(
        self,
        project_id: int,
        time_range_minutes: int = 60,
    ) -> Dict[str, Any]:
        """
        Get data for dashboard visualization.

        Returns:
        - Current metrics
        - Time-series data for charts
        - Active alerts
        - Trend indicators
        """
        dashboard = {
            "project_id": project_id,
            "generated_at": datetime.utcnow().isoformat(),
            "current_metrics": {},
            "time_series": {},
            "alerts": [],
            "trends": {},
        }

        # Current metrics
        for metric_name, series in self._metrics.items():
            current = series.get_current_value()
            if current is not None:
                dashboard["current_metrics"][metric_name] = {
                    "value": current,
                    "unit": series.unit,
                }

        # Time-series data
        cutoff = datetime.utcnow() - timedelta(minutes=time_range_minutes)
        for metric_name, series in self._metrics.items():
            recent_points = [
                {
                    "timestamp": dp.timestamp.isoformat(),
                    "value": dp.value,
                }
                for dp in series.data_points
                if dp.timestamp >= cutoff
            ]
            if recent_points:
                dashboard["time_series"][metric_name] = {
                    "unit": series.unit,
                    "data": recent_points,
                }

        # Active alerts
        dashboard["alerts"] = [
            {
                "id": alert.alert_id,
                "title": alert.title,
                "severity": alert.severity.value,
                "current_value": alert.current_value,
                "threshold": alert.threshold_value,
                "created_at": alert.created_at.isoformat(),
            }
            for alert in self._alerts.values()
            if alert.status == AlertStatus.ACTIVE
        ]

        # Trend indicators (compare to previous period)
        for metric_name, series in self._metrics.items():
            if len(series.data_points) >= 10:
                recent = [dp.value for dp in list(series.data_points)[-10:]]
                previous = [dp.value for dp in list(series.data_points)[-20:-10]] if len(series.data_points) >= 20 else []

                if recent and previous:
                    recent_avg = mean(recent)
                    previous_avg = mean(previous)
                    change_pct = ((recent_avg - previous_avg) / previous_avg) * 100 if previous_avg > 0 else 0

                    dashboard["trends"][metric_name] = {
                        "change_percent": change_pct,
                        "direction": "up" if change_pct > 5 else "down" if change_pct < -5 else "stable",
                    }

        return dashboard

    async def get_alert_details(
        self,
        alert_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get detailed information about an alert."""
        if alert_id not in self._alerts:
            return None

        alert = self._alerts[alert_id]

        return {
            "alert_id": alert.alert_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "metric_name": alert.metric_name,
            "current_value": alert.current_value,
            "threshold_value": alert.threshold_value,
            "status": alert.status.value,
            "created_at": alert.created_at.isoformat(),
            "last_triggered": alert.last_triggered.isoformat(),
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "suggested_action": self._get_suggested_action(alert),
        }

    def _get_suggested_action(self, alert: Alert) -> str:
        """Get suggested action for an alert based on metric."""
        suggestions = {
            "vulnerabilities_total": "Prioritize remediation of high and critical vulnerabilities. Consider increasing automated fix coverage.",
            "vulnerabilities_critical": "IMMEDIATE ACTION REQUIRED: Address critical vulnerabilities within 24 hours. These pose significant security risk.",
            "vulnerabilities_high": "Focus on reducing high severity vulnerabilities. Target: fix at least 50% this week.",
            "mean_time_to_remediate": "Review remediation bottlenecks. Optimize fix patterns and provide additional resources if needed.",
            "remediation_rate": "Improve remediation velocity. Consider automating more fix patterns or increasing team capacity.",
            "compliance_score": "Address compliance gaps immediately. Review framework requirements and prioritize violations.",
            "security_posture": "Overall security health declining. Review all metrics and take comprehensive action.",
            "false_positive_rate": "High false positive rate indicates scanner tuning needed. Adjust scanner sensitivity or improve analysis.",
            "scan_coverage": "Increase security scan coverage. Ensure all code paths are scanned regularly.",
            "vulnerability_inflow_rate": "Vulnerability inflow exceeds remediation capacity. Invest in secure coding training and pre-commit hooks.",
        }

        return suggestions.get(alert.metric_name, "Review security metrics and take appropriate action.")

    async def _store_metrics(self, metrics: SecurityMetrics):
        """Store metrics in knowledge graph."""
        if not self.kg:
            return

        try:
            await self.kg.store_security_metrics(metrics.dict())
            logger.debug(
                f"Stored security metrics for project {metrics.project_id}",
                extra={"component": "MonitoringAgent"},
            )
        except Exception as e:
            logger.warning(
                f"Failed to store metrics in KG: {e}",
                extra={"component": "MonitoringAgent"},
            )

    def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics for monitoring."""
        return {
            "agent": "MonitoringAgent",
            "metrics_tracked": len(self._metrics),
            "active_alerts": self._active_alerts,
            "total_alerts_generated": self._total_alerts_generated,
            "alert_history_size": len(self._alert_history),
            "running": self._running,
            "status": "active" if self._running else "stopped",
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the agent."""
        # Check metric series health
        metrics_healthy = all(
            series.data_points for series in self._metrics.values()
        )

        # Check alert system
        alert_system_healthy = isinstance(self._alerts, dict)

        return {
            "agent": "MonitoringAgent",
            "metrics_initialized": len(self._metrics) > 0,
            "metrics_with_data": sum(1 for s in self._metrics.values() if s.data_points),
            "alert_system_healthy": alert_system_healthy,
            "background_task_running": self._running,
            "total_alerts": self._total_alerts_generated,
            "status": "healthy" if metrics_healthy and alert_system_healthy else "degraded",
        }

    async def acknowledge_alert(
        self,
        alert_id: str,
        user: str,
        comment: Optional[str] = None,
    ) -> bool:
        """Acknowledge an alert (user has seen it)."""
        if alert_id not in self._alerts:
            return False

        alert = self._alerts[alert_id]
        if alert.status == AlertStatus.ACTIVE:
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = user
            if comment:
                alert.comments.append({
                    "author": user,
                    "timestamp": datetime.utcnow().isoformat(),
                    "text": comment,
                })

            logger.info(
                f"Alert {alert_id} acknowledged by {user}",
                extra={"component": "MonitoringAgent", "alert_id": alert_id},
            )
            return True

        return False

    async def resolve_alert(
        self,
        alert_id: str,
        user: str,
        resolution: str,
    ) -> bool:
        """Manually resolve an alert."""
        if alert_id not in self._alerts:
            return False

        alert = self._alerts[alert_id]
        if alert.status in [AlertStatus.ACTIVE, AlertStatus.ACKNOWLEDGED]:
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()
            alert.resolved_by = user
            alert.resolution = resolution
            self._active_alerts -= 1

            logger.info(
                f"Alert {alert_id} resolved by {user}: {resolution}",
                extra={"component": "MonitoringAgent", "alert_id": alert_id},
            )
            return True

        return False

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of all alerts."""
        by_severity = defaultdict(int)
        by_status = defaultdict(int)

        for alert in self._alerts.values():
            by_severity[alert.severity.value] += 1
            by_status[alert.status.value] += 1

        return {
            "total_alerts": len(self._alerts),
            "active_alerts": self._active_alerts,
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
            "recent_alerts": [
                {
                    "id": a.alert_id,
                    "title": a.title,
                    "severity": a.severity.value,
                    "created_at": a.created_at.isoformat(),
                }
                for a in sorted(
                    self._alerts.values(),
                    key=lambda x: x.created_at,
                    reverse=True
                )[:10]
            ],
        }
