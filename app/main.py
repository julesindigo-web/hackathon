"""
SecurAI Guardian - FastAPI Application

Main orchestration layer for the multi-agent security system.
Provides REST API endpoints for GitLab integration and dashboard.

Part of: SecurAI Guardian - GitLab AI Hackathon 2026
Author: CODER_AGENT_SUPREME_v21_OMEGA
Quality Target: 10/10 transcendent
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from core.config import settings
from app.orchestrator import SecurityOrchestrator
from agents.monitoring_agent import MonitoringAgent
from agents.knowledge_graph_agent import KnowledgeGraphAgent

# Import all agents
from agents.scanner_agent import ScannerAgent
from agents.analyzer_agent import AnalyzerAgent
from agents.remediation_agent import RemediationAgent
from agents.compliance_agent import ComplianceAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="SecurAI Guardian",
    description="Autonomous Multi-Agent Security System for GitLab",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator instance
_orchestrator: Optional[SecurityOrchestrator] = None
_monitoring_agent: Optional[MonitoringAgent] = None
_kg_agent: Optional[KnowledgeGraphAgent] = None


# Pydantic models for API
class ScanRequest(BaseModel):
    """Request to trigger a security scan."""

    project_id: int = Field(..., description="GitLab project ID")
    mr_iid: Optional[int] = Field(None, description="Merge request internal ID")
    pipeline_id: Optional[int] = Field(None, description="Pipeline ID")
    auto_remediate: bool = Field(False, description="Automatically apply fixes")


class ScanResponse(BaseModel):
    """Response from scan operation."""

    scan_id: str
    project_id: int
    vulnerabilities_found: int
    vulnerabilities_analyzed: int
    remediations_created: int
    compliance_score: Optional[float]
    security_posture: Optional[float]
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None


class VulnerabilityResponse(BaseModel):
    """Vulnerability details for API response."""

    id: str
    title: str
    description: str
    severity: str
    vulnerability_type: str
    location: Optional[str]
    priority_score: float
    false_positive_probability: float
    recommended_fix: Optional[str]
    code_patch: Optional[str]
    status: str


class ComplianceReportResponse(BaseModel):
    """Compliance report for API response."""

    project_id: int
    overall_compliance_score: float
    frameworks_assessed: List[str]
    frameworks_compliant: int
    frameworks_total: int
    total_violations: int
    status: str
    generated_at: datetime


class DashboardMetricsResponse(BaseModel):
    """Dashboard metrics for UI."""

    current_metrics: Dict[str, Any]
    time_series: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    trends: Dict[str, Any]
    generated_at: datetime


class AgentHealthResponse(BaseModel):
    """Health status of an agent."""

    agent: str
    status: str
    details: Dict[str, Any]


# Dependency: Get orchestrator
async def get_orchestrator() -> SecurityOrchestrator:
    """Get or initialize the global orchestrator."""
    global _orchestrator
    if _orchestrator is None:
        await initialize_system()
    return _orchestrator


# Dependency: Get monitoring agent
async def get_monitoring_agent() -> MonitoringAgent:
    """Get or initialize the monitoring agent."""
    global _monitoring_agent
    if _monitoring_agent is None:
        await initialize_system()
    return _monitoring_agent


# Dependency: Get knowledge graph agent
async def get_kg_agent() -> KnowledgeGraphAgent:
    """Get or initialize the knowledge graph agent."""
    global _kg_agent
    if _kg_agent is None:
        await initialize_system()
    return _kg_agent


@app.on_event("startup")
async def startup_event():
    """Initialize system on startup."""
    await initialize_system()
    logger.info("SecurAI Guardian started", extra={"component": "main"})


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    global _orchestrator, _monitoring_agent, _kg_agent

    if _monitoring_agent:
        await _monitoring_agent.stop()

    logger.info("SecurAI Guardian shutdown complete", extra={"component": "main"})


async def initialize_system():
    """Initialize all agents and orchestrator."""
    global _orchestrator, _monitoring_agent, _kg_agent

    logger.info("Initializing SecurAI Guardian system...", extra={"component": "main"})

    try:
        # Initialize agents
        scanner = ScannerAgent()
        analyzer = AnalyzerAgent()
        remediation = RemediationAgent()
        compliance = ComplianceAgent()
        monitoring = MonitoringAgent()
        kg_agent = KnowledgeGraphAgent()

        # Initialize orchestrator
        _orchestrator = SecurityOrchestrator(
            scanner_agent=scanner,
            analyzer_agent=analyzer,
            remediation_agent=remediation,
            compliance_agent=compliance,
            monitoring_agent=monitoring,
            kg_agent=kg_agent,
        )

        _monitoring_agent = monitoring
        _kg_agent = kg_agent

        # Start monitoring background collection
        await monitoring.start()

        logger.info("System initialization complete", extra={"component": "main"})

    except Exception as e:
        logger.error(f"System initialization failed: {e}", exc_info=True)
        raise


@app.get("/")
async def root():
    """Root endpoint with system information."""
    return {
        "name": "SecurAI Guardian",
        "version": "1.0.0",
        "description": "Autonomous Multi-Agent Security System for GitLab",
        "status": "operational",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=Dict[str, Any])
async def health_check():
    """System health check endpoint."""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "agents": {},
        "system": {
            "uptime": "N/A",  # Would calculate in production
            "version": "1.0.0",
        },
    }

    # Check all agents if initialized
    if _orchestrator:
        agent_health = await _orchestrator.health_check()
        health_status["agents"] = agent_health

    return health_status


@app.post("/api/v1/scan", response_model=ScanResponse)
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """
    Trigger a security scan for a GitLab project/MR.

    This endpoint initiates the full multi-agent security pipeline:
    1. Scanner Agent ingests security artifacts
    2. Analyzer Agent uses Claude to analyze vulnerabilities
    3. Remediation Agent applies automated fixes (if auto_remediate=True)
    4. Compliance Agent assesses regulatory impact
    5. Monitoring Agent updates security posture metrics
    6. Knowledge Graph Agent stores all data for learning
    """
    logger.info(
        f"Scan request received: project={request.project_id}, mr={request.mr_iid}",
        extra={"component": "api", "endpoint": "/scan"},
    )

    try:
        # Execute scan pipeline
        result = await orchestrator.execute_scan_pipeline(
            project_id=request.project_id,
            mr_iid=request.mr_iid,
            pipeline_id=request.pipeline_id,
            auto_remediate=request.auto_remediate,
        )

        return ScanResponse(
            scan_id=result["scan_id"],
            project_id=request.project_id,
            vulnerabilities_found=result["vulnerabilities_found"],
            vulnerabilities_analyzed=result["vulnerabilities_analyzed"],
            remediations_created=result["remediations_created"],
            compliance_score=result.get("compliance_score"),
            security_posture=result.get("security_posture"),
            status=result["status"],
            started_at=result["started_at"],
            completed_at=result.get("completed_at"),
        )

    except Exception as e:
        logger.error(
            f"Scan failed: {e}",
            exc_info=True,
            extra={"component": "api", "endpoint": "/scan"},
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    project_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """
    List vulnerabilities with optional filtering.

    Returns vulnerabilities from knowledge graph with analysis results.
    """
    try:
        vulns = await orchestrator.list_vulnerabilities(
            project_id=project_id,
            severity=severity,
            status=status,
            limit=limit,
        )

        return [
            VulnerabilityResponse(
                id=v["id"],
                title=v["title"],
                description=v["description"][:500],  # Truncate for list view
                severity=v["severity"],
                vulnerability_type=v["vulnerability_type"],
                location=v.get("location"),
                priority_score=v.get("priority_score", 0.0),
                false_positive_probability=v.get("false_positive_probability", 0.0),
                recommended_fix=v.get("recommended_fix"),
                code_patch=v.get("code_patch"),
                status=v.get("status", "open"),
            )
            for v in vulns
        ]

    except Exception as e:
        logger.error(f"Failed to list vulnerabilities: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: str,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """Get detailed information about a specific vulnerability."""
    try:
        vuln = await orchestrator.get_vulnerability(vuln_id)
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        return VulnerabilityResponse(**vuln)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get vulnerability {vuln_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vulnerabilities/{vuln_id}/remediate")
async def trigger_remediation(
    vuln_id: str,
    auto_apply: bool = False,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """
    Trigger remediation for a specific vulnerability.

    If auto_apply=True, automatically creates fix merge request.
    If False, returns remediation plan for review.
    """
    try:
        result = await orchestrator.remediate_vulnerability(
            vulnerability_id=vuln_id,
            auto_apply=auto_apply,
        )

        return {
            "vulnerability_id": vuln_id,
            "status": result["status"],
            "pattern_applied": result.get("pattern_applied"),
            "fix_mr_url": result.get("fix_mr_url"),
            "diff": result.get("diff"),
            "message": result.get("message"),
        }

    except Exception as e:
        logger.error(
            f"Remediation failed for {vuln_id}: {e}",
            exc_info=True,
            extra={"component": "api"},
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/compliance/report", response_model=ComplianceReportResponse)
async def get_compliance_report(
    project_id: int,
    frameworks: Optional[str] = None,  # Comma-separated list
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """
    Generate compliance report for a project.

    Assesses vulnerabilities against regulatory frameworks:
    - SOX (Sarbanes-Oxley)
    - HIPAA (Healthcare)
    - GDPR (EU Data Protection)
    - PCI-DSS (Payment Card Industry)
    - ISO 27001 (Information Security)
    - NIST CSF (Cybersecurity Framework)
    """
    try:
        framework_list = None
        if frameworks:
            from core.models import ComplianceFramework
            framework_list = [
                ComplianceFramework(f.strip())
                for f in frameworks.split(",")
                if f.strip()
            ]

        report = await orchestrator.get_compliance_report(
            project_id=project_id,
            frameworks=framework_list,
        )

        return ComplianceReportResponse(
            project_id=report.project_id,
            overall_compliance_score=report.overall_compliance_score,
            frameworks_assessed=[f.value for f in report.frameworks_assessed],
            frameworks_compliant=sum(
                1 for s in report.framework_status.values() if s.is_compliant
            ),
            frameworks_total=len(report.framework_status),
            total_violations=len(report.gaps),
            status="COMPLIANT" if report.overall_compliance_score >= 0.95 else "NON-COMPLIANT",
            generated_at=report.generated_at,
        )

    except Exception as e:
        logger.error(
            f"Compliance report failed: {e}",
            exc_info=True,
            extra={"component": "api"},
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/compliance/audit", response_model=Dict[str, Any])
async def get_audit_report(
    project_id: int,
    include_evidence: bool = True,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """
    Generate comprehensive audit report for external auditors.

    Includes:
    - Executive summary
    - Framework compliance details
    - Violation listings
    - Remediation status
    - Evidence artifacts
    - Sign-off section
    """
    try:
        report = await orchestrator.generate_audit_report(
            project_id=project_id,
            include_evidence=include_evidence,
        )

        return report

    except Exception as e:
        logger.error(
            f"Audit report failed: {e}",
            exc_info=True,
            extra={"component": "api"},
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/monitoring/dashboard", response_model=DashboardMetricsResponse)
async def get_dashboard_metrics(
    project_id: int,
    time_range_minutes: int = 60,
    monitoring_agent: MonitoringAgent = Depends(get_monitoring_agent),
):
    """
    Get real-time dashboard metrics for UI visualization.

    Returns:
    - Current security metrics
    - Time-series data for charts
    - Active alerts
    - Trend indicators
    """
    try:
        dashboard = await monitoring_agent.get_dashboard_data(
            project_id=project_id,
            time_range_minutes=time_range_minutes,
        )

        return DashboardMetricsResponse(
            current_metrics=dashboard["current_metrics"],
            time_series=dashboard["time_series"],
            alerts=dashboard["alerts"],
            trends=dashboard["trends"],
            generated_at=datetime.utcnow(),
        )

    except Exception as e:
        logger.error(
            f"Dashboard metrics failed: {e}",
            exc_info=True,
            extra={"component": "api"},
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/monitoring/alerts")
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    monitoring_agent: MonitoringAgent = Depends(get_monitoring_agent),
):
    """List security alerts with optional filtering."""
    try:
        summary = monitoring_agent.get_alert_summary()

        # Filter alerts if requested
        alerts = [
            a for a in monitoring_agent._alerts.values()
            if (not status or a.status.value == status) and
               (not severity or a.severity.value == severity)
        ]

        return {
            "summary": summary,
            "alerts": [
                {
                    "id": a.alert_id,
                    "title": a.title,
                    "severity": a.severity.value,
                    "metric_name": a.metric_name,
                    "current_value": a.current_value,
                    "threshold": a.threshold_value,
                    "status": a.status.value,
                    "created_at": a.created_at.isoformat(),
                }
                for a in alerts
            ],
        }

    except Exception as e:
        logger.error(f"Failed to list alerts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    user: str = "system",
    comment: Optional[str] = None,
    monitoring_agent: MonitoringAgent = Depends(get_monitoring_agent),
):
    """Acknowledge an alert."""
    success = await monitoring_agent.acknowledge_alert(alert_id, user, comment)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"status": "acknowledged", "alert_id": alert_id}


@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    user: str = "system",
    resolution: str = "Resolved by SecurAI Guardian",
    monitoring_agent: MonitoringAgent = Depends(get_monitoring_agent),
):
    """Manually resolve an alert."""
    success = await monitoring_agent.resolve_alert(alert_id, user, resolution)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"status": "resolved", "alert_id": alert_id}


@app.get("/api/v1/knowledge-graph/project/{project_id}")
async def get_project_context(
    project_id: int,
    kg_agent: KnowledgeGraphAgent = Depends(get_kg_agent),
):
    """Get comprehensive context for a project from knowledge graph."""
    try:
        context = await kg_agent.get_project_context(project_id)
        if not context:
            raise HTTPException(status_code=404, detail="Project not found in knowledge graph")

        return context.dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Failed to get project context: {e}",
            exc_info=True,
            extra={"component": "api"},
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/knowledge-graph/query")
async def query_knowledge_graph(
    project_id: int,
    query: str,
    node_types: Optional[str] = None,
    limit: int = 20,
    kg_agent: KnowledgeGraphAgent = Depends(get_kg_agent),
):
    """
    Query knowledge graph using natural language.

    Performs semantic search over stored security data.
    """
    try:
        node_type_list = None
        if node_types:
            node_type_list = [t.strip() for t in node_types.split(",")]

        results = await kg_agent.query_context(
            project_id=project_id,
            query=query,
            node_types=node_type_list,
            limit=limit,
        )

        return {
            "query": query,
            "results_count": len(results),
            "results": results,
        }

    except Exception as e:
        logger.error(
            f"Knowledge graph query failed: {e}",
            exc_info=True,
            extra={"component": "api"},
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/agents/health")
async def get_agents_health(
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """Get health status of all agents."""
    try:
        health = await orchestrator.health_check()
        return health

    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/agents/statistics")
async def get_agents_statistics(
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """Get statistics from all agents for monitoring."""
    try:
        stats = await orchestrator.get_statistics()
        return stats

    except Exception as e:
        logger.error(f"Failed to get statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/gitlab/webhook")
async def handle_gitlab_webhook(
    request: Dict[str, Any],
    background_tasks: BackgroundTasks,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator),
):
    """
    Handle GitLab webhook events.

    Supported events:
    - Merge request events (opened, updated, merged)
    - Pipeline events (completed)
    - Security scan events

    Automatically triggers security scans on relevant events.
    """
    try:
        event_type = request.get("object_kind")
        project_id = request.get("project", {}).get("id")

        if not project_id:
            raise HTTPException(status_code=400, detail="Missing project ID")

        logger.info(
            f"Webhook received: {event_type} for project {project_id}",
            extra={"component": "api", "webhook": event_type},
        )

        # Handle different event types
        if event_type == "merge_request":
            mr_iid = request.get("object_attributes", {}).get("iid")
            if mr_iid and request.get("object_attributes", {}).get("state") == "opened":
                # Auto-scan new MRs
                background_tasks.add_task(
                    orchestrator.execute_scan_pipeline,
                    project_id=project_id,
                    mr_iid=mr_iid,
                    auto_remediate=settings.auto_remediate_enabled,
                )

        elif event_type == "pipeline":
            pipeline_status = request.get("object_attributes", {}).get("status")
            if pipeline_status == "success":
                # Scan after successful pipeline
                pipeline_id = request.get("object_attributes", {}).get("id")
                background_tasks.add_task(
                    orchestrator.execute_scan_pipeline,
                    project_id=project_id,
                        pipeline_id=pipeline_id,
                    auto_remediate=settings.auto_remediate_enabled,
                )

        elif event_type == "push":
            # Optionally scan on push
            pass

        return {"status": "accepted", "event": event_type}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Webhook processing failed: {e}",
            exc_info=True,
            extra={"component": "api"},
        )
        raise HTTPException(status_code=500, detail=str(e))


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return {
        "error": exc.detail,
        "status_code": exc.status_code,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return {
        "error": "Internal server error",
        "status_code": 500,
        "timestamp": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="info",
    )
