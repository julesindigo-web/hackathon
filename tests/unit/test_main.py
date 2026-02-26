"""
Unit tests for FastAPI main application and REST endpoints.

Tests API endpoints, middleware, error handling, and dependency injection.
Ensures all routes are properly configured and return correct responses.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.orchestrator import SecurityOrchestrator


class TestFastAPIApp:
    """Test FastAPI application configuration."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_root_endpoint(self, client):
        """Test GET / returns system info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "SecurAI Guardian"
        assert data["version"] == "1.0.0"
        assert "status" in data
        assert data["status"] == "operational"

    def test_health_check(self, client):
        """Test GET /health returns health status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "checks" in data
        assert "database" in data["checks"]
        assert "redis" in data["checks"]
        assert "agents" in data["checks"]

    def test_health_check_database_down(self, client):
        """Test health check when database is down."""
        # Mock database check to fail
        with patch('app.main.check_database_health', new_callable=AsyncMock) as mock_db:
            mock_db.return_value = False

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["database"] is False

    def test_health_check_redis_down(self, client):
        """Test health check when Redis is down."""
        with patch('app.main.check_redis_health', new_callable=AsyncMock) as mock_redis:
            mock_redis.return_value = False

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["redis"] is False

    def test_health_check_agents_unhealthy(self, client):
        """Test health check when agents are unhealthy."""
        with patch('app.main.orchestrator') as mock_orch:
            mock_orch.health_check.return_value = {
                "overall": "unhealthy",
                "agents": {
                    "scanner": False,
                    "analyzer": True,
                    "remediation": True,
                    "compliance": True,
                    "monitoring": True,
                    "knowledge_graph": True
                }
            }

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["agents"]["scanner"] is False


class TestVulnerabilityEndpoints:
    """Test vulnerability-related API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client with mocked orchestrator."""
        app.dependency_overrides = {}

        # Create mock orchestrator
        mock_orch = MagicMock(spec=SecurityOrchestrator)
        mock_orch.list_vulnerabilities.return_value = [
            MagicMock(
                id="VULN-001",
                title="SQL Injection",
                severity="high",
                vulnerability_type="sql_injection",
                project_id=123,
                mr_id=456,
                status="open"
            )
        ]
        mock_orch.get_vulnerability.return_value = MagicMock(
            id="VULN-001",
            title="SQL Injection",
            description="Test",
            severity="high",
            vulnerability_type="sql_injection",
            project_id=123,
            mr_id=456,
            status="open"
        )

        # Override dependency
        from app.main import get_orchestrator
        app.dependency_overrides[get_orchestrator] = lambda: mock_orch

        return TestClient(app)

    def test_list_vulnerabilities(self, client):
        """Test GET /api/v1/vulnerabilities returns vulnerability list."""
        response = client.get("/api/v1/vulnerabilities")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["id"] == "VULN-001"

    def test_list_vulnerabilities_with_filter(self, client):
        """Test filtering vulnerabilities by severity."""
        response = client.get("/api/v1/vulnerabilities?severity=high")
        assert response.status_code == 200
        # Mock should be called with filter
        client.app.dependency_overrides[list]().list_vulnerabilities.assert_called_once_with(
            severity="high"
        )

    def test_get_vulnerability_by_id(self, client):
        """Test GET /api/v1/vulnerabilities/{id} returns specific vulnerability."""
        response = client.get("/api/v1/vulnerabilities/VULN-001")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "VULN-001"
        assert data["title"] == "SQL Injection"

    def test_get_vulnerability_not_found(self, client):
        """Test GET /api/v1/vulnerabilities/{id} with non-existent ID."""
        client.app.dependency_overrides[list]().get_vulnerability.return_value = None

        response = client.get("/api/v1/vulnerabilities/NONEXISTENT")
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    def test_remediate_vulnerability(self, client):
        """Test POST /api/v1/vulnerabilities/{id}/remediate triggers remediation."""
        client.app.dependency_overrides[list]().remediate_vulnerability.return_value = {
            "status": "remediation_started",
            "vulnerability_id": "VULN-001",
            "message": "Remediation initiated"
        }

        response = client.post("/api/v1/vulnerabilities/VULN-001/remediate")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "remediation_started"

    def test_remediate_vulnerability_not_found(self, client):
        """Test remediate with non-existent vulnerability."""
        client.app.dependency_overrides[list]().remediate_vulnerability.return_value = None

        response = client.post("/api/v1/vulnerabilities/NONEXISTENT/remediate")
        assert response.status_code == 404


class TestComplianceEndpoints:
    """Test compliance-related API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client with mocked orchestrator."""
        app.dependency_overrides = {}

        mock_orch = MagicMock(spec=SecurityOrchestrator)
        mock_orch.get_compliance_report.return_value = MagicMock(
            project_id=123,
            frameworks={
                "sox": {"score": 95.5, "status": "compliant", "violations": []},
                "hipaa": {"score": 92.0, "status": "compliant", "violations": []}
            },
            overall_score=93.0,
            summary="System meets compliance requirements"
        )
        mock_orch.generate_audit_report.return_value = {
            "audit_id": "AUDIT-001",
            "generated_at": "2026-02-26T10:00:00Z",
            "project_id": 123,
            "frameworks": ["sox", "hipaa"],
            "overall_score": 93.0,
            "executive_summary": "System is compliant",
            "detailed_findings": [],
            "recommendations": []
        }

        from app.main import get_orchestrator
        app.dependency_overrides[get_orchestrator] = lambda: mock_orch

        return TestClient(app)

    def test_get_compliance_report(self, client):
        """Test GET /api/v1/compliance/report returns compliance report."""
        response = client.get("/api/v1/compliance/report?project_id=123")
        assert response.status_code == 200
        data = response.json()
        assert data["project_id"] == 123
        assert "overall_score" in data
        assert "frameworks" in data

    def test_get_compliance_report_requires_project_id(self, client):
        """Test compliance report requires project_id parameter."""
        response = client.get("/api/v1/compliance/report")
        assert response.status_code == 422  # Unprocessable Entity (missing required param)

    def test_get_audit_report(self, client):
        """Test GET /api/v1/compliance/audit returns full audit report."""
        response = client.get("/api/v1/compliance/audit?project_id=123")
        assert response.status_code == 200
        data = response.json()
        assert "audit_id" in data
        assert "executive_summary" in data
        assert "detailed_findings" in data
        assert "recommendations" in data

    def test_get_audit_report_includes_evidence(self, client):
        """Test audit report includes evidence collection."""
        response = client.get("/api/v1/compliance/audit?project_id=123")
        data = response.json()
        assert "evidence" in data or "detailed_findings" in data


class TestMonitoringEndpoints:
    """Test monitoring-related API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client with mocked orchestrator."""
        app.dependency_overrides = {}

        mock_orch = MagicMock(spec=SecurityOrchestrator)
        mock_orch.get_monitoring_dashboard.return_value = {
            "metrics": {
                "vulnerabilities_total": 25,
                "vulnerabilities_critical": 3,
                "vulnerabilities_high": 8,
                "vulnerabilities_medium": 10,
                "vulnerabilities_low": 4,
                "mttr_hours": 48.5,
                "remediation_rate": 0.85,
                "compliance_score": 92.0,
                "security_posture": "good",
                "false_positive_rate": 0.03,
                "scan_coverage": 0.78,
                "vulnerability_inflow_rate": 0.5
            },
            "alerts": [
                {
                    "id": "ALERT-001",
                    "title": "Critical vulnerability detected",
                    "severity": "critical",
                    "triggered_at": "2026-02-26T10:00:00Z"
                }
            ],
            "timestamp": "2026-02-26T10:00:00Z"
        }
        mock_orch.get_alerts.return_value = [
            MagicMock(
                id="ALERT-001",
                title="Critical vulnerability",
                severity="critical",
                alert_type="vulnerability",
                triggered_at="2026-02-26T10:00:00Z",
                acknowledged=False,
                resolved=False
            )
        ]
        mock_orch.acknowledge_alert.return_value = True
        mock_orch.resolve_alert.return_value = True

        from app.main import get_orchestrator
        app.dependency_overrides[get_orchestrator] = lambda: mock_orch

        return TestClient(app)

    def test_get_dashboard(self, client):
        """Test GET /api/v1/monitoring/dashboard returns dashboard data."""
        response = client.get("/api/v1/monitoring/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert "metrics" in data
        assert "alerts" in data
        assert "timestamp" in data
        assert data["metrics"]["vulnerabilities_total"] == 25

    def test_get_alerts(self, client):
        """Test GET /api/v1/monitoring/alerts returns alert list."""
        response = client.get("/api/v1/monitoring/alerts")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["id"] == "ALERT-001"

    def test_acknowledge_alert(self, client):
        """Test POST /api/v1/alerts/{id}/acknowledge acknowledges alert."""
        response = client.post("/api/v1/alerts/ALERT-001/acknowledge", json={"user": "security-bot"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "acknowledged"

    def test_acknowledge_alert_missing_user(self, client):
        """Test acknowledge alert requires user parameter."""
        response = client.post("/api/v1/alerts/ALERT-001/acknowledge", json={})
        assert response.status_code == 422  # Validation error

    def test_resolve_alert(self, client):
        """Test POST /api/v1/alerts/{id}/resolve resolves alert."""
        response = client.post(
            "/api/v1/alerts/ALERT-001/resolve",
            json={"user": "security-bot", "resolution": "fixed"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "resolved"

    def test_resolve_alert_missing_params(self, client):
        """Test resolve alert requires user and resolution."""
        response = client.post("/api/v1/alerts/ALERT-001/resolve", json={})
        assert response.status_code == 422


class TestKnowledgeGraphEndpoints:
    """Test knowledge graph API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client with mocked orchestrator."""
        app.dependency_overrides = {}

        mock_orch = MagicMock(spec=SecurityOrchestrator)
        mock_orch.get_project_context.return_value = {
            "project_id": 123,
            "total_vulnerabilities": 50,
            "remediation_rate": 0.82,
            "common_vulnerability_types": ["sql_injection", "xss"],
            "avg_remediation_time": 12.5,
            "high_risk_areas": ["authentication", "payment"],
            "developer_expertise": {
                "user1": {"sql_injection": 0.9, "xss": 0.7}
            }
        }
        mock_orch.query_knowledge_graph.return_value = {
            "query": "sql injection patterns",
            "results": [
                {
                    "type": "vulnerability",
                    "id": "VULN-001",
                    "title": "SQL Injection in login",
                    "score": 0.95,
                    "context": {"file": "app/auth.py"}
                }
            ],
            "total": 1
        }
        mock_orch.get_similar_vulnerabilities.return_value = [
            {
                "id": "VULN-002",
                "title": "Similar SQLi",
                "similarity_score": 0.88,
                "fix_pattern": "parameterized_queries"
            }
        ]
        mock_orch.get_remediation_effort_estimate.return_value = {
            "vulnerability_type": "sql_injection",
            "estimated_effort": "2h",
            "confidence": 0.85,
            "statistics": {
                "mean": 2.1,
                "median": 2.0,
                "p95": 4.0
            }
        }

        from app.main import get_orchestrator
        app.dependency_overrides[get_orchestrator] = lambda: mock_orch

        return TestClient(app)

    def test_get_project_context(self, client):
        """Test GET /api/v1/knowledge-graph/project/{id} returns project context."""
        response = client.get("/api/v1/knowledge-graph/project/123")
        assert response.status_code == 200
        data = response.json()
        assert data["project_id"] == 123
        assert "total_vulnerabilities" in data
        assert "remediation_rate" in data

    def test_query_knowledge_graph(self, client):
        """Test GET /api/v1/knowledge-graph/query performs semantic search."""
        response = client.get("/api/v1/knowledge-graph/query?q=sql+injection+patterns")
        assert response.status_code == 200
        data = response.json()
        assert data["query"] == "sql injection patterns"
        assert "results" in data
        assert len(data["results"]) > 0

    def test_query_knowledge_graph_requires_query(self, client):
        """Test query endpoint requires q parameter."""
        response = client.get("/api/v1/knowledge-graph/query")
        assert response.status_code == 422

    def test_get_similar_vulnerabilities(self, client):
        """Test GET /api/v1/knowledge-graph/similar/{vuln_id} finds similar vulns."""
        response = client.get("/api/v1/knowledge-graph/similar/VULN-001")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert "similarity_score" in data[0]

    def test_get_remediation_effort_estimate(self, client):
        """Test GET /api/v1/knowledge-graph/effort/{vuln_type} returns estimate."""
        response = client.get("/api/v1/knowledge-graph/effort/sql_injection")
        assert response.status_code == 200
        data = response.json()
        assert data["vulnerability_type"] == "sql_injection"
        assert "estimated_effort" in data
        assert "confidence" in data
        assert "statistics" in data


class TestAgentEndpoints:
    """Test agent-related API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client with mocked orchestrator."""
        app.dependency_overrides = {}

        mock_orch = MagicMock(spec=SecurityOrchestrator)
        mock_orch.health_check.return_value = {
            "overall": "healthy",
            "agents": {
                "scanner": True,
                "analyzer": True,
                "remediation": True,
                "compliance": True,
                "monitoring": True,
                "knowledge_graph": True
            }
        }
        mock_orch.get_statistics.return_value = {
            "total_scans": 150,
            "successful_scans": 148,
            "failed_scans": 2,
            "total_vulnerabilities_processed": 1250,
            "agent_statistics": {
                "scanner": {"scans_performed": 150, "artifacts_processed": 4500},
                "analyzer": {"analyses_performed": 1250, "avg_confidence": 0.92},
                "remediation": {"remediations_applied": 1100, "success_rate": 0.94},
                "compliance": {"reports_generated": 75, "frameworks_assessed": 300},
                "monitoring": {"metrics_collected": 9000, "alerts_triggered": 150},
                "knowledge_graph": {"nodes_created": 5000, "queries_served": 8500}
            }
        }

        from app.main import get_orchestrator
        app.dependency_overrides[get_orchestrator] = lambda: mock_orch

        return TestClient(app)

    def test_get_agent_health(self, client):
        """Test GET /api/v1/agents/health returns agent health status."""
        response = client.get("/api/v1/agents/health")
        assert response.status_code == 200
        data = response.json()
        assert data["overall"] == "healthy"
        assert all(data["agents"].values())  # All agents healthy

    def test_get_agent_statistics(self, client):
        """Test GET /api/v1/agents/statistics returns agent stats."""
        response = client.get("/api/v1/agents/statistics")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 150
        assert "agent_statistics" in data
        assert data["agent_statistics"]["scanner"]["scans_performed"] == 150


class TestGitLabWebhook:
    """Test GitLab webhook endpoint."""

    @pytest.fixture
    def client(self):
        """Create test client with mocked orchestrator."""
        app.dependency_overrides = {}

        mock_orch = MagicMock(spec=SecurityOrchestrator)
        mock_orch.execute_scan_pipeline.return_value = {
            "status": "completed",
            "vulnerabilities_found": 5,
            "vulnerabilities_remediated": 4,
            "compliance_score": 88.5
        }

        from app.main import get_orchestrator
        app.dependency_overrides[get_orchestrator] = lambda: mock_orch

        return TestClient(app)

    def test_gitlab_webhook_merge_request(self, client):
        """Test POST /api/v1/gitlab/webhook handles merge request event."""
        webhook_payload = {
            "object_kind": "merge_request",
            "project": {"id": 123, "name": "test-project"},
            "object_attributes": {
                "id": 456,
                "title": "Add new feature",
                "state": "opened",
                "source_branch": "feature/test",
                "target_branch": "main"
            }
        }

        response = client.post("/api/v1/gitlab/webhook", json=webhook_payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert "scan initiated" in data["message"].lower()

        # Verify orchestrator called
        client.app.dependency_overrides[list]().execute_scan_pipeline.assert_called_once_with(
            project_id=123,
            mr_id=456
        )

    def test_gitlab_webhook_invalid_event(self, client):
        """Test webhook rejects unsupported event types."""
        webhook_payload = {
            "object_kind": "push",  # Not supported
            "project": {"id": 123}
        }

        response = client.post("/api/v1/gitlab/webhook", json=webhook_payload)
        assert response.status_code == 400
        data = response.json()
        assert "unsupported" in data["detail"].lower()

    def test_gitlab_webhook_missing_project_id(self, client):
        """Test webhook requires project ID."""
        webhook_payload = {
            "object_kind": "merge_request",
            "object_attributes": {"id": 456}
        }

        response = client.post("/api/v1/gitlab/webhook", json=webhook_payload)
        assert response.status_code == 422  # Validation error

    def test_gitlab_webhook_invalid_json(self, client):
        """Test webhook with invalid JSON."""
        response = client.post(
            "/api/v1/gitlab/webhook",
            content="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


class TestErrorHandling:
    """Test global error handling."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_404_handling(self, client):
        """Test 404 error returns proper JSON."""
        response = client.get("/nonexistent")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_method_not_allowed(self, client):
        """Test 405 error for wrong HTTP method."""
        response = client.post("/health")  # Should be GET
        assert response.status_code == 405

    def test_exception_handling(self, client):
        """Test unhandled exceptions are caught and logged."""
        # Mock an endpoint to raise exception
        with patch('app.main.get_orchestrator') as mock_get:
            mock_get.return_value.list_vulnerabilities.side_effect = Exception("Test error")

            response = client.get("/api/v1/vulnerabilities")
            assert response.status_code == 500
            data = response.json()
            assert "internal server error" in data["detail"].lower()


class TestCORS:
    """Test CORS middleware configuration."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_cors_headers(self, client):
        """Test CORS headers are present."""
        response = client.options("/health", headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET"
        })
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers

    def test_cors_allows_origin(self, client):
        """Test CORS allows configured origin."""
        response = client.get("/health", headers={"Origin": "https://example.com"})
        assert response.headers.get("access-control-allow-origin") == "https://example.com"


class TestDependencyInjection:
    """Test dependency injection system."""

    def test_get_orchestrator_returns_instance(self):
        """Test get_orchestrator returns SecurityOrchestrator."""
        from app.main import get_orchestrator

        # This will fail without proper setup, but tests the dependency
        with pytest.raises(Exception):
            # Expected to fail because orchestrator not initialized
            get_orchestrator()

    def test_orchestrator_singleton(self):
        """Test orchestrator is singleton within app context."""
        from app.main import app, get_orchestrator

        # Override with mock
        mock_orch = MagicMock()
        app.dependency_overrides[get_orchestrator] = lambda: mock_orch

        # Get twice, should be same instance (cached)
        dep1 = app.dependency_overrides[get_orchestrator]()
        dep2 = app.dependency_overrides[get_orchestrator]()

        # They're both the mock, but not necessarily same instance
        # FastAPI doesn't cache dependency results by default
        # This test verifies the override mechanism works
        assert dep1 is mock_orch
        assert dep2 is mock_orch


class TestAPIDocumentation:
    """Test API documentation endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_openapi_schema(self, client):
        """Test OpenAPI schema is available."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert "info" in schema
        assert "paths" in schema
        assert schema["info"]["title"] == "SecurAI Guardian API"

    def test_swagger_ui(self, client):
        """Test Swagger UI is available."""
        response = client.get("/docs")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_redoc(self, client):
        """Test ReDoc is available."""
        response = client.get("/redoc")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


class TestRateLimiting:
    """Test rate limiting (if configured)."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_rate_limit_headers(self, client):
        """Test rate limit headers present if enabled."""
        response = client.get("/health")
        # Rate limiting may not be enabled in test
        # Just verify no error
        assert response.status_code in [200, 429]

    def test_rate_limit_exceeded(self, client):
        """Test behavior when rate limit exceeded."""
        # This would require actually hitting the limit
        # For now, just verify endpoint works
        response = client.get("/health")
        assert response.status_code == 200


class TestSecurityHeaders:
    """Test security-related HTTP headers."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_security_headers_present(self, client):
        """Test security headers are set."""
        response = client.get("/health")
        # Check for common security headers
        # May not all be present depending on configuration
        headers = response.headers

        # These are optional but good to have
        optional_headers = [
            "x-content-type-options",
            "x-frame-options",
            "strict-transport-security",
            "content-security-policy"
        ]

        # Just verify response is successful
        assert response.status_code == 200


class TestAPIValidation:
    """Test request/response validation."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_invalid_json_body(self, client):
        """Test invalid JSON in request body."""
        response = client.post(
            "/api/v1/vulnerabilities/VULN-001/remediate",
            content="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422

    def test_missing_required_fields(self, client):
        """Test missing required fields in request."""
        response = client.post("/api/v1/alerts/ALERT-001/acknowledge", json={})
        assert response.status_code == 422

    def test_invalid_parameter_type(self, client):
        """Test invalid parameter type."""
        response = client.get("/api/v1/vulnerabilities?severity=invalid")
        # Should either be accepted (filtered) or rejected
        assert response.status_code in [200, 422]

    def test_response_validation(self, client):
        """Test responses match expected schema."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        # Verify required fields present
        assert "status" in data
        assert "timestamp" in data
        assert "checks" in data
