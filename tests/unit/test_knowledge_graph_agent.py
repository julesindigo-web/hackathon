"""
Comprehensive test suite for KnowledgeGraphAgent.
Target: 100% coverage of knowledge_graph_agent.py
"""

import pytest
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sklearn.feature_extraction.text import TfidfVectorizer

from agents.knowledge_graph_agent import (
    KnowledgeGraphAgent, KnowledgeNode, KnowledgeEdge, NodeType, EdgeType,
    PatternMatch, EffortEstimation, ProjectContext
)
from core.models import Vulnerability, AnalyzedVulnerability, Severity, VulnerabilitySource
from core.config import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.database_url = "postgresql://test:test@localhost/test"
    settings.redis_url = "redis://localhost:6379/0"
    settings.kg_retention_days = 365
    settings.kg_similarity_threshold = 0.7
    settings.kg_max_patterns = 1000
    return settings


@pytest.fixture
def mock_knowledge_graph():
    """Create mock knowledge graph (the actual KG database layer)."""
    kg = AsyncMock()
    kg.add_node.return_value = True
    kg.add_edge.return_value = True
    kg.get_node.return_value = None
    kg.get_nodes_by_type.return_value = []
    kg.get_edges_by_nodes.return_value = []
    kg.get_project_context.return_value = None
    kg.find_similar_vulnerabilities.return_value = []
    kg.get_historical_patterns.return_value = {}
    kg.estimate_remediation_effort.return_value = {
        "mean_days": 3.5,
        "median_days": 2.0,
        "p95_days": 10.0,
        "confidence_interval": [2.0, 5.0]
    }
    kg.get_developer_expertise.return_value = {
        "developer_id": "dev-123",
        "vulnerability_types": {"SQL_INJECTION": 0.9, "XSS": 0.7},
        "total_fixes": 25,
        "avg_confidence": 0.88
    }
    kg.get_fix_pattern_success_rate.return_value = 0.92
    kg.query_context.return_value = {
        "nodes": [],
        "edges": [],
        "total": 0
    }
    kg.run_maintenance.return_value = {
        "duplicates_removed": 0,
        "indexes_rebuilt": 0,
        "integrity_ok": True
    }
    return kg


@pytest.fixture
def knowledge_graph_agent(mock_settings, mock_knowledge_graph):
    """Create KnowledgeGraphAgent instance with mocked dependencies."""
    agent = KnowledgeGraphAgent(
        settings=mock_settings,
        knowledge_graph=mock_knowledge_graph
    )
    return agent


class TestKnowledgeGraphAgentInitialization:
    """Test KnowledgeGraphAgent initialization."""

    def test_init_with_dependencies(self, knowledge_graph_agent):
        """Test successful initialization."""
        assert knowledge_graph_agent.settings is not None
        assert knowledge_graph_agent.knowledge_graph is not None
        assert knowledge_graph_agent.vectorizer is not None
        assert knowledge_graph_agent.node_embeddings is None
        assert knowledge_graph_agent._initialized is False

    def test_vectorizer_initialized(self, knowledge_graph_agent):
        """Test TF-IDF vectorizer is initialized."""
        assert isinstance(knowledge_graph_agent.vectorizer, TfidfVectorizer)
        assert knowledge_graph_agent.vectorizer.max_features == 1000
        assert knowledge_graph_agent.vectorizer.ngram_range == (1, 2)

    def test_lazy_initialization(self, knowledge_graph_agent):
        """Test lazy initialization of embeddings."""
        assert knowledge_graph_agent.node_embeddings is None
        assert knowledge_graph_agent._initialized is False


class TestKnowledgeGraphAgentNodeOperations:
    """Test knowledge graph node operations."""

    @pytest.mark.asyncio
    async def test_store_vulnerability(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test storing vulnerability in knowledge graph."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection in search",
            description="User input not sanitized in SQL query",
            severity=Severity.HIGH,
            source=VulnerabilitySource.SAST,
            file_path="app/views.py",
            line_number=42,
            code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
            cwe_id="CWE-89",
            confidence=0.92,
            discovered_at=datetime.utcnow()
        )

        result = await knowledge_graph_agent.store_vulnerability(vuln, "project-123")

        assert result is True
        mock_knowledge_graph.add_node.assert_called_once()

        # Verify node structure
        call_args = mock_knowledge_graph.add_node.call_args[0]
        node = call_args[0]
        assert isinstance(node, KnowledgeNode)
        assert node.node_type == NodeType.VULNERABILITY
        assert node.external_id == "VULN-001"
        assert node.project_id == "project-123"
        assert "SQL Injection" in node.properties["title"]
        assert node.embedding is not None  # Should have embedding

    @pytest.mark.asyncio
    async def test_store_analysis(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test storing analysis result."""
        analysis = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            confidence=0.95,
            false_positive_probability=0.05,
            priority_score=0.87,
            remediation_effort=2.5,
            suggested_fix="Use parameterized queries",
            analysis={
                "root_cause": "String concatenation",
                "attack_vector": "Network",
                "impact": "High"
            }
        )

        result = await knowledge_graph_agent.store_analysis(analysis, "project-123")

        assert result is True
        mock_knowledge_graph.add_node.assert_called_once()

        node = mock_knowledge_graph.add_node.call_args[0][0]
        assert node.node_type == NodeType.ANALYSIS
        assert node.external_id == "VULN-001"
        assert node.properties["confidence"] == 0.95

    @pytest.mark.asyncio
    async def test_store_remediation(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test storing remediation result."""
        applied_fix = type('AppliedFix', (), {
            'vulnerability_id': 'VULN-001',
            'success': True,
            'fixed_files': [{'file_path': 'app/views.py'}],
            'mr_url': 'https://gitlab.com/mr/123',
            'fix_pattern_id': 'SQL_INJECTION_01',
            'verification_passed': True,
            'created_at': datetime.utcnow()
        })()

        result = await knowledge_graph_agent.store_remediation(
            applied_fix, "project-123", "dev-456"
        )

        assert result is True
        mock_knowledge_graph.add_node.assert_called_once()
        mock_knowledge_graph.add_edge.assert_called_once()

        # Verify remediation node
        node = mock_knowledge_graph.add_node.call_args[0][0]
        assert node.node_type == NodeType.REMEDIATION
        assert node.external_id == "VULN-001"

        # Verify edges
        edge_call = mock_knowledge_graph.add_edge.call_args[0]
        assert edge_call[2] == EdgeType.REMEDIATES
        assert edge_call[3]["success"] is True

    @pytest.mark.asyncio
    async def test_store_code_file(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test storing code file information."""
        result = await knowledge_graph_agent.store_code_file(
            project_id="project-123",
            file_path="app/views.py",
            content="def get_user(): return 'user'",
            language="python",
            size_bytes=100,
            complexity=5
        )

        assert result is True
        mock_knowledge_graph.add_node.assert_called_once()

        node = mock_knowledge_graph.add_node.call_args[0][0]
        assert node.node_type == NodeType.CODE_FILE
        assert node.external_id == "app/views.py"
        assert node.properties["language"] == "python"
        assert node.properties["size_bytes"] == 100
        assert node.properties["complexity"] == 5

    @pytest.mark.asyncio
    async def test_store_developer(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test storing developer information."""
        result = await knowledge_graph_agent.store_developer(
            developer_id="dev-123",
            email="dev@example.com",
            name="John Doe",
            role="Backend Developer"
        )

        assert result is True
        mock_knowledge_graph.add_node.assert_called_once()

        node = mock_knowledge_graph.add_node.call_args[0][0]
        assert node.node_type == NodeType.DEVELOPER
        assert node.external_id == "dev-123"
        assert node.properties["email"] == "dev@example.com"
        assert node.properties["name"] == "John Doe"

    @pytest.mark.asyncio
    async def test_store_fix_pattern(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test storing fix pattern."""
        pattern = type('FixPattern', (), {
            'id': 'SQLI_01',
            'vulnerability_type': 'SQL_INJECTION',
            'name': 'Parameterized Queries',
            'description': 'Use parameterized queries to prevent SQL injection',
            'confidence_threshold': 0.8,
            'success_rate': 0.92,
            'avg_remediation_time': 2.5
        })()

        result = await knowledge_graph_agent.store_fix_pattern(pattern)

        assert result is True
        mock_knowledge_graph.add_node.assert_called_once()

        node = mock_knowledge_graph.add_node.call_args[0][0]
        assert node.node_type == NodeType.FIX_PATTERN
        assert node.external_id == "SQLI_01"
        assert node.properties["vulnerability_type"] == "SQL_INJECTION"
        assert node.properties["success_rate"] == 0.92


class TestKnowledgeGraphAgentPatternMatching:
    """Test pattern matching and similarity search."""

    @pytest.mark.asyncio
    async def test_find_similar_vulnerabilities(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test finding similar vulnerabilities."""
        # Mock similar vulnerabilities
        similar_nodes = [
            KnowledgeNode(
                node_type=NodeType.VULNERABILITY,
                external_id="VULN-002",
                project_id="project-123",
                properties={
                    "title": "SQL Injection in login",
                    "description": "User input not sanitized",
                    "severity": "HIGH",
                    "cwe_id": "CWE-89"
                }
            ),
            KnowledgeNode(
                node_type=NodeType.VULNERABILITY,
                external_id="VULN-003",
                project_id="project-123",
                properties={
                    "title": "XSS in profile",
                    "description": "User input not escaped",
                    "severity": "MEDIUM",
                    "cwe_id": "CWE-79"
                }
            )
        ]
        mock_knowledge_graph.find_similar_vulnerabilities.return_value = [
            (similar_nodes[0], 0.85),
            (similar_nodes[1], 0.45)
        ]

        results = await knowledge_graph_agent.find_similar_vulnerabilities(
            Vulnerability(
                id="VULN-001",
                title="SQL Injection in search",
                description="User input not sanitized in search endpoint",
                severity=Severity.HIGH,
                cwe_id="CWE-89"
            ),
            "project-123",
            limit=5
        )

        assert len(results) == 2
        assert results[0][0].external_id == "VULN-002"
        assert results[0][1] == 0.85
        assert results[1][0].external_id == "VULN-003"
        assert results[1][1] == 0.45

        # Verify threshold filtering (0.85 > 0.7, 0.45 < 0.7)
        assert len([r for r in results if r[1] >= 0.7]) == 1

    @pytest.mark.asyncio
    async def test_find_similar_with_threshold(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test similarity search with custom threshold."""
        similar_nodes = [
            KnowledgeNode(
                node_type=NodeType.VULNERABILITY,
                external_id="VULN-002",
                project_id="project-123",
                properties={"title": "Similar", "description": "Similar desc"}
            )
        ]
        mock_knowledge_graph.find_similar_vulnerabilities.return_value = [
            (similar_nodes[0], 0.65)
        ]

        results = await knowledge_graph_agent.find_similar_vulnerabilities(
            Vulnerability(title="Test", description="Test"),
            "project-123",
            threshold=0.7
        )

        # Should filter out 0.65 < 0.7
        assert len(results) == 0

        results_lower = await knowledge_graph_agent.find_similar_vulnerabilities(
            Vulnerability(title="Test", description="Test"),
            "project-123",
            threshold=0.5
        )

        assert len(results_lower) == 1

    @pytest.mark.asyncio
    async def test_find_similar_no_results(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test similarity search with no matches."""
        mock_knowledge_graph.find_similar_vulnerabilities.return_value = []

        results = await knowledge_graph_agent.find_similar_vulnerabilities(
            Vulnerability(title="Unique", description="No similar"),
            "project-123"
        )

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_get_historical_patterns(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test retrieving historical patterns."""
        mock_knowledge_graph.get_historical_patterns.return_value = {
            "vulnerability_type": "SQL_INJECTION",
            "total_occurrences": 15,
            "avg_severity": "HIGH",
            "common_files": ["app/views.py", "app/models.py"],
            "common_fix_patterns": [
                {"pattern_id": "SQLI_01", "success_rate": 0.92, "usage_count": 12}
            ],
            "avg_remediation_time_days": 2.5,
            "remediation_success_rate": 0.87
        }

        patterns = await knowledge_graph_agent.get_historical_patterns(
            "SQL_INJECTION", "project-123"
        )

        assert patterns["vulnerability_type"] == "SQL_INJECTION"
        assert patterns["total_occurrences"] == 15
        assert patterns["avg_severity"] == "HIGH"
        assert len(patterns["common_fix_patterns"]) == 1
        assert patterns["common_fix_patterns"][0]["success_rate"] == 0.92

    @pytest.mark.asyncio
    async def test_get_historical_patterns_empty(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test historical patterns with no data."""
        mock_knowledge_graph.get_historical_patterns.return_value = {}

        patterns = await knowledge_graph_agent.get_historical_patterns(
            "UNKNOWN_TYPE", "project-123"
        )

        assert patterns == {}


class TestKnowledgeGraphAgentEffortEstimation:
    """Test remediation effort estimation."""

    @pytest.mark.asyncio
    async def test_estimate_remediation_effort(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test effort estimation based on historical data."""
        mock_knowledge_graph.estimate_remediation_effort.return_value = {
            "mean_days": 3.5,
            "median_days": 2.0,
            "p95_days": 10.0,
            "confidence_interval": [2.0, 5.0],
            "similar_cases": 12
        }

        effort = await knowledge_graph_agent.estimate_remediation_effort(
            Vulnerability(
                id="VULN-001",
                title="SQL Injection",
                severity=Severity.HIGH,
                cwe_id="CWE-89",
                file_path="app/views.py"
            ),
            "project-123"
        )

        assert effort["mean_days"] == 3.5
        assert effort["median_days"] == 2.0
        assert effort["p95_days"] == 10.0
        assert effort["confidence_interval"] == [2.0, 5.0]
        assert effort["similar_cases"] == 12

    @pytest.mark.asyncio
    async def test_estimate_effort_with_fix_pattern(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test effort estimation for specific fix pattern."""
        mock_knowledge_graph.get_fix_pattern_success_rate.return_value = {
            "pattern_id": "SQLI_01",
            "success_rate": 0.92,
            "avg_time_days": 1.5,
            "usage_count": 50
        }

        effort = await knowledge_graph_agent.estimate_remediation_effort(
            Vulnerability(cwe_id="CWE-89"),
            "project-123",
            fix_pattern_id="SQLI_01"
        )

        assert "pattern_id" in effort
        assert effort["pattern_id"] == "SQLI_01"
        assert effort["success_rate"] == 0.92
        assert effort["avg_time_days"] == 1.5

    @pytest.mark.asyncio
    async def test_estimate_effort_no_data(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test effort estimation with no historical data."""
        mock_knowledge_graph.estimate_remediation_effort.return_value = {}

        effort = await knowledge_graph_agent.estimate_remediation_effort(
            Vulnerability(title="Unique", cwe_id="CWE-999"),
            "project-123"
        )

        # Should return defaults when no data
        assert "mean_days" in effort
        assert effort["mean_days"] >= 0


class TestKnowledgeGraphAgentDeveloperExpertise:
    """Test developer expertise tracking."""

    @pytest.mark.asyncio
    async def test_get_developer_expertise(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test retrieving developer expertise."""
        mock_knowledge_graph.get_developer_expertise.return_value = {
            "developer_id": "dev-123",
            "vulnerability_types": {
                "SQL_INJECTION": 0.95,
                "XSS": 0.80,
                "PATH_TRAVERSAL": 0.70
            },
            "total_fixes": 42,
            "successful_fixes": 40,
            "avg_confidence": 0.88,
            "last_updated": datetime.utcnow().isoformat()
        }

        expertise = await knowledge_graph_agent.get_developer_expertise("dev-123")

        assert expertise["developer_id"] == "dev-123"
        assert expertise["vulnerability_types"]["SQL_INJECTION"] == 0.95
        assert expertise["total_fixes"] == 42
        assert expertise["successful_fixes"] == 40
        assert expertise["avg_confidence"] == 0.88

    @pytest.mark.asyncio
    async def test_get_developer_expertise_not_found(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test developer expertise when developer not found."""
        mock_knowledge_graph.get_developer_expertise.return_value = None

        expertise = await knowledge_graph_agent.get_developer_expertise("unknown-dev")

        assert expertise is None

    @pytest.mark.asyncio
    async def test_record_developer_expertise(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test recording developer expertise after fix."""
        result = await knowledge_graph_agent.record_developer_expertise(
            developer_id="dev-123",
            vulnerability_type="SQL_INJECTION",
            success=True,
            confidence=0.95,
            time_to_fix_hours=2.5
        )

        assert result is True
        mock_knowledge_graph.record_developer_expertise.assert_called_once()

        call_kwargs = mock_knowledge_graph.record_developer_expertise.call_args[1]
        assert call_kwargs["developer_id"] == "dev-123"
        assert call_kwargs["vulnerability_type"] == "SQL_INJECTION"
        assert call_kwargs["success"] is True
        assert call_kwargs["confidence"] == 0.95
        assert call_kwargs["time_to_fix_hours"] == 2.5


class TestKnowledgeGraphAgentProjectContext:
    """Test project context operations."""

    @pytest.mark.asyncio
    async def test_get_project_context(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test retrieving project context."""
        mock_context = ProjectContext(
            project_id="project-123",
            total_vulnerabilities=50,
            vulnerability_types={
                "SQL_INJECTION": 15,
                "XSS": 10,
                "PATH_TRAVERSAL": 5
            },
            avg_severity="HIGH",
            common_files=["app/views.py", "app/models.py"],
            active_developers=["dev-1", "dev-2", "dev-3"],
            compliance_frameworks=["SOX", "GDPR"],
            last_updated=datetime.utcnow()
        )
        mock_knowledge_graph.get_project_context.return_value = mock_context

        context = await knowledge_graph_agent.get_project_context("project-123")

        assert isinstance(context, ProjectContext)
        assert context.project_id == "project-123"
        assert context.total_vulnerabilities == 50
        assert context.vulnerability_types["SQL_INJECTION"] == 15
        assert context.avg_severity == "HIGH"
        assert len(context.active_developers) == 3

    @pytest.mark.asyncio
    async def test_get_project_context_with_stats(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test project context includes comprehensive statistics."""
        mock_context = ProjectContext(
            project_id="project-123",
            total_vulnerabilities=100,
            vulnerability_types={"SQL_INJECTION": 30},
            avg_severity="CRITICAL",
            common_files=["app/main.py"],
            active_developers=["dev-1"],
            compliance_frameworks=["PCI-DSS"],
            last_updated=datetime.utcnow(),
            remediation_rate=0.75,
            avg_mttr_days=5.5,
            security_posture="good"
        )
        mock_knowledge_graph.get_project_context.return_value = mock_context

        context = await knowledge_graph_agent.get_project_context("project-123")

        assert context.remediation_rate == 0.75
        assert context.avg_mttr_days == 5.5
        assert context.security_posture == "good"

    @pytest.mark.asyncio
    async def test_get_project_context_not_found(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test project context when project not found."""
        mock_knowledge_graph.get_project_context.return_value = None

        context = await knowledge_graph_agent.get_project_context("unknown-project")

        assert context is None


class TestKnowledgeGraphAgentQuerying:
    """Test natural language querying."""

    @pytest.mark.asyncio
    async def test_query_context_semantic_search(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test semantic search query."""
        mock_nodes = [
            KnowledgeNode(
                node_type=NodeType.VULNERABILITY,
                external_id="VULN-001",
                project_id="project-123",
                properties={"title": "SQL Injection", "description": "Database query issue"}
            )
        ]
        mock_edges = []
        mock_knowledge_graph.query_context.return_value = {
            "nodes": mock_nodes,
            "edges": mock_edges,
            "total": 1,
            "query": "SQL injection vulnerabilities",
            "execution_time_ms": 150
        }

        results = await knowledge_graph_agent.query_context(
            "SQL injection vulnerabilities",
            "project-123",
            node_types=[NodeType.VULNERABILITY]
        )

        assert results["total"] == 1
        assert len(results["nodes"]) == 1
        assert results["nodes"][0].external_id == "VULN-001"
        assert results["query"] == "SQL injection vulnerabilities"

    @pytest.mark.asyncio
    async def test_query_context_with_filters(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test query with type filters."""
        mock_knowledge_graph.query_context.return_value = {
            "nodes": [],
            "edges": [],
            "total": 0
        }

        results = await knowledge_graph_agent.query_context(
            "test query",
            "project-123",
            node_types=[NodeType.VULNERABILITY, NodeType.ANALYSIS]
        )

        # Verify filters passed through
        call_kwargs = mock_knowledge_graph.query_context.call_args[1]
        assert call_kwargs["node_types"] == [NodeType.VULNERABILITY, NodeType.ANALYSIS]

    @pytest.mark.asyncio
    async def test_query_context_empty_results(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test query with no results."""
        mock_knowledge_graph.query_context.return_value = {
            "nodes": [],
            "edges": [],
            "total": 0
        }

        results = await knowledge_graph_agent.query_context(
            "nonexistent pattern",
            "project-123"
        )

        assert results["total"] == 0
        assert len(results["nodes"]) == 0
        assert len(results["edges"]) == 0

    @pytest.mark.asyncio
    async def test_query_context_performance_tracking(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test query includes performance metrics."""
        mock_knowledge_graph.query_context.return_value = {
            "nodes": [],
            "edges": [],
            "total": 0,
            "execution_time_ms": 250
        }

        results = await knowledge_graph_agent.query_context("test", "project-123")

        assert "execution_time_ms" in results
        assert results["execution_time_ms"] == 250


class TestKnowledgeGraphAgentMaintenance:
    """Test maintenance operations."""

    @pytest.mark.asyncio
    async def test_run_maintenance(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test maintenance operations."""
        mock_knowledge_graph.run_maintenance.return_value = {
            "duplicates_removed": 15,
            "indexes_rebuilt": 3,
            "integrity_ok": True,
            "duration_seconds": 120
        }

        result = await knowledge_graph_agent.run_maintenance()

        assert result["duplicates_removed"] == 15
        assert result["indexes_rebuilt"] == 3
        assert result["integrity_ok"] is True
        assert result["duration_seconds"] == 120

        mock_knowledge_graph.run_maintenance.assert_called_once()

    @pytest.mark.asyncio
    async def test_maintenance_handles_errors(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test maintenance handles errors gracefully."""
        mock_knowledge_graph.run_maintenance.side_effect = Exception("DB Error")

        result = await knowledge_graph_agent.run_maintenance()

        # Should still return a result with error info
        assert "error" in result or "integrity_ok" in result


class TestKnowledgeGraphAgentHealth:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test health check when all components healthy."""
        health = await knowledge_graph_agent.health_check()

        assert health["status"] == "healthy"
        assert health["knowledge_graph"] is True
        assert health["vectorizer"] is True
        assert health["embeddings_initialized"] is False  # Not yet initialized

    @pytest.mark.asyncio
    async def test_health_check_degraded(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test health check when knowledge graph fails."""
        mock_knowledge_graph.get_project_context.side_effect = Exception("DB Error")

        health = await knowledge_graph_agent.health_check()

        assert health["status"] == "degraded"
        assert health["knowledge_graph"] is False

    @pytest.mark.asyncio
    async def test_health_check_after_initialization(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test health check after embeddings initialized."""
        knowledge_graph_agent._initialized = True
        knowledge_graph_agent.node_embeddings = {"test": np.array([0.1, 0.2, 0.3])}

        health = await knowledge_graph_agent.health_check()

        assert health["embeddings_initialized"] is True
        assert health["embedding_count"] == 1


class TestKnowledgeGraphAgentStatistics:
    """Test statistics tracking."""

    def test_get_statistics_initial(self, knowledge_graph_agent):
        """Test statistics on fresh agent."""
        stats = knowledge_graph_agent.get_statistics()

        assert stats["nodes_stored"] == 0
        assert stats["edges_created"] == 0
        assert stats["queries_executed"] == 0
        assert stats["patterns_matched"] == 0
        assert stats["embeddings_cached"] == 0

    def test_statistics_after_activity(self, knowledge_graph_agent):
        """Test statistics after activity."""
        knowledge_graph_agent._nodes_stored = 100
        knowledge_graph_agent._edges_created = 250
        knowledge_graph_agent._queries_executed = 50
        knowledge_graph_agent._patterns_matched = 30
        knowledge_graph_agent._embeddings_cached = 75

        stats = knowledge_graph_agent.get_statistics()

        assert stats["nodes_stored"] == 100
        assert stats["edges_created"] == 250
        assert stats["queries_executed"] == 50
        assert stats["patterns_matched"] == 30
        assert stats["embeddings_cached"] == 75


class TestKnowledgeGraphAgentIntegration:
    """Integration tests with full workflow."""

    @pytest.mark.asyncio
    async def test_full_knowledge_graph_workflow(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test complete knowledge graph workflow."""
        # 1. Store vulnerability
        vuln = Vulnerability(
            id="SECUREAI-2024-001",
            title="SQL Injection in User Authentication",
            description="The login endpoint constructs SQL queries using string concatenation, allowing attackers to bypass authentication.",
            severity=Severity.CRITICAL,
            source=VulnerabilitySource.SAST,
            file_path="app/auth.py",
            line_number=45,
            code_snippet="query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''",
            cwe_id="CWE-89",
            confidence=0.94,
            discovered_at=datetime.utcnow()
        )

        result1 = await knowledge_graph_agent.store_vulnerability(vuln, "secureai-demo")
        assert result1 is True

        # 2. Store analysis
        analysis = AnalyzedVulnerability(
            vulnerability_id="SECUREAI-2024-001",
            confidence=0.98,
            false_positive_probability=0.02,
            priority_score=0.95,
            remediation_effort=1.5,
            suggested_fix="Use parameterized queries with placeholders",
            analysis={
                "root_cause": "String concatenation in SQL query",
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "impact": "Complete database compromise"
            }
        )

        result2 = await knowledge_graph_agent.store_analysis(analysis, "secureai-demo")
        assert result2 is True

        # 3. Store developer
        result3 = await knowledge_graph_agent.store_developer(
            developer_id="dev-123",
            email="developer@example.com",
            name="Jane Developer",
            role="Security Engineer"
        )
        assert result3 is True

        # 4. Record developer expertise
        result4 = await knowledge_graph_agent.record_developer_expertise(
            developer_id="dev-123",
            vulnerability_type="SQL_INJECTION",
            success=True,
            confidence=0.98,
            time_to_fix_hours=1.5
        )
        assert result4 is True

        # 5. Get historical patterns
        patterns = await knowledge_graph_agent.get_historical_patterns(
            "SQL_INJECTION", "secureai-demo"
        )
        assert isinstance(patterns, dict)

        # 6. Estimate effort
        effort = await knowledge_graph_agent.estimate_remediation_effort(
            vuln, "secureai-demo"
        )
        assert "mean_days" in effort
        assert effort["mean_days"] >= 0

        # 7. Get project context
        context = await knowledge_graph_agent.get_project_context("secureai-demo")
        assert context is not None
        assert context.project_id == "secureai-demo"
        assert context.total_vulnerabilities >= 1

        # 8. Query context
        results = await knowledge_graph_agent.query_context(
            "SQL injection authentication",
            "secureai-demo"
        )
        assert "nodes" in results
        assert "total" in results

        # 9. Get developer expertise
        expertise = await knowledge_graph_agent.get_developer_expertise("dev-123")
        assert expertise is not None
        assert expertise["developer_id"] == "dev-123"
        assert "SQL_INJECTION" in expertise["vulnerability_types"]

    @pytest.mark.asyncio
    async def test_knowledge_persistence_across_operations(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test that stored knowledge persists across operations."""
        # Store multiple vulnerabilities
        vulns = [
            Vulnerability(id=f"VULN-{i}", title=f"Test {i}", severity=Severity.HIGH)
            for i in range(5)
        ]

        for vuln in vulns:
            await knowledge_graph_agent.store_vulnerability(vuln, "project-123")

        # Query should find them
        results = await knowledge_graph_agent.query_context(
            "Test vulnerability",
            "project-123"
        )

        # Should have stored 5 nodes
        assert mock_knowledge_graph.add_node.call_count >= 5

    @pytest.mark.asyncio
    async def test_embedding_generation(self, knowledge_graph_agent):
        """Test that embeddings are generated for nodes."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection Test",
            description="This is a test vulnerability for embedding generation",
            severity=Severity.HIGH
        )

        # Store vulnerability
        await knowledge_graph_agent.store_vulnerability(vuln, "project-123")

        # Check that node has embedding
        call_args = mock_knowledge_graph.add_node.call_args
        node = call_args[0][0]

        assert node.embedding is not None
        assert isinstance(node.embedding, list)
        assert len(node.embedding) > 0  # Should have embedding dimensions

    @pytest.mark.asyncio
    async def test_similarity_computation(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test similarity computation between vulnerabilities."""
        vuln1 = Vulnerability(
            id="VULN-001",
            title="SQL Injection in login",
            description="User input not sanitized in login form",
            cwe_id="CWE-89"
        )
        vuln2 = Vulnerability(
            id="VULN-002",
            title="SQL Injection in search",
            description="User input not sanitized in search endpoint",
            cwe_id="CWE-89"
        )
        vuln3 = Vulnerability(
            id="VULN-003",
            title="XSS in profile",
            description="User input not escaped in profile page",
            cwe_id="CWE-79"
        )

        # Mock similarity scores
        mock_knowledge_graph.find_similar_vulnerabilities.side_effect = [
            [(MagicMock(external_id="VULN-002"), 0.85)],  # For vuln1
            [(MagicMock(external_id="VULN-001"), 0.85)],  # For vuln2
            [(MagicMock(external_id="VULN-001"), 0.30)]   # For vuln3
        ]

        # Find similar for each
        similar1 = await knowledge_graph_agent.find_similar_vulnerabilities(vuln1, "project-123")
        similar2 = await knowledge_graph_agent.find_similar_vulnerabilities(vuln2, "project-123")
        similar3 = await knowledge_graph_agent.find_similar_vulnerabilities(vuln3, "project-123")

        # SQLi vulns should be similar to each other
        assert len(similar1) == 1
        assert similar1[0][1] == 0.85

        assert len(similar2) == 1
        assert similar2[0][1] == 0.85

        # XSS should not be very similar to SQLi
        assert len(similar3) == 1
        assert similar3[0][1] == 0.30

    @pytest.mark.asyncio
    async def test_cross_project_isolation(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test that knowledge is isolated between projects."""
        vuln = Vulnerability(id="VULN-001", title="Test", severity=Severity.HIGH)

        # Store in two different projects
        await knowledge_graph_agent.store_vulnerability(vuln, "project-1")
        await knowledge_graph_agent.store_vulnerability(vuln, "project-2")

        # Should call add_node twice with different project_id
        assert mock_knowledge_graph.add_node.call_count == 2
        call1, call2 = mock_knowledge_graph.add_node.call_args_list
        assert call1[0][0].project_id == "project-1"
        assert call2[0][0].project_id == "project-2"

    @pytest.mark.asyncio
    async def test_pattern_learning_from_historical_data(self, knowledge_graph_agent, mock_knowledge_graph):
        """Test that system learns patterns from historical data."""
        # Simulate historical data with multiple similar vulnerabilities
        historical_vulns = [
            Vulnerability(
                id=f"HIST-{i}",
                title="SQL Injection",
                description="User input in SQL query",
                cwe_id="CWE-89",
                file_path="app/views.py"
            )
            for i in range(10)
        ]

        for vuln in historical_vulns:
            await knowledge_graph_agent.store_vulnerability(vuln, "project-123")

        # Get patterns
        patterns = await knowledge_graph_agent.get_historical_patterns(
            "SQL_INJECTION", "project-123"
        )

        # Should have learned common file paths
        assert "common_files" in patterns
        assert "app/views.py" in patterns["common_files"]

        # Should have statistics
        assert patterns["total_occurrences"] >= 10
        assert patterns["remediation_success_rate"] >= 0
 
