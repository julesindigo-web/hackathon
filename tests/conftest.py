"""
SecurAI Guardian - Test Configuration and Fixtures

Provides shared fixtures for all test suites.
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

from core.config import settings
from agents.scanner_agent import ScannerAgent
from agents.analyzer_agent import AnalyzerAgent
from agents.remediation_agent import RemediationAgent
from agents.compliance_agent import ComplianceAgent
from agents.monitoring_agent import MonitoringAgent
from agents.knowledge_graph_agent import KnowledgeGraphAgent
from app.orchestrator import SecurityOrchestrator


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_gitlab_client():
    """Mock GitLab client for testing."""
    mock = MagicMock()
    mock.get_project = AsyncMock()
    mock.get_merge_request = AsyncMock()
    mock.get_pipeline = AsyncMock()
    mock.get_latest_pipeline = AsyncMock()
    mock.get_pipeline_jobs = AsyncMock()
    mock.download_artifact = AsyncMock(return_value=b'{"vulnerabilities": []}')
    mock.get_repository_file = AsyncMock(return_value="mock file content")
    mock.get_commit_history = AsyncMock(return_value=[])
    return mock


@pytest.fixture
def mock_knowledge_graph():
    """Mock knowledge graph client for testing."""
    mock = MagicMock()
    mock.query = AsyncMock(return_value=[])
    mock.create_node = AsyncMock(return_value="node-123")
    mock.create_edge = AsyncMock()
    mock.store_vulnerability = AsyncMock()
    mock.store_analysis = AsyncMock()
    mock.store_remediation = AsyncMock()
    mock.store_compliance_report = AsyncMock()
    mock.store_security_metrics = AsyncMock()
    return mock


@pytest.fixture
def scanner_agent(mock_gitlab_client, mock_knowledge_graph):
    """Create ScannerAgent with mocked dependencies."""
    return ScannerAgent(
        gitlab_client=mock_gitlab_client,
        knowledge_graph_client=mock_knowledge_graph,
    )


@pytest.fixture
def analyzer_agent(mock_gitlab_client, mock_knowledge_graph):
    """Create AnalyzerAgent with mocked dependencies."""
    # Mock Anthropic client
    from unittest.mock import patch
    with patch('anthropic.Anthropic') as mock_anthropic:
        mock_client = MagicMock()
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text='{"root_cause": "test", "exploitability_score": 0.8, "recommended_fix": "test fix", "false_positive_probability": 0.0, "priority_score": 0.9, "confidence": 0.95}')]
        mock_message.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create.return_value = mock_message
        mock_anthropic.return_value = mock_client

        agent = AnalyzerAgent(
            gitlab_client=mock_gitlab_client,
            knowledge_graph_client=mock_knowledge_graph,
            anthropic_client=mock_client,
        )
        yield agent


@pytest.fixture
def remediation_agent(mock_gitlab_client, mock_knowledge_graph):
    """Create RemediationAgent with mocked dependencies."""
    return RemediationAgent(
        gitlab_client=mock_gitlab_client,
        knowledge_graph_client=mock_knowledge_graph,
    )


@pytest.fixture
def compliance_agent(mock_gitlab_client, mock_knowledge_graph):
    """Create ComplianceAgent with mocked dependencies."""
    return ComplianceAgent(
        gitlab_client=mock_gitlab_client,
        knowledge_graph_client=mock_knowledge_graph,
    )


@pytest.fixture
def monitoring_agent(mock_gitlab_client, mock_knowledge_graph):
    """Create MonitoringAgent with mocked dependencies."""
    agent = MonitoringAgent(
        gitlab_client=mock_gitlab_client,
        knowledge_graph_client=mock_knowledge_graph,
    )
    # Don't start background collection in tests
    yield agent
    # Cleanup if needed


@pytest.fixture
def knowledge_graph_agent(mock_gitlab_client, mock_knowledge_graph):
    """Create KnowledgeGraphAgent with mocked dependencies."""
    return KnowledgeGraphAgent(
        gitlab_client=mock_gitlab_client,
        knowledge_graph_client=mock_knowledge_graph,
    )


@pytest.fixture
def orchestrator(
    scanner_agent,
    analyzer_agent,
    remediation_agent,
    compliance_agent,
    monitoring_agent,
    knowledge_graph_agent,
):
    """Create SecurityOrchestrator with all mocked agents."""
    return SecurityOrchestrator(
        scanner_agent=scanner_agent,
        analyzer_agent=analyzer_agent,
        remediation_agent=remediation_agent,
        compliance_agent=compliance_agent,
        monitoring_agent=monitoring_agent,
        kg_agent=knowledge_graph_agent,
    )
