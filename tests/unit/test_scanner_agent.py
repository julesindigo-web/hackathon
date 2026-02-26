"""
Unit tests for Scanner Agent

Tests coverage:
- Artifact fetching and parsing
- Vulnerability normalization
- Deduplication logic
- Error handling and self-healing
"""

import pytest
import json
from datetime import datetime

from agents.scanner_agent import ScannerAgent, ScanResult


class TestScannerAgent:
    """Test suite for ScannerAgent."""

    @pytest.mark.asyncio
    async def test_scan_with_no_artifacts(self, scanner_agent, mock_gitlab_client):
        """Test scan when no security artifacts found."""
        mock_gitlab_client.get_pipeline_jobs.return_value = []

        vulnerabilities = await scanner_agent.scan(project_id=1)

        assert len(vulnerabilities) == 0

    @pytest.mark.asyncio
    async def test_deduplication_removes_duplicates(self, scanner_agent):
        """Test that duplicate vulnerabilities are deduplicated."""
        # Create two identical scan results
        vuln_data = {
            "id": "SAST-1",
            "name": "SQL Injection",
            "description": "SQL injection vulnerability",
            "severity": "high",
            "location": {"file": "app.py", "start": {"line": 10}},
        }

        artifact = MagicMock()
        artifact.file_path = "sast.json"
        artifact.scanner_name = "sast"
        artifact.file_format = "json"
        artifact.content = json.dumps({"vulnerabilities": [vuln_data, vuln_data]}).encode()

        # Mock the parser to return duplicate findings
        original_parse = scanner_agent._parse_sast
        scanner_agent._parse_sast = AsyncMock(return_value=[
            ScanResult(
                vulnerability=Vulnerability(
                    id="SAST-1",
                    title="SQL Injection",
                    description="SQL injection vulnerability",
                    severity=Severity.HIGH,
                    vulnerability_type="sql_injection",
                    scanner_source=VulnerabilitySource.SAST,
                    location="app.py",
                    start_line=10,
                    content_hash="hash123",
                ),
                raw_finding=vuln_data,
                artifact_type="sast",
                confidence=0.95,
            ),
            ScanResult(
                vulnerability=Vulnerability(
                    id="SAST-1",
                    title="SQL Injection",
                    description="SQL injection vulnerability",
                    severity=Severity.HIGH,
                    vulnerability_type="sql_injection",
                    scanner_source=VulnerabilitySource.SAST,
                    location="app.py",
                    start_line=10,
                    content_hash="hash123",  # Same hash
                ),
                raw_finding=vuln_data,
                artifact_type="sast",
                confidence=0.95,
            ),
        ])

        try:
            vulnerabilities = await scanner_agent.scan(project_id=1)
            assert len(vulnerabilities) == 1  # Deduplicated to 1
        finally:
            scanner_agent._parse_sast = original_parse

    @pytest.mark.asyncio
    async def test_hash_computation_consistent(self, scanner_agent):
        """Test that vulnerability hash computation is consistent."""
        vuln1 = Vulnerability(
            id="SAST-1",
            title="Test",
            description="Test description",
            severity=Severity.MEDIUM,
            vulnerability_type="sql_injection",
            scanner_source=VulnerabilitySource.SAST,
            location="app.py",
            start_line=10,
            end_line=15,
        )

        vuln2 = Vulnerability(
            id="SAST-2",  # Different ID
            title="Test",
            description="Test description",
            severity=Severity.MEDIUM,
            vulnerability_type="sql_injection",
            scanner_source=VulnerabilitySource.SAST,
            location="app.py",
            start_line=10,
            end_line=15,
        )

        hash1 = scanner_agent._compute_vulnerability_hash(
            scanner="sast",
            vulnerability_type="sql_injection",
            file_path="app.py",
            start_line=10,
            end_line=15,
            description="Test description",
        )

        hash2 = scanner_agent._compute_vulnerability_hash(
            scanner="sast",
            vulnerability_type="sql_injection",
            file_path="app.py",
            start_line=10,
            end_line=15,
            description="Test description",
        )

        assert hash1 == hash2  # Same content produces same hash

    @pytest.mark.asyncio
    async def test_parse_sast_artifact(self, scanner_agent):
        """Test parsing of SAST artifact."""
        sast_data = {
            "vulnerabilities": [
                {
                    "id": "SAST-123",
                    "name": "SQL Injection",
                    "description": "Potential SQL injection in query",
                    "severity": "high",
                    "location": {
                        "file": "app/db.py",
                        "start": {"line": 42},
                        "end": {"line": 45},
                    },
                }
            ]
        }

        artifact = MagicMock()
        artifact.file_path = "gl-scanning-report.json"
        artifact.scanner_name = "sast"
        artifact.file_format = "json"
        artifact.content = json.dumps(sast_data).encode()

        findings = await scanner_agent._parse_sast(artifact)

        assert len(findings) == 1
        assert findings[0].vulnerability.title == "SQL Injection"
        assert findings[0].vulnerability.severity == Severity.HIGH
        assert findings[0].vulnerability.location == "app/db.py"
        assert findings[0].vulnerability.start_line == 42

    @pytest.mark.asyncio
    async def test_parse_dependency_artifact(self, scanner_agent):
        """Test parsing of Dependency Scanning artifact."""
        dep_data = {
            "vulnerabilities": [
                {
                    "id": "DEP-456",
                    "name": "CVE-2024-1234",
                    "description": "Arbitrary code execution",
                    "severity": "critical",
                    "dependency": {
                        "name": "requests",
                        "version": "2.25.0",
                    },
                }
            ]
        }

        artifact = MagicMock()
        artifact.file_path = "dependency-scanning-report.json"
        artifact.scanner_name = "dependency_scanning"
        artifact.file_format = "json"
        artifact.content = json.dumps(dep_data).encode()

        findings = await scanner_agent._parse_dependency(artifact)

        assert len(findings) == 1
        assert findings[0].vulnerability.vulnerability_type == "dependency"
        assert findings[0].vulnerability.metadata["package_name"] == "requests"
        assert findings[0].vulnerability.metadata["package_version"] == "2.25.0"

    @pytest.mark.asyncio
    async def test_parse_secret_detection(self, scanner_agent):
        """Test parsing of Secret Detection artifact."""
        secret_data = {
            "vulnerabilities": [
                {
                    "id": "SECRET-789",
                    "name": "Hardcoded Password",
                    "description": "Password hardcoded in source",
                    "severity": "critical",
                    "location": {
                        "file": "config.py",
                        "start": {"line": 10},
                    },
                    "type": "password",
                }
            ]
        }

        artifact = MagicMock()
        artifact.file_path = "secret_detection_report.json"
        artifact.scanner_name = "secret_detection"
        artifact.file_format = "json"
        artifact.content = json.dumps(secret_data).encode()

        findings = await scanner_agent._parse_secret(artifact)

        assert len(findings) == 1
        assert findings[0].vulnerability.severity == Severity.CRITICAL  # Secrets always critical
        assert findings[0].vulnerability.vulnerability_type == "secret"
        assert findings[0].vulnerability.metadata["secret_type"] == "password"

    def test_normalize_severity(self, scanner_agent):
        """Test severity normalization."""
        assert scanner_agent._normalize_severity("critical") == Severity.CRITICAL
        assert scanner_agent._normalize_severity("high") == Severity.HIGH
        assert scanner_agent._normalize_severity("medium") == Severity.MEDIUM
        assert scanner_agent._normalize_severity("low") == Severity.LOW
        assert scanner_agent._normalize_severity("info") == Severity.INFO
        assert scanner_agent._normalize_severity("unknown") == Severity.MEDIUM

    def test_is_security_artifact(self, scanner_agent):
        """Test security artifact detection."""
        assert scanner_agent._is_security_artifact("sast/report.json")
        assert scanner_agent._is_security_artifact("dast/report.xml")
        assert scanner_agent._is_security_artifact("dependency-scanning-report.json")
        assert scanner_agent._is_security_artifact("container-scanning/report.json")
        assert scanner_agent._is_security_artifact("secret_detection_report.json")
        assert not scanner_agent._is_security_artifact("test-output.txt")
        assert not scanner_agent._is_security_artifact("coverage.xml")

    def test_detect_scanner(self, scanner_agent):
        """Test scanner type detection from file path."""
        assert scanner_agent._detect_scanner("sast/report.json") == "sast"
        assert scanner_agent._detect_scanner("dast/report.json") == "dast"
        assert scanner_agent._detect_scanner("dependency-scanning-report.json") == "dependency_scanning"
        assert scanner_agent._detect_scanner("container-scanning-report.json") == "container_scanning"
        assert scanner_agent._detect_scanner("secret_detection_report.json") == "secret_detection"
        assert scanner_agent._detect_scanner("coverage.xml") == "coverage"
        assert scanner_agent._detect_scanner("unknown.txt") == "unknown"

    def test_detect_format(self, scanner_agent):
        """Test file format detection."""
        assert scanner_agent._detect_format("report.json") == "json"
        assert scanner_agent._detect_format("report.yaml") == "yaml"
        assert scanner_agent._detect_format("report.yml") == "yaml"
        assert scanner_agent._detect_format("report.xml") == "xml"
        assert scanner_agent._detect_format("report.txt") == "text"
        assert scanner_agent._detect_format("report.csv") == "csv"
        assert scanner_agent._detect_format("report.html") == "html"
        assert scanner_agent._detect_format("report.unknown") == "unknown"
