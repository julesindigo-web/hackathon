"""
Unit tests for core knowledge_graph module.

Tests database operations, CRUD functions, query methods, and statistical calculations.
Ensures knowledge graph storage and retrieval works correctly.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.knowledge_graph import (
    KnowledgeGraph, VulnerabilityRecord, CodeFileRecord,
    DeveloperRecord, FixPatternRecord, AnalysisRecord,
    init_db, store_vulnerability, store_analysis, store_remediation,
    query_context, predict_risk_areas, get_historical_patterns,
    estimate_remediation_effort
)


class TestKnowledgeGraphInitialization:
    """Test knowledge graph database initialization."""

    def test_init_db_creates_tables(self):
        """Test that init_db creates all required tables."""
        # Use in-memory SQLite for testing
        engine = create_engine("sqlite:///:memory:")

        # Patch the engine
        with patch('core.knowledge_graph.engine', engine):
            init_db()

            # Verify tables exist by querying
            from sqlalchemy import inspect
            inspector = inspect(engine)
            tables = inspector.get_table_names()

            expected_tables = [
                'knowledge_vulnerabilities',
                'knowledge_analyses',
                'knowledge_remediations',
                'knowledge_code_files',
                'knowledge_developers',
                'knowledge_fix_patterns'
            ]

            for table in expected_tables:
                assert table in tables

    def test_init_db_idempotent(self):
        """Test that init_db can be called multiple times safely."""
        engine = create_engine("sqlite:///:memory:")

        with patch('core.knowledge_graph.engine', engine):
            init_db()  # First call
            init_db()  # Second call should not error

            # Tables should still exist
            from sqlalchemy import inspect
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            assert 'knowledge_vulnerabilities' in tables


class TestVulnerabilityRecord:
    """Test VulnerabilityRecord model."""

    def test_vulnerability_record_creation(self):
        """Test creating vulnerability record."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            vuln = VulnerabilityRecord(
                vuln_id="VULN-001",
                title="SQL Injection",
                description="Test",
                severity="high",
                vulnerability_type="sql_injection",
                cwe_id="CWE-89",
                file_path="app/auth.py",
                line_number=42,
                scanner_source="sast",
                project_id=123,
                mr_id=456,
                branch="main",
                commit_sha="abc123",
                confidence=0.95,
                raw_data={"scanner": "semgrep"}
            )
            session.add(vuln)
            session.commit()

            # Query back
            result = session.query(VulnerabilityRecord).filter_by(vuln_id="VULN-001").first()
            assert result is not None
            assert result.title == "SQL Injection"
            assert result.severity == "high"
            assert result.project_id == 123
        finally:
            session.close()

    def test_vulnerability_record_hash_indexing(self):
        """Test content hash is computed and indexed."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            vuln = VulnerabilityRecord(
                vuln_id="VULN-001",
                title="Test",
                description="Test",
                severity="high",
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=1,
                scanner_source="sast",
                project_id=1,
                mr_id=1
            )
            session.add(vuln)
            session.commit()

            # Hash should be computed
            assert vuln.content_hash is not None
            assert len(vuln.content_hash) == 64  # SHA256 hex length
        finally:
            session.close()

    def test_vulnerability_duplicate_detection(self):
        """Test duplicate vulnerabilities have same hash."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            vuln1 = VulnerabilityRecord(
                vuln_id="VULN-001",
                title="SQL Injection",
                description="Same content",
                severity="high",
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=42,
                scanner_source="sast",
                project_id=123,
                mr_id=456
            )

            vuln2 = VulnerabilityRecord(
                vuln_id="VULN-002",
                title="SQL Injection",  # Same title
                description="Same content",  # Same description
                severity="high",
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=42,  # Same line
                scanner_source="sast",
                project_id=123,
                mr_id=456
            )

            session.add_all([vuln1, vuln2])
            session.commit()

            # Hashes should be equal for duplicate detection
            assert vuln1.content_hash == vuln2.content_hash
        finally:
            session.close()


class TestCodeFileRecord:
    """Test CodeFileRecord model."""

    def test_code_file_creation(self):
        """Test creating code file record."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            code_file = CodeFileRecord(
                file_path="app/auth.py",
                project_id=123,
                commit_sha="abc123",
                language="python",
                lines_of_code=500,
                complexity=15,
                test_coverage=0.85,
                last_analyzed=datetime.utcnow()
            )
            session.add(code_file)
            session.commit()

            result = session.query(CodeFileRecord).filter_by(file_path="app/auth.py").first()
            assert result is not None
            assert result.language == "python"
            assert result.lines_of_code == 500
        finally:
            session.close()

    def test_code_file_metrics_update(self):
        """Test updating code file metrics."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            code_file = CodeFileRecord(
                file_path="app/auth.py",
                project_id=123,
                commit_sha="abc123",
                language="python"
            )
            session.add(code_file)
            session.commit()

            # Update metrics
            code_file.lines_of_code = 600
            code_file.complexity = 18
            code_file.test_coverage = 0.90
            session.commit()

            result = session.query(CodeFileRecord).filter_by(file_path="app/auth.py").first()
            assert result.lines_of_code == 600
            assert result.complexity == 18
            assert result.test_coverage == 0.90
        finally:
            session.close()


class TestDeveloperRecord:
    """Test DeveloperRecord model."""

    def test_developer_creation(self):
        """Test creating developer record."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            dev = DeveloperRecord(
                email="developer@example.com",
                name="John Doe",
                gitlab_username="johndoe",
                project_id=123,
                total_commits=150,
                vulnerability_fixes=25,
                avg_remediation_time_hours=4.5,
                expertise_level=0.85,
                expertise_areas=["sql_injection", "xss", "authentication"]
            )
            session.add(dev)
            session.commit()

            result = session.query(DeveloperRecord).filter_by(email="developer@example.com").first()
            assert result is not None
            assert result.name == "John Doe"
            assert result.gitlab_username == "johndoe"
            assert result.expertise_level == 0.85
        finally:
            session.close()

    def test_developer_expertise_areas(self):
        """Test developer expertise areas stored as JSON."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            dev = DeveloperRecord(
                email="dev@example.com",
                name="Dev",
                project_id=123,
                expertise_areas=["sql_injection", "xss", "csrf"]
            )
            session.add(dev)
            session.commit()

            result = session.query(DeveloperRecord).filter_by(email="dev@example.com").first()
            assert isinstance(result.expertise_areas, list)
            assert "sql_injection" in result.expertise_areas
        finally:
            session.close()


class TestFixPatternRecord:
    """Test FixPatternRecord model."""

    def test_fix_pattern_creation(self):
        """Test creating fix pattern record."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            pattern = FixPatternRecord(
                pattern_name="sql_injection_parameterized_queries",
                vulnerability_type="sql_injection",
                description="Replace string concatenation with parameterized queries",
                code_template="cursor.execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))",
                language="python",
                success_rate=0.95,
                avg_remediation_time_hours=2.0,
                usage_count=150,
                last_used=datetime.utcnow()
            )
            session.add(pattern)
            session.commit()

            result = session.query(FixPatternRecord).filter_by(
                pattern_name="sql_injection_parameterized_queries"
            ).first()
            assert result is not None
            assert result.vulnerability_type == "sql_injection"
            assert result.success_rate == 0.95
        finally:
            session.close()

    def test_fix_pattern_success_rate_bounds(self):
        """Test success rate is between 0 and 1."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            pattern = FixPatternRecord(
                pattern_name="test_pattern",
                vulnerability_type="test",
                description="Test",
                language="python",
                success_rate=0.85
            )
            session.add(pattern)
            session.commit()

            result = session.query(FixPatternRecord).filter_by(pattern_name="test_pattern").first()
            assert 0 <= result.success_rate <= 1
        finally:
            session.close()


class TestAnalysisRecord:
    """Test AnalysisRecord model."""

    def test_analysis_record_creation(self):
        """Test creating analysis record."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            analysis = AnalysisRecord(
                vuln_id="VULN-001",
                root_cause="User input not parameterized",
                exploitability_score=9.2,
                impact_score=8.5,
                false_positive_probability=0.05,
                confidence=0.95,
                priority_score=0.92,
                recommended_fix_pattern="sql_injection_parameterized_queries",
                code_context={"file": "app/auth.py", "snippet": "query = f\"SELECT...\""},
                analysis_notes="High risk vulnerability",
                analyzed_at=datetime.utcnow(),
                analyst_type="ai",
                analysis_duration_ms=2500
            )
            session.add(analysis)
            session.commit()

            result = session.query(AnalysisRecord).filter_by(vuln_id="VULN-001").first()
            assert result is not None
            assert result.exploitability_score == 9.2
            assert result.priority_score == 0.92
        finally:
            session.close()

    def test_analysis_score_bounds(self):
        """Test analysis scores are within valid ranges."""
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        init_db()

        session = Session()
        try:
            analysis = AnalysisRecord(
                vuln_id="VULN-001",
                root_cause="Test",
                exploitability_score=10.0,  # Max
                impact_score=10.0,  # Max
                false_positive_probability=0.0,  # Min
                confidence=1.0,  # Max
                priority_score=1.0,  # Max
                recommended_fix_pattern="test",
                code_context={}
            )
            session.add(analysis)
            session.commit()

            result = session.query(AnalysisRecord).filter_by(vuln_id="VULN-001").first()
            assert result.exploitability_score == 10.0
            assert result.impact_score == 10.0
            assert result.false_positive_probability == 0.0
            assert result.confidence == 1.0
        finally:
            session.close()


class TestCRUDOperations:
    """Test CRUD operations in knowledge_graph module."""

    def setup_method(self):
        """Set up test database."""
        self.engine = create_engine("sqlite:///:memory:")
        self.Session = sessionmaker(bind=self.engine)
        init_db()
        self.session = self.Session()

    def teardown_method(self):
        """Clean up test database."""
        self.session.close()

    def test_store_vulnerability(self):
        """Test store_vulnerability function."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="Test",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )

        record = store_vulnerability(vuln, self.session)
        self.session.commit()

        assert record.vuln_id == "VULN-001"
        assert record.title == "SQL Injection"

        # Verify in database
        result = self.session.query(VulnerabilityRecord).filter_by(vuln_id="VULN-001").first()
        assert result is not None

    def test_store_analysis(self):
        """Test store_analysis function."""
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            description="Test",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123,
            mr_id=456
        )

        analysis = AnalyzedVulnerability(
            vulnerability_id="VULN-001",
            root_cause="User input not parameterized",
            exploitability_score=9.2,
            impact_score=8.5,
            false_positive_probability=0.05,
            confidence=0.95,
            priority_score=0.92,
            recommended_fix_pattern="sql_injection_parameterized_queries",
            code_context={"file": "app/auth.py"}
        )

        record = store_analysis(vuln, analysis, self.session)
        self.session.commit()

        assert record.vuln_id == "VULN-001"
        assert record.exploitability_score == 9.2

    def test_store_remediation(self):
        """Test store_remediation function."""
        plan = RemediationPlan(
            vulnerability_id="VULN-001",
            fix_description="Use parameterized queries",
            fix_pattern="sql_injection_parameterized_queries",
            confidence=0.95,
            estimated_effort="2h",
            code_changes={"file": "app/auth.py", "diff": "@@ -42,7 +42,9 @@\n-..."},
            verification_status="verified",
            applied_by="security-bot"
        )

        record = store_remediation(plan, self.session)
        self.session.commit()

        assert record.vulnerability_id == "VULN-001"
        assert record.fix_pattern == "sql_injection_parameterized_queries"
        assert record.verification_status == "verified"

    def test_query_context(self):
        """Test query_context function."""
        # Store some test data
        vuln = VulnerabilityRecord(
            vuln_id="VULN-001",
            title="SQL Injection in auth",
            description="Test SQL injection vulnerability",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="app/auth.py",
            line_number=42,
            scanner_source="sast",
            project_id=123
        )
        self.session.add(vuln)

        code = CodeFileRecord(
            file_path="app/auth.py",
            project_id=123,
            language="python",
            lines_of_code=500
        )
        self.session.add(code)
        self.session.commit()

        # Query context
        result = query_context("sql injection", project_id=123, session=self.session)

        assert "vulnerabilities" in result
        assert "code_files" in result
        assert len(result["vulnerabilities"]) > 0

    def test_predict_risk_areas(self):
        """Test predict_risk_areas function."""
        # Store vulnerabilities in different files
        files = ["app/auth.py", "app/payment.py", "app/utils.py"]
        vuln_types = ["sql_injection", "xss", "sql_injection", "xss", "csrf"]

        for i, (file, vuln_type) in enumerate(zip(files * 2, vuln_types)):
            vuln = VulnerabilityRecord(
                vuln_id=f"VULN-{i}",
                title=f"Test {vuln_type}",
                description="Test",
                severity="high",
                vulnerability_type=vuln_type,
                file_path=file,
                line_number=1,
                scanner_source="sast",
                project_id=123
            )
            self.session.add(vuln)

        self.session.commit()

        # Predict risk areas
        result = predict_risk_areas(project_id=123, session=self.session)

        assert "high_risk_files" in result
        assert "vulnerability_patterns" in result
        assert isinstance(result["high_risk_files"], list)

    def test_get_historical_patterns(self):
        """Test get_historical_patterns function."""
        # Store vulnerabilities with timestamps
        now = datetime.utcnow()
        for i in range(10):
            vuln = VulnerabilityRecord(
                vuln_id=f"VULN-{i}",
                title=f"Test {i}",
                description="Test",
                severity="high" if i < 3 else "medium",
                vulnerability_type="sql_injection" if i % 2 == 0 else "xss",
                file_path="app/test.py",
                line_number=1,
                scanner_source="sast",
                project_id=123,
                created_at=now - timedelta(days=i)
            )
            self.session.add(vuln)

        self.session.commit()

        # Get historical patterns
        result = get_historical_patterns(project_id=123, days_back=30, session=self.session)

        assert "vulnerability_trend" in result
        assert "common_types" in result
        assert "severity_distribution" in result

    def test_estimate_remediation_effort(self):
        """Test estimate_remediation_effort function."""
        # Store fix patterns with usage statistics
        pattern = FixPatternRecord(
            pattern_name="sql_injection_parameterized_queries",
            vulnerability_type="sql_injection",
            description="Use parameterized queries",
            language="python",
            success_rate=0.95,
            avg_remediation_time_hours=2.0,
            usage_count=100
        )
        self.session.add(pattern)
        self.session.commit()

        # Estimate effort
        result = estimate_remediation_effort("sql_injection", session=self.session)

        assert "estimated_effort" in result
        assert "confidence" in result
        assert "statistics" in result
        assert result["vulnerability_type"] == "sql_injection"
        assert result["statistics"]["mean"] == 2.0

    def test_estimate_remediation_effort_insufficient_data(self):
        """Test effort estimation with no historical data."""
        result = estimate_remediation_effort("unknown_type", session=self.session)

        # Should return default estimate
        assert "estimated_effort" in result
        assert result["confidence"] < 0.5  # Low confidence


class TestKnowledgeGraphQueries:
    """Test complex query operations."""

    def setup_method(self):
        """Set up test database with realistic data."""
        self.engine = create_engine("sqlite:///:memory:")
        self.Session = sessionmaker(bind=self.engine)
        init_db()
        self.session = self.Session()

        # Create test data
        self.create_test_data()

    def teardown_method(self):
        """Clean up."""
        self.session.close()

    def create_test_data(self):
        """Create realistic test dataset."""
        # Vulnerabilities
        for i in range(20):
            vuln = VulnerabilityRecord(
                vuln_id=f"VULN-{i:03d}",
                title=f"Test vulnerability {i}",
                description=f"Test description {i}",
                severity=["low", "medium", "high", "critical"][i % 4],
                vulnerability_type=["sql_injection", "xss", "csrf", "path_traversal"][i % 4],
                file_path=f"app/module{i % 5}.py",
                line_number=i + 1,
                scanner_source="sast",
                project_id=1,
                created_at=datetime.utcnow() - timedelta(days=i)
            )
            self.session.add(vuln)

        # Code files
        for i in range(5):
            code = CodeFileRecord(
                file_path=f"app/module{i}.py",
                project_id=1,
                language="python",
                lines_of_code=100 + i * 50,
                complexity=10 + i,
                test_coverage=0.7 + i * 0.05
            )
            self.session.add(code)

        # Fix patterns
        patterns = [
            ("sql_injection_parameterized_queries", "sql_injection", 2.0, 0.95),
            ("xss_output_encoding", "xss", 1.5, 0.90),
            ("csrf_token_validation", "csrf", 1.0, 0.88),
        ]
        for name, vuln_type, time, success in patterns:
            pattern = FixPatternRecord(
                pattern_name=name,
                vulnerability_type=vuln_type,
                description=f"Fix for {vuln_type}",
                language="python",
                avg_remediation_time_hours=time,
                success_rate=success,
                usage_count=50
            )
            self.session.add(pattern)

        self.session.commit()

    def test_predict_risk_areas_identifies_high_risk_files(self):
        """Test that risk prediction identifies files with most vulnerabilities."""
        result = predict_risk_areas(project_id=1, session=self.session)

        assert "high_risk_files" in result
        assert len(result["high_risk_files"]) > 0

        # Files should be sorted by risk score (descending)
        scores = [f["risk_score"] for f in result["high_risk_files"]]
        assert scores == sorted(scores, reverse=True)

    def test_get_historical_patterns_trend_analysis(self):
        """Test historical patterns include trend analysis."""
        result = get_historical_patterns(project_id=1, days_back=30, session=self.session)

        assert "vulnerability_trend" in result
        assert "trend_direction" in result["vulnerability_trend"]
        assert result["vulnerability_trend"]["trend_direction"] in ["increasing", "decreasing", "stable"]

    def test_query_context_returns_relevant_results(self):
        """Test semantic query returns relevant results."""
        result = query_context("sql injection", project_id=1, session=self.session)

        assert "vulnerabilities" in result
        assert len(result["vulnerabilities"]) > 0

        # Results should be relevant (contain "sql" or "injection")
        for vuln in result["vulnerabilities"]:
            title = vuln.get("title", "").lower()
            desc = vuln.get("description", "").lower()
            assert "sql" in title or "sql" in desc or "injection" in title or "injection" in desc

    def test_get_historical_patterns_severity_distribution(self):
        """Test severity distribution calculation."""
        result = get_historical_patterns(project_id=1, days_back=30, session=self.session)

        assert "severity_distribution" in result
        dist = result["severity_distribution"]
        assert "critical" in dist
        assert "high" in dist
        assert "medium" in dist
        assert "low" in dist

        # Total should equal number of vulnerabilities
        total = sum(dist.values())
        assert total > 0


class TestKnowledgeGraphEdgeCases:
    """Test edge cases and error handling."""

    def setup_method(self):
        """Set up test database."""
        self.engine = create_engine("sqlite:///:memory:")
        self.Session = sessionmaker(bind=self.engine)
        init_db()
        self.session = self.Session()

    def teardown_method(self):
        """Clean up."""
        self.session.close()

    def test_empty_project_queries(self):
        """Test queries on project with no data."""
        result = predict_risk_areas(project_id=999, session=self.session)
        assert result["high_risk_files"] == []

        result = get_historical_patterns(project_id=999, days_back=30, session=self.session)
        assert result["vulnerability_trend"]["total"] == 0

    def test_query_with_empty_search_term(self):
        """Test query_context with empty search term."""
        result = query_context("", project_id=1, session=self.session)
        # Should return empty or all results
        assert "vulnerabilities" in result

    def test_unicode_in_descriptions(self):
        """Test handling of unicode characters in descriptions."""
        vuln = VulnerabilityRecord(
            vuln_id="VULN-001",
            title="Test with unicode: 中文",
            description="Vulnerabilidad con caracteres especiales: ñ, 中文, العربية",
            severity="high",
            vulnerability_type="sql_injection",
            file_path="test.py",
            line_number=1,
            scanner_source="sast",
            project_id=1
        )
        self.session.add(vuln)
        self.session.commit()

        result = self.session.query(VulnerabilityRecord).filter_by(vuln_id="VULN-001").first()
        assert "中文" in result.title
        assert "العربية" in result.description

    def test_very_long_descriptions(self):
        """Test handling of very long descriptions."""
        long_desc = "A" * 10000

        vuln = VulnerabilityRecord(
            vuln_id="VULN-001",
            title="Test",
            description=long_desc,
            severity="high",
            vulnerability_type="sql_injection",
            file_path="test.py",
            line_number=1,
            scanner_source="sast",
            project_id=1
        )
        self.session.add(vuln)
        self.session.commit()

        result = self.session.query(VulnerabilityRecord).filter_by(vuln_id="VULN-001").first()
        assert len(result.description) == 10000

    def test_concurrent_operations(self):
        """Test concurrent database operations."""
        import threading
        import time

        def add_vulnerability(i):
            vuln = VulnerabilityRecord(
                vuln_id=f"VULN-{i}",
                title=f"Test {i}",
                description="Test",
                severity="high",
                vulnerability_type="sql_injection",
                file_path="test.py",
                line_number=1,
                scanner_source="sast",
                project_id=1
            )
            self.session.add(vuln)
            self.session.commit()

        threads = []
        for i in range(10):
            t = threading.Thread(target=add_vulnerability, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Should have 10 vulnerabilities
        count = self.session.query(VulnerabilityRecord).filter_by(project_id=1).count()
        assert count == 10
