"""
SecurAI Guardian - Knowledge Graph Client
PostgreSQL-based knowledge graph for security patterns and context
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Boolean, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert

from .config import get_settings
from .models import (
    VulnerabilityNode, CodeFileNode, DeveloperNode, FixPatternNode,
    RiskArea, EffortEstimate, Severity, Vulnerability
)

logger = logging.getLogger(__name__)
settings = get_settings()

# SQLAlchemy models
Base = declarative_base()


class VulnerabilityRecord(Base):
    """SQLAlchemy model for vulnerability nodes"""
    __tablename__ = "knowledge_vulnerabilities"

    id = Column(String, primary_key=True)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    cve_id = Column(String, nullable=True)
    location = Column(String, nullable=False)
    fix_patterns = Column(JSON, default=list)
    historical_count = Column(Integer, default=0)
    avg_time_to_fix = Column(Float, nullable=True)
    false_positive_rate = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CodeFileRecord(Base):
    """SQLAlchemy model for code file nodes"""
    __tablename__ = "knowledge_code_files"

    id = Column(String, primary_key=True)  # Generated hash
    path = Column(String, nullable=False, unique=True)
    language = Column(String, nullable=False)
    owner = Column(String, nullable=False)
    criticality_score = Column(Float, nullable=False)
    past_vulnerabilities = Column(Integer, default=0)
    last_security_incident = Column(DateTime, nullable=True)
    security_rating = Column(String, nullable=False)  # A/B/C/D/F
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DeveloperRecord(Base):
    """SQLAlchemy model for developer nodes"""
    __tablename__ = "knowledge_developers"

    id = Column(String, primary_key=True)  # Username
    username = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False)
    security_expertise = Column(Float, default=0.0)
    vulnerabilities_fixed = Column(Integer, default=0)
    avg_fix_time = Column(Float, nullable=True)  # hours
    preferred_review_time = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class FixPatternRecord(Base):
    """SQLAlchemy model for fix pattern nodes"""
    __tablename__ = "knowledge_fix_patterns"

    id = Column(String, primary_key=True)
    pattern_id = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=False)
    code_template = Column(Text, nullable=False)
    applicable_vuln_types = Column(JSON, default=list)
    success_rate = Column(Float, nullable=False)
    avg_fix_time = Column(Float, nullable=False)
    usage_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class KnowledgeGraphClient:
    """
    Knowledge Graph client for security context and learning
    Uses PostgreSQL with SQLAlchemy ORM
    """

    def __init__(self, database_url: str):
        """
        Initialize knowledge graph client

        Args:
            database_url: PostgreSQL connection URL
        """
        self.engine = create_engine(database_url, pool_size=20, max_overflow=30)
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        # Create tables if they don't exist
        Base.metadata.create_all(bind=self.engine)
        logger.info("Knowledge Graph database initialized")

    def get_session(self):
        """Get database session"""
        return self.SessionLocal()

    def close(self):
        """Close database connection"""
        self.engine.dispose()

    # Vulnerability Node Operations
    def upsert_vulnerability(self, vuln: VulnerabilityNode) -> None:
        """Insert or update vulnerability node"""
        with self.get_session() as session:
            record = session.query(VulnerabilityRecord).get(vuln.id)
            if record:
                # Update existing
                record.type = vuln.type
                record.severity = vuln.severity
                record.cve_id = vuln.cve_id
                record.location = vuln.location
                record.fix_patterns = vuln.fix_patterns
                record.historical_count = vuln.historical_count
                record.avg_time_to_fix = vuln.avg_time_to_fix
                record.false_positive_rate = vuln.false_positive_rate
                record.updated_at = datetime.utcnow()
            else:
                # Insert new
                record = VulnerabilityRecord(
                    id=vuln.id,
                    type=vuln.type,
                    severity=vuln.severity,
                    cve_id=vuln.cve_id,
                    location=vuln.location,
                    fix_patterns=vuln.fix_patterns,
                    historical_count=vuln.historical_count,
                    avg_time_to_fix=vuln.avg_time_to_fix,
                    false_positive_rate=vuln.false_positive_rate,
                    created_at=datetime.utcnow()
                )
                session.add(record)

            session.commit()

    def get_vulnerability_by_id(self, vuln_id: str) -> Optional[VulnerabilityNode]:
        """Get vulnerability node by ID"""
        with self.get_session() as session:
            record = session.query(VulnerabilityRecord).get(vuln_id)
            if record:
                return VulnerabilityNode(
                    id=record.id,
                    type=record.type,
                    severity=record.severity,
                    cve_id=record.cve_id,
                    location=record.location,
                    fix_patterns=record.fix_patterns or [],
                    historical_count=record.historical_count,
                    avg_time_to_fix=record.avg_time_to_fix,
                    false_positive_rate=record.false_positive_rate,
                    created_at=record.created_at,
                    updated_at=record.updated_at
                )
            return None

    def find_similar_vulnerabilities(
        self,
        vuln_type: str,
        location: str,
        limit: int = 10
    ) -> List[VulnerabilityNode]:
        """Find similar vulnerabilities by type and location pattern"""
        with self.get_session() as session:
            # Simple similarity: same type, similar location (directory)
            records = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.type == vuln_type,
                VulnerabilityRecord.location.like(f"%{location.split('/')[-2]}%") if '/' in location else True
            ).order_by(VulnerabilityRecord.historical_count.desc()).limit(limit).all()

            return [
                VulnerabilityNode(
                    id=r.id,
                    type=r.type,
                    severity=r.severity,
                    cve_id=r.cve_id,
                    location=r.location,
                    fix_patterns=r.fix_patterns or [],
                    historical_count=r.historical_count,
                    avg_time_to_fix=r.avg_time_to_fix,
                    false_positive_rate=r.false_positive_rate,
                    created_at=r.created_at,
                    updated_at=r.updated_at
                )
                for r in records
            ]

    # Code File Node Operations
    def upsert_code_file(self, file: CodeFileNode) -> None:
        """Insert or update code file node"""
        with self.get_session() as session:
            record = session.query(CodeFileRecord).get(file.id)
            if record:
                # Update
                record.path = file.path
                record.language = file.language
                record.owner = file.owner
                record.criticality_score = file.criticality_score
                record.past_vulnerabilities = file.past_vulnerabilities
                record.last_security_incident = file.last_security_incident
                record.security_rating = file.security_rating
                record.updated_at = datetime.utcnow()
            else:
                # Insert
                record = CodeFileRecord(
                    id=file.id,
                    path=file.path,
                    language=file.language,
                    owner=file.owner,
                    criticality_score=file.criticality_score,
                    past_vulnerabilities=file.past_vulnerabilities,
                    last_security_incident=file.last_security_incident,
                    security_rating=file.security_rating,
                    created_at=datetime.utcnow()
                )
                session.add(record)

            session.commit()

    def get_code_file(self, file_path: str) -> Optional[CodeFileNode]:
        """Get code file by path"""
        with self.get_session() as session:
            record = session.query(CodeFileRecord).filter_by(path=file_path).first()
            if record:
                return CodeFileNode(
                    id=record.id,
                    path=record.path,
                    language=record.language,
                    owner=record.owner,
                    criticality_score=record.criticality_score,
                    past_vulnerabilities=record.past_vulnerabilities,
                    last_security_incident=record.last_security_incident,
                    security_rating=record.security_rating,
                    created_at=record.created_at,
                    updated_at=record.updated_at
                )
            return None

    def update_file_vulnerability_count(self, file_path: str, increment: int = 1) -> None:
        """Increment vulnerability count for a file"""
        with self.get_session() as session:
            record = session.query(CodeFileRecord).filter_by(path=file_path).first()
            if record:
                record.past_vulnerabilities += increment
                record.last_security_incident = datetime.utcnow()
                record.updated_at = datetime.utcnow()
                session.commit()

    # Developer Node Operations
    def upsert_developer(self, developer: DeveloperNode) -> None:
        """Insert or update developer node"""
        with self.get_session() as session:
            record = session.query(DeveloperRecord).get(developer.id)
            if record:
                # Update
                record.username = developer.username
                record.email = developer.email
                record.security_expertise = developer.security_expertise
                record.vulnerabilities_fixed = developer.vulnerabilities_fixed
                record.avg_fix_time = developer.avg_fix_time
                record.preferred_review_time = developer.preferred_review_time
                record.updated_at = datetime.utcnow()
            else:
                # Insert
                record = DeveloperRecord(
                    id=developer.id,
                    username=developer.username,
                    email=developer.email,
                    security_expertise=developer.security_expertise,
                    vulnerabilities_fixed=developer.vulnerabilities_fixed,
                    avg_fix_time=developer.avg_fix_time,
                    preferred_review_time=developer.preferred_review_time,
                    created_at=datetime.utcnow()
                )
                session.add(record)

            session.commit()

    def get_developer_expertise(self, username: str) -> float:
        """Get developer security expertise score"""
        with self.get_session() as session:
            record = session.query(DeveloperRecord).filter_by(username=username).first()
            return record.security_expertise if record else 0.0

    def increment_developer_fix_count(self, username: str, fix_hours: float) -> None:
        """Increment developer's fix count and update average"""
        with self.get_session() as session:
            record = session.query(DeveloperRecord).filter_by(username=username).first()
            if record:
                record.vulnerabilities_fixed += 1
                # Update rolling average
                if record.avg_fix_time is None:
                    record.avg_fix_time = fix_hours
                else:
                    n = record.vulnerabilities_fixed
                    record.avg_fix_time = ((record.avg_fix_time * (n - 1)) + fix_hours) / n
                record.updated_at = datetime.utcnow()
                session.commit()

    # Fix Pattern Operations
    def upsert_fix_pattern(self, pattern: FixPatternNode) -> None:
        """Insert or update fix pattern"""
        with self.get_session() as session:
            record = session.query(FixPatternRecord).get(pattern.id)
            if record:
                # Update
                record.pattern_id = pattern.pattern_id
                record.description = pattern.description
                record.code_template = pattern.code_template
                record.applicable_vuln_types = pattern.applicable_vuln_types
                record.success_rate = pattern.success_rate
                record.avg_fix_time = pattern.avg_fix_time
                record.usage_count = pattern.usage_count
                record.updated_at = datetime.utcnow()
            else:
                # Insert
                record = FixPatternRecord(
                    id=pattern.id,
                    pattern_id=pattern.pattern_id,
                    description=pattern.description,
                    code_template=pattern.code_template,
                    applicable_vuln_types=pattern.applicable_vuln_types,
                    success_rate=pattern.success_rate,
                    avg_fix_time=pattern.avg_fix_time,
                    usage_count=pattern.usage_count,
                    created_at=datetime.utcnow()
                )
                session.add(record)

            session.commit()

    def get_fix_pattern(self, pattern_id: str) -> Optional[FixPatternNode]:
        """Get fix pattern by ID"""
        with self.get_session() as session:
            record = session.query(FixPatternRecord).get(pattern_id)
            if record:
                return FixPatternNode(
                    id=record.id,
                    pattern_id=record.pattern_id,
                    description=record.description,
                    code_template=record.code_template,
                    applicable_vuln_types=record.applicable_vuln_types,
                    success_rate=record.success_rate,
                    avg_fix_time=record.avg_fix_time,
                    usage_count=record.usage_count,
                    created_at=record.created_at,
                    updated_at=record.updated_at
                )
            return None

    def get_fix_patterns_for_vuln_type(self, vuln_type: str) -> List[FixPatternNode]:
        """Get all fix patterns applicable to a vulnerability type"""
        with self.get_session() as session:
            records = session.query(FixPatternRecord).filter(
                FixPatternRecord.applicable_vuln_types.contains([vuln_type])
            ).order_by(FixPatternRecord.success_rate.desc()).all()

            return [
                FixPatternNode(
                    id=r.id,
                    pattern_id=r.pattern_id,
                    description=r.description,
                    code_template=r.code_template,
                    applicable_vuln_types=r.applicable_vuln_types,
                    success_rate=r.success_rate,
                    avg_fix_time=r.avg_fix_time,
                    usage_count=r.usage_count,
                    created_at=r.created_at,
                    updated_at=r.updated_at
                )
                for r in records
            ]

    # Query Operations
    def predict_risk_areas(self, project_id: int) -> List[RiskArea]:
        """
        Predict which files are most likely to have vulnerabilities
        based on historical patterns
        """
        with self.get_session() as session:
            # Query files with most vulnerabilities, highest severity
            records = session.query(CodeFileRecord).filter(
                CodeFileRecord.past_vulnerabilities > 0
            ).order_by(
                CodeFileRecord.past_vulnerabilities.desc(),
                CodeFileRecord.criticality_score.desc()
            ).limit(10).all()

            result = []
            for record in records:
                # Calculate risk score (simple heuristic)
                risk_score = (record.past_vulnerabilities * 10) + (record.criticality_score * 100)

                result.append(RiskArea(
                    file_path=record.path,
                    risk_score=risk_score,
                    historical_vulns=record.past_vulnerabilities,
                    avg_severity=record.criticality_score,
                    recommendations=[
                        f"File has {record.past_vulnerabilities} historical vulnerabilities",
                        f"Security rating: {record.security_rating}",
                        "Recommend extra security review for changes"
                    ]
                ))

            return result

    def get_historical_patterns(self, file_path: str) -> List[Dict[str, Any]]:
        """Get historical vulnerability patterns for a file"""
        with self.get_session() as session:
            file_record = session.query(CodeFileRecord).filter_by(path=file_path).first()
            if not file_record:
                return []

            # Get related vulnerabilities
            vuln_records = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.location.like(f"%{file_path}%")
            ).all()

            patterns = []
            for vuln in vuln_records:
                patterns.append({
                    'type': vuln.type,
                    'severity': vuln.severity,
                    'cve_id': vuln.cve_id,
                    'fix_patterns': vuln.fix_patterns or [],
                    'count': vuln.historical_count
                })

            return patterns

    def store_analysis(
        self,
        vulnerability_id: str,
        analysis: Dict[str, Any],
        is_true_positive: bool,
        confidence: float
    ) -> None:
        """Store analysis results in knowledge graph"""
        # Update vulnerability node with analysis
        vuln_node = self.get_vulnerability_by_id(vulnerability_id)
        if vuln_node:
            vuln_node.historical_count += 1
            # Update false positive rate
            if not is_true_positive:
                vuln_node.false_positive_rate = (
                    (vuln_node.false_positive_rate * (vuln_node.historical_count - 1) + 1) /
                    vuln_node.historical_count
                )
            self.upsert_vulnerability(vuln_node)

        # Store fix pattern if provided
        if analysis.get('fix_recommendation'):
            pattern_id = f"pattern_{analysis['fix_recommendation'][:50]}"
            pattern = FixPatternNode(
                id=pattern_id,
                pattern_id=pattern_id,
                description=analysis['fix_recommendation'],
                code_template=analysis.get('code_before', ''),
                applicable_vuln_types=[vuln_node.type] if vuln_node else [],
                success_rate=confidence,
                avg_fix_time=4.0,  # Default estimate
                usage_count=1
            )
            self.upsert_fix_pattern(pattern)

    def estimate_remediation_effort(self, vulnerability: Vulnerability) -> EffortEstimate:
        """
        Estimate time/effort required to fix based on historical data
        """
        # Find similar past vulnerabilities
        similar = self.find_similar_vulnerabilities(
            vuln_type=vulnerability.source.value,
            location=vulnerability.file_path,
            limit=20
        )

        if len(similar) >= 5:
            # Calculate average fix time
            total_hours = sum(
                s.avg_time_to_fix for s in similar
                if s.avg_time_to_fix is not None
            )
            avg_hours = total_hours / len(similar) if total_hours > 0 else 4.0
            confidence = 0.8
        else:
            # Not enough data, use default estimates by severity
            defaults = {
                'critical': 16,  # 2 days
                'high': 8,       # 1 day
                'medium': 4,     # half day
                'low': 1         # 1 hour
            }
            avg_hours = defaults.get(vulnerability.severity.value, 4)
            confidence = 0.5

        return EffortEstimate(
            estimated_hours=avg_hours,
            confidence=confidence,
            based_on_n=len(similar),
            reasoning=f"Based on {len(similar)} similar historical vulnerabilities"
        )

    def query_context(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """
        Query knowledge graph for context about a vulnerability
        Returns comprehensive context for Analyzer Agent
        """
        context = {
            'file_history': {},
            'developer_expertise': {},
            'similar_vulnerabilities': [],
            'recommended_patterns': []
        }

        # Get file context
        file_node = self.get_code_file(vulnerability.file_path)
        if file_node:
            context['file_history'] = {
                'path': file_node.path,
                'language': file_node.language,
                'owner': file_node.owner,
                'past_vulnerabilities': file_node.past_vulnerabilities,
                'security_rating': file_node.security_rating,
                'criticality_score': file_node.criticality_score
            }

            # Get historical patterns for this file
            context['historical_patterns'] = self.get_historical_patterns(vulnerability.file_path)

        # Get fix patterns for this vulnerability type
        patterns = self.get_fix_patterns_for_vuln_type(vulnerability.source.value)
        context['recommended_patterns'] = [
            {
                'pattern_id': p.pattern_id,
                'description': p.description,
                'success_rate': p.success_rate,
                'avg_fix_time': p.avg_fix_time
            }
            for p in patterns[:5]  # Top 5 patterns
        ]

        return context


def get_knowledge_graph() -> KnowledgeGraphClient:
    """Factory function to create Knowledge Graph client"""
    return KnowledgeGraphClient(database_url=settings.database_url)
