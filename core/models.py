"""
SecurAI Guardian - Core Data Models
Pydantic schemas for type-safe data validation
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilitySource(str, Enum):
    """Security scanner sources"""
    SAST = "sast"
    DAST = "dast"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    SECRET = "secret"


class TriageAction(str, Enum):
    """Actions after analysis"""
    AUTO_FIX = "auto_fix"
    HUMAN_REVIEW = "human_review"
    DISCARD = "discard"


class RemediationStatus(str, Enum):
    """Remediation plan status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    READY_FOR_REVIEW = "ready_for_review"
    COMPLETED = "completed"
    FAILED = "failed"


class ComplianceFramework(str, Enum):
    """Compliance frameworks"""
    SOX = "SOX"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    PCI_DSS = "PCI-DSS"
    ISO27001 = "ISO27001"


class Vulnerability(BaseModel):
    """Unified vulnerability schema across all scanners"""
    id: str = Field(..., description="Unique vulnerability ID")
    source: VulnerabilitySource = Field(..., description="Scanner source")
    severity: Severity = Field(..., description="Severity level")
    cvss_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS score if available")
    cve_id: Optional[str] = Field(None, description="CVE identifier if applicable")

    # Location
    project_id: int = Field(..., description="GitLab project ID")
    mr_iid: Optional[int] = Field(None, description="Merge request IID")
    file_path: str = Field(..., description="File containing vulnerability")
    line_start: int = Field(..., ge=1, description="Starting line number")
    line_end: int = Field(..., ge=1, description="Ending line number")
    code_snippet: str = Field(..., description="Vulnerable code snippet")

    # Metadata
    dependency_name: Optional[str] = None
    dependency_version: Optional[str] = None
    fixed_version: Optional[str] = None
    scanner_uuid: str = Field(..., description="Scanner-specific UUID")

    # Timestamps
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    def content_hash(self) -> str:
        """Generate hash for deduplication"""
        import hashlib
        content = f"{self.source}:{self.file_path}:{self.line_start}:{self.code_snippet[:100]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AnalyzedVulnerability(Vulnerability):
    """Vulnerability with AI analysis"""
    is_true_positive: bool = Field(..., description="True positive or false positive")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score")

    # Exploitability assessment
    exploitability: str = Field(..., description="High/Medium/Low")
    attack_vector: Optional[str] = None  # Network/Local/Physical
    attack_complexity: Optional[str] = None  # Low/Medium/High
    privileges_required: Optional[str] = None  # None/Low/High
    user_interaction: Optional[bool] = None

    # Business impact
    business_impact: Dict[str, Any] = Field(default_factory=dict)
    financial_risk_tier: Optional[str] = None  # "$0-10K", "$10K-100K", "$100K-1M", "$1M+"

    # Remediation
    fix_recommendation: Optional[str] = None
    fix_patch: Optional[str] = None
    fix_confidence: Optional[float] = None

    # Compliance
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)

    # Decision
    triage_action: TriageAction = Field(..., description="Action to take")
    triage_reasoning: str = Field(..., description="Reasoning behind decision")


class KnowledgeGraphNode(BaseModel):
    """Base node in knowledge graph"""
    id: str
    type: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class VulnerabilityNode(KnowledgeGraphNode):
    """Vulnerability node in knowledge graph"""
    type: str = "vulnerability"
    vuln_type: str
    severity: Severity
    cve_id: Optional[str] = None
    location: str
    fix_patterns: List[str] = Field(default_factory=list)
    historical_count: int = 0
    avg_time_to_fix: Optional[float] = None  # days
    false_positive_rate: float = 0.0


class CodeFileNode(KnowledgeGraphNode):
    """Code file node in knowledge graph"""
    type: str = "code_file"
    path: str
    language: str
    owner: str  # GitLab username
    criticality_score: float = Field(..., ge=0, le=1)
    past_vulnerabilities: int = 0
    last_security_incident: Optional[datetime] = None
    security_rating: str = Field(..., description="A/B/C/D/F")


class DeveloperNode(KnowledgeGraphNode):
    """Developer node in knowledge graph"""
    type: str = "developer"
    username: str
    email: str
    security_expertise: float = Field(..., ge=0, le=1)  # Learned from fixes
    vulnerabilities_fixed: int = 0
    avg_fix_time: Optional[float] = None  # hours
    preferred_review_time: Optional[str] = None  # "morning", "afternoon", etc.


class FixPatternNode(KnowledgeGraphNode):
    """Fix pattern node in knowledge graph"""
    type: str = "fix_pattern"
    pattern_id: str
    description: str
    code_template: str
    applicable_vuln_types: List[str] = Field(default_factory=list)
    success_rate: float = Field(..., ge=0, le=1)
    avg_fix_time: float = Field(..., description="Average hours to apply")
    usage_count: int = 0


class RiskArea(BaseModel):
    """Predicted risk area"""
    file_path: str
    risk_score: float = Field(..., ge=0)
    historical_vulns: int
    avg_severity: float
    recommendations: List[str] = Field(default_factory=list)


class EffortEstimate(BaseModel):
    """Effort estimation for remediation"""
    estimated_hours: float
    confidence: float = Field(..., ge=0, le=1)
    based_on_n: int = Field(..., description="Number of similar past vulnerabilities")
    reasoning: Optional[str] = None


class MergeRequest(BaseModel):
    """GitLab merge request"""
    iid: int
    project_id: int
    title: str
    description: str
    source_branch: str
    target_branch: str
    url: str
    labels: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class SecurityPlan(BaseModel):
    """Security plan from Knowledge Graph Agent"""
    project_id: int
    mr_iid: Optional[int] = None
    high_risk_files: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_tests: List[str] = Field(default_factory=list)
    effort_estimates: List[EffortEstimate] = Field(default_factory=list)
    developer_mapping: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score: float = Field(..., ge=0, le=100)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Metrics(BaseModel):
    """Security metrics for dashboard"""
    mttr_days: float = Field(..., description="Mean time to remediate")
    total_vulnerabilities: int
    open_vulnerabilities: int
    auto_fix_rate: float = Field(..., ge=0, le=1, description="Percentage auto-fixed")
    true_positive_rate: float = Field(..., ge=0, le=1)
    false_positive_rate: float = Field(..., ge=0, le=1)
    compliance_status: Dict[ComplianceFramework, bool] = Field(default_factory=dict)
    vulnerability_trend: List[Dict[str, Any]] = Field(default_factory=list)


class ScanRequest(BaseModel):
    """Request to scan artifacts"""
    pipeline_id: int
    project_id: int
    mr_iid: Optional[int] = None


class ScanResponse(BaseModel):
    """Response from scanner"""
    vulnerabilities: List[Vulnerability]
    processing_time_seconds: float
    artifacts_processed: int


class AnalysisRequest(BaseModel):
    """Request to analyze vulnerabilities"""
    vulnerabilities: List[Vulnerability]
    project_id: int
    mr_iid: Optional[int] = None


class AnalysisResponse(BaseModel):
    """Response from analyzer"""
    analyses: List[AnalyzedVulnerability]
    processing_time_seconds: float
    cache_hit_rate: float = 0.0


class FixRequest(BaseModel):
    """Request to generate fix"""
    vulnerability: AnalyzedVulnerability
    project_id: int
    mr_iid: Optional[int] = None
    apply: bool = True


class FixResponse(BaseModel):
    """Response from remediator"""
    merge_request: Optional[MergeRequest] = None
    patch: Optional[str] = None
    test_results: Optional[Dict[str, Any]] = None
    processing_time_seconds: float


# FastAPI request/response models
class HealthCheck(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    agents: Dict[str, str]  # agent_name -> status


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
