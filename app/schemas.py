"""ReconPilot - Pydantic Schemas.

Request/response schemas for the API layer. All schemas use Pydantic v2.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator


# --- Authentication Schemas ---


class UserBase(BaseModel):
    """Base user schema."""
    id: str
    email: str
    full_name: Optional[str] = None
    is_active: bool = True
    is_superuser: bool = False


class UserCreate(BaseModel):
    """Schema for user registration."""
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = Field(None, max_length=100)
    
    @validator("password")
    def password_must_be_strong(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserInDB(UserBase):
    """User model as stored in database."""
    hashed_password: str


class Token(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Decoded token data."""
    email: Optional[str] = None


# --- Organization Schemas ---


class OrganizationBase(BaseModel):
    """Base organization schema."""
    name: str = Field(..., max_length=255)
    description: Optional[str] = Field(None, max_length=500)


class OrganizationCreate(OrganizationBase):
    """Schema for creating an organization."""


class OrganizationDB(OrganizationBase):
    """Organization as stored in database."""
    id: str
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class OrganizationMemberBase(BaseModel):
    """Base member schema."""
    role: str = Field("viewer", max_length=20, comment="Owner, Admin, Analyst, Viewer")


class OrganizationMemberCreate(OrganizationMemberBase):
    """Schema for adding a member."""
    user_id: str = Field(..., max_length=255)


class OrganizationMemberDB(OrganizationMemberBase):
    """Organization member as stored in database."""
    id: str
    user_id: str
    organization_id: str
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


# --- Project Schemas ---


class ProjectBase(BaseModel):
    """Base project schema."""
    name: str = Field(..., max_length=255)
    description: Optional[str] = Field(None, max_length=500)


class ProjectCreate(ProjectBase):
    """Schema for creating a project."""
    organization_id: Optional[str] = Field(None, max_length=255)


class ProjectUpdate(BaseModel):
    """Schema for updating a project."""
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    status: Optional[str] = Field(None, comment="active, paused, completed")


class ProjectDB(ProjectBase):
    """Project as stored in database."""
    id: str
    organization_id: str
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class ProjectScopeBase(BaseModel):
    """Base scope schema."""
    value: str = Field(..., max_length=255, description="Domain, subdomain, or CIDR")
    scope_type: str = Field("domain", max_length=50, comment="domain, subdomain, host, cidr")
    is_wildcard: bool = Field(False, comment="Whether this uses wildcard matching")


class ProjectScopeCreate(ProjectScopeBase):
    """Schema for adding a scope."""


class ProjectScopeDB(ProjectScopeBase):
    """Scope as stored in database."""
    id: str
    project_id: str
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


# --- Scan Schemas ---


class ScanBase(BaseModel):
    """Base scan schema."""
    name: str = Field(..., max_length=255, description="Human-readable scan name")
    description: Optional[str] = Field(None, max_length=500)
    profile: str = Field("standard", max_length=50, comment="quick, standard, deep")


class ScanCreate(ScanBase):
    """Schema for creating a scan."""
    project_id: str = Field(..., max_length=255)


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    profile: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = Field(None, comment="pending, running, completed, failed, cancelled")


class ScanDB(ScanBase):
    """Scan as stored in database."""
    id: str
    project_id: str
    jobs_count: int = Field(default=0)
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class ScanJobBase(BaseModel):
    """Base scan job schema."""
    status: str = Field("pending", max_length=20, comment="pending, running, completed, failed, cancelled")
    progress_percent: int = Field(0, ge=0, le=100, comment="0-100 progress")
    

class ScanJobCreate(BaseModel):
    """Schema for creating a scan job."""
    scan_id: str = Field(..., max_length=255)
    project_id: str = Field(..., max_length=255)


class ScanJobDB(ScanJobBase):
    """Scan job as stored in database."""
    id: str
    scan_id: str
    project_id: str
    recon_results: Optional[Dict[str, Any]] = Field(None, description="Results from recon engine")
    scanner_results: Optional[Dict[str, Any]] = Field(None, description="Results from nuclei scanner")
    scope_check_log: Optional[Dict[str, Any]] = Field(None, description="Scope enforcement audit log")
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


# --- Asset Schemas ---


class AssetBase(BaseModel):
    """Base asset schema."""
    hostname: str = Field(..., max_length=255, description="Hostname or IP address")
    scheme: str = Field("http", max_length=10, comment="http, https")
    port: Optional[int] = Field(None, ge=1, le=65535, comment="Port number")
    ip: Optional[str] = Field(None, max_length=45, comment="IP address (IPv4 or IPv6)")


class AssetCreate(AssetBase):
    """Schema for creating an asset."""
    project_id: str = Field(..., max_length=255)
    source: str = Field("recon", max_length=100, comment="How asset was discovered")


class AssetUpdate(BaseModel):
    """Schema for updating an asset."""
    hostname: Optional[str] = Field(None, max_length=255)
    scheme: Optional[str] = Field(None, max_length=10)
    port: Optional[int] = Field(None, ge=1, le=65535)
    ip: Optional[str] = Field(None, max_length=45)
    status_code: Optional[int] = Field(None, ge=100, le=599)
    title: Optional[str] = Field(None, max_length=500)
    server: Optional[str] = Field(None, max_length=255)
    content_type: Optional[str] = Field(None, max_length=255)
    technologies: Optional[List[str]] = Field(None)
    is_active: Optional[bool] = Field(None)
    in_scope: Optional[str] = Field(
        None,
        comment="in_scope, out_of_scope, pending_review",
    )


class AssetDB(AssetBase):
    """Asset as stored in database."""
    id: str
    project_id: str
    first_seen: datetime
    last_seen: datetime
    last_checked: Optional[datetime] = None
    is_active: bool
    in_scope: str
    asset_type: str = "host"  # computed property, stored as default
    
    model_config = {"from_attributes": True}
    
    @property
    def asset_type_property(self) -> str:
        """Determine asset type from hostname."""
        if self.hostname.startswith("http"):
            return "url"
        if "." in self.hostname:
            parts = self.hostname.split(".")
            if len(parts) > 2:
                return "subdomain"
            return "domain"
        return "host"


class AssetInScopeQuery(BaseModel):
    """Query parameter for in-scope assets."""
    in_scope: Optional[str] = Field(None, comment="in_scope, out_of_scope, pending_review")


# --- Asset Type Schemas ---


class AssetTypeSummary(BaseModel):
    """Summary of asset types in a project."""
    type: str
    count: int


# --- Finding Schemas ---


class FindingBase(BaseModel):
    """Base finding schema."""
    title: str = Field(..., max_length=500)
    category: str = Field(
        ...,
        max_length=100,
        comment="exposure, misconfiguration, known_vulnerabilities, technology_specific, api_related, takeover_indicators",
    )
    severity: str = Field(..., max_length=20, comment="HIGH, MEDIUM, LOW")
    confidence: int = Field(ge=0, le=100, description="0-100 percentage")
    priority: int = Field(ge=0, le=100, description="Deterministic priority score")
    endpoint: Optional[str] = Field(None, max_length=500, description="Vulnerable endpoint URL")
    evidence: Optional[str] = Field(None, description="Raw evidence supporting the finding")
    description: Optional[str] = Field(None, max_length=2000)
    impact: Optional[str] = Field(None, max_length=2000, comment="Potential impact if exploited")
    remediation: Optional[str] = Field(None, max_length=2000, comment="Remediation guidance")
    fingerprint: str = Field(..., max_length=64, description="Stable fingerprint for deduplication")
    asset_id: Optional[str] = Field(None, max_length=36, description="Associated asset ID")


class FindingCreate(FindingBase):
    """Schema for creating a finding."""
    project_id: str = Field(..., max_length=255)
    asset_id: Optional[str] = Field(None, max_length=36)


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""
    title: Optional[str] = Field(None, max_length=500)
    severity: Optional[str] = Field(None, max_length=20, comment="HIGH, MEDIUM, LOW")
    confidence: Optional[int] = Field(None, ge=0, le=100)
    priority: Optional[int] = Field(None, ge=0, le=100)
    endpoint: Optional[str] = Field(None, max_length=500)
    evidence: Optional[str] = Field(None)
    description: Optional[str] = Field(None, max_length=2000)
    impact: Optional[str] = Field(None, max_length=2000)
    remediation: Optional[str] = Field(None, max_length=2000)
    status: Optional[str] = Field(None, comment="new, confirmed, false_positive, accepted, resolved, reopened")


class FindingDB(FindingBase):
    """Finding as stored in database."""
    id: str
    project_id: str
    asset_id: Optional[str]
    first_seen: datetime
    last_seen: datetime
    status: str
    
    model_config = {"from_attributes": True}


class FindingSummary(BaseModel):
    """Summary view for dashboard."""
    id: str
    title: str
    severity: str
    confidence: int
    priority: int
    status: str
    asset_hostname: str
    first_seen: datetime
    last_seen: datetime


# Finding status enum
class FindingStatus(str):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    REOPENED = "reopened"


# --- Finding Deduplication ---


class FingerprintRequest(BaseModel):
    """Request to compute or check a finding fingerprint."""
    project_id: str = Field(..., max_length=255)
    asset_id: Optional[str] = Field(None, max_length=36)
    template_id: Optional[str] = Field(None, max_length=100)
    endpoint: Optional[str] = Field(None, max_length=500)
    evidence: Optional[str] = Field(None, max_length=2000)


# --- Correlation Engine ---


class CorrelationGroup(BaseModel):
    """Group of related findings."""
    root_finding_id: str
    affected_findings: List[str]
    root_cause: str
    affected_assets: List[str]


# --- Risk and Confidence Engine ---


class SeverityConfidencePriority(BaseModel):
    """Separate severity, confidence, and priority values."""
    severity: str = Field(..., comment="HIGH, MEDIUM, LOW")
    confidence: int = Field(ge=0, le=100, description="0-100 percentage")
    priority: int = Field(ge=0, le=100, description="Deterministic priority score")


class PriorityScoreRequest(BaseModel):
    """Request to calculate priority score."""
    severity: str = Field(..., comment="HIGH, MEDIUM, LOW")
    confidence: int = Field(ge=0, le=100, description="0-100 percentage")
    asset_criticality: int = Field(
        default=50, ge=0, le=100,
        description="Asset criticality weight 0-100",
    )


class PriorityScoreResponse(BaseModel):
    """Response with calculated priority."""
    priority: int
    algorithm: str = "deterministic_weighted_average"
    explanation: str


# --- AI Security Analyst ---


class AIAnalysisRequest(BaseModel):
    """Request for AI analysis of findings."""
    finding_ids: List[str] = Field(..., description="Finding IDs to analyze")
    analysis_type: str = Field(
        "explain",
        max_length=50,
        comment="explain, summarize, relate, suggest_verification, impact, remediation, report_draft",
    )


class AIAnalysisResponse(BaseModel):
    """Response from AI analysis."""
    finding_id: str
    analysis: str
    is_ai: bool = Field(True, description="Flag to distinguish from scanner evidence")
    confidence: float = Field(ge=0, le=1, description="AI confidence in this analysis")


class AIAnalysisBatchResponse(BaseModel):
    """Batch AI analysis response."""
    analyses: List[AIAnalysisResponse]


# --- Report Generator ---


class ReportBase(BaseModel):
    """Base report schema."""
    title: str = Field(..., max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    format: str = Field("html", max_length=20, comment="html, json")


class ReportCreate(ReportBase):
    """Schema for creating a report."""
    project_id: str = Field(..., max_length=255)


class ReportDB(ReportBase):
    """Report as stored in database."""
    id: str
    project_id: str
    status: str = Field("draft", max_length=20, comment="draft, reviewed, published")
    generated_at: datetime
    generated_by: str = Field(..., max_length=255, description="User ID or system")
    
    model_config = {"from_attributes": True}


class ReportQualityCheck(BaseModel):
    """Report quality checker result."""
    score: int = Field(ge=0, le=100, description="Quality score out of 100")
    checks: Dict[str, bool] = Field(
        description="Individual check results: affected_asset, clear_title, evidence, reproduction_guidance, impact, remediation",
    )
    missing_sections: List[str] = Field(default_factory=list, description="List of missing or weak sections")


class ReportQualityResponse(BaseModel):
    """Report quality response."""
    report_id: str
    quality: ReportQualityCheck
    recommendations: List[str] = Field(default_factory=list)


# Report status enum
class ReportStatus(str):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    PUBLISHED = "published"


# --- Continuous Monitoring ---


class MonitoringConfigBase(BaseModel):
    """Base monitoring configuration schema."""
    name: str = Field(max_length=255, default="Continuous Monitoring")
    frequency: str = Field("daily", max_length=50, comment="every 6 hours, daily, weekly")
    profile: str = Field("standard", max_length=50, comment="quick, standard, deep")


class MonitoringConfigCreate(MonitoringConfigBase):
    """Schema for creating monitoring config."""
    project_id: str = Field(..., max_length=255)


class MonitoringConfigDB(MonitoringConfigBase):
    """Monitoring config as stored in database."""
    id: str
    project_id: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class MonitoringCycleRequest(BaseModel):
    """Request to start a monitoring cycle."""
    project_id: str = Field(..., max_length=255)


class MonitoringChangeDetected(BaseModel):
    """Schema for representing a detected change in monitoring."""
    change_type: str = Field(
        ...,
        comment="new_asset, removed_asset, new_endpoint, technology_change, new_finding, reopened_finding",
    )
    asset_id: Optional[str] = Field(None, max_length=36)
    finding_id: Optional[str] = Field(None, max_length=36)
    description: str
    severity: str = Field(..., comment="HIGH, MEDIUM, LOW")


# --- Notification Schemas ---


class NotificationBase(BaseModel):
    """Base notification schema."""
    category: str = Field(
        ...,
        max_length=50,
        comment="NEW_ASSET, IMPORTANT_CHANGE, HIGH_FINDING, CRITICAL_FINDING, SCAN_FAILED, SCAN_COMPLETED, REGRESSION",
    )
    title: str = Field(..., max_length=255)
    message: str


class NotificationCreate(NotificationBase):
    """Schema for creating a notification."""
    project_id: Optional[str] = Field(None, max_length=255)
    user_id: Optional[str] = Field(None, max_length=255)


class NotificationDB(NotificationBase):
    """Notification as stored in database."""
    id: str
    is_read: bool
    project_id: Optional[str]
    user_id: Optional[str]
    created_at: datetime
    
    model_config = {"from_attributes": True}


class NotificationCategory(str):
    """Notification categories enum."""
    NEW_ASSET = "NEW_ASSET"
    IMPORTANT_CHANGE = "IMPORTANT_CHANGE"
    HIGH_FINDING = "HIGH_FINDING"
    CRITICAL_FINDING = "CRITICAL_FINDING"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    REGRESSION = "REGRESSION"


# --- Project Schemas ---


class ProjectSchema(ProjectBase):
    """Project response schema."""
    id: str
    owner_id: str
    created_at: datetime
    
    model_config = {"from_attributes": True}


class EngagementCreate(BaseModel):
    """Schema for creating an engagement - input only."""
    name: str = Field(..., max_length=255)
    project_id: str = Field(..., max_length=255)
    description: Optional[str] = Field(None, max_length=500)


class EngagementSchema(BaseModel):
    """Engagement response schema."""
    id: str
    name: str
    description: Optional[str] = None
    status: str = "draft"
    project_id: str
    created_at: datetime
    
    model_config = {"from_attributes": True}


class AuthorizationSchema(BaseModel):
    """Authorization response schema."""
    id: str
    engagement_id: str
    project_id: Optional[str] = None
    user_id: str
    target_domain: str
    method: str
    verification_token: Optional[str] = None
    verified: bool = False
    verified_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    bounty_platform: Optional[str] = None
    bounty_program_handle: Optional[str] = None
    instructions: Optional[str] = None
    
    model_config = {"from_attributes": True}


class ScopeRuleSchema(BaseModel):
    """Scope rule response schema."""
    id: str
    engagement_id: str
    target: str
    is_include: bool
    source: str = "manual"  # manual, bounty_platform_synced, etc.
    created_at: datetime
    
    model_config = {"from_attributes": True}


# --- API Response Envelopes ---


class APIResponse(BaseModel):
    """Standard API response envelope."""
    success: bool = True
    data: Any = None
    error: Optional[dict] = None
    meta: Optional[dict] = None


class APIError(BaseModel):
    """Standard API error response."""
    code: str
    message: str
    details: Optional[dict] = None


class PaginationMeta(BaseModel):
    """Pagination metadata."""
    page: int = 1
    per_page: int = 50
    total: int = 0
    pages: int = 0


class PaginatedResponse(BaseModel):
    """Paginated API response."""
    success: bool = True
    data: List[Any]
    meta: PaginationMeta