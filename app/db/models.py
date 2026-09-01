"""SQLAlchemy database models for RedPulse.

Models: User, Project, Engagement, Authorization, ScopeRule, PlatformConnection,
Asset, ReconJob, ReconResult.
Enums are Python Enum classes mapped via SQLAlchemy Enum for DB-level enforcement.
"""

import uuid
from enum import Enum

import sqlalchemy as sa
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Text,
    Integer,
    Float,
    JSON,
    UniqueConstraint,
    ForeignKey,
)
from sqlalchemy.orm import RelationshipProperty, relationship

from app.db.base import Base


# ----- Python Enum classes (used in model definitions) -----


class UserStatus(str, Enum):
    """User account status enum."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


class ProjectStatus(str, Enum):
    """Project status enum values."""

    DRAFT = "draft"
    PENDING_VERIFICATION = "pending_verification"
    AUTHORIZED = "authorized"
    EXPIRED = "expired"


class EngagementStatus(str, Enum):
    """Engagement status enum values."""

    DRAFT = "draft"
    PENDING_VERIFICATION = "pending_verification"
    AUTHORIZED = "authorized"
    EXPIRED = "expired"


class AuthorizationMethod(str, Enum):
    """Authorization method enum values."""

    DNS_TXT = "dns_txt"
    BOUNTY_PROGRAM = "bug_bounty_program"


class RuleType(str, Enum):
    """Scope rule type enum values."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class RuleSource(str, Enum):
    """Scope rule source enum values."""

    USER_DEFINED = "user_defined"
    BOUNTY_PLATFORM_SYNCED = "bounty_platform_synced"


class ReconJobStatus(str, Enum):
    """Recon job status enum values."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReconTool(str, Enum):
    """Recon tool enum values."""

    SUBFINDER = "subfinder"
    HTTPX = "httpx"
    NMAP = "nmap"


class AssetType(str, Enum):
    """Asset type enum values."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    SERVICE = "service"


class ChangeType(str, Enum):
    """Asset change detection enum."""

    NEW = "new"
    CHANGED = "changed"
    REMOVED = "removed"


class WorkspaceRole(str, Enum):
    """Workspace member role enum (RBAC)."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class SubscriptionPlan(str, Enum):
    """Subscription plan enum with centralized pricing and metadata."""

    FREE = "free"
    BUSINESS = "business"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, Enum):
    """Subscription status enum."""

    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    TRIALING = "trialing"


class CreditType(str, Enum):
    """Credit transaction type."""

    GRANTED = "granted"
    PURCHASED = "purchased"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REFUNDED = "refunded"


# SQLAlchemy Enum types for DB-level constraint
user_status_enum = sa.Enum(UserStatus)
project_status_enum = sa.Enum(ProjectStatus)
engagement_status_enum = sa.Enum(EngagementStatus)
authorization_method_enum = sa.Enum(AuthorizationMethod)
rule_type_enum = sa.Enum(RuleType)
rule_source_enum = sa.Enum(RuleSource)
recon_job_status_enum = sa.Enum(ReconJobStatus)
recon_tool_enum = sa.Enum(ReconTool)
asset_type_enum = sa.Enum(AssetType)
change_type_enum = sa.Enum(ChangeType)
workspace_role_enum = sa.Enum(WorkspaceRole)
subscription_plan_enum = sa.Enum(SubscriptionPlan)
subscription_status_enum = sa.Enum(SubscriptionStatus)
credit_type_enum = sa.Enum(CreditType)


# ----- Models -----


class User(Base):
    """User model representing an authenticated account."""

    __tablename__ = "users"

    id = Column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships - engagements accessed through projects
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    authorizations = relationship("Authorization", back_populates="user", cascade="all, delete-orphan")
    platform_connections = relationship("PlatformConnection", back_populates="user", cascade="all, delete-orphan")


class Project(Base):
    """Project model - represents a target engagement scope."""

    __tablename__ = "projects"

    id = Column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(engagement_status_enum, nullable=False, default=EngagementStatus.DRAFT)
    owner_id = Column(
        String(36), ForeignKey("users.id"), nullable=False
    )  # FK to User.id
    workspace_id = Column(
        String(36), ForeignKey("workspaces.id"), nullable=True, index=True
    )  # FK to Workspace.id (multi-tenancy)
    created_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    owner = relationship("User", back_populates="projects")
    workspace = relationship("Workspace", back_populates="projects")
    engagements = relationship("Engagement", back_populates="project", cascade="all, delete-orphan")
    authorizations = relationship("Authorization", back_populates="project", cascade="all, delete-orphan")


class Engagement(Base):
    """Engagement model - a specific testing engagement within a project."""

    __tablename__ = "engagements"

    id = Column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(engagement_status_enum, nullable=False, default=EngagementStatus.DRAFT)
    project_id = Column(
        String(36), ForeignKey("projects.id"), nullable=False
    )  # FK to Project.id
    created_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    project = relationship("Project", back_populates="engagements")
    authorization = relationship(
        "Authorization", back_populates="engagement", uselist=False, cascade="all, delete-orphan"
    )
    scope_rules = relationship("ScopeRule", back_populates="engagement", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="engagement", cascade="all, delete-orphan")
    recon_jobs = relationship("ReconJob", back_populates="engagement", cascade="all, delete-orphan")


class Authorization(Base):
    """Authorization model - verified permission to test a target domain."""

    __tablename__ = "authorizations"

    id = Column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    engagement_id = Column(
        String(36), ForeignKey("engagements.id"), nullable=False
    )  # FK to Engagement.id
    project_id = Column(
        String(36), ForeignKey("projects.id"), nullable=False
    )  # FK to Project.id (denormalized)
    user_id = Column(
        String(36), ForeignKey("users.id"), nullable=False
    )  # FK to User.id
    target_domain = Column(String(255), nullable=False)
    method = Column(authorization_method_enum, nullable=False)  # dns_txt or bug_bounty_program
    verification_token = Column(String(500), nullable=True)  # only used for dns_txt method
    bounty_platform = Column(String(100), nullable=True)  # e.g. "hackerone", "bugcrowd"
    bounty_program_handle = Column(String(255), nullable=True)  # the program's identifier on that platform
    verified = Column(Boolean, nullable=False, default=False)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    engagement = relationship("Engagement", back_populates="authorization")
    project = relationship("Project", back_populates="authorizations")
    user = relationship("User", back_populates="authorizations")


class ScopeRule(Base):
    """Scope rule model - defines authorized/included or excluded targets for an engagement."""

    __tablename__ = "scope_rules"

    id = Column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    engagement_id = Column(
        String(36), ForeignKey("engagements.id"), nullable=False
    )  # FK to Engagement.id
    pattern = Column(String(255), nullable=False)  # e.g. "example.com", "*.example.com"
    rule_type = Column(rule_type_enum, nullable=False)  # include | exclude
    source = Column(rule_source_enum, nullable=False)  # user_defined | bounty_platform_synced
    created_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    engagement = relationship("Engagement", back_populates="scope_rules")


class PlatformConnection(Base):
    """Platform connection for bug bounty program authentication."""

    __tablename__ = "platform_connections"

    id = Column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id = Column(
        String(36), ForeignKey("users.id"), nullable=False
    )  # FK to User.id
    platform = Column(String(50), nullable=False)  # hackerone, bugcrowd
    access_token = Column(String(500), nullable=False)  # encrypted at rest
    platform_username = Column(String(255), nullable=True)
    connected_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    user = relationship("User", back_populates="platform_connections")


# ----- Recon Models -----


class Asset(Base):
    """Asset model - represents a discovered host, subdomain, IP, URL, or service."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "value", "asset_type", name="uq_asset_per_engagement"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False, index=True)
    asset_type = Column(asset_type_enum, nullable=False)
    value = Column(String(500), nullable=False)  # hostname, IP, URL, or service identifier
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)  # tcp, udp, http, https
    service_name = Column(String(100), nullable=True)  # http, ssh, dns, etc.
    technology = Column(String(200), nullable=True)  # nginx, Apache, etc.
    http_status = Column(Integer, nullable=True)
    http_title = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    source_tool = Column(recon_tool_enum, nullable=False)
    source_job_id = Column(String(36), ForeignKey("recon_jobs.id"), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=sa.func.now())
    last_seen = Column(DateTime, nullable=False, default=sa.func.now())
    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    engagement = relationship("Engagement", back_populates="assets")
    recon_job = relationship("ReconJob", back_populates="assets")


class ReconJob(Base):
    """ReconJob model - tracks a recon job execution."""

    __tablename__ = "recon_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    tool = Column(recon_tool_enum, nullable=False)
    target = Column(String(500), nullable=False)  # domain or URL to scan
    status = Column(recon_job_status_enum, nullable=False, default=ReconJobStatus.PENDING)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    result_summary = Column(JSON, nullable=True)  # stats: hosts_found, services_found, etc.
    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    engagement = relationship("Engagement", back_populates="recon_jobs")
    assets = relationship("Asset", back_populates="recon_job", cascade="all, delete-orphan")
    results = relationship("ReconResult", back_populates="recon_job", cascade="all, delete-orphan")
    user = relationship("User")


# ==================== SaaS Layer Models (Phase 9) ====================


class Workspace(Base):
    """Workspace model - multi-tenancy container.

    Each workspace isolates data between different customers/teams.
    All projects, engagements, and findings belong to a workspace.
    """

    __tablename__ = "workspaces"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

# Relationships
    owner = relationship("User", foreign_keys=[owner_id])
    members = relationship("WorkspaceMember", back_populates="workspace", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="workspace")
    subscription = relationship("Subscription", back_populates="workspace", uselist=False)
    idempotency_keys = relationship("IdempotencyKey", back_populates="workspace", cascade="all, delete-orphan")


class WorkspaceMember(Base):
    """Workspace membership with RBAC role.

    Roles:
    - admin: Full access (manage members, billing, all projects)
    - analyst: Can run scans, manage findings, create reports
    - viewer: Read-only access to all workspace data
    """

    __tablename__ = "workspace_members"
    __table_args__ = (
        UniqueConstraint("workspace_id", "user_id", name="uq_workspace_member"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    role = Column(workspace_role_enum, nullable=False, default=WorkspaceRole.VIEWER)
    invited_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    joined_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    workspace = relationship("Workspace", back_populates="members")
    user = relationship("User", foreign_keys=[user_id])
    inviter = relationship("User", foreign_keys=[invited_by])


class Subscription(Base):
    """Subscription model for billing via Stripe.

    Tracks the current plan, Stripe customer/subscription IDs,
    and billing cycle dates.
    """

    __tablename__ = "subscriptions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False, unique=True, index=True)
    plan = Column(subscription_plan_enum, nullable=False, default=SubscriptionPlan.FREE)
    status = Column(subscription_status_enum, nullable=False, default=SubscriptionStatus.ACTIVE)

    # Stripe identifiers
    stripe_customer_id = Column(String(255), nullable=True, unique=True)
    stripe_subscription_id = Column(String(255), nullable=True, unique=True)
    stripe_price_id = Column(String(255), nullable=True)

    # Plan limits
    max_projects = Column(Integer, nullable=False, default=1)
    max_scans_per_day = Column(Integer, nullable=False, default=5)
    max_assets_per_project = Column(Integer, nullable=False, default=100)
    max_monitoring_schedules = Column(Integer, nullable=False, default=1)

    # Billing cycle
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    cancel_at_period_end = Column(Boolean, nullable=False, default=False)

    # Credits included in plan
    monthly_credits = Column(Integer, nullable=False, default=100)
    credits_used_this_period = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    workspace = relationship("Workspace", back_populates="subscription")


class CreditBalance(Base):
    """Credit balance and transaction history.

    Credits are consumed for scan operations, AI analysis, and exports.
    Each transaction is tracked for audit purposes.
    """

    __tablename__ = "credit_balances"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    # Balance
    balance = Column(Integer, nullable=False, default=0)
    total_granted = Column(Integer, nullable=False, default=0)
    total_purchased = Column(Integer, nullable=False, default=0)
    total_consumed = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    user = relationship("User")
    transactions = relationship("CreditTransaction", back_populates="balance", cascade="all, delete-orphan")


class CreditTransaction(Base):
    """Individual credit transaction for audit trail."""

    __tablename__ = "credit_transactions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    balance_id = Column(String(36), ForeignKey("credit_balances.id"), nullable=False, index=True)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    credit_type = Column(credit_type_enum, nullable=False)
    amount = Column(Integer, nullable=False, comment="Positive for grants/purchases, negative for consumption")
    description = Column(String(500), nullable=True)
    reference_id = Column(String(36), nullable=True, comment="ID of related scan/finding/export")

    created_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    balance = relationship("CreditBalance", back_populates="transactions")
    workspace = relationship("Workspace")
    user = relationship("User")


class DuplicatePrediction(Base):
    """Tracks predicted duplicate findings before report export.

    When a report is about to be exported, this model stores predictions
    of which findings might be duplicates of publicly disclosed vulnerabilities.
    Users must review these predictions before the report is sent.
    """

    __tablename__ = "duplicate_predictions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)

    # Prediction details
    predicted_duplicate = Column(Boolean, nullable=False, default=False)
    confidence_score = Column(Float, nullable=False, default=0.0, comment="0.0-1.0 confidence")
    similar_report_url = Column(String(2000), nullable=True, comment="URL of potentially duplicate report")
    similar_report_source = Column(String(100), nullable=True, comment="hackerone, bugcrowd, cve, etc.")
    similar_report_title = Column(String(500), nullable=True)
    disclosed_at = Column(DateTime, nullable=True, comment="When the similar report was disclosed")

    # User review
    reviewed = Column(Boolean, nullable=False, default=False)
    is_duplicate = Column(Boolean, nullable=True, comment="User's determination after review")
    review_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    finding = relationship("Finding")
    project = relationship("Project")
    workspace = relationship("Workspace")


class ReconResult(Base):
    """ReconResult model - raw tool output for audit trail."""

    __tablename__ = "recon_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    recon_job_id = Column(String(36), ForeignKey("recon_jobs.id"), nullable=False, index=True)
    tool = Column(recon_tool_enum, nullable=False)
    raw_output = Column(Text, nullable=True)  # full tool stdout/stderr
    parsed_data = Column(JSON, nullable=True)  # structured parse result
    created_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    recon_job = relationship("ReconJob", back_populates="results")


# ----- Assessment & Finding Models -----


class VulnScanStatus(str, Enum):
    """Vulnerability scan status enum."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    """Finding status lifecycle enum."""

    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    REOPENED = "reopened"


class FindingSeverity(str, Enum):
    """Finding severity enum."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Finding category classification for triage.

    Phase 8: Added RCE, SSRF_CLOUD_METADATA, JWT_VULNERABILITY,
    RACE_CONDITION, MASS_ASSIGNMENT, BUSINESS_LOGIC_BYPASS.
    """

    ACCESS_CONTROL = "access_control"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    BUSINESS_LOGIC = "business_logic"
    BUSINESS_LOGIC_BYPASS = "business_logic_bypass"
    SENSITIVE_DATA = "sensitive_data"
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    SSRF_CLOUD_METADATA = "ssrf_cloud_metadata"
    RCE = "rce"
    JWT_VULNERABILITY = "jwt_vulnerability"
    RACE_CONDITION = "race_condition"
    MASS_ASSIGNMENT = "mass_assignment"
    FILE_INCLUSION = "file_inclusion"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    KNOWN_VULNERABILITIES = "known_vulnerabilities"
    TAKEOVER_INDICATORS = "takeover_indicators"
    TECHNOLOGY_SPECIFIC = "technology_specific"


class TriageTag(str, Enum):
    """Triage tags for advanced finding classification.

    Phase 8: Added REMOTE_CODE_EXECUTION, SSRF_CLOUD_METADATA,
    JWT_ATTACK, RACE_CONDITION, MASS_ACCOUNT_TAKEOVER,
    BUSINESS_LOGIC_BYPASS.
    """

    CRITICAL_RISK = "critical_risk"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    SESSION_HIJACKING = "session_hijacking"
    INSECURE_DIRECT_OBJECT = "insecure_direct_object"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    AUTH_BYPASS = "auth_bypass"
    BUSINESS_LOGIC_FLAW = "business_logic_flaw"
    SENSITIVE_SECRET = "sensitive_secret"
    JAVASCRIPT_SECRETS = "javascript_secrets"
    COOKIE_SECURITY = "cookie_security"
    CORS_MISCONFIG = "cors_misconfig"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    # Phase 8: Advanced high-impact tags
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    SSRF_CLOUD_METADATA = "ssrf_cloud_metadata"
    JWT_ATTACK = "jwt_attack"
    RACE_CONDITION = "race_condition"
    MASS_ACCOUNT_TAKEOVER = "mass_account_takeover"
    BUSINESS_LOGIC_BYPASS = "business_logic_bypass"


class TriageDecision(str, Enum):
    """Triage decision enum - analyst verdict on a finding."""

    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    ACCEPTED_RISK = "accepted_risk"


class RetestStatus(str, Enum):
    """Retest job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RetestResult(str, Enum):
    """Retest verification result."""

    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    INCONCLUSIVE = "inconclusive"


vuln_scan_status_enum = sa.Enum(VulnScanStatus)
finding_status_enum = sa.Enum(FindingStatus)
finding_severity_enum = sa.Enum(FindingSeverity)
triage_decision_enum = sa.Enum(TriageDecision)
retest_status_enum = sa.Enum(RetestStatus)
retest_result_enum = sa.Enum(RetestResult)


class VulnerabilityScan(Base):
    """VulnerabilityScan model - tracks a Nuclei scan execution against assets.

    Supports authenticated scanning via optional auth_headers / auth_cookies
    fields that are passed through to Nuclei for testing behind login portals.
    """

    __tablename__ = "vulnerability_scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    status = Column(vuln_scan_status_enum, nullable=False, default=VulnScanStatus.PENDING)
    target = Column(String(500), nullable=False)
    template_path = Column(String(500), nullable=True)

    # Authenticated scanning credentials
    auth_headers = Column(JSON, nullable=True, comment="Custom HTTP headers for auth (e.g. Authorization: Bearer ...)")
    auth_cookies = Column(String(2000), nullable=True, comment="Session cookies for authenticated crawling")

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    result_summary = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    engagement = relationship("Engagement", back_populates="vulnerability_scans")
    asset = relationship("Asset")
    user = relationship("User")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """Finding model - a security vulnerability discovered by Nuclei or other scanners.

    Fingerprint-based deduplication: same (engagement_id, fingerprint) = same finding.
    Status lifecycle: new -> confirmed -> accepted/resolved/false_positive -> reopened.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("engagement_id", "fingerprint", name="uq_finding_per_engagement"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=True, index=True)
    scan_id = Column(String(36), ForeignKey("vulnerability_scans.id"), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    # Vulnerability details
    title = Column(String(500), nullable=False)
    template_id = Column(String(200), nullable=True, comment="Nuclei template ID")
    severity = Column(finding_severity_enum, nullable=False)
    confidence = Column(Integer, nullable=False, default=0, comment="0-100")
    category = Column(String(100), nullable=True, comment="exposure, misconfiguration, etc.")
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    endpoint = Column(String(500), nullable=True, comment="Vulnerable endpoint URL")
    matched_at = Column(String(500), nullable=True, comment="Nuclei matched-at field")
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    # Advanced triage fields (Phase 5)
    triage_tags = Column(JSON, nullable=True, comment="Triage tags: critical_risk, privilege_escalation, etc.")
    poc_curl = Column(Text, nullable=True, comment="Auto-generated PoC curl command for reproduction")
    poc_steps = Column(Text, nullable=True, comment="Human-readable reproduction steps")
    sensitive_params = Column(JSON, nullable=True, comment="Flagged object-ID params (user_id, account_id, etc.)")

    # Dedup & lifecycle
    fingerprint = Column(String(64), nullable=False, comment="Stable dedup fingerprint")
    status = Column(finding_status_enum, nullable=False, default=FindingStatus.NEW)
    first_seen = Column(DateTime, nullable=False, default=sa.func.now())
    last_seen = Column(DateTime, nullable=False, default=sa.func.now())
    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Raw data
    raw_output = Column(Text, nullable=True)

    # Relationships
    engagement = relationship("Engagement", back_populates="findings")
    project = relationship("Project")
    asset = relationship("Asset")
    scan = relationship("VulnerabilityScan", back_populates="findings")
    user = relationship("User")


# Add back_populates targets to Engagement
Engagement.vulnerability_scans = relationship(
    "VulnerabilityScan", back_populates="engagement", cascade="all, delete-orphan"
)
Engagement.findings = relationship(
    "Finding", back_populates="engagement", cascade="all, delete-orphan"
)


# ----- Webhook & Monitoring Models (Phase 7) -----


class WebhookConfig(Base):
    """Webhook configuration for delivering alerts to external services.

    Supports Telegram, Discord, and custom webhook endpoints.
    Each webhook is scoped to a project and can filter by severity.
    """

    __tablename__ = "webhook_configs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    # Webhook details
    name = Column(String(255), nullable=False, comment="Human-readable name for this webhook")
    webhook_type = Column(
        String(50), nullable=False,
        comment="telegram, discord, slack, custom",
    )
    url = Column(String(2000), nullable=False, comment="Webhook URL (Telegram bot API or Discord webhook URL)")

    # Filtering
    min_severity = Column(
        String(20), nullable=False, default="high",
        comment="Minimum severity to trigger alert: critical, high, medium, low, info",
    )
    enabled = Column(Boolean, nullable=False, default=True)

    # Optional: custom headers for custom webhooks
    headers = Column(JSON, nullable=True, comment="Extra HTTP headers for custom webhooks")

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    project = relationship("Project")
    user = relationship("User")


class MonitoringSchedule(Base):
    """Scheduled monitoring configuration for continuous scanning.

    Defines how often a project should be scanned, what tools to use,
    and tracks the last scan time for scheduling.
    """

    __tablename__ = "monitoring_schedules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    # Schedule details
    name = Column(String(255), nullable=False, default="Continuous Monitoring")
    frequency = Column(
        String(50), nullable=False, default="daily",
        comment="every_6h, daily, weekly, monthly",
    )
    profile = Column(
        String(50), nullable=False, default="standard",
        comment="quick, standard, deep",
    )
    enabled = Column(Boolean, nullable=False, default=True)

    # Scope
    targets = Column(JSON, nullable=True, comment="List of target domains/URLs to scan")
    scan_all_assets = Column(Boolean, nullable=False, default=True, comment="Scan all discovered assets")

    # State
    last_scan_at = Column(DateTime, nullable=True)
    next_scan_at = Column(DateTime, nullable=True)
    last_scan_findings_count = Column(Integer, nullable=True)
    last_scan_status = Column(String(20), nullable=True, comment="completed, failed, running")
    consecutive_failures = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    project = relationship("Project")
    user = relationship("User")


# ----- Phase 10: Public API, Custom Webhooks & Audit Logging -----


class ApiKey(Base):
    """API Key for Public API access.

    Keys are stored as SHA-256 hashes; only the prefix is stored in plain text
    for identification. The full key is shown once at creation time.
    Supports scoped access and expiration.
    """

    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=True, index=True)

    name = Column(String(255), nullable=False, comment="Human-readable key name")
    prefix = Column(String(20), nullable=False, index=True, comment="Visible prefix e.g. rp_abc123")
    key_hash = Column(String(64), nullable=False, unique=True, index=True, comment="SHA-256 of full key")
    scopes = Column(JSON, nullable=False, default=lambda: ["read"], comment="List of scopes")

    is_active = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    user = relationship("User")
    workspace = relationship("Workspace")


class CustomWebhook(Base):
    """Custom Webhook for workspace-level event delivery.

    Distinct from WebhookConfig (project alerts). Supports HMAC signing,
    custom headers, retry, and event filtering.
    """

    __tablename__ = "custom_webhooks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    name = Column(String(255), nullable=False)
    url = Column(String(2000), nullable=False)
    secret = Column(String(255), nullable=True, comment="HMAC signing secret (stored plain for dispatch)")
    events = Column(JSON, nullable=False, default=lambda: ["scan.completed"], comment="Subscribed events")

    is_active = Column(Boolean, nullable=False, default=True)
    headers = Column(JSON, nullable=True, comment="Custom HTTP headers")

    # Delivery tracking
    last_triggered_at = Column(DateTime, nullable=True)
    last_status = Column(String(20), nullable=True, comment="success, failed")
    failure_count = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    workspace = relationship("Workspace")
    user = relationship("User")


class AuditLog(Base):
    """Comprehensive audit trail for scans, exports, and key operations.

    Records every sensitive action with actor, resource, timing, and context
    for compliance and forensics. Immutable append-only.
    """

    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Actor
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    api_key_id = Column(String(36), ForeignKey("api_keys.id"), nullable=True, index=True)

    # Scope
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=True, index=True)

    # Action
    action = Column(String(100), nullable=False, index=True, comment="e.g. scan.create, export.json")
    resource_type = Column(String(50), nullable=False, index=True, comment="scan, export, project, api_key, webhook")
    resource_id = Column(String(36), nullable=True, index=True)

    details = Column(JSON, nullable=True, comment="Extra context: target, severity, format, etc.")
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    status = Column(String(20), nullable=False, default="success", comment="success, failure")

    created_at = Column(DateTime, nullable=False, default=sa.func.now(), index=True)

    # Relationships
    user = relationship("User")
    api_key = relationship("ApiKey")
    workspace = relationship("Workspace")
    project = relationship("Project")


# ----- Phase 11-12: Triage & Retest (False Positive Workflow + Retest) -----


class TriageFeedback(Base):
    """Analyst triage feedback - feeds AI layer to reduce false positives.

    Stores human verdict vs AI suggestion for continuous learning.
    Each finding can have multiple feedback entries (e.g., re-triage).
    """

    __tablename__ = "triage_feedback"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=True, index=True)

    analyst_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    decision = Column(triage_decision_enum, nullable=False)
    reason = Column(Text, nullable=True, comment="Analyst justification")
    evidence = Column(Text, nullable=True, comment="Supporting evidence URL or snippet")

    # AI suggestion snapshot at triage time (for learning)
    ai_prediction = Column(String(50), nullable=True, comment="AI's prediction: false_positive / true_positive")
    ai_confidence = Column(Float, nullable=True, comment="AI confidence 0.0-1.0")
    ai_reasoning = Column(Text, nullable=True, comment="AI reasoning text")

    # Learning flags
    ai_was_correct = Column(Boolean, nullable=True, comment="Whether AI matched analyst decision")
    # Explicit weighted learning: feedback_weight is computed in TriageService.submit_triage as
    # base 1.0 * severity_factor {critical:1.5, high:1.3, medium:1.0, low:0.7, info:0.5}
    #         * confidence_factor {finding.confidence <30:0.8, >80:1.2}
    #         * ai_conf_factor {AI confidently wrong:1.25, confidently correct:1.1}
    # Capped 0.5..2.0. Used by TriageAIService as weighted FP rate, so not all feedback is equal.
    feedback_weight = Column(Float, nullable=False, default=1.0, comment="Weighted importance for AI training: severity * confidence * AI-surprise, capped 0.5..2.0")

    created_at = Column(DateTime, nullable=False, default=sa.func.now(), index=True)
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    finding = relationship("Finding")
    project = relationship("Project")
    workspace = relationship("Workspace")
    analyst = relationship("User")


class RetestJob(Base):
    """Retest workflow - verifies a finding is fixed via targeted micro-scan."""

    __tablename__ = "retest_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=True, index=True)
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=True, index=True)

    requested_by = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    status = Column(retest_status_enum, nullable=False, default=RetestStatus.PENDING)
    result = Column(retest_result_enum, nullable=True)

    # Snapshot of original finding at retest creation (for comparison) - ensures same endpoint/parameter check
    original_evidence = Column(Text, nullable=True)
    original_endpoint = Column(String(500), nullable=True)
    original_template_id = Column(String(200), nullable=True, comment="Original nuclei template_id - retest runs same check")
    original_parameter = Column(String(200), nullable=True, comment="Vulnerable parameter if applicable")

    # Verification output
    evidence = Column(Text, nullable=True, comment="New evidence / micro-scan output")
    verified_at = Column(DateTime, nullable=True)
    worker_id = Column(String(100), nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)

    # Auto-resolution flag
    auto_resolved = Column(Boolean, nullable=False, default=False, comment="Whether finding was auto-marked resolved on FIXED")

    created_at = Column(DateTime, nullable=False, default=sa.func.now(), index=True)
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    finding = relationship("Finding")
    project = relationship("Project")
    workspace = relationship("Workspace")
    requester = relationship("User")


# ----- Phase 11-12: Observability - Worker Health -----


class WorkerHealth(Base):
    """Worker heartbeat / health for observability - tracks Celery workers and queues."""

    __tablename__ = "worker_health"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    worker_name = Column(String(255), nullable=False, index=True, unique=True)
    queue = Column(String(100), nullable=False, default="default")
    status = Column(String(20), nullable=False, default="healthy", comment="healthy, degraded, down, crashed")
    last_heartbeat = Column(DateTime, nullable=False, default=sa.func.now(), index=True)
    jobs_processed = Column(Integer, nullable=False, default=0)
    jobs_failed = Column(Integer, nullable=False, default=0)
    consecutive_failures = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True, comment="Extra metrics: queue_length, memory, etc.")

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())
# ----- Idempotency Keys -----

class IdempotencyKey(Base):
    """Idempotency key for webhook and checkout event deduplication."""

    __tablename__ = "idempotency_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(255), nullable=False, unique=True, index=True)
    key_hash = Column(String(64), nullable=False, comment="SHA256 hash of event data")
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=True)
    event_type = Column(String(100), nullable=False, default="")
    processed_at = Column(DateTime, nullable=False, default=sa.func.now())

    created_at = Column(DateTime, nullable=False, default=sa.func.now())
    updated_at = Column(DateTime, nullable=False, default=sa.func.now(), onupdate=sa.func.now())

    # Relationships
    workspace = relationship("Workspace", back_populates="idempotency_keys")

