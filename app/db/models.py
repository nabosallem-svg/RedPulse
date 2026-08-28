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
    created_at = Column(DateTime, nullable=False, default=sa.func.now())

    # Relationships
    owner = relationship("User", back_populates="projects")
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
    user = relationship("User")
    assets = relationship("Asset", back_populates="recon_job", cascade="all, delete-orphan")
    results = relationship("ReconResult", back_populates="recon_job", cascade="all, delete-orphan")


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
    """Finding category classification for triage."""

    ACCESS_CONTROL = "access_control"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    BUSINESS_LOGIC = "business_logic"
    SENSITIVE_DATA = "sensitive_data"
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    FILE_INCLUSION = "file_inclusion"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    KNOWN_VULNERABILITIES = "known_vulnerabilities"
    TAKEOVER_INDICATORS = "takeover_indicators"
    TECHNOLOGY_SPECIFIC = "technology_specific"


class TriageTag(str, Enum):
    """Triage tags for advanced finding classification."""

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


vuln_scan_status_enum = sa.Enum(VulnScanStatus)
finding_status_enum = sa.Enum(FindingStatus)
finding_severity_enum = sa.Enum(FindingSeverity)


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