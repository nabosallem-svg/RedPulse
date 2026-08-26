"""ReconPilot - Database Models.

SQLAlchemy ORM models for the ReconPilot platform.
All tenant-owned tables include project_id or organization_id for isolation.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
    UniqueConstraint,
    JSON,
    CheckConstraint,
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


# --- Helper mixins ---


class TimestampMixin:
    """Add created_at and updated_at columns."""
    created_at = Column(DateTime, nullable=False, default=lambda: DateTime().now)  # noqa: E731
    updated_at = Column(
        DateTime, nullable=False,
        default=lambda: DateTime().now, onupdate=lambda: DateTime().now  # noqa: E731
    )


class UUIDMixin:
    """Add id column as primary key."""
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))  # noqa: E731


# --- Core Models ---


class Organization(Base, UUIDMixin, TimestampMixin):
    """Organization entity for multi-tenancy."""
    
    __tablename__ = "organizations"
    
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    
    # Relationships
    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="organization", cascade="all, delete-orphan")


class OrganizationMember(Base, UUIDMixin, TimestampMixin):
    """User membership in an organization with roles."""
    
    __tablename__ = "organization_members"
    
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_user"),
    )
    
    role = Column(
        String,
        nullable=False,
        default="viewer",
        comment="Owner, Admin, Analyst, Viewer",
    )
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    user_id = Column(String, nullable=False)
    
    # Relationships
    organization = relationship("Organization", back_populates="members")
    projects = relationship("Project", secondary="project_organization_members", back_populates="members")  # many-to-many via projects


# Association table for project-member access
project_organization_members = Table(
    "project_organization_members",
    Base.metadata,
    Column("project_id", String, ForeignKey("projects.id"), nullable=False),
    Column("member_id", String, ForeignKey("organization_members.id"), nullable=False),
)


class Project(Base, UUIDMixin, TimestampMixin):
    """Security assessment project."""
    
    __tablename__ = "projects"
    
    __table_args__ = (
        Index("ix_projects_org_id", "organization_id"),
        Index("ix_projects_status", "status"),
    )
    
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(
        String,
        nullable=False,
        default="active",
        comment="active, paused, completed",
    )
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    
    # Relationships
    organization = relationship("Organization", back_populates="projects")
    scopes = relationship("Scope", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="project", cascade="all, delete-orphan")
    monitoring_configs = relationship("MonitoringConfig", back_populates="project", cascade="all, delete-orphan")
    
    # Enforce organization isolation in queries
    @classmethod
    def query_filtered(cls, session, organization_id: str):
        """Return a query filtered by organization_id for tenant isolation."""
        return session.query(cls).filter(cls.organization_id == organization_id)


class Scope(Base, UUIDMixin, TimestampMixin):
    """Authorized target scope for a project."""
    
    __tablename__ = "scopes"
    
    __table_args__ = (
        Index("ix_scopes_project_id", "project_id"),
        UniqueConstraint("project_id", "value", name="uq_project_scope"),
    )
    
    value = Column(String, nullable=False, comment="Domain, subdomain, or CIDR")
    scope_type = Column(
        String,
        nullable=False,
        default="domain",
        comment="domain, subdomain, host, cidr",
    )
    is_wildcard = Column(Boolean, default=False, comment="Whether this uses wildcard matching"),
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="scopes")
    
    # Enforce project isolation
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)


class Scan(Base, UUIDMixin, TimestampMixin):
    """Scan job container."""
    
    __tablename__ = "scans"
    
    __table_args__ = (
        Index("ix_scans_project_id", "project_id"),
        Index("ix_scans_status", "status"),
    )
    
    name = Column(String, nullable=False, default="New Scan")
    description = Column(Text, nullable=True)
    status = Column(
        String,
        nullable=False,
        default="pending",
        comment="pending, running, completed, failed, cancelled",
    )
    profile = Column(
        String,
        nullable=False,
        default="standard",
        comment="quick, standard, deep",
    )
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    jobs = relationship("ScanJob", back_populates="scan", cascade="all, delete-orphan")
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)


class ScanJob(Base, UUIDMixin, TimestampMixin):
    """Individual scan job execution."""
    
    __tablename__ = "scan_jobs"
    
    __table_args__ = (
        Index("ix_scan_jobs_scan_id", "scan_id"),
        Index("ix_scan_jobs_status", "status"),
    )
    
    status = Column(
        String,
        nullable=False,
        default="pending",
        comment="pending, running, completed, failed, cancelled",
    )
    progress_percent = Column(Integer, default=0, comment="0-100 progress")
    recon_results = Column(JSON, nullable=True, comment="Results from recon engine")
    scanner_results = Column(JSON, nullable=True, comment="Results from nuclei scanner")
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    scope_check_log = Column(JSON, nullable=True, comment="Scope enforcement audit log")
    
    # Relationships
    scan = relationship("Scan", back_populates="jobs")
    assets_discovered = relationship("Asset", back_populates="scan_job", cascade="all, delete-orphan")  # noqa: E501
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)


class Asset(Base, UUIDMixin, TimestampMixin):
    """Discovered asset with full intelligence metadata."""
    
    __tablename__ = "assets"
    
    __table_args__ = (
        Index("ix_assets_project_id", "project_id"),
        Index("ix_assets_hostname", "hostname"),
        Index("ix_assets_in_scope", "in_scope"),
        Index("ix_assets_is_active", "is_active"),
        UniqueConstraint("project_id", "hostname", "scheme", name="uq_project_host_scheme"),
    )
    
    hostname = Column(String, nullable=False, comment="Hostname or IP")
    scheme = Column(String, nullable=False, default="http", comment="http, https")
    port = Column(Integer, nullable=True, comment="Port number")
    ip = Column(String, nullable=True, comment="IP address")
    status_code = Column(Integer, nullable=True, comment="HTTP status code")
    title = Column(String, nullable=True, comment="Page title")
    server = Column(String, nullable=True, comment="Server header")
    content_type = Column(String, nullable=True, comment="MIME content type")
    technologies = Column(JSON, nullable=True, comment="Detected technologies array")
    source = Column(String, nullable=False, default="recon", comment="How asset was discovered")
    first_seen = Column(DateTime, nullable=False, default=lambda: DateTime().now)  # noqa: E731
    last_seen = Column(DateTime, nullable=False, default=lambda: DateTime().now)  # noqa: E731
    last_checked = Column(DateTime, nullable=True, comment="When last checked/probed")
    is_active = Column(Boolean, default=True, comment="Whether asset is actively monitored")
    in_scope = Column(
        String,
        nullable=False,
        default="pending_review",
        comment="in_scope, out_of_scope, pending_review",
    )
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    asset_changes = relationship("AssetChange", back_populates="asset", cascade="all, delete-orphan")
    
    # Asset type enum values
    ASSET_TYPES = ["domain", "subdomain", "host", "url", "api", "service"]
    
    @property
    def asset_type(self) -> str:
        """Determine asset type from hostname."""
        if self.hostname.startswith("http"):
            return "url"
        if "." in self.hostname:
            parts = self.hostname.split(".")
            if len(parts) > 2:
                return "subdomain"
            return "domain"
        return "host"
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)
    
    @classmethod
    def query_in_scope(cls, session, project_id: str):
        return session.query(cls).filter(
            cls.project_id == project_id,
            cls.in_scope == "in_scope"
        )


class AssetChange(Base, UUIDMixin, TimestampMixin):
    """Historical changes to asset state."""
    
    __tablename__ = "asset_changes"
    
    __table_args__ = (
        Index("ix_asset_changes_asset_id", "asset_id"),
        Index("ix_asset_changes_changed_at", "changed_at"),
    )
    
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False)
    changed_field = Column(String, nullable=False, comment="Field that changed")
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=False)
    changed_at = Column(DateTime, nullable=False, default=lambda: DateTime().now)  # noqa: E731
    
    # Relationships
    asset = relationship("Asset", back_populates="asset_changes")
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        # Join with asset to filter by project
        from sqlalchemy.orm import aliased
        # Simplified - in production would use proper join
        return session.query(cls).join(Asset).filter(Asset.project_id == project_id)


class Finding(Base, UUIDMixin, TimestampMixin):
    """Security finding from scanner analysis."""
    
    __tablename__ = "findings"
    
    __table_args__ = (
        Index("ix_findings_project_id", "project_id"),
        Index("ix_findings_asset_id", "asset_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_priority", "priority"),
        UniqueConstraint("project_id", "fingerprint", name="uq_project_fingerprint"),
    )
    
    # Core fields
    title = Column(String, nullable=False, max_length=255)
    template_id = Column(String, nullable=True, comment="Nuclei template ID or checker ID")
    category = Column(
        String,
        nullable=False,
        comment="exposure, misconfiguration, known_vulnerabilities, technology_specific, api_related, takeover_indicators",
    )
    severity = Column(
        String,
        nullable=False,
        comment="HIGH, MEDIUM, LOW",
    )
    confidence = Column(Integer, nullable=False, default=0, comment="0-100 percentage")
    priority = Column(Integer, nullable=False, default=0, comment="Deterministic priority score")
    endpoint = Column(String, nullable=True, comment="Vulnerable endpoint URL")
    evidence = Column(Text, nullable=True, description="Raw evidence supporting the finding")
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True, comment="Potential impact if exploited")
    remediation = Column(Text, nullable=True, comment="Remediation guidance")
    fingerprint = Column(
        String,
        nullable=False,
        comment="Stable fingerprint for deduplication",
    )
    first_seen = Column(DateTime, nullable=False, default=lambda: DateTime().now)  # noqa: E731
    last_seen = Column(DateTime, nullable=False, default=lambda: DateTime().now)  # noqa: E731
    status = Column(
        String,
        nullable=False,
        default="new",
        comment="new, confirmed, false_positive, accepted, resolved, reopened",
    )
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    events = relationship("FindingEvent", back_populates="finding", cascade="all, delete-orphan")
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)
    
    @property
    def is_terminal_status(self) -> bool:
        """Check if finding status is terminal (resolved, false_positive, accepted)."""
        return self.status in ("resolved", "false_positive", "accepted")
    
    @property
    def is_regression(self) -> bool:
        """Check if this finding reappeared after being resolved."""
        return self.status == "reopened"


class FindingEvent(Base, UUIDMixin, TimestampMixin):
    """History of finding state changes."""
    
    __tablename__ = "finding_events"
    
    __table_args__ = (
        Index("ix_finding_events_finding_id", "finding_id"),
        Index("ix_finding_events_created_at", "created_at"),
    )
    
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    event_type = Column(
        String,
        nullable=False,
        comment="confirmed, false_positive, accepted, resolved, reopened",
    )
    notes = Column(Text, nullable=True)
    changed_by = Column(String, nullable=True, comment="User ID or system")
    
    # Relationships
    finding = relationship("Finding", back_populates="events")
    
    @classmethod
    def query_filtered(cls, session, project_id: str, finding_id: str = None):
        query = session.query(FindingEvent).join(Finding).filter(Finding.project_id == project_id)
        if finding_id:
            query = query.filter(FindingEvent.finding_id == finding_id)
        return query


class Report(Base, UUIDMixin, TimestampMixin):
    """Generated security assessment report."""
    
    __tablename__ = "reports"
    
    __table_args__ = (
        Index("ix_reports_project_id", "project_id"),
        Index("ix_reports_status", "status"),
    )
    
    title = Column(String, nullable=False, max_length=255)
    description = Column(Text, nullable=True)
    format = Column(
        String,
        nullable=False,
        default="html",
        comment="html, json",
    )
    status = Column(
        String,
        nullable=False,
        default="draft",
        comment="draft, reviewed, published",
    )
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="reports")
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)


class MonitoringConfig(Base, UUIDMixin, TimestampMixin):
    """Continuous monitoring configuration."""
    
    __tablename__ = "monitoring_configs"
    
    __table_args__ = (
        Index("ix_monitoring_project_id", "project_id"),
    )
    
    name = Column(String, nullable=False, default="Continuous Monitoring")
    frequency = Column(
        String,
        nullable=False,
        default="daily",
        comment="every 6 hours, daily, weekly",
    )
    profile = Column(
        String,
        nullable=False,
        default="standard",
        comment="quick, standard, deep",
    )
    is_active = Column(Boolean, default=True, comment="Whether monitoring is active")
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="monitoring_configs")
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)


class Notification(Base, UUIDMixin, TimestampMixin):
    """Notification records sent to users."""
    
    __tablename__ = "notifications"
    
    __table_args__ = (
        Index("ix_notifications_project_id", "project_id"),
        Index("ix_notifications_category", "category"),
        Index("ix_notifications_created_at", "created_at"),
    )
    
    category = Column(
        String,
        nullable=False,
        comment="NEW_ASSET, IMPORTANT_CHANGE, HIGH_FINDING, CRITICAL_FINDING, SCAN_FAILED, SCAN_COMPLETED, REGRESSION",
    )
    title = Column(String, nullable=False, max_length=255)
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False, comment="Whether user has read it")
    project_id = Column(String, ForeignKey("projects.id"), nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="notifications")
    
    @classmethod
    def query_filtered(cls, session, project_id: str, category: str = None):
        query = session.query(cls).filter(cls.project_id == project_id)
        if category:
            query = query.filter(cls.category == category)
        return query


class AuditLog(Base, UUIDMixin, TimestampMixin):
    """Audit trail of significant operations."""
    
    __tablename__ = "audit_logs"
    
    __table_args__ = (
        Index("ix_audit_logs_project_id", "project_id"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_event", "event"),
    )
    
    event = Column(String, nullable=False, comment="Type of operation performed")
    details = Column(JSON, nullable=True, description="Additional event details")
    project_id = Column(String, ForeignKey("projects.id"), nullable=True)
    user_id = Column(String, nullable=True, comment="User who performed the action")
    
    @classmethod
    def query_filtered(cls, session, project_id: str):
        return session.query(cls).filter(cls.project_id == project_id)