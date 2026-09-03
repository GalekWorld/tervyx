import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class UUIDTimestampMixin:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class UpdatedAtMixin:
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


alert_security_events = Table(
    "alert_security_events",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "security_event_id",
        ForeignKey("security_events.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Index("ix_alert_security_events_security_event_id", "security_event_id"),
)


incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)


incident_alert_groups = Table(
    "incident_alert_groups",
    Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "alert_group_id",
        ForeignKey("alert_groups.id", ondelete="CASCADE"),
        primary_key=True,
        unique=True,
    ),
    Index("ix_incident_alert_groups_alert_group_id", "alert_group_id"),
)


alert_group_alerts = Table(
    "alert_group_alerts",
    Base.metadata,
    Column("alert_group_id", ForeignKey("alert_groups.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, unique=True),
    Index("ix_alert_group_alerts_alert_id", "alert_id"),
)


class Organization(UUIDTimestampMixin, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="organization")


class User(UUIDTimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "email"),
        UniqueConstraint("organization_id", "id", name="uq_users_organization_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst", nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(500))
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="users")


class IdentityProvider(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "identity_providers"
    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        Index("ix_identity_providers_org_enabled", "organization_id", "enabled"),
        CheckConstraint(
            "provider_type IN ('entra', 'okta', 'google', 'keycloak', 'generic')",
            name="ck_identity_provider_type",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider_type: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allowed_redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enforce_mfa: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    provider_tenant_id: Mapped[str | None] = mapped_column(String(255))


class FederatedIdentity(UUIDTimestampMixin, Base):
    __tablename__ = "federated_identities"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider_id", "subject"),
        UniqueConstraint("organization_id", "provider_id", "user_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    provider_tenant_id: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320))


class AuthSession(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (Index("ix_auth_sessions_org_user", "organization_id", "user_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="SET NULL"), index=True
    )
    auth_method: Mapped[str] = mapped_column(String(50), nullable=False)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mfa_methods: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(500))


class PlatformAdminEligibility(UpdatedAtMixin, UUIDTimestampMixin, Base):
    """Eligibility is not an active privilege; JIT activation is still required."""

    __tablename__ = "platform_admin_eligibilities"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class PrivilegedAccessPolicy(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "privileged_access_policies"
    __table_args__ = (UniqueConstraint("organization_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    break_glass_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    max_duration_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    step_up_max_age_minutes: Mapped[int] = mapped_column(Integer, default=15, nullable=False)
    allowed_mfa_methods: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: ["fido2", "passkey", "hardware", "ngcmfa", "webauthn"], nullable=False
    )


class PrivilegedAccessRequest(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "privileged_access_requests"
    __table_args__ = (
        Index("ix_privileged_access_requests_org_status", "organization_id", "status"),
        CheckConstraint(
            "status IN ('requested', 'approved', 'active', 'denied', 'revoked', 'expired')",
            name="ck_privileged_access_request_status",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    requester_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    approver_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    requested_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    requested_duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="requested", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PrivilegedSession(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "privileged_sessions"
    __table_args__ = (
        UniqueConstraint("request_id"),
        Index("ix_privileged_sessions_org_user", "organization_id", "user_id"),
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired')", name="ck_privileged_session_status"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    base_session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("auth_sessions.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("privileged_access_requests.id", ondelete="RESTRICT"), nullable=False
    )
    capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    step_up_verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(500))


class OIDCLoginTransaction(UUIDTimestampMixin, Base):
    __tablename__ = "oidc_login_transactions"
    __table_args__ = (UniqueConstraint("state_hash"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="CASCADE"), index=True, nullable=False
    )
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(255), nullable=False)
    code_verifier_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserCapability(UUIDTimestampMixin, Base):
    __tablename__ = "user_capabilities"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", "capability"),
        CheckConstraint("effect IN ('allow', 'deny')", name="ck_user_capability_effect"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    capability: Mapped[str] = mapped_column(String(100), nullable=False)
    effect: Mapped[str] = mapped_column(String(10), nullable=False)


class RefreshToken(UUIDTimestampMixin, Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash"),
        Index("ix_refresh_tokens_org_user", "organization_id", "user_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("auth_sessions.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL")
    )


class Endpoint(UUIDTimestampMixin, Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("organization_id", "agent_id"),
        UniqueConstraint("organization_id", "id", name="uq_endpoints_organization_id"),
        Index("ix_endpoints_org_status", "organization_id", "status"),
        CheckConstraint("criticality BETWEEN 1 AND 5", name="ck_endpoint_criticality"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    operating_system: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    criticality: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Endpoint identity/enrolment state is tenant-scoped and never supplied by
    # agent payloads. Secrets are stored only as hashes; the clear token is
    # returned once during administrative enrolment.
    identity_key: Mapped[str] = mapped_column(
        String(128), unique=True, default=lambda: uuid.uuid4().hex, nullable=False
    )
    enrollment_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    certificate_serial: Mapped[str | None] = mapped_column(String(255))
    certificate_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_interval_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_health: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    agent_version: Mapped[str | None] = mapped_column(String(100))

    organization: Mapped[Organization] = relationship(back_populates="endpoints")
    security_events: Mapped[list["SecurityEvent"]] = relationship(
        back_populates="endpoint", foreign_keys="SecurityEvent.endpoint_id"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="endpoint", foreign_keys="Alert.endpoint_id"
    )


class SecurityEvent(UUIDTimestampMixin, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "source", "external_id"),
        Index("ix_events_org_occurred", "organization_id", "occurred_at"),
        Index(
            "ix_events_org_endpoint_occurred",
            "organization_id",
            "endpoint_id",
            text("occurred_at DESC"),
        ),
        ForeignKeyConstraint(
            ["organization_id", "endpoint_id"],
            ["endpoints.organization_id", "endpoints.id"],
            name="fk_events_tenant_endpoint",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    normalized_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    endpoint: Mapped[Endpoint] = relationship(
        back_populates="security_events", foreign_keys=[endpoint_id]
    )
    alerts: Mapped[list["Alert"]] = relationship(
        secondary=alert_security_events, back_populates="security_events"
    )


class Alert(UUIDTimestampMixin, Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("organization_id", "source", "external_id"),
        UniqueConstraint("organization_id", "id", name="uq_alerts_organization_id"),
        Index("ix_alerts_org_status", "organization_id", "status"),
        Index(
            "ix_alerts_org_endpoint_occurred",
            "organization_id",
            "endpoint_id",
            text("occurred_at DESC"),
        ),
        CheckConstraint("severity >= 0 AND severity <= 10", name="ck_alert_severity"),
        Index(
            "ix_alerts_org_correlation_occurred",
            "organization_id",
            "correlation_key",
            "occurred_at",
        ),
        ForeignKeyConstraint(
            ["organization_id", "endpoint_id"],
            ["endpoints.organization_id", "endpoints.id"],
            name="fk_alerts_tenant_endpoint",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(100), index=True)
    mitre_attack: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    rule_version: Mapped[int | None] = mapped_column(Integer)
    correlation_key: Mapped[str | None] = mapped_column(String(512))

    endpoint: Mapped[Endpoint] = relationship(back_populates="alerts", foreign_keys=[endpoint_id])
    security_events: Mapped[list[SecurityEvent]] = relationship(
        secondary=alert_security_events, back_populates="alerts"
    )
    incidents: Mapped[list["Incident"]] = relationship(
        secondary=incident_alerts, back_populates="alerts"
    )
    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="alert", foreign_keys="Investigation.alert_id"
    )
    alert_groups: Mapped[list["AlertGroup"]] = relationship(
        secondary=alert_group_alerts, back_populates="alerts"
    )


class AlertGroup(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "alert_groups"
    __table_args__ = (
        Index("ix_alert_groups_org_last_seen", "organization_id", text("last_seen DESC")),
        Index("ix_alert_groups_org_correlation", "organization_id", "correlation_key"),
        UniqueConstraint("organization_id", "id", name="uq_alert_groups_organization_id"),
        CheckConstraint("severity >= 0 AND severity <= 10", name="ck_alert_group_severity"),
        CheckConstraint(
            "status IN ('open', 'investigating', 'resolved', 'false_positive')",
            name="ck_alert_group_status",
        ),
        ForeignKeyConstraint(
            ["organization_id", "assigned_to"],
            ["users.organization_id", "users.id"],
            name="fk_alert_groups_tenant_assignee",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    correlation_key: Mapped[str] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    affected_endpoint_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    affected_users: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source_ips: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    destination_ips: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_attack: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    resolution_reason: Mapped[str | None] = mapped_column(Text)
    analyst_feedback: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    alerts: Mapped[list[Alert]] = relationship(
        secondary=alert_group_alerts, back_populates="alert_groups"
    )
    history: Mapped[list["AlertGroupHistory"]] = relationship(
        back_populates="alert_group",
        cascade="all, delete-orphan",
        foreign_keys="AlertGroupHistory.alert_group_id",
    )

    @property
    def alert_ids(self) -> list[uuid.UUID]:
        return [alert.id for alert in self.alerts]


class AlertGroupHistory(UUIDTimestampMixin, Base):
    __tablename__ = "alert_group_history"
    __table_args__ = (
        Index("ix_alert_group_history_org_group", "organization_id", "alert_group_id"),
        ForeignKeyConstraint(
            ["organization_id", "alert_group_id"],
            ["alert_groups.organization_id", "alert_groups.id"],
            name="fk_alert_group_history_tenant_group",
        ),
        ForeignKeyConstraint(
            ["organization_id", "actor_id"],
            ["users.organization_id", "users.id"],
            name="fk_alert_group_history_tenant_actor",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    alert_group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alert_groups.id", ondelete="CASCADE"), index=True, nullable=False
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(50))
    new_status: Mapped[str | None] = mapped_column(String(50))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    alert_group: Mapped[AlertGroup] = relationship(
        back_populates="history", foreign_keys=[alert_group_id]
    )


class DetectionRuleConfiguration(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "detection_rule_configurations"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id", "version"),
        Index("ix_detection_rule_configs_org_rule_active", "organization_id", "rule_id", "active"),
        CheckConstraint("version >= 1", name="ck_detection_rule_config_version"),
        CheckConstraint(
            "suppression_window_seconds >= 0", name="ck_detection_rule_config_suppression"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    suppression_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class DetectionRuleMetric(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "detection_rule_metrics"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id"),
        Index("ix_detection_rule_metrics_org_rule", "organization_id", "rule_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    executions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    matches: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_suppressed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_match: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DetectionSuppression(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "detection_suppressions"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id", "correlation_key"),
        Index("ix_detection_suppressions_org_rule", "organization_id", "rule_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    correlation_key: Mapped[str] = mapped_column(String(512), nullable=False)
    last_alert_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Incident(UUIDTimestampMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_org_status", "organization_id", "status"),
        CheckConstraint(
            "status IN ('open', 'investigating', 'contained', 'resolved', "
            "'false_positive', 'reopened')",
            name="ck_incident_status",
        ),
        UniqueConstraint("organization_id", "id", name="uq_incidents_organization_id"),
        CheckConstraint("sla_due_at >= first_seen", name="ck_incident_sla_due_after_first_seen"),
        ForeignKeyConstraint(
            ["organization_id", "assigned_to"],
            ["users.organization_id", "users.id"],
            name="fk_incidents_tenant_assignee",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.8, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    correlation_key: Mapped[str | None] = mapped_column(String(512), index=True)
    affected_endpoint_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    affected_users: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source_ips: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    destination_ips: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_attack: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    resolution: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_due_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    alerts: Mapped[list[Alert]] = relationship(
        secondary=incident_alerts, back_populates="incidents"
    )
    alert_groups: Mapped[list[AlertGroup]] = relationship(secondary=incident_alert_groups)
    history: Mapped[list["IncidentHistory"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        foreign_keys="IncidentHistory.incident_id",
    )
    enrichments: Mapped[list["IncidentEnrichment"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        foreign_keys="IncidentEnrichment.incident_id",
    )
    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="incident", foreign_keys="Investigation.incident_id"
    )

    @property
    def alert_ids(self) -> list[uuid.UUID]:
        return [alert.id for alert in self.alerts]

    @property
    def alert_group_ids(self) -> list[uuid.UUID]:
        return [group.id for group in self.alert_groups]


class IncidentHistory(UUIDTimestampMixin, Base):
    __tablename__ = "incident_history"
    __table_args__ = (
        Index("ix_incident_history_org_incident", "organization_id", "incident_id"),
        ForeignKeyConstraint(
            ["organization_id", "incident_id"],
            ["incidents.organization_id", "incidents.id"],
            name="fk_incident_history_tenant_incident",
        ),
        ForeignKeyConstraint(
            ["organization_id", "actor_id"],
            ["users.organization_id", "users.id"],
            name="fk_incident_history_tenant_actor",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(50))
    new_status: Mapped[str | None] = mapped_column(String(50))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="history", foreign_keys=[incident_id])


class IncidentEnrichment(UUIDTimestampMixin, Base):
    __tablename__ = "incident_enrichments"
    __table_args__ = (
        UniqueConstraint("organization_id", "incident_id", "fingerprint"),
        Index("ix_incident_enrichments_org_incident", "organization_id", "incident_id"),
        CheckConstraint(
            "source_type IN ('internal', 'external')", name="ck_incident_enrichment_source"
        ),
        ForeignKeyConstraint(
            ["organization_id", "incident_id"],
            ["incidents.organization_id", "incidents.id"],
            name="fk_incident_enrichments_tenant_incident",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    enrichment_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped[Incident] = relationship(
        back_populates="enrichments", foreign_keys=[incident_id]
    )


class Investigation(UUIDTimestampMixin, Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint(
            "(alert_id IS NOT NULL AND incident_id IS NULL) OR "
            "(alert_id IS NULL AND incident_id IS NOT NULL)",
            name="ck_investigation_single_subject",
        ),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_risk_score"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_confidence"),
        CheckConstraint(
            "status IN ('pending', 'in_progress', 'completed', 'closed')",
            name="ck_investigation_status",
        ),
        UniqueConstraint("organization_id", "incident_id"),
        ForeignKeyConstraint(
            ["organization_id", "alert_id"],
            ["alerts.organization_id", "alerts.id"],
            name="fk_investigations_tenant_alert",
        ),
        ForeignKeyConstraint(
            ["organization_id", "incident_id"],
            ["incidents.organization_id", "incidents.id"],
            name="fk_investigations_tenant_incident",
        ),
        Index("ix_investigations_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    classification: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), default="completed", nullable=False)

    alert: Mapped[Alert | None] = relationship(
        back_populates="investigations", foreign_keys=[alert_id]
    )
    incident: Mapped[Incident | None] = relationship(
        back_populates="investigations", foreign_keys=[incident_id]
    )


class AuditLog(UUIDTimestampMixin, Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_org_created", "organization_id", "created_at"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    actor_type: Mapped[str] = mapped_column(String(50), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class SecuritySignal(UUIDTimestampMixin, Base):
    __tablename__ = "security_signals"
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint"),
        Index("ix_security_signals_org_last_seen", "organization_id", "last_seen_at"),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_security_signal_severity",
        ),
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'closed')",
            name="ck_security_signal_status",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    signal_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    source_action: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)


class AuditLedgerEntry(UUIDTimestampMixin, Base):
    """Append-only, tenant-scoped cryptographic audit ledger."""

    __tablename__ = "audit_ledger_entries"
    __table_args__ = (
        UniqueConstraint("organization_id", "sequence"),
        UniqueConstraint("audit_log_id"),
        UniqueConstraint("security_signal_id"),
        Index("ix_audit_ledger_org_sequence", "organization_id", "sequence"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    entry_type: Mapped[str] = mapped_column(String(50), nullable=False)
    audit_log_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("audit_logs.id", ondelete="RESTRICT"), nullable=True
    )
    security_signal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_signals.id", ondelete="RESTRICT"), nullable=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class IntegrationAccount(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "integration_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        UniqueConstraint("organization_id", "id", name="uq_integrations_organization_id"),
        Index("ix_integrations_org_type", "organization_id", "integration_type"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    integration_type: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    credential_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="configured", nullable=False)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


class IntegrationCheckpoint(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "integration_checkpoints"
    __table_args__ = (
        UniqueConstraint("organization_id", "integration_account_id", "stream"),
        ForeignKeyConstraint(
            ["organization_id", "integration_account_id"],
            ["integration_accounts.organization_id", "integration_accounts.id"],
            name="fk_checkpoints_tenant_integration",
            ondelete="CASCADE",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    integration_account_id: Mapped[uuid.UUID] = mapped_column(index=True, nullable=False)
    stream: Mapped[str] = mapped_column(String(100), nullable=False)
    last_position: Mapped[str | None] = mapped_column(String(500))
    last_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cursor: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeadLetterEvent(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "dead_letter_events"
    __table_args__ = (
        Index("ix_dlq_org_status", "organization_id", "status"),
        ForeignKeyConstraint(
            ["organization_id", "integration_account_id"],
            ["integration_accounts.organization_id", "integration_accounts.id"],
            name="fk_dlq_tenant_integration",
            ondelete="CASCADE",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    integration_account_id: Mapped[uuid.UUID] = mapped_column(index=True, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    error: Mapped[str] = mapped_column(Text, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_failed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_failed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)


class TenantQuota(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "tenant_quotas"
    __table_args__ = (
        UniqueConstraint("organization_id"),
        CheckConstraint("max_events_per_day >= 0", name="ck_tenant_quota_events"),
        CheckConstraint("max_jobs_per_minute >= 0", name="ck_tenant_quota_jobs"),
        CheckConstraint("max_api_requests_per_minute >= 0", name="ck_tenant_quota_api"),
        CheckConstraint("max_storage_bytes >= 0", name="ck_tenant_quota_storage"),
        CheckConstraint("max_queue_depth >= 1", name="ck_tenant_quota_queue"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    max_events_per_day: Mapped[int] = mapped_column(Integer, nullable=False)
    max_jobs_per_minute: Mapped[int] = mapped_column(Integer, nullable=False)
    max_api_requests_per_minute: Mapped[int] = mapped_column(Integer, nullable=False)
    max_storage_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    max_queue_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class TenantUsageLedger(UUIDTimestampMixin, Base):
    __tablename__ = "tenant_usage_ledgers"
    __table_args__ = (
        UniqueConstraint("organization_id", "period_start"),
        Index("ix_tenant_usage_org_period", "organization_id", "period_start"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    events_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    jobs_dispatched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hot_storage_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    archived_storage_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)


class DataRetentionPolicy(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "data_retention_policies"
    __table_args__ = (
        UniqueConstraint("organization_id"),
        CheckConstraint("archive_after_days >= 1", name="ck_retention_archive_after_days"),
        CheckConstraint("retention_days >= archive_after_days", name="ck_retention_days"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    archive_after_days: Mapped[int] = mapped_column(Integer, nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class SecurityEventArchive(UpdatedAtMixin, UUIDTimestampMixin, Base):
    __tablename__ = "security_event_archives"
    __table_args__ = (
        Index(
            "ix_event_archives_org_range",
            "organization_id",
            "first_occurred_at",
            "last_occurred_at",
        ),
        UniqueConstraint("organization_id", "storage_key"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    storage_key: Mapped[str] = mapped_column(String(2048), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    first_occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="archived", nullable=False)
