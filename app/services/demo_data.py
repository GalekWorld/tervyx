import os
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import hash_password
from app.core.database import set_tenant_context
from app.models import (
    Alert,
    AuditLog,
    Endpoint,
    Incident,
    Investigation,
    Organization,
    SecurityEvent,
    User,
)

DEMO_ORGANIZATION_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")


def seed_demo_data(session: Session) -> Organization:
    set_tenant_context(session, DEMO_ORGANIZATION_ID)
    existing = session.scalar(select(Organization).where(Organization.id == DEMO_ORGANIZATION_ID))
    if existing is not None:
        demo_password = os.getenv("DEMO_ADMIN_PASSWORD")
        if demo_password:
            user = session.scalar(
                select(User).where(
                    User.organization_id == DEMO_ORGANIZATION_ID,
                    User.email == "analyst@acme.demo",
                )
            )
            if user is not None:
                user.password_hash = hash_password(demo_password)
                session.commit()
        return existing

    now = datetime.now(UTC)
    organization = Organization(
        id=DEMO_ORGANIZATION_ID, name="Acme Security Demo", slug="acme-demo"
    )
    session.add(organization)
    session.flush()

    demo_password = os.getenv("DEMO_ADMIN_PASSWORD")
    session.add(
        User(
            organization_id=organization.id,
            email="analyst@acme.demo",
            display_name="Demo Analyst",
            role="admin",
            password_hash=hash_password(demo_password) if demo_password else None,
        )
    )

    endpoint_specs = [
        ("workstation-01", "Windows 11", "10.0.0.11"),
        ("workstation-02", "Windows 11", "10.0.0.12"),
        ("finance-laptop", "Windows 11", "10.0.0.21"),
        ("web-server", "Ubuntu 24.04", "10.0.1.10"),
        ("database-server", "Ubuntu 24.04", "10.0.1.20"),
    ]
    endpoints = []
    for index, (hostname, operating_system, ip_address) in enumerate(endpoint_specs, 1):
        endpoint = Endpoint(
            organization_id=organization.id,
            hostname=hostname,
            operating_system=operating_system,
            ip_address=ip_address,
            agent_id=f"demo-{index:03}",
            status="active",
            last_seen=now - timedelta(minutes=index),
        )
        endpoints.append(endpoint)
        session.add(endpoint)
    session.flush()

    event_specs = [
        (endpoints[0], "evt-001", "authentication_failed", 6, "Repeated login failures"),
        (endpoints[0], "evt-002", "authentication_success", 4, "Login after failures"),
        (endpoints[3], "evt-003", "file_integrity", 8, "Web root file changed"),
        (endpoints[4], "evt-004", "privilege_escalation", 9, "Unexpected sudo use"),
        (endpoints[2], "evt-005", "malware_detection", 9, "Suspicious executable"),
        (endpoints[1], "evt-006", "process_start", 3, "Unsigned process started"),
    ]
    events = []
    for index, (endpoint, external_id, event_type, severity, message) in enumerate(event_specs):
        event = SecurityEvent(
            organization_id=organization.id,
            endpoint_id=endpoint.id,
            source="wazuh",
            external_id=external_id,
            event_type=event_type,
            severity=severity,
            occurred_at=now - timedelta(minutes=30 - index),
            raw_payload={"demo": True, "message": message},
        )
        events.append(event)
        session.add(event)
    session.flush()

    alert_specs = [
        (endpoints[0], "alert-001", "Potential credential attack", 7, events[:2]),
        (endpoints[3], "alert-002", "Unauthorized web content change", 8, [events[2]]),
        (endpoints[2], "alert-003", "Malware detected on finance laptop", 9, [events[4]]),
    ]
    alerts = []
    for index, (endpoint, external_id, title, severity, related_events) in enumerate(alert_specs):
        alert = Alert(
            organization_id=organization.id,
            endpoint_id=endpoint.id,
            source="wazuh",
            external_id=external_id,
            title=title,
            description=f"Demo alert: {title}",
            severity=severity,
            status="open",
            occurred_at=now - timedelta(minutes=20 - index),
            security_events=related_events,
        )
        alerts.append(alert)
        session.add(alert)
    session.flush()

    incident = Incident(
        organization_id=organization.id,
        title="Coordinated compromise under review",
        description="Demo incident grouping two high-signal alerts.",
        severity=9,
        status="investigating",
        occurred_at=now - timedelta(minutes=15),
        alerts=[alerts[1], alerts[2]],
    )
    session.add(incident)
    session.flush()

    for alert, risk_score, classification, confidence in [
        (alerts[0], 68, "suspicious_authentication", 0.78),
        (alerts[1], 82, "web_server_tampering", 0.87),
        (alerts[2], 91, "probable_malware", 0.93),
    ]:
        session.add(
            Investigation(
                organization_id=organization.id,
                alert_id=alert.id,
                risk_score=risk_score,
                classification=classification,
                confidence=confidence,
                evidence=[{"type": "demo_event", "alert_id": str(alert.id)}],
                explanation="Deterministic demo result; no LLM was invoked.",
                recommended_actions=[
                    {
                        "action": "review_endpoint_timeline",
                        "requires_approval": True,
                    }
                ],
                status="completed",
            )
        )

    session.add(
        AuditLog(
            organization_id=organization.id,
            actor_type="system",
            actor_id="seed_demo",
            action="demo_data.created",
            resource_type="organization",
            resource_id=str(organization.id),
            details={"endpoints": 5, "alerts": 3, "incidents": 1},
        )
    )
    session.commit()
    return organization
