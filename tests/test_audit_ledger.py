from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLedgerEntry, AuditLog, SecuritySignal
from app.services.audit_ledger import AuditLedgerService
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID


def _audit(session: Session, organization_id, action: str) -> AuditLog:
    item = AuditLog(
        organization_id=organization_id,
        actor_type="user",
        actor_id="actor-1",
        action=action,
        resource_type="test",
        resource_id="resource-1",
        details={"safe": True},
    )
    session.add(item)
    return item


def test_audit_ledger_is_hash_chained_ordered_and_includes_signals(session: Session) -> None:
    _audit(session, TEST_ORG_ID, "first")
    _audit(session, TEST_ORG_ID, "second")
    signal = SecuritySignal(
        organization_id=TEST_ORG_ID,
        signal_type="test",
        severity="medium",
        fingerprint="signal-test",
        evidence={"source": "test"},
        source_action="test",
        actor_id="actor-1",
        first_seen_at=datetime.now(UTC),
        last_seen_at=datetime.now(UTC),
    )
    session.add(signal)
    session.commit()

    entries = list(
        session.scalars(
            select(AuditLedgerEntry)
            .where(AuditLedgerEntry.organization_id == TEST_ORG_ID)
            .order_by(AuditLedgerEntry.sequence)
        )
    )
    assert [entry.sequence for entry in entries] == [1, 2, 3]
    assert entries[0].previous_hash == "0" * 64
    assert any(entry.security_signal_id == signal.id for entry in entries)
    assert AuditLedgerService(session).verify(TEST_ORG_ID).valid


def test_audit_ledger_detects_tampering_and_is_tenant_scoped(session: Session) -> None:
    _audit(session, TEST_ORG_ID, "local")
    _audit(session, OTHER_ORG_ID, "foreign")
    session.commit()
    service = AuditLedgerService(session)
    assert service.verify(TEST_ORG_ID).entries == 1
    assert service.verify(OTHER_ORG_ID).entries == 1
    exported = service.export(TEST_ORG_ID)
    assert len(exported) == 1
    assert exported[0]["payload"]["action"] == "local"

    entry = session.scalar(
        select(AuditLedgerEntry).where(AuditLedgerEntry.organization_id == TEST_ORG_ID)
    )
    assert entry is not None
    entry.payload = {"tampered": True}
    session.commit()
    result = service.verify(TEST_ORG_ID)
    assert not result.valid
    assert result.error == "entry hash mismatch"


def test_audit_ledger_detects_tampered_audit_log_source(session: Session) -> None:
    audit = _audit(session, TEST_ORG_ID, "immutable")
    session.commit()

    audit.details = {"tampered": True}
    session.commit()

    result = AuditLedgerService(session).verify(TEST_ORG_ID)
    assert not result.valid
    assert result.error == "audit log source mismatch"


def test_audit_ledger_does_not_ledger_itself_or_duplicate_entries(session: Session) -> None:
    _audit(session, TEST_ORG_ID, "one")
    session.commit()
    service = AuditLedgerService(session)
    assert service.seal_pending() == 0
    session.commit()
    assert service.verify(TEST_ORG_ID).entries == 1


def test_audit_ledger_export_and_verify_are_tenant_scoped(
    client: TestClient, session: Session
) -> None:
    _audit(session, TEST_ORG_ID, "api.local")
    _audit(session, OTHER_ORG_ID, "api.foreign")
    session.commit()
    verification = client.get("/api/v1/audit/ledger/verify")
    assert verification.status_code == 200
    assert verification.json() == {"valid": True, "entries": 1, "error": None}
    exported = client.get("/api/v1/audit/ledger/export")
    assert exported.status_code == 200
    assert [item["payload"]["action"] for item in exported.json()] == ["api.local"]
