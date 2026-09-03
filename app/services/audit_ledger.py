"""Independent append-only, hash-chained security audit ledger."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.event import listens_for
from sqlalchemy.orm import Session

from app.models import AuditLedgerEntry, AuditLog, SecuritySignal

GENESIS_HASH = "0" * 64


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _hash(previous_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(f"{previous_hash}:{_canonical(payload)}".encode()).hexdigest()


def _iso(value) -> str:
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat()


@dataclass(frozen=True)
class LedgerVerification:
    valid: bool
    entries: int
    error: str | None = None


class AuditLedgerService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def seal_pending(self) -> int:
        """Seal unledgered audit and signal rows in their tenant-local chains."""
        audits = list(
            self.session.scalars(
                select(AuditLog)
                .outerjoin(AuditLedgerEntry, AuditLedgerEntry.audit_log_id == AuditLog.id)
                .where(AuditLedgerEntry.id.is_(None))
            )
        )
        signals = list(
            self.session.scalars(
                select(SecuritySignal)
                .outerjoin(
                    AuditLedgerEntry,
                    AuditLedgerEntry.security_signal_id == SecuritySignal.id,
                )
                .where(AuditLedgerEntry.id.is_(None))
            )
        )
        pending: dict[uuid.UUID, list[tuple[str, AuditLog | SecuritySignal]]] = {}
        for audit in audits:
            pending.setdefault(audit.organization_id, []).append(("audit_log", audit))
        for signal in signals:
            pending.setdefault(signal.organization_id, []).append(("security_signal", signal))

        sealed = 0
        for organization_id, rows in pending.items():
            # The row lock below protects an existing head.  A transactional
            # advisory lock also serializes creation of a tenant's first head.
            if self.session.bind and self.session.bind.dialect.name == "postgresql":
                lock_id = int.from_bytes(organization_id.bytes[:8], "big", signed=True)
                self.session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
                )
            head = self.session.scalar(
                select(AuditLedgerEntry)
                .where(AuditLedgerEntry.organization_id == organization_id)
                .order_by(AuditLedgerEntry.sequence.desc())
                .limit(1)
                .with_for_update()
            )
            sequence = head.sequence if head else 0
            previous_hash = head.entry_hash if head else GENESIS_HASH
            rows.sort(key=lambda row: (_iso(row[1].created_at), str(row[1].id), row[0]))
            for entry_type, source in rows:
                payload = self._payload(entry_type, source)
                sequence += 1
                entry = AuditLedgerEntry(
                    organization_id=organization_id,
                    sequence=sequence,
                    entry_type=entry_type,
                    audit_log_id=source.id if isinstance(source, AuditLog) else None,
                    security_signal_id=source.id if isinstance(source, SecuritySignal) else None,
                    payload=payload,
                    previous_hash=previous_hash,
                    entry_hash=_hash(previous_hash, payload),
                )
                self.session.add(entry)
                previous_hash = entry.entry_hash
                sealed += 1
        if sealed:
            self.session.flush()
        return sealed

    def verify(self, organization_id: uuid.UUID) -> LedgerVerification:
        entries = list(
            self.session.scalars(
                select(AuditLedgerEntry)
                .where(AuditLedgerEntry.organization_id == organization_id)
                .order_by(AuditLedgerEntry.sequence)
            )
        )
        previous_hash = GENESIS_HASH
        for expected_sequence, entry in enumerate(entries, start=1):
            if entry.sequence != expected_sequence:
                return LedgerVerification(False, len(entries), "non-contiguous sequence")
            if entry.previous_hash != previous_hash:
                return LedgerVerification(False, len(entries), "previous hash mismatch")
            if entry.entry_hash != _hash(previous_hash, entry.payload):
                return LedgerVerification(False, len(entries), "entry hash mismatch")
            # AuditLog is immutable once sealed.  Check the source snapshot as
            # well, so a mutation outside the ledger cannot go unnoticed even
            # on development databases without the PostgreSQL trigger.
            if entry.audit_log_id:
                audit = self.session.get(AuditLog, entry.audit_log_id)
                if audit is None:
                    return LedgerVerification(False, len(entries), "audit log source missing")
                if self._payload("audit_log", audit) != entry.payload:
                    return LedgerVerification(False, len(entries), "audit log source mismatch")
            previous_hash = entry.entry_hash
        return LedgerVerification(True, len(entries))

    def export(self, organization_id: uuid.UUID) -> list[dict[str, Any]]:
        entries = list(
            self.session.scalars(
                select(AuditLedgerEntry)
                .where(AuditLedgerEntry.organization_id == organization_id)
                .order_by(AuditLedgerEntry.sequence)
            )
        )
        return [
            {
                "sequence": entry.sequence,
                "entry_type": entry.entry_type,
                "created_at": _iso(entry.created_at),
                "previous_hash": entry.previous_hash,
                "entry_hash": entry.entry_hash,
                "payload": entry.payload,
            }
            for entry in entries
        ]

    @staticmethod
    def _payload(entry_type: str, source: AuditLog | SecuritySignal) -> dict[str, Any]:
        if isinstance(source, AuditLog):
            return {
                "type": entry_type,
                "id": str(source.id),
                "created_at": _iso(source.created_at),
                "actor_type": source.actor_type,
                "actor_id": source.actor_id,
                "action": source.action,
                "resource_type": source.resource_type,
                "resource_id": source.resource_id,
                "details": source.details,
            }
        return {
            "type": entry_type,
            "id": str(source.id),
            "created_at": _iso(source.created_at),
            "signal_type": source.signal_type,
            "severity": source.severity,
            "actor_id": source.actor_id,
            "evidence": source.evidence,
            "occurrences": source.occurrences,
        }


@listens_for(Session, "before_commit")
def seal_audit_ledger_before_commit(session: Session) -> None:
    if session.info.get("audit_ledger_sealing"):
        return
    session.info["audit_ledger_sealing"] = True
    try:
        session.flush()
        AuditLedgerService(session).seal_pending()
    finally:
        session.info.pop("audit_ledger_sealing", None)
