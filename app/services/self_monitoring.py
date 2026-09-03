"""Deterministic detection of internal security abuse from audit evidence."""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, SecuritySignal


class SelfMonitoringService:
    WINDOW = timedelta(minutes=10)

    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def evaluate(self, *, now: datetime | None = None) -> list[SecuritySignal]:
        current = now or datetime.now(UTC)
        start = current - self.WINDOW
        logs = list(
            self.session.scalars(
                select(AuditLog).where(
                    AuditLog.organization_id == self.organization_id,
                    AuditLog.created_at >= start,
                    AuditLog.created_at <= current,
                    AuditLog.action.notin_(
                        ("security.signal_generated", "security.signal_updated")
                    ),
                )
            )
        )
        candidates: list[tuple[str, str, str, str | None, dict]] = []
        by_actor: Counter[str] = Counter()
        by_ip: Counter[str] = Counter()
        for log in logs:
            actor = log.actor_id or "unknown"
            by_actor[actor] += 1
            ip = log.details.get("client_ip") if isinstance(log.details, dict) else None
            if isinstance(ip, str) and ip:
                by_ip[ip] += 1

        def add(signal_type: str, severity: str, action: str, actor: str | None, evidence: dict):
            candidates.append((signal_type, severity, action, actor, evidence))

        cross_tenant = [
            log
            for log in logs
            if log.action in {"security.cross_tenant_attempt", "security.tenant_scope_denied"}
            or bool(log.details.get("cross_tenant"))
        ]
        if cross_tenant:
            add(
                "cross_tenant_attempt",
                "critical",
                "security.tenant_scope_denied",
                cross_tenant[-1].actor_id,
                {
                    "count": len(cross_tenant),
                    "resource_ids": [log.resource_id for log in cross_tenant[-10:]],
                },
            )

        enum_logs = [
            log
            for log in logs
            if log.action
            in {
                "security.enumeration_candidate",
                "http.request",
                "security.http_denied",
            }
            and isinstance(log.details, dict)
            and (
                log.action == "security.enumeration_candidate"
                or log.details.get("status_code") in {404, 403}
            )
        ]
        enum_by_actor: Counter[str] = Counter(log.actor_id or "unknown" for log in enum_logs)
        for actor, count in enum_by_actor.items():
            if count >= 10:
                add("mass_enumeration", "high", "http.request", actor, {"count": count})

        ip_enumeration = [ip for ip, count in by_ip.items() if count >= 25]
        if ip_enumeration:
            add("ip_abuse", "high", "http.request", None, {"ips": ip_enumeration})

        capability_logs = [log for log in logs if log.action == "identity.capability_changed"]
        for actor, count in Counter(log.actor_id or "unknown" for log in capability_logs).items():
            if count >= 3:
                add(
                    "capability_churn",
                    "high",
                    "identity.capability_changed",
                    actor,
                    {"count": count},
                )

        secret_logs = [
            log
            for log in logs
            if log.action
            in {"integration.secret_rotated", "auth.emergency_revocation", "auth.refresh_revoked"}
        ]
        if len(secret_logs) >= 3:
            add(
                "secret_activity_spike",
                "high",
                secret_logs[-1].action,
                secret_logs[-1].actor_id,
                {"count": len(secret_logs)},
            )

        disabled = [
            log
            for log in logs
            if (log.action == "detection_rule.configured" and log.details.get("enabled") is False)
            or log.action in {"identity.provider_disabled", "security.control_disabled"}
        ]
        if disabled:
            add(
                "security_control_disabled",
                "critical",
                disabled[-1].action,
                disabled[-1].actor_id,
                {"count": len(disabled)},
            )

        dlq_logs = [
            log
            for log in logs
            if log.action in {"dead_letter.reprocess_requested", "dead_letter.discarded"}
        ]
        if len(dlq_logs) >= 10:
            add(
                "dlq_mass_action",
                "high",
                dlq_logs[-1].action,
                dlq_logs[-1].actor_id,
                {"count": len(dlq_logs)},
            )

        for actor_key, count in by_actor.items():
            if actor_key != "unknown" and count >= 30:
                add("admin_action_anomaly", "high", "audit.activity", actor_key, {"count": count})

        signals: list[SecuritySignal] = []
        for signal_type, severity, action, candidate_actor, evidence in candidates:
            fingerprint = hashlib.sha256(
                f"{self.organization_id}:{signal_type}:{candidate_actor or 'none'}".encode()
            ).hexdigest()
            existing = self.session.scalar(
                select(SecuritySignal)
                .where(
                    SecuritySignal.organization_id == self.organization_id,
                    SecuritySignal.fingerprint == fingerprint,
                )
                .with_for_update()
            )
            if existing is None:
                existing = SecuritySignal(
                    organization_id=self.organization_id,
                    signal_type=signal_type,
                    severity=severity,
                    fingerprint=fingerprint,
                    evidence=evidence,
                    source_action=action,
                    actor_id=candidate_actor,
                    first_seen_at=current,
                    last_seen_at=current,
                    occurrences=1,
                    status="open",
                )
                self.session.add(existing)
                self.session.flush()
                self.session.add(
                    AuditLog(
                        organization_id=self.organization_id,
                        actor_type="system",
                        actor_id="self-monitoring",
                        action="security.signal_generated",
                        resource_type="security_signal",
                        resource_id=str(existing.id),
                        details={
                            "signal_type": signal_type,
                            "severity": severity,
                            "fingerprint": fingerprint,
                        },
                    )
                )
            else:
                existing.last_seen_at = current
                existing.occurrences += 1
                existing.evidence = evidence
                existing.severity = severity
                # Signals are intentionally mutable for deduplication.  Record
                # each state change as an immutable audit event, which is then
                # sealed by the audit ledger without feeding this detector.
                self.session.add(
                    AuditLog(
                        organization_id=self.organization_id,
                        actor_type="system",
                        actor_id="self-monitoring",
                        action="security.signal_updated",
                        resource_type="security_signal",
                        resource_id=str(existing.id),
                        details={
                            "signal_type": signal_type,
                            "severity": severity,
                            "fingerprint": fingerprint,
                            "occurrences": existing.occurrences,
                        },
                    )
                )
            signals.append(existing)
        self.session.flush()
        return signals
