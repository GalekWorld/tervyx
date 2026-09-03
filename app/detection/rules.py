"""Deterministic, provider-neutral detection rules for normalized security events."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SecurityEvent


@dataclass(frozen=True, slots=True)
class RuleMatch:
    rule_id: str
    title: str
    description: str
    severity: int
    mitre_attack: tuple[tuple[str, str], ...]
    evidence: dict[str, object]
    related_event_ids: tuple[uuid.UUID, ...]


class DetectionRule(Protocol):
    rule_id: str

    def evaluate(self, session: Session, event: SecurityEvent) -> RuleMatch | None: ...


def _text(event: SecurityEvent) -> str:
    data = event.normalized_data
    return " ".join(
        str(value or "")
        for value in (
            data.get("category"),
            data.get("action"),
            data.get("message"),
            data.get("process_name"),
            data.get("command_line"),
        )
    ).lower()


def _subject(event: SecurityEvent) -> str:
    return str(
        event.normalized_data.get("actor")
        or event.normalized_data.get("target")
        or event.endpoint_id
    )


class MultipleFailedLoginsRule:
    rule_id = "multiple_failed_logins"
    threshold = 5
    window = timedelta(minutes=10)

    def evaluate(self, session: Session, event: SecurityEvent) -> RuleMatch | None:
        if event.normalized_data.get("outcome") != "failure" or "login" not in _text(event):
            return None
        since = event.occurred_at - self.window
        candidates = list(
            session.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.organization_id == event.organization_id,
                    SecurityEvent.endpoint_id == event.endpoint_id,
                    SecurityEvent.occurred_at >= since,
                    SecurityEvent.occurred_at <= event.occurred_at,
                )
                .order_by(SecurityEvent.occurred_at)
            )
        )
        failures = [
            item
            for item in candidates
            if item.normalized_data.get("outcome") == "failure"
            and "login" in _text(item)
            and _subject(item) == _subject(event)
        ]
        if len(failures) != self.threshold:
            return None
        ids = tuple(item.id for item in failures)
        return RuleMatch(
            self.rule_id,
            "Multiple failed logins",
            f"{len(failures)} failed logins for {_subject(event)} within 10 minutes.",
            7,
            (("T1110", "Brute Force"),),
            {"subject": _subject(event), "failed_login_count": len(failures), "window_minutes": 10},
            ids,
        )


class SuccessfulLoginAfterFailuresRule:
    rule_id = "successful_login_after_failures"
    threshold = 3
    window = timedelta(minutes=10)

    def evaluate(self, session: Session, event: SecurityEvent) -> RuleMatch | None:
        if event.normalized_data.get("outcome") != "success" or "login" not in _text(event):
            return None
        since = event.occurred_at - self.window
        failures = list(
            session.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.organization_id == event.organization_id,
                    SecurityEvent.endpoint_id == event.endpoint_id,
                    SecurityEvent.occurred_at >= since,
                    SecurityEvent.occurred_at < event.occurred_at,
                )
                .order_by(SecurityEvent.occurred_at)
            )
        )
        failures = [
            item
            for item in failures
            if item.normalized_data.get("outcome") == "failure"
            and "login" in _text(item)
            and _subject(item) == _subject(event)
        ]
        if len(failures) < self.threshold:
            return None
        ids = tuple(item.id for item in failures[-self.threshold :]) + (event.id,)
        return RuleMatch(
            self.rule_id,
            "Successful login after failed attempts",
            f"Successful login for {_subject(event)} followed {len(failures)} failed attempts.",
            8,
            (("T1078", "Valid Accounts"),),
            {
                "subject": _subject(event),
                "prior_failed_login_count": len(failures),
                "window_minutes": 10,
            },
            ids,
        )


class KeywordRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: int,
        mitre: tuple[str, str],
        keywords: tuple[str, ...],
    ) -> None:
        self.rule_id, self.title, self.severity = rule_id, title, severity
        self.mitre_attack = (mitre,)
        self.keywords = keywords

    def evaluate(self, _session: Session, event: SecurityEvent) -> RuleMatch | None:
        value = _text(event)
        matched = [keyword for keyword in self.keywords if keyword in value]
        if not matched:
            return None
        return RuleMatch(
            self.rule_id,
            self.title,
            f"{self.title}: matched {', '.join(matched)}.",
            self.severity,
            self.mitre_attack,
            {"matched_indicators": matched, "normalized_event": event.normalized_data},
            (event.id,),
        )


class SuspiciousPowerShellRule(KeywordRule):
    def __init__(self) -> None:
        super().__init__(
            "suspicious_powershell",
            "Suspicious PowerShell execution",
            8,
            ("T1059.001", "PowerShell"),
            ("powershell", "pwsh"),
        )

    def evaluate(self, session: Session, event: SecurityEvent) -> RuleMatch | None:
        match = super().evaluate(session, event)
        if match is None:
            return None
        command = str(event.normalized_data.get("command_line") or "").lower()
        if not any(
            token in command
            for token in ("-enc", "encodedcommand", "iex", "downloadstring", "-nop")
        ):
            return None
        return match


DEFAULT_RULES: tuple[DetectionRule, ...] = (
    MultipleFailedLoginsRule(),
    SuccessfulLoginAfterFailuresRule(),
    SuspiciousPowerShellRule(),
    KeywordRule(
        "admin_account_created",
        "Administrator account created",
        8,
        ("T1098", "Account Manipulation"),
        ("create_admin", "admin_created", "administrator account created"),
    ),
    KeywordRule(
        "privilege_escalation",
        "Privilege escalation",
        9,
        ("T1068", "Exploitation for Privilege Escalation"),
        ("privilege_escalation", "elevate_privilege", "role_escalation"),
    ),
    KeywordRule(
        "security_controls_disabled",
        "Security controls disabled",
        9,
        ("T1562.001", "Impair Defenses"),
        ("security_control_disabled", "disable_defender", "disable antivirus", "tamper protection"),
    ),
    KeywordRule(
        "execution_from_temp",
        "Execution from temporary directory",
        7,
        ("T1204.002", "User Execution: Malicious File"),
        ("\\temp\\", "/" + "tmp/", "appdata\\local\\temp"),
    ),
)
