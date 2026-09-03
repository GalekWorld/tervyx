"""Tenant-scoped persistence for rule configuration, suppression and metrics."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import DetectionRuleConfiguration, DetectionRuleMetric, DetectionSuppression

DEFAULT_SUPPRESSION_WINDOW_SECONDS = 900


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class DetectionConfigurationService:
    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def active(self, rule_id: str) -> DetectionRuleConfiguration:
        self._lock(rule_id)
        configuration = self.session.scalar(
            select(DetectionRuleConfiguration).where(
                DetectionRuleConfiguration.organization_id == self.organization_id,
                DetectionRuleConfiguration.rule_id == rule_id,
                DetectionRuleConfiguration.active.is_(True),
            )
        )
        if configuration is not None:
            return configuration
        configuration = DetectionRuleConfiguration(
            organization_id=self.organization_id,
            rule_id=rule_id,
            version=1,
            enabled=True,
            active=True,
            suppression_window_seconds=DEFAULT_SUPPRESSION_WINDOW_SECONDS,
            configuration={},
        )
        self.session.add(configuration)
        self.session.flush()
        return configuration

    def configure(
        self,
        rule_id: str,
        *,
        enabled: bool,
        suppression_window_seconds: int,
        configuration: dict[str, Any] | None = None,
    ) -> DetectionRuleConfiguration:
        if suppression_window_seconds < 0:
            raise ValueError("suppression_window_seconds must be non-negative")
        self._lock(rule_id)
        current = self.session.scalar(
            select(DetectionRuleConfiguration).where(
                DetectionRuleConfiguration.organization_id == self.organization_id,
                DetectionRuleConfiguration.rule_id == rule_id,
                DetectionRuleConfiguration.active.is_(True),
            )
        )
        next_version = 1
        if current is not None:
            current.active = False
            next_version = current.version + 1
        updated = DetectionRuleConfiguration(
            organization_id=self.organization_id,
            rule_id=rule_id,
            version=next_version,
            enabled=enabled,
            active=True,
            suppression_window_seconds=suppression_window_seconds,
            configuration=configuration or {},
        )
        self.session.add(updated)
        self.session.flush()
        return updated

    def metric(self, rule_id: str) -> DetectionRuleMetric:
        self._lock(f"metric:{rule_id}")
        metric = self.session.scalar(
            select(DetectionRuleMetric).where(
                DetectionRuleMetric.organization_id == self.organization_id,
                DetectionRuleMetric.rule_id == rule_id,
            )
        )
        if metric is not None:
            return metric
        metric = DetectionRuleMetric(
            organization_id=self.organization_id,
            rule_id=rule_id,
            executions=0,
            matches=0,
            alerts_created=0,
            alerts_suppressed=0,
        )
        self.session.add(metric)
        self.session.flush()
        return metric

    def suppresses(
        self,
        rule_id: str,
        correlation_key: str,
        occurred_at: datetime,
        window_seconds: int,
    ) -> bool:
        self._lock(f"suppression:{rule_id}:{correlation_key}")
        state = self.session.scalar(
            select(DetectionSuppression).where(
                DetectionSuppression.organization_id == self.organization_id,
                DetectionSuppression.rule_id == rule_id,
                DetectionSuppression.correlation_key == correlation_key,
            )
        )
        if state is not None:
            last_alert_at = _as_utc(state.last_alert_at)
            occurred_at = _as_utc(occurred_at)
        if state is not None and last_alert_at <= occurred_at < last_alert_at + timedelta(
            seconds=window_seconds
        ):
            state.suppressed_count += 1
            return True
        if state is None:
            state = DetectionSuppression(
                organization_id=self.organization_id,
                rule_id=rule_id,
                correlation_key=correlation_key,
                last_alert_at=occurred_at,
                suppressed_count=0,
            )
            self.session.add(state)
        else:
            state.last_alert_at = occurred_at
        return False

    def _lock(self, key: str) -> None:
        """Serialize first-row creation and updates on PostgreSQL; no-op in unit SQLite."""
        bind = self.session.bind
        if bind is not None and bind.dialect.name == "postgresql":
            self.session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": f"detection:{self.organization_id}:{key}"},
            )
