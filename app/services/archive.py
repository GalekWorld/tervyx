"""Tenant-scoped archival with write-then-delete semantics.

Events are only removed from PostgreSQL after the archive object has been
written and checksumed.  This makes retries safe and prevents silent loss when
object storage or the database becomes unavailable halfway through a run.
"""

import gzip
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import AuditLog, DataRetentionPolicy, SecurityEvent, SecurityEventArchive
from app.services import audit_ledger  # noqa: F401 - registers the sealing listener
from app.services.quotas import QuotaService


class ObjectStorage(Protocol):
    def put_bytes(self, key: str, value: bytes) -> None: ...

    def delete(self, key: str) -> None: ...


class FilesystemObjectStorage:
    """Development-only S3-compatible contract implementation."""

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        candidate = (self.root / key).resolve()
        if self.root not in candidate.parents and candidate != self.root:
            raise ValueError("Unsafe object storage key")
        return candidate

    def put_bytes(self, key: str, value: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def delete(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            path.unlink()


class S3ObjectStorage:
    def __init__(self) -> None:
        import boto3

        settings = get_settings()
        self.bucket = settings.object_storage_bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.object_storage_endpoint_url or None,
            region_name=settings.object_storage_region,
        )

    def put_bytes(self, key: str, value: bytes) -> None:
        self.client.put_object(
            Bucket=self.bucket, Key=key, Body=value, ServerSideEncryption="AES256"
        )

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)


def get_object_storage() -> ObjectStorage:
    settings = get_settings()
    if settings.object_storage_backend == "s3":
        return S3ObjectStorage()
    if settings.app_env == "production":
        raise RuntimeError("Filesystem archive storage is prohibited in production")
    return FilesystemObjectStorage(settings.object_storage_local_path)


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    archived_events: int = 0
    archived_bytes: int = 0
    purged_archives: int = 0


class RetentionService:
    def __init__(self, session: Session, storage: ObjectStorage | None = None) -> None:
        self.session = session
        self.storage = storage or get_object_storage()

    def policy(self, organization_id: uuid.UUID) -> DataRetentionPolicy:
        policy = self.session.scalar(
            select(DataRetentionPolicy).where(
                DataRetentionPolicy.organization_id == organization_id
            )
        )
        if policy is not None:
            return policy
        settings = get_settings()
        policy = DataRetentionPolicy(
            organization_id=organization_id,
            archive_after_days=settings.retention_archive_after_days,
            retention_days=settings.retention_default_days,
            enabled=True,
        )
        self.session.add(policy)
        self.session.flush()
        return policy

    def archive_due(
        self, organization_id: uuid.UUID, *, now: datetime | None = None
    ) -> ArchiveResult:
        now = now or datetime.now(UTC)
        policy = self.policy(organization_id)
        if not policy.enabled:
            return ArchiveResult()
        cutoff = now - timedelta(days=policy.archive_after_days)
        events = list(
            self.session.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.organization_id == organization_id,
                    SecurityEvent.occurred_at < cutoff,
                )
                .order_by(SecurityEvent.occurred_at)
                .limit(get_settings().archive_batch_size)
            )
        )
        if not events:
            self.session.commit()
            return ArchiveResult()
        rows = [
            {
                "id": str(event.id),
                "organization_id": str(event.organization_id),
                "endpoint_id": str(event.endpoint_id),
                "source": event.source,
                "external_id": event.external_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "occurred_at": event.occurred_at.isoformat(),
                "raw_payload": event.raw_payload,
            }
            for event in events
        ]
        data = gzip.compress(
            "\n".join(json.dumps(row, sort_keys=True, default=str) for row in rows).encode()
        )
        checksum = hashlib.sha256(data).hexdigest()
        key = (
            f"{get_settings().object_storage_prefix}/tenants/{organization_id}/events/"
            f"{now:%Y/%m/%d}/{uuid.uuid4()}.ndjson.gz"
        )
        self.storage.put_bytes(key, data)  # must complete before destructive DB work
        archive = SecurityEventArchive(
            organization_id=organization_id,
            storage_key=key,
            checksum_sha256=checksum,
            event_count=len(events),
            byte_count=len(data),
            first_occurred_at=events[0].occurred_at,
            last_occurred_at=events[-1].occurred_at,
            status="archived",
        )
        self.session.add(archive)
        hot_bytes = sum(
            len(json.dumps(event.raw_payload, default=str).encode()) for event in events
        )
        QuotaService(self.session).record_archive(
            organization_id, hot_bytes=hot_bytes, archive_bytes=len(data)
        )
        for event in events:
            self.session.delete(event)
        self.session.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="system",
                actor_id="retention",
                action="security_events.archived",
                resource_type="security_event_archive",
                resource_id=str(archive.id),
                details={"count": len(events), "checksum": checksum},
            )
        )
        self.session.commit()
        return ArchiveResult(archived_events=len(events), archived_bytes=len(data))

    def purge_expired_archives(
        self, organization_id: uuid.UUID, *, now: datetime | None = None
    ) -> ArchiveResult:
        now = now or datetime.now(UTC)
        policy = self.policy(organization_id)
        cutoff = now - timedelta(days=policy.retention_days)
        archives = list(
            self.session.scalars(
                select(SecurityEventArchive).where(
                    SecurityEventArchive.organization_id == organization_id,
                    SecurityEventArchive.created_at < cutoff,
                    SecurityEventArchive.status == "archived",
                )
            )
        )
        for archive in archives:
            self.storage.delete(archive.storage_key)
            archive.status = "purged"
            self.session.add(
                AuditLog(
                    organization_id=organization_id,
                    actor_type="system",
                    actor_id="retention",
                    action="security_event_archive.purged",
                    resource_type="security_event_archive",
                    resource_id=str(archive.id),
                    details={"storage_key": archive.storage_key},
                )
            )
        self.session.commit()
        return ArchiveResult(purged_archives=len(archives))
