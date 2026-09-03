import json
import uuid
from dataclasses import dataclass
from typing import Any, cast

from redis import Redis
from redis.exceptions import RedisError


class BackpressureError(RuntimeError):
    pass


@dataclass(frozen=True)
class TenantWorkItem:
    organization_id: uuid.UUID
    body: dict[str, Any]


class TenantFairQueue:
    """Redis round-robin queue: at most one item per tenant per dispatch pass."""

    active_key = "tenant-work:active"
    round_robin_key = "tenant-work:round-robin"

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    def enqueue(self, organization_id: uuid.UUID, body: dict[str, Any], *, max_depth: int) -> int:
        key = self._tenant_key(organization_id)
        encoded = json.dumps(body, separators=(",", ":"), default=str)
        try:
            pipe = self.redis.pipeline()
            pipe.rpush(key, encoded)
            pipe.llen(key)
            result = pipe.execute()
            depth = int(result[1])
            if depth > max_depth:
                self.redis.rpop(key)
                raise BackpressureError("Tenant queue capacity exceeded")
            if self.redis.sadd(self.active_key, str(organization_id)):
                self.redis.rpush(self.round_robin_key, str(organization_id))
            return depth
        except RedisError as exc:
            raise BackpressureError("Tenant scheduler is unavailable") from exc

    def dequeue_fair(self, limit: int) -> list[TenantWorkItem]:
        items: list[TenantWorkItem] = []
        for _ in range(max(0, limit)):
            try:
                raw_org = self.redis.lpop(self.round_robin_key)
            except RedisError as exc:
                raise BackpressureError("Tenant scheduler is unavailable") from exc
            if raw_org is None:
                break
            organization_id = uuid.UUID(
                str(cast(Any, raw_org.decode() if isinstance(raw_org, bytes) else raw_org))
            )
            key = self._tenant_key(organization_id)
            raw_item = self.redis.lpop(key)
            remaining = int(cast(Any, self.redis.llen(key)))
            if remaining:
                self.redis.rpush(self.round_robin_key, str(organization_id))
            else:
                self.redis.srem(self.active_key, str(organization_id))
            if raw_item is None:
                continue
            decoded = raw_item.decode() if isinstance(raw_item, bytes) else raw_item
            items.append(
                TenantWorkItem(organization_id=organization_id, body=json.loads(cast(Any, decoded)))
            )
        return items

    @staticmethod
    def _tenant_key(organization_id: uuid.UUID) -> str:
        return f"tenant-work:{organization_id}"
