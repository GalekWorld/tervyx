from app.integrations.base import SecuritySourceAdapter


class AdapterRegistry:
    def __init__(self, adapters: list[SecuritySourceAdapter]) -> None:
        self._adapters = {adapter.source: adapter for adapter in adapters}

    def get(self, source: str) -> SecuritySourceAdapter:
        try:
            return self._adapters[source.lower()]
        except KeyError as exc:
            raise ValueError(f"Unsupported security source: {source}") from exc
