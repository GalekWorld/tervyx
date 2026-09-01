import ipaddress
import socket
from urllib.parse import urlparse

from app.core.config import get_settings


class UnsafeURLError(ValueError):
    pass


def validate_outbound_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeURLError("Integration URL must be HTTPS without embedded credentials")
    settings = get_settings()
    hostname = parsed.hostname.lower()
    if settings.app_env == "test" and settings.allow_private_integration_urls:
        return value.rstrip("/")
    allowed_hosts = settings.integration_allowed_hosts_list
    if allowed_hosts and not any(
        hostname == pattern
        or (pattern.startswith("*.") and hostname.endswith(pattern.removeprefix("*")))
        for pattern in allowed_hosts
    ):
        raise UnsafeURLError("Integration hostname is not allowlisted")
    allowed_networks = [
        ipaddress.ip_network(item) for item in settings.integration_private_networks
    ]
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)}
    except socket.gaierror as exc:
        raise UnsafeURLError("Integration hostname cannot be resolved") from exc
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise UnsafeURLError("Integration URL resolves to a private or reserved address")
        if not address.is_global and not (
            settings.allow_private_integration_urls
            or any(address in network for network in allowed_networks)
        ):
            raise UnsafeURLError("Integration URL resolves to an unauthorized private address")
    return value.rstrip("/")
