import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    private_path = Path(os.environ.get("JWT_PRIVATE_KEY_PATH", "/run/jwt/private.pem"))
    public_path = Path(os.environ.get("JWT_PUBLIC_KEY_PATH", "/run/jwt/public.pem"))
    private_path.parent.mkdir(parents=True, exist_ok=True)
    if private_path.exists() and public_path.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,  # type: ignore[arg-type]
            serialization.PrivateFormat.PKCS8,  # type: ignore[arg-type]
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,  # type: ignore[arg-type]
            serialization.PublicFormat.SubjectPublicKeyInfo,  # type: ignore[arg-type]
        )
    )
    private_path.chmod(0o444)
    public_path.chmod(0o444)


if __name__ == "__main__":
    main()
