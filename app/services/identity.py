import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.credentials import CredentialStore
from app.core.database import set_tenant_context
from app.integrations.oidc import OIDCClient, OIDCError
from app.integrations.oidc.client import pkce_pair
from app.models import (
    AuditLog,
    AuthSession,
    FederatedIdentity,
    IdentityProvider,
    OIDCLoginTransaction,
    RefreshToken,
    User,
)


class IdentityError(RuntimeError):
    pass


def state_organization(state: str) -> uuid.UUID:
    try:
        organization, _transaction, random_value = state.split(".", 2)
        if len(random_value) < 32:
            raise ValueError
        return uuid.UUID(organization)
    except (ValueError, AttributeError) as exc:
        raise IdentityError("Invalid OIDC state") from exc


class IdentityService:
    def __init__(self, session: Session, credential_store: CredentialStore) -> None:
        self.session = session
        self.credential_store = credential_store

    def _cipher(self) -> Fernet:
        key = get_settings().oidc_transaction_key
        if not key:
            raise IdentityError("OIDC transaction encryption key is not configured")
        try:
            return Fernet(key.encode())
        except (ValueError, TypeError) as exc:
            raise IdentityError("OIDC transaction encryption key is invalid") from exc

    def begin(self, provider: IdentityProvider, redirect_uri: str) -> tuple[str, int]:
        if not provider.enabled or redirect_uri not in provider.allowed_redirect_uris:
            raise IdentityError("OIDC provider or redirect URI is not allowed")
        verifier, challenge = pkce_pair()
        nonce = secrets.token_urlsafe(32)
        transaction_id = uuid.uuid4()
        state = f"{provider.organization_id}.{transaction_id}.{secrets.token_urlsafe(32)}"
        settings = get_settings()
        self.session.add(
            OIDCLoginTransaction(
                id=transaction_id,
                organization_id=provider.organization_id,
                provider_id=provider.id,
                state_hash=hashlib.sha256(state.encode()).hexdigest(),
                nonce=nonce,
                code_verifier_ciphertext=self._cipher().encrypt(verifier.encode()).decode(),
                redirect_uri=redirect_uri,
                expires_at=datetime.now(UTC)
                + timedelta(minutes=settings.oidc_transaction_ttl_minutes),
            )
        )
        client = OIDCClient(
            provider,
            "",
            timeout=settings.oidc_http_timeout_seconds,
            resilience_key=f"{provider.organization_id}:{provider.id}",
        )
        try:
            authorization_url = client.authorization_url(
                state=state,
                nonce=nonce,
                redirect_uri=redirect_uri,
                code_challenge=challenge,
            )
        finally:
            close = getattr(client, "close", None)
            if close:
                close()
        self.session.commit()
        return authorization_url, settings.oidc_transaction_ttl_minutes * 60

    def callback(self, state: str, code: str, redirect_uri: str) -> tuple[User, AuthSession]:
        organization_id = state_organization(state)
        set_tenant_context(self.session, organization_id)
        try:
            transaction_id = uuid.UUID(state.split(".", 2)[1])
        except (ValueError, IndexError) as exc:
            raise IdentityError("Invalid OIDC state") from exc
        transaction = self.session.scalar(
            select(OIDCLoginTransaction)
            .where(
                OIDCLoginTransaction.id == transaction_id,
                OIDCLoginTransaction.organization_id == organization_id,
                OIDCLoginTransaction.state_hash == hashlib.sha256(state.encode()).hexdigest(),
                OIDCLoginTransaction.used_at.is_(None),
                OIDCLoginTransaction.expires_at > datetime.now(UTC),
            )
            .with_for_update()
        )
        if transaction is None or transaction.redirect_uri != redirect_uri:
            raise IdentityError("OIDC transaction is invalid, expired, or already used")
        transaction.used_at = datetime.now(UTC)
        self.session.commit()
        set_tenant_context(self.session, organization_id)
        provider = self.session.scalar(
            select(IdentityProvider).where(
                IdentityProvider.id == transaction.provider_id,
                IdentityProvider.organization_id == organization_id,
                IdentityProvider.enabled.is_(True),
            )
        )
        if provider is None:
            raise IdentityError("OIDC provider is unavailable")
        try:
            verifier = (
                self._cipher()
                .decrypt(transaction.code_verifier_ciphertext.encode(), ttl=900)
                .decode()
            )
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise IdentityError("OIDC transaction verifier is invalid") from exc
        credentials = self.credential_store.get(organization_id, provider.client_secret_reference)
        client_secret = credentials.get("client_secret")
        if not isinstance(client_secret, str) or not client_secret:
            raise IdentityError("OIDC client secret is unavailable")
        client = OIDCClient(
            provider,
            client_secret,
            timeout=get_settings().oidc_http_timeout_seconds,
            resilience_key=f"{organization_id}:{provider.id}",
        )
        try:
            identity = client.exchange_code(
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=verifier,
                nonce=transaction.nonce,
            )
        except OIDCError as exc:
            raise IdentityError(str(exc)) from exc
        finally:
            close = getattr(client, "close", None)
            if close:
                close()

        federated = self.session.scalar(
            select(FederatedIdentity).where(
                FederatedIdentity.organization_id == organization_id,
                FederatedIdentity.provider_id == provider.id,
                FederatedIdentity.subject == identity.subject,
            )
        )
        user = (
            self.session.scalar(
                select(User).where(
                    User.id == federated.user_id,
                    User.organization_id == organization_id,
                )
            )
            if federated
            else None
        )
        if user is None and identity.email:
            user = self.session.scalar(
                select(User).where(
                    User.organization_id == organization_id,
                    User.email == identity.email,
                    User.is_active.is_(True),
                )
            )
            if user is not None:
                self.session.add(
                    FederatedIdentity(
                        organization_id=organization_id,
                        provider_id=provider.id,
                        user_id=user.id,
                        subject=identity.subject,
                        provider_tenant_id=identity.provider_tenant_id,
                        email=identity.email,
                    )
                )
        if user is None or not user.is_active:
            raise IdentityError("Federated identity is not provisioned")
        if (provider.enforce_mfa or user.role == "admin") and not identity.mfa_verified:
            raise IdentityError("Multifactor authentication is required")

        now = datetime.now(UTC)
        auth_session = AuthSession(
            organization_id=organization_id,
            user_id=user.id,
            provider_id=provider.id,
            auth_method=f"oidc:{provider.provider_type}",
            mfa_verified=identity.mfa_verified,
            mfa_verified_at=now if identity.mfa_verified else None,
            mfa_methods=sorted(identity.mfa_methods),
            expires_at=now + timedelta(hours=get_settings().session_ttl_hours),
            last_seen_at=now,
        )
        self.session.add(auth_session)
        self.session.flush()
        self.session.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(user.id),
                action="auth.oidc_login_succeeded",
                resource_type="auth_session",
                resource_id=str(auth_session.id),
                details={"provider_id": str(provider.id), "mfa_verified": identity.mfa_verified},
            )
        )
        self.session.commit()
        return user, auth_session

    def revoke_session(
        self, auth_session: AuthSession, *, actor_id: uuid.UUID, reason: str
    ) -> None:
        now = datetime.now(UTC)
        auth_session.revoked_at = now
        auth_session.revocation_reason = reason[:500]
        self.session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.organization_id == auth_session.organization_id,
                RefreshToken.session_id == auth_session.id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        self.session.add(
            AuditLog(
                organization_id=auth_session.organization_id,
                actor_type="user",
                actor_id=str(actor_id),
                action="auth.session_revoked",
                resource_type="auth_session",
                resource_id=str(auth_session.id),
                details={"reason": reason[:500]},
            )
        )
        self.session.commit()

    def revoke_user_sessions(
        self, organization_id: uuid.UUID, user_id: uuid.UUID, *, actor_id: uuid.UUID, reason: str
    ) -> int:
        now = datetime.now(UTC)
        session_ids = list(
            self.session.scalars(
                select(AuthSession.id).where(
                    AuthSession.organization_id == organization_id,
                    AuthSession.user_id == user_id,
                    AuthSession.revoked_at.is_(None),
                )
            )
        )
        self.session.execute(
            update(AuthSession)
            .where(AuthSession.id.in_(session_ids))
            .values(revoked_at=now, revocation_reason=reason[:500])
        )
        if session_ids:
            self.session.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.organization_id == organization_id,
                    RefreshToken.session_id.in_(session_ids),
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
        self.session.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(actor_id),
                action="auth.global_logout",
                resource_type="user",
                resource_id=str(user_id),
                details={"reason": reason[:500], "session_count": len(session_ids)},
            )
        )
        self.session.commit()
        return len(session_ids)
