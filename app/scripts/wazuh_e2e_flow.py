import json
import os
import uuid

import httpx
from sqlalchemy import delete, func, select

from app.core.auth import create_worker_token, hash_password
from app.core.database import SessionLocal, set_tenant_context
from app.models import Alert, Endpoint, IntegrationAccount, Organization, SecurityEvent, User
from app.workers.tasks import sync_wazuh_agents, sync_wazuh_alerts


def main() -> None:
    run_id = uuid.uuid4().hex
    organization_id = uuid.uuid4()
    account_id = uuid.uuid4()
    password = os.environ.get("WAZUH_E2E_APP_PASSWORD", "local-e2e-password")
    with SessionLocal() as session:
        session.add(Organization(id=organization_id, name="Wazuh E2E", slug=f"wazuh-e2e-{run_id}"))
        session.flush()
        set_tenant_context(session, organization_id)
        session.add(
            User(
                organization_id=organization_id,
                email=f"e2e-{run_id}@example.invalid",
                display_name="Wazuh E2E",
                role="admin",
                password_hash=hash_password(password),
            )
        )
        session.add(
            IntegrationAccount(
                id=account_id,
                organization_id=organization_id,
                integration_type="wazuh",
                name="local-wazuh",
                base_url="https://host.docker.internal:55000",
                credential_reference="env://WAZUH_E2E_CREDENTIALS",
                enabled=True,
                status="configured",
            )
        )
        session.commit()

    worker_token = create_worker_token(organization_id, account_id)
    agents_result = sync_wazuh_agents.delay(str(account_id), worker_token).get(timeout=180)
    alerts_result = sync_wazuh_alerts.delay(str(account_id), worker_token).get(timeout=300)

    with SessionLocal() as session:
        set_tenant_context(session, organization_id)
        counts = {
            "endpoints": int(
                session.scalar(
                    select(func.count(Endpoint.id)).where(
                        Endpoint.organization_id == organization_id
                    )
                )
                or 0
            ),
            "events": int(
                session.scalar(
                    select(func.count(SecurityEvent.id)).where(
                        SecurityEvent.organization_id == organization_id
                    )
                )
                or 0
            ),
            "alerts": int(
                session.scalar(
                    select(func.count(Alert.id)).where(Alert.organization_id == organization_id)
                )
                or 0
            ),
        }

    headers = {"Host": "localhost"}
    with httpx.Client(base_url="http://gateway:8080", headers=headers, timeout=30) as client:
        login = client.post(
            "/api/v1/auth/token",
            json={
                "organization_slug": f"wazuh-e2e-{run_id}",
                "email": f"e2e-{run_id}@example.invalid",
                "password": password,
            },
        )
        login.raise_for_status()
        access_token = login.json()["access_token"]
        response = client.get(
            "/api/v1/alerts",
            params={"page": 1, "page_size": 5, "source": "wazuh"},
            headers={"Host": "localhost", "Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        api_total = int(response.headers["X-Total-Count"])

    if not counts["events"] or not counts["alerts"] or api_total != counts["alerts"]:
        raise RuntimeError("Wazuh E2E did not persist and expose alerts consistently")
    print(
        json.dumps(
            {
                "agents_job": agents_result,
                "alerts_job": alerts_result,
                "database": counts,
                "api_alert_total": api_total,
            },
            sort_keys=True,
        )
    )

    with SessionLocal() as session:
        session.execute(delete(Organization).where(Organization.id == organization_id))
        session.commit()


if __name__ == "__main__":
    main()
