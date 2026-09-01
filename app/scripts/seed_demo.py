from app.core.database import SessionLocal
from app.services.demo_data import seed_demo_data


def main() -> None:
    with SessionLocal() as session:
        organization = seed_demo_data(session)
        print(f"Demo organization ready: {organization.id}")


if __name__ == "__main__":
    main()
