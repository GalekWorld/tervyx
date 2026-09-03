from scripts.validate_supply_chain import main


def test_supply_chain_repository_controls_are_present() -> None:
    assert main() == 0
