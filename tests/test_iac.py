from scripts.validate_iac import main


def test_iac_contract_static_validation_passes() -> None:
    assert main() == 0
