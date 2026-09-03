from scripts.validate_iac import main as validate_iac
from scripts.validate_vulnerability_policy import main as validate_vulnerabilities


def test_iac_and_vulnerability_policies_are_valid() -> None:
    assert validate_iac() == 0
    assert validate_vulnerabilities() == 0
