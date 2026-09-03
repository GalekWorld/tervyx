"""Read-only GitHub branch-protection evidence collector.

Requires GITHUB_TOKEN and GITHUB_REPOSITORY only when --check is requested;
never mutates repository settings.
"""

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="query GitHub read-only")
    parser.add_argument("--branch", default="main")
    args = parser.parse_args()
    if not args.check:
        print("GitHub protection check not requested; use --check in a configured runner")
        return 0
    repository = os.getenv("GITHUB_REPOSITORY")
    token = os.getenv("GITHUB_TOKEN")
    if not repository or not token:
        print("FAIL: GITHUB_REPOSITORY and GITHUB_TOKEN are required for external validation")
        return 1
    request = Request(
        f"https://api.github.com/repos/{repository}/branches/{args.branch}/protection",
        headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"},
    )
    try:
        # URL is constructed exclusively with the fixed HTTPS GitHub API host.
        with urlopen(request, timeout=15) as response:  # noqa: S310
            protection = json.load(response)
    except (HTTPError, URLError, TimeoutError) as exc:
        print(f"FAIL: could not read branch protection: {exc}")
        return 1
    required = protection.get("required_pull_request_reviews") or {}
    checks = protection.get("required_status_checks") or {}
    failures = []
    if not required.get("required_approving_review_count", 0) >= 1:
        failures.append("one required PR approval")
    if not checks.get("strict"):
        failures.append("strict required status checks")
    if protection.get("allow_force_pushes") or protection.get("allow_deletions"):
        failures.append("force-push/deletion disabled")
    if not protection.get("enforce_admins", {}).get("enabled"):
        failures.append("admin enforcement")
    if failures:
        print("FAIL: " + ", ".join(failures))
        return 1
    print("PASS: GitHub branch protection evidence satisfies baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
