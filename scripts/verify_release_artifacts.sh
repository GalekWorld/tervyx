#!/usr/bin/env sh
set -eu

: "${IMAGE:?set IMAGE to the immutable registry image reference}"
: "${DIGEST:?set DIGEST to the sha256 digest from the release job}"
: "${REPOSITORY:?set REPOSITORY to ORG/REPO}"

IMAGE_DIGEST="$IMAGE@$DIGEST"
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/.*" \
  "$IMAGE_DIGEST" > "${EVIDENCE_FILE:-cosign-verify.json}"
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/.*" \
  "$IMAGE_DIGEST" > "${ATTESTATION_FILE:-cosign-attestation.json}"
printf '%s\n' "release_artifacts=verified image=$IMAGE_DIGEST"
