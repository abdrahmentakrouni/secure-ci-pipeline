#!/usr/bin/env bash
# Verify the shipped image: cosign keyless signature + SBOM attestation.
#
#   bash scripts/verify_signature.sh
#   bash scripts/verify_signature.sh ghcr.io/abdrahmentakrouni/secure-ci-pipeline@sha256:...
#
# Requires cosign on PATH. Verification is keyless: it checks that the
# image was signed inside this repository's workflow, not by some other
# identity — and that the signature is in the public transparency log.

set -euo pipefail

IMAGE="${1:-ghcr.io/abdrahmentakrouni/secure-ci-pipeline:latest}"

command -v cosign >/dev/null 2>&1 || {
  echo "[!] cosign not found — install it first:"
  echo "    https://docs.sigstore.dev/cosign/system_config/installation/"
  exit 1
}

# Resolve a tag to its immutable digest so verification cannot be swapped.
if [[ "$IMAGE" != *"@sha256:"* ]]; then
  echo "[*] resolving $IMAGE to a digest"
  DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null | cut -d@ -f2 || true)"
  if [ -z "${DIGEST:-}" ]; then
    echo "[!] no local digest for $IMAGE — pull it first: docker pull $IMAGE"
    exit 1
  fi
  IMAGE="${IMAGE%%:*}@${DIGEST}"
fi

echo "[*] verifying keyless signature on $IMAGE"
cosign verify "$IMAGE" \
  --certificate-identity-regexp \
  '^https://github.com/abdrahmentakrouni/secure-ci-pipeline/\.github/workflows/security-pipeline\.yml@.*' \
  --certificate-oidc-issuer '^https://token.actions.githubusercontent.com$'

echo "[*] verifying SBOM attestation"
cosign verify-attestation --type spdxjson "$IMAGE" \
  --certificate-identity-regexp \
  '^https://github.com/abdrahmentakrouni/secure-ci-pipeline/.*' \
  --certificate-oidc-issuer '^https://token.actions.githubusercontent.com$'

echo "[ok] signature + SBOM attestation verified for $IMAGE"
