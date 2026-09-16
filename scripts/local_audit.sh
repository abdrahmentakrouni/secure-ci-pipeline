#!/usr/bin/env bash
# One-shot local mirror of the CI security gate.
#
#   bash scripts/local_audit.sh               # secrets + lint + build + scan + gate
#   bash scripts/local_audit.sh --skip-build  # re-gate existing reports in reports/
#   bash scripts/local_audit.sh --secrets-only
#
# Output lands in reports/ (git-ignored) and the policy gate decides the
# verdict exactly like it does in CI.

set -euo pipefail

cd "$(dirname "$0")/.."

TAG="local/app:audit"
REPORTS="reports"
MODE="full"
for arg in "$@"; do
  case "$arg" in
    --skip-build)   MODE="rescan" ;;
    --secrets-only) MODE="secrets" ;;
    *)
      echo "unknown option: $arg"
      echo "usage: $0 [--skip-build | --secrets-only]"
      exit 1
      ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] missing tool: $1"
    echo "    install pinned copies with: bash scripts/ci_install_tools.sh $1"
    exit 1
  }
}

mkdir -p "$REPORTS"

if [ "$MODE" = "full" ] || [ "$MODE" = "secrets" ]; then
  need gitleaks
  echo "[*] gitleaks: scanning git history for leaked secrets"
  if ! gitleaks detect --source . --config .gitleaks.toml --redact; then
    echo "[!] gitleaks found leaks — rotate the exposed key first, then purge history"
    exit 1
  fi
  echo "[ok] no secrets in history"
fi

if [ "$MODE" = "full" ]; then
  need hadolint
  echo "[*] hadolint: linting app/Dockerfile"
  hadolint app/Dockerfile
  echo "[ok] Dockerfile clean"

  need docker
  echo "[*] docker: building $TAG"
  docker build -t "$TAG" app

  need trivy
  need grype
  echo "[*] trivy: vulnerability scan"
  trivy image --quiet --scanners vuln --ignore-unfixed \
    --format json --output "$REPORTS/trivy.json" "$TAG"

  echo "[*] grype: second-opinion scan"
  grype "$TAG" --only-fixed -o json > "$REPORTS/grype.json"
fi

if [ "$MODE" = "full" ] || [ "$MODE" = "rescan" ]; then
  need python3
  echo "[*] policy gate"
  rc=0
  python3 scripts/policy_gate.py \
    --trivy "$REPORTS/trivy.json" \
    --grype "$REPORTS/grype.json" \
    --policy policy/scan-policy.yml \
    --image "$TAG" || rc=$?
  case "$rc" in
    0) echo "[ok] verdict PASS — image may ship" ;;
    2) echo "[!] verdict BLOCK — fix the findings or allowlist with expiry" ; exit 2 ;;
    *) echo "[!] gate error (exit $rc)" ; exit "$rc" ;;
  esac
fi
