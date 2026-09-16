#!/usr/bin/env bash
# Self-test for the policy gate: fixtures -> expected verdicts.
# The gate that decides what ships must itself be tested.

set -euo pipefail

cd "$(dirname "$0")"
FIX="tests/fixtures"
POLICY="../policy/scan-policy.yml"

run_case() {
  # run_case <label> <policy> <expect> <trivy> <grype>
  local label="$1" policy="$2" expect="$3" trivy="$4" grype="$5"
  echo "[*] $label"
  python3 policy_gate.py \
    --trivy "$trivy" --grype "$grype" \
    --policy "$policy" \
    --image "selftest" \
    --expect "$expect" --quiet
}

run_case "clean fixtures must PASS" \
  "$POLICY" PASS "$FIX/trivy_clean.json" "$FIX/grype_clean.json"

run_case "vulnerable fixtures must BLOCK" \
  "$POLICY" BLOCK "$FIX/trivy_vuln.json" "$FIX/grype_vuln.json"

run_case "active allowlist must PASS" \
  "$FIX/policy_allowlist.yml" PASS "$FIX/trivy_vuln.json" "$FIX/grype_vuln.json"

run_case "expired allowlist must BLOCK again" \
  "$FIX/policy_expired.yml" BLOCK "$FIX/trivy_vuln.json" "$FIX/grype_vuln.json"

echo "[ok] policy gate self-test passed (4 cases)"
