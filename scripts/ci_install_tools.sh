#!/usr/bin/env bash
# Install pinned release binaries with SHA-256 verification.
#
# Every scanner this pipeline relies on is downloaded at a hard-pinned
# version and verified against a hash recorded here before it is trusted.
# A compromised or silently-updated "latest" binary can never run here.
#
# Usage: ci_install_tools.sh <tool> [tool...]
#   tools: trivy grype gitleaks hadolint syft
#
# Hashes were taken from each project's official checksum file at pin time.

set -euo pipefail

DEST="${HOME}/.local/bin"
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

install_tar() {
  # install_tar <name> <url> <sha256> <binary-name>
  local name="$1" url="$2" want="$3" bin="$4"
  echo "[*] $name: downloading pinned ${url##*/}"
  curl -fsSL --retry 3 -o "${TMP}/${name}.tgz" "$url"
  echo "${want}  ${TMP}/${name}.tgz" | sha256sum --check --status \
    || { echo "[!] $name: SHA-256 mismatch, aborting"; exit 1; }
  tar -xzf "${TMP}/${name}.tgz" -C "$TMP" "$bin"
  install -m 0755 "${TMP}/${bin}" "${DEST}/${bin}"
  echo "[ok] $name: $("${DEST}/${bin}" --version 2>/dev/null | head -n 1)"
}

install_raw() {
  # install_raw <name> <url> <sha256> <binary-name>
  local name="$1" url="$2" want="$3" bin="$4"
  echo "[*] $name: downloading pinned ${url##*/}"
  curl -fsSL --retry 3 -o "${TMP}/${bin}" "$url"
  echo "${want}  ${TMP}/${bin}" | sha256sum --check --status \
    || { echo "[!] $name: SHA-256 mismatch, aborting"; exit 1; }
  install -m 0755 "${TMP}/${bin}" "${DEST}/${bin}"
  echo "[ok] $name: $("${DEST}/${bin}" --version 2>/dev/null | head -n 1)"
}

TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz"
TRIVY_SHA="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"

GRYPE_URL="https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_amd64.tar.gz"
GRYPE_SHA="1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2"

GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
GITLEAKS_SHA="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"

HADOLINT_URL="https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-Linux-x86_64"
HADOLINT_SHA="c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507"

SYFT_URL="https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz"
SYFT_SHA="8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <tool> [tool...]  (trivy grype gitleaks hadolint syft)"
  exit 1
fi

for tool in "$@"; do
  case "$tool" in
    trivy)    install_tar trivy "$TRIVY_URL" "$TRIVY_SHA" trivy ;;
    grype)    install_tar grype "$GRYPE_URL" "$GRYPE_SHA" grype ;;
    gitleaks) install_tar gitleaks "$GITLEAKS_URL" "$GITLEAKS_SHA" gitleaks ;;
    hadolint) install_raw hadolint "$HADOLINT_URL" "$HADOLINT_SHA" hadolint ;;
    syft)     install_tar syft "$SYFT_URL" "$SYFT_SHA" syft ;;
    *)
      echo "[!] unknown tool: $tool (supported: trivy grype gitleaks hadolint syft)"
      exit 1
      ;;
  esac
done

# Make the binaries visible to later workflow steps.
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$DEST" >> "$GITHUB_PATH"
fi
