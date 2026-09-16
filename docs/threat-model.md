# Threat model

What this pipeline defends against, what it does not, and where each
defence lives. The scope is the software supply chain of one container
image, from source commit to signed registry artifact.

## Assets

- the release image published to `ghcr.io/abdrahmentakrouni/secure-ci-pipeline`
- the repository and its CI credentials
- the policy file that decides what ships

## Adversaries

- a careless developer (the most common real attacker): commits a secret,
  pins nothing, ships an old base image
- an attacker who obtained a package or tool binary and wants it executed
  inside the pipeline
- an attacker who wants to swap the approved image for a tampered one
  between build and deploy

## Threats and controls

| # | threat | control | where |
|---|--------|---------|-------|
| 1 | API key, token or password committed to git history | gitleaks full-history scan with redaction | job 1, every push |
| 2 | vulnerable base image (EOL distro, unpatched CVEs) | trivy + grype scan of the built image, policy blocks CRITICAL | scan-gate |
| 3 | vulnerable application dependencies (known CVEs) | same scan covers python packages; `app-vulnerable` demonstrates the block | scan-gate |
| 4 | weak Dockerfile (root user, latest tag, no healthcheck) | hadolint on the release Dockerfile | lint |
| 5 | compromised scanner binary (attacker replaces a tool) | pinned versions + SHA-256 verification before install; mismatch aborts the run | `ci_install_tools.sh` |
| 6 | image swapped after approval (build ≠ what ships) | image pushed by digest, signed keylessly in the same run, verified immediately; deploy-side verification via `scripts/verify_signature.sh` | ship |
| 7 | signing key leaked | there is no signing key: cosign keyless uses a short-lived OIDC-bound certificate from Fulcio, logged in Rekor | ship |
| 8 | silently weakened policy (someone "temporarily" disables the gate) | policy is a reviewed file; fixture self-test asserts PASS/BLOCK semantics on every run | gate-selftest |
| 9 | accepted risk quietly becomes permanent | allowlist entries carry an expiry date; expired entries stop suppressing automatically | `policy_gate.py` |
| 10 | image rot: new CVE published after ship | nightly rescan of the shipped image with the same policy; verdict change opens an alert issue; signature re-verified | nightly-rescan |
| 11 | unpinned CI actions drifting | actions referenced by version tag; checkout pinned to v4 | workflows |

## Explicitly out of scope

- **Runtime security.** What happens inside a running container (syscall
  anomalies, container escape) is the domain of runtime tooling — see
  Falco or a managed EDR. This gate stops bad images from ever shipping.
- **Kubernetes admission enforcement.** Enforcing the signature at
  cluster admission is a one-line policy in Kyverno/Connaisseur once the
  signature exists; the wiring depends on the cluster, not this repo.
- **Source code vulnerability analysis (SAST).** Dependency and OS
  vulnerabilities are covered; logic flaws in the app itself are not.

## Assumptions

- GitHub Actions runners and the actions referenced (`actions/checkout`,
  `docker/*`, `sigstore/cosign-installer`) are trusted computing base.
- PyPI packages declared in `app/requirements.txt` are reviewed at
  version-pinning time; the scanners catch known-CVE regressions, not
  zero-days in dependencies.
- The registry (GHCR) preserves digest immutability.
