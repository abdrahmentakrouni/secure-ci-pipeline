# Architecture

## What this pipeline is

A supply-chain security gate for container builds. Every change to the
repository passes through seven controls; a release image only reaches the
registry when all of them hold. The same gate runs locally
(`scripts/local_audit.sh`), so what passes on a laptop is what passes in CI.

```
                       push / PR
                           │
     ┌─────────────────────┼──────────────────────┐
     │                     │                      │
 [1 gitleaks]        [2 hadolint +         [3 gate self-test]
  git history          shellcheck]           fixture suite proves
  secret check          │                    the policy engine
     │                  │                    itself works
     └──────────────────┬──────────────────────┘
                        │
              [4 scan-gate matrix]
               build ──► trivy ──► grype ──► policy_gate.py
                app        report    report    │
                app-vulnerable                 ├─ app:           must PASS
                          (same two scanners)  └─ app-vulnerable: must BLOCK
                        │
                 all four jobs green
                        │
              [5 ship — main branch only]
               push ghcr.io/abdrahmentakrouni/secure-ci-pipeline
                        │
               [6 cosign sign — keyless OIDC]
               [7 syft SBOM ──► cosign attest]
                        │
               cosign verify (in-pipeline proof)
                        │
        nightly-rescan ──► same policy ──► issue alert on drift
```

## Design decisions, and why

**Two scanners, one gate.** Trivy and Grype use different vulnerability
databases and matching logic. Running both means a CVE missed by one is
usually caught by the other, and a borderline severity call has to survive
two opinions. Reports are merged in `policy_gate.py`, which keeps the more
severe classification of the two.

**Scanners never decide alone.** Neither tool is configured to fail the
build directly. Both only produce JSON evidence; the verdict comes from
`policy/scan-policy.yml` through `policy_gate.py`. Security policy becomes
a reviewed, versioned, testable artifact instead of a hidden flag inside a
CI plugin. It also means swapping either scanner later changes nothing
about how policy is expressed.

**Every tool binary is pinned and hashed.** `scripts/ci_install_tools.sh`
downloads trivy 0.74.0, grype 0.118.0, gitleaks 8.30.1, hadolint 2.15.1
and syft 1.51.1, verifies each against a SHA-256 recorded in the script,
and aborts on mismatch. A compromised "latest" binary can never execute in
this pipeline — the same discipline applied to images below, applied to the
pipeline's own toolchain.

**The gate is tested like code.** `scripts/test_policy_gate.sh` runs four
fixture cases: clean reports must PASS, vulnerable reports must BLOCK, an
active allowlist entry must suppress, and an expired allowlist entry must
stop suppressing. The CI runs this suite as a first-class job, so a policy
engine bug is caught before it can silently wave a bad image through.

**Proving a block is a green job.** The vulnerable build is expected to be
blocked; the job asserts `BLOCK` as the verdict. If the gate ever returns
`PASS` for the rotten image, that leg fails and the whole pipeline goes
red. A security control that never proves itself is decoration.

**Keyless signing.** After the gate passes and the image is pushed, cosign
signs it using the workflow's OIDC identity: GitHub issues a short-lived
token bound to this repository and workflow file, Fulcio turns it into a
signing certificate, and the signature lands in the Rekor transparency
log. There are no long-lived signing keys to leak, and
`cosign verify` cryptographically answers "was this image built and
approved by this exact pipeline?" — the property a bank's Kubernetes
admission controller (Kyverno, Connaisseur) needs to reject everything else.

**SBOM attestation.** syft generates an SPDX document for the exact image
digest and cosign attaches it as an attestation in the registry. The buyer
of the image gets a machine-readable ingredient list bound to the image,
not a document that may or may not match what is running.

**Drift detection.** A verdict is a point-in-time statement. A CVE
published tomorrow makes today's clean image vulnerable, so a scheduled
workflow re-scans the shipped image every night with the same policy and
re-verifies its signature; a changed verdict opens or updates an issue.
Shipped does not mean forgotten.

## Control mapping

| control | implementation | evidence artifact |
|---------|----------------|-------------------|
| no leaked secrets | gitleaks full-history scan | job log, verbose diff |
| safe image construction | hadolint on release Dockerfile | job log |
| known-vulnerability blocklist | trivy + grype JSON reports | `scan-reports-*` artifacts |
| risk-based verdict | policy YAML + `policy_gate.py` | run summary table |
| reviewed security policy | PR checks on `policy/` | PR history |
| untampered toolchain | pinned SHA-256-verified binaries | `ci_install_tools.sh` |
| image integrity | cosign keyless signature + Rekor | signature, transparency log entry |
| ingredient list | SPDX SBOM attestation | `signing-evidence` artifact |
| continuous assurance | nightly rescan + issue alert | workflow runs, issues |

## Local vs CI parity

`local_audit.sh` runs gitleaks, hadolint, both scanners and the same
policy file against a locally built `local/app:audit` tag. The only steps
that are CI-only are the registry push, signing and attestation — they
require the workflow's OIDC identity, which is exactly what makes the
signature meaningful.

## Going further

The natural next step for a Kubernetes cluster is enforcing this at
admission: Kyverno or Connaisseur can be configured to allow only images
whose cosign signature carries this repository's OIDC identity. At that
point the gate is not just in the pipeline — it is in the cluster.
