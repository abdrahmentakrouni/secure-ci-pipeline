# Runbook — when the gate goes red

The gate blocked a build. Follow these steps in order. The worst possible
reaction is "someone make it green" — the second worst is adding a
forever-allowlist entry.

## 0. Read the verdict table

Open the failed run. The `scan + gate (...)` job prints a Markdown table
in the step summary: severity counts, the violating CVEs, which rule
matched, and the verdict. That table is the input for everything below.

## 1. A secret was found (gitleaks job red)

1. **Rotate the exposed credential first.** The job log shows the match
   (redacted). Assume it is compromised the moment it was committed.
2. Revoke and re-issue the key in its provider console.
3. Only then clean history (`git filter-repo` or BFG), coordinate with
   anyone who has clones, and re-push.
4. Re-run the pipeline. It must come back green with **no** allowlist
   entry — gitleaks findings are never allowlisted, they are rotated.

## 2. A vulnerability blocked the build (scan-gate red)

1. Download the `scan-reports-<target>` artifacts; both trivy and grype
   JSON are attached.
2. Triage each violating CVE:
   - **Fixable and relevant** → bump the base image
     (`python:3.12-alpine3.21` → newer tag) or the dependency version in
     `requirements.txt`. Re-run. This is the normal, happy path.
   - **Fixable, not reachable** (e.g. a library the app never imports) →
     allowlist entry with a written reason **and** an expiry date, then a
     PR that a second person reviews. See `policy/README.md`.
   - **No fix available** → the default policy already ignores unfixed
     findings (`ignore_unfixed: true`); if you tightened that, decide
     explicitly whether to relax the rule or accept the block.
3. Prefer fixing over allowlisting. An allowlist entry is a promise to
   remove the CVE before the expiry date.

## 3. The self-test went red (gate-selftest job)

The policy engine itself disagrees with the fixtures. Do not touch the
policy file to make the test pass; first decide who is right — the fixture
or the engine — and align the other one. A wrong verdict in either
direction (false PASS or false BLOCK) is a security incident in this
repo's terms.

## 4. The vulnerable-image leg failed

Two possible meanings:

- **It returned PASS** — the gate failed to block a rotten image. Stop
  and treat this as a broken control: check what changed in
  `policy_gate.py` or `policy/scan-policy.yml`.
- **It returned BLOCK as expected but exited wrong** — an expectation
  wiring bug (`--expect BLOCK` missing on the job). Fix the workflow.

## 5. Nightly issue: "shipped image no longer meets policy"

The image in the registry drifted out of policy — typically a new CVE
with a fix appeared. Steps:

1. Confirm the finding in the issue body (it embeds the full gate table).
2. Bump the base image and let the pipeline push + sign a new release.
3. Confirm the issue: the next nightly run posts a fresh PASS summary.
   Close the issue only after a PASS run, never by hand-waving.

## 6. Verifying a deploy target before release

Before any environment pulls the image, verify the signature against this
pipeline's identity — one command, no trust in whoever pushed it:

```bash
docker pull ghcr.io/abdrahmentakrouni/secure-ci-pipeline:latest
bash scripts/verify_signature.sh
```

It resolves the tag to a digest, checks the Fulcio certificate identity
against this repository's workflow, and validates the SPDX attestation.
Anything that fails this check never reaches a cluster.
