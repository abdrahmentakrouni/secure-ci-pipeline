# Policy directory

`scan-policy.yml` is the only file the release gate obeys. If the build
was blocked or allowed, it was this file that decided it.

## Keys

| key | meaning |
|-----|---------|
| `gate.block[]` | rules that fail the build. Each needs a `severity`, optionally `fixed: true` (only findings with an upstream fix count) and `max_allowed` (risk appetite, default 0) |
| `gate.warn[]` | findings reported in the summary but not enforced |
| `gate.ignore_unfixed` | findings without any available fix are tracked, not fatal |
| `gate.allowlist[]` | accepted risks: `id`, written `reason`, `expires` date |

## Adding an allowlist entry

Allowlists are for *accepted, explained* risk — not for silencing noise.
Every entry needs a reason a reviewer can judge and an expiry date after
which the CVE blocks again automatically:

```yaml
allowlist:
  - id: CVE-2024-21538
    reason: "regex DoS in transitive dep, code path unreachable from app"
    expires: 2026-12-31
```

The policy gate self-test (`scripts/test_policy_gate.sh`) covers exactly
this behaviour, including the expired-allowlist case. Changing this file
runs the full pipeline on the PR — a broken policy cannot reach main.
