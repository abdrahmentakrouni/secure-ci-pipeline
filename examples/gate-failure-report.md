# Example — a blocked build

This is the step summary produced when the gate scans the
`app-vulnerable` image (an end-of-life `python:3.8-slim` base with
`flask==0.12.2`, `jinja2==2.10` and `requests==2.19.1`). The job is green
in CI because the pipeline asserts this verdict — the gate is doing its
job. Numbers below are from a representative run; CVE counts move as
databases update.

---

## Security gate — `app-vulnerable:ci`

policy: `release-gate-default` · scanners: trivy, grype · unique findings: 87

| severity | findings |
|---|---|
| CRITICAL | 9 |
| HIGH | 41 |
| MEDIUM | 30 |
| LOW | 7 |

### violations

| CVE | severity | fix available | rule |
|---|---|---|---|
| CVE-2023-44487 | CRITICAL | yes | CRITICAL fixed (max_allowed=0, found=9) |
| CVE-2024-45490 | CRITICAL | yes | CRITICAL fixed (max_allowed=0, found=9) |
| CVE-2023-0286 | HIGH | yes | HIGH fixed (max_allowed=5, found=41) |
| CVE-2019-10906 | HIGH | yes | HIGH fixed (max_allowed=5, found=41) |
| CVE-2018-1000656 | HIGH | yes | HIGH fixed (max_allowed=5, found=41) |
| … | | | … and 79 more |

**verdict: BLOCK**

---

The pipeline exits non-zero here, the `ship` job never starts, and no
image reaches the registry. The same report for the `app` release image
reads the opposite way: zero CRITICAL, verdict **PASS**, proceed to
signing.
