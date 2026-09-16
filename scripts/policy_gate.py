#!/usr/bin/env python3
"""Policy-as-code gate for container vulnerability scans.

Reads Trivy and Grype JSON reports, applies policy/scan-policy.yml and
decides whether the build ships. Emits a Markdown verdict table (into
$GITHUB_STEP_SUMMARY when present) so every CI run shows what blocked it.

Exit codes:
  0  verdict matches the expectation (PASS/BLOCK as requested)
  2  verdict is BLOCK and no expectation was set (local gate mode)
  3  verdict did not match --expect
  4  bad input: unreadable report or policy

Usage:
  policy_gate.py --trivy trivy.json --grype grype.json \\
      --policy policy/scan-policy.yml --image app:ci [--expect PASS]
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]


def fail(msg, code=4):
    print(f"[policy-gate] error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        import subprocess
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--user", "pyyaml"],
            check=True,
        )
        import yaml
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        fail(f"policy file not found: {path}")
    except yaml.YAMLError as exc:
        fail(f"cannot parse policy: {exc}")
    return data


def _merge(findings, vid, severity, fixed):
    """Keep the more severe report when both scanners saw the same CVE."""
    current = findings.get(vid)
    if current is None:
        findings[vid] = {"severity": severity, "fixed": fixed}
        return
    if severity in SEVERITIES and current["severity"] in SEVERITIES:
        if SEVERITIES.index(severity) < SEVERITIES.index(current["severity"]):
            current["severity"] = severity
    current["fixed"] = current["fixed"] or fixed


def load_trivy(path):
    """Map CVE -> {severity, fixed} from a Trivy JSON report."""
    findings = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        fail(f"cannot read trivy report {path}: {exc}")
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vid = vuln.get("VulnerabilityID") or "UNKNOWN"
            severity = (vuln.get("Severity") or "UNKNOWN").upper()
            if severity not in SEVERITIES:
                severity = "UNKNOWN"
            _merge(findings, vid, severity, bool(vuln.get("FixedVersion")))
    return findings


def load_grype(path):
    """Map CVE -> {severity, fixed} from a Grype JSON report."""
    findings = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        fail(f"cannot read grype report {path}: {exc}")
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        vid = vuln.get("id") or "UNKNOWN"
        severity = (vuln.get("severity") or "UNKNOWN").upper()
        if severity not in SEVERITIES:
            severity = "UNKNOWN"
        fix = vuln.get("fix") or {}
        fixed = fix.get("state") == "fixed" or bool(fix.get("versions"))
        _merge(findings, vid, severity, fixed)
    return findings


def active_allowlist(gate):
    """CVE ids whose acceptance has not expired yet."""
    today = datetime.date.today()
    active = {}
    for entry in gate.get("allowlist") or []:
        cid = entry.get("id")
        if not cid:
            continue
        expires = str(entry.get("expires", "")).strip()
        try:
            expired = bool(expires) and datetime.date.fromisoformat(expires) < today
        except ValueError:
            # an unparsable expiry can never be trusted to suppress a CVE
            expired = True
        if not expired:
            active[cid] = entry
    return active


def rule_matches(rule, severity, fixed):
    if str(rule.get("severity", "")).upper() != severity:
        return False
    if rule.get("fixed", False) and not fixed:
        return False
    return True


def evaluate(policy, findings, allow):
    """Apply block/warn rules; return (verdict, violations, warnings, counts)."""
    gate = policy.get("gate") or {}
    ignore_unfixed = bool(gate.get("ignore_unfixed", True))

    counts = {s: 0 for s in SEVERITIES}
    for info in findings.values():
        if info["severity"] in counts:
            counts[info["severity"]] += 1

    # first matching block rule per finding wins
    hit_sets = [[] for _ in (gate.get("block") or [])]
    warn_ids = []
    for vid, info in sorted(findings.items()):
        severity, fixed = info["severity"], info["fixed"]
        if vid in allow:
            continue
        if ignore_unfixed and not fixed:
            continue
        for idx, rule in enumerate(gate.get("block") or []):
            if rule_matches(rule, severity, fixed):
                hit_sets[idx].append(
                    {"id": vid, "severity": severity, "fixed": fixed}
                )
                break
        for rule in gate.get("warn") or []:
            if rule_matches(rule, severity, fixed):
                warn_ids.append(vid)
                break

    violations = []
    for rule, hits in zip(gate.get("block") or [], hit_sets):
        limit = int(rule.get("max_allowed", 0))
        if len(hits) > limit:
            label = (
                f"{rule.get('severity')} fixed"
                f" (max_allowed={limit}, found={len(hits)})"
            )
            for hit in hits:
                violations.append({**hit, "rule": label})

    warnings = sorted(set(warn_ids))
    verdict = "BLOCK" if violations else "PASS"
    return verdict, violations, warnings, counts


def render(policy, image, sources, n_findings, allow, violations, warnings, counts, verdict):
    name = policy.get("name", "unnamed policy")
    lines = [f"## Security gate — `{image}`", ""]
    lines.append(
        f"policy: `{name}` · scanners: {', '.join(sources)}"
        f" · unique findings: {n_findings}"
    )
    lines.append("")
    lines.append("| severity | findings |")
    lines.append("|---|---|")
    if any(counts.values()):
        for sev in SEVERITIES:
            if counts[sev]:
                lines.append(f"| {sev} | {counts[sev]} |")
    else:
        lines.append("| — | 0 |")
    lines.append("")
    if allow:
        ids = ", ".join(f"`{cid}`" for cid in sorted(allow))
        lines.append(f"accepted risks (allowlist active): {ids}")
        lines.append("")
    if violations:
        lines.append("### violations")
        lines.append("")
        lines.append("| CVE | severity | fix available | rule |")
        lines.append("|---|---|---|---|")
        for v in violations[:25]:
            fixed = "yes" if v["fixed"] else "no"
            lines.append(f"| {v['id']} | {v['severity']} | {fixed} | {v['rule']} |")
        if len(violations) > 25:
            lines.append(f"… and {len(violations) - 25} more")
        lines.append("")
    elif warnings:
        lines.append(f"warnings (non-blocking): {', '.join(warnings)}")
        lines.append("")
    lines.append(f"**verdict: {verdict}**")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="container vulnerability policy gate")
    parser.add_argument("--trivy", help="trivy JSON report")
    parser.add_argument("--grype", help="grype JSON report")
    parser.add_argument("--policy", required=True, help="policy YAML file")
    parser.add_argument("--image", required=True, help="image name for the report header")
    parser.add_argument("--expect", choices=["PASS", "BLOCK"],
                        help="assert the verdict (used by CI and the self-test)")
    parser.add_argument("--summary-file", help="write the markdown summary here")
    parser.add_argument("--verdict-file", help="write PASS|BLOCK|ERROR here")
    parser.add_argument("--quiet", action="store_true", help="suppress the stdout report")
    args = parser.parse_args()

    if not args.trivy and not args.grype:
        fail("need at least one of --trivy / --grype")

    # optimistic default: if the gate itself crashes, the verdict file says
    # ERROR so a nightly rescan never silently reports "all clear"
    if args.verdict_file:
        with open(args.verdict_file, "w", encoding="utf-8") as fh:
            fh.write("ERROR\n")

    policy = load_yaml(args.policy)

    findings = {}
    if args.trivy:
        for vid, info in load_trivy(args.trivy).items():
            _merge(findings, vid, info["severity"], info["fixed"])
    if args.grype:
        for vid, info in load_grype(args.grype).items():
            _merge(findings, vid, info["severity"], info["fixed"])

    allow = active_allowlist(policy.get("gate") or {})
    verdict, violations, warnings, counts = evaluate(policy, findings, allow)

    sources = [s for s, p in (("trivy", args.trivy), ("grype", args.grype)) if p]
    report = render(policy, args.image, sources, len(findings),
                    allow, violations, warnings, counts, verdict)

    if not args.quiet:
        print(report)
    summary_target = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_target:
        with open(summary_target, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    if args.summary_file:
        with open(args.summary_file, "w", encoding="utf-8") as fh:
            fh.write(report)
    if args.verdict_file:
        with open(args.verdict_file, "w", encoding="utf-8") as fh:
            fh.write(verdict + "\n")

    if args.expect:
        if verdict != args.expect:
            print(f"[policy-gate] expectation mismatch: expected {args.expect}, got {verdict}")
            sys.exit(3)
        sys.exit(0)
    if verdict == "BLOCK":
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
