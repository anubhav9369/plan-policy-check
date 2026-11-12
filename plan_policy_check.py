"""Check an InspectablePlan against a policy pack before it may execute.

A plan is only allowed to run after it passes its checks *and* a human
has approved it (see
`plan-approve <https://github.com/anubhav9369/plan-approve>`_). This
module is the checks half: it runs a policy pack — security, privacy,
org and ethics rules — over a plan and reports every violation with its
severity, so a risky plan is blocked before anything happens instead of
after.

A policy pack is JSON:

.. code-block:: json

    {
      "name": "default",
      "rules": [
        {"id": "SEC-01", "category": "security", "severity": "high",
         "check": "external-send-gated",
         "description": "Steps that send outside the system must be gated."},
        {"id": "ORG-01", "category": "org", "severity": "medium",
         "check": "spend-limit", "max_amount": 0,
         "description": "No step may spend money unless the policy allows it."}
      ]
    }

Checks are small, named functions. A rule names its check and any
parameters it needs (``max_amount`` for ``spend-limit``). An unknown
check name is an error, not a silent pass — a policy that cannot be
evaluated must not look like a clean bill of health.

Verdict: ``blocked`` when any high-severity rule fails (execution must
not proceed), ``review`` when only medium/low rules fail, ``pass`` when
nothing fails. Exit codes match: 0 pass, 1 blocked, 2 review.
"""

import argparse
import json
import re
import sys

SEND_WORDS = ("send", "email", "mail", "publish", "post", "share",
              "message", "forward")
IRREVERSIBLE_WORDS = ("delete", "remove", "pay", "purchase", "buy",
                      "subscribe", "publish", "send", "email")
PII_WORDS = ("personal data", "personal email", "email address", "phone",
             "address", "bank", "password", "passport", "date of birth")
SPEND_WORDS = ("pay", "purchase", "buy", "spend", "subscribe")
AMOUNT_RE = re.compile(r"\$(\d+(?:\.\d{1,2})?)")

SEVERITIES = ("high", "medium", "low")


def _contains(action, words):
    lowered = action.lower()
    return [w for w in words if w in lowered]


def _finding(rule, step, message):
    return {
        "rule_id": rule["id"],
        "category": rule["category"],
        "severity": rule["severity"],
        "step": step["id"] if step else None,
        "message": message,
    }


def _check_external_send_gated(rule, plan, decisions):
    findings = []
    for step in plan.get("steps", []):
        if _contains(step.get("action", ""), SEND_WORDS) \
                and not step.get("needs_permission"):
            findings.append(_finding(
                rule, step,
                f"Step {step['id']} sends outside the system but is not "
                "permission-gated."))
    return findings


def _check_irreversible_gated(rule, plan, decisions):
    findings = []
    for step in plan.get("steps", []):
        if _contains(step.get("action", ""), IRREVERSIBLE_WORDS) \
                and not step.get("needs_permission"):
            findings.append(_finding(
                rule, step,
                f"Step {step['id']} is irreversible but is not "
                "permission-gated."))
    return findings


def _check_no_pii_outbound(rule, plan, decisions):
    findings = []
    for step in plan.get("steps", []):
        action = step.get("action", "")
        if _contains(action, PII_WORDS) \
                and _contains(action, SEND_WORDS) \
                and not step.get("needs_permission"):
            findings.append(_finding(
                rule, step,
                f"Step {step['id']} moves personal data outside the system "
                "without a permission gate."))
    return findings


def _check_spend_limit(rule, plan, decisions):
    limit = rule.get("max_amount", 0)
    findings = []
    for step in plan.get("steps", []):
        action = step.get("action", "")
        if not _contains(action, SPEND_WORDS):
            continue
        amounts = AMOUNT_RE.findall(action)
        if not amounts:
            findings.append(_finding(
                rule, step,
                f"Step {step['id']} spends money but states no amount, so "
                "the spend cannot be checked against the limit."))
        elif float(amounts[0]) > limit:
            findings.append(_finding(
                rule, step,
                f"Step {step['id']} spends ${amounts[0]}, over the policy "
                f"limit of ${limit}."))
    return findings


def _check_every_step_has_why(rule, plan, decisions):
    findings = []
    for step in plan.get("steps", []):
        if not (step.get("why") or "").strip():
            findings.append(_finding(
                rule, step,
                f"Step {step['id']} states no reason for existing."))
    return findings


def _check_plan_has_constraints(rule, plan, decisions):
    if not plan.get("constraints"):
        return [_finding(rule, None,
                         "The plan states no constraints on what it may do.")]
    return []


def _check_approved_decision(rule, plan, decisions):
    if decisions is None:
        return None  # skipped: nothing to check against
    mine = [d for d in decisions if d.get("plan_id") == plan.get("id")]
    if not mine:
        return [_finding(rule, None,
                         "No approval record exists for this plan.")]
    latest = mine[-1]
    if latest.get("decision") != "approved":
        return [_finding(
            rule, None,
            f"Latest decision is '{latest.get('decision')}', not "
            "'approved'.")]
    return []


CHECKS = {
    "external-send-gated": _check_external_send_gated,
    "irreversible-gated": _check_irreversible_gated,
    "no-pii-outbound": _check_no_pii_outbound,
    "spend-limit": _check_spend_limit,
    "every-step-has-why": _check_every_step_has_why,
    "plan-has-constraints": _check_plan_has_constraints,
    "approved-decision": _check_approved_decision,
}


def check_plan(plan, policy, decisions=None):
    """Run every rule in *policy* over *plan*.

    *decisions* is a list of decision records (as written by
    plan-approve) or None, in which case the ``approved-decision``
    rule is reported as skipped rather than passed.
    """
    findings, skipped = [], []
    for rule in policy.get("rules", []):
        check = CHECKS.get(rule.get("check"))
        if check is None:
            raise ValueError(f"unknown check: {rule.get('check')!r}")
        result = check(rule, plan, decisions)
        if result is None:
            skipped.append({"rule_id": rule["id"],
                            "reason": "no decisions log supplied"})
        else:
            findings.extend(result)
    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in SEVERITIES}
    if counts["high"]:
        verdict = "blocked"
    elif counts["medium"] or counts["low"]:
        verdict = "review"
    else:
        verdict = "pass"
    return {
        "plan_id": plan.get("id"),
        "plan_version": plan.get("version"),
        "policy": policy.get("name"),
        "verdict": verdict,
        "findings": findings,
        "skipped": skipped,
        "summary": counts,
    }


def render_markdown(report):
    lines = [f"# Policy check: {report['plan_id']} v{report['plan_version']}",
             "",
             f"Policy: {report['policy']} — **verdict: {report['verdict']}**",
             "",
             "Findings: "
             + ", ".join(f"{sev} {report['summary'][sev]}"
                         for sev in SEVERITIES),
             ""]
    if report["findings"]:
        for f in report["findings"]:
            where = f"step {f['step']}" if f["step"] else "plan"
            lines.append(f"- [{f['severity']}] {f['rule_id']} "
                         f"({f['category']}, {where}): {f['message']}")
    else:
        lines.append("No findings — the plan passes every evaluated rule.")
    if report["skipped"]:
        lines.append("")
        for s in report["skipped"]:
            lines.append(f"- Skipped {s['rule_id']}: {s['reason']}.")
    return "\n".join(lines) + "\n"


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_log(path):
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check an InspectablePlan against a policy pack.")
    parser.add_argument("plan", help="plan JSON file")
    parser.add_argument("policy", help="policy pack JSON file")
    parser.add_argument("--decisions",
                        help="JSONL decisions log (from plan-approve)")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--out", help="write the report to this file")
    args = parser.parse_args(argv)

    plan = read_json(args.plan)
    policy = read_json(args.policy)
    decisions = read_log(args.decisions) if args.decisions else None
    report = check_plan(plan, policy, decisions)

    text = json.dumps(report, indent=2) if args.json \
        else render_markdown(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
    print(text, end="" if text.endswith("\n") else "\n")
    return {"pass": 0, "blocked": 1, "review": 2}[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
