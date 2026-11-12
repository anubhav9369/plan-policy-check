# plan-policy-check

A plan is only allowed to run after it passes its checks *and* a human
has approved it. This is the checks half: validate an InspectablePlan
against a policy pack — security, privacy, org and ethics rules — and
block the plan before anything happens instead of after.

Part of Week 3 (policy validation) of the trustworthy-agentic-ai
prototype for **BRJP26100123 — Building Trustworthy AI Systems through
Explainability and Human-in-the-Loop Control**. Companion repos:
[trustworthy-agentic-ai](https://github.com/anubhav9369/trustworthy-agentic-ai)
(the InspectablePlan schema),
[plan-explainer](https://github.com/anubhav9369/plan-explainer)
(plain-language rendering + review checklist),
[plan-diff](https://github.com/anubhav9369/plan-diff)
(what changed between two plan versions),
[plan-risk-scan](https://github.com/anubhav9369/plan-risk-scan)
(what needs a human's attention before approval),
[plan-approve](https://github.com/anubhav9369/plan-approve)
(the human decision point), and
[plan-refine](https://github.com/anubhav9369/plan-refine)
(applying the human's requested changes).

## The rules

| Rule | What it stops |
| --- | --- |
| A rule that cannot be evaluated is an error, never a pass | A policy that looks clean because it was never really checked |
| A high-severity failure blocks execution | A risky plan running because a human missed one step |
| A rule that needs a decisions log is skipped, not passed, when none is supplied | Treating "no approval record" as "approved" |
| The verdict is derived from the findings, never set by hand | A plan marked "pass" with violations still in it |

## The default policy pack

`examples/policy.json` — seven rules in four categories:

| ID | Category | Severity | Check |
| --- | --- | --- | --- |
| SEC-01 | security | high | Steps that send outside the system must be permission-gated |
| SEC-02 | security | high | Irreversible steps (delete, pay, publish, send) must be permission-gated |
| SEC-03 | security | high | The latest recorded decision for this plan must be `approved` |
| PRI-01 | privacy | high | Steps moving personal data outside the system must be permission-gated |
| ORG-01 | org | medium | No step may spend money (default limit $0) |
| ETH-01 | ethics | medium | Every step must state why it exists |
| ETH-02 | ethics | low | The plan must state at least one constraint |

A policy pack is plain JSON, so a team can add its own rules without
touching the code — add a rule object with an `id`, `category`,
`severity`, `check` and `description`; `spend-limit` also takes
`max_amount`.

## Usage

```bash
python3 plan_policy_check.py examples/plan.json examples/policy.json
```

The example plan is blocked: 4 high findings (the ungated email step
sends personal data out, and the $49 subscription is an ungated,
irreversible spend) and 1 medium. The approval rule is reported as
skipped — no decisions log was supplied.

```bash
python3 plan_policy_check.py examples/clean-plan.json examples/policy.json \
  --decisions examples/decisions.jsonl
```

The clean plan passes every rule, including the approval check, and
exits 0. Exit codes: 0 pass, 1 blocked, 2 review (medium/low findings
only). `--json` prints the report as JSON; `--out report.json` writes
it to a file.

Python API:

```python
from plan_policy_check import check_plan, read_json, read_log

report = check_plan(read_json("examples/plan.json"),
                    read_json("examples/policy.json"),
                    decisions=read_log("examples/decisions.jsonl"))
report["verdict"]  # "blocked" | "review" | "pass"
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

9 tests, all passing.
