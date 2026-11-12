"""Tests for plan_policy_check — 9 tests, stdlib unittest only."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plan_policy_check import check_plan  # noqa: E402

POLICY = {"name": "test", "rules": [
    {"id": "SEC-01", "category": "security", "severity": "high",
     "check": "external-send-gated", "description": ""},
    {"id": "SEC-02", "category": "security", "severity": "high",
     "check": "irreversible-gated", "description": ""},
    {"id": "SEC-03", "category": "security", "severity": "high",
     "check": "approved-decision", "description": ""},
    {"id": "PRI-01", "category": "privacy", "severity": "high",
     "check": "no-pii-outbound", "description": ""},
    {"id": "ORG-01", "category": "org", "severity": "medium",
     "check": "spend-limit", "max_amount": 10, "description": ""},
    {"id": "ETH-01", "category": "ethics", "severity": "medium",
     "check": "every-step-has-why", "description": ""},
    {"id": "ETH-02", "category": "ethics", "severity": "low",
     "check": "plan-has-constraints", "description": ""},
]}

BASE = {
    "id": "summarise-paper",
    "version": 1,
    "goal": "Summarise this paper and email the summary to me by 6 PM today",
    "assumptions": ["The goal is complete."],
    "constraints": ["Nothing leaves the system before approval."],
    "risks": ["Wrong recipient."],
    "steps": [
        {"id": "step-1", "action": "Restate the goal.",
         "why": "Avoid acting on a misread goal.", "needs_permission": False,
         "failure_points": [], "alternatives_considered": []},
    ],
}

APPROVED = [{"plan_id": "summarise-paper", "plan_version": "1",
             "decision": "approved", "reviewer": "Anubhav",
             "reason": "Looks safe."}]


def plan():
    return copy.deepcopy(BASE)


def step(step_id, action, gated=False, why="A reason."):
    return {"id": step_id, "action": action, "why": why,
            "needs_permission": gated, "failure_points": [],
            "alternatives_considered": []}


def rule_ids(report):
    return [f["rule_id"] for f in report["findings"]]


class TestPolicyCheck(unittest.TestCase):
    def test_ungated_external_send_fails(self):
        p = plan()
        p["steps"].append(step("step-2", "Send the summary immediately."))
        report = check_plan(p, POLICY, decisions=APPROVED)
        self.assertIn("SEC-01", rule_ids(report))
        self.assertEqual(report["verdict"], "blocked")

    def test_gated_external_send_passes(self):
        p = plan()
        p["steps"].append(step("step-2", "Send the summary after approval.",
                               gated=True))
        report = check_plan(p, POLICY, decisions=APPROVED)
        self.assertNotIn("SEC-01", rule_ids(report))
        self.assertNotIn("SEC-02", rule_ids(report))
        self.assertEqual(report["verdict"], "pass")

    def test_ungated_irreversible_fails(self):
        p = plan()
        p["steps"].append(step("step-2", "Delete the draft copy."))
        report = check_plan(p, POLICY, decisions=APPROVED)
        self.assertIn("SEC-02", rule_ids(report))
        self.assertEqual(report["summary"]["high"], 1)

    def test_pii_outbound_requires_gate(self):
        p = plan()
        p["steps"].append(step(
            "step-2",
            "Email the summary with the author's personal email address."))
        self.assertIn("PRI-01", rule_ids(check_plan(p, POLICY,
                                                    decisions=APPROVED)))
        gated = plan()
        gated["steps"].append(step(
            "step-2",
            "Email the summary with the author's personal email address.",
            gated=True))
        self.assertNotIn("PRI-01", rule_ids(check_plan(gated, POLICY,
                                                       decisions=APPROVED)))

    def test_spend_limit(self):
        over = plan()
        over["steps"].append(step("step-2", "Pay $49 for the premium tool."))
        self.assertIn("ORG-01", rule_ids(check_plan(over, POLICY,
                                                    decisions=APPROVED)))
        under = plan()
        under["steps"].append(step("step-2", "Pay $5 for the premium tool."))
        self.assertNotIn("ORG-01", rule_ids(check_plan(under, POLICY,
                                                       decisions=APPROVED)))
        unbounded = plan()
        unbounded["steps"].append(step("step-2", "Subscribe to the tool."))
        report = check_plan(unbounded, POLICY, decisions=APPROVED)
        self.assertIn("ORG-01", rule_ids(report))
        self.assertIn("no amount", report["findings"][-1]["message"])

    def test_step_without_why_fails(self):
        p = plan()
        p["steps"].append(step("step-2", "Restate the goal again.", why=""))
        report = check_plan(p, POLICY, decisions=APPROVED)
        self.assertIn("ETH-01", rule_ids(report))
        self.assertEqual(report["verdict"], "review")

    def test_plan_without_constraints_fails(self):
        p = plan()
        p["constraints"] = []
        report = check_plan(p, POLICY, decisions=APPROVED)
        self.assertIn("ETH-02", rule_ids(report))
        self.assertEqual(report["verdict"], "review")

    def test_verdict_levels(self):
        clean = check_plan(plan(), POLICY, decisions=APPROVED)
        self.assertEqual(clean["verdict"], "pass")
        self.assertEqual(clean["summary"], {"high": 0, "medium": 0,
                                            "low": 0})
        medium_only = plan()
        medium_only["steps"].append(
            step("step-2", "Restate the goal again.", why=""))
        self.assertEqual(check_plan(medium_only, POLICY,
                                   decisions=APPROVED)["verdict"], "review")
        blocked = plan()
        blocked["steps"].append(step("step-2", "Send the summary now."))
        self.assertEqual(check_plan(blocked, POLICY,
                                   decisions=APPROVED)["verdict"], "blocked")

    def test_approved_decision_rule(self):
        p = plan()
        no_log = check_plan(p, POLICY)
        self.assertEqual(no_log["skipped"][0]["rule_id"], "SEC-03")
        self.assertNotIn("SEC-03", rule_ids(no_log))
        self.assertEqual(check_plan(p, POLICY,
                                   decisions=APPROVED)["verdict"], "pass")
        sent_back = [{"plan_id": "summarise-paper", "plan_version": "1",
                      "decision": "request-changes", "reviewer": "Anubhav",
                      "reason": "Gate the send step."}]
        report = check_plan(p, POLICY, decisions=sent_back)
        self.assertIn("SEC-03", rule_ids(report))
        self.assertEqual(report["verdict"], "blocked")
        other_plan = [{"plan_id": "other-plan", "plan_version": "1",
                       "decision": "approved", "reviewer": "Anubhav",
                       "reason": "Fine."}]
        self.assertIn("SEC-03", rule_ids(check_plan(p, POLICY,
                                                    decisions=other_plan)))


if __name__ == "__main__":
    unittest.main()
