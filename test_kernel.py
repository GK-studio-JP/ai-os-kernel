import hashlib
import json
import unittest

from kernel import authorize, validate_dispatch

def signed_plan(value):
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    value["fingerprint"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return value


REGISTRY = {
    "schema": "ai-os-process-registry:v1",
    "processes": [
        {"id": "PROC-A", "repository": "owner/a", "capabilities": ["context.read", "ipc.send"]},
        {"id": "PROC-B", "repository": "owner/b", "capabilities": []},
        {
            "id": "PROC-BROWSER",
            "repository": "owner/browser",
            "capabilities": [],
            "routing": {"target_mode": "registered-process-repository"},
        },
    ],
}


class KernelTests(unittest.TestCase):
    def test_authorize_capability(self):
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-1",
            "caller": {"process": "PROC-A"},
            "operation": "request_context",
        }
        result = authorize(REGISTRY, syscall)
        self.assertEqual(result["decision"], "APPROVED")
        self.assertTrue(result["persist_required"])

    def test_deny_missing_capability(self):
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-2",
            "caller": {"process": "PROC-B"},
            "operation": "send_message",
        }
        result = authorize(REGISTRY, syscall)
        self.assertEqual(result["decision"], "DENIED")
        self.assertEqual(result["reason_code"], "missing_capability")

    def test_dynamic_capability_escalates(self):
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-3",
            "caller": {"process": "PROC-A"},
            "operation": "request_capability",
        }
        self.assertEqual(authorize(REGISTRY, syscall)["decision"], "ESCALATE")

    def test_validate_dispatch(self):
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#1",
                    "process": "PROC-A",
                    "target_repository": "owner/a",
                }
            ],
        })
        result = validate_dispatch(REGISTRY, plan)
        self.assertTrue(result["valid"])

    def test_tampered_plan_fingerprint_fails(self):
        plan = signed_plan(
            {
                "schema": "ai-os-dispatch-plan:v1",
                "authoritative": False,
                "dispatches": [
                    {
                        "schema": "ai-os-dispatch:v1",
                        "authoritative": False,
                        "task": "#1",
                        "process": "PROC-A",
                        "target_repository": "owner/a",
                    }
                ],
            }
        )
        plan["dispatches"][0]["task"] = "#999"
        result = validate_dispatch(REGISTRY, plan)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(error["code"] == "plan_fingerprint_mismatch" for error in result["errors"])
        )

    def test_dispatch_repo_mismatch_fails(self):
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#1",
                    "process": "PROC-A",
                    "target_repository": "owner/wrong",
                }
            ],
        })
        result = validate_dispatch(REGISTRY, plan)
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "target_repository_mismatch")

    def test_runtime_process_can_target_registered_repo(self):
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#2",
                    "process": "PROC-BROWSER",
                    "target_repository": "owner/a",
                }
            ],
        })
        result = validate_dispatch(REGISTRY, plan)
        self.assertTrue(result["valid"])

    def test_runtime_process_rejects_unregistered_repo(self):
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#2",
                    "process": "PROC-BROWSER",
                    "target_repository": "owner/external",
                }
            ],
        })
        result = validate_dispatch(REGISTRY, plan)
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "target_repository_unregistered")


if __name__ == "__main__":
    unittest.main()
