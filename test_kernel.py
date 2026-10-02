import hashlib
import json
import unittest
from pathlib import Path

from kernel import authorize, authorize_dispatch_mutation, validate_dispatch

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
            "capabilities": ["repository.write.branch"],
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

    def test_dispatch_requires_target_repository(self):
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#2",
                    "process": "PROC-BROWSER",
                    "target_repository": "",
                }
            ],
        })
        result = validate_dispatch(REGISTRY, plan)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(error["code"] == "target_repository_required" for error in result["errors"])
        )

    def test_mutation_receipt_rejects_empty_repository_scope(self):
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#2",
                    "process": "PROC-BROWSER",
                    "target_repository": "",
                }
            ],
        })
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-MUT-EMPTY-REPO",
            "caller": {"process": "PROC-BROWSER"},
            "operation": "mutate_repository",
            "scope": {
                "task": "#2",
                "repository": "",
                "mode": "branch-pr",
            },
        }
        result = authorize_dispatch_mutation(REGISTRY, plan, syscall)
        self.assertFalse(result["approved"])
        self.assertTrue(
            any(error["code"] == "target_repository_required" for error in result["errors"])
        )

    def test_browser_mutation_receipt_binds_dispatch_scope(self):
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
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-MUT-1",
            "caller": {"process": "PROC-BROWSER"},
            "operation": "mutate_repository",
            "scope": {
                "task": "#2",
                "repository": "owner/a",
                "mode": "branch-pr",
            },
        }
        result = authorize_dispatch_mutation(REGISTRY, plan, syscall)
        self.assertTrue(result["approved"])
        self.assertEqual(result["required_capability"], "repository.write.branch")
        self.assertEqual(result["task"], "#2")
        self.assertEqual(result["target_repository"], "owner/a")
        self.assertTrue(result["constraints"]["forbid_direct_main_commit"])
        self.assertTrue(result["constraints"]["require_pull_request"])
        self.assertTrue(result["fingerprint"].startswith("sha256:"))

    def test_browser_mutation_receipt_rejects_scope_mismatch(self):
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
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-MUT-2",
            "caller": {"process": "PROC-BROWSER"},
            "operation": "mutate_repository",
            "scope": {
                "task": "#2",
                "repository": "owner/b",
                "mode": "branch-pr",
            },
        }
        result = authorize_dispatch_mutation(REGISTRY, plan, syscall)
        self.assertFalse(result["approved"])
        self.assertTrue(
            any(error["code"] == "repository_scope_mismatch" for error in result["errors"])
        )

    def test_browser_mutation_receipt_requires_capability(self):
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
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-MUT-3",
            "caller": {"process": "PROC-A"},
            "operation": "mutate_repository",
            "scope": {
                "task": "#1",
                "repository": "owner/a",
                "mode": "branch-pr",
            },
        }
        result = authorize_dispatch_mutation(REGISTRY, plan, syscall)
        self.assertFalse(result["approved"])
        self.assertTrue(
            any(error["code"] == "kernel_decision_not_approved" for error in result["errors"])
        )

    def test_explicit_repository_allowlist_accepts_listed_target(self):
        registry = {
            "schema": "ai-os-process-registry:v1",
            "processes": [
                {
                    "id": "PROC-AIOS",
                    "repository": "owner/control",
                    "capabilities": ["repository.write.branch"],
                    "routing": {
                        "target_mode": "explicit-repository-allowlist",
                        "target_repositories": ["owner/control", "owner/api"],
                    },
                }
            ],
        }
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#30",
                    "process": "PROC-AIOS",
                    "target_repository": "owner/api",
                }
            ],
        })
        self.assertTrue(validate_dispatch(registry, plan)["valid"])

    def test_explicit_repository_allowlist_rejects_unlisted_target(self):
        registry = {
            "schema": "ai-os-process-registry:v1",
            "processes": [
                {
                    "id": "PROC-AIOS",
                    "repository": "owner/control",
                    "capabilities": ["repository.write.branch"],
                    "routing": {
                        "target_mode": "explicit-repository-allowlist",
                        "target_repositories": ["owner/control", "owner/api"],
                    },
                }
            ],
        }
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#31",
                    "process": "PROC-AIOS",
                    "target_repository": "owner/external",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any(error["code"] == "target_repository_not_allowed" for error in result["errors"]))

    def test_explicit_repository_allowlist_fails_closed_when_malformed(self):
        registry = {
            "schema": "ai-os-process-registry:v1",
            "processes": [
                {
                    "id": "PROC-AIOS",
                    "repository": "owner/control",
                    "capabilities": ["repository.write.branch"],
                    "routing": {
                        "target_mode": "explicit-repository-allowlist",
                        "target_repositories": [],
                    },
                }
            ],
        }
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#32",
                    "process": "PROC-AIOS",
                    "target_repository": "owner/control",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any(error["code"] == "invalid_target_repository_allowlist" for error in result["errors"]))

    def test_production_registry_allows_aios_to_target_api(self):
        registry = json.loads(Path("registry/processes.json").read_text(encoding="utf-8"))
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#33",
                    "process": "PROC-AIOS",
                    "target_repository": "GK-studio-JP/ai-os-api",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertTrue(result["valid"], result["errors"])

    def test_production_registry_allows_aios_to_target_memory(self):
        registry = json.loads(Path("registry/processes.json").read_text(encoding="utf-8"))
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#35",
                    "process": "PROC-AIOS",
                    "target_repository": "GK-studio-JP/ai-os-memory",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertTrue(result["valid"], result["errors"])

    def test_production_registry_allows_aios_to_target_bulletin_board(self):
        registry = json.loads(Path("registry/processes.json").read_text(encoding="utf-8"))
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#36",
                    "process": "PROC-AIOS",
                    "target_repository": "GK-studio-JP/ai-bulletin-board",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertTrue(result["valid"], result["errors"])

    def test_production_registry_rejects_unlisted_aios_target(self):
        registry = json.loads(Path("registry/processes.json").read_text(encoding="utf-8"))
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#37",
                    "process": "PROC-AIOS",
                    "target_repository": "GK-studio-JP/not-allowed",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(
                error["code"] == "target_repository_not_allowed"
                for error in result["errors"]
            )
        )

    def test_production_registry_allows_aios_branch_pr_mutation(self):
        registry = json.loads(Path("registry/processes.json").read_text(encoding="utf-8"))
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#34",
                    "process": "PROC-AIOS",
                    "target_repository": "GK-studio-JP/ai-os-kernel",
                }
            ],
        })
        syscall = {
            "schema": "ai-os-syscall:v1",
            "id": "SYS-AIOS-MUT-1",
            "caller": {"process": "PROC-AIOS"},
            "operation": "mutate_repository",
            "scope": {
                "task": "#34",
                "repository": "GK-studio-JP/ai-os-kernel",
                "mode": "branch-pr",
            },
        }
        result = authorize_dispatch_mutation(registry, plan, syscall)
        self.assertTrue(result["approved"], result["errors"])
        self.assertTrue(result["constraints"]["require_pull_request"])

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


    def test_production_registry_allows_browser_worker_to_target_browser_agent(self):
        registry = json.loads(
            Path("registry/processes.json").read_text(encoding="utf-8")
        )
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#20",
                    "process": "PROC-RUNTIME-BROWSER-WORKER",
                    "target_repository": "GK-studio-JP/browser-agent",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertTrue(result["valid"], result["errors"])

    def test_production_registry_rejects_unregistered_browser_worker_target(self):
        registry = json.loads(
            Path("registry/processes.json").read_text(encoding="utf-8")
        )
        plan = signed_plan({
            "schema": "ai-os-dispatch-plan:v1",
            "authoritative": False,
            "dispatches": [
                {
                    "schema": "ai-os-dispatch:v1",
                    "authoritative": False,
                    "task": "#20",
                    "process": "PROC-RUNTIME-BROWSER-WORKER",
                    "target_repository": "GK-studio-JP/not-registered",
                }
            ],
        })
        result = validate_dispatch(registry, plan)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(
                error["code"] == "target_repository_unregistered"
                for error in result["errors"]
            )
        )


if __name__ == "__main__":
    unittest.main()
