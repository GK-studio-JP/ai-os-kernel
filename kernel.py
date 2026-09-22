from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

REGISTRY_SCHEMA = "ai-os-process-registry:v1"
SYSCALL_SCHEMA = "ai-os-syscall:v1"
DECISION_SCHEMA = "ai-os-kernel-decision:v1"
PLAN_SCHEMA = "ai-os-dispatch-plan:v1"
DISPATCH_SCHEMA = "ai-os-dispatch:v1"
VALIDATION_SCHEMA = "ai-os-kernel-dispatch-validation:v1"
RECEIPT_SCHEMA = "ai-os-kernel-capability-receipt:v1"

OP_CAPABILITY = {
    "spawn_task": "task.spawn",
    "request_context": "context.read",
    "send_message": "ipc.send",
    "publish_event": "event.publish",
    "commit_state": "state.commit",
    "mutate_repository": "repository.write.branch",
    "wait": None,
    "exit": None,
    "escalate": None,
}


def _read(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | None, value: Any) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def _fingerprint(value: dict[str, Any]) -> str:
    material = {key: item for key, item in value.items() if key != "fingerprint"}
    canonical = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _plan_fingerprint(plan: dict[str, Any]) -> str:
    return _fingerprint(plan)


def process_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if registry.get("schema") != REGISTRY_SCHEMA:
        raise ValueError(f"unsupported registry schema: {registry.get('schema')!r}")
    processes = registry.get("processes")
    if not isinstance(processes, list):
        raise ValueError("registry processes must be a list")
    result: dict[str, dict[str, Any]] = {}
    for process in processes:
        if not isinstance(process, dict) or not process.get("id"):
            raise ValueError("registry process entry is invalid")
        pid = str(process["id"])
        if pid in result:
            raise ValueError(f"duplicate process id: {pid}")
        caps = process.get("capabilities")
        if not isinstance(caps, list) or any(not isinstance(c, str) for c in caps):
            raise ValueError(f"invalid capabilities for process {pid}")
        result[pid] = process
    return result


def authorize(registry: dict[str, Any], syscall: dict[str, Any]) -> dict[str, Any]:
    processes = process_map(registry)
    if syscall.get("schema") != SYSCALL_SCHEMA:
        raise ValueError(f"unsupported syscall schema: {syscall.get('schema')!r}")
    syscall_id = syscall.get("id")
    caller = syscall.get("caller")
    operation = syscall.get("operation")
    if not syscall_id or not isinstance(caller, dict) or not caller.get("process") or not operation:
        raise ValueError("syscall id, caller.process, and operation are required")

    process_id = str(caller["process"])
    process = processes.get(process_id)
    base = {
        "schema": DECISION_SCHEMA,
        "authoritative": False,
        "persist_required": True,
        "syscall": syscall_id,
        "caller": process_id,
        "operation": operation,
    }
    if process is None:
        return {**base, "decision": "DENIED", "reason_code": "unknown_process", "required_capability": None}

    if operation == "request_capability":
        return {
            **base,
            "decision": "ESCALATE",
            "reason_code": "dynamic_capability_grant_requires_policy",
            "required_capability": None,
        }

    if operation not in OP_CAPABILITY:
        return {**base, "decision": "DENIED", "reason_code": "unknown_operation", "required_capability": None}

    required = OP_CAPABILITY[operation]
    capabilities = set(process.get("capabilities") or [])
    if required is not None and required not in capabilities:
        return {
            **base,
            "decision": "DENIED",
            "reason_code": "missing_capability",
            "required_capability": required,
        }
    return {**base, "decision": "APPROVED", "reason_code": "policy_match", "required_capability": required}


def validate_dispatch(registry: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    processes = process_map(registry)
    errors: list[dict[str, Any]] = []
    if plan.get("schema") != PLAN_SCHEMA:
        errors.append({"code": "unsupported_plan_schema", "value": plan.get("schema")})
    if plan.get("authoritative") is not False:
        errors.append({"code": "dispatch_plan_must_be_non_authoritative"})

    supplied_fingerprint = plan.get("fingerprint")
    expected_fingerprint = _plan_fingerprint(plan)
    if supplied_fingerprint != expected_fingerprint:
        errors.append(
            {
                "code": "plan_fingerprint_mismatch",
                "expected": expected_fingerprint,
                "actual": supplied_fingerprint,
            }
        )

    dispatches = plan.get("dispatches")
    if not isinstance(dispatches, list):
        errors.append({"code": "dispatches_must_be_list"})
        dispatches = []

    for index, dispatch in enumerate(dispatches):
        if not isinstance(dispatch, dict):
            errors.append({"code": "invalid_dispatch", "index": index})
            continue
        if dispatch.get("schema") != DISPATCH_SCHEMA:
            errors.append({"code": "unsupported_dispatch_schema", "index": index, "value": dispatch.get("schema")})
        if dispatch.get("authoritative") is not False:
            errors.append({"code": "dispatch_must_be_non_authoritative", "index": index})
        process_id = dispatch.get("process")
        process = processes.get(str(process_id)) if process_id else None
        if process is None:
            errors.append({"code": "unknown_target_process", "index": index, "process": process_id})
            continue
        expected_repo = process.get("repository")
        raw_target_repo = dispatch.get("target_repository")
        target_repo = raw_target_repo.strip() if isinstance(raw_target_repo, str) else ""
        routing = process.get("routing") or {}
        target_mode = routing.get("target_mode", "self")

        if not target_repo:
            errors.append(
                {
                    "code": "target_repository_required",
                    "index": index,
                    "process": process_id,
                    "actual": raw_target_repo,
                }
            )
        elif target_mode == "self":
            if expected_repo and target_repo != expected_repo:
                errors.append(
                    {
                        "code": "target_repository_mismatch",
                        "index": index,
                        "process": process_id,
                        "expected": expected_repo,
                        "actual": target_repo,
                    }
                )
        elif target_mode == "registered-process-repository":
            registered_repositories = {
                value.get("repository")
                for value in processes.values()
                if value.get("repository")
            }
            if target_repo not in registered_repositories:
                errors.append(
                    {
                        "code": "target_repository_unregistered",
                        "index": index,
                        "process": process_id,
                        "actual": target_repo,
                    }
                )
        else:
            errors.append(
                {
                    "code": "unsupported_target_mode",
                    "index": index,
                    "process": process_id,
                    "target_mode": target_mode,
                }
            )

    return {
        "schema": VALIDATION_SCHEMA,
        "authoritative": False,
        "persist_required": True,
        "valid": not errors,
        "dispatch_count": len(dispatches),
        "errors": errors,
        "source_plan_fingerprint": plan.get("fingerprint"),
    }


def authorize_dispatch_mutation(
    registry: dict[str, Any],
    plan: dict[str, Any],
    syscall: dict[str, Any],
) -> dict[str, Any]:
    validation = validate_dispatch(registry, plan)
    decision = authorize(registry, syscall)
    errors: list[dict[str, Any]] = []

    if not validation["valid"]:
        errors.append({"code": "dispatch_validation_failed", "details": validation["errors"]})

    dispatches = plan.get("dispatches")
    if not isinstance(dispatches, list) or len(dispatches) != 1:
        errors.append({"code": "exactly_one_dispatch_required"})
        dispatch: dict[str, Any] = {}
    else:
        dispatch = dispatches[0] if isinstance(dispatches[0], dict) else {}
        if not dispatch:
            errors.append({"code": "invalid_dispatch"})

    if syscall.get("operation") != "mutate_repository":
        errors.append({"code": "mutation_operation_required"})
    if decision.get("decision") != "APPROVED":
        errors.append(
            {
                "code": "kernel_decision_not_approved",
                "decision": decision.get("decision"),
                "reason_code": decision.get("reason_code"),
            }
        )

    caller = str((syscall.get("caller") or {}).get("process") or "")
    if dispatch and caller != str(dispatch.get("process") or ""):
        errors.append(
            {
                "code": "caller_process_mismatch",
                "expected": dispatch.get("process"),
                "actual": caller,
            }
        )

    scope = syscall.get("scope")
    if not isinstance(scope, dict):
        errors.append({"code": "mutation_scope_required"})
        scope = {}

    expected_task = str(dispatch.get("task") or "")
    raw_expected_repository = dispatch.get("target_repository")
    expected_repository = (
        raw_expected_repository.strip()
        if isinstance(raw_expected_repository, str)
        else ""
    )
    if not expected_repository:
        errors.append({"code": "target_repository_required"})
    if str(scope.get("task") or "") != expected_task:
        errors.append(
            {
                "code": "task_scope_mismatch",
                "expected": expected_task,
                "actual": scope.get("task"),
            }
        )
    if str(scope.get("repository") or "") != expected_repository:
        errors.append(
            {
                "code": "repository_scope_mismatch",
                "expected": expected_repository,
                "actual": scope.get("repository"),
            }
        )
    if scope.get("mode") != "branch-pr":
        errors.append({"code": "unsupported_mutation_mode", "actual": scope.get("mode")})

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "authoritative": False,
        "persist_required": True,
        "approved": not errors,
        "caller": caller,
        "operation": "mutate_repository",
        "required_capability": decision.get("required_capability"),
        "task": expected_task,
        "target_repository": expected_repository,
        "source_plan_fingerprint": plan.get("fingerprint"),
        "constraints": {
            "mode": "branch-pr",
            "allowed_browser_actions": ["fill", "click"],
            "forbid_direct_main_commit": True,
            "require_new_branch": True,
            "require_pull_request": True,
        },
        "errors": errors,
    }
    receipt["fingerprint"] = _fingerprint(receipt)
    return receipt


def command_authorize(args: argparse.Namespace) -> None:
    _write(args.output, authorize(_read(args.registry), _read(args.syscall)))


def command_authorize_dispatch_mutation(args: argparse.Namespace) -> None:
    result = authorize_dispatch_mutation(
        _read(args.registry),
        _read(args.plan),
        _read(args.syscall),
    )
    _write(args.output, result)
    if not result["approved"]:
        raise SystemExit(2)


def command_validate_dispatch(args: argparse.Namespace) -> None:
    result = validate_dispatch(_read(args.registry), _read(args.plan))
    _write(args.output, result)
    if not result["valid"]:
        raise SystemExit(2)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="aios-kernel")
    sub = root.add_subparsers(dest="command", required=True)

    p = sub.add_parser("authorize", help="evaluate one structured syscall")
    p.add_argument("--registry", required=True)
    p.add_argument("--syscall", required=True)
    p.add_argument("--output")
    p.set_defaults(func=command_authorize)

    p = sub.add_parser("validate-dispatch", help="validate scheduler dispatch target identity")
    p.add_argument("--registry", required=True)
    p.add_argument("--plan", required=True)
    p.add_argument("--output")
    p.set_defaults(func=command_validate_dispatch)

    p = sub.add_parser(
        "authorize-dispatch-mutation",
        help="bind a branch/PR repository mutation receipt to one validated dispatch",
    )
    p.add_argument("--registry", required=True)
    p.add_argument("--plan", required=True)
    p.add_argument("--syscall", required=True)
    p.add_argument("--output")
    p.set_defaults(func=command_authorize_dispatch_mutation)
    return root


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
