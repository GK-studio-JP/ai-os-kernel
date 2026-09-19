from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REGISTRY_SCHEMA = "ai-os-process-registry:v1"
SYSCALL_SCHEMA = "ai-os-syscall:v1"
DECISION_SCHEMA = "ai-os-kernel-decision:v1"
PLAN_SCHEMA = "ai-os-dispatch-plan:v1"
DISPATCH_SCHEMA = "ai-os-dispatch:v1"
VALIDATION_SCHEMA = "ai-os-kernel-dispatch-validation:v1"

OP_CAPABILITY = {
    "spawn_task": "task.spawn",
    "request_context": "context.read",
    "send_message": "ipc.send",
    "publish_event": "event.publish",
    "commit_state": "state.commit",
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
        target_repo = dispatch.get("target_repository")
        if target_repo and expected_repo and target_repo != expected_repo:
            errors.append(
                {
                    "code": "target_repository_mismatch",
                    "index": index,
                    "process": process_id,
                    "expected": expected_repo,
                    "actual": target_repo,
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


def command_authorize(args: argparse.Namespace) -> None:
    _write(args.output, authorize(_read(args.registry), _read(args.syscall)))


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
    return root


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
