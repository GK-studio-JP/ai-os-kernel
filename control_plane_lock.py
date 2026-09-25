from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "ai-os-control-plane-lock:v1"
REQUIRED_REPOSITORIES = (
    "GK-studio-JP/ai-os-context",
    "GK-studio-JP/ai-os-scheduler",
    "GK-studio-JP/ai-os-runtime",
    "GK-studio-JP/ai-os-runtime-browser-worker",
    "GK-studio-JP/browser-agent",
)
OUTPUT_NAMES = {
    "GK-studio-JP/ai-os-context": "context_sha",
    "GK-studio-JP/ai-os-scheduler": "scheduler_sha",
    "GK-studio-JP/ai-os-runtime": "runtime_sha",
    "GK-studio-JP/ai-os-runtime-browser-worker": "browser_worker_sha",
    "GK-studio-JP/browser-agent": "browser_agent_sha",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class LockError(ValueError):
    pass


def load_lock(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LockError(f"cannot read control-plane lock {path}: {exc}") from exc

    if not isinstance(value, dict):
        raise LockError("lock root must be an object")

    expected_root = {"schema", "repositories"}
    if set(value) != expected_root:
        raise LockError(
            f"lock root must contain exactly {sorted(expected_root)}"
        )
    if value.get("schema") != SCHEMA:
        raise LockError(f"unsupported lock schema: {value.get('schema')!r}")

    rows = value.get("repositories")
    if not isinstance(rows, list):
        raise LockError("repositories must be a list")

    seen: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise LockError("each repository entry must be an object")
        expected_row = {"repository", "commit"}
        if set(row) != expected_row:
            raise LockError(
                "repository entries must contain exactly "
                f"{sorted(expected_row)}"
            )

        repository = row.get("repository")
        commit = row.get("commit")
        if not isinstance(repository, str) or not repository:
            raise LockError("repository must be a non-empty string")
        if repository in seen:
            raise LockError(f"duplicate repository: {repository}")
        if not isinstance(commit, str) or HEX40.fullmatch(commit) is None:
            raise LockError(
                f"{repository}: commit must be a lowercase immutable 40-hex SHA"
            )
        seen[repository] = commit

    required = set(REQUIRED_REPOSITORIES)
    actual = set(seen)
    missing = sorted(required - actual)
    extra = sorted(actual - required)
    if missing or extra:
        raise LockError(
            f"repository set mismatch: missing={missing!r} extra={extra!r}"
        )
    return value


def repository_map(lock: dict[str, Any]) -> dict[str, str]:
    return {
        str(row["repository"]): str(row["commit"])
        for row in lock["repositories"]
    }


def commit_for(lock: dict[str, Any], repository: str) -> str:
    if repository not in REQUIRED_REPOSITORIES:
        raise LockError(f"repository is not governed by this lock: {repository}")
    return repository_map(lock)[repository]


def write_github_outputs(lock: dict[str, Any], output_path: Path) -> None:
    commits = repository_map(lock)
    lines = [
        f"{OUTPUT_NAMES[repository]}={commits[repository]}\n"
        for repository in REQUIRED_REPOSITORIES
    ]
    try:
        with output_path.open("a", encoding="utf-8") as output:
            output.writelines(lines)
    except OSError as exc:
        raise LockError(f"cannot write GitHub outputs {output_path}: {exc}") from exc


def command_validate(args: argparse.Namespace) -> None:
    lock = load_lock(Path(args.lock))
    print("CONTROL_PLANE_LOCK_OK", len(lock["repositories"]))


def command_get(args: argparse.Namespace) -> None:
    lock = load_lock(Path(args.lock))
    print(commit_for(lock, args.repository))


def command_export_github(args: argparse.Namespace) -> None:
    lock = load_lock(Path(args.lock))
    write_github_outputs(lock, Path(args.output))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="aios-control-plane-lock")
    sub = root.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate the canonical control-plane lock")
    p.add_argument("--lock", default="registry/control-plane-lock.json")
    p.set_defaults(func=command_validate)

    p = sub.add_parser("get", help="print one governed repository commit")
    p.add_argument("--lock", default="registry/control-plane-lock.json")
    p.add_argument("--repository", required=True)
    p.set_defaults(func=command_get)

    p = sub.add_parser(
        "export-github",
        help="append deterministic dependency SHA outputs for GitHub Actions",
    )
    p.add_argument("--lock", default="registry/control-plane-lock.json")
    p.add_argument("--output", required=True)
    p.set_defaults(func=command_export_github)
    return root


def main() -> None:
    args = parser().parse_args()
    try:
        args.func(args)
    except LockError as exc:
        raise SystemExit(f"CONTROL_PLANE_LOCK_ERROR: {exc}") from exc


if __name__ == "__main__":
    main()
