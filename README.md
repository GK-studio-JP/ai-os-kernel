# ai-os-kernel

`ai-os-kernel` is the minimal authority boundary for the GitHub-native AI OS.

Its v0.1 implementation keeps deterministic identity/capability checks in ordinary code. The LLM may reason about policy proposals, but it does not get to silently invent authority.

```text
Context projection
      |
      v
Scheduler dispatch plan
      |
      v
ai-os-kernel
  |      \
  |       +--> syscall capability decision
  +----------> dispatch target/registry validation
      |
      v
bounded Worker capsule
```

## Microkernel boundary

The Kernel owns identity, capability checks, IPC/syscall policy boundaries, and process registry consistency. It does **not** choose task priority or subsystem implementation details.

The current CLI emits deterministic decision/validation envelopes with `authoritative: false` and `persist_required: true`. This is intentional: a runtime must persist a Kernel decision durably before using it as execution authority. A transient CLI result or Actions artifact is evidence, not a capability grant.

## Syscall authorization

Supported v0.1 operations:

- `spawn_task` -> `task.spawn`
- `request_context` -> `context.read`
- `send_message` -> `ipc.send`
- `publish_event` -> `event.publish`
- `commit_state` -> `state.commit`
- `wait` -> registered-process baseline
- `exit` -> registered-process baseline
- `escalate` -> registered-process baseline
- `request_capability` -> `ESCALATE` until durable grant policy exists

Example:

```bash
python kernel.py authorize \
  --registry registry/processes.json \
  --syscall syscall.json \
  --output decision.json
```

## Scheduler boundary validation

The Kernel can validate that a Scheduler dispatch targets a registered process and that an explicitly supplied target repository matches the process registry:

```bash
python kernel.py validate-dispatch \
  --registry registry/processes.json \
  --plan dispatch/plan.json \
  --output validation.json
```

This does not re-rank tasks. It only enforces the Kernel's identity boundary.

## End-to-end smoke workflow

`.github/workflows/control-plane-smoke.yml` performs the current bounded control-plane loop:

1. rebuild live Context projection from `GK-studio-JP/ai-bulletin-board`;
2. run `GK-studio-JP/ai-os-scheduler` to select at most one runnable task;
3. validate target identity through this Kernel;
4. copy only the selected task's Context Capsule into a Worker boot bundle;
5. upload the disposable `ai-os-control-plane-bundle` artifact.

The bundle still cannot authorize an ownership-sensitive write. A Worker/runtime must refresh the canonical Issue and obtain/persist the required authority before mutation.

## Invariants

- Unknown processes fail closed.
- Unknown syscalls fail closed.
- Missing capabilities fail closed.
- Dynamic capability grants escalate rather than self-approve.
- Kernel validation never changes Scheduler ordering.
- Kernel output is not durable authority until persisted by the runtime.
- Repository implementation details stay outside the Kernel.

## Control-plane dependency lock

The Kernel registry is the authority boundary for control-plane dependency selection. `registry/control-plane-lock.json` pins the audited commits for Context, Scheduler, Runtime, Browser Worker, and Browser Agent with full lowercase 40-hex Git commit SHAs.

`control_plane_lock.py` validates this lock fail closed: the schema and fields are exact, the repository set is fixed, duplicates and unknown repositories/fields are rejected, and floating branches or mutable tags are not accepted as commits.

Consumers should pin only one immutable Kernel bootstrap commit, then resolve governed dependency SHAs from that Kernel snapshot. For GitHub Actions, the supported resolver is:

```bash
python control_plane_lock.py export-github \
  --lock registry/control-plane-lock.json \
  --output "$GITHUB_OUTPUT"
```

A consumer must not independently choose a different Context, Scheduler, Runtime, Browser Worker, or Browser Agent SHA already governed by the selected Kernel snapshot. Updating those dependency versions therefore starts with a Kernel lock PR; consumer workflow migrations then select that immutable Kernel snapshot. Third-party GitHub Action pins remain separate supply-chain pins and stay immutable.
