from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException

from kernel import authorize, validate_dispatch

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "registry" / "processes.json"

app = FastAPI(title="ai-os-kernel HTTP API", version="1")


def _authorize(authorization: str | None) -> None:
    token = os.getenv("AIOS_SERVICE_TOKEN")
    if not token:
        raise HTTPException(status_code=503, detail="AIOS_SERVICE_TOKEN is not configured")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="unauthorized")


def _registry(payload: dict[str, Any]) -> dict[str, Any]:
    supplied = payload.get("registry")
    if supplied is not None:
        if not isinstance(supplied, dict):
            raise ValueError("registry must be an object")
        return supplied
    return json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "ai-os-kernel"}


@app.post("/api/kernel/validate-dispatch")
def validate(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(authorization)
    try:
        return validate_dispatch(_registry(payload), payload["plan"])
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/kernel/authorize")
def authorize_syscall(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(authorization)
    try:
        return authorize(_registry(payload), payload["syscall"])
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
