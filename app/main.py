"""HTTP API for the X12 envelope audit service."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .x12 import AuditError, audit

app = FastAPI(title="X12 Envelope Audit", version="1.0.0")

_STATUS_BY_CODE = {"PAYLOAD_TOO_LARGE": 413}


@app.get("/health")
async def health() -> dict[str, str]:
    """Readiness probe used by the container health check."""
    return {"status": "ok"}


@app.post("/api/x12/audit")
async def audit_interchange(request: Request) -> JSONResponse:
    payload = await request.body()
    try:
        result = audit(payload)
    except AuditError as exc:
        return JSONResponse(
            status_code=_STATUS_BY_CODE.get(exc.code, 400),
            content={
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "segment": exc.segment,
                },
            },
        )
    return JSONResponse(
        content={
            "ok": True,
            "interchangeControlNumber": result.interchange_control_number,
            "groups": result.groups,
            "transactions": result.transactions,
            "sha256": result.sha256,
        }
    )
