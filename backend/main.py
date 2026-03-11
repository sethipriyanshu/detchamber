from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from sandbox.runtime import ExecutionResult, run_in_sandbox


app = FastAPI(title="Detonation Chamber Backend", version="0.1.0")


class AnalyzeRequest(BaseModel):
    code: str
    engines: List[str] = ["security"]
    timeout_ms: Optional[int] = None


class AnalysisMeta(BaseModel):
    engines: List[str]
    timed_out: bool = False
    duration_ms: float


class SecurityReport(BaseModel):
    violations: List[Dict]


class AnalysisReport(BaseModel):
    meta: AnalysisMeta
    security: Optional[SecurityReport] = None
    complexity: Optional[Dict] = None
    taint: Optional[Dict] = None


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(request: AnalyzeRequest) -> AnalysisReport:
    timeout_s = int((request.timeout_ms or 0) / 1000) or None
    result: ExecutionResult = run_in_sandbox(request.code, timeout_s=timeout_s)

    security = None
    if "security" in request.engines:
        security = SecurityReport(
            violations=[
                {
                    "severity": v.severity,
                    "operation": v.operation,
                    "message": v.message,
                    "lineno": v.lineno,
                    "func_name": v.func_name,
                }
                for v in result.violations
            ]
        )

    report = AnalysisReport(
        meta=AnalysisMeta(
            engines=request.engines,
            timed_out=result.timed_out,
            duration_ms=result.duration_ms,
        ),
        security=security,
        complexity=None,
        taint=None,
    )
    return report


@app.websocket("/ws/analyze")
async def analyze_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        request = AnalyzeRequest(**payload)
        timeout_s = int((request.timeout_ms or 0) / 1000) or None

        await websocket.send_json(
            {
                "type": "status",
                "engine": "orchestrator",
                "message": "analysis_start",
                "engines": request.engines,
            }
        )
        result: ExecutionResult = run_in_sandbox(request.code, timeout_s=timeout_s)

        security = None
        if "security" in request.engines:
            security = {
                "violations": [
                    {
                        "severity": v.severity,
                        "operation": v.operation,
                        "message": v.message,
                        "lineno": v.lineno,
                        "func_name": v.func_name,
                    }
                    for v in result.violations
                ]
            }

        await websocket.send_json(
            {
                "type": "complete",
                "report": {
                    "meta": {
                        "engines": request.engines,
                        "timed_out": result.timed_out,
                        "duration_ms": result.duration_ms,
                    },
                    "security": security,
                    "complexity": None,
                    "taint": None,
                },
            }
        )
    except WebSocketDisconnect:
        return
