from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sandbox.runtime import ExecutionResult, run_in_sandbox
from engines.profiler import ComplexityResult, run_profiler
from engines.taint import TaintReport, run_taint
from .ai_summary import router as ai_router


app = FastAPI(title="Detonation Chamber Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ai_router)


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


class TaintFindingModel(BaseModel):
    source_var: str
    sink_func: str
    source_line: int
    sink_line: int


class TaintReportModel(BaseModel):
    findings: List[TaintFindingModel]


class AnalysisReport(BaseModel):
    meta: AnalysisMeta
    security: Optional[SecurityReport] = None
    complexity: Optional[List[Dict]] = None
    taint: Optional[TaintReportModel] = None


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

    complexity: Optional[List[Dict]] = None
    if "complexity" in request.engines:
        profiler_results: List[ComplexityResult] = run_profiler(request.code)
        complexity = [
            {
                "function_name": r.function_name,
                "complexity_class": r.complexity_class,
                "confidence": r.confidence,
                "matrix": {
                    n: {
                        "n": p.n,
                        "time_ms": p.time_ms,
                        "peak_kb": p.peak_kb,
                    }
                    for n, p in r.matrix.items()
                },
            }
            for r in profiler_results
        ] or None

    taint_report: Optional[TaintReportModel] = None
    if "taint" in request.engines:
        tr: TaintReport = run_taint(request.code)
        if tr.findings:
            taint_report = TaintReportModel(
                findings=[
                    TaintFindingModel(
                        source_var=f.source_var,
                        sink_func=f.sink_func,
                        source_line=f.source_line,
                        sink_line=f.sink_line,
                    )
                    for f in tr.findings
                ]
            )

    report = AnalysisReport(
        meta=AnalysisMeta(
            engines=request.engines,
            timed_out=result.timed_out,
            duration_ms=result.duration_ms,
        ),
        security=security,
        complexity=complexity,
        taint=taint_report,
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

        complexity: Optional[List[Dict]] = None
        if "complexity" in request.engines:
            profiler_results = run_profiler(request.code)
            complexity = [
                {
                    "function_name": r.function_name,
                    "complexity_class": r.complexity_class,
                    "confidence": r.confidence,
                }
                for r in profiler_results
            ] or None

        taint_payload: Optional[Dict] = None
        if "taint" in request.engines:
            tr = run_taint(request.code)
            if tr.findings:
                taint_payload = {
                    "findings": [
                        {
                            "source_var": f.source_var,
                            "sink_func": f.sink_func,
                            "source_line": f.source_line,
                            "sink_line": f.sink_line,
                        }
                        for f in tr.findings
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
                    "complexity": complexity,
                    "taint": taint_payload,
                },
            }
        )
    except WebSocketDisconnect:
        return
