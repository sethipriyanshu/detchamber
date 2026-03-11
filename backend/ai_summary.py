from __future__ import annotations

import os
from typing import Any, Dict

import google.generativeai as genai
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


load_dotenv()

router = APIRouter()


class AISummaryRequest(BaseModel):
  report: Dict[str, Any]


class AISummaryResponse(BaseModel):
  summary: str
  recommendations: str


def _build_prompt(report: Dict[str, Any]) -> str:
  meta = report.get("meta", {})
  engines = ", ".join(meta.get("engines", [])) or "none"

  security = report.get("security") or {}
  complexity = report.get("complexity") or []
  taint = report.get("taint") or {}

  return f"""
You are an expert security and programming assistant. You will see a JSON-like analysis report for a code snippet produced by a tool called Detonation Chamber.

The report has three possible sections:
- security: runtime sandbox violations
- complexity: empirical complexity estimates per function
- taint: static taint-analysis findings for data flow from untrusted input to sinks

Engines enabled: {engines}

Security section (if any):
{security}

Complexity section (if any):
{complexity}

Taint section (if any):
{taint}

1. In 2–3 short sentences, summarize the most important risks or findings for a senior engineer.
2. Then give 3–5 concise bullet points with concrete recommendations (what to change in the code), ordered from highest to lowest impact.

Keep the tone direct and technical. Do not restate the raw JSON.
"""


def _call_gemini(prompt: str) -> str:
  api_key = os.getenv("GEMINI_API_KEY")
  if not api_key:
    raise RuntimeError("GEMINI_API_KEY is not configured")

  model_name = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash-001")

  genai.configure(api_key=api_key)
  model = genai.GenerativeModel(model_name)
  response = model.generate_content(prompt)
  return response.text or ""


@router.post("/ai/summary", response_model=AISummaryResponse)
async def ai_summary(req: AISummaryRequest) -> AISummaryResponse:
  prompt = _build_prompt(req.report)
  try:
    text = _call_gemini(prompt)
  except Exception as exc:  # noqa: BLE001
    # Surface a clean 503 to the frontend; it can show a fallback card.
    raise HTTPException(status_code=503, detail=f"AI summary unavailable: {exc}") from exc

  # Very simple split: first paragraph as summary, rest as recommendations.
  parts = text.strip().split("\n\n", 1)
  summary = parts[0].strip()
  recommendations = parts[1].strip() if len(parts) > 1 else ""

  return AISummaryResponse(summary=summary, recommendations=recommendations or "No extra notes.")

