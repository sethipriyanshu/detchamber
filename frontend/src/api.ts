import { BACKEND_HTTP_URL, BACKEND_WS_URL } from "./config";

export interface AnalyzePayload {
  code: string;
  engines: string[];
  timeout_ms?: number;
}

export interface AnalysisReport {
  meta: {
    engines: string[];
    timed_out: boolean;
    duration_ms: number;
  };
  security: any;
  complexity: any;
  taint: any;
}

export interface AISummary {
  summary: string;
  recommendations: string;
}

export async function analyzeOnce(payload: AnalyzePayload): Promise<AnalysisReport> {
  const res = await fetch(`${BACKEND_HTTP_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    throw new Error(`Analyze failed with status ${res.status}`);
  }
  return (await res.json()) as AnalysisReport;
}

export async function fetchAISummary(report: AnalysisReport): Promise<AISummary> {
  const res = await fetch(`${BACKEND_HTTP_URL}/ai/summary`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ report })
  });
  if (!res.ok) {
    throw new Error(`AI summary failed with status ${res.status}`);
  }
  return (await res.json()) as AISummary;
}

export type AnalyzeEvent =
  | {
      type: "status";
      engine: string;
      message: string;
      engines: string[];
    }
  | {
      type: "complete";
      report: AnalysisReport;
    };

export function openAnalyzeWebSocket(
  payload: AnalyzePayload,
  onEvent: (e: AnalyzeEvent) => void,
  onError: (err: Event) => void
): WebSocket {
  const ws = new WebSocket(`${BACKEND_WS_URL}/ws/analyze`);
  ws.onopen = () => {
    ws.send(JSON.stringify(payload));
  };
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data) as AnalyzeEvent;
      onEvent(data);
    } catch (e) {
      console.error("Invalid WS message", e);
    }
  };
  ws.onerror = onError;
  return ws;
}

