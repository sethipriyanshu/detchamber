import { useEffect, useMemo, useState } from "react";
import Editor from "@monaco-editor/react";

import { detectLanguage } from "./languageDetection";
import {
  AISummary,
  AnalyzeEvent,
  AnalyzePayload,
  AnalysisReport,
  fetchAISummary,
  openAnalyzeWebSocket
} from "./api";

type EngineName = "security" | "complexity" | "taint";

interface EngineToggle {
  name: EngineName;
  label: string;
  color: string;
}

const ENGINE_TOGGLES: EngineToggle[] = [
  { name: "security", label: "Security", color: "#ef4444" },
  { name: "complexity", label: "Complexity", color: "#f97316" },
  { name: "taint", label: "Taint", color: "#3b82f6" }
];

type ViewMode = "editor" | "report";
type Page = "workspace" | "about";

export function App() {
  const [code, setCode] = useState<string>("print('hello from Detonation Chamber')\n");
  const [languageBadge, setLanguageBadge] = useState<string>("Language: unknown");
  const [detectedLang, setDetectedLang] = useState<string>("unknown");
  const [engines, setEngines] = useState<Record<EngineName, boolean>>({
    security: true,
    complexity: true,
    taint: true
  });
  const [isRunning, setIsRunning] = useState(false);
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  const [view, setView] = useState<ViewMode>("editor");
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [page, setPage] = useState<Page>("workspace");
  const monacoTheme = theme === "dark" ? "vs-dark" : "vs-light";
  const [aiSummary, setAiSummary] = useState<AISummary | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  useEffect(() => {
    document.body.classList.toggle("theme-light", theme === "light");
  }, [theme]);

  useEffect(() => {
    const handle = setTimeout(() => {
      const result = detectLanguage(code);
      setDetectedLang(result.language);
      if (result.language === "python") {
        setLanguageBadge("Python detected — all engines ready");
      } else if (result.language === "unknown") {
        setLanguageBadge("Language unknown. Please ensure you submit valid Python code.");
      } else {
        setLanguageBadge(
          `${result.language} detected. We currently only support Python but are actively working to add support for this.`
        );
      }
    }, 300);
    return () => clearTimeout(handle);
  }, [code]);

  const selectedEngines = useMemo(
    () => Object.entries(engines).filter(([, v]) => v).map(([k]) => k) as EngineName[],
    [engines]
  );

  const detonateDisabled =
    isRunning ||
    detectedLang !== "python" ||
    selectedEngines.length === 0 ||
    !code.trim() ||
    page !== "workspace";

  function toggleEngine(name: EngineName) {
    setEngines((prev) => ({ ...prev, [name]: !prev[name] }));
  }

  function clearConsole() {
    setConsoleLines([]);
  }

  function handleAnalyze() {
    if (detonateDisabled) return;
    clearConsole();
    setIsRunning(true);
    setView("editor");
    setReport(null);
    setAiSummary(null);
    setAiError(null);

    const payload: AnalyzePayload = {
      code,
      engines: selectedEngines
    };

    const socket = openAnalyzeWebSocket(
      payload,
      (event: AnalyzeEvent) => {
        if (event.type === "status") {
          setConsoleLines((lines) => [
            ...lines,
            `[orchestrator] ${event.message} — engines: ${event.engines.join(", ")}`
          ]);
        } else if (event.type === "complete") {
          setReport(event.report);
          setView("report");
          setIsRunning(false);
          setConsoleLines((lines) => [
            ...lines,
            `[orchestrator] analysis complete in ${event.report.meta.duration_ms.toFixed(2)} ms`
          ]);
          socket.close();
          setWs(null);

          // Fire-and-forget AI summary generation
          setAiLoading(true);
          fetchAISummary(event.report)
            .then((s) => {
              setAiSummary(s);
              setAiError(null);
            })
            .catch(() => {
              setAiError("AI summary unavailable for this run.");
            })
            .finally(() => setAiLoading(false));
        }
      },
      () => {
        setConsoleLines((lines) => [...lines, "[error] WebSocket error"]);
        setIsRunning(false);
      }
    );

    setWs(socket);
  }

  function renderSummary() {
    if (!report) return null;
    const findings =
      (report.security?.violations?.length ?? 0) +
      (Array.isArray(report.complexity) ? report.complexity.length : 0) +
      (report.taint?.findings?.length ?? 0);

    const verdict =
      findings === 0 ? "PASS" : (report.taint?.findings?.some((f: any) => f) ? "FAIL" : "WARN");

    return (
      <div className="summary-card">
        <div className="summary-verdict">{verdict}</div>
        <div className="summary-details">
          <span>Total findings: {findings}</span>
          <span>Duration: {report.meta.duration_ms.toFixed(2)} ms</span>
        </div>
      </div>
    );
  }

  function renderSecurityTab() {
    if (!report) {
      return <div className="empty-state">Run analysis to view security results.</div>;
    }

    const engines = report.meta.engines || [];
    if (!engines.includes("security")) {
      return <div className="empty-state">Security engine was disabled for this run.</div>;
    }

    if (!report.security || !report.security.violations?.length) {
      return (
        <div className="empty-state success">
          <div className="empty-title">No security violations detected</div>
          <div className="empty-subtitle">
            All sandboxed operations stayed within the allowed policy for this run.
          </div>
        </div>
      );
    }

    return (
      <table className="report-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Operation</th>
            <th>Line</th>
            <th>Function</th>
            <th>Origin</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {report.security.violations.map((v: any, idx: number) => (
            <tr key={idx}>
              <td>{v.severity}</td>
              <td>{v.operation}</td>
              <td>{v.lineno ?? "-"}</td>
              <td>{v.func_name ?? "-"}</td>
              <td>{v.origin ?? "runtime"}</td>
              <td>{v.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  function renderComplexityTab() {
    if (!report) {
      return <div className="empty-state">Run analysis to view complexity measurements.</div>;
    }

    const engines = report.meta.engines || [];
    if (!engines.includes("complexity")) {
      return <div className="empty-state">Complexity profiler was disabled for this run.</div>;
    }

    if (!Array.isArray(report.complexity) || !report.complexity.length) {
      return (
        <div className="empty-state success">
          <div className="empty-title">No profileable functions found</div>
          <div className="empty-subtitle">
            The profiler didn&apos;t find any top‑level functions it could safely benchmark in this
            snippet.
          </div>
        </div>
      );
    }

    return (
      <table className="report-table">
        <thead>
          <tr>
            <th>Function</th>
            <th>Class</th>
            <th>Confidence</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {report.complexity.map((c: any, idx: number) => (
            <tr key={idx}>
              <td>{c.function_name}</td>
              <td>{c.complexity_class}</td>
              <td>{(c.confidence * 100).toFixed(1)}%</td>
              <td>{c.source ?? "measured"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  function renderTaintTab() {
    if (!report) {
      return <div className="empty-state">Run analysis to view taint results.</div>;
    }

    const engines = report.meta.engines || [];
    if (!engines.includes("taint")) {
      return <div className="empty-state">Taint tracker was disabled for this run.</div>;
    }

    if (!report.taint || !report.taint.findings?.length) {
      return (
        <div className="empty-state success">
          <div className="empty-title">No unsafe data flows detected</div>
          <div className="empty-subtitle">
            No untrusted inputs were seen flowing into sensitive sinks without passing through a
            sanitizer.
          </div>
        </div>
      );
    }

    return (
      <table className="report-table">
        <thead>
          <tr>
            <th>Source var</th>
            <th>Sink</th>
            <th>Source line</th>
            <th>Sink line</th>
          </tr>
        </thead>
        <tbody>
          {report.taint.findings.map((f: any, idx: number) => (
            <tr key={idx}>
              <td>{f.source_var}</td>
              <td>{f.sink_func}</td>
              <td>{f.source_line}</td>
              <td>{f.sink_line}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  const [activeTab, setActiveTab] = useState<"security" | "complexity" | "taint">("security");

  function renderInfoPage() {
    return (
      <div className="info-page">
        <div>
          <h2>About Detonation Chamber</h2>
          <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
            Detonation Chamber runs your code through three independent analysis engines before you
            ever wire it into a real system.
          </p>
        </div>
        <div className="info-grid">
          <div className="info-card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3>Security Sandbox</h3>
              <span className="pill red">Runtime</span>
            </div>
            <p>
              Executes your code inside an isolated sandbox and intercepts dangerous operations like
              file access, shell execution, and network calls.
            </p>
            <div className="info-metadata">
              <span>• Flags high‑risk syscalls</span>
              <span>• Shows line + call context</span>
            </div>
          </div>
          <div className="info-card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3>Complexity Profiler</h3>
              <span className="pill amber">Scaling</span>
            </div>
            <p>
              Benchmarks your functions on synthetic inputs and fits the timing curve to estimate
              true Big‑O behaviour with a confidence score.
            </p>
            <div className="info-metadata">
              <span>• Empirical runtime curves</span>
              <span>• Detects hidden O(n²)+ paths</span>
            </div>
          </div>
          <div className="info-card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3>Taint Tracker</h3>
              <span className="pill blue">Data flow</span>
            </div>
            <p>
              Traces untrusted input through your AST and highlights flows into sensitive sinks like
              eval, exec, and os.system without sanitisation.
            </p>
            <div className="info-metadata">
              <span>• Source → sink traces</span>
              <span>• Classic injection patterns</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-root">
      <header className="app-header">
        <div className="top-nav">
          <h1>Detonation Chamber</h1>
          <div className="nav-group">
            <button
              className={page === "workspace" ? "nav-link active" : "nav-link"}
              onClick={() => setPage("workspace")}
            >
              Workspace
            </button>
            <button
              className={page === "about" ? "nav-link active" : "nav-link"}
              onClick={() => setPage("about")}
            >
              About
            </button>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <div className="engine-toggles">
            {ENGINE_TOGGLES.map((engine) => (
              <label
                key={engine.name}
                style={{ borderColor: engine.color }}
                className={engines[engine.name] ? "toggle active" : "toggle"}
              >
                <input
                  type="checkbox"
                  checked={engines[engine.name]}
                  onChange={() => toggleEngine(engine.name)}
                />
                {engine.label}
              </label>
            ))}
          </div>
          <button
            className="theme-toggle"
            type="button"
            onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
          >
            <span>{theme === "dark" ? "🌙" : "☀️"}</span>
            <span>{theme === "dark" ? "Dark" : "Light"}</span>
          </button>
          <button
            className="detonate-btn"
            disabled={detonateDisabled}
            onClick={handleAnalyze}
            style={{ opacity: detonateDisabled ? 0.5 : 1 }}
          >
            DETONATE
          </button>
        </div>
      </header>

      {page === "workspace" ? (
        <>
          <div className="status-bar">
            <span>{languageBadge}</span>
            {isRunning && <span className="status-running">Running…</span>}
          </div>

          <main className="app-main workspace">
            <section className="editor-panel">
              <Editor
                height="100%"
                defaultLanguage="python"
                language="python"
                theme={monacoTheme}
                value={code}
                onChange={(value) => setCode(value ?? "")}
                options={{
                  minimap: { enabled: false },
                  fontSize: 14,
                  smoothScrolling: true,
                  cursorBlinking: "smooth"
                }}
              />
            </section>

            <section className="right-panel">
              <div className="right-panel-tabs">
                <button
                  className={view === "editor" ? "tab active" : "tab"}
                  onClick={() => setView("editor")}
                >
                  Console
                </button>
                <button
                  className={view === "report" ? "tab active" : "tab"}
                  onClick={() => setView("report")}
                  disabled={!report}
                >
                  Report
                </button>
              </div>

              {view === "editor" && (
                <div className="console-panel">
                  <pre>
                    {consoleLines.map((line, idx) => (
                      <div key={idx}>{line}</div>
                    ))}
                  </pre>
                </div>
              )}

              {view === "report" && report && (
                <div className="report-panel">
                  {renderSummary()}
                  <div className="ai-summary-wrapper">
                    {aiLoading && (
                      <div className="ai-card">
                        <div className="ai-title">AI summary</div>
                        <div className="ai-body">Generating insights from Gemini…</div>
                      </div>
                    )}
                    {aiError && !aiLoading && (
                      <div className="ai-card ai-error">
                        <div className="ai-title">AI summary</div>
                        <div className="ai-body">{aiError}</div>
                      </div>
                    )}
                    {aiSummary && !aiLoading && (
                      <div className="ai-card">
                        <div className="ai-title">AI summary</div>
                        <div className="ai-body">{aiSummary.summary}</div>
                        <div className="ai-subtitle">How to improve</div>
                        <div className="ai-body">{aiSummary.recommendations}</div>
                      </div>
                    )}
                  </div>
                  <div className="report-tabs">
                    <button
                      className={activeTab === "security" ? "tab active" : "tab"}
                      onClick={() => setActiveTab("security")}
                    >
                      Security
                    </button>
                    <button
                      className={activeTab === "complexity" ? "tab active" : "tab"}
                      onClick={() => setActiveTab("complexity")}
                    >
                      Complexity
                    </button>
                    <button
                      className={activeTab === "taint" ? "tab active" : "tab"}
                      onClick={() => setActiveTab("taint")}
                    >
                      Taint
                    </button>
                  </div>
                  <div className="report-tab-body">
                    {activeTab === "security" && renderSecurityTab()}
                    {activeTab === "complexity" && renderComplexityTab()}
                    {activeTab === "taint" && renderTaintTab()}
                  </div>
                </div>
              )}
            </section>
          </main>
        </>
      ) : (
        <main className="app-main about">
          <section className="editor-panel full-width">{renderInfoPage()}</section>
        </main>
      )}
    </div>
  );
}

export default App;

