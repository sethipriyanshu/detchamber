## Detonation Chamber

Detonation Chamber is a local “pre‑flight sandbox” for AI‑generated code. Instead of dropping LLM‑written snippets straight into your codebase, you paste them into the Chamber and detonate them first.

For each run, it produces a unified report from **three analysis engines**:

- **Security Sandbox**: watches runtime behavior in an isolated subprocess and flags dangerous operations.
- **Complexity Profiler**: empirically (and statically, as a fallback) estimates the algorithmic complexity of your functions.
- **Taint Tracker**: performs static data‑flow analysis to find untrusted inputs flowing into dangerous sinks.

Everything runs **locally**; no code or findings are sent to external services except optionally to Gemini, if you choose to enable AI summaries.

---

## System Architecture

### High‑level layout

- **Frontend** (`frontend/`)
  - React + Vite + TypeScript SPA.
  - Monaco Editor for code input.
  - Right‑hand pane:
    - Console streaming per‑engine status from WebSocket.
    - Report tabs: **Security**, **Complexity**, **Taint**.
    - Optional AI summary card (Gemini) with a natural‑language summary and recommendations.

- **Orchestrator API** (`backend/main.py`)
  - FastAPI app.
  - Endpoints:
    - `GET /health`: health check.
    - `POST /analyze`: one‑shot analysis (returns JSON report).
    - `WS /ws/analyze`: streaming analysis (status + final report).
    - `POST /ai/summary`: optional Gemini‑powered AI summary.
  - Sequentially runs Security → Complexity → Taint so each engine gets a chance to execute and report progress.

- **Engines**

  - **Security Sandbox**
    - Runtime:
      - Executes user code inside a separate subprocess (`sandbox/runtime.py`).
      - Replaces dangerous builtins (`open`, `eval`, etc.) with blocking wrappers.
      - Records `ThreatLogEntry` items (severity, operation, line, function).
    - Static:
      - AST‑based scanner (`engines/security_static.py`) walks the code and flags calls to `open`, `os.system`, `subprocess.run`, etc., regardless of whether they execute at runtime.
    - Report:
      - Both runtime and static findings are merged into a single `security.violations` array, each with an `origin` field (`runtime` or `static`).

  - **Complexity Profiler** (`engines/profiler/`)
    - Detects top‑level `def` functions in your snippet.
    - Runtime measurement:
      - For each function and input size `n` in `[10, 50, 100, 500, 1000, 5000]`, runs the function in the sandbox.
      - Measures wall time and peak memory; builds a `MeasurementMatrix`.
    - Classification:
      - Fits observed timings to several complexity classes (`O(1)`, `O(n)`, `O(n^2)`, etc.) and returns the best match with a confidence score.
    - Static fallback:
      - If runtime profiling fails for all functions, falls back to a simple AST‑based heuristic (loop nesting depth) to estimate a class with low confidence.
    - Each result is tagged with a `source` field (`measured` vs `static`) so the UI can show how trustworthy it is.

  - **Taint Tracker** (`engines/taint/`)
    - Purely static: parses code into an AST and builds a simplified control‑flow view.
    - Marks sources (e.g. `input()`) and sinks (e.g. `os.system`, `eval`) and tracks how tainted values propagate between them.
    - Produces `findings` showing `source_var`, `sink_func`, and line numbers involved.

---

## Running the project locally

You can run the project directly on your machine, or via Docker.

### Prerequisites

- Python 3.9+ (backend).
- Node.js 18+ and npm (frontend).
- Optional: Docker and Docker Compose (for `make dev` / `docker compose up`).
- Optional: a Gemini API key, if you want AI summaries.

### 1. Backend (FastAPI + engines)

From the project root:

```bash
python3 -m pip install -r requirements.txt
python3 -m uvicorn backend.main:app --reload
```

The backend will be available at `http://127.0.0.1:8000`.

Quick check:

```bash
curl http://127.0.0.1:8000/health
```

You should get:

```json
{"status": "ok"}
```

### 2. Frontend (React + Vite)

In a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the app in your browser at:

```text
http://127.0.0.1:3000
```

### 3. Using the UI

1. Go to the **Workspace** tab.
2. Paste Python code into the Monaco editor.
3. Ensure the language badge shows **Python detected — all engines ready**.
4. Select which engines you want to run (Security, Complexity, Taint).
5. Click **DETONATE**.

During analysis:

- The **Console** tab streams progress:
  - `orchestrator` start.
  - `security` / `complexity` / `taint` start + completed.
- The **Report** tab shows:
  - Summary verdict (PASS / WARN / FAIL), total findings, duration.
  - **Security** findings (runtime + static).
  - **Complexity** results (measured + static estimates).
  - **Taint** data‑flow findings.
  - Optional AI summary card if configured.

---

## Running with Docker / Makefile

If you have Docker and Docker Compose installed, you can use the included `docker-compose.yml` and `Makefile`.

From the project root:

```bash
make dev
```

This will:

- Build a backend image from `Dockerfile.backend` and run FastAPI on port `8000`.
- Build a frontend image from `Dockerfile.frontend` and run Vite dev server on port `3000`.

Then open `http://127.0.0.1:3000` in your browser.

Other useful targets:

```bash
make dev-backend   # run uvicorn locally (no Docker)
make dev-frontend  # run frontend dev server locally
make test          # run backend tests (pytest)
make lint          # run backend + frontend linters (best-effort)
```

---

## Enabling Gemini AI summaries (optional)

If you want a natural‑language summary of the report and concrete remediation tips:

1. Create a Gemini API key in Google AI Studio / Google Cloud.
2. Copy `.env.example` to `.env` at the project root:

   ```bash
   cp .env.example .env
   ```

3. Edit `.env` and set:

   ```bash
   GEMINI_API_KEY=your_real_key_here
   GEMINI_MODEL_NAME=models/gemini-1.0-pro  # or any model with generateContent enabled
   ```

4. Restart the backend:

   ```bash
   python3 -m uvicorn backend.main:app --reload
   ```

When analysis completes, the frontend calls `POST /ai/summary` with the `AnalysisReport` and shows:

- **AI summary**: short description of the main issues.
- **How to improve**: ordered bullet‑style recommendations.

If the call fails or the model is unavailable, the UI shows a soft “AI summary unavailable for this run” message instead of blocking.

---

## Project structure

High‑level layout:

- `backend/`
  - `main.py`: FastAPI app, `/analyze`, `/ws/analyze`, `/ai/summary`, `AnalysisReport` models.
- `sandbox/`
  - `runtime.py`: subprocess execution, timeout handling, threat logging.
  - `security.py`: restricted builtins, runtime security tracer.
- `engines/`
  - `profiler/`: complexity detector, input generator, measurement harness, classifier.
  - `taint/`: AST parser, CFG builder, taint propagation engine.
  - `security_static.py`: static security scanner.
- `frontend/`
  - React + Vite + TypeScript SPA (Monaco editor, console, report UI, AI summary card).
- `tests/`
  - Backend/unit tests for sandbox, API, profiler, and taint tracker.

---

## Future: multi‑language support

The current v1 release is **Python‑only**, but the architecture is intentionally designed to support additional languages via adapters.

### Adapter concept

Each new language would implement a common interface for the three engines:

- **Security**: provide a way to run untrusted code in an isolated, observable environment (e.g., language‑specific sandboxes, containers, or VM‑based sandboxes).
- **Complexity**: detect functions/entrypoints and either:
  - Generate synthetic inputs and benchmark them, or
  - Integrate with existing profiling/tracing tools in that ecosystem.
- **Taint**: parse the language into an AST/IR, define sources/sinks, and implement data‑flow / taint propagation over that IR.

The FastAPI orchestrator and the frontend remain mostly language‑agnostic; they work with a normalized `AnalysisReport` shape regardless of implementation details underneath.

### Examples of future adapters

- **JavaScript / TypeScript**
  - Sandbox: Node.js with `vm` / `isolated-vm` inside a locked‑down container.
  - Parser: `@babel/parser` to build an AST.
  - Security:
    - Intercept filesystem (`fs`), `child_process`, network requests, and `eval`/`Function` uses.
  - Complexity:
    - Detect exported or top‑level functions and run empirical benchmarks with synthetic arrays/objects.
  - Taint:
    - Treat `req.*`, `process.env`, query/body params as sources and SQL/OS/HTTP calls as sinks.

- **JVM languages (Java, Kotlin)**
  - Sandbox: run inside a restricted JVM with a custom SecurityManager‑like layer or container jail.
  - Parser/IR: use existing compiler APIs or libraries (e.g., JavaParser) to build AST/CFG.
  - Security:
    - Watch for reflection, process spawning, file and network APIs.
  - Complexity:
    - Focus on methods in selected classes (e.g., service or algorithm packages).
  - Taint:
    - Follow data through method calls, fields, and collections into JDBC, process execution, etc.

- **Go / Rust**
  - Sandbox: containerized or VM‑based execution with strict resource limits and network/filesystem controls.
  - Parser/IR: use language‑specific AST tooling (`go/ast`, Rust compiler APIs or tree‑sitter grammars).
  - Security & Taint:
    - Focus on OS / network APIs, unsafe operations, and FFI calls.

Adding a new language would primarily involve:

1. Implementing language‑specific engines under `engines/<language>/`.
2. Extending the orchestrator’s dispatch logic to choose the adapter based on a detection step (or explicit language selection).
3. Optionally enhancing the frontend language detection and UX to surface language‑specific caveats.

This keeps the **UX and report format stable**, while letting you grow Detonation Chamber into a cross‑language pre‑flight sandbox over time.

---

## Development workflow

Typical inner loop:

1. Start backend:

   ```bash
   python3 -m uvicorn backend.main:app --reload
   ```

2. Start frontend:

   ```bash
   cd frontend
   npm run dev
   ```

3. Paste AI‑generated snippets into the UI, adjust engines, and iterate based on the report.
4. Run tests periodically:

   ```bash
   make test
   ```

Detonation Chamber is designed so you can drop it into your portfolio or daily workflow as a local, transparent guardrail between “LLM output” and “production code”. It surfaces runtime behavior, scaling issues, and unsafe data flows in one place before anything ever touches your real codebase.

