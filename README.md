# Agentic AI Exposure Assessor

**English** | [日本語 (Japanese)](README.ja.md)

A **defensive** diagnostic / visualization tool for Agentic AI applications. It combines:

- **Tenable-AI-Exposure-style inventory & exposure management** — agents, users, tools,
  permissions, data sources and integrations are treated as *assets*; misconfigurations and
  risky combinations become *Findings* with an *Exposure / Risk Score*.
- **OpenTelemetry / OTLP-style runtime trace collection** — OTLP-style trace JSON is
  ingested and normalized into spans, tool calls, inter-agent messages and memory/RAG
  operations, so you can see *what actually executed*, not just what was configured.
- **Promptfoo-tracing-style trajectory evaluation** — rules reason about the
  *tool-call sequence*, *tool arguments* and *approval events*, not only final output.

Findings are mapped to the **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10).

> This is a **diagnostic, read-only** tool. It does **not** attack systems, bypass auth,
> escalate privileges, or generate exploit code. It only ingests configuration and trace
> data you provide and reports risks.

---

## Why no Docker?

Docker Desktop may require a **paid license for corporate use**, so this MVP is
**deliberately Docker-free**:

- No Docker Desktop, no Docker Compose, no Dockerfile.
- No WSL requirement, no Linux-only shell scripts, no PowerShell-only scripts, no `make`.
- Everything runs in a **plain local Python virtual environment**.

It is built and tested for **Windows + Git Bash**, using `pathlib.Path` everywhere so both
Windows (`C:\...`) and POSIX-style (`C:/...`) paths work. Outputs go to relative paths
(`./reports`, `./data/app.db`) and missing directories are created from Python.

---

## Prerequisites

- **OS**: Windows PC
- **Terminal**: Git Bash / MINGW64
- **Python**: 3.12 or newer
- No Docker required.

---

## Setup (Windows + Git Bash)

```bash
py -3.12 -m venv .venv
source .venv/Scripts/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m agentic_ai_exposure_assessor.cli init-fixtures
python -m agentic_ai_exposure_assessor.cli ingest-config --fixtures ./fixtures
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./fixtures/otlp_trace_sample.json
python -m agentic_ai_exposure_assessor.cli assess
python -m agentic_ai_exposure_assessor.cli export-report --format markdown --output ./reports/report.md
python -m agentic_ai_exposure_assessor.cli serve
```

### If `py -3.12` is not available

Use whatever Python 3.12+ is on `PATH`:

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -e ".[dev]"
```

### If `source .venv/Scripts/activate` does not work in Git Bash

You can always call the venv's Python directly (no activation needed):

```bash
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli init-fixtures
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli ingest-config --fixtures ./fixtures
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./fixtures/otlp_trace_sample.json
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli assess
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli export-report --format html --output ./reports/report.html
```

---

## Architecture

```
 fixtures (*.yml)                 OTLP trace (*.json)
        |                                 |
        v                                 v
 config_loader.py                  trace_ingest.py
        |                                 |
        +-------------> SQLite (./data/app.db) <----------- models.py / db.py
                              |
                              v
                   risk_engine.py  --uses-->  rules/owasp_agentic.py (ASI01..ASI10)
                              |                          + scoring.py + redaction.py
                              v
                          Findings
                          /      \
                  report.py       app.py (FastAPI Web UI + JSON API)
              (JSON/MD/HTML)      graph.py (Mermaid)
```

- **Inventory layer** (Tenable-like): `Agent`, `User`, `Tool`, `Permission`,
  `DataSource`, `ApprovalPolicy`.
- **Runtime evidence layer** (OTLP-like): `RuntimeSpan`, `RuntimeToolCall`,
  `InterAgentMessage`, `MemoryOperation`.
- **Assessment layer**: `Finding`, `AssessmentRun`, scored and OWASP-tagged.

Connectors are pluggable (`connectors/`): the MVP ships a **fixture** config connector and
an **OTLP file** trace connector; cloud connectors (Copilot Studio, ChatGPT Enterprise,
and by analogy Dify / Bedrock / MCP) are documented stubs.

---

## Target data

| File | Purpose |
| --- | --- |
| `fixtures/agent_inventory.yml` | Agents, owners, exposure, allowed tools, data sources |
| `fixtures/tool_registry.yml` | Tools, category, risk level, approval, scopes, sandbox |
| `fixtures/permissions.yml` | Principal -> tool grants with scope and level |
| `fixtures/approval_policies.yml` | Per-tool human approval requirements |
| `fixtures/data_sources.yml` | RAG / memory / DB / file / web sources, PII, trust |
| `fixtures/users.yml` | Human principals (optional) |
| `fixtures/otlp_trace_sample.json` | OTLP-style runtime trace (native OTLP shape) |
| `fixtures/promptfoo_eval_sample.json` | Simplified flat-span trace (alternate shape) |

The OTLP ingester reads these span attributes (among others): `service.name`, `agent.name`,
`agent.id`, `gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.*`, `tool.name`,
`tool.arguments`, `tool.output`, `function.name`, `mcp.server.name`, `mcp.tool.name`,
`approval.required`, `approval.status`, `approval.approver`, `network.peer.address`,
`network.peer.port`, `network.protocol.name`, `tls.protocol.name`, `tls.cipher`,
`data.source.name`, `memory.operation`, `rag.query`, `rag.source`, `user.id`.

---

## OWASP Top 10 for Agentic Applications 2026 mapping

| Code | Category |
| --- | --- |
| ASI01 | Agent Goal and Instruction Manipulation |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain and Dependency Risks |
| ASI05 | Unexpected or Unauthorized Code Execution |
| ASI06 | Memory, RAG, and Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures and Uncontrolled Autonomy |
| ASI09 | Human-Agent Trust and Approval Exploitation |
| ASI10 | Rogue or Unmanaged Agents |

> Category codes/titles are constants in `owasp.py` so they are trivial to rename if the
> final published taxonomy differs.

### Implemented rules

| Rule ID | OWASP | What it detects |
| --- | --- | --- |
| ASI02-001 | ASI02 | Tool executed that is not in the agent's `allowed_tools` |
| ASI02-002 | ASI02 | Tool executed that is not in the tool registry (unknown tool) |
| ASI02-003 | ASI02 | Dangerous arguments (shell, URL, file path, credential, SQL write, external email) |
| ASI03-001 | ASI03 | Over-broad / wildcard permission scope |
| ASI03-002 | ASI03 | Permission level exceeds the tool's risk ceiling |
| ASI03-003 | ASI03 | Runtime credential scope outside the tool's `allowed_scopes` |
| ASI05-001 | ASI05 | shell / code_execution / file_system tool ran without approval |
| ASI05-002 | ASI05 | `sandbox_required=true` but no sandbox evidence in the trace |
| ASI05-003 | ASI05 | Dangerous command/path/URL pattern in code-exec tool arguments |
| ASI06-001 | ASI06 | Memory write from an untrusted source (poisoning) |
| ASI06-002 | ASI06 | Untrusted RAG context used without sanitization evidence |
| ASI07-001 | ASI07 | Inter-agent message without observed TLS |
| ASI07-002 | ASI07 | Data flow from a high-trust to a low-trust agent |
| ASI08-001 | ASI08 | Tool-call count per trace exceeds budget |
| ASI08-002 | ASI08 | Same tool retried beyond threshold |
| ASI08-003 | ASI08 | High-risk tool executed right after a failed tool call |
| ASI09-001 | ASI09 | `requires_approval=true` tool ran without observed approval |
| ASI09-002 | ASI09 | Tool ran with approval status other than `approved` (skipped/timeout/bypass/denied) |
| ASI10-001 | ASI10 | Unknown / unmanaged agent observed in traces |
| ASI10-002 | ASI10 | Inventoried agent with no owner |
| ASI10-003 | ASI10 | Publicly exposed agent holding high-risk tools |

ASI01 and ASI04 are reserved in `owasp.py` as extension points (no default rules in the MVP).

### Scoring

`risk_score = likelihood * impact * confidence` (each 1–5, range 1–125). Severity is
derived from the score: `critical >= 75`, `high >= 45`, `medium >= 20`, `low >= 8`, else
`info`. Per-agent and per-run totals are aggregated in `scoring.py`.

---

## CLI

```bash
python -m agentic_ai_exposure_assessor.cli init-fixtures
python -m agentic_ai_exposure_assessor.cli ingest-config --fixtures ./fixtures
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./fixtures/otlp_trace_sample.json
python -m agentic_ai_exposure_assessor.cli assess
python -m agentic_ai_exposure_assessor.cli export-report --format markdown --output ./reports/report.md
python -m agentic_ai_exposure_assessor.cli export-report --format html --output ./reports/report.html
python -m agentic_ai_exposure_assessor.cli export-report --format json --output ./reports/report.json
python -m agentic_ai_exposure_assessor.cli serve
```

`reset-db` drops/recreates all tables if you want a clean slate. The SQLite path can be
overridden with the `AAEA_DB_PATH` environment variable.

---

## Web UI

```bash
python -m agentic_ai_exposure_assessor.cli serve
# or directly with Uvicorn:
python -m uvicorn agentic_ai_exposure_assessor.app:app --reload --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>. The dashboard shows per-agent risk scores, OWASP
category counts, high-risk tools, tools executed without approval, unknown agents/tools,
top findings and Mermaid trace graphs. Endpoints:

`GET /`, `GET /agents`, `GET /tools`, `GET /traces`, `GET /findings`, `GET /owasp`,
`GET /reports/latest`, `GET /api/findings`, `POST /ingest/config`, `POST /ingest/traces`,
`POST /assess`.

---

## Fixtures (intentionally vulnerable sample)

- **customer-support-agent** — sends email without approval to an external recipient;
  connected to a PII-bearing `customer_db`; granted an over-broad `mail.*` scope.
- **devops-agent** — runs a shell command without approval, `sandbox_required` with no
  sandbox evidence, and reaches out to an unknown external IP with dangerous arguments
  (includes Windows paths `C:\Users\diag\Downloads\sample.txt` and `C:/Users/diag/...`).
- **rogue-agent** — not in the inventory but appears in the trace running an unknown tool.
- **public-web-agent** — public exposure while holding a high-risk `run_shell` tool; uses
  untrusted RAG content without sanitization.
- **analytics-agent** — runs `query_database` with a `db.admin` scope outside its
  `allowed_scopes`.
- **legacy-batch-agent** — inventoried with no owner.
- Inter-agent messages: one without TLS (high-trust -> low-trust) and one secured with TLS.
- A memory write from an untrusted source.

---

## Privacy & redaction

- Secret-like values (API keys, bearer tokens, passwords, private keys, provider key
  prefixes) are masked everywhere, including reports and stored evidence.
- Raw prompts and raw tool outputs are **not** stored verbatim — they are redacted and
  truncated into short summaries at ingest time.
- Emails can optionally be masked.

---

## Reports

Reports are written under `./reports` (created automatically):

- `report.md` — Markdown with the required chapters: Executive Summary, Scope, Agent
  Inventory, Tool & Permission Matrix, Runtime Trace Analysis, Approval Gate Analysis,
  OWASP Mapping, Findings, Recommendations, Appendix: Evidence (with Mermaid graphs).
- `report.html` — styled HTML with rendered Mermaid graphs.
- `report.json` — full machine-readable data.

---

## Tests

```bash
python -m pytest
# or, without activating the venv:
./.venv/Scripts/python.exe -m pytest
```

Lint / type-check (optional):

```bash
python -m ruff check .
python -m mypy src
```

---

## Known limitations

- MVP uses fixtures; no live cloud connectors yet (stubs only).
- Single-run semantics: each `assess` replaces prior findings; each ingest replaces prior
  data of the same type (use `--append` on `ingest-otlp` to keep runtime data).
- Heuristic detectors (dangerous arguments, secrets) favor over-flagging; tune thresholds
  in `rules/base.py` (`AssessmentContext`).
- ASI01 / ASI04 have no default rules yet.
- SQLite + in-process FastAPI; not intended for high-concurrency production use.

---

## Future extensions

- Connectors: Microsoft Copilot Studio, ChatGPT Enterprise, Dify, Amazon Bedrock Agents,
  MCP servers.
- Promptfoo trace import (first-class), richer trajectory rules (`tool-used`,
  `tool-args-match`, `tool-sequence`).
- OTLP ingestion via an OpenTelemetry Collector (gRPC/HTTP), in addition to JSON files.
- Graph database backend (Neo4j) for agent/tool/data-flow graphs.
- PDF report export.
- ASI01 / ASI04 rule packs (goal/instruction manipulation, supply-chain/dependency risk).
