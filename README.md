# IPCF Research Prototype

Intelligent Pre-Collection Fabric (IPCF) is a research prototype for SOC telemetry mediation before events reach a SIEM or downstream analytics pipeline. The prototype demonstrates raw evidence preservation, multi-agent event processing, gap causality reasoning, governance shaping, schema mediation, forensic compression, oversight, and benchmark evaluation.

This is not a production SOC product. It is a working research scaffold designed to make the architecture testable and explainable.

## What Has Been Built So Far

The current prototype includes:

- A FastAPI application that exposes telemetry ingestion, threat context updates, human gate decisions, dashboard data, and benchmark controls.
- A coordination bus used by agents to publish decisions, heartbeats, alerts, and processing events.
- A write-once raw evidence store that saves raw telemetry before compression/forwarding and returns a SHA-256 provenance pointer.
- A structured annotation envelope that acts as the output contract between IPCF and downstream SIEM-style tooling.
- Agent 01, Collection Control, for adaptive collection depth based on threat context.
- Agent 02, Governance Shaping, for policy-aware field masking and regulated/executive asset handling.
- Agent 03, Gap Causality Classifier, which is the main research contribution. It classifies telemetry gaps as `none`, `adversarial`, `infra_failure`, or `schema_drift`.
- Agent 04A, Schema Mediation, for runtime field mapping and schema drift detection.
- Agent 04B, Forensic Compression, for investigation-aware compression while preserving provenance.
- Agent 05, Oversight and Integrity, for liveness, decision drift, confidence collapse, masking spikes, and agent error monitoring.
- A benchmark injector that generates labelled normal, adversarial, infrastructure failure, and schema drift events.
- A benchmark evaluator that computes accuracy, per-class precision/recall/F1, macro F1, adversarial F1, confusion matrix, and binary gap-flagging comparison.
- A simple browser dashboard in `dashboard/index.html`.
- Docker and Docker Compose setup for running the API.
- Existing generated artifacts under `data/raw_evidence/` and `data/benchmark_results.json`.

## Repository Layout

```text
ipcf/
  api/
    main.py                  FastAPI app and event-processing pipeline
  agents/
    base_agent.py            Shared async agent base class and DeepSeek client
    agent01_collection.py    Agent 01 collection depth control
    agent03_gap_causality.py Agent 03 gap causality classifier
    agents_remaining.py      Agents 02, 04A, 04B, and 05
  benchmark/
    injector.py              Labelled benchmark event generation
    evaluator.py             Benchmark metrics and reports
  core/
    annotation_envelope.py   Annotation envelope dataclasses/enums
    coordination_bus.py      Internal event bus
    raw_evidence_store.py    Write-once raw evidence store
    threat_context.py        Host threat context manager
  dashboard/
    index.html               Simple monitoring UI
  data/
    raw_evidence/            Stored immutable raw-event evidence files
    benchmark_results.json   Latest benchmark output
  Dockerfile
  docker-compose.yml
  requirements.txt
```

## Architecture Flow

The implemented pipeline follows the intended IPCF event flow:

```text
Telemetry event
  -> coordination bus ingestion message
  -> Agent 01: collection control
  -> Agent 03: gap causality and telemetry quality
  -> Agent 02: governance shaping and masking
  -> Agent 04A: schema mediation
  -> Agent 04B: forensic compression and raw evidence storage
  -> Agent 05: oversight flags
  -> annotation-style processed event returned to API caller
```

Raw evidence is persisted by Agent 04B through `RawEvidenceStore` before compressed output is finalised. The output includes a `provenance_pointer` so investigators can retrieve the raw event with an audited access request.

## Environment

Create a local `.env` file in the project root:

```env
DEEPSEEK_API_KEY=your_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
API_PORT=8000
RAW_EVIDENCE_DIR=./data/raw_evidence
THREAT_HIGH_THRESHOLD=0.7
THREAT_MEDIUM_THRESHOLD=0.4
```

The agents use the OpenAI-compatible SDK pointed at DeepSeek. If the model call fails, Agent 01 and Agent 03 include deterministic rule-based fallback logic.

## Install Locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run the API

```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Then open:

```text
http://localhost:8000/
http://localhost:8000/health
```

## Run with Docker

```bash
docker compose up --build
```

The API is exposed on port `8000`, and local `data/` is mounted into the container.

## Main API Endpoints

- `POST /api/event` - process one telemetry event through the IPCF fabric.
- `POST /api/threat-context` - update host threat score/TTP state for Agent 01 and Agent 03.
- `POST /api/human-gate/approve` - simulate a human approval or denial decision.
- `GET /api/dashboard/stats` - aggregate agent, bus, evidence store, and fabric stats.
- `GET /api/dashboard/events` - recent processed events.
- `GET /api/dashboard/gaps` - Agent 03 gap history and baselines.
- `GET /api/dashboard/schema` - Agent 04A schema drift history.
- `GET /api/bus/messages` - recent coordination bus messages.
- `POST /api/benchmark/run` - start a benchmark run in the background.
- `GET /api/benchmark/results` - retrieve the latest stored benchmark report.

## Example Event

```json
{
  "source_id": "host_7",
  "source_type": "endpoint",
  "host_id": "host_7",
  "raw_timestamp": "2026-07-01T10:00:00Z",
  "asset_class": "standard",
  "is_regulated_device": false,
  "event_data": {
    "EventID": 4688,
    "SubjectUserName": "alice",
    "IpAddress": "192.168.1.25",
    "ProcessName": "powershell.exe",
    "CommandLine": "powershell -enc ..."
  }
}
```

Submit it with:

```bash
curl -X POST http://localhost:8000/api/event ^
  -H "Content-Type: application/json" ^
  -d "{\"source_id\":\"host_7\",\"source_type\":\"endpoint\",\"event_data\":{\"EventID\":4688,\"SubjectUserName\":\"alice\",\"IpAddress\":\"192.168.1.25\",\"ProcessName\":\"powershell.exe\"}}"
```

## Benchmarking

The benchmark framework is focused on Agent 03.

It generates labelled events for:

- normal telemetry
- adversarial log suppression
- infrastructure failure
- schema drift

Run a benchmark through the API:

```bash
curl -X POST http://localhost:8000/api/benchmark/run ^
  -H "Content-Type: application/json" ^
  -d "{\"n_events\":100,\"inject_adversarial\":10,\"inject_infra\":10,\"inject_schema\":10}"
```

Fetch results:

```bash
curl http://localhost:8000/api/benchmark/results
```

The evaluator reports:

- total events
- overall accuracy
- macro F1
- adversarial F1, the primary research metric
- adversarial precision and recall
- per-class precision/recall/F1
- confusion matrix
- binary gap-flagging baseline comparison

## Current Output Artifacts

The prototype already contains generated local artifacts:

- `data/raw_evidence/*.json` - immutable raw-event evidence files addressed by SHA-256 pointer.
- `data/raw_evidence/access_log.jsonl` - audited retrieval log, created when retrieval is used.
- `data/benchmark_results.json` - latest benchmark report.

These are local experiment artifacts, not curated datasets.

## Research Contribution Captured

The strongest implemented research slice is Agent 03:

- Telemetry absence is treated as a first-class security signal.
- Gaps are classified by likely cause rather than only flagged as missing.
- The benchmark evaluates multi-class gap causality and highlights adversarial F1 as the main metric.
- Gap causality output is propagated through the annotation/event result so downstream analytics can consume it.

## Known Limitations

- The system is a prototype and should not be treated as production ready.
- Persistence is local file-based rather than backed by an enterprise datastore.
- Human gate approval is represented through API messages, not a full workflow UI.
- Agent 02, Agent 04A, Agent 04B, and Agent 05 are functional but intentionally compact.
- DeepSeek calls depend on a valid `.env` and network access; rule-based fallbacks exist for key decisions.
- The benchmark is synthetic and should be expanded with larger datasets and repeatable experiment scripts.
- Raw evidence files are made read-only locally, but this is not equivalent to production-grade WORM storage.

## Suggested Next Steps

1. Add unit and integration tests for the API pipeline, evidence retrieval, and benchmark evaluator.
2. Add a command-line benchmark runner so experiments can be executed without starting FastAPI.
3. Store processed annotation envelopes in a dedicated downstream mock store.
4. Add explicit fail-safe fallback behavior if an agent raises an exception mid-pipeline.
5. Improve benchmark reporting with CSV/JSON export per run and experiment IDs.
6. Add a small labelled benchmark fixture committed under `benchmark/datasets/`.
7. Separate Agents 02, 04A, 04B, and 05 into individual files once the design stabilises.
