# BAKAAN: Intelligent Pre-Collection Fabric

BAKAAN is a research prototype for an Intelligent Pre-Collection Fabric (IPCF) for autonomous cyber defense in Security Operations Centres (SOCs).

The central idea is that the layer before SIEM ingestion is currently passive, schema-dependent, and unintelligent. Raw telemetry sources send logs into collection and normalisation pipelines, but missing logs, parser failures, schema drift, privacy-sensitive fields, and adversarial log suppression often arrive silently. The IPCF treats this pre-normalisation boundary as a coordination and decision problem rather than a dumb pipe.

This repository is a working prototype of that idea. It is not a production SOC platform.

## Research Motivation

Modern SOCs already use SIEMs, UEBA, ML detectors, SOAR workflows, and increasingly LLM/agent-based triage. Most of these systems operate after ingestion, assuming that upstream telemetry is complete, parseable, and trustworthy.

The research gap explored here is:

```text
Raw sources -> [missing intelligence here] -> SIEM normalisation -> analytics -> analyst/SOAR
```

The IPCF sits in that missing region. It asks whether telemetry should be actively mediated before it enters the SIEM pipeline.

## Research Questions

The prototype is aligned with three research questions from the project presentation:

1. How can a coordinated multi-agent system control security telemetry prior to its entry into the normalisation pipeline, and what architecture should it have?
2. Is the lack of telemetry a security signal that can differentiate between infrastructure failure, adversary suppression, and schema drift?
3. How should autonomous agents and human operators share control over irreversible pre-collection decisions?

## Core Research Claim

The main scholarly claim is Agent 03: telemetry gap causality.

Instead of treating missing data as merely absent, the fabric classifies the likely cause of a telemetry gap:

- `adversarial`: attacker-induced logging suppression, aligned with MITRE ATT&CK T1562-style behaviour.
- `infra_failure`: collector, parser, network path, or pipeline failure.
- `schema_drift`: vendor or source format changed and the parser no longer matches.
- `none`: no gap detected.

The intended research contribution is not simply "detect missing logs." It is to make the cause of telemetry absence explicit, quantifiable, and consumable by downstream analytics.

## What Has Been Built So Far

The current implementation includes:

- A FastAPI application for telemetry ingestion, dashboard data, human gate simulation, threat-context updates, and benchmark control.
- An async coordination bus for agent decisions, heartbeats, alerts, and inter-agent messages.
- A write-once raw evidence store that persists raw event evidence and returns a SHA-256 provenance pointer.
- An annotation envelope model that carries quality, gap, provenance, collection, governance, and oversight fields.
- Agent 01, Collection Control, for threat-state-driven collection depth decisions.
- Agent 02, Governance Shaping, for privacy-aware masking and regulated/executive asset handling.
- Agent 03, Gap Causality Classifier, the main research contribution.
- Agent 04A, Schema Mediation, for OCSF-style field mapping and runtime schema drift detection.
- Agent 04B, Forensic Compression, for investigation-aware compression while preserving raw evidence provenance.
- Agent 05, Oversight and Integrity, for monitoring liveness, decision drift, confidence collapse, masking spikes, and agent errors.
- A synthetic benchmark injector for normal, adversarial, infrastructure failure, and schema drift events.
- A benchmark evaluator that computes precision, recall, F1, adversarial F1, macro F1, confusion matrix, and binary gap-flagging comparison.
- Docker and Docker Compose support.
- A simple dashboard in `dashboard/index.html`.

## Architecture Mapping

The current prototype maps to the IPCF architecture as follows:

```text
Layer A: raw telemetry sources
  -> API event ingestion
  -> coordination bus
  -> Agent 01: collection control
  -> Agent 03: data quality and gap causality
  -> Agent 02: governance shaping
  -> Agent 04A: schema mediation
  -> Agent 04B: provenance-preserving compression
  -> Agent 05: oversight and integrity
  -> annotated output for downstream SIEM-style use
```

Raw evidence preservation is handled by `core/raw_evidence_store.py`. The evidence pointer is attached to processed output so compressed or governed records can still be traced back to raw telemetry.

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
    raw_evidence/            Stored raw-event evidence files
    benchmark_results.json   Latest benchmark output
  Dockerfile
  docker-compose.yml
  requirements.txt
```

## Agent Summary

### Agent 01: Collection Control

Controls collection depth based on semantic threat state rather than simple traffic rarity or static policy.

Current depth levels:

- `metadata`
- `entity`
- `full`

This implements the research claim that adaptive collection should be driven by real-time security context, not only sampling-rate optimisation.

### Agent 02: Governance Shaping

Applies dynamic per-field masking based on asset class:

- standard
- regulated
- executive
- network

This supports context-sensitive privacy governance rather than uniform pseudonymisation.

### Agent 03: Gap Causality Classifier

Classifies telemetry gaps into:

- adversarial suppression
- infrastructure failure
- schema drift
- no gap

This is the primary research component and the first part to benchmark seriously.

### Agent 04A: Schema Mediation

Maps vendor fields to common OCSF-style names and detects schema drift when fields appear or disappear.

### Agent 04B: Forensic Compression

Compresses normalised telemetry while preserving forensically important fields and storing raw evidence before final output.

### Agent 05: Oversight and Integrity

Monitors the multi-agent system itself: heartbeats, decision drift, confidence collapse, governance activity, and errors.

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

The agents use the OpenAI-compatible SDK pointed at DeepSeek. Agent 01 and Agent 03 include deterministic fallback logic when LLM calls fail.

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

- `POST /api/event` - process one telemetry event through the fabric.
- `POST /api/threat-context` - update host threat score and active TTPs.
- `POST /api/human-gate/approve` - simulate human approval or denial.
- `GET /api/dashboard/stats` - fabric, agent, bus, and evidence-store stats.
- `GET /api/dashboard/events` - recent processed events.
- `GET /api/dashboard/gaps` - Agent 03 gap history and baselines.
- `GET /api/dashboard/schema` - Agent 04A schema drift history.
- `GET /api/bus/messages` - recent coordination bus messages.
- `POST /api/benchmark/run` - start a benchmark run in the background.
- `GET /api/benchmark/results` - retrieve the latest benchmark report.

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

PowerShell example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8000/api/event `
  -ContentType "application/json" `
  -Body '{"source_id":"host_7","source_type":"endpoint","event_data":{"EventID":4688,"SubjectUserName":"alice","IpAddress":"192.168.1.25","ProcessName":"powershell.exe"}}'
```

## Benchmarking the Research Claim

The benchmark framework is currently centred on Agent 03.

The synthetic injector creates labelled events for:

- normal telemetry
- adversarial log suppression
- infrastructure failure
- schema drift

Run a benchmark through the API:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8000/api/benchmark/run `
  -ContentType "application/json" `
  -Body '{"n_events":100,"inject_adversarial":10,"inject_infra":10,"inject_schema":10}'
```

Fetch the result:

```powershell
Invoke-RestMethod http://localhost:8000/api/benchmark/results
```

The benchmark reports:

- total events
- overall accuracy
- macro F1
- adversarial F1
- adversarial precision and recall
- per-class precision, recall, and F1
- confusion matrix
- binary gap-flagging baseline comparison

The adversarial class F1 is the most important metric because it measures whether the fabric can distinguish attacker-induced log suppression from benign pipeline failure.

## Intended Evaluation Plan

The presentation frames evaluation in four layers:

1. Agent 03 gap causality: three-class precision, recall, and F1 across adversarial suppression, infrastructure failure, and schema drift.
2. Downstream impact: compare provenance-based detection with and without gap annotations.
3. Collection control: compare static collection against threat-state-driven depth escalation.
4. Governance shaping: measure field exposure violations and compliance behaviour under regulated asset scenarios.

Potential datasets named in the research plan include:

- Microsoft SimuLand and OTRF Security Datasets
- LANL Comprehensive Cyber-Security Events
- Azure Sentinel sample data
- Splunk Attack Data repository
- UNSW-NB15 and CICIDS 2017

The current repository has the synthetic injection harness. Real dataset integration is future work.

## Current Output Artifacts

The repository currently contains local experiment artifacts:

- `data/raw_evidence/*.json`
- `data/raw_evidence/access_log.jsonl`, once retrieval is used
- `data/benchmark_results.json`

These files are generated evidence/results from local runs and should not be treated as a curated benchmark dataset.

## What Is Still Prototype-Grade

- The benchmark is synthetic and should be expanded with real datasets.
- Agent 03 needs stronger temporal modelling for actual missing-event windows.
- The downstream KAIROS/MAGIC comparison is not implemented yet.
- Human gate control exists as API messages, not a full operator workflow.
- The raw evidence store is local file-based, not production WORM storage.
- Fail-safe raw forwarding should be hardened around each individual agent.
- Agent 02, Agent 04A, Agent 04B, and Agent 05 are functional but compact and should be separated into dedicated modules.

## Suggested Next Development Steps

1. Add a command-line benchmark runner that does not require the FastAPI server.
2. Add integration tests for `/api/event`, `/api/benchmark/run`, and evidence retrieval.
3. Add explicit per-agent fail-safe fallback so a single agent failure still forwards raw evidence with a minimal envelope.
4. Implement a stronger temporal gap simulator that can model silence windows instead of single-event labels.
5. Persist processed annotation envelopes to a downstream mock SIEM store.
6. Add experiment run IDs and write benchmark reports under `data/benchmark_runs/`.
7. Create a small committed benchmark fixture under `benchmark/datasets/`.
8. Integrate at least one real public dataset slice for preliminary evaluation.
