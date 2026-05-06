"""
main.py — IPCF FastAPI Application
Wires all agents together, exposes REST API for event processing,
dashboard data, threat context updates, human gate approvals,
and benchmark control.
"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("ipcf.api")

# ── Imports (project modules) ─────────────────────────────────────────────────
from core.coordination_bus import CoordinationBus, BusMessage, MessageType
from core.annotation_envelope import (
    AnnotationEnvelope, CollectionDepth, GapCausalityLabel, AssetClass
)
from core.threat_context import ThreatContextManager
from core.raw_evidence_store import RawEvidenceStore
from agents.agent01_collection import CollectionControlAgent
from agents.agent03_gap_causality import GapCausalityAgent
from agents.agents_remaining import (
    GovernanceShapingAgent, SchemaMediationAgent,
    ForensicCompressionAgent, OversightIntegrityAgent,
)

# ── Global singletons ─────────────────────────────────────────────────────────
bus = CoordinationBus()
threat_ctx = ThreatContextManager(
    high_threshold=float(os.getenv("THREAT_HIGH_THRESHOLD", 0.7)),
    medium_threshold=float(os.getenv("THREAT_MEDIUM_THRESHOLD", 0.4)),
)
evidence_store = RawEvidenceStore(
    store_dir=os.getenv("RAW_EVIDENCE_DIR", "./data/raw_evidence")
)

# Instantiate all five agents
agent01 = CollectionControlAgent(bus, threat_ctx)
agent02 = GovernanceShapingAgent(bus)
agent03 = GapCausalityAgent(bus, threat_ctx)
agent04a = SchemaMediationAgent(bus)
agent04b = ForensicCompressionAgent(bus, evidence_store)
agent05 = OversightIntegrityAgent(bus)

ALL_AGENTS = [agent01, agent02, agent03, agent04a, agent04b, agent05]

# Processing metrics
_processed_events: List[Dict] = []
_processing_stats = {
    "total_events": 0,
    "gaps_detected": 0,
    "adversarial_gaps": 0,
    "infra_failures": 0,
    "schema_drifts": 0,
    "human_gates_triggered": 0,
    "avg_latency_ms": 0.0,
}


# ── Startup / shutdown ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting IPCF fabric...")
    for agent in ALL_AGENTS:
        await agent.start()
    logger.info("All agents started. IPCF fabric running.")
    yield
    logger.info("Shutting down IPCF fabric...")
    for agent in ALL_AGENTS:
        await agent.stop()


app = FastAPI(
    title="IPCF — Intelligent Pre-Collection Fabric",
    description="Multi-agent pre-normalisation telemetry governance system",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic request models ───────────────────────────────────────────────────
class TelemetryEvent(BaseModel):
    source_id: str
    source_type: str = "endpoint"
    host_id: Optional[str] = None
    raw_timestamp: str = ""
    event_data: Dict[str, Any] = {}
    asset_class: str = AssetClass.STANDARD.value
    is_regulated_device: bool = False
    network_path_fault: bool = False
    field_type_mismatch: bool = False
    unknown_fields: Optional[str] = None
    inject_gap: bool = False            # for testing
    gap_injection_type: Optional[str] = None  # adversarial|infra_failure|schema_drift


class ThreatUpdate(BaseModel):
    host_id: str
    threat_score: float
    active_ttps: List[str] = []
    investigation_active: bool = False


class HumanApproval(BaseModel):
    event_id: str
    approved: bool
    approved_by: str
    reason: str = ""


class BenchmarkConfig(BaseModel):
    dataset: str = "lanl"
    n_events: int = 100
    inject_adversarial: int = 10
    inject_infra: int = 10
    inject_schema: int = 10


# ── Core event processing pipeline ───────────────────────────────────────────
async def process_event_through_fabric(event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run event through all five agents in sequence.
    A01 → A03 → A02 → A04A → A04B → A05
    Each agent adds fields to the event dict.
    """
    start = time.time()
    event_dict["event_id"] = event_dict.get("event_id", str(uuid.uuid4()))
    event_dict["host_id"] = event_dict.get("host_id") or event_dict["source_id"]

    # Publish ingestion to bus
    await bus.publish(BusMessage(
        msg_type=MessageType.EVENT_INGESTED,
        source_agent="fabric_ingress",
        payload={"source_id": event_dict["source_id"],
                 "event_id": event_dict["event_id"]},
    ))

    # Pipeline
    event_dict = await agent01.process(event_dict)   # collection depth
    event_dict = await agent03.process(event_dict)   # gap causality ★
    event_dict = await agent02.process(event_dict)   # governance shaping
    event_dict = await agent04a.process(event_dict)  # schema mediation
    event_dict = await agent04b.process(event_dict)  # forensic compression
    event_dict = await agent05.process(event_dict)   # oversight flags

    latency = (time.time() - start) * 1000
    event_dict["fabric_processing_latency_ms"] = round(latency, 2)

    # Update global stats
    _processing_stats["total_events"] += 1
    if event_dict.get("gap_detected"):
        _processing_stats["gaps_detected"] += 1
        label = event_dict.get("gap_causality_label", "none")
        if label == GapCausalityLabel.ADVERSARIAL.value:
            _processing_stats["adversarial_gaps"] += 1
        elif label == GapCausalityLabel.INFRA_FAILURE.value:
            _processing_stats["infra_failures"] += 1
        elif label == GapCausalityLabel.SCHEMA_DRIFT.value:
            _processing_stats["schema_drifts"] += 1
    if event_dict.get("human_gate_required"):
        _processing_stats["human_gates_triggered"] += 1

    # Rolling avg latency
    prev = _processing_stats["avg_latency_ms"]
    n = _processing_stats["total_events"]
    _processing_stats["avg_latency_ms"] = round(
        ((prev * (n - 1)) + latency) / n, 2
    )

    # Keep recent event log for dashboard
    _processed_events.append({
        "event_id": event_dict["event_id"],
        "source_id": event_dict["source_id"],
        "timestamp": time.time(),
        "gap_detected": event_dict.get("gap_detected", False),
        "gap_causality_label": event_dict.get("gap_causality_label", "none"),
        "quality_score": event_dict.get("quality_score", 1.0),
        "collection_depth": event_dict.get("collection_depth", "metadata"),
        "latency_ms": latency,
    })
    if len(_processed_events) > 500:
        _processed_events.pop(0)

    await bus.publish(BusMessage(
        msg_type=MessageType.ENVELOPE_READY,
        source_agent="fabric_egress",
        payload={"event_id": event_dict["event_id"],
                 "latency_ms": latency,
                 "quality_score": event_dict.get("quality_score", 1.0)},
    ))
    return event_dict


# ── REST API endpoints ────────────────────────────────────────────────────────

@app.post("/api/event", summary="Process a telemetry event through the fabric")
async def process_event(event: TelemetryEvent) -> JSONResponse:
    """
    Main event ingestion endpoint.
    Runs event through all five agents and returns the annotation envelope.
    """
    try:
        event_dict = event.model_dump()
        result = await process_event_through_fabric(event_dict)

        # Serialise GovernanceTag if present
        if hasattr(result.get("governance_tag"), "to_dict" if False else "__class__"):
            gt = result["governance_tag"]
            result["governance_tag"] = {
                "asset_class": gt.asset_class.value,
                "fields_masked": gt.fields_masked,
                "policy_version": gt.policy_version,
                "requires_human_approval": gt.requires_human_approval,
                "applied_regulations": gt.applied_regulations,
            }
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Event processing failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/threat-context", summary="Update threat state for a host")
async def update_threat_context(update: ThreatUpdate):
    """
    Called by SIEM webhook (or benchmark harness) to update host threat state.
    This feeds Agent 01's collection depth decisions.
    """
    state = await threat_ctx.update_host_threat(
        host_id=update.host_id,
        threat_score=update.threat_score,
        active_ttps=update.active_ttps,
        investigation_active=update.investigation_active,
    )
    return {"status": "updated", "host_id": update.host_id,
            "threat_level": state.threat_level.value}


@app.post("/api/human-gate/approve", summary="Human operator approval/denial")
async def human_gate_decision(approval: HumanApproval):
    """Human operator approves or denies a gate-triggered action."""
    msg_type = (MessageType.HUMAN_APPROVAL_GRANTED if approval.approved
                else MessageType.HUMAN_APPROVAL_DENIED)
    await bus.publish(BusMessage(
        msg_type=msg_type,
        source_agent="human_operator",
        payload={
            "event_id": approval.event_id,
            "approved_by": approval.approved_by,
            "reason": approval.reason,
        },
        priority=1,
    ))
    return {"status": "approved" if approval.approved else "denied",
            "event_id": approval.event_id}


@app.get("/api/dashboard/stats", summary="Real-time fabric statistics")
async def get_stats():
    """Dashboard: aggregate stats for all agents and fabric."""
    return {
        "fabric_stats": _processing_stats,
        "bus_stats": bus.get_stats(),
        "threat_context": threat_ctx.get_all_states(),
        "evidence_store": evidence_store.get_stats(),
        "agents": {
            a.agent_id: a.health.to_dict() for a in ALL_AGENTS
        },
        "oversight_alerts": agent05.get_alerts(10),
        "agent_liveness": agent05.get_agent_liveness(),
        "timestamp": time.time(),
    }


@app.get("/api/dashboard/events", summary="Recent processed events")
async def get_recent_events(limit: int = 50):
    return {"events": _processed_events[-limit:]}


@app.get("/api/dashboard/gaps", summary="Gap detection history")
async def get_gap_history():
    return {
        "gaps": agent03.get_gap_history(),
        "baselines": agent03.get_baselines_summary(),
    }


@app.get("/api/dashboard/schema", summary="Schema drift history")
async def get_schema_history():
    return {"drift_events": agent04a.get_drift_history()}


@app.get("/api/bus/messages", summary="Recent coordination bus messages")
async def get_bus_messages(limit: int = 50):
    return {"messages": bus.get_recent_messages(limit)}


@app.post("/api/benchmark/run", summary="Run benchmark evaluation")
async def run_benchmark(config: BenchmarkConfig, background_tasks: BackgroundTasks):
    """Start a benchmark run in the background."""
    background_tasks.add_task(_run_benchmark, config)
    return {"status": "started", "config": config.model_dump()}


async def _run_benchmark(config: BenchmarkConfig):
    """Background benchmark task."""
    from benchmark.injector import GapInjector
    from benchmark.evaluator import BenchmarkEvaluator

    logger.info(f"Starting benchmark: {config.n_events} events, "
                f"dataset={config.dataset}")
    injector = GapInjector()
    evaluator = BenchmarkEvaluator()

    events = injector.generate_events(
        n_normal=config.n_events,
        n_adversarial=config.inject_adversarial,
        n_infra=config.inject_infra,
        n_schema=config.inject_schema,
    )
    for event_dict, true_label in events:
        result = await process_event_through_fabric(event_dict)
        predicted = result.get("gap_causality_label", "none")
        evaluator.record(true_label, predicted)

    report = evaluator.compute_metrics()
    logger.info(f"Benchmark complete: {report}")

    # Store results
    import json
    from pathlib import Path
    results_path = Path("./data/benchmark_results.json")
    results_path.parent.mkdir(exist_ok=True)
    results_path.write_text(json.dumps(report, indent=2))


@app.get("/api/benchmark/results", summary="Latest benchmark results")
async def get_benchmark_results():
    from pathlib import Path
    p = Path("./data/benchmark_results.json")
    if not p.exists():
        return {"status": "no_results_yet"}
    return json.loads(p.read_text())


@app.get("/health")
async def health():
    return {"status": "ok", "agents": len(ALL_AGENTS),
            "total_events_processed": _processing_stats["total_events"]}


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the monitoring dashboard."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "../dashboard/index.html")
    with open(dashboard_path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=int(os.getenv("API_PORT", 8000)),
        reload=False,
        log_level="info",
    )
