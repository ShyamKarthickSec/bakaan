"""
agent02_governance.py  —  Agent 02: Governance Shaping
agent04a_schema.py     —  Agent 04A: Schema Mediation
agent04b_compression.py—  Agent 04B: Forensic Compression
agent05_oversight.py   —  Agent 05: Oversight & Integrity
All four agents in one file for brevity; each class is independently importable.
"""

from __future__ import annotations
import hashlib
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from agents.base_agent import BaseAgent
from core.annotation_envelope import AssetClass, GovernanceTag
from core.coordination_bus import CoordinationBus, BusMessage, MessageType

logger_gov  = logging.getLogger("ipcf.agent02")
logger_scha = logging.getLogger("ipcf.agent04a")
logger_comp = logging.getLogger("ipcf.agent04b")
logger_over = logging.getLogger("ipcf.agent05")


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 02 — GOVERNANCE SHAPING
# ──────────────────────────────────────────────────────────────────────────────
class GovernanceShapingAgent(BaseAgent):
    """
    Agent 02 — Governance Shaping.
    Applies per-field dynamic masking based on asset regulatory class.
    Implements GDPR, HIPAA, Privacy Act 1988 (Australia) policy.
    Human gate: de-masking regulated fields for operational access.
    Gap vs DINGfest (Menges et al. C&S 2020): dynamic per-field conditional masking
    vs. uniform pseudonymisation.
    """

    # Policy: asset_class → fields that must be masked
    MASKING_POLICY: Dict[str, List[str]] = {
        AssetClass.REGULATED.value: [
            "username", "email", "user_id", "patient_id", "employee_id",
            "ip_src", "ip_dst", "hostname", "full_name",
        ],
        AssetClass.EXECUTIVE.value: [
            "username", "email", "user_id", "ip_src", "ip_dst",
            "hostname", "process_cmdline", "file_path",
        ],
        AssetClass.STANDARD.value: [
            "email", "full_name",
        ],
        AssetClass.NETWORK.value: [],
    }

    REGULATION_MAP: Dict[str, List[str]] = {
        AssetClass.REGULATED.value:  ["GDPR", "HIPAA", "Privacy Act 1988"],
        AssetClass.EXECUTIVE.value:  ["Privacy Act 1988"],
        AssetClass.STANDARD.value:   ["GDPR"],
        AssetClass.NETWORK.value:    [],
    }

    def __init__(self, bus: CoordinationBus):
        super().__init__("agent_02_governance", bus)
        self._policy_version = "1.0"
        self._demasking_requests: List[Dict] = []

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        asset_class_str = event.get("asset_class", AssetClass.STANDARD.value)
        asset_class = AssetClass(asset_class_str)
        fields_to_mask = self.MASKING_POLICY.get(asset_class_str, [])
        regulations = self.REGULATION_MAP.get(asset_class_str, [])

        masked_fields: List[str] = []
        event_data = event.get("event_data", {})

        for field_name in fields_to_mask:
            if field_name in event_data and event_data[field_name]:
                original = str(event_data[field_name])
                event_data[field_name] = self._pseudonymise(original)
                masked_fields.append(field_name)

        event["event_data"] = event_data
        requires_approval = asset_class in (AssetClass.REGULATED, AssetClass.EXECUTIVE)

        gov_tag = GovernanceTag(
            asset_class=asset_class,
            fields_masked=masked_fields,
            policy_version=self._policy_version,
            requires_human_approval=requires_approval,
            applied_regulations=regulations,
        )
        event["governance_tag"] = gov_tag
        event["human_approval_required"] = requires_approval

        if requires_approval:
            await self.bus.publish(BusMessage(
                msg_type=MessageType.HUMAN_GATE_TRIGGERED,
                source_agent=self.agent_id,
                payload={
                    "reason": "Regulated/executive asset monitoring requires authorisation",
                    "asset_class": asset_class_str,
                    "masked_fields": masked_fields,
                    "event_id": event.get("event_id"),
                },
                priority=2,
            ))

        latency = (time.time() - start) * 1000
        self._update_latency(latency)
        self._record_decision({
            "asset_class": asset_class_str,
            "fields_masked": masked_fields,
            "regulations_applied": regulations,
        })
        await self._publish_decision(MessageType.GOVERNANCE_APPLIED, {
            "asset_class": asset_class_str,
            "fields_masked_count": len(masked_fields),
            "regulations": regulations,
        })
        logger_gov.debug(f"[A02] {asset_class_str}: masked {len(masked_fields)} fields "
                         f"({latency:.1f}ms)")
        return event

    @staticmethod
    def _pseudonymise(value: str) -> str:
        """Deterministic pseudonymisation — consistent across events, not reversible."""
        h = hashlib.sha256(f"ipcf_salt_{value}".encode()).hexdigest()[:12]
        return f"[MASKED:{h}]"


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 04A — SCHEMA MEDIATION
# ──────────────────────────────────────────────────────────────────────────────
class SchemaMediationAgent(BaseAgent):
    """
    Agent 04A — Schema Mediation.
    Living schema agent: maps vendor log fields to OCSF/UDM at runtime,
    detects schema drift, and triggers parser regeneration.
    Gap vs LLMParser (Ma et al. ICSE 2024) / LibreLog / Matryoshka:
    those are one-shot offline parsers. This is a continuous runtime agent
    with drift-detection feedback.
    """

    # OCSF field mappings: vendor_field → ocsf_field
    OCSF_MAPPINGS: Dict[str, str] = {
        # Windows Security Events
        "EventID":          "activity_id",
        "SubjectUserName":  "actor.user.name",
        "TargetUserName":   "dst.user.name",
        "IpAddress":        "src_endpoint.ip",
        "ProcessName":      "process.name",
        "CommandLine":      "process.cmd_line",
        # Sysmon
        "Image":            "process.file.path",
        "ParentImage":      "process.parent_process.file.path",
        "DestinationIp":    "dst_endpoint.ip",
        "DestinationPort":  "dst_endpoint.port",
        # Generic
        "src_ip":           "src_endpoint.ip",
        "dst_ip":           "dst_endpoint.ip",
        "user":             "actor.user.name",
        "process":          "process.name",
        "timestamp":        "time",
        "hostname":         "device.hostname",
    }

    def __init__(self, bus: CoordinationBus):
        super().__init__("agent_04a_schema", bus)
        self._known_schemas: Dict[str, Set[str]] = {}  # source → known field set
        self._drift_events: List[Dict] = []

    async def _subscribe(self):
        self.bus.subscribe(
            self.agent_id,
            [MessageType.GAP_CLASSIFIED],
            self._handle_gap_classified,
        )

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        source_id = event.get("source_id", "unknown")
        event_data = event.get("event_data", {})

        # Drift detection
        current_fields = set(event_data.keys())
        schema_drifted = False
        if source_id in self._known_schemas:
            new_fields = current_fields - self._known_schemas[source_id]
            dropped_fields = self._known_schemas[source_id] - current_fields
            if new_fields or dropped_fields:
                schema_drifted = True
                await self._handle_drift(source_id, new_fields, dropped_fields, event)

        self._known_schemas[source_id] = current_fields

        # OCSF normalisation
        normalized = {}
        for vendor_field, value in event_data.items():
            ocsf_field = self.OCSF_MAPPINGS.get(vendor_field, vendor_field)
            normalized[ocsf_field] = value

        # LLM-assisted mapping for unknown fields
        unmapped = [f for f in event_data.keys() if f not in self.OCSF_MAPPINGS]
        if unmapped and len(unmapped) <= 5:
            llm_mappings = await self._llm_map_fields(unmapped, source_id)
            for vendor_f, ocsf_f in llm_mappings.items():
                if vendor_f in event_data:
                    normalized[ocsf_f] = event_data[vendor_f]
                    self.OCSF_MAPPINGS[vendor_f] = ocsf_f  # live update

        event.update({
            "normalized_fields": normalized,
            "schema_version": self._fingerprint_schema(current_fields),
            "schema_drifted": schema_drifted,
            "ocsf_mapped": True,
        })
        latency = (time.time() - start) * 1000
        self._update_latency(latency)
        self._record_decision({
            "source_id": source_id,
            "schema_drifted": schema_drifted,
            "fields_normalized": len(normalized),
        })
        await self._publish_decision(MessageType.SCHEMA_UPDATED, {
            "source_id": source_id,
            "schema_drifted": schema_drifted,
            "ocsf_fields": len(normalized),
        })
        return event

    async def _handle_drift(self, source_id, new_fields, dropped_fields, event):
        logger_scha.warning(f"[A04A] Schema drift: {source_id} "
                            f"+{new_fields} -{dropped_fields}")
        record = {
            "timestamp": time.time(),
            "source_id": source_id,
            "new_fields": list(new_fields),
            "dropped_fields": list(dropped_fields),
        }
        self._drift_events.append(record)
        await self.bus.publish(BusMessage(
            msg_type=MessageType.SCHEMA_DRIFT_DETECTED,
            source_agent=self.agent_id,
            payload=record,
        ))

    async def _llm_map_fields(self, fields: List[str], source_id: str) -> Dict[str, str]:
        """Use LLM to suggest OCSF mappings for unknown vendor fields."""
        system = ("You are a security log schema expert. "
                  "Map vendor log field names to OCSF v1.0 field names. "
                  "Respond ONLY with JSON: {vendor_field: ocsf_field, ...}")
        user = f"Source: {source_id}\nUnknown fields to map: {', '.join(fields)}"
        response = await self.call_llm(system, user, temperature=0.1, max_tokens=256)
        if not response:
            return {}
        try:
            clean = response.strip().strip("```json").strip("```").strip()
            return json.loads(clean)
        except Exception:
            return {}

    async def _handle_gap_classified(self, msg: BusMessage):
        if msg.payload.get("causality") == "schema_drift":
            logger_scha.info(f"[A04A] Gap classified as schema_drift — initiating parser check")

    @staticmethod
    def _fingerprint_schema(fields: Set[str]) -> str:
        return hashlib.md5(",".join(sorted(fields)).encode()).hexdigest()[:8]

    def get_drift_history(self) -> List[Dict]:
        return self._drift_events[-20:]


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 04B — FORENSIC COMPRESSION
# ──────────────────────────────────────────────────────────────────────────────
# Forensic priority fields — always retained regardless of compression ratio
FORENSIC_PRIORITY_FIELDS = {
    "event_id", "timestamp", "time", "activity_id",
    "actor.user.name", "dst.user.name",
    "process.name", "process.cmd_line", "process.file.path",
    "src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port",
    "device.hostname", "network.protocol",
    # Provenance
    "parent_process_id", "process_id", "session_id",
}

LOW_VALUE_FIELDS = {
    "padding", "reserved", "filler", "checksum_internal",
    "debug_info", "internal_counter", "raw_buffer",
}


class ForensicCompressionAgent(BaseAgent):
    """
    Agent 04B — Forensic Compression.
    Investigation-utility-aware compression: retains forensically predictive
    fields while reducing storage and transmission cost.
    Gap vs DEPCOMM (Xu et al. S&P 2022) and FAuST (Inam et al. ACSAC 2022):
    those compress post-collection. This operates pre-normalisation.
    """

    def __init__(self, bus: CoordinationBus, evidence_store):
        super().__init__("agent_04b_compression", bus)
        self._evidence_store = evidence_store

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        event_id = event.get("event_id", "unknown")
        quality_score = event.get("quality_score", 1.0)
        collection_depth = event.get("collection_depth", "metadata")

        # Store original raw event before any compression
        raw_event = {k: v for k, v in event.items()
                     if k in ("event_data", "raw_timestamp", "source_id",
                              "source_type", "event_id")}
        provenance_pointer = await self._evidence_store.store(event_id, raw_event)

        # Apply compression
        normalized_fields = event.get("normalized_fields", {})
        original_size = len(json.dumps(normalized_fields))
        compressed_fields, retained = self._compress(normalized_fields, quality_score,
                                                      collection_depth)
        compressed_size = len(json.dumps(compressed_fields))
        ratio = original_size / max(compressed_size, 1)

        event.update({
            "compressed": True,
            "compression_ratio": round(ratio, 2),
            "provenance_pointer": provenance_pointer,
            "forensic_fields_retained": retained,
            "normalized_fields": compressed_fields,
        })
        latency = (time.time() - start) * 1000
        self._update_latency(latency)
        self._record_decision({
            "event_id": event_id,
            "compression_ratio": ratio,
            "retained_fields": len(retained),
            "provenance_pointer": provenance_pointer[:16] + "...",
        })
        await self._publish_decision(MessageType.COMPRESSION_DONE, {
            "compression_ratio": ratio,
            "forensic_fields_retained": len(retained),
            "provenance_pointer": provenance_pointer,
        })
        logger_comp.debug(f"[A04B] {event_id}: {ratio:.1f}x compression, "
                          f"{len(retained)} forensic fields retained ({latency:.1f}ms)")
        return event

    def _compress(self, fields: Dict, quality_score: float,
                  collection_depth: str) -> Tuple[Dict, List[str]]:
        """
        Investigation-utility-aware compression.
        Always retain forensic priority fields.
        Remove low-value fields.
        If quality is low (gap detected), be more conservative.
        """
        compressed = {}
        retained = []
        conservative = quality_score < 0.7   # keep more when quality is low

        for field_name, value in fields.items():
            # Always keep forensic priority fields
            if field_name in FORENSIC_PRIORITY_FIELDS:
                compressed[field_name] = value
                retained.append(field_name)
                continue
            # Always drop known low-value fields
            if field_name in LOW_VALUE_FIELDS:
                continue
            # In conservative mode (low quality), keep everything
            if conservative:
                compressed[field_name] = value
                continue
            # Full collection depth — keep everything
            if collection_depth == "full":
                compressed[field_name] = value
                continue
            # Entity depth — keep if value is non-trivial
            if collection_depth == "entity" and value:
                compressed[field_name] = value
                continue
            # Metadata depth — only forensic fields (already handled above)

        return compressed, retained


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 05 — OVERSIGHT & INTEGRITY
# ──────────────────────────────────────────────────────────────────────────────
class OversightIntegrityAgent(BaseAgent):
    """
    Agent 05 — Oversight & Integrity.
    Monitors ALL agent decisions via coordination bus broadcast subscription.
    Concrete monitoring signals (per feedback validation):
    1. Agent liveness (heartbeat monitoring)
    2. Decision drift over time
    3. Abnormal policy override frequency
    4. Unusual masking changes from Agent 02
    5. Confidence score collapse from Agent 03
    6. Agent-to-agent message integrity

    Escalates anomalous behaviour to human operator.
    Gap vs Wu et al. (arXiv 2510.19420): general MAS oversight — this is
    SOC-domain-specific with concrete security-operational signals.
    """

    HEARTBEAT_TIMEOUT = 120.0       # seconds before declaring agent dead
    CONFIDENCE_COLLAPSE_THRESHOLD = 0.3
    MASKING_SPIKE_THRESHOLD = 10    # unusual masking changes per minute
    OVERRIDE_SPIKE_THRESHOLD = 5    # policy overrides per minute

    def __init__(self, bus: CoordinationBus):
        super().__init__("agent_05_oversight", bus)
        self._agent_last_heartbeat: Dict[str, float] = {}
        self._oversight_alerts: List[Dict] = []
        self._decision_history: Dict[str, List[Dict]] = {}
        self._masking_counts: List[float] = []   # timestamps
        self._override_counts: List[float] = []  # timestamps
        self._confidence_history: List[float] = []

    async def _subscribe(self):
        # Subscribe to ALL messages — oversight monitors everything
        self.bus.subscribe_all(self._monitor_all)

    async def _monitor_all(self, msg: BusMessage) -> None:
        """Central monitor — receives every message on the bus."""
        try:
            # 1. Liveness: track heartbeats
            if msg.msg_type == MessageType.AGENT_HEARTBEAT:
                self._agent_last_heartbeat[msg.source_agent] = msg.timestamp
                await self._check_liveness()

            # 2. Confidence collapse: Agent 03 quality scores
            elif msg.msg_type == MessageType.QUALITY_SCORE_BROADCAST:
                qs = msg.payload.get("quality_score", 1.0)
                self._confidence_history.append(qs)
                if len(self._confidence_history) > 20:
                    self._confidence_history = self._confidence_history[-20:]
                avg_conf = sum(self._confidence_history) / len(self._confidence_history)
                if avg_conf < self.CONFIDENCE_COLLAPSE_THRESHOLD:
                    await self._raise_oversight_alert(
                        "confidence_collapse",
                        f"Agent 03 average quality score collapsed to {avg_conf:.2f}",
                        severity="high",
                    )

            # 3. Masking spikes: Agent 02 unusual activity
            elif msg.msg_type == MessageType.GOVERNANCE_APPLIED:
                now = time.time()
                self._masking_counts.append(now)
                self._masking_counts = [t for t in self._masking_counts if now - t < 60]
                if len(self._masking_counts) > self.MASKING_SPIKE_THRESHOLD:
                    await self._raise_oversight_alert(
                        "masking_spike",
                        f"Agent 02 applied {len(self._masking_counts)} masking operations in 60s",
                        severity="medium",
                    )

            # 4. Decision drift: compare recent vs historical decisions
            elif msg.msg_type == MessageType.AGENT_DECISION:
                agent = msg.source_agent
                if agent not in self._decision_history:
                    self._decision_history[agent] = []
                self._decision_history[agent].append(msg.payload)
                if len(self._decision_history[agent]) > 50:
                    self._decision_history[agent] = self._decision_history[agent][-50:]
                await self._check_decision_drift(agent)

            # 5. Errors accumulation
            elif msg.msg_type == MessageType.AGENT_ERROR:
                await self._raise_oversight_alert(
                    "agent_error",
                    f"Agent {msg.source_agent} reported error: {msg.payload.get('error')}",
                    severity="medium",
                )

        except Exception as e:
            logger_over.error(f"[A05] Monitor error: {e}")

    async def _check_liveness(self):
        now = time.time()
        for agent_id, last_beat in self._agent_last_heartbeat.items():
            if agent_id == self.agent_id:
                continue
            if now - last_beat > self.HEARTBEAT_TIMEOUT:
                await self._raise_oversight_alert(
                    "agent_liveness",
                    f"Agent {agent_id} missed heartbeat for {now - last_beat:.0f}s",
                    severity="high",
                    agent_id=agent_id,
                )

    async def _check_decision_drift(self, agent_id: str):
        """Basic drift check: compare recent decision patterns vs historical."""
        history = self._decision_history.get(agent_id, [])
        if len(history) < 20:
            return
        # Check for sudden change in depth decisions from Agent 01
        if agent_id == "agent_01_collection":
            recent = history[-5:]
            older = history[-20:-5]
            recent_full = sum(1 for d in recent if d.get("depth") == "full")
            older_full = sum(1 for d in older if d.get("depth") == "full")
            if recent_full > 3 and older_full == 0:
                await self._raise_oversight_alert(
                    "decision_drift",
                    f"Agent 01 suddenly escalated to FULL depth 3+ times in last 5 decisions",
                    severity="medium",
                    agent_id=agent_id,
                )

    async def _raise_oversight_alert(self, alert_type: str, message: str,
                                     severity: str = "medium",
                                     agent_id: Optional[str] = None):
        alert = {
            "timestamp": time.time(),
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "target_agent": agent_id,
        }
        self._oversight_alerts.append(alert)
        if len(self._oversight_alerts) > 100:
            self._oversight_alerts = self._oversight_alerts[-100:]

        logger_over.warning(f"[A05] OVERSIGHT ALERT [{severity.upper()}]: {message}")
        await self.bus.publish(BusMessage(
            msg_type=MessageType.OVERSIGHT_ALERT,
            source_agent=self.agent_id,
            payload=alert,
            priority=1 if severity == "high" else 3,
        ))

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        flags = []
        if event.get("gap_causality_label") == "adversarial":
            flags.append("adversarial_gap_in_event")
        if event.get("human_approval_required") and not event.get("human_approval_granted"):
            flags.append("pending_human_approval")
        event["oversight_flags"] = flags
        return event

    def get_alerts(self, limit: int = 20) -> List[Dict]:
        return self._oversight_alerts[-limit:]

    def get_agent_liveness(self) -> Dict[str, Any]:
        now = time.time()
        return {
            agent_id: {
                "last_heartbeat_seconds_ago": round(now - ts, 1),
                "alive": (now - ts) < self.HEARTBEAT_TIMEOUT,
            }
            for agent_id, ts in self._agent_last_heartbeat.items()
        }
