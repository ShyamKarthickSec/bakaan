"""
agent01_collection.py
Agent 01 — Collection Control Agent
Decides collection depth based on real-time threat state.
The controlling variable is semantic threat context C, not traffic statistics.
This is what distinguishes the IPCF from IFS (Bartos & Rehak 2015) and Cyber-AnDe (TIFS 2024).
"""

from __future__ import annotations
import json
import logging
import time
from typing import Any, Dict

from agents.base_agent import BaseAgent
from core.annotation_envelope import CollectionDepth
from core.coordination_bus import CoordinationBus, BusMessage, MessageType
from core.threat_context import ThreatContextManager, ThreatLevel

logger = logging.getLogger("ipcf.agent01")

SYSTEM_PROMPT = """You are Agent 01 of the Intelligent Pre-Collection Fabric (IPCF),
a cybersecurity pre-normalisation telemetry system. Your role is Collection Control.

Given a telemetry source and the current threat state, decide the collection depth:
- metadata: source type, timestamp, host ID only. Use when threat is QUIESCENT.
- entity: metadata + process names, user IDs, connection endpoints. Use when threat is ALERT.
- full: all available fields including command lines, payloads, full network flows. Use when threat is ACTIVE.

Respond ONLY with valid JSON in this exact format:
{
  "depth": "metadata|entity|full",
  "priority": 0.0-1.0,
  "reasoning": "one sentence",
  "human_gate_required": true|false,
  "human_gate_reason": "reason or null"
}

Human gate is required ONLY for: full packet capture, regulated device monitoring.
Never require human gate for metadata or entity collection.
"""


class CollectionControlAgent(BaseAgent):
    """
    Agent 01 — Collection Control.
    Depth decision matrix:
      QUIESCENT → metadata
      ALERT     → entity
      ACTIVE    → full (human gate if regulated device)
    Human gate: full packet capture | regulated device full collection
    """

    # Deterministic fallback — used when LLM is unavailable
    DEPTH_MAP = {
        ThreatLevel.QUIESCENT: CollectionDepth.METADATA,
        ThreatLevel.ALERT: CollectionDepth.ENTITY,
        ThreatLevel.ACTIVE: CollectionDepth.FULL,
    }

    def __init__(self, bus: CoordinationBus, threat_ctx: ThreatContextManager):
        super().__init__("agent_01_collection", bus)
        self.threat_ctx = threat_ctx
        self._use_llm = True   # toggle for testing

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        host_id = event.get("source_id", "unknown")
        source_type = event.get("source_type", "unknown")
        is_regulated = event.get("is_regulated_device", False)

        # Get current threat state
        host_state = self.threat_ctx.get_host_state(host_id)
        threat_level = host_state.threat_level
        threat_score = host_state.threat_score

        depth, priority, human_gate, gate_reason, reasoning = \
            await self._decide_depth(host_id, source_type, threat_level,
                                     threat_score, is_regulated, host_state.active_ttps)

        latency = (time.time() - start) * 1000
        self._update_latency(latency)

        decision = {
            "collection_depth": depth.value,
            "priority_score": priority,
            "threat_state_at_collection": threat_score,
            "threat_level": threat_level.value,
            "human_gate_required": human_gate,
            "human_gate_reason": gate_reason,
            "reasoning": reasoning,
        }
        event.update(decision)
        self._record_decision({**decision, "host_id": host_id})

        await self._publish_decision(MessageType.DEPTH_DECISION, decision)

        if human_gate:
            logger.warning(f"[A01] Human gate triggered for {host_id}: {gate_reason}")
            await self.bus.publish(BusMessage(
                msg_type=MessageType.HUMAN_GATE_TRIGGERED,
                source_agent=self.agent_id,
                payload={
                    "host_id": host_id,
                    "reason": gate_reason,
                    "depth_requested": depth.value,
                    "event_id": event.get("event_id"),
                },
                priority=1,
            ))

        logger.debug(f"[A01] {host_id}: {threat_level.value} → {depth.value} "
                     f"(p={priority:.2f}, {latency:.1f}ms)")
        return event

    async def _decide_depth(
        self, host_id, source_type, threat_level, threat_score,
        is_regulated, active_ttps
    ):
        """Use LLM for nuanced decisions, fall back to rule-based if unavailable."""
        human_gate = False
        gate_reason = None

        if self._use_llm:
            try:
                result = await self._llm_depth_decision(
                    host_id, source_type, threat_level, threat_score,
                    is_regulated, active_ttps
                )
                if result:
                    depth = CollectionDepth(result["depth"])
                    priority = float(result["priority"])
                    human_gate = result.get("human_gate_required", False)
                    gate_reason = result.get("human_gate_reason")
                    reasoning = result.get("reasoning", "LLM decision")
                    return depth, priority, human_gate, gate_reason, reasoning
            except Exception as e:
                logger.warning(f"[A01] LLM failed, using rule-based: {e}")

        # Rule-based fallback
        depth = self.DEPTH_MAP[threat_level]
        priority = min(1.0, threat_score + 0.1)

        if depth == CollectionDepth.FULL and is_regulated:
            human_gate = True
            gate_reason = "Full collection on regulated device requires authorisation"

        reasoning = (f"Rule-based: {threat_level.value} threat → "
                     f"{depth.value} collection")
        return depth, priority, human_gate, gate_reason, reasoning

    async def _llm_depth_decision(
        self, host_id, source_type, threat_level, threat_score,
        is_regulated, active_ttps
    ) -> Dict | None:
        user_prompt = f"""Source: {host_id} ({source_type})
Threat level: {threat_level.value}
Threat score: {threat_score:.3f}
Regulated device: {is_regulated}
Active TTPs: {', '.join(active_ttps) if active_ttps else 'none'}

Decide collection depth and priority."""

        response = await self.call_llm(SYSTEM_PROMPT, user_prompt,
                                       temperature=0.1, max_tokens=256)
        if not response:
            return None
        # Parse JSON — strip markdown fences if present
        clean = response.strip().strip("```json").strip("```").strip()
        return json.loads(clean)
