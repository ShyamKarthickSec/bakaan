"""
agent03_gap_causality.py
Agent 03 — Data Quality Assurance + Gap Causality Classifier
★ PRIMARY RESEARCH CONTRIBUTION ★

Treats telemetry absence as a first-class security signal.
Classifies gaps into three categories:
  - adversarial:    attacker-induced log suppression (T1562 sub-techniques)
  - infra_failure:  broken pipe, parser error, network path interruption
  - schema_drift:   vendor changed log format silently

No prior peer-reviewed system proposes gap causality as a classifier target.
Reference: Mukherjee et al. USENIX Security 2023 (demonstrates the attack);
           eAudit Sekar et al. IEEE S&P 2024 (demonstrates the mechanism);
           MAGIC Jia et al. USENIX Security 2024 (acknowledges quality dependency).
"""

from __future__ import annotations
import asyncio
import collections
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

from agents.base_agent import BaseAgent
from core.annotation_envelope import GapCausalityLabel
from core.coordination_bus import CoordinationBus, BusMessage, MessageType
from core.threat_context import ThreatContextManager

logger = logging.getLogger("ipcf.agent03")

SYSTEM_PROMPT = """You are Agent 03 of the Intelligent Pre-Collection Fabric (IPCF).
Your role is Gap Causality Classification — the primary research contribution.

Given telemetry source behaviour, classify the cause of a detected gap:
- adversarial: attacker deliberately suppressed logging (T1562.002, T1562.003, T1562.008)
  Indicators: correlated host anomaly, missing expected Event IDs, no infra fault signals,
  coincides with lateral movement or privilege escalation TTPs, sudden clean gap
- infra_failure: infrastructure problem caused the gap
  Indicators: parser error logs present, connector health degraded, network path issues,
  gradual degradation, multiple sources affected simultaneously
- schema_drift: vendor changed log format, parser no longer matches
  Indicators: field name mismatches, type errors in pipeline, affects single vendor,
  started after vendor update, partial event capture

Respond ONLY with valid JSON:
{
  "causality": "adversarial|infra_failure|schema_drift|none",
  "confidence": 0.0-1.0,
  "quality_score": 0.0-1.0,
  "key_indicators": ["indicator1", "indicator2"],
  "reasoning": "one sentence",
  "recommended_action": "escalate_to_analyst|repair_pipeline|update_schema|monitor"
}
"""


@dataclass
class SourceBaseline:
    """Behavioural baseline for a telemetry source."""
    source_id: str
    event_window: Deque[float] = field(default_factory=lambda: collections.deque(maxlen=1000))
    expected_rate_per_minute: float = 0.0
    last_event_time: float = field(default_factory=time.time)
    schema_fingerprint: str = ""
    parser_errors: int = 0
    connector_healthy: bool = True

    def add_event(self, ts: float = None):
        self.event_window.append(ts or time.time())
        self.last_event_time = ts or time.time()
        self._recalculate_rate()

    def _recalculate_rate(self):
        if len(self.event_window) < 2:
            return
        window = list(self.event_window)
        span = window[-1] - window[0]
        if span > 0:
            self.expected_rate_per_minute = (len(window) / span) * 60

    @property
    def seconds_since_last_event(self) -> float:
        return time.time() - self.last_event_time

    def expected_events_in_window(self, window_seconds: float) -> float:
        return (self.expected_rate_per_minute / 60) * window_seconds


class GapCausalityAgent(BaseAgent):
    """
    Agent 03 — Gap Causality Classifier.

    Pipeline:
    1. Maintain per-source behavioural baselines
    2. Detect deviation from expected event volume
    3. Collect gap indicators (host anomaly, T1562 signals, infra health)
    4. Classify causality using LLM + rule-based fallback
    5. Annotate envelope with gap_causality_label, quality_score, confidence
    6. Broadcast classification to coordination bus
    7. Escalate adversarial findings immediately

    Evaluation target: 3-class F1 across adversarial / infra_failure / schema_drift
    """

    def __init__(
        self,
        bus: CoordinationBus,
        threat_ctx: ThreatContextManager,
        baseline_window_seconds: float = 300,
        deviation_threshold: float = 0.5,
    ):
        super().__init__("agent_03_gap_causality", bus)
        self.threat_ctx = threat_ctx
        self.baseline_window = baseline_window_seconds
        self.deviation_threshold = deviation_threshold
        self._baselines: Dict[str, SourceBaseline] = {}
        self._gap_history: List[Dict] = []

        # Classification performance tracking (for benchmark)
        self._predictions: List[str] = []
        self._ground_truth: List[str] = []

    async def _subscribe(self):
        self.bus.subscribe(
            self.agent_id,
            [MessageType.SCHEMA_DRIFT_DETECTED],
            self._handle_schema_drift_signal,
        )

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        source_id = event.get("source_id", "unknown")
        host_id = event.get("host_id", source_id)

        # Update baseline
        baseline = self._get_or_create_baseline(source_id)
        if "raw_timestamp" in event:
            baseline.add_event()

        # Detect gap
        gap_detected, gap_duration = self._detect_gap(baseline, source_id)
        causality = GapCausalityLabel.NONE
        confidence = 1.0
        quality_score = 1.0
        indicators: List[str] = []
        reasoning = "No gap detected"
        action = "monitor"

        if gap_detected:
            indicators = self._collect_indicators(source_id, host_id, baseline, event)
            causality, confidence, quality_score, reasoning, action = \
                await self._classify_gap(source_id, host_id, gap_duration,
                                         indicators, baseline, event)
            self._record_gap(source_id, causality, confidence, gap_duration, indicators)
            logger.warning(f"[A03] Gap classified: {source_id} → "
                           f"{causality.value} (conf={confidence:.2f})")

        else:
            # No gap — still check schema health
            schema_ok = self._check_schema_health(event, baseline)
            if not schema_ok:
                causality = GapCausalityLabel.SCHEMA_DRIFT
                confidence = 0.75
                quality_score = 0.6
                indicators = ["field_mismatch_detected"]
                reasoning = "Schema drift detected via field mismatch"
                action = "update_schema"
                gap_detected = True
                gap_duration = 0.0

        # Update annotation envelope fields
        event.update({
            "gap_detected": gap_detected,
            "gap_causality_label": causality.value,
            "gap_confidence": confidence,
            "quality_score": quality_score,
            "gap_duration_seconds": gap_duration if gap_detected else None,
            "gap_indicators": indicators,
            "gap_reasoning": reasoning,
            "recommended_action": action,
        })

        latency = (time.time() - start) * 1000
        self._update_latency(latency)
        self._record_decision({
            "source_id": source_id,
            "gap_detected": gap_detected,
            "causality": causality.value,
            "confidence": confidence,
            "quality_score": quality_score,
        })

        # Broadcast quality score
        await self._publish_decision(MessageType.GAP_CLASSIFIED, {
            "source_id": source_id,
            "causality": causality.value,
            "confidence": confidence,
            "quality_score": quality_score,
            "indicators": indicators,
        })

        # Broadcast quality score for downstream detectors (KAIROS/MAGIC integration)
        await self.bus.publish(BusMessage(
            msg_type=MessageType.QUALITY_SCORE_BROADCAST,
            source_agent=self.agent_id,
            payload={
                "source_id": source_id,
                "quality_score": quality_score,
                "gap_causality_label": causality.value,
                "confidence": confidence,
            },
        ))

        # Immediate escalation for adversarial findings
        if causality == GapCausalityLabel.ADVERSARIAL:
            await self.bus.publish(BusMessage(
                msg_type=MessageType.HUMAN_GATE_TRIGGERED,
                source_agent=self.agent_id,
                payload={
                    "source_id": source_id,
                    "host_id": host_id,
                    "reason": "Adversarial log suppression detected",
                    "indicators": indicators,
                    "confidence": confidence,
                    "gap_duration_seconds": gap_duration,
                    "event_id": event.get("event_id"),
                },
                priority=1,
            ))

        return event

    def _get_or_create_baseline(self, source_id: str) -> SourceBaseline:
        if source_id not in self._baselines:
            self._baselines[source_id] = SourceBaseline(source_id=source_id)
        return self._baselines[source_id]

    def _detect_gap(self, baseline: SourceBaseline, source_id: str):
        """Detect deviation from expected event volume."""
        if baseline.expected_rate_per_minute == 0:
            return False, 0.0   # insufficient baseline history

        silence_seconds = baseline.seconds_since_last_event
        expected = baseline.expected_events_in_window(silence_seconds)

        if expected < 1:
            return False, 0.0   # low-volume source, not enough to flag

        # Gap if silence is > deviation_threshold of expected inter-event time
        expected_interval = 60 / baseline.expected_rate_per_minute
        if silence_seconds > expected_interval * (1 + self.deviation_threshold) * 5:
            return True, silence_seconds

        return False, 0.0

    def _collect_indicators(
        self, source_id: str, host_id: str,
        baseline: SourceBaseline, event: Dict
    ) -> List[str]:
        """Collect observable indicators to inform gap causality classification."""
        indicators = []
        host_state = self.threat_ctx.get_host_state(host_id)

        # Adversarial indicators
        if host_state.threat_score > 0.4:
            indicators.append(f"elevated_host_threat_score:{host_state.threat_score:.2f}")
        if host_state.investigation_active:
            indicators.append("active_investigation_on_host")
        t1562_ttps = [t for t in host_state.active_ttps
                      if t.startswith("T1562") or t.startswith("T1070")]
        if t1562_ttps:
            indicators.append(f"t1562_ttp_active:{','.join(t1562_ttps)}")

        # Infrastructure failure indicators
        if not baseline.connector_healthy:
            indicators.append("connector_health_degraded")
        if baseline.parser_errors > 0:
            indicators.append(f"parser_errors:{baseline.parser_errors}")
        if event.get("network_path_fault"):
            indicators.append("network_path_fault_reported")

        # Schema drift indicators
        if event.get("field_type_mismatch"):
            indicators.append("field_type_mismatch")
        if event.get("unknown_fields"):
            indicators.append(f"unknown_fields:{event.get('unknown_fields')}")

        return indicators

    def _check_schema_health(self, event: Dict, baseline: SourceBaseline) -> bool:
        """Quick schema health check — returns True if schema looks healthy."""
        if event.get("field_type_mismatch") or event.get("unknown_fields"):
            return False
        return True

    async def _classify_gap(
        self, source_id, host_id, gap_duration, indicators,
        baseline: SourceBaseline, event: Dict
    ):
        """LLM-based gap causality classification with rule-based fallback."""

        if self._use_llm:
            try:
                result = await self._llm_classify(
                    source_id, host_id, gap_duration, indicators, baseline
                )
                if result:
                    causality = GapCausalityLabel(result["causality"])
                    return (
                        causality,
                        float(result["confidence"]),
                        float(result["quality_score"]),
                        result.get("reasoning", "LLM classification"),
                        result.get("recommended_action", "monitor"),
                    )
            except Exception as e:
                logger.warning(f"[A03] LLM failed, using rule-based: {e}")

        return self._rule_based_classify(indicators, gap_duration)

    async def _llm_classify(self, source_id, host_id, gap_duration, indicators, baseline):
        host_state = self.threat_ctx.get_host_state(host_id)
        user_prompt = f"""Telemetry gap analysis:
Source: {source_id}
Host: {host_id}
Gap duration: {gap_duration:.1f} seconds
Expected rate: {baseline.expected_rate_per_minute:.1f} events/min
Host threat score: {host_state.threat_score:.3f}
Host threat level: {host_state.threat_level.value}
Active TTPs on host: {', '.join(host_state.active_ttps) or 'none'}
Connector healthy: {baseline.connector_healthy}
Parser errors: {baseline.parser_errors}
Observed indicators: {', '.join(indicators) if indicators else 'none'}

Classify the gap causality."""

        response = await self.call_llm(SYSTEM_PROMPT, user_prompt,
                                       temperature=0.1, max_tokens=300)
        if not response:
            return None
        clean = response.strip().strip("```json").strip("```").strip()
        return json.loads(clean)

    def _rule_based_classify(self, indicators: List[str], gap_duration: float):
        """Rule-based fallback when LLM unavailable."""
        adversarial_signals = sum(
            1 for i in indicators
            if any(s in i for s in ["t1562", "threat_score", "investigation"])
        )
        infra_signals = sum(
            1 for i in indicators
            if any(s in i for s in ["connector", "parser_error", "network_path"])
        )
        schema_signals = sum(
            1 for i in indicators
            if any(s in i for s in ["field_type", "unknown_fields", "schema"])
        )

        if adversarial_signals >= 2:
            return (GapCausalityLabel.ADVERSARIAL, 0.75, 0.2,
                    "Rule-based: multiple adversarial indicators", "escalate_to_analyst")
        if infra_signals >= 1:
            return (GapCausalityLabel.INFRA_FAILURE, 0.70, 0.5,
                    "Rule-based: infrastructure fault indicators", "repair_pipeline")
        if schema_signals >= 1:
            return (GapCausalityLabel.SCHEMA_DRIFT, 0.70, 0.6,
                    "Rule-based: schema drift indicators", "update_schema")

        return (GapCausalityLabel.INFRA_FAILURE, 0.45, 0.5,
                "Rule-based: insufficient indicators, defaulting to infra", "monitor")

    def _record_gap(self, source_id, causality, confidence, duration, indicators):
        self._gap_history.append({
            "timestamp": time.time(),
            "source_id": source_id,
            "causality": causality.value,
            "confidence": confidence,
            "duration_seconds": duration,
            "indicators": indicators,
        })
        if len(self._gap_history) > 200:
            self._gap_history = self._gap_history[-200:]

    async def _handle_schema_drift_signal(self, msg: BusMessage):
        """Handle schema drift signals from Agent 04A."""
        source_id = msg.payload.get("source_id")
        if source_id and source_id in self._baselines:
            self._baselines[source_id].parser_errors += 1
            logger.info(f"[A03] Schema drift signal received for {source_id}")

    def record_ground_truth(self, true_label: str):
        """Called by benchmark harness for evaluation."""
        self._ground_truth.append(true_label)

    def record_prediction(self, pred_label: str):
        self._predictions.append(pred_label)

    def get_gap_history(self) -> List[Dict]:
        return self._gap_history[-50:]

    def get_baselines_summary(self) -> Dict[str, Any]:
        return {
            sid: {
                "expected_rate_per_min": round(b.expected_rate_per_minute, 2),
                "seconds_since_last_event": round(b.seconds_since_last_event, 1),
                "connector_healthy": b.connector_healthy,
                "parser_errors": b.parser_errors,
            }
            for sid, b in self._baselines.items()
        }
