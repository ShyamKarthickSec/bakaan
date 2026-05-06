"""
coordination_bus.py
The shared asyncio message bus connecting all IPCF agents.
Provides: orchestration, conflict resolution, quality-score broadcast,
threat-context propagation, human escalation routing, and Agent 05 audit trail.
"""

from __future__ import annotations
import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger("ipcf.bus")


class MessageType(str, Enum):
    # Agent lifecycle
    AGENT_HEARTBEAT = "agent_heartbeat"
    AGENT_ERROR = "agent_error"
    AGENT_DECISION = "agent_decision"

    # Event flow
    EVENT_INGESTED = "event_ingested"
    DEPTH_DECISION = "depth_decision"
    GAP_DETECTED = "gap_detected"
    GAP_CLASSIFIED = "gap_classified"
    GOVERNANCE_APPLIED = "governance_applied"
    SCHEMA_UPDATED = "schema_updated"
    COMPRESSION_DONE = "compression_done"
    ENVELOPE_READY = "envelope_ready"

    # Escalation
    HUMAN_GATE_TRIGGERED = "human_gate_triggered"
    HUMAN_APPROVAL_GRANTED = "human_approval_granted"
    HUMAN_APPROVAL_DENIED = "human_approval_denied"

    # Threat context
    THREAT_CONTEXT_UPDATE = "threat_context_update"

    # Oversight
    OVERSIGHT_FLAG = "oversight_flag"
    OVERSIGHT_ALERT = "oversight_alert"

    # Quality
    QUALITY_SCORE_BROADCAST = "quality_score_broadcast"

    # Schema drift
    SCHEMA_DRIFT_DETECTED = "schema_drift_detected"


@dataclass
class BusMessage:
    msg_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    msg_type: MessageType = MessageType.AGENT_HEARTBEAT
    source_agent: str = "system"
    target_agent: Optional[str] = None   # None = broadcast
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    priority: int = 5                    # 1 (highest) → 10 (lowest)
    requires_ack: bool = False
    correlation_id: Optional[str] = None  # links related messages

    def to_dict(self) -> Dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "msg_type": self.msg_type.value,
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "priority": self.priority,
            "correlation_id": self.correlation_id,
        }


class CoordinationBus:
    """
    Central asyncio pub/sub bus.
    - Agents subscribe to message types they care about.
    - Agent 05 receives a copy of ALL messages for audit.
    - Human escalation messages are routed to the escalation queue.
    """

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._broadcast_subscribers: List[Callable] = []  # Agent 05
        self._escalation_queue: asyncio.Queue = asyncio.Queue()
        self._message_log: List[Dict] = []              # full audit trail
        self._lock = asyncio.Lock()
        self._stats = {
            "total_messages": 0,
            "messages_by_type": {},
            "escalations_pending": 0,
            "agents_connected": set(),
        }

    def subscribe(self, agent_id: str, msg_types: List[MessageType],
                  handler: Callable) -> None:
        """Subscribe an agent handler to specific message types."""
        for mt in msg_types:
            key = mt.value
            if key not in self._subscribers:
                self._subscribers[key] = []
            self._subscribers[key].append(handler)
        self._stats["agents_connected"].add(agent_id)
        logger.info(f"Agent {agent_id} subscribed to {[m.value for m in msg_types]}")

    def subscribe_all(self, handler: Callable) -> None:
        """Subscribe to all messages — used exclusively by Agent 05 oversight."""
        self._broadcast_subscribers.append(handler)

    async def publish(self, message: BusMessage) -> None:
        """Publish a message to all relevant subscribers."""
        async with self._lock:
            self._stats["total_messages"] += 1
            mt = message.msg_type.value
            self._stats["messages_by_type"][mt] = \
                self._stats["messages_by_type"].get(mt, 0) + 1
            self._message_log.append(message.to_dict())

        # Route to type-specific subscribers
        handlers = self._subscribers.get(message.msg_type.value, [])
        tasks = []
        for handler in handlers:
            if message.target_agent is None or \
               message.target_agent == getattr(handler, "__agent_id__", None):
                tasks.append(asyncio.create_task(self._safe_call(handler, message)))

        # Always route to broadcast subscribers (Agent 05)
        for handler in self._broadcast_subscribers:
            tasks.append(asyncio.create_task(self._safe_call(handler, message)))

        # Route human escalations to escalation queue
        if message.msg_type == MessageType.HUMAN_GATE_TRIGGERED:
            self._stats["escalations_pending"] += 1
            await self._escalation_queue.put(message)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_call(self, handler: Callable, message: BusMessage) -> None:
        try:
            await handler(message)
        except Exception as e:
            logger.error(f"Handler {handler} failed on {message.msg_type}: {e}")

    async def get_escalation(self, timeout: float = 5.0) -> Optional[BusMessage]:
        """Get next pending human escalation."""
        try:
            msg = await asyncio.wait_for(self._escalation_queue.get(), timeout=timeout)
            self._stats["escalations_pending"] = max(0, self._stats["escalations_pending"] - 1)
            return msg
        except asyncio.TimeoutError:
            return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_messages": self._stats["total_messages"],
            "messages_by_type": self._stats["messages_by_type"],
            "escalations_pending": self._stats["escalations_pending"],
            "agents_connected": list(self._stats["agents_connected"]),
            "audit_log_size": len(self._message_log),
        }

    def get_recent_messages(self, n: int = 50) -> List[Dict]:
        return self._message_log[-n:]
