"""
threat_context.py
Manages the current threat state C, propagated from Layer C (SIEM) back to
Agent 01 to enable threat-state-driven collection depth decisions.
This is the feedback loop that makes collection depth semantic, not statistical.
"""

from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from enum import Enum

logger = logging.getLogger("ipcf.threat_context")


class ThreatLevel(str, Enum):
    QUIESCENT = "quiescent"    # normal operations, no active threat
    ALERT = "alert"            # elevated concern, partial enrichment
    ACTIVE = "active"          # confirmed incident, full fidelity


@dataclass
class HostThreatState:
    host_id: str
    threat_level: ThreatLevel = ThreatLevel.QUIESCENT
    threat_score: float = 0.0          # 0.0-1.0
    active_ttps: List[str] = field(default_factory=list)   # MITRE ATT&CK IDs
    last_updated: float = field(default_factory=time.time)
    alert_count: int = 0
    investigation_active: bool = False


class ThreatContextManager:
    """
    Maintains per-source threat state.
    Updated by:
    - SIEM webhook callbacks (in production)
    - Benchmark injector (in testing)
    - Manual API calls (for demo)

    Agent 01 queries this before making every depth decision.
    """

    def __init__(self, high_threshold: float = 0.7, medium_threshold: float = 0.4):
        self._host_states: Dict[str, HostThreatState] = {}
        self._global_threat_score: float = 0.0
        self._high_threshold = high_threshold
        self._medium_threshold = medium_threshold
        self._lock = asyncio.Lock()
        self._update_callbacks = []

    async def update_host_threat(
        self,
        host_id: str,
        threat_score: float,
        active_ttps: Optional[List[str]] = None,
        investigation_active: bool = False,
    ) -> HostThreatState:
        """Update threat state for a specific host. Called by SIEM webhook."""
        async with self._lock:
            level = self._score_to_level(threat_score)
            state = HostThreatState(
                host_id=host_id,
                threat_level=level,
                threat_score=threat_score,
                active_ttps=active_ttps or [],
                last_updated=time.time(),
                investigation_active=investigation_active,
            )
            if host_id in self._host_states:
                state.alert_count = self._host_states[host_id].alert_count + 1
            self._host_states[host_id] = state
            self._recalculate_global()

            for cb in self._update_callbacks:
                try:
                    await cb(state)
                except Exception as e:
                    logger.error(f"Threat context callback failed: {e}")

            logger.info(f"Host {host_id} threat updated: {level.value} ({threat_score:.2f})")
            return state

    def get_host_state(self, host_id: str) -> HostThreatState:
        """Get current threat state for a host. Defaults to quiescent."""
        return self._host_states.get(
            host_id,
            HostThreatState(host_id=host_id)
        )

    def get_global_threat_score(self) -> float:
        return self._global_threat_score

    def get_all_states(self) -> Dict[str, Dict]:
        return {
            hid: {
                "threat_level": s.threat_level.value,
                "threat_score": s.threat_score,
                "active_ttps": s.active_ttps,
                "investigation_active": s.investigation_active,
                "alert_count": s.alert_count,
                "last_updated": s.last_updated,
            }
            for hid, s in self._host_states.items()
        }

    def _score_to_level(self, score: float) -> ThreatLevel:
        if score >= self._high_threshold:
            return ThreatLevel.ACTIVE
        if score >= self._medium_threshold:
            return ThreatLevel.ALERT
        return ThreatLevel.QUIESCENT

    def _recalculate_global(self):
        if not self._host_states:
            self._global_threat_score = 0.0
            return
        self._global_threat_score = max(s.threat_score for s in self._host_states.values())

    def on_update(self, callback):
        self._update_callbacks.append(callback)
