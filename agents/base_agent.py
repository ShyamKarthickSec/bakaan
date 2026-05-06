"""
base_agent.py
Abstract base class for all IPCF agents.
Provides: DeepSeek LLM client, health reporting, decision logging,
bus message helpers, and the standard process() interface.
"""

from __future__ import annotations
import asyncio
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from openai import AsyncOpenAI

from core.coordination_bus import CoordinationBus, BusMessage, MessageType

logger = logging.getLogger("ipcf.base_agent")


@dataclass
class AgentHealth:
    agent_id: str
    status: str = "running"          # running | degraded | failed
    last_heartbeat: float = field(default_factory=time.time)
    decisions_made: int = 0
    errors: int = 0
    avg_latency_ms: float = 0.0
    decision_log: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "status": self.status,
            "last_heartbeat": self.last_heartbeat,
            "decisions_made": self.decisions_made,
            "errors": self.errors,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "recent_decisions": self.decision_log[-10:],
        }


class BaseAgent(ABC):
    """
    All five IPCF agents inherit from this class.
    Key responsibilities:
    - Provides self.llm for DeepSeek API calls
    - Provides self.bus for publishing decisions
    - Tracks health and latency
    - Sends heartbeats every 30s
    - Logs every decision for Agent 05 oversight
    """

    HEARTBEAT_INTERVAL = 30.0

    def __init__(self, agent_id: str, bus: CoordinationBus):
        self.agent_id = agent_id
        self.bus = bus
        self.health = AgentHealth(agent_id=agent_id)
        self._running = False
        self._latency_samples: List[float] = []

        # DeepSeek client using OpenAI-compatible SDK
        self.llm = AsyncOpenAI(
            api_key=os.getenv("DEEPSEEK_API_KEY", ""),
            base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        )
        self.model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        logger.info(f"Agent {agent_id} initialised with model {self.model}")

    @abstractmethod
    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Core processing method. Each agent implements this.
        Input: event dict from coordination bus or previous agent.
        Output: updated event dict with agent's decisions added.
        """
        ...

    async def start(self) -> None:
        """Start the agent — subscribe to bus and begin heartbeat."""
        self._running = True
        await self._subscribe()
        asyncio.create_task(self._heartbeat_loop())
        logger.info(f"Agent {self.agent_id} started")

    async def stop(self) -> None:
        self._running = False
        self.health.status = "stopped"
        logger.info(f"Agent {self.agent_id} stopped")

    async def _subscribe(self) -> None:
        """Override in subclasses to subscribe to specific bus message types."""
        pass

    async def _heartbeat_loop(self) -> None:
        while self._running:
            self.health.last_heartbeat = time.time()
            await self.bus.publish(BusMessage(
                msg_type=MessageType.AGENT_HEARTBEAT,
                source_agent=self.agent_id,
                payload=self.health.to_dict(),
                priority=9,
            ))
            await asyncio.sleep(self.HEARTBEAT_INTERVAL)

    async def call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> str:
        """
        Call DeepSeek API. Low temperature for deterministic decisions.
        Returns the response text or empty string on failure.
        """
        try:
            response = await self.llm.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"[{self.agent_id}] LLM call failed: {e}")
            self.health.errors += 1
            return ""

    def _record_decision(self, decision: Dict[str, Any]) -> None:
        """Record a decision in health log for Agent 05 and dashboard."""
        self.health.decisions_made += 1
        entry = {"timestamp": time.time(), **decision}
        self.health.decision_log.append(entry)
        if len(self.health.decision_log) > 100:
            self.health.decision_log = self.health.decision_log[-100:]

    def _update_latency(self, latency_ms: float) -> None:
        self._latency_samples.append(latency_ms)
        if len(self._latency_samples) > 50:
            self._latency_samples = self._latency_samples[-50:]
        self.health.avg_latency_ms = sum(self._latency_samples) / len(self._latency_samples)

    async def _publish_decision(self, msg_type: MessageType, payload: Dict) -> None:
        await self.bus.publish(BusMessage(
            msg_type=msg_type,
            source_agent=self.agent_id,
            payload={**payload, "agent_id": self.agent_id, "timestamp": time.time()},
        ))
