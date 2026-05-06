"""
annotation_envelope.py
Defines the structured output of the IPCF fabric — the concrete data contract
between the fabric and Layer B (SIEM pipeline). Every event exiting the fabric
carries this envelope.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
import json


class CollectionDepth(str, Enum):
    METADATA = "metadata"
    ENTITY = "entity"
    FULL = "full"


class GapCausalityLabel(str, Enum):
    NONE = "none"                    # no gap detected
    ADVERSARIAL = "adversarial"      # attacker-induced log suppression
    INFRA_FAILURE = "infra_failure"  # broken pipe, parser failure, network issue
    SCHEMA_DRIFT = "schema_drift"    # vendor changed log format


class AssetClass(str, Enum):
    STANDARD = "standard"
    REGULATED = "regulated"          # GDPR / HIPAA / Privacy Act 1988
    EXECUTIVE = "executive"
    NETWORK = "network"


@dataclass
class GovernanceTag:
    asset_class: AssetClass
    fields_masked: List[str] = field(default_factory=list)
    policy_version: str = "1.0"
    requires_human_approval: bool = False
    applied_regulations: List[str] = field(default_factory=list)


@dataclass
class AnnotationEnvelope:
    """
    The concrete output contract of the IPCF.
    Every event forwarded to Layer B carries these fields.
    Downstream detectors (KAIROS, MAGIC) can consume
    quality_score and gap_causality_label as weighted inputs.
    """
    # Original event fields
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    source_type: str = ""
    raw_timestamp: str = ""
    event_data: Dict[str, Any] = field(default_factory=dict)

    # Agent 01 — Collection Control
    collection_depth: CollectionDepth = CollectionDepth.METADATA
    priority_score: float = 0.5          # 0.0 (low) → 1.0 (high)
    threat_state_at_collection: float = 0.0

    # Agent 02 — Governance
    governance_tag: Optional[GovernanceTag] = None
    human_approval_required: bool = False
    human_approval_granted: bool = False

    # Agent 03 — Gap Causality (primary contribution)
    gap_detected: bool = False
    gap_causality_label: GapCausalityLabel = GapCausalityLabel.NONE
    gap_confidence: float = 1.0          # confidence in causality classification
    quality_score: float = 1.0          # overall telemetry quality 0.0-1.0
    gap_duration_seconds: Optional[float] = None
    gap_indicators: List[str] = field(default_factory=list)

    # Agent 04A — Schema Mediation
    schema_version: str = "unknown"
    schema_drifted: bool = False
    ocsf_mapped: bool = False
    normalized_fields: Dict[str, Any] = field(default_factory=dict)

    # Agent 04B — Forensic Compression
    compressed: bool = False
    compression_ratio: float = 1.0
    provenance_pointer: str = ""         # hash → raw evidence store
    forensic_fields_retained: List[str] = field(default_factory=list)

    # Agent 05 — Oversight
    oversight_flags: List[str] = field(default_factory=list)
    fabric_processing_latency_ms: float = 0.0

    # Fabric metadata
    fabric_version: str = "1.0.0"
    processed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["collection_depth"] = self.collection_depth.value
        d["gap_causality_label"] = self.gap_causality_label.value
        if self.governance_tag:
            d["governance_tag"]["asset_class"] = self.governance_tag.asset_class.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @property
    def is_high_quality(self) -> bool:
        return self.quality_score >= 0.7 and not self.gap_detected

    @property
    def requires_immediate_escalation(self) -> bool:
        return self.gap_causality_label == GapCausalityLabel.ADVERSARIAL
