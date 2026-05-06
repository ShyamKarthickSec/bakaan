"""
injector.py
Synthetic gap injection framework for evaluating Agent 03's gap causality classifier.
Three injection types matching the evaluation design:
  1. Schema drift    — modify field names without updating parser
  2. Infra failure   — simulate network path interruption
  3. Adversarial     — T1562.002-compatible logging suppression scenario

Methodology follows Mukherjee et al. USENIX Security 2023 and
Sekar et al. IEEE S&P 2024 (controlled injection with ground-truth labels).
"""

from __future__ import annotations
import random
import time
import uuid
from typing import List, Tuple, Dict, Any


class GapInjector:
    """
    Generates labelled telemetry events for benchmark evaluation.
    Each event is paired with its ground-truth gap causality label.
    """

    SOURCE_TYPES = ["endpoint", "network", "identity", "cloud", "application"]
    ASSET_CLASSES = ["standard", "regulated", "network", "executive"]

    def __init__(self, seed: int = 42):
        random.seed(seed)

    def generate_events(
        self,
        n_normal: int = 100,
        n_adversarial: int = 20,
        n_infra: int = 20,
        n_schema: int = 20,
    ) -> List[Tuple[Dict[str, Any], str]]:
        """
        Generate a shuffled mix of normal and gap-injected events.
        Returns list of (event_dict, ground_truth_label) tuples.
        Ground truth labels: none | adversarial | infra_failure | schema_drift
        """
        events = []
        events.extend(self._normal_events(n_normal))
        events.extend(self._adversarial_gap_events(n_adversarial))
        events.extend(self._infra_failure_events(n_infra))
        events.extend(self._schema_drift_events(n_schema))
        random.shuffle(events)
        return events

    # ── Normal events ─────────────────────────────────────────────────────────
    def _normal_events(self, n: int) -> List[Tuple[Dict, str]]:
        return [
            (self._make_event(
                source_id=f"host_{random.randint(1, 20)}",
                source_type=random.choice(self.SOURCE_TYPES),
                asset_class=random.choice(self.ASSET_CLASSES),
                event_data=self._random_event_data(),
                inject_gap=False,
            ), "none")
            for _ in range(n)
        ]

    # ── Adversarial gap (T1562.002 scenario) ──────────────────────────────────
    def _adversarial_gap_events(self, n: int) -> List[Tuple[Dict, str]]:
        """
        Simulate attacker-induced log suppression.
        Indicators: elevated threat score on host, active T1562 TTP,
        sudden clean gap (no infra signals), coincident lateral movement.
        """
        events = []
        for _ in range(n):
            host_id = f"host_{random.randint(1, 5)}"  # high-value hosts
            event = self._make_event(
                source_id=host_id,
                source_type="endpoint",
                asset_class="standard",
                event_data=self._random_event_data(),
                inject_gap=True,
                gap_injection_type="adversarial",
            )
            # Adversarial-specific indicators
            event["_threat_score_override"] = round(random.uniform(0.6, 0.95), 3)
            event["_active_ttps"] = random.choice([
                ["T1562.002"], ["T1562.003"], ["T1562.008"],
                ["T1562.002", "T1021.002"],  # lateral movement combo
            ])
            event["network_path_fault"] = False
            event["field_type_mismatch"] = False
            events.append((event, "adversarial"))
        return events

    # ── Infrastructure failure ────────────────────────────────────────────────
    def _infra_failure_events(self, n: int) -> List[Tuple[Dict, str]]:
        """
        Simulate network path interruption / parser failure.
        Indicators: connector health degraded, parser errors, no host anomalies.
        """
        events = []
        for _ in range(n):
            event = self._make_event(
                source_id=f"host_{random.randint(1, 20)}",
                source_type=random.choice(self.SOURCE_TYPES),
                asset_class=random.choice(self.ASSET_CLASSES),
                event_data=self._random_event_data(),
                inject_gap=True,
                gap_injection_type="infra_failure",
            )
            event["network_path_fault"] = random.choice([True, True, False])
            event["_connector_healthy"] = False
            event["_parser_errors"] = random.randint(1, 10)
            event["field_type_mismatch"] = False
            event["_threat_score_override"] = round(random.uniform(0.0, 0.25), 3)
            events.append((event, "infra_failure"))
        return events

    # ── Schema drift ──────────────────────────────────────────────────────────
    def _schema_drift_events(self, n: int) -> List[Tuple[Dict, str]]:
        """
        Simulate vendor schema change (field rename/type change).
        Indicators: field mismatches, single-vendor impact, no host anomalies.
        """
        events = []
        for _ in range(n):
            # Use drifted field names
            drifted_data = self._drifted_event_data()
            event = self._make_event(
                source_id=f"vendor_{random.choice(['sysmon', 'crowdstrike', 'sentinel'])}",
                source_type="endpoint",
                asset_class="standard",
                event_data=drifted_data,
                inject_gap=True,
                gap_injection_type="schema_drift",
            )
            event["field_type_mismatch"] = True
            event["unknown_fields"] = "NewFieldV2,RenamedProcess"
            event["network_path_fault"] = False
            event["_threat_score_override"] = round(random.uniform(0.0, 0.2), 3)
            events.append((event, "schema_drift"))
        return events

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _make_event(self, source_id: str, source_type: str, asset_class: str,
                    event_data: Dict, inject_gap: bool = False,
                    gap_injection_type: str = None) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "source_id": source_id,
            "host_id": source_id,
            "source_type": source_type,
            "asset_class": asset_class,
            "raw_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_data": event_data,
            "is_regulated_device": asset_class == "regulated",
            "inject_gap": inject_gap,
            "gap_injection_type": gap_injection_type,
            "network_path_fault": False,
            "field_type_mismatch": False,
            "unknown_fields": None,
        }

    def _random_event_data(self) -> Dict[str, Any]:
        return {
            "EventID": random.choice([4624, 4625, 4688, 4776, 5140]),
            "SubjectUserName": f"user_{random.randint(1, 100)}",
            "IpAddress": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            "ProcessName": random.choice([
                "lsass.exe", "cmd.exe", "powershell.exe",
                "svchost.exe", "explorer.exe",
            ]),
            "CommandLine": random.choice([
                "cmd /c whoami",
                "powershell -enc ...",
                "net user administrator",
                "ipconfig /all",
            ]),
            "LogonType": random.randint(2, 10),
            "timestamp": time.time(),
        }

    def _drifted_event_data(self) -> Dict[str, Any]:
        """Event data with renamed fields — simulating vendor schema drift."""
        return {
            "EventIDv2": random.choice([4624, 4625, 4688]),  # renamed
            "SubjectUser": f"user_{random.randint(1, 100)}",  # renamed
            "SourceIPAddress": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",  # renamed
            "NewFieldV2": "unexpected_value",                 # new field
            "RenamedProcess": "cmd.exe",                      # renamed
            "timestamp": time.time(),
        }
