"""
evaluator.py
Benchmark evaluation framework for the Gap Causality Classifier (Agent 03).
Computes 3-class F1, precision, recall, and confusion matrix.
Primary evaluation metric: adversarial class F1 (core research claim).
Follows methodology from Mukherjee et al. USENIX Security 2023.
Baseline comparison: binary gap flagging (gap vs. no gap).
"""

from __future__ import annotations
import json
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional


LABELS = ["none", "adversarial", "infra_failure", "schema_drift"]


class BenchmarkEvaluator:
    """
    3-class gap causality classifier evaluation.
    Records (true_label, predicted_label) pairs and computes:
    - Per-class precision, recall, F1
    - Macro-averaged F1
    - Adversarial class F1 (★ primary metric)
    - Confusion matrix
    - Baseline comparison: binary gap-flagging accuracy
    """

    def __init__(self):
        self._records: List[Dict[str, str]] = []
        self._start_time = time.time()

    def record(self, true_label: str, predicted_label: str) -> None:
        self._records.append({
            "true": true_label,
            "predicted": predicted_label,
            "timestamp": time.time(),
        })

    def compute_metrics(self) -> Dict[str, Any]:
        if not self._records:
            return {"error": "no records"}

        trues = [r["true"] for r in self._records]
        preds = [r["predicted"] for r in self._records]
        n = len(self._records)

        # Confusion matrix
        confusion: Dict[str, Dict[str, int]] = {
            l: {l2: 0 for l2 in LABELS} for l in LABELS
        }
        for t, p in zip(trues, preds):
            if t in confusion and p in confusion:
                confusion[t][p] += 1

        # Per-class metrics
        per_class: Dict[str, Dict[str, float]] = {}
        for label in LABELS:
            tp = confusion[label][label]
            fp = sum(confusion[l][label] for l in LABELS if l != label)
            fn = sum(confusion[label][l] for l in LABELS if l != label)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1        = (2 * precision * recall / (precision + recall)
                         if (precision + recall) > 0 else 0.0)
            per_class[label] = {
                "precision": round(precision, 4),
                "recall":    round(recall, 4),
                "f1":        round(f1, 4),
                "support":   tp + fn,
            }

        macro_f1 = sum(m["f1"] for m in per_class.values()) / len(per_class)
        accuracy = sum(1 for t, p in zip(trues, preds) if t == p) / n

        # Baseline: binary gap-flagging (gap vs none)
        binary_trues = ["gap" if t != "none" else "none" for t in trues]
        binary_preds = ["gap" if p != "none" else "none" for p in preds]
        binary_acc = sum(1 for t, p in zip(binary_trues, binary_preds) if t == p) / n

        # Binary F1 for gap class
        tp_b = sum(1 for t, p in zip(binary_trues, binary_preds)
                   if t == "gap" and p == "gap")
        fp_b = sum(1 for t, p in zip(binary_trues, binary_preds)
                   if t == "none" and p == "gap")
        fn_b = sum(1 for t, p in zip(binary_trues, binary_preds)
                   if t == "gap" and p == "none")
        bp = tp_b / (tp_b + fp_b) if (tp_b + fp_b) > 0 else 0.0
        br = tp_b / (tp_b + fn_b) if (tp_b + fn_b) > 0 else 0.0
        binary_f1 = 2 * bp * br / (bp + br) if (bp + br) > 0 else 0.0

        return {
            "summary": {
                "total_events": n,
                "accuracy": round(accuracy, 4),
                "macro_f1": round(macro_f1, 4),
                "adversarial_f1": per_class["adversarial"]["f1"],   # ★ primary
                "adversarial_precision": per_class["adversarial"]["precision"],
                "adversarial_recall": per_class["adversarial"]["recall"],
                "duration_seconds": round(time.time() - self._start_time, 1),
            },
            "per_class": per_class,
            "confusion_matrix": confusion,
            "baseline_comparison": {
                "binary_gap_accuracy": round(binary_acc, 4),
                "binary_gap_f1": round(binary_f1, 4),
                "3class_vs_binary_f1_delta": round(
                    per_class["adversarial"]["f1"] - binary_f1, 4
                ),
            },
            "label_distribution": {
                "true":      {l: trues.count(l) for l in LABELS},
                "predicted": {l: preds.count(l) for l in LABELS},
            },
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def print_report(self) -> None:
        report = self.compute_metrics()
        print("\n" + "=" * 60)
        print("IPCF BENCHMARK REPORT — Agent 03 Gap Causality Classifier")
        print("=" * 60)
        s = report["summary"]
        print(f"Total events:         {s['total_events']}")
        print(f"Overall accuracy:     {s['accuracy']:.4f}")
        print(f"Macro F1:             {s['macro_f1']:.4f}")
        print(f"★ Adversarial F1:     {s['adversarial_f1']:.4f}  (primary metric)")
        print(f"  Adversarial Prec:   {s['adversarial_precision']:.4f}")
        print(f"  Adversarial Recall: {s['adversarial_recall']:.4f}")
        print("\nPer-class metrics:")
        for label, metrics in report["per_class"].items():
            print(f"  {label:<16} P={metrics['precision']:.3f} "
                  f"R={metrics['recall']:.3f} F1={metrics['f1']:.3f} "
                  f"(n={metrics['support']})")
        b = report["baseline_comparison"]
        print(f"\nBaseline (binary gap-flagging):")
        print(f"  Accuracy: {b['binary_gap_accuracy']:.4f}")
        print(f"  F1:       {b['binary_gap_f1']:.4f}")
        print(f"  3-class adversarial F1 improvement: "
              f"{b['3class_vs_binary_f1_delta']:+.4f}")
        print("=" * 60 + "\n")
