#!/usr/bin/env python3
"""
=============================================================
  feedback.py — Human-in-the-Loop Feedback Loop (A5)
  Author: Angga Firmansyah — A5 Integration (FP-SOC-K3)
=============================================================

Memenuhi requirement soal #8: "Peran Human dalam Kolaborasi" +
mekanisme feedback untuk retraining A4.

Alur feedback:
  1. ai_filter.py menulis keputusan ke decisions.log
  2. Analyst (Syifa) meninjau alert di zone NEEDS_REVIEW (0.60-0.84)
     dan zone FILTERED_FP yang diragukan
  3. Analyst menandai true_label sebenarnya via record_feedback()
  4. get_misclassified() mendeteksi salah klasifikasi
  5. CSV hasil -> dipakai A4 untuk retrain (closed-loop improvement)

File CSV: feedback/feedback.csv
Format:
  timestamp,alert_id,rule_id,ai_decision,ai_confidence,true_label,analyst,note
"""
from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

FEEDBACK_HEADER = [
    "timestamp",
    "alert_id",
    "rule_id",
    "ai_decision",
    "ai_confidence",
    "true_label",
    "analyst",
    "note",
]


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def feedback_csv_path(feedback_dir: str) -> str:
    _ensure_dir(feedback_dir)
    return os.path.join(feedback_dir, "feedback.csv")


def record_feedback(
    feedback_dir: str,
    alert_id: str,
    rule_id: int,
    ai_decision: str,
    ai_confidence: float,
    true_label: int,
    analyst: str = "analyst",
    note: str = "",
) -> None:
    """
    Catat 1 feedback dari analyst.

    true_label: 1 = serangan nyata (TP), 0 = false alarm (FP)
    ai_decision: 'FILTERED_FP' | 'NEEDS_REVIEW' | 'FORWARD_TO_SOAR'
    """
    path = feedback_csv_path(feedback_dir)
    is_new = not os.path.exists(path)

    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": str(alert_id),
        "rule_id": int(rule_id),
        "ai_decision": ai_decision,
        "ai_confidence": round(float(ai_confidence), 4),
        "true_label": int(true_label),
        "analyst": analyst,
        "note": note,
    }

    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEEDBACK_HEADER)
        if is_new:
            writer.writeheader()
        writer.writerow(row)


def load_feedback(feedback_dir: str) -> List[Dict[str, str]]:
    """Baca seluruh feedback.csv. List kosong bila belum ada."""
    path = feedback_csv_path(feedback_dir)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def get_misclassified(feedback_dir: str) -> List[Dict[str, str]]:
    """
    Deteksi salah klasifikasi AI untuk retraining A4.

    Aturan salah klasifikasi:
      - AI bilang FILTERED_FP (dianggap FP) tapi analyst bilang TP (true_label=1)
        -> MISSED_ATTACK (bahaya! serangan lolos)
      - AI bilang FORWARD_TO_SOAR (dianggap TP) tapi analyst bilang FP (true_label=0)
        -> FALSE_ALARM_TO_SOAR (boros SOAR)
    """
    rows = load_feedback(feedback_dir)
    misclassified = []
    for r in rows:
        decision = r.get("ai_decision", "")
        true_label = int(r.get("true_label", -1))

        if decision == "FILTERED_FP" and true_label == 1:
            r["error_type"] = "MISSED_ATTACK"
            misclassified.append(r)
        elif decision == "FORWARD_TO_SOAR" and true_label == 0:
            r["error_type"] = "FALSE_ALARM_TO_SOAR"
            misclassified.append(r)
        elif decision == "NEEDS_REVIEW":
            # NEEDS_REVIEW memang menunggu human — bukan 'salah', tapi perlu
            # masuk dataset retraining sebagai contoh borderline.
            r["error_type"] = "BORDERLINE_RESOLVED"
            misclassified.append(r)
    return misclassified


def summarize_feedback(feedback_dir: str) -> Dict[str, int]:
    """Ringkasan statistik feedback untuk laporan benchmark."""
    rows = load_feedback(feedback_dir)
    summary = {
        "total": len(rows),
        "tp_correct": 0,
        "fp_correct": 0,
        "missed_attack": 0,
        "false_alarm_to_soar": 0,
        "needs_reviewed": 0,
    }
    for r in rows:
        decision = r.get("ai_decision", "")
        true_label = int(r.get("true_label", -1))
        if decision == "FILTERED_FP" and true_label == 0:
            summary["fp_correct"] += 1
        elif decision == "FORWARD_TO_SOAR" and true_label == 1:
            summary["tp_correct"] += 1
        elif decision == "FILTERED_FP" and true_label == 1:
            summary["missed_attack"] += 1
        elif decision == "FORWARD_TO_SOAR" and true_label == 0:
            summary["false_alarm_to_soar"] += 1
        elif decision == "NEEDS_REVIEW":
            summary["needs_reviewed"] += 1
    return summary


# --- CLI ringkas untuk demo human-in-the-loop ---
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Feedback loop CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # -- Sub: add --
    sp = sub.add_parser("add", help="tambah 1 feedback")
    sp.add_argument("--dir", default="feedback", help="folder feedback")
    sp.add_argument("--alert-id", required=True)
    sp.add_argument("--rule-id", type=int, required=True)
    sp.add_argument("--decision", required=True,
                    choices=["FILTERED_FP", "NEEDS_REVIEW", "FORWARD_TO_SOAR"])
    sp.add_argument("--confidence", type=float, required=True)
    sp.add_argument("--true-label", type=int, required=True, choices=[0, 1],
                    help="1=serangan nyata(TP), 0=false alarm(FP)")
    sp.add_argument("--analyst", default="analyst")
    sp.add_argument("--note", default="")

    # -- Sub: stats --
    sp_stats = sub.add_parser("stats", help="tampilkan ringkasan")
    sp_stats.add_argument("--dir", default="feedback", help="folder feedback")

    # -- Sub: misclassified --
    sp_mis = sub.add_parser("misclassified", help="daftar salah klasifikasi")
    sp_mis.add_argument("--dir", default="feedback", help="folder feedback")

    args = p.parse_args()
    fb_dir = args.dir
    if args.cmd == "add":
        record_feedback(fb_dir, args.alert_id, args.rule_id, args.decision,
                        args.confidence, args.true_label, args.analyst, args.note)
        print(f"[OK] feedback tercatat di {feedback_csv_path(fb_dir)}")
    elif args.cmd == "stats":
        import json
        print(json.dumps(summarize_feedback(fb_dir), indent=2))
    elif args.cmd == "misclassified":
        for m in get_misclassified(fb_dir):
            print(f"  [{m['error_type']}] alert={m['alert_id']} rule={m['rule_id']} "
                  f"ai={m['ai_decision']}({m['ai_confidence']}) true={m['true_label']}")
