#!/usr/bin/env python3
"""
=============================================================
  ai_filter.py — AI False-Alarm Filter (A5 Integration)
  Author: Angga Firmansyah — AI Lead (A4/A5), FP-SOC-K3
=============================================================

Side-car yang berjalan di Wazuh Manager. Membaca alert baru dari
/var/ossec/logs/alerts/alerts.json, mengklasifikasi TP/FP pakai
model.pkl (Random Forest), lalu memutuskan 1 dari 3 zona:

    ZONA 1  FILTERED_FP      confidence >= 0.85   -> alert difilter
    ZONA 2  NEEDS_REVIEW     0.60 <= conf < 0.85  -> human triage (Syifa)
    ZONA 3  FORWARD_TO_SOAR confidence <  0.60    -> teruskan ke SOAR

Catatan konvensi confidence:
    confidence = P(False Positive) = predict_proba(X)[:, 0]
    (bukan P(TP)) — lihat notebook cell 20.

DESAIN AMAN (sesuai implementation plan):
    - TIDAK memodifikasi core Wazuh (wazuh-analysisd).
    - Berjalan sebagai service terpisah (side-car) via systemd.
    - Hanya MEMBACA alerts.json (read-only). Output ditulis ke folder
      /var/ossec/ai-filter/ yang tidak mengganggu Wazuh.
    - Tracking offset via .offset file -> tahan restart, tidak reprocess.

USAGE (live di Manager):
    sudo python3 ai_filter.py --config config.yaml
    sudo python3 ai_filter.py --config config.yaml --once   # proses sekali lalu keluar

USAGE (test lokal, tidak butuh Wazuh):
    python3 -m pytest tests/    # lihat tests/test_ai_filter.py
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import joblib
import yaml

# Import modul sejawat di folder yang sama
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import (  # noqa: E402
    FreqTracker,
    extract_features,
    features_to_vector,
    load_feature_columns,
)
from feedback import record_feedback  # noqa: E402

# Decision labels
FILTERED_FP = "FILTERED_FP"
NEEDS_REVIEW = "NEEDS_REVIEW"
FORWARD_TO_SOAR = "FORWARD_TO_SOAR"

# Rule yang memicu SOAR (untuk mode exec forwarding)
SOAR_RULES_FIREWALL = {"100402"}              # firewall-drop
SOAR_RULES_MALWARE = {"100300", "100301"}     # remove-malware.py


# =============================================================
#  LOGGER
# =============================================================
def setup_logger(log_dir: str, level: str = "INFO") -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("ai_filter")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(os.path.join(log_dir, "ai_filter.log"), encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


# =============================================================
#  CORE CLASSIFIER
# =============================================================
class AIFilter:
    """Load model + lakukan klasifikasi 1 alert."""

    def __init__(self, config: dict, base_dir: str):
        self.cfg = config
        self.base = base_dir

        # Resolve path relatif terhadap config (folder integration/)
        self.model_path = self._resolve(config["model_path"])
        self.scaler_path = self._resolve(config["scaler_path"])
        self.fc_path = self._resolve(config["feature_columns"])

        self.feature_columns = load_feature_columns(self.fc_path)
        self.model = joblib.load(self.model_path)
        # scaler mungkin tidak dipakai RF, tapi load bila ada (untuk LR)
        self.scaler = None
        if os.path.exists(self.scaler_path):
            try:
                self.scaler = joblib.load(self.scaler_path)
            except Exception:
                self.scaler = None

        self.target_rules = {str(r) for r in config.get("target_rule_ids", [])}
        self.th_filter = float(config["thresholds"]["filter_fp"])
        self.th_review = float(config["thresholds"]["needs_review"])

        self.freq_tracker = FreqTracker(int(config.get("freq_window", {}).get("seconds", 60)))

    def _resolve(self, rel: str) -> str:
        if os.path.isabs(rel):
            return rel
        return os.path.normpath(os.path.join(self.base, rel))

    def is_target(self, alert: dict) -> bool:
        rid = str((alert.get("rule") or {}).get("id", ""))
        return rid in self.target_rules

    def classify(self, alert: dict) -> Dict[str, object]:
        """
        Klasifikasi 1 alert. Mengembalikan dict:
          {rule_id, src_ip, confidence, decision, feature_vector}
        confidence = P(FP) di skala 0..1.
        """
        rule_id = str((alert.get("rule") or {}).get("id", ""))
        src_ip = self._extract_src_ip(alert)

        # epoch untuk freq window: pakai timestamp alert bila ada
        epoch = self._alert_epoch(alert)
        self.freq_tracker.record(src_ip, epoch)
        freq = self.freq_tracker.count(src_ip, epoch)

        feat = extract_features(alert, freq_per_minute=freq,
                                feature_columns=self.feature_columns)
        X = [features_to_vector(feat, self.feature_columns)]

        # RF tidak butuh scaler; bila model ternyata LR, apply scaler
        if self.scaler is not None and self._needs_scaling():
            X = self.scaler.transform(X)

        proba = self.model.predict_proba(X)[0]
        # Kelas 0 = FP (False Positive). predict_proba urutan sesuai model.classes_
        # Default sklearn: classes_ sorted -> [0, 1], jadi [:,0]=P(FP)
        confidence_fp = float(proba[0]) if self.model.classes_[0] == 0 else float(1 - proba[0])

        decision = self._decide(confidence_fp)
        return {
            "rule_id": rule_id,
            "src_ip": src_ip,
            "freq_per_minute": freq,
            "confidence": round(confidence_fp, 4),
            "decision": decision,
            "features": feat,
        }

    def _decide(self, confidence_fp: float) -> str:
        if confidence_fp >= self.th_filter:
            return FILTERED_FP
        if confidence_fp >= self.th_review:
            return NEEDS_REVIEW
        return FORWARD_TO_SOAR

    def _needs_scaling(self) -> bool:
        """RF tidak butuh scaler. Deteksi sederhana dari nama kelas model."""
        return "Logistic" in type(self.model).__name__

    @staticmethod
    def _extract_src_ip(alert: dict) -> str:
        # delegate ke feature_extractor agar konsisten
        from feature_extractor import extract_src_ip
        return extract_src_ip(alert)

    @staticmethod
    def _alert_epoch(alert: dict) -> float:
        ts = alert.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return time.time()


# =============================================================
#  OFFSET TRACKING (tahan restart)
# =============================================================
def read_offset(path: str) -> int:
    try:
        with open(path, "r") as f:
            return int(f.read().strip() or "0")
    except (FileNotFoundError, ValueError):
        return 0


def write_offset(path: str, offset: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(str(offset))


# =============================================================
#  ALERTS TAILING + DISPATCH
# =============================================================
def iter_new_alerts(path: str, offset: int) -> tuple:
    """
    Baca baris baru dari alerts.json mulai offset.
    Mengembalikan (list_of_alerts, new_offset).
    Truncate-tolerant: bila file lebih kecil dari offset, reset ke 0.
    """
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return [], offset
    if size < offset:
        # log rotated / truncate -> mulai dari awal
        offset = 0

    alerts: List[dict] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                # baris parsial; skip, offset di-fix nanti
                break
        new_offset = f.tell()
    return alerts, new_offset


class DecisionLogger:
    """Tulis keputusan AI ke beberapa output file (audit + benchmark)."""

    def __init__(self, log_dir: str, feedback_dir: str, forwarding_cfg: dict):
        self.log_dir = log_dir
        self.feedback_dir = feedback_dir
        self.forwarding = forwarding_cfg
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(feedback_dir, exist_ok=True)

        self.decisions_path = os.path.join(log_dir, "ai_decisions.log")
        self.filtered_path = os.path.join(log_dir, "filtered_fp.log")
        self.review_path = os.path.join(log_dir, "needs_review.csv")
        self.forwarded_path = os.path.join(log_dir, "forwarded_to_soar.log")

        # init CSV header untuk needs_review
        if not os.path.exists(self.review_path):
            with open(self.review_path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    "timestamp", "alert_id", "rule_id", "src_ip",
                    "confidence", "decision", "freq", "analyst_verdict", "note"
                ])

    def log_decision(self, alert: dict, result: dict, logger: logging.Logger) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        alert_id = str(alert.get("id") or alert.get("_id") or
                       (alert.get("rule", {}).get("id", "") +
                        str(alert.get("timestamp", ""))))
        line = (f"{ts} | id={alert_id} rule={result['rule_id']} "
                f"src={result['src_ip'] or '-'} freq={result['freq_per_minute']} "
                f"conf={result['confidence']} -> {result['decision']}")

        # Selalu catat ke decisions.log (audit lengkap)
        with open(self.decisions_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        logger.info(line)

        decision = result["decision"]

        if decision == FILTERED_FP:
            with open(self.filtered_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

        elif decision == NEEDS_REVIEW:
            # Tulis ke CSV untuk human triage (Syifa)
            with open(self.review_path, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    ts, alert_id, result["rule_id"], result["src_ip"],
                    result["confidence"], decision, result["freq_per_minute"], "", ""
                ])

        elif decision == FORWARD_TO_SOAR:
            # Catat ke forwarded log
            with open(self.forwarded_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            # Eksekusi SOAR bila mode=exec
            self._maybe_trigger_soar(alert, result, logger)

    def _maybe_trigger_soar(self, alert: dict, result: dict,
                            logger: logging.Logger) -> None:
        if not self.forwarding.get("enabled", False):
            return
        method = self.forwarding.get("method", "log")
        if method != "exec":
            return

        rule_id = result["rule_id"]
        src_ip = result["src_ip"]
        soar = self.forwarding.get("soar", {})

        try:
            if rule_id in SOAR_RULES_FIREWALL and src_ip:
                cmd = soar.get("firewall_drop", "firewall-drop")
                logger.warning(f"[SOAR-EXEC] firewall-drop untuk {src_ip} (rule {rule_id})")
                # Active response script dipanggil via agent_control/active-responses
                # Implementasi sebenarnya tergantung deploy; di sini di-log saja aman.
                self._exec_active_response(cmd, src_ip, logger)
            elif rule_id in SOAR_RULES_MALWARE:
                cmd = soar.get("remove_malware", "remove-malware.py")
                logger.warning(f"[SOAR-EXEC] remove-malware untuk rule {rule_id}")
                self._exec_active_response(cmd, src_ip, logger)
        except Exception as e:
            logger.error(f"[SOAR-EXEC] gagal: {e}")

    @staticmethod
    def _exec_active_response(cmd: str, src_ip: str,
                              logger: logging.Logger) -> None:
        """
        Pemanggilan Active Response non-invasif.

        Default: tulis marker ke log (tidak benar2 menjalankan firewall-drop
        yang bisa self-lockout). Untuk live deploy, admin Wazuh dapat mengaktifkan
        pemanggilan langsung /var/ossec/active-response/bin/<cmd> dengan hati-hati.
        """
        # CATATAN KEAMANAN: eksekusi langsung firewall-drop bisa memblokir IP
        # admin sendiri (lihat setup-soar.md kendala #4). Maka default aman.
        logger.info(f"[SOAR-MARKER] {cmd} queued for {src_ip or 'n/a'} "
                    f"(eksekusi langsung disabled by default)")


# =============================================================
#  MAIN LOOP
# =============================================================
class AIFilterService:
    def __init__(self, config_path: str):
        self.config_path = os.path.abspath(config_path)
        self.base = os.path.dirname(self.config_path)
        with open(self.config_path, "r", encoding="utf-8") as f:
            self.cfg = yaml.safe_load(f)

        self.log_dir = self._resolve(self.cfg.get("log_dir", "/var/ossec/ai-filter"))
        self.feedback_dir = self._resolve(self.cfg.get("feedback_dir",
                                       "/var/ossec/ai-filter/feedback"))
        self.logger = setup_logger(self.log_dir, self.cfg.get("log_level", "INFO"))

        self.filter = AIFilter(self.cfg, self.base)
        self.alerts_json = self.cfg.get("alerts_json",
                                        "/var/ossec/logs/alerts/alerts.json")
        self.offset_file = self._resolve(self.cfg.get("offset_file",
                                        "/var/ossec/ai-filter/.offset"))
        self.poll_interval = int(self.cfg.get("poll_interval", 2))
        self.decision_logger = DecisionLogger(
            self.log_dir, self.feedback_dir, self.cfg.get("forwarding", {}))

        self._running = True

    def _resolve(self, rel: str) -> str:
        if os.path.isabs(rel):
            return rel
        return os.path.normpath(os.path.join(self.base, rel))

    def stop(self, *_):
        self._running = False
        self.logger.info("Shutdown signal diterima, berhenti setelah poll ini...")

    def run(self, once: bool = False) -> None:
        self.logger.info("=" * 60)
        self.logger.info("AI Filter (A5) mulai berjalan")
        self.logger.info(f"  alerts_json   : {self.alerts_json}")
        self.logger.info(f"  model         : {self.filter.model_path}")
        self.logger.info(f"  target_rules  : {sorted(self.filter.target_rules)}")
        self.logger.info(f"  thresholds    : filter>={self.filter.th_filter}, "
                         f"review>={self.filter.th_review}")
        self.logger.info("=" * 60)

        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

        offset = read_offset(self.offset_file)

        while self._running:
            try:
                alerts, offset = iter_new_alerts(self.alerts_json, offset)
                if alerts:
                    write_offset(self.offset_file, offset)
                    processed = 0
                    for alert in alerts:
                        if not self.filter.is_target(alert):
                            continue
                        result = self.filter.classify(alert)
                        self.decision_logger.log_decision(alert, result, self.logger)
                        processed += 1
                    if processed:
                        self.logger.info(f"Proses {processed} alert target "
                                         f"(dari {len(alerts)} total baris)")
                else:
                    write_offset(self.offset_file, offset)
            except FileNotFoundError:
                self.logger.warning(f"alerts.json belum ada: {self.alerts_json} "
                                    "(deploy di Wazuh Manager)")
            except Exception as e:
                self.logger.exception(f"Error di loop: {e}")

            if once:
                break
            time.sleep(self.poll_interval)

        self.logger.info("AI Filter berhenti.")


# =============================================================
#  CLI
# =============================================================
def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_cfg = os.path.join(here, "config.yaml")

    p = argparse.ArgumentParser(description="AI False-Alarm Filter (A5)")
    p.add_argument("--config", default=default_cfg, help="path config.yaml")
    p.add_argument("--once", action="store_true",
                   help="proses alert baru sekali lalu keluar (test mode)")
    p.add_argument("--classify", metavar="JSON_FILE",
                   help="klasifikasi 1 alert dari file JSON lalu keluar (test mode)")
    args = p.parse_args()

    # Mode cepat: klasifikasi single alert (tanpa loop) untuk test
    if args.classify:
        with open(args.classify, "r", encoding="utf-8") as f:
            alert = json.load(f)
        svc = AIFilterService(args.config)
        result = svc.filter.classify(alert)
        print(json.dumps(result, indent=2, default=str))
        return

    svc = AIFilterService(args.config)
    svc.run(once=args.once)


if __name__ == "__main__":
    main()
