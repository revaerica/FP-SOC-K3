#!/usr/bin/env python3
"""
=============================================================
  feature_extractor.py — Ekstraksi Fitur Alert Wazuh → Model AI
  Author: Angga Firmansyah — A5 Integration (FP-SOC-K3)
=============================================================

Modul ini adalah SUMBER KEBENARAN TUNGGAL untuk transformasi
1 alert Wazuh (dict JSON) menjadi 6 fitur numerik yang dimakan
model.pkl.

Dipakai oleh:
  - ai_filter.py        (inferensi live)
  - tests/              (validasi & benchmark)

URUTAN FITUR (HARUS sama dengan training/feature_columns.json):
    rule_id, rule_level, freq_per_minute, hour_of_day, src_port, dst_port

Catatan penting konsistensi:
  - Training tidak memakai src_ip sebagai fitur (lihat SOC_training.ipynb
    cell 8). Jadi extractor ini juga TIDAK mengeluarkan src_ip sebagai
    fitur — meskipun src_ip dipakai internal untuk menghitung freq_per_minute.
  - Mekanisme perhitungan freq_per_minute sengaja disamakan dengan
    data/extract_alerts.py (window ±60 detik per src_ip).
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

FEATURE_COLUMNS_DEFAULT: Tuple[str, ...] = (
    "rule_id",
    "rule_level",
    "freq_per_minute",
    "hour_of_day",
    "src_port",
    "dst_port",
)

# Pattern dipakai untuk ekstraksi src_ip dari full_log (fallback)
_IP_RE = re.compile(r"SRC=(\d{1,3}(?:\.\d{1,3}){3})")
_LEADING_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})")


def load_feature_columns(path: str) -> List[str]:
    """Baca feature_columns.json. Kalau tidak ada, pakai default."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            cols = json.load(f)
        if isinstance(cols, list) and len(cols) >= 6:
            return [str(c) for c in cols]
    except FileNotFoundError:
        pass
    return list(FEATURE_COLUMNS_DEFAULT)


def _safe_int(value: Any, default: int = 0) -> int:
    """Parse nilai ke int aman (None/str kosong/float -> int/default)."""
    if value is None:
        return default
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return default


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse timestamp Wazuh. Wazuh umumnya pakai ISO 8601 (+00:00)."""
    if not ts_str:
        return None
    # Coba beberapa format umum
    for parser in (
        lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")),
    ):
        try:
            return parser(ts_str)
        except (ValueError, TypeError):
            continue
    return None


def extract_src_ip(alert: Dict[str, Any]) -> str:
    """Ambil src_ip dari alert. Coba data.srcip dulu, fallback ke full_log."""
    data = alert.get("data", {}) or {}
    ip = data.get("srcip") or data.get("src_ip")
    if ip:
        return str(ip)
    full_log = alert.get("full_log", "") or ""
    m = _IP_RE.search(full_log)
    if m:
        return m.group(1)
    m = _LEADING_IP_RE.search(full_log)
    if m:
        return m.group(1)
    return ""


def extract_port(data: Dict[str, Any], *keys: str) -> int:
    """Ambil port dari salah satu key kandidat (srcport/src_port/dstport/dst_port)."""
    for k in keys:
        v = data.get(k)
        if v not in (None, ""):
            return _safe_int(v)
    return 0


class FreqTracker:
    """
    Sliding window counter untuk menghitung freq_per_minute.

    Memakai deque per src_ip, menyimpan epoch second tiap alert dari IP tsb.
    Saat query, buang entry lebih tua dari `window_seconds`, lalu hitung sisa.

    Thread-safety: ai_filter single-threaded; tidak pakai lock.
    """

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._events: Dict[str, deque] = {}

    def record(self, src_ip: str, epoch: float) -> None:
        """Catat 1 event untuk src_ip pada waktu epoch (detik)."""
        if not src_ip:
            return
        dq = self._events.setdefault(src_ip, deque())
        dq.append(epoch)
        self._prune(src_ip, epoch)

    def _prune(self, src_ip: str, now_epoch: float) -> None:
        dq = self._events.get(src_ip)
        if not dq:
            return
        cutoff = now_epoch - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def count(self, src_ip: str, now_epoch: float) -> int:
        """Hitung jumlah event src_ip dalam window (termasuk saat ini)."""
        if not src_ip:
            return 1
        self._prune(src_ip, now_epoch)
        return len(self._events.get(src_ip, ()))


def extract_features(
    alert: Dict[str, Any],
    freq_per_minute: int = 1,
    feature_columns: Optional[List[str]] = None,
) -> Dict[str, int]:
    """
    Ubah 1 alert Wazuh menjadi dict fitur sesuai feature_columns.

    freq_per_minute harus sudah dihitung pemanggil (via FreqTracker) supaya
    konsisten dengan training. Default 1 bila tidak relevan (alert tunggal).

    Mengembalikan dict: {col_name: value} dalam urutan feature_columns.
    """
    cols = feature_columns or list(FEATURE_COLUMNS_DEFAULT)

    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}

    rule_id = _safe_int(rule.get("id"))
    rule_level = _safe_int(rule.get("level"))
    hour_of_day = 0
    ts = parse_timestamp(alert.get("timestamp", ""))
    if ts is not None:
        hour_of_day = ts.hour

    src_port = extract_port(data, "srcport", "src_port")
    dst_port = extract_port(data, "dstport", "dst_port")

    raw = {
        "rule_id": rule_id,
        "rule_level": rule_level,
        "freq_per_minute": int(freq_per_minute),
        "hour_of_day": hour_of_day,
        "src_port": src_port,
        "dst_port": dst_port,
    }
    # Pastikan urutan & keberadaan key persis = feature_columns
    return {c: raw[c] for c in cols}


def features_to_vector(
    feat: Dict[str, int], feature_columns: List[str]
) -> List[int]:
    """Susun dict fitur menjadi list sesuai urutan feature_columns (input model)."""
    return [int(feat[c]) for c in feature_columns]
