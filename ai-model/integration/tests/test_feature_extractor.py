#!/usr/bin/env python3
"""
test_feature_extractor.py — Unit test untuk feature_extractor.py
Validasi bahwa ekstraksi 6 fitur dari alert Wazuh benar dan konsisten
dengan training/feature_columns.json.

Jalankan dari folder integration/:
    python -m pytest tests/test_feature_extractor.py -v
atau tanpa pytest:
    python tests/test_feature_extractor.py
"""
import json
import os
import sys

# Tambah folder integration/ ke path
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))

from feature_extractor import (  # noqa: E402
    FreqTracker,
    extract_features,
    extract_src_ip,
    features_to_vector,
    load_feature_columns,
    parse_timestamp,
)

# ---- Helper: bangun alert contoh ----
def make_alert(rule_id=100200, level=12, hour=8, srcport=51864, dstport=22,
               srcip="103.94.191.168", timestamp="2026-06-23T08:30:00.000+00:00",
               full_log=""):
    return {
        "id": "test-1",
        "timestamp": timestamp,
        "rule": {"id": rule_id, "level": level, "description": "test"},
        "data": {"srcip": srcip, "srcport": srcport, "dstport": dstport},
        "full_log": full_log or f"kernel: SYN-FLOOD: SRC={srcip} DST=10.0.0.5",
    }


# ---- TESTS ----
def test_feature_columns_match_training():
    """Urutan fitur HARUS sama dengan feature_columns.json training."""
    fc_path = os.path.normpath(os.path.join(HERE, "..", "..", "training",
                                            "feature_columns.json"))
    cols = load_feature_columns(fc_path)
    expected = ["rule_id", "rule_level", "freq_per_minute", "hour_of_day",
                "src_port", "dst_port"]
    assert cols == expected, f"feature_columns mismatch: {cols} != {expected}"
    print(f"  [OK] feature_columns match: {cols}")


def test_extract_features_basic():
    a = make_alert()
    feat = extract_features(a, freq_per_minute=42)
    assert feat["rule_id"] == 100200
    assert feat["rule_level"] == 12
    assert feat["hour_of_day"] == 8
    assert feat["src_port"] == 51864
    assert feat["dst_port"] == 22
    assert feat["freq_per_minute"] == 42
    print(f"  [OK] basic extraction: {feat}")


def test_extract_features_missing_fields():
    """Alert tanpa field data/rule harus tetap aman (default 0)."""
    a = {"timestamp": "2026-06-23T08:30:00.000+00:00"}
    feat = extract_features(a, freq_per_minute=1)
    assert feat["rule_id"] == 0
    assert feat["rule_level"] == 0
    assert feat["src_port"] == 0
    assert feat["dst_port"] == 0
    assert feat["hour_of_day"] == 8
    print(f"  [OK] missing fields handled: {feat}")


def test_parse_timestamp_variants():
    assert parse_timestamp("2026-06-23T08:30:00.000+00:00") is not None
    assert parse_timestamp("2026-06-23T08:30:00Z") is not None
    assert parse_timestamp("") is None
    assert parse_timestamp("garbage") is None
    dt = parse_timestamp("2026-06-23T08:30:00.000+00:00")
    assert dt.hour == 8
    print("  [OK] timestamp parsing variants")


def test_extract_src_ip_from_data_and_log():
    a = make_alert(srcip="1.2.3.4")
    assert extract_src_ip(a) == "1.2.3.4"
    # fallback ke full_log bila data.srcip kosong
    a2 = {"data": {}, "full_log": "SYN-FLOOD: SRC=9.9.9.9 DST=1.1.1.1"}
    assert extract_src_ip(a2) == "9.9.9.9"
    # bila tidak ada sama sekali
    assert extract_src_ip({"data": {}, "full_log": "nothing here"}) == ""
    print("  [OK] src_ip extraction (data + fallback)")


def test_features_to_vector_order():
    feat = extract_features(make_alert(), freq_per_minute=5)
    cols = list(feat.keys())
    vec = features_to_vector(feat, cols)
    assert vec == [feat[c] for c in cols]
    assert len(vec) == 6
    print(f"  [OK] vector order preserved: {vec}")


def test_freq_tracker_window():
    """FreqTracker menghitung event dalam window 60s."""
    t = FreqTracker(window_seconds=60)
    ip = "10.0.0.5"
    # 5 event dalam 10 detik -> count 5
    for e in range(100, 110, 2):
        t.record(ip, e)
    assert t.count(ip, 109) == 5, f"expected 5, got {t.count(ip, 109)}"
    # event lama (100-108) di luar window saat query di 200 -> ter-prune -> 0
    assert t.count(ip, 200) == 0, "event lama harus terbuang (0, bukan 1)"
    # record event baru di 200 -> count 1
    t.record(ip, 200)
    assert t.count(ip, 200) == 1
    # IP berbeda tidak tercampur
    t.record("8.8.8.8", 200)
    assert t.count("10.0.0.5", 200) == 1
    assert t.count("8.8.8.8", 200) == 1
    print("  [OK] freq_tracker sliding window")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        print(f"[RUN] {t.__name__}")
        t()
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed")


if __name__ == "__main__":
    _run_all()
    # pytest compatibility: bila dipanggil via pytest, fungsi test_ diambil otomatis
