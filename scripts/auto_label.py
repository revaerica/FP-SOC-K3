"""
Auto-label wrapper — menjalankan auto_label.py kanonik di ai-model/data/.

Catatan: Versi kanonik (sumber kebenaran) berada di:
    ai-model/data/auto_label.py
File ini disimpan hanya untuk kompatibilitas pemanggilan lama dari folder scripts/.
Logika labeling tidak diduplikasi agar tidak terjadi drift antar 2 versi.

Usage:
    python3 scripts/auto_label.py [input.csv] [output.csv]

Author: A3 (Data & Kriteria) — wrapper oleh Angga (A4/A5 AI Lead)
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
CANONICAL = os.path.normpath(os.path.join(_HERE, "..", "ai-model", "data", "auto_label.py"))

if __name__ == "__main__":
    # Teruskan argumen (input/output path opsional) ke versi kanonik
    sys.argv[0] = CANONICAL
    # Baca modul kanonik sebagai __main__ supaya blok __main__-nya jalan
    with open(CANONICAL, "r", encoding="utf-8") as f:
        code = f.read()
    exec(compile(code, CANONICAL, "exec"), {"__name__": "__main__", "__file__": CANONICAL})
