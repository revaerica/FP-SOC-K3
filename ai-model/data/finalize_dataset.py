#!/usr/bin/env python3
"""
=============================================================
  finalize_dataset.py — Finalisasi CSV Dataset untuk Shinta
  Author: Syifa (A3) — FP-SOC-K3
  
  Jalankan SETELAH selesai labeling raw_alerts.csv:
    python3 finalize_dataset.py raw_alerts.csv labeled_alerts.csv
  
  Script ini:
  1. Validasi semua baris sudah dilabeli (tidak ada label kosong)
  2. Hapus kolom bantu (src_ip, description, full_log_snippet, auto_suggestion)
  3. Cek proporsi TP:FP
  4. Output: labeled_alerts.csv siap untuk Shinta
=============================================================
"""
import csv
import sys
import os

# Kolom yang dibutuhkan model (urutan HARUS persis seperti feature_columns.json)
REQUIRED_COLUMNS = ["rule_id", "rule_level", "freq_per_minute", "hour_of_day", "src_port", "dst_port", "label"]

def validate_and_finalize(input_file, output_file):
    print(f"[*] Membaca {input_file}...")
    
    rows = []
    errors = []
    
    with open(input_file, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        
        # Cek kolom yang ada
        print(f"[*] Kolom ditemukan: {reader.fieldnames}")
        
        for col in REQUIRED_COLUMNS:
            if col not in reader.fieldnames:
                print(f"[ERROR] Kolom '{col}' tidak ditemukan di CSV!")
                sys.exit(1)
        
        for i, row in enumerate(reader, 2):  # 2 karena header = baris 1
            # Cek label tidak kosong
            label = row.get("label", "").strip()
            if label == "" or label == "?":
                errors.append(f"  Baris {i}: label kosong/belum diisi (rule_id={row.get('rule_id')})")
                continue
            
            if label not in ("0", "1"):
                errors.append(f"  Baris {i}: label invalid '{label}' (harus 0 atau 1)")
                continue
            
            # Validasi numerik
            try:
                clean_row = {
                    "rule_id": int(row["rule_id"]),
                    "rule_level": int(row["rule_level"]),
                    "freq_per_minute": int(float(row["freq_per_minute"])),
                    "hour_of_day": int(row["hour_of_day"]),
                    "src_port": int(row.get("src_port", 0) or 0),
                    "dst_port": int(row.get("dst_port", 0) or 0),
                    "label": int(label),
                }
                rows.append(clean_row)
            except (ValueError, TypeError) as e:
                errors.append(f"  Baris {i}: error konversi — {e}")
    
    # Report errors
    if errors:
        print(f"\n[!] Ditemukan {len(errors)} baris bermasalah:")
        for err in errors[:20]:  # Tampilkan max 20
            print(err)
        if len(errors) > 20:
            print(f"  ... dan {len(errors) - 20} error lainnya")
        print(f"\n[!] Baris valid: {len(rows)}")
        
        if len(rows) == 0:
            print("[ERROR] Tidak ada baris valid. Perbaiki file dulu!")
            sys.exit(1)
        
        resp = input("\nLanjutkan dengan baris yang valid saja? (y/n): ").strip().lower()
        if resp != 'y':
            print("Dibatalkan.")
            sys.exit(0)
    
    # Hitung statistik
    tp_count = sum(1 for r in rows if r["label"] == 1)
    fp_count = sum(1 for r in rows if r["label"] == 0)
    total = len(rows)
    
    print(f"\n{'='*50}")
    print(f"STATISTIK DATASET")
    print(f"{'='*50}")
    print(f"Total baris valid  : {total}")
    print(f"True Positive (1)  : {tp_count} ({tp_count/total*100:.1f}%)")
    print(f"False Positive (0) : {fp_count} ({fp_count/total*100:.1f}%)")
    
    # Warnings
    if total < 150:
        print(f"\n[WARNING] Dataset kurang dari 150 baris! Target minimal 150.")
    
    if tp_count / total > 0.80:
        print(f"\n[WARNING] Proporsi TP terlalu tinggi ({tp_count/total*100:.0f}%). Target 65-70%.")
        print("  Tambahkan lebih banyak skenario FP (traffic normal).")
    
    if fp_count / total > 0.50:
        print(f"\n[WARNING] Proporsi FP terlalu tinggi ({fp_count/total*100:.0f}%). Target 30-35%.")
    
    # Rule distribution
    from collections import Counter
    rule_dist = Counter(r["rule_id"] for r in rows)
    print(f"\nDistribusi per Rule ID:")
    for rule_id, count in sorted(rule_dist.items()):
        tp_in_rule = sum(1 for r in rows if r["rule_id"] == rule_id and r["label"] == 1)
        fp_in_rule = count - tp_in_rule
        print(f"  Rule {rule_id}: {count} total ({tp_in_rule} TP, {fp_in_rule} FP)")
    
    # Write final CSV
    print(f"\n[*] Menulis {output_file}...")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=REQUIRED_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"[OK] Dataset final tersimpan: {output_file}")
    print(f"[OK] {total} baris, {len(REQUIRED_COLUMNS)} kolom")
    print(f"[OK] Kolom: {', '.join(REQUIRED_COLUMNS)}")
    print(f"\n[NEXT] Kirim file ini ke Shinta!")
    print(f"  cp {output_file} ai-model/data/labeled_alerts.csv")
    print(f"  git add ai-model/data/labeled_alerts.csv")
    print(f"  git commit -m 'feat(data): labeled dataset dari Syifa'")
    print(f"  git push")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 finalize_dataset.py <input_csv> [output_csv]")
        print("  input_csv  = raw_alerts.csv yang sudah dilabeli")
        print("  output_csv = (opsional) default: labeled_alerts.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "labeled_alerts.csv"
    
    if not os.path.exists(input_file):
        print(f"[ERROR] File '{input_file}' tidak ditemukan!")
        sys.exit(1)
    
    validate_and_finalize(input_file, output_file)
