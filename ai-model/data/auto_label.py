"""
Auto-label raw_alerts.csv and produce labeled_alerts.csv
Based on false-alarm-criteria.md (Only real data, no synthetic data)
"""
import csv
import re
import random
from collections import Counter, defaultdict
from datetime import datetime

INPUT = r"c:\sem4\soc\fp\FP-SOC-K3\ai-model\data\raw_alerts.csv"
OUTPUT = r"c:\sem4\soc\fp\FP-SOC-K3\ai-model\data\labeled_alerts.csv"

# Known IP categories
INTERNAL_IPS = {"127.0.0.1", "127.0.0.53"}
AZURE_HEALTH = {"168.63.129.16"}
ATTACKER_IP = "70.153.25.99"  # Agent-2
WHITELIST = {"103.94.191.164"}

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def is_internal(ip):
    return ip in INTERNAL_IPS or ip.startswith("10.0.0.") or ip in AZURE_HEALTH or ip in WHITELIST

def parse_syslog_ts(snippet):
    """Parse Month Day HH:MM:SS from the full_log_snippet"""
    match = re.search(r'([A-Za-z]{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})', snippet)
    if not match:
        return None
    month_str, day_str, hour_str, min_str, sec_str = match.groups()
    month = MONTHS.get(month_str, 6)
    day = int(day_str)
    hour = int(hour_str)
    minute = int(min_str)
    second = int(sec_str)
    # Use 2026 as the standard year
    return datetime(2026, month, day, hour, minute, second)

def label_alert(row):
    """Auto-label based on false-alarm-criteria.md"""
    rule_id = int(row["rule_id"])
    freq = int(row["freq_per_minute"])
    src_ip = row.get("src_ip", "")
    dst_port = int(row["dst_port"]) if row["dst_port"] else 0
    src_port = int(row["src_port"]) if row["src_port"] else 0

    # === MALWARE: Always TP ===
    if rule_id in (100300, 100301, 100302):
        return 1  # TP

    # === UDP Flood (100201) ===
    if rule_id == 100201:
        # Loopback DNS traffic (127.0.0.1 → 127.0.0.53 port 53) = FP
        if src_ip in INTERNAL_IPS and (dst_port == 53 or src_port == 53):
            return 0  # FP — internal DNS resolver
        # Azure health probe
        if src_ip in AZURE_HEALTH:
            return 0  # FP — Azure infrastructure
        # External IP with high freq
        if not is_internal(src_ip) and freq > 30:
            return 1  # TP
        # Low freq from anywhere
        if freq < 10:
            return 0  # FP
        # Default for UDP
        if is_internal(src_ip):
            return 0
        return 1  # External + moderate freq = TP

    # === SYN Flood (100200) ===
    if rule_id == 100200:
        # Internal IP
        if is_internal(src_ip):
            return 0  # FP
        # Known attacker
        if src_ip == ATTACKER_IP:
            return 1  # TP
        # External with high freq = real attack (including internet bots hitting SSH)
        if freq > 30:
            return 1  # TP — real brute force / scan
        # External with moderate freq targeting port 22 = SSH scan/attack
        if dst_port == 22 and freq > 5:
            return 1  # TP — SSH brute force attempt
        # Low freq from external
        if freq < 5:
            return 0  # FP — sporadic connection attempt
        # Default for external SYN
        return 1  # TP

    return 0  # default


def main():
    print(f"[*] Reading {INPUT}...")
    rows = []
    with open(INPUT, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print(f"[*] Total raw rows: {len(rows)}")

    # === 1. CORRECT THE BUGS LOCALLY ===
    print("[*] Re-parsing timestamps and recomputing frequency...")
    
    # Parse timestamps from syslog snippet
    for row in rows:
        ts = parse_syslog_ts(row["full_log_snippet"])
        if ts:
            row["_ts"] = ts
            row["hour_of_day"] = str(ts.hour)
        else:
            row["_ts"] = datetime.min
            row["hour_of_day"] = "0"

    # Sort rows by timestamp
    rows.sort(key=lambda x: x["_ts"])

    # Group rows by source IP to optimize sliding window frequency check
    ip_to_indices = {}
    for i, r in enumerate(rows):
        ip = r.get("src_ip", "")
        if ip not in ip_to_indices:
            ip_to_indices[ip] = []
        ip_to_indices[ip].append(i)

    # Recompute frequency count within ±60s window
    for ip, indices in ip_to_indices.items():
        if not ip:
            for idx in indices:
                rows[idx]["freq_per_minute"] = "1"
            continue
            
        m = len(indices)
        left = 0
        right = 0
        for i, idx in enumerate(indices):
            ts = rows[idx]["_ts"]
            
            # Slide left pointer to start of 60s window
            while left < m and (ts - rows[indices[left]]["_ts"]).total_seconds() > 60:
                left += 1
                
            # Slide right pointer to end of 60s window
            while right < m and (rows[indices[right]]["_ts"] - ts).total_seconds() <= 60:
                right += 1
                
            rows[idx]["freq_per_minute"] = str(right - left)

    # === 2. OVERWRITE RAW CSV WITH CORRECTED VALUES ===
    print(f"[*] Overwriting {INPUT} with corrected features...")
    RAW_COLS = ["rule_id", "rule_level", "freq_per_minute", "hour_of_day", "src_port", "dst_port", "src_ip", "description", "full_log_snippet", "label"]
    
    # Pre-calculate labels for raw dataset
    for row in rows:
        row["label"] = str(label_alert(row))

    with open(INPUT, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=RAW_COLS, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"[OK] {INPUT} corrected successfully!")

    # Analyze before sampling
    print("\n=== CORRECTED DATA DISTRIBUTION ===")
    rule_counts = Counter(r["rule_id"] for r in rows)
    for rid, cnt in sorted(rule_counts.items()):
        print(f"  Rule {rid}: {cnt}")

    ip_counts = Counter(r.get("src_ip", "") for r in rows)
    print(f"\n=== TOP 10 SOURCE IPs ===")
    for ip, cnt in ip_counts.most_common(10):
        cat = "INTERNAL" if is_internal(ip) else "EXTERNAL"
        print(f"  {ip or '(empty)'}: {cnt} [{cat}]")

    # Label stats
    tp = sum(1 for r in rows if r["label"] == "1")
    fp = sum(1 for r in rows if r["label"] == "0")
    print(f"\n=== CORRECTED LABEL DISTRIBUTION ===")
    print(f"  TP (1): {tp} ({tp/len(rows)*100:.3f}%)")
    print(f"  FP (0): {fp} ({fp/len(rows)*100:.3f}%)")

    # Per-rule breakdown
    print(f"\n=== PER-RULE LABEL BREAKDOWN ===")
    for rid in sorted(rule_counts.keys()):
        tp_r = sum(1 for r in rows if r["rule_id"] == rid and r["label"] == "1")
        fp_r = sum(1 for r in rows if r["rule_id"] == rid and r["label"] == "0")
        print(f"  Rule {rid}: {tp_r} TP, {fp_r} FP")

    # === 3. SAMPLING: Real TPs (75) and Sampled FPs (40) ===
    # This keeps target ~65:35 ratio (75:40 = 65.2:34.8)
    random.seed(42)

    tp_rows = [r for r in rows if r["label"] == "1"]
    fp_rows = [r for r in rows if r["label"] == "0"]

    sampled_tp = tp_rows  # Keep all 75 real TPs
    sampled_fp = random.sample(fp_rows, min(40, len(fp_rows)))

    sampled = sampled_tp + sampled_fp
    random.shuffle(sampled)

    actual_tp = sum(1 for r in sampled if r["label"] == "1")
    actual_fp = sum(1 for r in sampled if r["label"] == "0")

    print(f"\n=== FINAL SAMPLED DATASET (REAL DATA ONLY) ===")
    print(f"  Total: {len(sampled)}")
    print(f"  TP: {actual_tp} ({actual_tp/len(sampled)*100:.1f}%)")
    print(f"  FP: {actual_fp} ({actual_fp/len(sampled)*100:.1f}%)")

    # Sampled per-rule
    sampled_rule = Counter(r["rule_id"] for r in sampled)
    print(f"\n  Per-rule in sample:")
    for rid, cnt in sorted(sampled_rule.items()):
        tp_s = sum(1 for r in sampled if r["rule_id"] == rid and r["label"] == "1")
        fp_s = cnt - tp_s
        print(f"    Rule {rid}: {cnt} total ({tp_s} TP, {fp_s} FP)")

    # Write final CSV (only the 6 features + label)
    FINAL_COLS = ["rule_id", "rule_level", "freq_per_minute", "hour_of_day", "src_port", "dst_port", "label"]

    with open(OUTPUT, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FINAL_COLS, extrasaction='ignore')
        writer.writeheader()
        for row in sampled:
            writer.writerow({k: row[k] for k in FINAL_COLS})

    print(f"\n[OK] Saved to {OUTPUT}")
    print(f"[OK] {len(sampled)} rows, columns: {', '.join(FINAL_COLS)}")


if __name__ == "__main__":
    main()
