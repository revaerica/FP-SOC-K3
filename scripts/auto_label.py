"""
Auto-label raw_alerts.csv and produce labeled_alerts.csv
Based on false-alarm-criteria.md
"""
import csv
from collections import Counter, defaultdict

INPUT = r"c:\sem4\soc\fp\FP-SOC-K3\ai-model\data\raw_alerts.csv"
OUTPUT = r"c:\sem4\soc\fp\FP-SOC-K3\ai-model\data\labeled_alerts.csv"

# Known IP categories
INTERNAL_IPS = {"127.0.0.1", "127.0.0.53"}
AZURE_HEALTH = {"168.63.129.16"}
ATTACKER_IP = "70.153.25.99"  # Agent-2

# Whitelisted from ossec-manager.conf
WHITELIST = {"103.94.191.164"}

def is_internal(ip):
    return ip in INTERNAL_IPS or ip.startswith("10.0.0.") or ip in AZURE_HEALTH or ip in WHITELIST

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

    # === ICMP Flood (100202) ===
    if rule_id == 100202:
        if is_internal(src_ip) or src_ip in AZURE_HEALTH:
            return 0
        if freq > 30:
            return 1
        return 0

    # === HTTP request (100400) — always FP (helper rule) ===
    if rule_id == 100400:
        return 0

    # === HTTP Flood (100402) ===
    if rule_id == 100402:
        if is_internal(src_ip):
            return 0
        return 1  # HTTP flood = TP

    return 0  # default


def main():
    print(f"[*] Reading {INPUT}...")
    rows = []
    with open(INPUT, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print(f"[*] Total rows: {len(rows)}")

    # Analyze before labeling
    print("\n=== DATA DISTRIBUTION ===")
    rule_counts = Counter(r["rule_id"] for r in rows)
    for rid, cnt in sorted(rule_counts.items()):
        print(f"  Rule {rid}: {cnt}")

    ip_counts = Counter(r.get("src_ip", "") for r in rows)
    print(f"\n=== TOP 15 SOURCE IPs ===")
    for ip, cnt in ip_counts.most_common(15):
        cat = "INTERNAL" if is_internal(ip) else "EXTERNAL"
        print(f"  {ip or '(empty)'}: {cnt} [{cat}]")

    freq_counts = Counter(r["freq_per_minute"] for r in rows)
    print(f"\n=== FREQ VALUES ===")
    for freq, cnt in sorted(freq_counts.items(), key=lambda x: int(x[0])):
        print(f"  freq={freq}: {cnt}")

    # Label all
    print("\n[*] Auto-labeling...")
    for row in rows:
        row["label"] = label_alert(row)

    # Stats
    tp = sum(1 for r in rows if r["label"] == 1)
    fp = sum(1 for r in rows if r["label"] == 0)
    print(f"\n=== LABEL DISTRIBUTION (ALL {len(rows)} rows) ===")
    print(f"  TP (1): {tp} ({tp/len(rows)*100:.1f}%)")
    print(f"  FP (0): {fp} ({fp/len(rows)*100:.1f}%)")

    # Per-rule breakdown
    print(f"\n=== PER-RULE LABEL BREAKDOWN ===")
    for rid in sorted(rule_counts.keys()):
        tp_r = sum(1 for r in rows if r["rule_id"] == rid and r["label"] == 1)
        fp_r = sum(1 for r in rows if r["rule_id"] == rid and r["label"] == 0)
        print(f"  Rule {rid}: {tp_r} TP, {fp_r} FP")

    # === SAMPLING: we need ~200-300 rows, balanced 65:35 ===
    import random
    random.seed(42)

    target_total = 250
    target_tp = int(target_total * 0.65)  # ~162
    target_fp = target_total - target_tp   # ~88

    tp_rows = [r for r in rows if r["label"] == 1]
    fp_rows = [r for r in rows if r["label"] == 0]

    # Sample
    sampled_tp = random.sample(tp_rows, min(target_tp, len(tp_rows)))
    sampled_fp = random.sample(fp_rows, min(target_fp, len(fp_rows)))

    sampled = sampled_tp + sampled_fp
    random.shuffle(sampled)

    actual_tp = sum(1 for r in sampled if r["label"] == 1)
    actual_fp = sum(1 for r in sampled if r["label"] == 0)

    print(f"\n=== SAMPLED DATASET ===")
    print(f"  Total: {len(sampled)}")
    print(f"  TP: {actual_tp} ({actual_tp/len(sampled)*100:.1f}%)")
    print(f"  FP: {actual_fp} ({actual_fp/len(sampled)*100:.1f}%)")

    # Sampled per-rule
    sampled_rule = Counter(r["rule_id"] for r in sampled)
    print(f"\n  Per-rule in sample:")
    for rid, cnt in sorted(sampled_rule.items()):
        tp_s = sum(1 for r in sampled if r["rule_id"] == rid and r["label"] == 1)
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
