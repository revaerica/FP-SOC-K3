#!/usr/bin/env python3
"""
=============================================================
  extract_alerts.py — Extract Alert Wazuh → CSV untuk Dataset AI
  Author: Syifa (A3) — FP-SOC-K3
  
  Jalankan di Wazuh Manager:
    sudo python3 extract_alerts.py
  
  Output: /tmp/raw_alerts.csv (siap dilabeli manual)
=============================================================
"""
import json
import csv
import re
import sys
from datetime import datetime
from collections import Counter

# =============================================
# CONFIG
# =============================================
ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
OUTPUT_CSV = "/tmp/raw_alerts.csv"

# Custom rule IDs yang kita pedulikan
TARGET_RULES = {
    "100200",  # SYN Flood
    "100201",  # UDP Flood
    "100202",  # ICMP Flood
    "100300",  # ClamAV FOUND
    "100301",  # ClamAV EICAR
    "100302",  # ClamAV daemon FOUND
    "100400",  # HTTP request (korelasi helper)
    "100402",  # HTTP Flood L7
}

# IP internal yang kemungkinan FP
INTERNAL_IPS = {"10.0.0.", "168.63.129.16", "127.0.0.1"}


def parse_port(value):
    """Safely parse port number"""
    if value is None:
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def extract_ip_from_log(full_log):
    """Extract source IP dari iptables log atau web access log"""
    if not full_log:
        return ""
    # iptables format: SRC=1.2.3.4
    match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', full_log)
    if match:
        return match.group(1)
    # Web access log format: IP di awal baris
    match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', full_log)
    if match:
        return match.group(1)
    return ""


def extract_alerts():
    """Baca alerts.json dan filter custom rules"""
    alerts = []
    skipped = 0
    total_lines = 0

    print(f"[*] Membaca {ALERT_FILE}...")

    try:
        with open(ALERT_FILE, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                rule_id = str(alert.get("rule", {}).get("id", ""))

                # Filter hanya custom rules
                if rule_id not in TARGET_RULES:
                    continue

                rule_level = alert.get("rule", {}).get("level", 0)

                # Parse timestamp → hour_of_day
                ts_str = alert.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str)
                    hour_of_day = ts.hour
                except Exception:
                    hour_of_day = 0

                # Extract ports
                data = alert.get("data", {})
                src_port = parse_port(
                    data.get("srcport") or data.get("src_port")
                )
                dst_port = parse_port(
                    data.get("dstport") or data.get("dst_port")
                )

                # Extract source IP (coba dari data, fallback ke full_log)
                full_log = alert.get("full_log", "")
                src_ip = (
                    data.get("srcip")
                    or data.get("src_ip")
                    or extract_ip_from_log(full_log)
                    or ""
                )

                alerts.append({
                    "timestamp": ts_str,
                    "rule_id": int(rule_id),
                    "rule_level": rule_level,
                    "hour_of_day": hour_of_day,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "src_ip": src_ip,
                    "description": alert.get("rule", {}).get("description", ""),
                    "full_log_snippet": full_log[:200],
                })

    except FileNotFoundError:
        print(f"[ERROR] File {ALERT_FILE} tidak ditemukan!")
        print("Pastikan kamu menjalankan script ini di Wazuh Manager dengan sudo.")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied untuk {ALERT_FILE}!")
        print("Jalankan dengan: sudo python3 extract_alerts.py")
        sys.exit(1)

    print(f"[*] Total baris dibaca: {total_lines}")
    print(f"[*] Alert custom rule ditemukan: {len(alerts)}")
    print(f"[*] Baris invalid/skipped: {skipped}")

    return alerts


def compute_freq_per_minute(alerts):
    """
    Hitung freq_per_minute: berapa kali src_ip yang sama
    muncul dalam window ±60 detik di sekitar setiap alert.
    """
    print("[*] Menghitung freq_per_minute...")

    # Parse timestamps
    for a in alerts:
        try:
            a["_ts"] = datetime.fromisoformat(a["timestamp"])
        except Exception:
            a["_ts"] = datetime.min

    # Sort by timestamp
    alerts.sort(key=lambda x: x["_ts"])

    n = len(alerts)
    for i, alert in enumerate(alerts):
        if not alert["src_ip"]:
            alert["freq_per_minute"] = 1
            continue

        count = 0
        for j in range(max(0, i - 500), min(n, i + 500)):
            other = alerts[j]
            if other["src_ip"] == alert["src_ip"]:
                diff = abs((alert["_ts"] - other["_ts"]).total_seconds())
                if diff <= 60:
                    count += 1

        alert["freq_per_minute"] = count

    return alerts


def auto_suggest_label(alert):
    """
    Auto-suggest label berdasarkan kriteria.
    HANYA SARAN — Syifa harus review manual!
    """
    rid = alert["rule_id"]
    freq = alert["freq_per_minute"]
    src_ip = alert["src_ip"]

    # Malware selalu TP
    if rid in (100300, 100301, 100302):
        return "1"

    # HTTP Flood dengan frekuensi tinggi
    if rid == 100402 and freq > 20:
        return "1"

    # HTTP request biasa dengan frekuensi rendah
    if rid == 100400 and freq < 5:
        return "0"

    # DDoS dari IP internal → FP
    if rid in (100200, 100201, 100202):
        if any(src_ip.startswith(prefix) for prefix in INTERNAL_IPS):
            return "0"
        if freq > 30:
            return "1"
        if freq < 10:
            return "0"

    return "?"  # Perlu review manual


def write_csv(alerts):
    """Write CSV — ada kolom suggestion dan label kosong untuk diisi manual"""
    fieldnames = [
        "rule_id", "rule_level", "freq_per_minute", "hour_of_day",
        "src_port", "dst_port",
        "src_ip", "description", "full_log_snippet",
        "auto_suggestion", "label"
    ]

    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for alert in alerts:
            alert["auto_suggestion"] = auto_suggest_label(alert)
            alert["label"] = ""  # Syifa isi manual!
            writer.writerow(alert)

    print(f"\n[✓] CSV tersimpan di: {OUTPUT_CSV}")
    print(f"[✓] Total {len(alerts)} baris alert")
    print(f"[✓] Buka file ini, review kolom 'auto_suggestion', lalu isi kolom 'label'!")


def print_summary(alerts):
    """Print ringkasan untuk verifikasi"""
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    # Per rule
    rule_counts = Counter(a["rule_id"] for a in alerts)
    print("\nJumlah alert per Rule ID:")
    for rule_id, count in sorted(rule_counts.items()):
        print(f"  Rule {rule_id}: {count} alert")

    # Per IP
    ip_counts = Counter(a["src_ip"] for a in alerts if a["src_ip"])
    print(f"\nTop 10 Source IP:")
    for ip, count in ip_counts.most_common(10):
        print(f"  {ip}: {count} alert")

    # Freq stats
    freqs = [a["freq_per_minute"] for a in alerts]
    if freqs:
        print(f"\nfreq_per_minute stats:")
        print(f"  Min: {min(freqs)}, Max: {max(freqs)}, Avg: {sum(freqs)/len(freqs):.1f}")

    # Auto suggestion breakdown
    suggestions = Counter(auto_suggest_label(a) for a in alerts)
    print(f"\nAuto-suggestion breakdown:")
    for label, count in sorted(suggestions.items()):
        label_name = {"1": "TP", "0": "FP", "?": "PERLU REVIEW"}.get(label, label)
        print(f"  {label_name}: {count}")

    print(f"\n[NEXT] Download file CSV:")
    print(f"  scp azureuser@70.153.25.103:{OUTPUT_CSV} ./raw_alerts.csv")
    print("=" * 60)


if __name__ == "__main__":
    alerts = extract_alerts()

    if not alerts:
        print("\n[!] Tidak ada alert custom rule ditemukan!")
        print("    Kemungkinan:")
        print("    - Serangan belum dijalankan Joce")
        print("    - Rules belum terpasang (cek /var/ossec/etc/rules/local_rules.xml)")
        print("    - Agent belum terkoneksi (cek: sudo /var/ossec/bin/agent_control -l)")
        sys.exit(1)

    alerts = compute_freq_per_minute(alerts)
    write_csv(alerts)
    print_summary(alerts)
