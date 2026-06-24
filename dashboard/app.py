from flask import Flask, jsonify, render_template
import os, csv, re
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

BASE = "/var/ossec/ai-filter"

def read_log_lines(path, limit=500):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        lines = [l.strip() for l in f if l.strip()]
    return lines[-limit:]

def read_csv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows[-100:]

def parse_log_lines(lines):
    # Format: 2026-06-24T07:01:47+00:00 | id=xxx rule=100200 src=x freq=1 conf=0.0 -> ZONE
    pattern = re.compile(r'rule=(\d+).*conf=([\d.]+)\s*->\s*(\w+)')
    parsed = []
    for line in lines:
        m = pattern.search(line)
        if m:
            parsed.append({
                'rule_id': m.group(1),
                'conf': float(m.group(2)),
                'zone': m.group(3)
            })
    return parsed

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    decisions = read_log_lines(f"{BASE}/ai_decisions.log")
    parsed = parse_log_lines(decisions)

    filtered = [p for p in parsed if p['zone'] == 'FILTERED_FP']
    forwarded = [p for p in parsed if p['zone'] == 'FORWARD_TO_SOAR']
    review = read_csv(f"{BASE}/needs_review.csv")

    # hitung per rule
    rule_counts = defaultdict(lambda: {"filtered": 0, "forwarded": 0, "review": 0})
    for p in filtered:
        rule_counts[p['rule_id']]['filtered'] += 1
    for p in forwarded:
        rule_counts[p['rule_id']]['forwarded'] += 1
    for r in review:
        rid = r.get('rule_id', 'unknown')
        rule_counts[rid]['review'] += 1

    return jsonify({
        "total_filtered": len(filtered),
        "total_forwarded": len(forwarded),
        "total_review": len(review),
        "total_processed": len(parsed),
        "rule_breakdown": rule_counts,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/api/needs_review")
def api_needs_review():
    return jsonify(read_csv(f"{BASE}/needs_review.csv"))

@app.route("/api/soar_log")
def api_soar_log():
    return jsonify(read_log_lines(f"{BASE}/forwarded_to_soar.log", limit=50))

@app.route("/api/filtered_log")
def api_filtered_log():
    lines = read_log_lines(f"{BASE}/ai_decisions.log", limit=200)
    filtered = [l for l in lines if 'FILTERED_FP' in l]
    return jsonify(filtered[-50:])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
