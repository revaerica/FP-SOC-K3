# Urutan Pengerjaan — Kelompok 7 ITS

> Baca ini dulu sebelum mulai. Urutan WAJIB diikuti karena ada dependensi antar langkah.
> Dokumen ini mencakup **semua fase dari awal (setup infra) sampai akhir (AI filter aktif + feedback loop)**.

---

## Peta Besar — Alur End-to-End

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FASE A–C : INFRA & DETEKSI                                │
│                                                                             │
│  FASE A  Deploy Web Server              (Agent-1)                         │
│    │                                                                       │
│    ▼                                                                       │
│  FASE B  Logging iptables + ClamAV     (Agent-1)                         │
│    │                                                                       │
│    ▼                                                                       │
│  FASE C  Custom Rules + Decoder         (Manager)                          │
│    │       → Wazuh mendeteksi serangan & malware                          │
│    ▼                                                                       │
│  FASE D  Eksekusi Serangan              (Agent-2 → Agent-1)                │
│    │                                                                       │
│    ▼                                                                       │
│  FASE E  Verifikasi Deteksi             (Dashboard / Manager)              │
│    │                                                                       │
│    ▼                                                                       │
│  FASE F  SOAR (auto-block + quarantine) (Agent-1 + Manager)               │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FASE G–J : AI FALSE-ALARM FILTER                         │
│                                                                             │
│  FASE G  Data Pipeline                    (Manager → Lokal)                │
│    │       extract_alerts → auto_label → labeled_alerts.csv                │
│    ▼                                                                       │
│  FASE H  Training Model AI                (Laptop Lokal)                  │
│    │       train_model.py → model.pkl + metrics.json                      │
│    │       unit test → benchmark                                        │
│    ▼                                                                       │
│  FASE I  Deploy AI Filter ke Manager       (Laptop → Manager)            │
│    │       deploy.sh → ai_filter.py (side-car, systemd)                  │
│    │       → 3-Zone Decision: FILTER / REVIEW / FORWARD                   │
│    ▼                                                                       │
│  FASE J  Feedback Loop (Human-in-the-Loop)(Manager)                     │
│            analyst review → feedback → retrain (closed-loop)              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Lokasi Eksekusi per Fase

| Fase | Lokasi | VM | Fungsi |
|------|--------|----|--------|
| A | Agent-1 | `10.0.0.5` | Web Server |
| B | Agent-1 | `10.0.0.5` | Logging + ClamAV |
| C | Manager | `10.0.0.4` | Rules + Decoder |
| D | Agent-2 | `10.0.0.6` | Serangan |
| E | Manager / Dashboard | `10.0.0.4` | Verifikasi alert |
| F | Agent-1 + Manager | — | SOAR Active Response |
| **G** | **Manager → Laptop** | — | **Data Pipeline AI** |
| **H** | **Laptop Lokal** | — | **Training Model** |
| **I** | **Laptop → Manager** | — | **Deploy AI Filter** |
| **J** | **Manager** | — | **Feedback Loop** |

---

## Prasyarat (dari Orang 1–4)
Pastikan sudah ada:
- Wazuh Manager aktif di `10.0.0.4`
- Wazuh Agent-1 (`10.0.0.5`) dan Agent-2 (`10.0.0.6`) sudah terdaftar
- Dashboard bisa diakses di `https://70.153.25.103`

---

## FASE A — Deploy Web Server (di Agent-1)

```bash
# 1. Salin file ke lokasi yang benar
sudo mkdir -p /opt/wazuh-lab/webserver
sudo cp scripts/webserver/app.py /opt/wazuh-lab/webserver/app.py
sudo cp scripts/webserver/wazuh-webserver.service /etc/systemd/system/

# 2. Aktifkan sebagai service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-webserver
sudo systemctl start wazuh-webserver

# 3. Verifikasi
curl -s http://localhost/status ; echo
# Harus muncul: {"service":"wazuh-lab-web","status":"ok","requests":0}
```

---

## FASE B — Konfigurasi Logging (di Agent-1)

```bash
# 1. Iptables logging untuk DDoS layer 3/4
sudo iptables -I INPUT -p tcp --syn -j LOG --log-prefix "SYN-FLOOD: " --log-level 4
sudo iptables -I INPUT -p udp        -j LOG --log-prefix "UDP-FLOOD: " --log-level 4
sudo iptables -I INPUT -p icmp -m limit --limit 10/sec -j LOG --log-prefix "ICMP-FLOOD: " --log-level 4

# 2. Daftarkan log ke ossec.conf agent (tambahkan sebelum </ossec_config>)
# Salin isi dari configs/ossec-agent.conf

# 3. Install ClamAV
sudo apt-get install -y clamav clamav-daemon
sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam

# 4. Restart agent
sudo systemctl restart wazuh-agent
```

---

## FASE C — Rules & Decoder (di Manager)

```bash
# 1. Salin rules dan decoder
sudo cp rules/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
sudo cp rules/local_rules.xml   /var/ossec/ruleset/rules/local_rules.xml
sudo rm -f /var/ossec/etc/rules/local_rules.xml   # hapus jika ada duplikat

# 2. WAJIB test sebelum restart
sudo /var/ossec/bin/wazuh-analysisd -t

# 3. Kalau lolos test, baru restart
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager | grep Active
```

---

## FASE D — Eksekusi Serangan (di Agent-2)

```bash
# Jalankan dari Agent-2 (10.0.0.6)
sudo bash scripts/ddos_attack.sh syn  10.0.0.5 30
sudo bash scripts/ddos_attack.sh udp  10.0.0.5 30
sudo bash scripts/ddos_attack.sh icmp 10.0.0.5 30
sudo bash scripts/ddos_attack.sh http 10.0.0.5 60

# Malware (jalankan di Agent-1)
sudo bash scripts/malware_sim.sh
```

---

## FASE E — Verifikasi Deteksi (di Manager)

```bash
sudo grep -c "Rule: 100200 " /var/ossec/logs/alerts/alerts.log   # SYN
sudo grep -c "Rule: 100201 " /var/ossec/logs/alerts/alerts.log   # UDP
sudo grep -c "Rule: 100202 " /var/ossec/logs/alerts/alerts.log   # ICMP
sudo grep -c "Rule: 100402 " /var/ossec/logs/alerts/alerts.log   # HTTP
sudo grep -cE "100300|100301" /var/ossec/logs/alerts/alerts.log  # Malware
```

---

## FASE F — SOAR (di Agent-1 + Manager)

```bash
# Di Agent-1: pasang script karantina
sudo cp scripts/remove-malware.py /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/remove-malware.py
sudo chmod 750 /var/ossec/active-response/bin/remove-malware.py
sudo sed -i 's/\r//' /var/ossec/active-response/bin/remove-malware.py  # fix CRLF

# Di Manager: tambahkan konfigurasi SOAR
# Salin isi dari configs/ossec-manager.conf ke /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager

# Tes SOAR karantina
sudo logger -t clamscan "/tmp/eicar_test.txt: Eicar-Test-Signature FOUND"
sleep 12
sudo grep "KARANTINA" /var/ossec/logs/active-responses.log | tail -3
sudo ls -l /var/ossec/quarantine/
```

---

## FASE G — Data Pipeline AI (Manager → Laptop)

> **Lokasi:** Manager (ekstrak) → Laptop lokal (label + finalisasi)
> **Dependensi:** Fase D selesai (ada alert di alerts.json)

Fase ini mengekstrak alert dari Wazuh, melabeli TP/FP, dan menghasilkan dataset siap training.

### G1 — Ekstrak Alert dari Wazuh (di Manager)

```bash
# Jalankan di Manager
sudo python3 ai-model/data/extract_alerts.py

# Output: /tmp/raw_alerts.csv (~79.561 baris)
# Verifikasi:
wc -l /tmp/raw_alerts.csv
```

### G2 — Download Dataset ke Laptop

```bash
# Dari laptop lokal
scp azureuser@<MANAGER_IP>:/tmp/raw_alerts.csv ai-model/data/raw_alerts.csv
```

### G3 — Auto-Label Dataset (di Laptop)

```bash
# Label otomatis berdasarkan false-alarm-criteria.md
cd ai-model/data
python3 auto_label.py
# Output: labeled_alerts.csv (115 baris, 65% TP + 35% FP)
```

> **Detail kriteria labeling:** lihat [`data/false-alarm-criteria.md`](ai-model/data/false-alarm-criteria.md)

### G4 — Validasi Dataset

```bash
python3 finalize_dataset.py raw_alerts.csv labeled_alerts.csv
# Cek distribusi: target ~65% TP, ~35% FP
```

---

## FASE H — Training Model AI (di Laptop Lokal)

> **Lokasi:** Laptop lokal (tidak butuh VM Azure)
> **Dependensi:** Fase G selesai (`labeled_alerts.csv` ada)
> **Detail lengkap:** [`ai-model/README.md`](ai-model/README.md)

### H1 — Install Dependency

```bash
pip install -r ai-model/integration/requirements.txt
# scikit-learn, joblib, pyyaml, pandas, numpy
```

### H2 — Training Model

```bash
cd ai-model/training
python train_model.py
```

**Output yang diharapkan:**
```
  RF Precision : 0.987
  RF Recall(TP): 1.000   ← 0 serangan terlewat
  RF F1        : 0.993
  RF AUC       : 1.000
  CV 5-fold    : Recall=1.000±0.000

  DONE — artifacts tersimpan:
    model.pkl, scaler.pkl, feature_columns.json, metrics.json
```

### H3 — Unit Test & Benchmark

```bash
cd ai-model/integration

# Test 1: feature extractor (7 test)
python tests/test_feature_extractor.py
# Expected: 7/7 passed

# Test 2: model benchmark (3 test — ini BUKTI A4 untuk laporan)
python tests/test_ai_filter.py
# Expected: 3/3 passed
#   Precision=0.987, Recall=1.000, F1=0.993
#   32.2% alert difilter (reduction)
#   1.7% needs review
```

> **Metrik ini adalah benchmark BEFORE vs AFTER AI untuk laporan akhir.**

---

## FASE I — Deploy AI Filter ke Manager (Laptop → Manager)

> **Lokasi:** Laptop (kirim) → Manager (jalankan)
> **Dependensi:** Fase H selesai (`model.pkl` ada) + Fase F selesai (SOAR aktif)

### I1 — Salin Repo ke Manager

```bash
# Dari laptop — kirim seluruh folder ai-model
scp -r ai-model/ azureuser@<MANAGER_IP>:/opt/ai-filter/
```

### I2 — Jalankan Deploy Script (di Manager)

```bash
# SSH ke Manager
ssh azureuser@<MANAGER_IP>

# Jalankan deploy (otomatis: copy, fix CRLF, install deps, enable systemd)
cd /opt/ai-filter/integration
sudo bash deploy.sh
```

**Yang dilakukan `deploy.sh`:**
1. Salin `ai_filter.py`, `feature_extractor.py`, `feedback.py`, `config.yaml` ke `/opt/ai-filter/integration/`
2. Salin `model.pkl`, `scaler.pkl`, `feature_columns.json` ke `/opt/ai-filter/training/`
3. Fix CRLF (Windows → Unix)
4. Install Python dependency
5. Smoke test load model
6. Pasang & enable systemd service

### I3 — Verifikasi AI Filter Berjalan

```bash
# Cek status service
sudo systemctl status wazuh-ai-filter
# Harus: Active: active (running)

# Monitor log real-time
sudo journalctl -u wazuh-ai-filter -f

# Cek keputusan AI
sudo cat /var/ossec/ai-filter/ai_decisions.log | tail -20

# Cek hasil filtering
sudo cat /var/ossec/ai-filter/filtered_fp.log | wc -l      # alert yang difilter
sudo cat /var/ossec/ai-filter/needs_review.csv                 # alert untuk human review
sudo cat /var/ossec/ai-filter/forwarded_to_soar.log | wc -l  # alert ke SOAR
```

### I4 — Jalankan Serangan Uji & Lihat AI Bekerja

```bash
# Dari Agent-2, jalankan serangan (sama seperti Fase D)
sudo bash scripts/ddos_attack.sh http 10.0.0.5 30

# Lihat di Manager — AI filter otomatis memproses alert baru
sudo tail -f /var/ossec/ai-filter/ai_decisions.log
# Contoh output:
#   2026-06-23T10:30:00 | id=xxx rule=100402 src=10.0.0.6 freq=45 conf=0.02 -> FORWARD_TO_SOAR
#   2026-06-23T10:30:01 | id=xxx rule=100200 src=10.0.0.5 freq=1200 conf=0.95 -> FILTERED_FP
```

---

## FASE J — Feedback Loop — Human-in-the-Loop (di Manager)

> **Lokasi:** Manager (ai_filter berjalan) + analyst review
> **Dependensi:** Fase I selesai (ai_filter aktif, ada alert di needs_review.csv)
> **Detail:** [`ai-model/integration/feedback.py`](ai-model/integration/feedback.py)

### J1 — Analyst Review Alert NEEDS_REVIEW

```bash
# Lihat alert yang perlu review manusia
cat /var/ossec/ai-filter/needs_review.csv
```

| Kolom | Arti |
|-------|------|
| `confidence` | P(FP) dari model. 0.60–0.84 = model ragu |
| `rule_id` | Rule Wazuh yang terpicu |
| `analyst_verdict` | Diisi analyst: kosong = belum direview |

### J2 — Catat Feedback

```bash
cd /opt/ai-filter/integration

# Contoh: alert yang AI filter (FP) tapi sebenarnya serangan (TP)
python feedback.py add \
  --dir /var/ossec/ai-filter/feedback \
  --alert-id <alert_id> \
  --rule-id 100200 \
  --decision FILTERED_FP \
  --confidence 0.91 \
  --true-label 1 \
  --analyst Syifa \
  --note "Sesungguhnya brute-force dari IP eksternal"

# Contoh: alert yang AI teruskan (TP) tapi ternyata false alarm (FP)
python feedback.py add \
  --dir /var/ossec/ai-filter/feedback \
  --alert-id <alert_id> \
  --rule-id 100201 \
  --decision FORWARD_TO_SOAR \
  --confidence 0.30 \
  --true-label 0 \
  --analyst Syifa
```

### J3 — Lihat Statistik & Salah Klasifikasi

```bash
# Statistik keseluruhan
python feedback.py stats --dir /var/ossec/ai-filter/feedback
# Output: {"total": N, "tp_correct": N, "fp_correct": N, "missed_attack": N, ...}

# Daftar salah klasifikasi (untuk retraining)
python feedback.py misclassified --dir /var/ossec/ai-filter/feedback
# Output: [MISSED_ATTACK] alert=xxx ... atau [FALSE_ALARM_TO_SOAR] alert=xxx ...
```

### J4 — Retrain Model dengan Feedback (Closed-Loop)

```bash
# 1. Gabungkan feedback ke dataset (di laptop)
#    Tambahkan baris baru / koreksi label di labeled_alerts.csv

# 2. Retrain model
cd ai-model/training
python train_model.py --data ../data/labeled_alerts_v2.csv

# 3. Deploy ulang ke Manager
scp training/model.pkl azureuser@<MANAGER_IP>:/opt/ai-filter/training/
ssh azureuser@<MANAGER_IP> "sudo systemctl restart wazuh-ai-filter"
```

---

## Tips Penting

| Hal | Jangan | Lakukan |
|-----|--------|---------|
| Edit rules | Langsung restart | Selalu `wazuh-analysisd -t` dulu |
| SOAR trigger | Pakai rule per-paket (100200) | Pakai rule korelasi (100402) |
| Upload script dari Windows | Langsung copy | Fix CRLF dengan `sed -i 's/\r//'` |
| SOAR location malware | `local` | `defined-agent` + `agent_id` |
| Recovery self-lockout | Panic | Azure Portal → Run Command → `iptables -F INPUT` |

---

## Ringkasan Seluruh Fase

| Fase | Nama | Lokasi | Output Kunci | Waktu Estimasi |
|------|------|--------|--------------|----------------|
| **A** | Deploy Web Server | Agent-1 | Web server aktif di `:80` | 5 menit |
| **B** | Logging + ClamAV | Agent-1 | kern.log, access.log, clamav.log terdaftar | 10 menit |
| **C** | Custom Rules | Manager | 8 custom rules terpasang (100200–100402) | 5 menit |
| **D** | Serangan | Agent-2 → Agent-1 | Alert tergenerate di Wazuh | 10–15 menit |
| **E** | Verifikasi | Manager / Dashboard | Alert terdeteksi di dashboard | 5 menit |
| **F** | SOAR | Agent-1 + Manager | Auto-block + auto-quarantine aktif | 10 menit |
| **G** | Data Pipeline | Manager → Laptop | `labeled_alerts.csv` (115 baris) | 15 menit |
| **H** | Training AI | Laptop | `model.pkl` + metrik benchmark | 5–10 menit |
| **I** | Deploy AI Filter | Laptop → Manager | `ai_filter.py` berjalan (systemd) | 10 menit |
| **J** | Feedback Loop | Manager | Feedback tercatat, model bisa retrain | Berkelanjutan |

**Total estimasi end-to-end:** ~1.5–2 jam (tanpa install Wazuh dari nol)

---

## Shutdown & Cleanup

```bash
# Stop AI filter (tanpa hapus data)
sudo systemctl stop wazuh-ai-filter

# Stop seluruh lab (hemat Azure credit)
# Matikan (STOP, bukan shutdown) VM di Azure Portal

# Uninstall AI filter (opsional)
sudo systemctl disable --now wazuh-ai-filter
sudo rm /etc/systemd/system/wazuh-ai-filter.service
sudo systemctl daemon-reload
sudo rm -rf /opt/ai-filter /var/ossec/ai-filter
```

---

## Dokumen Pendukung

| Dokumen | Isi |
|---------|-----|
| [`README.md`](README.md) | Laporan utama Wazuh Lab (DDoS, SOAR, screenshot) |
| [`docs/architecture.md`](docs/architecture.md) | Arsitektur infra VM + alur data |
| [`docs/setup-agent.md`](docs/setup-agent.md) | Detail setup Agent-1 (Fase A–B) |
| [`docs/setup-manager.md`](docs/setup-manager.md) | Detail setup Manager (Fase C) |
| [`docs/setup-soar.md`](docs/setup-soar.md) | Detail SOAR Active Response (Fase F) |
| [`ai-model/README.md`](ai-model/README.md) | **Arsitektur AI + alur kerja detail + ASCII art** |
| [`ai-model/data/false-alarm-criteria.md`](ai-model/data/false-alarm-criteria.md) | Kriteria TP/FP per rule ID |
