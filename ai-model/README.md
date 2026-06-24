# AI False-Alarm Classifier — FP-SOC-K3

> **Project:** Reducing SOC False Alarms through Human-AI Collaboration Model
> **Mata Kuliah:** Manajemen Insiden & Keamanan Siber (MIKS) — Semester Genap 2024/2025
> **AI Lead (A4/A5):** Angga Firmansyah (5027241062)

---

## 1. Arsitektur Sistem (End-to-End)

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        ARSITEKTUR SOC + AI FILTER                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  [Attacker]                    [Target]                                     ║
║  wazuh-agent-2                 wazuh-agent-1                               ║
║  10.0.0.6                      10.0.0.5                                    ║
║       │                            │                                        ║
║       │  hping3 SYN/UDP/ICMP        │  Web Server :80                       ║
║       │  ddos_attack.sh HTTP         │  ClamAV scan                         ║
║       │                             │  iptables LOG (kern.log)             ║
║       └────────────┬────────────────┘                                        ║
║                    │                                                         ║
║              Wazuh Agent (log forwarding)                                    ║
║                    │                                                         ║
║                    ▼                                                         ║
║  ╔═══════════════════════════════════════════════════════╗                  ║
║  ║          WAZUH MANAGER  (10.0.0.4)                    ║                  ║
║  ║                                                   ╔    ╠                  ║
║  ║  alerts.json                                       ║ AI  ╠                  ║
║  ║  (new alerts written here)                        ║ LAYER║                  ║
║  ║       │                                            ║    ╠                  ║
║  ║       ▼                                            ╚    ╠                  ║
║  ║  ┌───────────────────────────────┐                  ║                  ║
║  ║  │    Custom Rules & Decoder      │                  ║                  ║
║  ║  │    local_rules.xml             │                  ║                  ║
║  ║  │    100200 → SYN Flood          │                  ║                  ║
║  ║  │    100201 → UDP Flood          │                  ║                  ║
║  ║  │    100202 → ICMP Flood         │                  ║                  ║
║  ║  │    100300/301/302 → Malware    │                  ║                  ║
║  ║  │    100400/402 → HTTP Flood     │                  ║                  ║
║  ║  └──────────────┬────────────────┘                  ║                  ║
║  ║                 │                                    ║                  ║
║  ║                 ▼                                    ║                  ║
║  ║  ┌──────────────────────────────────────────────┐  ║                  ║
║  ║  │        AI FILTER (ai_filter.py — Side-car)     │  ║                  ║
║  ║  │                                               │  ║                  ║
║  ║  │  1. Load model.pkl (Random Forest)            │  ║                  ║
║  ║  │  2. Ekstrak 6 fitur per alert                 │  ║                  ║
║  ║  │  3. predict_proba → confidence P(FP)           │  ║                  ║
║  ║  │  4. 3-Zone Decision:                          │  ║                  ║
║  ║  │                                               │  ║                  ║
║  ║  │  ┌───────────────────────────────────────┐    │  ║                  ║
║  ║  │  │  conf >= 0.85  →  FILTERED_FP        │    │  ║                  ║
║  ║  │  │  0.60-0.84     →  NEEDS_REVIEW       │    │  ║                  ║
║  ║  │  │  conf < 0.60   →  FORWARD_TO_SOAR    │    │  ║                  ║
║  ║  │  └───────────────────────────────────────┘    │  ║                  ║
║  ║  └─────┬──────────────┬──────────────┬───────────┘  ║                  ║
║  ║        │              │              │               ║                  ║
║  ║        ▼              ▼              ▼               ║                  ║
║  ║  ┌───────────┐ ┌────────────┐ ┌────────────────┐   ║                  ║
║  ║  │ filtered_ │ │ needs_     │ │ forwarded_     │   ║                  ║
║  ║  │ fp.log     │ │ review.csv │ │ to_soar.log    │   ║                  ║
║  ║  │ (audit)    │ │ (human     │ │ (audit)        │   ║                  ║
║  ║  └───────────┘ │ triage)    │ └───────┬────────┘   ║                  ║
║  ║                 └─────┬──────┘         │            ║                  ║
║  ║                       │                ▼            ║                  ║
║  ║                       ▼    ┌───────────────────┐  ║                  ║
║  ║              feedback.py    │  SOAR Response    │  ║                  ║
║  ║              (retraining)   │  Active Response   │  ║                  ║
║  ║                  │         │  firewall-drop     │  ║                  ║
║  ║                  ▼         │  remove-malware.py │  ║                  ║
║  ║            retrain model   └───────────────────┘  ║                  ║
║  ╚════════════════════════════════════════════════════╝                  ║
║                                                                       ║    ║
║  ┌─────────────────────────────────────────────────────────────────────┐ ║    ║
║  │  Wazuh Dashboard (https://<manager-ip>)                           │ ║    ║
║  │  → Threat Hunting → Events (lihat semua alert)                     │ ║    ║
║  │  → Malware Detection (ClamAV alert)                               │ ║    ║
║  ╚─────────────────────────────────────────────────────────────────────┘ ║    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

### Peran Human dalam Kolaborasi

```
  ┌─────────────────────────────────────────────────────────┐
  │                  HUMAN-AI COLLABORATION FLOW              │
  │                                                          │
  │  Alert masuk                                             │
  │       │                                                  │
  │       ▼                                                  │
  │  ┌─ AI Model ──────────────────────────────────────┐     │
  │  │  confidence >= 0.85 → FILTERED (otomatis)       │     │
  │  │  confidence < 0.60  → FORWARD (otomatis ke SOAR) │     │
  │  └──────────────────────────────────────────────────┘     │
  │       │                                                  │
  │       ▼  (0.60 – 0.84)                                  │
  │  ┌─ HUMAN TRIAGE (Syifa) ───────────────────────────┐   │
  │  │  needs_review.csv → analyst review manual         │   │
  │  │  keputusan: APPROVE (forward) / REJECT (filter)     │   │
  │  └──────────────────────┬───────────────────────────┘   │
  │                         │                                │
  │                         ▼                                │
  │  ┌─ FEEDBACK LOOP ──────────────────────────────────┐   │
  │  │  feedback.py → catat salah klasifikasi             │   │
  │  │  → MISSED_ATTACK / FALSE_ALARM_TO_SOAR            │   │
  │  │  → dataset untuk retraining (closed-loop)          │   │
  │  └──────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────┘
```

---

## 2. Komponen AI

### 2.1 Model Training (A4 — `training/`)

| File                   | Fungsi                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------- |
| `SOC_training.ipynb`   | Notebook eksplorasi + training (EDA, 3 model, ROC, threshold analysis)                        |
| `train_model.py`       | Versi .py runnable — retrain ulang tanpa Jupyter (reproducible)                               |
| `model.pkl`            | Random Forest terlatih (200 trees, max_depth=12, class_weight=balanced)                       |
| `scaler.pkl`           | StandardScaler (dipakai oleh Logistic Regression baseline)                                    |
| `feature_columns.json` | Urutan 6 fitur wajib: `rule_id, rule_level, freq_per_minute, hour_of_day, src_port, dst_port` |
| `metrics.json`         | Hasil evaluasi terakhir (precision/recall/F1/AUC/confusion matrix)                            |

**Algoritma:** Random Forest (model utama) + Logistic Regression (baseline pembanding).

> ⚠️ **Tidak ganti algoritma.** RF robust untuk data tabular kecil, cepat dijelaskan,
> dan sudah terbukti Recall=1.0 di dataset berlabel.

### 2.2 Fitur Model (6 fitur, TANPA src_ip)

```
  Fitur              | Sumber Wazuh           | Tipe    | Justifikasi
  ───────────────────┼────────────────────────┼─────────┼───────────────────
  rule_id            | alert.rule.id          | int     | Jenis serangan
  rule_level         | alert.rule.level       | int     | Severity Wazuh
  freq_per_minute    | dihitung in-memory     | int     | Burst rate (sliding 60s)
  hour_of_day        | alert.timestamp        | int     | Pola temporal
  src_port           | alert.data.srcport     | int     | Port sumber
  dst_port           | alert.data.dstport     | int     | Port target
```

> **Catatan penting:** `src_ip` TIDAK dipakai sebagai fitur model meskipun sangat
> informatif di labeling. Ini adalah keputusan desain: model harus belajar dari
> pola numerik (frekuensi, port, jam), bukan sekadar "apakah IP internal".

### 2.3 Dataset

| File                      | Baris  | Isi                                           |
| ------------------------- | ------ | --------------------------------------------- |
| `data/raw_alerts.csv`     | 79.561 | Semua alert dari Wazuh (3 jam monitoring)     |
| `data/labeled_alerts.csv` | 115    | Dataset berlabel (75 TP, 40 FP — ratio 65:35) |

### 2.4 Threshold 3-Zone Decision

| Confidence (P(False Positive)) | Zona               | Aksi                                               |
| ------------------------------ | ------------------ | -------------------------------------------------- |
| **≥ 0.85**                     | 🔴 FILTERED_FP     | Alert difilter. Tidak diteruskan ke SOAR.          |
| **0.60 – 0.84**                | 🟡 NEEDS_REVIEW    | Diteruskan ke analyst (Syifa) untuk review manual. |
| **< 0.60**                     | 🟢 FORWARD_TO_SOAR | Alert diteruskan ke SOAR untuk respons otomatis.   |

> **Konvensi confidence:** `confidence = predict_proba(X)[:, 0]` = P(False Positive).
> Ini berarti confidence tinggi → model yakin alert ini FALSE POSITIVE (bukan serangan).

---

## 3. Integration (A5 — `integration/`)

### 3.1 Komponen

| File                      | Fungsi                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| `ai_filter.py`            | **Core:** side-car yang tail alerts.json, klasifikasi, 3-zone decision |
| `feature_extractor.py`    | Ekstrak 6 fitur dari alert JSON Wazuh (sumber kebenaran tunggal)       |
| `feedback.py`             | Feedback loop: catat salah klasifikasi, deteksi MISSED_ATTACK          |
| `config.yaml`             | Konfigurasi: path model, threshold, target rules, forwarding mode      |
| `requirements.txt`        | Dependencies: scikit-learn, joblib, pyyaml, pandas, numpy              |
| `wazuh-ai-filter.service` | systemd unit untuk auto-start di Manager                               |
| `deploy.sh`               | Script deploy ke Wazuh Manager (copy + fix CRLF + enable service)      |

### 3.2 Prinsip Desain

1. **TIDAK memodifikasi core Wazuh** — berjalan sebagai side-car terpisah
2. **Read-only terhadap alerts.json** — hanya membaca, tidak menulis
3. **Offset tracking** — tahan restart (tidak reprocess alert lama)
4. **Non-invasif default** — mode forwarding `log` (catat ke file), bukan `exec` (panggil SOAR langsung)
5. **Configurable** — semua path, threshold, target rule di `config.yaml`

### 3.3 Mekanisme Forwarding ke SOAR

```
  Mode "log" (default, aman):
    FORWARD_TO_SOAR → tulis ke forwarded_to_soar.log
    (administrator bisa verifikasi sebelum aktifkan mode exec)

  Mode "exec" (opsional, berisiko self-lockout):
    FORWARD_TO_SOAR → panggil Active Response script langsung
    rule 100402 → firewall-drop (blokir IP 120s)
    rule 100300/100301 → remove-malware.py (karantina)
```

---

## 4. Cara Menjalankan Seluruh Sistem

### 4.1 Prasyarat

- Python 3.9+
- pip packages: `scikit-learn`, `joblib`, `pyyaml`, `pandas`, `numpy`
- Wazuh Manager aktif dengan custom rules 100200–100402 terpasang
- (Opsional) pytest untuk menjalankan unit test

### 4.2 Step 1: Train / Retrain Model (A4)

```bash
# Dari folder ai-model/training/
cd ai-model/training

# Jalankan training (reproducible, tanpa Jupyter)
python train_model.py

# Output: model.pkl, scaler.pkl, feature_columns.json, metrics.json
# Default baca dari ../data/labeled_alerts.csv

# Atau dengan dataset kustom:
python train_model.py --data path/to/custom.csv --out ./output/
```

**Hasil training benchmark (terverifikasi di Windows):**

```
  RF Precision : 0.987
  RF Recall(TP): 1.000   ← tidak ada serangan yang terlewat
  RF F1        : 0.993
  RF AUC       : 1.000
  CV 5-fold    : Recall=1.000±0.000 (sangat stabil)
```

### 4.3 Step 2: Unit Test Lokal (Windows/Linux)

```bash
# Dari folder ai-model/integration/
cd ai-model/integration

# Install dependency
pip install -r requirements.txt

# Test feature extractor (7 test)
python tests/test_feature_extractor.py

# Test model + benchmark AI (3 test)
python tests/test_ai_filter.py

# Atau via pytest:
pytest tests/ -v
```

**Expected output:**

```
  test_feature_extractor.py: 7/7 passed
  test_ai_filter.py:
    - Model accuracy: Precision=0.987, Recall=1.000, F1=0.993
    - 3-Zone: 32.2% filtered, 1.7% needs review, 66.1% forwarded
    - Pipeline sample: 12/12 alert diproses
  RESULT: 10/10 passed
```

### 4.4 Step 3: Deploy ke Wazuh Manager (Linux)

```bash
# 1. Salin repo ke Manager (SCP / git clone)
scp -r ai-model/ azureuser@<MANAGER_IP>:/opt/ai-filter/

# 2. Jalankan deploy script (di Manager)
ssh azureuser@<MANAGER_IP>
cd /opt/ai-filter/integration
sudo bash deploy.sh

# 3. Verifikasi service aktif
sudo systemctl status wazuh-ai-filter

# 4. Monitor log
sudo journalctl -u wazuh-ai-filter -f
sudo tail -f /var/ossec/ai-filter/ai_decisions.log

# 5. Cek hasil filtering
sudo cat /var/ossec/ai-filter/filtered_fp.log     # alert yang difilter
sudo cat /var/ossec/ai-filter/needs_review.csv      # alert untuk human review
sudo cat /var/ossec/ai-filter/forwarded_to_soar.log # alert ke SOAR
```

### 4.5 Step 4: Feedback Loop (Human-in-the-Loop)

```bash
# Di Manager — analyst (Syifa) mereview needs_review.csv
cat /var/ossec/ai-filter/needs_review.csv

# Setelah review, catat feedback:
cd /opt/ai-filter/integration
python feedback.py add \
  --dir /var/ossec/ai-filter/feedback \
  --alert-id <alert_id> \
  --rule-id 100200 \
  --decision NEEDS_REVIEW \
  --confidence 0.72 \
  --true-label 1 \
  --analyst Syifa \
  --note "Sesungguhnya brute-force dari IP eksternal"

# Lihat statistik feedback
python feedback.py stats --dir /var/ossec/ai-filter/feedback

# Lihat salah klasifikasi (untuk retraining)
python feedback.py misclassified --dir /var/ossec/ai-filter/feedback
```

### 4.6 Step 5: Retrain dengan Data Baru (Closed-Loop)

```bash
# Setelah cukup feedback terkumpul, gabungkan ke dataset:
# 1. Export feedback → CSV
# 2. Gabung dengan labeled_alerts.csv (tambah baris baru / koreksi label)
# 3. Retrain model
cd /opt/ai-filter/training
python train_model.py --data ../data/labeled_alerts_v2.csv

# 4. Restart AI filter service
sudo systemctl restart wazuh-ai-filter
```

### 4.7 Shutdown / Uninstall

```bash
# Stop service
sudo systemctl stop wazuh-ai-filter

# Disable otomatis start
sudo systemctl disable wazuh-ai-filter

# Hapus (opsional)
sudo rm /etc/systemd/system/wazuh-ai-filter.service
sudo systemctl daemon-reload
sudo rm -rf /opt/ai-filter /var/ossec/ai-filter
```

---

## 5. Benchmark Before vs After AI

| Metrik                   | Before AI (Baseline) | After AI (Model Aktif)      | Perbaikan |
| ------------------------ | -------------------- | --------------------------- | --------- |
| Total alert dari Wazuh   | ~79.561 (3 jam)      | 79.561 (masuk AI filter)    | —         |
| Alert difilter (FP)      | 0 (tidak ada filter) | **32.2%** (37/115 sample)   | ✅        |
| Alert ke SOAR            | 100% (semua)         | **66.1%** (76/115 sample)   | ↓ 33.9%   |
| Alert perlu human review | 100%                 | **1.7%** (2/115 sample)     | ↓ 98.3%   |
| True Positive recall     | N/A (manual)         | **100%** (0 missed attack)  | ✅        |
| False Positive Rate      | 99.9% (baseline)     | **Reduced** via FILTERED_FP | ✅        |

> **Catatan:** angka di atas dari benchmark `labeled_alerts.csv` (115 baris).
> Pada data riil 79.561 alert (99.9% FP), AI diharapkan mengurangi volume review
> secara signifikan dengan Recall TP 100% (tidak ada serangan yang terlewat).

---

## 6. Struktur Folder

```
ai-model/
├── README.md                          ← dokumen ini
├── training/                          ← A4: model artifacts
│   ├── SOC_training.ipynb              ← notebook eksplorasi + training
│   ├── train_model.py                  ← versi .py runnable (reproducible)
│   ├── model.pkl                       ← Random Forest terlatih
│   ├── scaler.pkl                      ← StandardScaler
│   ├── feature_columns.json            ← urutan 6 fitur (sumber kebenaran)
│   └── metrics.json                   ← hasil evaluasi terakhir
├── data/                              ← A3: dataset + pipeline
│   ├── raw_alerts.csv                  ← 79.561 alert Wazuh (semua)
│   ├── labeled_alerts.csv              ← 115 alert berlabel (75 TP + 40 FP)
│   ├── extract_alerts.py               ← ekstrak alerts.json → CSV
│   ├── finalize_dataset.py             ← validasi + finalisasi dataset
│   ├── auto_label.py                   ← auto-label berdasarkan kriteria
│   └── false-alarm-criteria.md        ← dokumen kriteria TP/FP
├── model/                             ← placeholder (output training)
│   └── README.md                       ← penjelasan folder
└── integration/                        ← A5: AI filter + deploy
    ├── ai_filter.py                    ← side-car klasifikasi (core)
    ├── feature_extractor.py            ← ekstraksi 6 fitur
    ├── feedback.py                     ← feedback loop + CLI
    ├── config.yaml                     ← konfigurasi (threshold, path)
    ├── requirements.txt                ← Python dependencies
    ├── wazuh-ai-filter.service         ← systemd unit
    ├── deploy.sh                       ← script deploy ke Manager
    └── tests/
        ├── test_feature_extractor.py   ← 7 unit tests
        ├── test_ai_filter.py           ← 3 benchmark tests
        ├── sample_alerts.jsonl         ← 12 alert Wazuh-format (TP+FP)
        └── sample_groundtruth.json     ← label benar untuk sample
```

---

## 7. Troubleshooting

| Masalah                       | Gejala                                        | Solusi                                                                  |
| ----------------------------- | --------------------------------------------- | ----------------------------------------------------------------------- |
| `model.pkl` gagal load        | `InconsistentVersionWarning` / error unpickle | Sklearn version beda. Retrain: `python train_model.py`                  |
| `alerts.json` tidak ditemukan | `[WARNING] alerts.json belum ada`             | Jalankan di Wazuh Manager, bukan laptop                                 |
| `ai_filter.py` crash          | `PermissionError`                             | Jalankan dengan `sudo`                                                  |
| CRLF line ending              | `/usr/bin/env: 'python3\r': No such file`     | `sed -i 's/\r//' ai_filter.py` (otomatis oleh deploy.sh)                |
| Semua alert FORWARD_TO_SOAR   | confidence rendah di semua alert              | freq_per_minute=1 saat single; normal di live burst                     |
| Self-lockout                  | IP admin diblokir firewall-drop               | Pakai mode `log` (default), bukan `exec`. Recovery: `iptables -F INPUT` |

---

## 8. Tim

| Peran                | Nama                 | NRP            | Fokus                                      |
| -------------------- | -------------------- | -------------- | ------------------------------------------ |
| A3 — Data & Kriteria | Syifa Nurul Alfiah   | 5027241019     | Dataset, labeling, kriteria FP             |
| **A4/A5 — AI Lead**  | **Angga Firmansyah** | **5027241062** | **Model training, integration, AI filter** |

---

## 9. Referensi

- [Implementation Plan v2](<../../implementation_plan_v2%20(1).md>) — rencana implementasi lengkap
- [False Alarm Criteria](data/false-alarm-criteria.md) — definisi TP/FP per rule
- [Wazuh Documentation](https://documentation.wazuh.com/) — referensi resmi Wazuh
- [setup-soar.md](../docs/setup-soar.md) — panduan SOAR Active Response
