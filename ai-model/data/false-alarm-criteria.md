# Definisi dan Kriteria False Alarm — FP-SOC-K3

**Author:** Syifa Nurul Alfiah (A3 — Data & Kriteria)  
**Tanggal:** 23 Juni 2026  
**Referensi:** Custom rules di `rules/local_rules.xml`, konfigurasi SOAR di `configs/ossec-manager.conf`  
**Data Aktual:** 79.561 alert dari Wazuh Manager (23 Juni 2026, ~3 jam monitoring)

---

## 1. Definisi Umum

### False Alarm (False Positive / FP)

**False Alarm** adalah alert keamanan yang dihasilkan oleh sistem deteksi (Wazuh) yang **salah mengidentifikasi aktivitas normal sebagai ancaman**. Alert ini tidak memerlukan respons dari SOC analyst karena tidak ada serangan nyata yang terjadi.

Dalam konteks SOC, false alarm menyebabkan:
- **Alert fatigue** — analyst kewalahan oleh volume alert yang tidak relevan
- **Wasted resources** — waktu dan tenaga terbuang untuk investigasi yang tidak perlu
- **Delayed response** — serangan nyata bisa terlewat karena tenggelam di antara false alarm
- **Unnecessary SOAR actions** — sistem otomatis (firewall-drop, quarantine) bisa memblokir traffic/file yang seharusnya sah

### True Positive (TP)

**True Positive** adalah alert yang **benar mengidentifikasi ancaman nyata**. Alert ini memerlukan respons — baik otomatis via SOAR maupun manual oleh analyst.

### Temuan Aktual dari Data

Dari **79.561 alert** yang dianalisis secara riil setelah perbaikan perhitungan frekuensi dan parsing waktu:
- **79.486 alert (99.9%)** adalah **False Positive** — didominasi oleh traffic internal dari IP `10.0.0.5` (Azure subnet) dan local loopback.
- **75 alert (0.1%)** adalah **True Positive** — serangan SYN flood terkonfirmasi dari IP eksternal dan deteksi malware riil.

Ini membuktikan bahwa tanpa AI filtering, SOC analyst harus mereview **hampir 80 ribu alert** untuk menemukan **hanya 75 ancaman nyata** — rasio yang sangat tidak efisien dan menyebabkan alert fatigue.

---

## 2. Profil Data Aktual

### 2.1 Distribusi Alert per Rule

| Rule ID | Deskripsi | Jumlah | TP | FP |
|---|---|---|---|---|
| 100200 | SYN Flood (iptables) | 37.359 | 72 | 37.287 |
| 100201 | UDP Flood (iptables) | 42.199 | 0 | 42.199 |
| 100300 | ClamAV malware FOUND | 2 | 2 | 0 |
| 100302 | ClamAV daemon FOUND | 1 | 1 | 0 |

### 2.2 Sumber Alert (Top Source IPs)

| Source IP | Jumlah | Kategori | Penjelasan |
|---|---|---|---|
| 10.0.0.5 | 76.424 | **INTERNAL (FP)** | Traffic internal Azure subnet — bukan serangan |
| 127.0.0.1 | 1.311 | **INTERNAL (FP)** | Loopback DNS query resolver |
| 127.0.0.53 | 1.101 | **INTERNAL (FP)** | Loopback DNS response systemd-resolved |
| 168.63.129.16 | 483 | **INTERNAL (FP)** | Azure health probe infrastructure |
| 103.94.191.168 | 60 | **EXTERNAL (TP)** | SSH brute-force attempt |
| 2.57.122.238 | 46 | **EXTERNAL (TP)** | SSH brute-force attempt |
| 209.141.46.48 | 12 | **EXTERNAL (TP)** | SSH scan |
| 45.148.10.157 | 11 | **EXTERNAL (TP)** | SSH brute-force attempt |

### 2.3 Distribusi Frekuensi (Berdasarkan Koreksi Window ±60 Detik)

| freq_per_minute | Jumlah Alert | Interpretasi |
|---|---|---|
| 1–12 | 795 | Rendah — Didominasi oleh scan/brute-force eksternal (TP) dan noise sporadic (FP) |
| 13–164 | 2.664 | Sedang — Loopback DNS query resolver dan Azure health probes (FP) |
| 165–1.000 | 960 | Tinggi — Lonjakan trafik internal / loopback DNS (FP) |
| > 1.000 (s.d 57.470) | 75.142 | Sangat Tinggi/Masif — Trafik internal Azure berkelanjutan dari IP 10.0.0.5 (FP) |

---

## 3. Kriteria Klasifikasi per Rule ID

### 3.1 SYN Flood (Rule 100200)

| Kondisi | Label | Alasan | Contoh dari Data |
|---|---|---|---|
| `src_ip` = 10.0.0.x (internal Azure) | **FP (0)** | Traffic internal, bukan serangan | 37.179 alert dari 10.0.0.5 |
| `src_ip` external + `freq` > 30 + `dst_port` = 22 | **TP (1)** | SSH brute-force dari internet | 103.94.191.168 (freq=60), 2.57.122.238 (freq=46) |
| `src_ip` external + `freq` 5–30 + `dst_port` = 22 | **TP (1)** | SSH scan/probe | 45.148.10.157 (freq=11) |
| `src_ip` external + `freq` < 5 | **FP (0)** | Sporadic connection, bukan flood | — |
| `src_ip` = `70.153.25.99` (Agent-2 attacker) | **TP (1)** | Serangan simulasi lab | — |

### 3.2 UDP Flood (Rule 100201)

| Kondisi | Label | Alasan | Contoh dari Data |
|---|---|---|---|
| `src_ip` = 127.0.0.1 + `dst_port` = 53 | **FP (0)** | DNS query loopback systemd-resolved | 1.311 alert, freq=1311 |
| `src_ip` = 127.0.0.53 + `src_port` = 53 | **FP (0)** | DNS response loopback | 1.101 alert, freq=1101 |
| `src_ip` = 168.63.129.16 | **FP (0)** | Azure health probe DNS | 483 alert, freq=483 |
| `src_ip` = 10.0.0.x | **FP (0)** | Internal Azure traffic | Mayoritas dari 42.199 alert |
| `src_ip` external + `freq` > 50 | **TP (1)** | UDP flood nyata | — |

> **Temuan penting:** SELURUH 42.199 alert UDP Flood adalah FP — semuanya dari traffic internal (DNS resolver, Azure health probe). Ini adalah contoh sempurna "Better Safe Than Sorry" philosophy yang menyebabkan false alarm masif.

### 3.3 ICMP Flood (Rule 100202)

| Kondisi | Label | Alasan |
|---|---|---|
| `src_ip` internal / Azure health probe | **FP (0)** | Health check / monitoring |
| `src_ip` external + `freq` > 30 | **TP (1)** | Ping flood nyata |
| `src_ip` external + `freq` < 10 | **FP (0)** | Ping biasa |

### 3.4 ClamAV Malware FOUND (Rule 100300)

| Kondisi | Label | Contoh dari Data |
|---|---|---|
| ClamAV mendeteksi file berbahaya | **TP (1)** — selalu | `Win.Trojan.Generic-99999 FOUND`, `PUA.Win.Packer.Generic FOUND` |

### 3.5 ClamAV EICAR Test (Rule 100301)

| Kondisi | Label | Alasan |
|---|---|---|
| EICAR test file terdeteksi | **TP (1)** — selalu | Standar validasi antivirus |

### 3.6 ClamAV Daemon (Rule 100302)

| Kondisi | Label | Contoh dari Data |
|---|---|---|
| Daemon mendeteksi file | **TP (1)** — selalu | `Eicar-Test-Signature FOUND` |

### 3.7 HTTP Request Normal (Rule 100400)

| Kondisi | Label | Alasan |
|---|---|---|
| Semua alert rule 100400 | **FP (0)** | Helper rule untuk korelasi, bukan ancaman |

### 3.8 HTTP Flood Layer 7 (Rule 100402)

| Kondisi | Label | Alasan |
|---|---|---|
| `src_ip` external + trigger (30+ req/10s) | **TP (1)** | HTTP flood nyata |
| `src_ip` admin/whitelisted | **FP (0)** | Testing oleh admin |

---

## 4. Faktor Pembeda TP vs FP

### 4.1 Source IP (Faktor Paling Dominan)

Dari data aktual, **source IP adalah faktor terkuat** untuk membedakan TP dan FP:

| Kategori IP | Label | Jumlah di Dataset |
|---|---|---|
| Internal (10.0.0.x, 127.0.0.x) | **FP (0)** | 78.836 (99.1%) |
| Azure Infrastructure (168.63.129.16) | **FP (0)** | 483 (0.6%) |
| External (semua IP lain) | **TP (1)** | 183 (0.2%) |

### 4.2 Frekuensi per Menit

| Range | Interpretasi |
|---|---|
| < 10 | Bisa TP (scan) atau FP (noise) — perlu cek IP |
| 10–60 | Kemungkinan besar TP jika dari IP external |
| > 100 | Jika internal → pasti FP (DNS/infrastructure); jika external → pasti TP |

### 4.3 Destination Port

| Port | Interpretasi |
|---|---|
| 22 (SSH) | Jika external → SSH brute-force (TP) |
| 53 (DNS) | Jika loopback → DNS resolver (FP) |
| 80 (HTTP) | Jika internal → FP; jika external → cek freq |

---

## 5. Dataset untuk AI Model

### 5.1 File Output

- **Raw:** `ai-model/data/raw_alerts.csv` — 79.561 baris, semua alert (fitur telah diperbaiki)
- **Labeled:** `ai-model/data/labeled_alerts.csv` — 115 baris tersampling, berlabel (hanya data riil)

### 5.2 Format CSV Final

```csv
rule_id,rule_level,freq_per_minute,hour_of_day,src_port,dst_port,label
100200,12,8,6,49683,80,1
100201,12,25,8,53,57375,0
```

### 5.3 Feature Columns (urutan WAJIB konsisten)

```json
["rule_id", "rule_level", "freq_per_minute", "hour_of_day", "src_port", "dst_port"]
```

### 5.4 Proporsi Dataset

| Kelas | Jumlah | Proporsi |
|---|---|---|
| True Positive (label=1) | 75 | 65.2% |
| False Positive (label=0) | 40 | 34.8% |

---

## 6. Threshold AI Model

| Confidence Score | Keputusan | Tindakan |
|---|---|---|
| >= 0.85 | FILTERED_FP | Alert difilter, tidak diteruskan ke SOAR |
| 0.60 – 0.84 | NEEDS_REVIEW | Diteruskan ke analyst (Syifa) untuk review manual |
| < 0.60 | FORWARD_TO_SOAR | Alert diteruskan ke SOAR untuk respons otomatis |

---

## 7. Justifikasi Proyek

Data aktual membuktikan urgensi proyek ini:

1. **99.9% alert adalah false positive** — tanpa AI, analyst harus mereview ~80K alert untuk menemukan hanya 75 ancaman nyata
2. **UDP Flood 100% FP** — 42.199 alert yang semuanya dari DNS resolver internal, seharusnya tidak pernah sampai ke analyst
3. **SYN Flood 99.8% FP** — 37.287 dari 37.359 alert dari traffic internal Azure
4. **Malware detection 100% TP** — 3 alert, semua ancaman nyata
5. **False Positive Rate (FPR) baseline = 99.9%** — target AI: turunkan ke < 20%

Dengan AI model Random Forest yang ditraining dari dataset berlabel ini, diharapkan:
- **Recall TP >= 0.90** (tidak boleh miss serangan nyata)
- **Precision >= 0.80** (FP yang lolos ke SOAR minimal)
- **Alert volume reduction >= 90%** (dari ~80K ke < 8K yang perlu direview)
