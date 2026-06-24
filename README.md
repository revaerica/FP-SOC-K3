# Wazuh Lab — Web Server, DDoS & Malware Simulation + SOAR

> **Kelompok:** 7 — ITS  
> **Mata Kuliah:** Manajemen Insiden & Keamanan Siber (MIKS)  
> **Tanggal Laporan:** 31 Mei 2026  
> **Platform:** Wazuh SIEM + SOAR — Microsoft Azure  
> **Klasifikasi:** Internal / Lab Report

---

## Anggota

| No | Nama | NRP | Peran |
|----|------|-----|-------|
| 1  | Shinta Alya Ramadani | 5027241016 | AGENT |
| 2  | Angga Firmansyah | 5027241062 | MANAGER |

---

## 1. Executive Summary

Fase ini melanjutkan proyek Wazuh Lab dengan menambahkan **web server sebagai target serangan nyata**, lalu mengeksekusi **4 jenis serangan DDoS** (SYN, UDP, ICMP, HTTP layer-7) dan **simulasi malware** (EICAR + ClamAV), serta membuktikan bahwa **Wazuh mendeteksi seluruh serangan**.

Setelah deteksi berhasil, proyek ditingkatkan dengan **SOAR (Security Orchestration, Automation, and Response)** menggunakan Active Response bawaan Wazuh — mengubah sistem dari SIEM (deteksi saja) menjadi **SIEM + SOAR** (deteksi + respons otomatis).

### Temuan Utama

- Kelima jenis serangan terdeteksi dengan rule terpisah
- Malware berhasil tampil di modul **Malware Detection** (bukan hanya Security Events)
- **SOAR Playbook 1:** File malware otomatis dikarantina ke `/var/ossec/quarantine/`
- **SOAR Playbook 2:** IP penyerang DDoS otomatis diblokir 120 detik, rollback otomatis

### Infrastruktur

| Peran | VM | IP Public | IP Private | Fungsi |
|-------|-----|-----------|------------|--------|
| Manager | wazuh-manager | 70.153.25.103 | 10.0.0.4 | Decoder + Rules + SOAR |
| Target | wazuh-agent-1 | 70.153.24.223 | 10.0.0.5 | Web Server + ClamAV |
| Attacker | wazuh-agent-2 | 48.193.46.1 | 10.0.0.6 | Sumber serangan |

- Dashboard: `https://70.153.25.103` (admin / admin)
- Website target: `http://70.153.24.223`

---

## 2. Arsitektur & Alur Serangan

```
[wazuh-agent-2 / Attacker]  ─── hping3 / ddos_attack.sh ──►  [wazuh-agent-1 / Target]
        10.0.0.6                                                      10.0.0.5
                                                                   (web server :80)
                                                                   (ClamAV scan)
                                                                        │
                                                               Log forwarding ke Manager
                                                                        │
                                                              [wazuh-manager 10.0.0.4]
                                                              Custom Rules + Decoder
                                                                        │
                                                          ┌─────────────┴──────────────┐
                                                     SIEM Alert                  SOAR Response
                                                  (Dashboard)              (Active Response)
                                               Threat Hunting            ┌───────────────────┐
                                               Malware Detection         │ firewall-drop      │
                                                                         │ remove-malware.py  │
                                                                         └───────────────────┘
```

---

## 3. Custom Rules — Daftar Lengkap

| Rule ID | Level | Deteksi | Muncul di |
|---------|-------|---------|-----------|
| 100200 | 12 | SYN Flood (iptables kern.log) | Security Events |
| 100201 | 12 | UDP Flood (iptables kern.log) | Security Events |
| 100202 | 12 | ICMP Flood (iptables kern.log) | Security Events |
| 100300 | 12 | ClamAV malware (FOUND) | **Malware Detection** |
| 100301 | 14 | ClamAV EICAR test | **Malware Detection** |
| 100302 | 12 | ClamAV daemon (clamd) FOUND | **Malware Detection** |
| 100400 | 1 | Penanda request web (korelasi) | — |
| 100402 | 12 | HTTP Flood layer-7 (30 req/IP/10s) | Security Events |

> **KUNCI MALWARE DETECTION:** Rule ClamAV **wajib** punya group `rootcheck`.  
> Tanpa itu, alert hanya muncul di Security Events, tidak di modul Malware Detection.

---

## 4. Hasil Deteksi

| Jenis Serangan | Rule ID | Jumlah Alert | Terdeteksi |
|----------------|---------|--------------|------------|
| SYN Flood | 100200 | 75.319 | ✅ YA |
| UDP Flood | 100201 | 12.047 | ✅ YA |
| ICMP Flood | 100202 | 4 | ✅ YA |
| HTTP Flood L7 | 100402 | 480 | ✅ YA |
| Malware EICAR | 100300/100301 | 8 | ✅ YA |

### Analisis Log Density

| Jenis | Cara dicatat | Sebab jumlah |
|-------|--------------|--------------|
| SYN / UDP | 1 alert per paket, tanpa rate-limit | Sangat banyak (puluhan ribu) |
| ICMP | 1 alert per paket, dibatasi 10/detik + anti-flood Wazuh | Sedikit (rem ganda) |
| HTTP | Rule korelasi: 1 alert = 30 request dalam 10 detik | Sedang (padat per alert) |

---

## 5. SOAR Playbook

| Playbook | Pemicu (Rule) | Aksi Otomatis | Hasil |
|----------|--------------|---------------|-------|
| Auto-block DDoS | 100402 (HTTP flood) | `firewall-drop`: blokir IP 120 detik | IP di-DROP di iptables, rollback otomatis |
| Auto-quarantine malware | 100300/100301 (ClamAV) | `remove-malware.py`: pindah file | File masuk `/var/ossec/quarantine/` |

### Bukti SOAR Berjalan

```
# Auto-quarantine malware
remove-malware: OK rule=100301 KARANTINA: /tmp/eicar_test.txt
  -> /var/ossec/quarantine/eicar_test.txt.20260601-105444.quarantine

# Auto-block & rollback DDoS
firewall-drop: add    ... 10.0.0.6  (saat memblokir)
firewall-drop: delete ... 10.0.0.6  (otomatis dibuka setelah 120 detik)
```

### Cara Verifikasi di Dashboard

```
# Threat Hunting → Events
rule.groups:active_response    → event Active Response yang dicatat Wazuh
remove-malware                 → log karantina dari active-responses.log
rule.id:100402                 → HTTP flood yang memicu SOAR
```

---

## 6. Troubleshooting — Kendala & Solusi

### Kendala 1 — Manager crash setelah pasang decoder
- **Gejala:** `Job for wazuh-manager.service failed`
- **Penyebab:** Regex `\d`, `\[` tidak didukung mesin os_regex Wazuh
- **Solusi:** Kosongkan `local_decoder.xml` — gunakan decoder bawaan `web-accesslog`

### Kendala 2 — Malware tidak muncul di Malware Detection
- **Penyebab:** Modul hanya tampilkan alert dengan `rule.groups` berisi `rootcheck`
- **Solusi:** Tambahkan group `rootcheck` pada rule 100300-100302

### Kendala 3 — HTTP flood tidak pernah terpicu
- **Penyebab:** Rule bawaan 31108 level 0 tidak dihitung engine korelasi `frequency`
- **Solusi:** Tambahkan rule perantara 100400 (level 1) sebagai trigger korelasi

### Kendala 4 — SOAR self-lockout (memblokir IP admin sendiri)
- **Penyebab:** `firewall-drop` terpicu rule per-paket 100200, memblokir SSH admin
- **Solusi:** Firewall-drop hanya dipicu rule 100402 (korelasi) + whitelist IP admin
- **Recovery:** Azure Portal → Run Command → `iptables -F INPUT`

### Kendala 5 — SOAR script gagal jalan (Windows CRLF)
- **Gejala:** `/usr/bin/env: 'python3\r': No such file or directory`
- **Solusi:** `sudo sed -i 's/\r//' /var/ossec/active-response/bin/remove-malware.py`

### Kendala 6 — SOAR `location=local` kirim AR ke Manager, bukan Agent
- **Solusi:** Ubah ke `location=defined-agent` + `agent_id=001`

---

## 7. AI False-Alarm Classifier (Human-AI Collaboration)

> **AI Lead:** Angga Firmansyah (A4/A5)
> **Detail lengkap:** [`ai-model/README.md`](ai-model/README.md)

Komponen AI duduk **di antara Wazuh dan SOAR**, mengurangi false alarm sebelum
alert sampai ke analyst atau respons otomatis.

```
  Wazuh alerts.json
       │
       ▼
  ┌─ AI FILTER (ai_filter.py) ──────────────────┐
  │  Random Forest (model.pkl)                  │
  │  confidence >= 0.85  → FILTERED_FP (ditahan) │
  │  0.60–0.84         → NEEDS_REVIEW (human)    │
  │  < 0.60            → FORWARD_TO_SOAR         │
  └──────────────────────────────────────────────┘
       │                                    │
       ▼                                    ▼
  filtered_fp.log                      SOAR Active Response
  (audit, tidak ke SOAR)               (firewall-drop, quarantine)
```

### Metrik Benchmark

| Metrik | Nilai |
|--------|-------|
| Precision | 0.987 |
| Recall (TP) | 1.000 — tidak ada serangan terlewat |
| F1 Score | 0.993 |
| Alert Reduction | 32.2% false alarm difilter |
| CV 5-fold Recall | 1.000±0.000 (sangat stabil) |

### Cara Cepat

```bash
# Test lokal (Windows/Linux)
cd ai-model/integration
pip install -r requirements.txt
python tests/test_ai_filter.py

# Deploy ke Manager
sudo bash deploy.sh
sudo systemctl status wazuh-ai-filter
```

---

## Struktur Repository

```
.
├── README.md                   ← Laporan utama (ini)
├── URUTAN_PENGERJAAN.md        ← Panduan urutan deploy
├── BACAINIAGENT.txt            ← Catatan penting untuk agent
├── ai-model/                   ← AI False-Alarm Classifier (Angga — A4/A5)
│   ├── README.md               ← Arsitektur AI + cara run (LINUXAS)
│   ├── training/               ← Model artifacts + train_model.py
│   ├── data/                   ← Dataset berlabel + pipeline
│   └── integration/            ← ai_filter.py + tests + deploy
├── configs/
│   ├── ossec-agent.conf        ← Konfigurasi localfile agent-1
│   └── ossec-manager.conf      ← Konfigurasi SOAR manager
├── rules/
│   ├── local_decoder.xml       ← Decoder (sengaja dikosongkan)
│   └── local_rules.xml         ← Semua custom rules 100200-100402
├── scripts/
│   ├── webserver/
│   │   ├── app.py              ← Web server Python
│   │   └── wazuh-webserver.service
│   ├── ddos_attack.sh          ← Script serangan DDoS
│   ├── malware_sim.sh          ← Simulasi malware EICAR
│   └── remove-malware.py       ← SOAR: skrip karantina
└── Documentation/              ← Screenshot-screenshot (upload manual)
```
