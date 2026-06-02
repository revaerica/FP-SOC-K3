# Simulasi Serangan — DDoS & Malware

---

## Fase D — Eksekusi Serangan DDoS

> Semua perintah DDoS dijalankan di **wazuh-agent-2** (10.0.0.6)  
> Target: **wazuh-agent-1** (10.0.0.5) — web server port 80

### Step 9 — Serangan DDoS 4 jenis

```bash
# SYN flood ke port 80 (web server)
sudo hping3 -S --flood -V -p 80 10.0.0.5
# atau pakai script:
sudo bash scripts/ddos_attack.sh syn 10.0.0.5 30

# UDP flood ke port 53
sudo hping3 --udp --flood -V -p 53 10.0.0.5
sudo bash scripts/ddos_attack.sh udp 10.0.0.5 30

# ICMP flood
sudo hping3 --icmp --flood -V 10.0.0.5
sudo bash scripts/ddos_attack.sh icmp 10.0.0.5 30

# HTTP flood layer-7 (50 worker paralel, 60 detik)
sudo bash scripts/ddos_attack.sh http 10.0.0.5 60

# Semua sekaligus:
sudo bash scripts/ddos_attack.sh all 10.0.0.5 30
```

**Bukti SYN flood mengenai web server (port 80):**
```
SRC=10.0.0.6 (Agent-2)  DST=10.0.0.5  DPT=80  PROTO=TCP ... SYN
```

---

## Fase D — Simulasi Malware

> Dijalankan di **wazuh-agent-1** (10.0.0.5)

### Step 10 — EICAR + ClamAV

```bash
sudo bash scripts/malware_sim.sh
```

Script ini membuat file uji EICAR (aman, standar industri), menjalankan
ClamAV scan, dan memastikan hasilnya masuk ke log yang dipantau Wazuh.

**Hasil scan:**
```
/tmp/malware-sim/eicar_test.txt: Win.Test.EICAR_HDB-1 FOUND
```

---

## Fase E — Verifikasi Hasil Deteksi

### Step 11 — Rekap jumlah alert per jenis

```bash
# Jalankan di Manager (10.0.0.4)
sudo grep -c "Rule: 100200 " /var/ossec/logs/alerts/alerts.log   # SYN
sudo grep -c "Rule: 100201 " /var/ossec/logs/alerts/alerts.log   # UDP
sudo grep -c "Rule: 100202 " /var/ossec/logs/alerts/alerts.log   # ICMP
sudo grep -c "Rule: 100402 " /var/ossec/logs/alerts/alerts.log   # HTTP
sudo grep -cE "100300|100301" /var/ossec/logs/alerts/alerts.log  # Malware
```

### Tabel Hasil Deteksi

| Jenis Serangan | Rule ID | Jumlah Alert | Terdeteksi |
|----------------|---------|--------------|------------|
| SYN Flood | 100200 | 75.319 | ✅ YA |
| UDP Flood | 100201 | 12.047 | ✅ YA |
| ICMP Flood | 100202 | 4 | ✅ YA |
| HTTP Flood L7 | 100402 | 480 | ✅ YA |
| Malware EICAR | 100300/100301 | 8 | ✅ YA |

### Step 12 — Verifikasi di Dashboard

Di menu **Threat Hunting → Events**, gunakan query berikut:

```
rule.id:100200                          → SYN flood
rule.id:100201                          → UDP flood
rule.id:100202                          → ICMP flood
rule.id:100402                          → HTTP flood
rule.id:100300 or rule.id:100301        → Malware
```

---

## Analisis Log Density

Perbedaan jumlah alert antar jenis bukan kelemahan, melainkan hasil mekanisme
berbeda — ini bahan analisis utama:

| Jenis | Cara Dicatat | Sebab Jumlah |
|-------|-------------|--------------|
| SYN / UDP | 1 alert per paket, tanpa rate-limit | Sangat banyak (puluhan ribu) |
| ICMP | 1 alert per paket, TAPI iptables dibatasi 10/detik + anti-flood Wazuh | Sedikit (rem ganda) |
| HTTP | Rule korelasi: 1 alert = 30 request dalam 10 detik | Sedang (padat per alert) |

**Kesimpulan analisis:**  
Volume serangan SYN/UDP yang sangat tinggi menghasilkan log density jauh lebih
besar dibanding ICMP (yang sengaja di-rate-limit) dan HTTP (yang dikorelasikan).
Hal ini menunjukkan pentingnya strategi penanganan log density pada SIEM:
rate-limiting di level firewall dan rule korelasi di level Manager efektif
menekan banjir alert tanpa kehilangan kemampuan deteksi.
