# Setup Manager — Custom Rules & Decoder

> Semua perintah dijalankan di **wazuh-manager** (10.0.0.4)

---

## Fase C — Decoder + Custom Rules

### Step 6 — Pasang decoder & rules

```bash
sudo cp rules/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
sudo cp rules/local_rules.xml   /var/ossec/ruleset/rules/local_rules.xml

# Hapus jika ada file rules di lokasi lama (cegah duplikat)
sudo rm -f /var/ossec/etc/rules/local_rules.xml
```

### Step 7 — Test konfigurasi SEBELUM restart (wajib)

```bash
# Jika ada error, Manager tidak akan restart — perbaiki dulu!
sudo /var/ossec/bin/wazuh-analysisd -t

# Kalau lolos, baru restart
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager | grep Active
```

**Hasil yang diharapkan:** `Active: active (running)`

---

## Daftar Custom Rules

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
> Tanpa itu alert hanya muncul di Security Events, tidak di modul Malware Detection.
> Inilah penyebab pada percobaan sebelumnya malware tidak muncul di section
> Malware Detection.

---

## Step 8 — Validasi rule dengan logtest

Gunakan `wazuh-logtest` untuk memverifikasi rule sebelum menjalankan serangan nyata.

**Test SYN flood:**
```
Input log:
  2026-05-17T15:09:17 wazuh-agent-1 kernel: SYN-FLOOD: ... SRC=10.0.0.6 DST=10.0.0.5 ... DPT=80 SYN

Hasil yang diharapkan:
  id: '100200'
  level: '12'
  description: 'DDoS: SYN Flood terdeteksi via iptables'
```

**Test Malware EICAR:**
```
Input log:
  May 31 10:00:00 wazuh-agent-1 clamscan: /tmp/.../eicar_test.txt: Win.Test.EICAR_HDB-1 FOUND

Hasil yang diharapkan:
  id: '100301'
  level: '14'
  groups: [..., 'rootcheck', ...]
```

✅ Kedua rule match sesuai harapan.

---

## Kenapa `local_decoder.xml` Dikosongkan?

Percobaan pertama menggunakan decoder custom untuk web access log dengan
regex seperti `\d` dan `\[`. Hasilnya Manager crash dengan error:

```
(1452): Syntax error on regex
```

Mesin regex bawaan Wazuh (os_regex) tidak mendukung sintaks `\d` maupun `\[`.
Solusinya: Wazuh sudah memiliki decoder bawaan `web-accesslog` yang menangani
format Apache Combined Log dengan benar. File `local_decoder.xml` dikosongkan.

**Pelajaran:** Selalu jalankan `wazuh-analysisd -t` sebelum restart.
