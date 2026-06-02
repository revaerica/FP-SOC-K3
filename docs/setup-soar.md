# Setup SOAR — Security Orchestration, Automation, and Response

Setelah deteksi berhasil (Fase A–E), proyek ditingkatkan dengan menambahkan
**respons otomatis** menggunakan fitur Active Response bawaan Wazuh. Ini mengubah
sistem dari SIEM (deteksi saja) menjadi **SIEM + SOAR** (deteksi + respons otomatis).

---

## Fase F — Implementasi SOAR

### Step 13 — Pasang script karantina di Agent-1

```bash
# Salin script dari repo
sudo cp scripts/remove-malware.py /var/ossec/active-response/bin/remove-malware.py

# Set permission yang benar
sudo chown root:wazuh /var/ossec/active-response/bin/remove-malware.py
sudo chmod 750 /var/ossec/active-response/bin/remove-malware.py

# WAJIB: fix Windows CRLF line ending jika script dibuat di Windows
sudo sed -i 's/\r//' /var/ossec/active-response/bin/remove-malware.py

# Verifikasi
sudo file /var/ossec/active-response/bin/remove-malware.py
# Harus: Python script, ASCII text executable (BUKAN: with CRLF line terminators)
```

> **Kenapa harus fix CRLF?**  
> Script dibuat di Windows menggunakan CRLF (`\r\n`). Linux membaca shebang
> sebagai `python3\r` yang tidak dikenal — script gagal dieksekusi secara
> diam-diam tanpa error yang jelas di log Wazuh.

---

### Step 14 — Konfigurasi Active Response di Manager

Tambahkan ke `/var/ossec/etc/ossec.conf` (atau salin dari `configs/ossec-manager.conf`):

```xml
<!-- Whitelist: IP yang TIDAK BOLEH diblokir SOAR -->
<global>
  <white_list>10.0.0.0/24</white_list>      <!-- subnet internal + SSH admin -->
  <white_list>168.63.129.16</white_list>     <!-- Azure health probe -->
  <white_list>114.10.47.78</white_list>      <!-- IP publik admin (sesuaikan) -->
</global>

<!-- Daftarkan script karantina -->
<command>
  <name>remove-malware</name>
  <executable>remove-malware.py</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<!-- Playbook 1: Auto-block IP saat HTTP Flood (rule korelasi) -->
<!-- JANGAN gunakan rule 100200/100201/100202 — akan lockout SSH admin! -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100402</rules_id>
  <timeout>120</timeout>
</active-response>

<!-- Playbook 2: Auto-quarantine malware di Agent-1 -->
<!-- location HARUS defined-agent, bukan local! -->
<active-response>
  <command>remove-malware</command>
  <location>defined-agent</location>
  <agent_id>001</agent_id>
  <rules_id>100300,100301</rules_id>
</active-response>
```

```bash
# Test config dulu
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

---

## SOAR Playbook

| Playbook | Pemicu (Rule) | Aksi Otomatis | Hasil |
|----------|--------------|---------------|-------|
| Auto-block DDoS | 100402 (HTTP flood) | `firewall-drop`: blokir IP 120 detik | IP di-DROP di iptables, rollback otomatis |
| Auto-quarantine malware | 100300/100301 (ClamAV) | `remove-malware.py`: pindah file | File masuk `/var/ossec/quarantine/` |

---

## Step 15 — Simulasi & Verifikasi Auto-Quarantine

```bash
# Trigger manual untuk uji karantina
sudo logger -t clamscan "/tmp/eicar_test.txt: Eicar-Test-Signature FOUND"

# Tunggu Active Response berjalan
sleep 12

# Cek log karantina
sudo grep "KARANTINA" /var/ossec/logs/active-responses.log | tail -3

# Cek isi folder karantina
sudo ls -l /var/ossec/quarantine/
```

**Hasil yang diharapkan:**
```
remove-malware: OK rule=100301 KARANTINA: /tmp/eicar_test.txt
  -> /var/ossec/quarantine/eicar_test.txt.20260601-105444.quarantine
```

---

## Step 16 — Verifikasi Auto-Block DDoS

Saat HTTP flood terdeteksi (rule 100402), cek log:

```bash
sudo tail -f /var/ossec/logs/active-responses.log
```

**Hasil yang diharapkan:**
```
firewall-drop: add    ... 10.0.0.6   (saat serangan terdeteksi)
firewall-drop: delete ... 10.0.0.6   (otomatis setelah 120 detik)
```

---

## Cara Lihat SOAR di Dashboard

```
# Threat Hunting → Events
rule.groups:active_response     → semua event Active Response
remove-malware                  → log karantina dari active-responses.log
rule.id:100402                  → HTTP flood yang memicu SOAR firewall-drop

# Malware Detection → pilih wazuh-agent-1
→ Alert EICAR level 14 yang memicu SOAR karantina
```

---

## Kendala SOAR & Solusinya

### Kendala 4 — Self-lockout: memblokir IP admin sendiri
- **Gejala:** SSH ke Agent-1 timeout setelah SOAR aktif
- **Penyebab:** `firewall-drop` dipicu rule 100200 (per-paket) yang fired pada SEMUA traffic termasuk SSH admin
- **Solusi:** Gunakan rule 100402 (korelasi) + whitelist IP admin
- **Recovery:** Azure Portal → Run Command → `iptables -F INPUT`

### Kendala 5 — Script tidak jalan: Windows CRLF
- **Gejala:** `/usr/bin/env: 'python3\r': No such file or directory`
- **Solusi:** `sudo sed -i 's/\r//' /var/ossec/active-response/bin/remove-malware.py`

### Kendala 6 — AR terkirim ke Manager, bukan Agent-1
- **Gejala:** Alert 100301 ada tapi karantina tidak terjadi
- **Penyebab:** `<location>local</location>` menjalankan script di Manager
- **Solusi:** `<location>defined-agent</location>` + `<agent_id>001</agent_id>`
