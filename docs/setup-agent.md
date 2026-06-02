# Setup Agent-1 — Web Server + Logging + ClamAV

> Semua perintah dijalankan di **wazuh-agent-1** (10.0.0.5)

---

## Fase A — Deploy Web Server

Web server berbasis Python stdlib (zero-dependency), menulis access log
format Apache Combined ke `/var/log/webserver/access.log`.

### Step 1 — Pasang web server sebagai service

```bash
sudo mkdir -p /opt/wazuh-lab/webserver
sudo cp scripts/webserver/app.py /opt/wazuh-lab/webserver/app.py
sudo cp scripts/webserver/wazuh-webserver.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable wazuh-webserver
sudo systemctl start wazuh-webserver
sudo systemctl status wazuh-webserver --no-pager
```

**Hasil yang diharapkan:** `Active: active (running)`

### Step 2 — Verifikasi web server jalan

```bash
curl -s http://localhost/status ; echo
```

**Hasil:**
```json
{"service":"wazuh-lab-web","status":"ok","requests":0}
```

✅ Web server aktif dan melayani request.

---

## Fase B — Konfigurasi Logging

### Step 3 — Logging iptables (DDoS layer 3/4)

Aturan iptables ini membuat setiap paket SYN, UDP, dan ICMP dicatat ke
`kern.log` dengan prefix tertentu yang akan dicocokkan oleh custom rules Wazuh.

```bash
sudo iptables -I INPUT -p tcp --syn -j LOG --log-prefix "SYN-FLOOD: " --log-level 4
sudo iptables -I INPUT -p udp        -j LOG --log-prefix "UDP-FLOOD: " --log-level 4
sudo iptables -I INPUT -p icmp -m limit --limit 10/sec -j LOG --log-prefix "ICMP-FLOOD: " --log-level 4

# Verifikasi 3 rule aktif
sudo iptables -L INPUT -n | grep LOG
```

> **Kenapa ICMP diberi `--limit 10/sec`?**  
> Tanpa rate-limit, ICMP flood menghasilkan ratusan ribu log per menit dan
> bisa memenuhi disk. Limit 10/detik + anti-flood Wazuh menghasilkan hanya
> 4 alert — cukup untuk membuktikan deteksi tanpa membanjiri storage.

### Step 4 — Daftarkan log ke Wazuh Agent

Tambahkan snippet berikut ke `/var/ossec/etc/ossec.conf` tepat di atas
`</ossec_config>` (atau salin dari `configs/ossec-agent.conf`):

```xml
<!-- Kernel log: alert iptables SYN/UDP/ICMP -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>

<!-- Access log web server format Apache Combined -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/webserver/access.log</location>
</localfile>

<!-- Log ClamAV untuk deteksi malware -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/clamav/clamav.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

### Step 5 — Install ClamAV

```bash
sudo apt-get install -y clamav clamav-daemon

# Update database virus (wajib sebelum scan)
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam

# Verifikasi versi dan database
clamscan --version
```

**Hasil:**
```
ClamAV 1.4.4/28017/Sun May 31 06:27:13 2026
```

✅ ClamAV terinstall & database virus ter-update.
