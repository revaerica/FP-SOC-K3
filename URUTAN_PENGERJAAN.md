# Urutan Pengerjaan — Kelompok 7 ITS

> Baca ini dulu sebelum mulai. Urutan WAJIB diikuti karena ada dependensi antar langkah.

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

## Tips Penting

| Hal | Jangan | Lakukan |
|-----|--------|---------|
| Edit rules | Langsung restart | Selalu `wazuh-analysisd -t` dulu |
| SOAR trigger | Pakai rule per-paket (100200) | Pakai rule korelasi (100402) |
| Upload script dari Windows | Langsung copy | Fix CRLF dengan `sed -i 's/\r//'` |
| SOAR location malware | `local` | `defined-agent` + `agent_id` |
| Recovery self-lockout | Panic | Azure Portal → Run Command → `iptables -F INPUT` |
