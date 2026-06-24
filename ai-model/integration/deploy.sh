#!/usr/bin/env bash
# =============================================================
# deploy.sh — Deploy AI Filter ke Wazuh Manager
# Author: Angga Firmansyah — A5 Integration (FP-SOC-K3)
#
# Jalankan di Wazuh Manager (Linux):
#   sudo bash deploy.sh
#
# Lakukan dari folder integration/ (lokasi deploy.sh ini).
# Asumsi: repo sudah di-clone / disalin ke Manager.
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AI_MODEL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="/opt/ai-filter"
PYTHON="${PYTHON:-python3}"

echo "================================================"
echo "  Deploy AI Filter (A5) ke Wazuh Manager"
echo "================================================"
echo "Source : $AI_MODEL_DIR"
echo "Target : $DEPLOY_DIR"
echo ""

# 1. Buat folder deploy
echo "[1/7] Membuat folder $DEPLOY_DIR ..."
mkdir -p "$DEPLOY_DIR/integration"
mkdir -p "$DEPLOY_DIR/training"
mkdir -p /var/ossec/ai-filter/feedback

# 2. Salin file integration + training artifacts
echo "[2/7] Menyalin file integration ..."
cp "$SCRIPT_DIR"/ai_filter.py "$SCRIPT_DIR"/feature_extractor.py \
   "$SCRIPT_DIR"/feedback.py "$SCRIPT_DIR"/config.yaml \
   "$SCRIPT_DIR"/requirements.txt \
   "$DEPLOY_DIR/integration/" 2>/dev/null || true

echo "[3/7] Menyalin artifact model (model.pkl, scaler.pkl, feature_columns.json) ..."
cp "$AI_MODEL_DIR"/training/model.pkl \
   "$AI_MODEL_DIR"/training/scaler.pkl \
   "$AI_MODEL_DIR"/training/feature_columns.json \
   "$DEPLOY_DIR/training/" 2>/dev/null || true

# 3. FIX CRLF (jika script dibuat di Windows) — sesuai setup-soar.md kendala #5
echo "[4/7] Memperbaiki CRLF line ending (Windows -> Unix) ..."
find "$DEPLOY_DIR" -name "*.py" -exec sed -i 's/\r//' {} \;

# 4. Install dependency Python
echo "[5/7] Install dependency Python ..."
$PYTHON -m pip install -q -r "$DEPLOY_DIR/integration/requirements.txt" || {
    echo "[WARN] pip install gagal. Pastikan sklearn/joblib/pyyaml terinstall."
}

# 5. Smoke test: load model + classify 1 sample
echo "[6/7] Smoke test load model ..."
$PYTHON "$DEPLOY_DIR/integration/ai_filter.py" \
    --config "$DEPLOY_DIR/integration/config.yaml" --once 2>&1 | head -20 || true

# 6. Pasang systemd service
echo "[7/7] Memasang systemd service ..."
cp "$SCRIPT_DIR/wazuh-ai-filter.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable wazuh-ai-filter
systemctl restart wazuh-ai-filter

echo ""
echo "================================================"
echo "  DEPLOY SELESAI"
echo "================================================"
echo ""
echo "Cek status : sudo systemctl status wazuh-ai-filter"
echo "Cek log    : sudo journalctl -u wazuh-ai-filter -f"
echo "Cek output : sudo ls -la /var/ossec/ai-filter/"
echo "            sudo cat /var/ossec/ai-filter/ai_decisions.log"
echo ""
echo "Stop       : sudo systemctl stop wazuh-ai-filter"
echo "Uninstall  : sudo systemctl disable --now wazuh-ai-filter;"
echo "             sudo rm /etc/systemd/system/wazuh-ai-filter.service;"
echo "             sudo systemctl daemon-reload"
