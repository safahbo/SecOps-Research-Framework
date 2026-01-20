#!/bin/bash
# ============================================================
# PROJECT: SecOps-Research-Framework (SRF)
# MODULE: SRF Command Line Interface (CLI)
# AUTHOR: Safa Hacıbayramoğlu
# VERSION: 1.0.0
# DESCRIPTION: Main orchestration tool for the autonomous defense engine.
# ============================================================

# --- Configuration ---
# Scriptin çalıştığı klasörü bulur (src/)
BASE_DIR=$(dirname "$0")

# Otomasyon scriptinin yerini belirler (src/automation/secops-watchdog.sh)
WATCHDOG_SCRIPT="$BASE_DIR/automation/secops-watchdog.sh"
LOG_FILE="/var/log/secops-test.log"

# --- Colors (UI Design) ---
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Banner Function ---
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "   _____   _____   ______   "
    echo "  / ____| |  __ \ |  ____|  "
    echo " | (___   | |__) || |__     "
    echo "  \___ \  |  _  / |  __|    "
    echo "  ____) | | | \ \ | |       "
    echo " |_____/  |_|  \_\|_|       "
    echo -e "${NC}"
    echo -e "${YELLOW} SecOps-Research-Framework (SRF) - v1.0.0${NC}"
    echo -e " Author: Safa Hacıbayramoğlu"
    echo -e " System: Autonomous Defense Engine"
    echo " ----------------------------------"
}

# --- Core Functions ---

check_health() {
    echo -e "\n${BLUE}[*] Checking Framework Components...${NC}"
    
    # 1. Check Wazuh Manager
    if systemctl is-active --quiet wazuh-manager; then
        echo -e "${GREEN}[OK] Wazuh Manager Service is ACTIVE${NC}"
    else
        echo -e "${RED}[!!] Wazuh Manager Service is DOWN${NC}"
    fi

    # 2. Check Wazuh Agent
    if systemctl is-active --quiet wazuh-agent; then
        echo -e "${GREEN}[OK] Wazuh Agent Service is ACTIVE${NC}"
    else
        echo -e "${RED}[!!] Wazuh Agent Service is DOWN${NC}"
    fi

    # 3. Check API Connectivity
    if curl -s -k -m 2 https://127.0.0.1:55000 > /dev/null; then
        echo -e "${GREEN}[OK] API Endpoint is REACHABLE${NC}"
    else
         echo -e "${RED}[!!] API Endpoint is UNREACHABLE${NC}"
    fi
}

run_autotest() {
    echo -e "\n${YELLOW}[*] Initiating Auto-Test (Self-Check) Sequence...${NC}"
    
    if [ -f "$WATCHDOG_SCRIPT" ]; then
        echo -e "${BLUE} -> Executing Watchdog Module...${NC}"
        bash "$WATCHDOG_SCRIPT"
    else
        echo -e "${RED}[ERROR] Watchdog module not found at: $WATCHDOG_SCRIPT${NC}"
        echo "Please check 'src/automation/' folder."
    fi
}

view_audit_logs() {
    echo -e "\n${BLUE}[*] Fetching Last 5 Audit Entries:${NC}"
    echo "------------------------------------------------"
    if [ -f "$LOG_FILE" ]; then
        tail -n 5 "$LOG_FILE"
    else
        echo -e "${YELLOW}[!] No audit logs found yet. Run an Auto-Test first.${NC}"
    fi
    echo "------------------------------------------------"
}

# --- Interactive Menu ---
while true; do
    show_banner
    echo "Select an operation:"
    echo "1) Check System Health Status"
    echo "2) Execute Auto-Test (Verify Detection)"
    echo "3) View System Audit Logs"
    echo "4) Exit Framework"
    echo ""
    read -p "Enter choice [1-4]: " choice

    case $choice in
        1) check_health; read -p "Press Enter..." ;;
        2) run_autotest; read -p "Press Enter..." ;;
        3) view_audit_logs; read -p "Press Enter..." ;;
        4) echo -e "${GREEN}Shutting down SRF CLI... Goodbye.${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
done
