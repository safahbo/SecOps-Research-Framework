#!/bin/bash
# Project: SecOps-Research-Framework
# Module: Auto-Test & Self-Healing Watchdog
# Author: Safa Hacıbayramoğlu
# Version: 1.0.0

# CONFIGURATION
WAZUH_API_URL="https://127.0.0.1:55000"
TEST_ID="AUTOTEST-$(date +%s)"
RULE_ID="100099" # Defined in src/rules/local_rules.xml
LOG_FILE="/var/log/secops-test.log"

# UI COLORS
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[*] Initiating SecOps Autonomous Self-Check Sequence...${NC}"

# STEP 1: TRIGGER (Simulate Attack)
# We inject a specific log that matches our custom rule to test visibility.
echo "[*] Injecting simulation payload (ID: $TEST_ID)..."
echo "{\"integration\": \"secops-autotest\", \"test_id\": \"$TEST_ID\", \"status\": \"simulation_active\"}" >> /var/log/syslog

# Buffer time for log processing (Logun işlenmesi için bekleme)
sleep 5

# STEP 2: VERIFY (API Check - JSON First)
# Getting JWT Token securely
TOKEN=$(curl -s -k -u wazuh:wazuh -X POST "$WAZUH_API_URL/security/user/authenticate" | jq -r .data.token)

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo -e "${RED}[CRITICAL] API Connection Failed! Watchdog cannot verify system health.${NC}"
    exit 1
fi

# Checking if the simulation triggered an alert
ALERT_CHECK=$(curl -s -k -H "Authorization: Bearer $TOKEN" "$WAZUH_API_URL/alerts?rule_id=$RULE_ID&q=full_log:$TEST_ID")
COUNT=$(echo $ALERT_CHECK | jq '.data.total_affected_items')

# STEP 3: REPORT & DECISION
if [ "$COUNT" -gt 0 ]; then
    echo -e "${GREEN}[PASS] SYSTEM HEALTHY. Detection Engine confirmed visibility.${NC}"
    echo "$(date) - [PASS] Simulation $TEST_ID detected successfully." >> $LOG_FILE
    exit 0
else
    echo -e "${RED}[FAIL] BLIND SPOT DETECTED! Simulation was NOT detected.${NC}"
    echo "$(date) - [FAIL] Simulation $TEST_ID FAILED. Investigation required." >> $LOG_FILE
    exit 1
fi
