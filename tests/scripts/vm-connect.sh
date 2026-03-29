#!/bin/bash
# vm-connect.sh — Ensure the winrm-rs test VM is running and reachable from WSL2.
#
# Handles:
#   1. Check if VM is running, start it if not
#   2. Wait for VM to get an IP
#   3. Update the port proxy (WSL2 → Windows host → VM)
#   4. Wait for WinRM to respond
#   5. Export env vars for cargo test
#
# Usage:
#   eval $(tests/scripts/vm-connect.sh)
#   cargo test --test integration_real -- --ignored

set -euo pipefail

GSUDO="/mnt/c/Program Files/gsudo/2.6.1/gsudo.exe"
VM_NAME="winrm-rs-test"
VAGRANT_DIR="C:\\winrm-rs-vagrant"

# Step 1: Ensure VM is running
STATE=$("$GSUDO" powershell.exe -Command "(Get-VM '$VM_NAME').State" 2>/dev/null | tr -d '\r\n')
if [ "$STATE" != "Running" ]; then
    echo "Starting VM $VM_NAME..." >&2
    "$GSUDO" powershell.exe -Command "Start-VM '$VM_NAME'" 2>/dev/null
    sleep 5
fi

# Step 2: Wait for IP (max 60s)
echo "Waiting for VM IP..." >&2
VM_IP=""
for i in $(seq 1 12); do
    VM_IP=$("$GSUDO" powershell.exe -Command "(Get-VM '$VM_NAME' | Get-VMNetworkAdapter).IPAddresses[0]" 2>/dev/null | tr -d '\r\n')
    if [ -n "$VM_IP" ] && [ "$VM_IP" != "" ]; then
        break
    fi
    sleep 5
done

if [ -z "$VM_IP" ]; then
    echo "ERROR: Could not get VM IP after 60s" >&2
    exit 1
fi
echo "VM IP: $VM_IP" >&2

# Step 3: Update port proxy (WinRM)
"$GSUDO" cmd.exe /c "netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=55985 >nul 2>&1 & netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=55985 connectaddress=$VM_IP connectport=5985" 2>/dev/null

# Step 4: Wait for WinRM (max 60s)
GW=$(ip route | grep default | awk '{print $3}')
echo "Waiting for WinRM on $GW:55985..." >&2
for i in $(seq 1 12); do
    if timeout 3 bash -c "echo > /dev/tcp/$GW/55985" 2>/dev/null; then
        echo "WinRM ready." >&2
        break
    fi
    sleep 5
done

# Step 5: Export for callers
echo "export WINRM_TEST_HOST=$GW"
echo "export WINRM_TEST_PORT=55985"
echo "export WINRM_TEST_USER=vagrant"
echo "export WINRM_TEST_PASS=vagrant"
