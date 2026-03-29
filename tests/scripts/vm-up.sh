#!/bin/bash
# vm-up.sh — Create the winrm-rs test VM via Vagrant + Hyper-V.
#
# First time: downloads ~7 GB box, takes ~15 min.
# Subsequent: just starts the existing VM.
#
# Usage:
#   bash tests/scripts/vm-up.sh

set -euo pipefail

GSUDO="/mnt/c/Program Files/gsudo/2.6.1/gsudo.exe"
VAGRANT_DIR="C:\\winrm-rs-vagrant"
SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== winrm-rs VM setup ==="

# Copy Vagrantfile to Windows-accessible directory
mkdir -p /mnt/c/winrm-rs-vagrant
cp "$SCRIPT_DIR/Vagrantfile" /mnt/c/winrm-rs-vagrant/Vagrantfile
echo "Vagrantfile copied to $VAGRANT_DIR"

# Run vagrant up with admin privileges
echo "Starting vagrant up (this may take 15 min on first run)..."
"$GSUDO" powershell.exe -Command "
    cd '$VAGRANT_DIR';
    & 'C:\Program Files\Vagrant\bin\vagrant.exe' up --provider=hyperv
"

echo "VM created. Run 'eval \$(tests/scripts/vm-connect.sh)' to connect."
