#!/bin/bash
# vm-destroy.sh — Destroy the winrm-rs test VM and clean up port proxy.
set -euo pipefail

GSUDO="/mnt/c/Program Files/gsudo/2.6.1/gsudo.exe"
VAGRANT_DIR="C:\\winrm-rs-vagrant"

"$GSUDO" powershell.exe -Command "
    cd '$VAGRANT_DIR';
    & 'C:\Program Files\Vagrant\bin\vagrant.exe' destroy -f;
    netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=55985 2>\$null;
    Write-Host 'VM destroyed and port proxy removed'
"
