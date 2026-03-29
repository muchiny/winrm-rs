# -*- mode: ruby -*-
# vi: set ft=ruby :

# winrm-rs — Windows Server test VM for integration testing
#
# Prerequisites:
#   1. Vagrant on Windows: winget install Hashicorp.Vagrant
#   2. Hyper-V enabled (WSL2 implies this)
#
# Usage from WSL2:
#   vagrant.exe up --provider=hyperv    # Create and start the VM
#   vagrant.exe ssh -c "ipconfig"       # Get the VM IP address
#   WINRM_TEST_HOST=<ip> WINRM_TEST_PASS=vagrant cargo test --test integration_real -- --ignored
#   vagrant.exe destroy -f              # Tear down

Vagrant.configure("2") do |config|
  config.vm.define "winrm-test" do |win|
    # Windows Server 2025 Standard Evaluation (180 days, free)
    win.vm.box = "gusztavvargadr/windows-server-2025-standard"
    win.vm.hostname = "winrm-test"

    # WinRM communicator
    win.vm.communicator = "winrm"
    win.winrm.transport = :plaintext
    win.winrm.basic_auth_only = true
    win.winrm.port = 5985
    win.winrm.guest_port = 5985
    win.winrm.username = "vagrant"
    win.winrm.password = "vagrant"

    # Hyper-V provider
    win.vm.provider "hyperv" do |h|
      h.vmname = "winrm-rs-test"
      h.cpus = 2
      h.memory = 2048
      h.enable_virtualization_extensions = false
    end

    # Default Switch (no interactive prompt)
    win.vm.network "public_network", bridge: "Default Switch"

    # Disable SMB shared folders (avoids credential prompt)
    win.vm.synced_folder ".", "/vagrant", disabled: true

    # Provisioning: configure WinRM for all auth methods
    win.vm.provision "shell", inline: <<-SHELL
      # Basic auth + unencrypted (for HTTP testing)
      Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Basic -Value $true
      Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted -Value $true

      # NTLM auth (enabled by default, ensure it stays on)
      Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Negotiate -Value $true

      # CredSSP auth
      Enable-WSManCredSSP -Role Server -Force -ErrorAction SilentlyContinue

      # Increase shell limits for file transfer tests
      Set-Item -Path WSMan:\\localhost\\Shell\\MaxMemoryPerShellMB -Value 1024

      # Firewall: allow WinRM HTTP
      New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

      Write-Host "winrm-rs test VM provisioning complete."
      Write-Host "WinRM: port 5985 (HTTP, Basic + NTLM + CredSSP)"
      Write-Host "User:  vagrant / vagrant"
    SHELL
  end
end
