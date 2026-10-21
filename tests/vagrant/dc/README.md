# Kerberos bench — `winrm.test` domain controller

A separate Hyper-V VM that exists only to exercise `AuthMethod::Kerberos`
live. It does not touch the Server 2025 workgroup bench (`winrm-rs-test`).

| | |
|---|---|
| Hyper-V VM | `winrm-rs-dc` (4096 MB, 2 vCPU, Default Switch) |
| Box | `gusztavvargadr/windows-server-2025-standard` (same as the 2025 bench) |
| Domain | `winrm.test`, NetBIOS `WINRM`, realm `WINRM.TEST`, host `dc` |
| Vagrant dir (Windows) | `C:\winrm-rs-dc-vagrant` |
| Host ports | WinRM HTTP `57985` → VM `5985`; KDC TCP `57088` → VM `88` |
| Test account | `WINRM\vagrant` / `vagrant` (Domain Admins, password never expires) |

All credentials are throwaway values for this lab VM only:
`WINRM\vagrant` / `vagrant`, `WINRM\Administrator` / `Vagrant-DC-2025!`,
DSRM `Vagrant-DSRM-2025!`. The domain password policy is relaxed (no
complexity, no minimum length, no expiry) so that `vagrant` is accepted.

The `Vagrantfile` and the `tests/scripts/vm-*.sh` scripts are git-ignored
like the other benches' (`.gitignore`: dev-only files); this README is the
tracked description.

## Bring up

```bash
bash tests/scripts/vm-up-dc.sh      # copies the Vagrantfile, `vagrant up`
```

First run: imports the box (~7 GB), sets the hostname, promotes the DC
(`Install-ADDSForest -DomainName winrm.test -DomainNetbiosName WINRM
-InstallDns`), reboots, then makes sure `WINRM\vagrant` exists. On the first
DC of a new forest the box's local `vagrant` account becomes a domain account;
a startup scheduled task (`winrm-rs-ensure-vagrant`, script
`C:\winrm-rs\ensure-vagrant.ps1`, log `C:\winrm-rs\ensure-vagrant.log`)
recreates or repairs it at every boot in case it does not.

WinRM on the DC: Basic, Negotiate and Kerberos on, `AllowUnencrypted = true`
(winrm-rs sends the SOAP body of a Kerberos request in clear over HTTP; it has
no Kerberos message encryption).

If `vagrant up` runs detached (no console for gsudo), launch it on the
Windows side and read the log:

```bash
"/mnt/c/Program Files/gsudo/2.6.1/gsudo.exe" powershell.exe -Command \
  "Start-Process powershell.exe -ArgumentList '-NoProfile','-File','C:\winrm-rs-dc-vagrant\up.ps1' -WindowStyle Hidden"
iconv -f utf-16le -t utf-8 /mnt/c/winrm-rs-dc-vagrant/up.log | tr -d '\r' | tail
```

(`up.ps1` = `Set-Location C:\winrm-rs-dc-vagrant; vagrant up --provider=hyperv *> up.log`.)

## WSL client

One-time, with sudo:

```bash
sudo dnf install -y krb5-workstation      # kinit / klist / kvno
```

`/etc/hosts` needs `127.0.0.1 dc.winrm.test`: the client derives the SPN
`HTTP/<host>` from the host string, so the tests connect by name, and under
`networkingMode=Mirrored` the host's port proxies answer on loopback. WSL may
regenerate `/etc/hosts` on restart (`/etc/wsl.conf` does not set
`generateHosts = false`); `vm-connect-dc.sh` re-adds the line with `sudo` when
it is missing, after a backup in `/var/tmp/hosts.bak.<timestamp>`.

No system Kerberos config is written. `vm-connect-dc.sh` creates a private
`target/winrm-krb5/krb5.conf` (realm `WINRM.TEST`, `kdc =
tcp/127.0.0.1:57088`, `udp_preference_limit = 1`, no DNS lookups, `rdns =
false`) and points `KRB5_CONFIG` at it; the ticket cache is
`target/winrm-krb5/ccache` (`KRB5CCNAME`).

## Run the tests

```bash
eval "$(tests/scripts/vm-connect-dc.sh)"
kinit vagrant@WINRM.TEST                  # password: vagrant
klist                                      # krbtgt/WINRM.TEST@WINRM.TEST
kvno HTTP/dc.winrm.test@WINRM.TEST         # service ticket for the SPN
cargo test --features kerberos --test integration_real kerberos -- --ignored --nocapture
```

`KRB5_TRACE=/dev/stderr` shows the client-side Kerberos exchange. Kerberos
tolerates 5 minutes of clock skew; the DC syncs its clock from the Hyper-V
host. On `Clock skew too great`, resync the DC (`w32tm /resync`), not WSL.

## Exposure on the host network

`vm-connect-dc.sh` (through `gsudo`) creates, on the Windows host:

- two `netsh` port proxies listening on `0.0.0.0`: `57985` → VM `5985`
  (WinRM HTTP) and `57088` → VM `88` (KDC, TCP);
- two inbound firewall rules, `WinRM DC HTTP` and `WinRM DC KDC`, with no
  `RemoteAddress` restriction.

While the bench is up, any machine that can reach the host on those ports can
talk to an unencrypted WinRM endpoint (`AllowUnencrypted = true`) and try the
lab Domain Admin `vagrant` / `vagrant`. This mirrors what the Server 2025
bench already does. Tear the bench down (below) when you are not testing. If
you want to narrow it, restrict the two firewall rules to the WSL subnet or to
localhost (`Set-NetFirewallRule -DisplayName 'WinRM DC HTTP','WinRM DC KDC'
-RemoteAddress ...`); the scripts do not do this.

## Stop (keeps the VM)

```bash
G="/mnt/c/Program Files/gsudo/2.6.1/gsudo.exe"
"$G" powershell.exe -Command "Stop-VM winrm-rs-dc"
```

## Destroy (irreversible)

Warning: this deletes the VM and its disks; the domain is lost and the next
`vm-up-dc.sh` rebuilds it from scratch.

```bash
G="/mnt/c/Program Files/gsudo/2.6.1/gsudo.exe"
"$G" powershell.exe -Command "cd C:\winrm-rs-dc-vagrant; & 'C:\Program Files\Vagrant\bin\vagrant.exe' destroy -f"
```

## Remove the host and WSL side

```bash
G="/mnt/c/Program Files/gsudo/2.6.1/gsudo.exe"
"$G" cmd.exe /c "netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=57985 & netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=57088"
"$G" powershell.exe -Command "Remove-NetFirewallRule -DisplayName 'WinRM DC HTTP','WinRM DC KDC'"
rm -rf target/winrm-krb5
sudo sed -i '/^127\.0\.0\.1 dc\.winrm\.test$/d' /etc/hosts
```

Then delete `C:\winrm-rs-dc-vagrant`. Optional leftovers: `sudo dnf remove
krb5-workstation` (the Kerberos client tools) and the `/etc/hosts` backups
`/var/tmp/hosts.bak.*` written by `vm-connect-dc.sh`.
