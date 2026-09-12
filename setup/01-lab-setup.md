# Lab Setup

Notes on how I built the lab and the problems I ran into.

## What's running

Two VirtualBox VMs:

- Ubuntu Server 22.04 running Splunk
- Windows 11 Enterprise LTSC running Sysmon and Atomic Red Team

Each VM has two network adapters. One NAT for downloads, one host-only so the VMs
can reach each other without touching the physical network. Windows forwards its
event logs to Splunk over TCP 9997.

Attacks run on the Windows box, Sysmon records them, and I write the detection
queries in Splunk.

Shared folders and drag-and-drop are off, and the Windows VM only has a local
account on it. Defender is disabled there, so I treat it as compromised.

## Why LTSC

Windows 10 went end of support in October 2025 and the evaluation ISO isn't
available anymore. LTSC has no Store or Copilot, which means much less background
process noise in Sysmon. That matters on a 500 MB/day licence.

## Logging

Sysmon with the SwiftOnSecurity config.

Group Policy:
- Audit Process Creation (Success)
- Include command line in process creation events
- PowerShell Script Block Logging

Forwarded channels: Sysmon Operational, Security, System, PowerShell Operational.
All into `index=main`.

One thing to watch: I used `renderXml = false`, so the sourcetype comes through as
`WinEventLog:Microsoft-Windows-Sysmon/Operational`. A lot of guides use
`XmlWinEventLog:` instead, which only works with `renderXml = true`. Searches just
return nothing otherwise, with no error to tell you why.

## Problems

### Windows 11 VM wouldn't boot

Black screen, no keyboard response, and a green turtle icon in the VirtualBox
status bar. The turtle means VirtualBox is running in software emulation because
it can't get at hardware virtualisation.

Windows 11 enables Memory Integrity by default, which starts Hyper-V underneath and
takes VT-x away from VirtualBox. Ubuntu still booted through the emulated path.
Windows 11 with TPM and Secure Boot didn't.

Fix:

- Memory integrity off, under Windows Security > Device security > Core isolation
- In `optionalfeatures`, untick Hyper-V, Virtual Machine Platform, Windows
  Hypervisor Platform, Windows Sandbox
- `bcdedit /set hypervisorlaunchtype off`
- Reboot, then check `msinfo32` says Virtualization-based security is not enabled

This breaks WSL2 and Docker Desktop while it's off. Reverse it with
`bcdedit /set hypervisorlaunchtype auto`.

### Splunk won't run as root

Splunk 10 refuses to start as root. There's a `--run-as-root` flag but it's
deprecated, so I made a service account instead.

```bash
sudo useradd -r -m -U -s /bin/bash splunk
sudo chown -R splunk:splunk /opt/splunk
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
```

Then for boot start:

```bash
sudo /opt/splunk/bin/splunk enable boot-start -user splunk -systemd-managed 1
```

The `chown` matters. If you tried starting it as root first there will be
root-owned files left in `/opt/splunk` and it fails in ways that are hard to read.

### Sysmon logs not reaching Splunk

Security, System and PowerShell all arrived. Sysmon didn't, even though the service
was running and the channel had events in it.

`splunkd.log` on the Windows side had the answer:

```
Could not subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational' ... errorCode=5
```

errorCode 5 is access denied. The forwarder's default service account can't read the
Sysmon channel, which has a tighter ACL than the other three. That's why three of
four inputs worked.

```powershell
Stop-Service SplunkForwarder
sc.exe config SplunkForwarder obj= LocalSystem
Start-Service SplunkForwarder
```

The space after `obj=` is required.

### Atomic Red Team install failed

`Install-AtomicRedTeam` reported failure, but the real error was a few lines further
down:

```
powershell-yaml.psm1 cannot be loaded because running scripts is disabled
on this system
```

Execution policy. There's also a NuGet prompt in the output above it, which is a
distraction.

```powershell
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
Install-AtomicRedTeam -getAtomics -Force
```

I used `LocalMachine` rather than `Process` because I open a new admin PowerShell
for each test and `Process` only lasts for one session.

## Other things worth knowing

Tamper Protection has to be turned off by hand in the Windows Security UI before
`Set-MpPreference -DisableRealtimeMonitoring $true` will work. It can't be scripted,
and it fails quietly if you skip it.

Pausing Windows Update only lasts five weeks. I disabled it in Group Policy instead,
so an update run doesn't dump thousands of process events into the index in the
middle of false positive tuning.

The default Ubuntu mirror was giving me around 500 Kbps and stalled the install on
`linux-firmware`. Switching to `archive.ubuntu.com` fixed it.
