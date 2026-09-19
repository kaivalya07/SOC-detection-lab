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
## When a detection returns nothing

This happened enough times that it turned into the main thing I learned building
this.

Five times a detection looked broken and the query was fine. The telemetry just
wasn't there. Each time I went looking at my SPL first, and each time that was the
wrong place.

### 1. The audit subcategory was never enabled

Writing T1136.001 I searched for Security Event ID 4720 after creating an account.
Nothing. The account definitely existed, I'd just made it.

In setup I'd enabled Audit Process Creation, which is under Detailed Tracking.
Account management is a separate subcategory and it's off by default, so Windows was
never writing 4720 at all.

    auditpol /set /subcategory:"User Account Management" /success:enable
    auditpol /set /subcategory:"Security Group Management" /success:enable

### 2. The forwarder lost its channel subscription

Twice, after running `Sysmon64.exe -u force`, logs stopped arriving in Splunk. Sysmon
was running, the forwarder was running, and nothing errored anywhere I was looking.

Uninstalling Sysmon unregisters the event channel. When it re-registers it comes back
with fresh ACLs, and the forwarder's default service account can't read it. The
forwarder log says so, but nothing else does:

    WinEventLogChannel::subscribeToEvtChannel: Could not subscribe to Windows
    Event Log channel 'Microsoft-Windows-Sysmon/Operational' ... errorCode=5

errorCode 5 is access denied.

    sc.exe config SplunkForwarder obj= LocalSystem

I lost an hour to this the second time, chasing Defender and SPL syntax, because the
symptom is identical to a badly written query.

### 3. A config reload can't add a new rule type

I spent most of a session trying to get Sysmon to log ProcessAccess events for a LSASS
detection. The rule was in the config file. Sysmon said "Configuration file
validated" and "Configuration updated". The rule never appeared in the live config.

`-c` reloads a config but can only modify rule types that were present when Sysmon was
originally installed. It silently drops anything new. Same thing killed registry
logging later when my config got overwritten.

The fix is a full reinstall, not a reload:

    Sysmon64.exe -u force
    Sysmon64.exe -accepteula -i config.xml

One catch - `-u force` often fails to delete C:\Windows\Sysmon64.exe because the file
is still locked, and then the reinstall fails too. The machine is left with no Sysmon
at all and no obvious sign of it. Only a reboot clears the lock.

### 4. The platform blocked the attack before it could be logged

T1003.001 is dumping credentials out of LSASS memory. I configured the detection,
ran the attack, and got nothing.

Windows 11 runs LSASS as a protected process - RunAsPPL is set to 2 by default. The
kernel refuses handle opens to LSASS from anything that isn't equally protected, so
the access never happens and there's nothing for Sysmon to observe.

The detection wasn't broken. The attack was.

### 5. Defender kept turning itself back on

Real-time protection reverted between sessions, every session, and blocked atomics
mid-test. `Set-MpPreference -DisableRealtimeMonitoring $true` fails silently while
Tamper Protection is on, and Tamper Protection reverts too. It can only be turned off
in the GUI, by design.

Worth noticing that this is why real attackers disable Defender through Group Policy
or by tampering with the service rather than the cmdlet - the cmdlet doesn't hold.

### What I do now

Before touching a query that returns nothing, I check the event exists at the source:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
        Group-Object Id | Select Name, Count

If it's there and Splunk is empty, it's forwarding. If it's not there, it's Sysmon
config or audit policy. If neither, the attack didn't run.

The part that stuck with me: a SIEM shows you what it received, not what happened. An
empty result looks the same whether you wrote a bad rule or your logging silently
stopped three days ago. On a real network nobody would have noticed the forwarder
losing its subscription - the dashboards would just be quiet.
