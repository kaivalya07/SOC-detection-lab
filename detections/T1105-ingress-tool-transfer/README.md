# T1105 - Ingress Tool Transfer

Tactic: Command and Control
Data source: Sysmon Event ID 1
Tested with: ran it manually

## What it detects

An attacker pulling a file onto the machine after they've already got in. Usually
their next stage, or a tool they need that isn't already there.

## How I tested it

No Windows tests for T1105 in the atomics library, so I ran it myself:

    certutil.exe -urlcache -split -f https://raw.githubusercontent.com/.../LICENSE.txt C:\Windows\Temp\test1105.txt

certutil is meant for certificate management. -urlcache turns it into a file
downloader. It's signed by Microsoft and already on every Windows machine, which is
exactly why attackers use it instead of bringing their own tool.

## Tuning

1 hit, mine, no false positives.

I expected noise here. Invoke-WebRequest is how I downloaded the Sysmon config
earlier in this project, so I thought my own admin activity would show up. It didn't,
because that ran before Sysmon was reinstalled with the clean config.

Being honest about that: on a machine where admins actually work, Invoke-WebRequest
and curl would fire this constantly. The certutil conditions are the reliable part -
nobody uses certutil to download files for a legitimate reason.

## What I'd change on a real system

Drop Invoke-WebRequest and DownloadFile from the rule, or scope them to unusual
parent processes. Keep certutil and curl with http. The signal is in the tool being
misused, not in downloads generally.
