# T1053.005 - Scheduled Task

Tactic: Persistence
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1053.005 Test 1

## What it detects

Someone creating a Windows scheduled task. Attackers use these so their malware
starts again after a reboot, same goal as a Run key but a different mechanism.

I'm looking for task creation specifically, not task usage. Listing tasks is normal.
Creating one that runs a program at every logon is not.

## How I tested it

    Invoke-AtomicTest T1053.005 -TestNumbers 1

It made two tasks 21ms apart:

    schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
    schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"

The second one is the more dangerous of the two. /ru system means it runs as SYSTEM.
If an attacker is running as a normal user and can create a task like that, they've
escalated privileges.

I only know that because command line logging is on. Without it I'd see schtasks.exe
ran and nothing about what it did.

## Covering both methods

You can make a scheduled task with schtasks.exe or with PowerShell. I check both:

- schtasks.exe with /create
- Register-ScheduledTask
- New-ScheduledTask

If someone knows schtasks is being watched they'll use the PowerShell version, so
covering only one would be an easy bypass.

## Tuning

2 hits over all time, both from my test.

I ran some normal task commands to check it wasn't too broad:

    schtasks /query /fo LIST /v
    Get-ScheduledTask

Neither matched. The /create condition is what does the work - reading tasks is
common, creating them is not.

## What's weak about this

Software installers and IT admins create scheduled tasks legitimately, so a real
environment would have more noise than my lab. I wouldn't want to exclude by task
name since attackers pick innocent looking names. Better angle would be alerting on
tasks that run as SYSTEM or point at things in temp folders.
