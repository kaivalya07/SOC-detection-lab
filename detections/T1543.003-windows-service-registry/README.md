# T1543.003 - Create or Modify System Process: Windows Service

Tactic: Persistence
Data source: Sysmon Event ID 13 (registry value set)
Tested with: Atomic Red Team T1569.002 Test 1

## What it detects

A service being created or modified where the ImagePath points at a command rather
than a program. Windows services live in the registry, so creating one always leaves
a registry write behind.

A normal service ImagePath looks like C:\Program Files\Something\service.exe. A
malicious one looks like cmd.exe /c powershell -w hidden.

## Why registry and not just the command line

I already detect sc.exe create in T1569.002. This catches the same thing one layer
down. If an attacker creates a service through the Windows API instead of running
sc.exe, there's no sc.exe process to see - but the registry write still happens,
because that's where services are stored.

Two detections, two data sources, one technique. If one is evaded the other still
fires.

## How I found it

I was originally writing T1112 Modify Registry and testing DisableTaskMgr. Those
never logged, because the SwiftOnSecurity Sysmon config doesn't watch that registry
path.

While checking what registry events WERE being captured, I found these ImagePath
writes from my service test. That turned out to be a better detection than the one I
was trying to write, so I wrote this instead.

## Tuning

2 hits over all time, both from my test, no false positives.

    HKLM\System\CurrentControlSet\Services\ARTService\ImagePath
    = C:\WINDOWS\system32\cmd.exe /c powershell.exe -nop -w hidden -command ...

Software installers create services legitimately, so on a real machine this would
need watching. But the Details conditions mean it only fires when the ImagePath
contains cmd.exe, powershell, hidden window flags or a temp path - none of which a
normal service uses.
