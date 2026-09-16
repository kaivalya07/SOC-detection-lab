# T1082 - System Information Discovery

Tactic: Discovery
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1082 Test 1

## What it detects

Commands that tell you about the machine - systeminfo, hostname, wmic os get.
An attacker who just got onto a box runs these to find out where they are.

## Tuning

21 hits over all time and I could not tune it down.

Most of them were HOSTNAME.EXE launched by powershell.exe. That's my own PowerShell
profile - I added an Import-Module line to it earlier so I didn't have to load Atomic
Red Team manually every time, and it runs hostname on every new window.

But even if I excluded that, the problem doesn't go away. systeminfo run by me and
systeminfo run by an attacker produce exactly the same event. Same image, same command
line, same parent in some cases. There's no field that tells them apart.

## Why I kept it anyway

This rule on its own would be useless as an alert. 21 hits in a lab with almost no
activity means hundreds a day on a real machine, and an analyst would mute it in a
week.

I kept it as a building block. It's part of the discovery burst rule, which is the
one that actually works. See detections/discovery-burst/.

Writing this one taught me that some techniques aren't detectable by themselves. The
signal is in the combination, not the command.
