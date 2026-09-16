# T1059.001 - PowerShell

Tactic: Execution
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1059.001 Test 1

## What it detects

PowerShell loading a script from a weird location, or pulling code off the internet
and running it.

I didn't want to alert on powershell.exe by itself. It runs constantly on Windows so
that would just be noise.

## How I tested it

Ran Invoke-AtomicTest T1059.001 -TestNumbers 1. That downloads Invoke-Mimikatz.ps1
and imports it. Then I noted the time and went looking for it in Splunk.

## Tuning

My baseline was 14 PowerShell runs over 4 days, out of 2761 Sysmon events.

First version of the query got 4 hits. Only 1 of them was my test. The other 3 were
normal things:

- Import-Module PSReadLine
- Import-Module Microsoft.PowerShell.Archive
- Invoke-Expression 'Get-Date'

3 false positives out of 4 hits. In a real SOC nobody would keep an alert like that
switched on.

What I changed:

- Took out Import-Module on its own. Scripts import modules all the time, so on its
  own it doesn't tell you anything.
- Made IEX and Invoke-Expression only count if "http" is in the command too. Running
  Invoke-Expression 'Get-Date' is harmless. Downloading something and running it isn't.
- Added .ps1 so it picks up script files being loaded, which is what the atomic
  actually did.

After that: 2 hits, both from my test. One for loading the module and one for the
cleanup deleting the file. No false positives.

So 4 hits down to 2, and the 3 legitimate ones are gone.

## What I know is weak about this

My lab is quiet. On a real machine with admins running scripts all day, the .ps1
condition would catch a lot more and I'd have to narrow it further - probably by
excluding signed scripts or known script folders.
