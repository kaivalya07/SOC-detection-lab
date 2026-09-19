# T1197 - BITS Jobs

Tactic: Defense Evasion
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1197 Test 1

## What it detects

bitsadmin being used to download a file. BITS is the Background Intelligent Transfer
Service - it's what Windows Update uses, so the traffic looks completely normal and
it keeps going after the user logs off.

Attackers like it because the download happens under a trusted Windows service rather
than their own process.

## How I tested it

    Invoke-AtomicTest T1197 -TestNumbers 1

    bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/.../T1197.md C:\Users\...\AppData\Local\Temp\bitsadmin1_flag.ps1

Note where it lands - a .ps1 in the user's temp folder. That's the shape to look for:
BITS pulling a script into a temp directory.

## Tuning

1 hit, mine, no false positives.

bitsadmin.exe is deprecated and barely used by anything modern, so any use of it is
worth a look. Windows Update uses the BITS service directly, not this command line
tool.

I also cover Start-BitsTransfer, the PowerShell equivalent, since someone avoiding
bitsadmin.exe would use that.
