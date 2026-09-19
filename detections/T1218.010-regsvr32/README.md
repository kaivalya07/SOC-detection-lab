# T1218.010 - Regsvr32

Tactic: Defense Evasion
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1218.010 Test 1

## What it detects

regsvr32.exe being used to run a scriptlet instead of registering a DLL. This is the
Squiblydoo technique - regsvr32 is a signed Microsoft binary, so running code through
it gets past application allowlisting that would block an unknown exe.

## How I tested it

    Invoke-AtomicTest T1218.010 -TestNumbers 1

    regsvr32.exe /s /u /i:"...\RegSvr32.sct" scrobj.dll

/i: passes a scriptlet and scrobj.dll is the script runtime. That combination is the
whole technique.

## Tuning

2 hits over all time, both mine, no false positives.

Nothing needed tuning. regsvr32 with scrobj.dll and /i: has no legitimate use I could
find on this machine. It's a narrow, high confidence detection.
