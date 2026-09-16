# T1547.001 - Registry Run Keys

Tactic: Persistence
Data source: Sysmon Event ID 13 (registry value set)
Tested with: Atomic Red Team T1547.001 Test 1

## What it detects

Something adding itself to the Windows Run or RunOnce keys, which is the list of
programs Windows starts automatically at login. Attackers use this so their malware
survives a reboot.

This one uses Event ID 13 instead of Event ID 1. Not process creation - it's a
registry value being written. Different telemetry for a different kind of behaviour.

## How I tested it

    Invoke-AtomicTest T1547.001 -TestNumbers 1

It wrote C:\Path\AtomicRedTeam.exe into the user's Run key. The Details field in
Sysmon shows the actual value written, which is the thing that would launch at login.

## Tuning

7 hits over all time. 1 was my test, 6 were legitimate, from two different sources.

**Microsoft Edge** - 3 hits. msedge.exe writing MicrosoftEdgeAutoLaunch. Edge setting
itself to start at login, does it repeatedly.

**rundll32.exe** - 3 hits. Writing HKLM\...\RunOnce\GrpConv as SYSTEM on 12 Sept,
which was when I was installing Windows updates. GrpConv is the Program Group
Converter, a built in Windows thing.

I was careful with the rundll32 one because rundll32 is itself a technique attackers
abuse (T1218.011) and I've got it on my list to detect separately. I only excluded it
after checking what the value name actually was and when it ran.

### How I wrote the exclusions

I did not exclude by process name. Malware gets named msedge.exe all the time, and if
I excluded anything called msedge.exe then dropping a file with that name would be
enough to bypass the rule.

Instead both exclusions need several things true at once:

- Edge: the full install path AND the MicrosoftEdgeAutoLaunch value name
- rundll32: the full system32 path AND the exact GrpConv value AND running as SYSTEM

To get past these an attacker would have to write to a protected directory and use
the exact same value name. Any other rundll32 registry write still alerts.

7 hits down to 1. No false positives left.

## What's weak about this

Software installers write Run keys legitimately, so on a real machine where people
install things this would be noisier than my lab. I'd probably end up checking whether
the writing process is signed, rather than adding an exclusion for every application.
