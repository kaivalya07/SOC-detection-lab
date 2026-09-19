# T1003.002 - Security Account Manager (SAM)

Tactic: Credential Access
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1003.002 Test 1, plus manual reg save

## What it detects

An attacker copying the registry hives that hold Windows password hashes - SAM,
SYSTEM and SECURITY - so they can crack them offline on their own machine.

This is the credential theft technique that works when reading LSASS memory doesn't.
See the note at the bottom about why I ended up here instead of T1003.001.

## How I tested it

    Invoke-AtomicTest T1003.002 -TestNumbers 1

and also ran it by hand:

    reg save hklm\sam C:\Windows\Temp\sam.hive
    reg save hklm\system C:\Windows\Temp\system.hive
    reg save hklm\security C:\Windows\Temp\security.hive

Both produced hives full of real password hashes for the VM, which I deleted straight
after.

## Catching the chained version

The atomic ran it two ways. Three separate reg save commands, and one chained line:

    cmd.exe /c reg save HKLM\sam %temp%\sam & reg save HKLM\system %temp%\system & reg save HKLM\security %temp%\security

That's how a real attacker does it - one command, not three. So I deliberately did
NOT filter on Image=reg.exe. If I had, I'd have caught the three child reg.exe
processes but missed the cmd.exe parent that launched them. The query matches on the
command line content instead, so it catches both shapes.

## Tuning

7 hits over all time, all of them mine, no false positives.

Zero false positives sounds too clean, so I checked it wasn't just a lucky baseline.
I ran a legitimate reg save of a normal key:

    reg save HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion C:\Windows\Temp\test.hive

The rule did not fire, because it requires SAM, SYSTEM or SECURITY specifically. That
confirms it targets credential theft and not reg save in general.

The reason this is high confidence: backing up the registry is normal, but saving the
SAM, SYSTEM or SECURITY hives specifically - usually to a temp folder - has almost no
legitimate reason. Very different from the discovery commands, where the same command
is used by everyone.

## Note - why not T1003.001 (LSASS)

I started on T1003.001, dumping LSASS memory, which is the more famous technique. It
didn't work, and the reason was worth learning.

Windows 11 runs LSASS as a protected process (RunAsPPL=2 in the registry). The kernel
blocks handle opens to LSASS from anything not equally protected, so the memory access
Mimikatz needs is stopped before it even happens - and before Sysmon can log it.

So on a default Windows 11 machine the LSASS route is blocked by the platform, and
attackers fall back to exactly this - grabbing the hashes from the registry instead.
Which is why this is the credential access technique I detect.
