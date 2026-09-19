# T1059.003 - Windows Command Shell

Tactic: Execution
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1059.003, plus attacks from my other tests

## What it detects

cmd.exe being used to run something suspicious - a hidden PowerShell command, a
binary out of a temp folder, or a service being created.

Not cmd.exe on its own. That runs constantly and means nothing.

## Tuning

This started at 154 hits over all time, which tells you how useless cmd.exe is as a
signal by itself.

First narrowing - requiring hidden window flags, -nop, -enc, a temp path, or sc.exe
create - got it to 19.

Of those 19:

- 5 were mine (4 from the service creation test, 1 from the SAM registry dump)
- 14 were the Splunk Universal Forwarder installer from 12 Sept

The 14 were all one msiexec.exe spawning cmd.exe fourteen times in the same second -
icacls calls, service installation, rundll32 setupapi. All legitimate, all matching
because MSI installers extract to a temp folder and my rule looks for temp paths.

Excluded msiexec.exe as a parent, by full path rather than by name, so a file called
msiexec.exe somewhere else doesn't get a free pass.

154 to 19 to 5. 149 false positives removed.

## What I learned writing this

The temp path condition is doing most of the work and also causing most of the noise.
Installers live in temp. On a real machine with people installing software this rule
would need more than one exclusion.

The stronger signals are the PowerShell flags - -w hidden and -nop. Nobody types those
by accident. If I had to pick one condition to keep, it'd be those, not the path.

## Related

Row 1 in my results is services.exe launching cmd.exe, which is the ARTService from
T1569.002 actually executing. Same attack, third angle - I catch the sc.exe that
creates it, the registry write that defines it, and the cmd.exe it eventually runs.
