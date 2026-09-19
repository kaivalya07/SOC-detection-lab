# T1569.002 - Service Execution

Tactic: Execution
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1569.002 Test 1

## What it detects

Creating a Windows service to run a command. Services run as SYSTEM, so this is
execution and privilege escalation at the same time.

## How I tested it

    Invoke-AtomicTest T1569.002 -TestNumbers 1

    sc.exe create ARTService binPath= "cmd.exe /c powershell.exe -nop -w hidden -command ..."

The tell is in binPath. A real service points at an executable. This one points at
cmd.exe running a hidden PowerShell command, which no legitimate service does.

## Tuning

2 hits, both mine, no false positives.

I also cover New-Service and psexec, since sc.exe isn't the only way to do this and
someone avoiding sc.exe would use one of those.

## Related

The same attack shows up in two other detections I wrote - T1059.003 catches the
cmd.exe that the service launches, and T1543.003 catches the registry write where the
service is defined. Three different views of one action.
