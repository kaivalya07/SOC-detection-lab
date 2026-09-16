# T1033 - System Owner/User Discovery

Tactic: Discovery
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1033 Test 1

## What it detects

whoami and net user - an attacker checking which account they're running as and who
else exists on the box.

## Tuning

19 hits over all time. Same problem as T1082.

Some of them were my own cleanup commands from the T1136.001 work
(net user svc_test /delete). Some were whoami from the atomic. Some were whoami I
ran myself as benign activity.

I added NOT CommandLine="*/add*" so it doesn't overlap with the account creation rule,
since that's a different technique and I detect it separately.

Beyond that there's nothing to narrow. whoami takes no meaningful arguments. There is
nothing in the event to distinguish an attacker running it from an admin running it.

## Why I kept it

Same reason as T1082 - it feeds the discovery burst rule. On its own the false
positive rate makes it unusable.
