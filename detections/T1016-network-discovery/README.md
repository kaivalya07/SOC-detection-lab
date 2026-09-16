# T1016 - System Network Configuration Discovery

Tactic: Discovery
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1016 Test 1

## What it detects

ipconfig, arp, route, nbtstat, netsh - an attacker mapping the network from the
machine they landed on, looking for what else they can reach.

## Tuning

5 hits, which is fewer than the other two discovery rules only because I'd run these
commands less often myself.

4 of the 5 were the atomic: ipconfig /all, netsh interface show, arp -a, nbtstat -n,
all from cmd.exe inside 240 milliseconds. The fifth was ipconfig /all that I ran
earlier as benign activity.

Same issue again. ipconfig /all is ipconfig /all whoever runs it.

## What's interesting here

Looking at the timestamps was what led me to the burst detection. Four different
network commands from the same cmd.exe inside a quarter of a second isn't someone
checking their IP address. Nobody types that fast. It's a script.

That timing pattern is the actual signal, not the commands.
