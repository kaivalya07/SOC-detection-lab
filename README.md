# SOC Detection Lab

Detection rules I wrote and tested in a home lab. Splunk for the SIEM, Sysmon for
endpoint telemetry, Atomic Red Team to run the attacks.

Every rule here was tested the same way: run the attack, find it in Splunk, write a
query, then check what else that query catches and narrow it. The before and after
numbers are in each writeup.

![coverage](coverage/coverage.svg)

## Setup

    [ Windows 11 VM ]                 [ Ubuntu VM ]
      Sysmon               ------>      Splunk
      Atomic Red Team       :9997       indexes + search
      Universal Forwarder

Build notes and the problems I hit are in setup/01-lab-setup.md

## Detections

| ID | Technique | Tactic | Data source | Result |
|---|---|---|---|---|
| T1059.001 | PowerShell | Execution | Sysmon 1 | 4 hits > 2, 3 FPs removed |
| T1070.001 | Clear Event Logs | Defense Evasion | Sysmon 1, System 104 | 1 hit, no FPs |
| T1547.001 | Registry Run Keys | Persistence | Sysmon 13 | 7 hits > 1, 6 FPs removed |
| T1053.005 | Scheduled Task | Persistence | Sysmon 1 | 2 hits, no FPs |
| T1136.001 | Create Local Account | Persistence | Sysmon 1, Security 4720/4732 | 4 hits > 2, 2 FPs removed |
| T1082 | System Info Discovery | Discovery | Sysmon 1 | 21 hits, see below |
| T1033 | User Discovery | Discovery | Sysmon 1 | 19 hits, see below |
| T1016 | Network Discovery | Discovery | Sysmon 1 | 5 hits, see below |
| - | Discovery Burst | Discovery | Sysmon 1 | 60 events > 2 alerts |

Still working through the rest, target is 20.

## Start here

**detections/discovery-burst/** is the one I'd read first.

I wrote three separate discovery rules and they got 21, 19 and 5 hits in a lab that
barely gets used. All three were unusable, because whoami run by an attacker and
whoami run by an admin produce identical events. Nothing in the log tells them apart.

So I stopped detecting the commands and detected the pattern instead - four or more
different discovery commands from the same parent process inside five minutes. That
collapsed 60 events into 2 alerts, and both were real reconnaissance bursts.

**detections/T1547.001-registry-run-keys/** has the most careful tuning. 7 down to 1,
and the false positives were Microsoft Edge and rundll32.exe. I didn't exclude them by
process name, because malware gets named msedge.exe all the time - the exclusions
match on full path plus the specific registry value plus the account it ran as.

**detections/T1136.001-create-local-account/** is where a rule returned nothing and I
assumed it was broken. It wasn't. The account management audit subcategory was never
enabled, so Windows wasn't generating the events at all. A detection returning zero
doesn't mean the attack didn't happen.

## Notes

Splunk is on UTC and the Windows VM is on IST, so timestamps differ by 5:30.
