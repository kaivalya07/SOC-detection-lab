# T1070.001 - Clear Windows Event Logs

Tactic: Defense Evasion
Data source: Sysmon Event ID 1, plus Windows System log Event ID 104
Tested with: ran the technique manually

## What it detects

Someone wiping Windows event logs. This is usually the last thing an attacker does,
after they've already done the damage, to make the investigation harder.

There's almost no normal reason to clear an event log, so this is a high confidence
detection. If it fires, something is wrong.

## How I tested it

Atomic Red Team doesn't have T1070.001 in the library. You get T1070, .003, .004,
.005, .006 and .008 but not .001 - the Windows log clearing tests got folded into the
parent technique.

So I ran it myself:

    wevtutil cl Application

wevtutil is the built in Windows tool for event logs and cl is its clear command.

## Detecting it two ways

The Sysmon query catches the command being run. But I also check System Event ID 104:

    index=main sourcetype="WinEventLog:System" EventCode=104
    | table _time, Computer, user

Windows writes 104 when a log gets cleared. The log basically records its own
destruction as the last thing in it. 1102 is the same thing for the Security log.

Both fired 14 milliseconds apart, 05:55:55.069 and 05:55:55.083.

I kept both because they fail differently. If an attacker clears logs some other way
that my Sysmon query doesn't cover, 104 still catches it.

## Tuning

I ran three normal wevtutil commands to see if they'd trip it:

    wevtutil qe Application /c:2     (read events)
    wevtutil el                      (list logs)
    wevtutil gl Application          (get log config)

None of them matched. 4 wevtutil runs total, rule caught 1, which was the clear.
No false positives.

The cl condition is what makes this work. Without it the rule would fire on anyone
reading a log, which happens all the time.

## Notes

Splunk is showing UTC and Windows shows IST, so my 11:25 local is 05:55 in Splunk.
I left it on UTC since that's normal for a SIEM with endpoints in different places.
