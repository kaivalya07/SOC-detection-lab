## When a detection returns nothing

This happened enough times that it turned into the main thing I learned building
this.

Five times a detection looked broken and the query was fine. The telemetry just
wasn't there. Each time I went looking at my SPL first, and each time that was the
wrong place.

### 1. The audit subcategory was never enabled

Writing T1136.001 I searched for Security Event ID 4720 after creating an account.
Nothing. The account definitely existed, I'd just made it.

In setup I'd enabled Audit Process Creation, which is under Detailed Tracking.
Account management is a separate subcategory and it's off by default, so Windows was
never writing 4720 at all.

    auditpol /set /subcategory:"User Account Management" /success:enable
    auditpol /set /subcategory:"Security Group Management" /success:enable

### 2. The forwarder lost its channel subscription

Twice, after running `Sysmon64.exe -u force`, logs stopped arriving in Splunk. Sysmon
was running, the forwarder was running, and nothing errored anywhere I was looking.

Uninstalling Sysmon unregisters the event channel. When it re-registers it comes back
with fresh ACLs, and the forwarder's default service account can't read it. The
forwarder log says so, but nothing else does:

    WinEventLogChannel::subscribeToEvtChannel: Could not subscribe to Windows
    Event Log channel 'Microsoft-Windows-Sysmon/Operational' ... errorCode=5

errorCode 5 is access denied.

    sc.exe config SplunkForwarder obj= LocalSystem

I lost an hour to this the second time, chasing Defender and SPL syntax, because the
symptom is identical to a badly written query.

### 3. A config reload can't add a new rule type

I spent most of a session trying to get Sysmon to log ProcessAccess events for a LSASS
detection. The rule was in the config file. Sysmon said "Configuration file
validated" and "Configuration updated". The rule never appeared in the live config.

`-c` reloads a config but can only modify rule types that were present when Sysmon was
originally installed. It silently drops anything new. Same thing killed registry
logging later when my config got overwritten.

The fix is a full reinstall, not a reload:

    Sysmon64.exe -u force
    Sysmon64.exe -accepteula -i config.xml

One catch - `-u force` often fails to delete C:\Windows\Sysmon64.exe because the file
is still locked, and then the reinstall fails too. The machine is left with no Sysmon
at all and no obvious sign of it. Only a reboot clears the lock.

### 4. The platform blocked the attack before it could be logged

T1003.001 is dumping credentials out of LSASS memory. I configured the detection,
ran the attack, and got nothing.

Windows 11 runs LSASS as a protected process - RunAsPPL is set to 2 by default. The
kernel refuses handle opens to LSASS from anything that isn't equally protected, so
the access never happens and there's nothing for Sysmon to observe.

The detection wasn't broken. The attack was.

### 5. Defender kept turning itself back on

Real-time protection reverted between sessions, every session, and blocked atomics
mid-test. `Set-MpPreference -DisableRealtimeMonitoring $true` fails silently while
Tamper Protection is on, and Tamper Protection reverts too. It can only be turned off
in the GUI, by design.

Worth noticing that this is why real attackers disable Defender through Group Policy
or by tampering with the service rather than the cmdlet - the cmdlet doesn't hold.

### What I do now

Before touching a query that returns nothing, I check the event exists at the source:

    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
        Group-Object Id | Select Name, Count

If it's there and Splunk is empty, it's forwarding. If it's not there, it's Sysmon
config or audit policy. If neither, the attack didn't run.

The part that stuck with me: a SIEM shows you what it received, not what happened. An
empty result looks the same whether you wrote a bad rule or your logging silently
stopped three days ago. On a real network nobody would have noticed the forwarder
losing its subscription - the dashboards would just be quiet.
