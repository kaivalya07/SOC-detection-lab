# T1136.001 - Create Local Account

Tactic: Persistence
Data source: Sysmon Event ID 1, plus Security Event ID 4720 and 4732
Tested with: ran it manually

## What it detects

An attacker making their own user account on the machine. It survives reboots, and it
survives you resetting the password on whatever account they originally got in with.
If they add it to Administrators they own the box.

This is the persistence that outlives the incident response, because nobody notices
one extra account in a user list.

## How I tested it

T1136.001 has no Windows tests in the atomics library - it returned "Found 0 atomic
tests applicable to windows platform". So I ran it myself:

    net user svc_backup Passw0rd123! /add
    net localgroup administrators svc_backup /add

I named it svc_backup on purpose. Attackers pick names that look like service
accounts so they don't stand out in a user list.

## Two things I found

### net.exe hands off to net1.exe

When you run net user, Windows spawns net1.exe internally and that's what actually
does the work. I saw both in Sysmon 16ms apart - powershell.exe launched net.exe,
net.exe launched net1.exe.

I check both. A rule that only watches net.exe can miss this depending on Windows
version.

### The word "user" matched things it shouldn't

My first version got 4 hits. Two were mine. The other two were from 12 Sept:

    net localgroup "Performance Monitor Users" "NT SERVICE\SplunkForwarder" /add

That's the Splunk forwarder installer adding its service account to a group. It
matched because I had CommandLine="*user*" and the word Users appears inside
"Performance Monitor Users".

Nothing to do with net user at all. The wildcard just found the letters.

Fixed it two ways:

- "user " with a space after it, so it matches the net user subcommand and not any
  word containing user
- Excluded anything with localgroup in it, since that's a different command

4 hits down to 2, which are the net.exe and net1.exe pair from my own test.

## The audit policy gap

The Security log query returned 0 results at first. The account definitely existed -
I'd just made it.

The reason: in Phase 3 I enabled Audit Process Creation, which is under Detailed
Tracking. Account management is a different subcategory and it's off by default. So
Windows was never writing 4720 events in the first place.

    auditpol /set /subcategory:"User Account Management" /success:enable
    auditpol /set /subcategory:"Security Group Management" /success:enable

After that, made another test account and got:

    06:43:24.354  4720  account created
    06:43:24.390  4732  added to group
    06:43:26.539  4732  added to group

Create then escalate, 36ms apart. That sequence is the thing to alert on - a new
account on its own is worth a look, a new account added to Administrators seconds
later is an incident.

Worth remembering that a detection returning nothing doesn't mean the attack didn't
happen. Sometimes the logging just isn't turned on.

## What's weak about this

Helpdesk staff create accounts as part of their job so this would be noisier in a real
environment. I'd want to know which accounts are created outside normal provisioning -
made by a user rather than a service account, or made outside working hours.
