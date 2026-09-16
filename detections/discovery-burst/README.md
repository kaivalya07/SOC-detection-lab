# Discovery Burst - correlated detection

Tactic: Discovery
Data source: Sysmon Event ID 1
Covers: T1082, T1033, T1016 and related discovery techniques

## The problem this solves

I wrote three separate discovery rules first - T1082, T1033, T1016. They got 21, 19
and 5 hits in a lab that barely gets used. Every one of them would be unusable as a
real alert.

The reason is that discovery commands are identical whoever runs them. whoami is
whoami. systeminfo is systeminfo. There's no field in the event that says whether the
person typing it is an admin or an intruder.

So I stopped trying to detect the commands and detected the behaviour instead.

## The idea

An attacker who just landed on a machine doesn't run one command. They run several,
quickly, from the same process, because they're working out where they are - what the
machine is, who they are on it, what network it's on, what's running.

A normal person runs one command because they wanted to know one thing.

So: count how many DIFFERENT discovery commands come from the same parent process
inside a 5 minute window, and alert when it's 4 or more.

## The query

    | bin _time span=5m
    | stats dc(Image) as unique_commands, values(Image) as commands by _time, ParentImage
    | where unique_commands >= 4

bin buckets events into 5 minute windows. dc(Image) counts distinct commands, not
total events - so someone running ipconfig 50 times still only counts as 1.

## Results

60 raw events collapsed into 2 alerts.

    06:55  cmd.exe         7 commands  ARP, ipconfig, nbtstat, net, netsh, systeminfo, whoami
    05:30  powershell.exe  5 commands  ipconfig, net, systeminfo, tasklist, whoami

Both are real bursts. The 06:55 one is the atomics. The 05:30 one is me running
benign discovery commands in a batch - which is honestly a correct alert, because
running five discovery commands back to back is the pattern, whoever's doing it. On a
real machine that would be an admin running a script, and it's worth a look.

The repeated hostname.exe from my PowerShell profile disappeared completely. It's one
command, not four, so it never reaches the threshold.

## One thing I had to fix

My first version grouped by ParentImage AND User, and I got each result twice - once
with the username resolved and once as NOT_TRANSLATED. Splunk couldn't resolve the SID
on some events and was treating the two forms as separate groups. Dropped User from
the grouping and the duplicates went.

## Threshold

I used 4. Three felt too low - an admin checking a machine might legitimately run
whoami, ipconfig and hostname together. Seven of the twelve commands in one window is
clearly automated.

On a busier machine I'd want to check what the normal distribution looks like before
settling on a number.
