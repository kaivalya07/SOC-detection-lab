# T1027 - Obfuscated Files or Information

Tactic: Defense Evasion
Data source: Sysmon Event ID 1
Tested with: ran it manually

## What it detects

PowerShell being run with a base64 encoded command. Attackers encode their commands so
that anything reading the command line sees a wall of base64 instead of what the script
actually does.

## How I tested it

No Windows tests for T1027 in the atomics library, so:

    powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==

That decodes to Write-Host "test". Harmless, but it looks identical to a real encoded
payload from the logs.

## Tuning

1 hit, mine, no false positives.

Legitimate software does occasionally use -EncodedCommand, usually installers passing
scripts with awkward quoting. Nothing on this machine did.

## Overlap with T1059.001

My PowerShell detection already looks for -enc and -EncodedCommand. This one is
narrower and catches the encoding regardless of which binary is doing it, including
FromBase64String in a command line.

Keeping both is deliberate. T1059.001 is about PowerShell being abused. This one is
about obfuscation as a behaviour, and the same base64 pattern shows up in cmd.exe and
in scheduled task arguments too.

## What's weak about this

I'm only catching encoding on the command line. Real obfuscation is usually inside the
script - string concatenation, character substitution, compressed payloads. Catching
that needs PowerShell script block logging (Event 4104), which I enabled in setup but
haven't built a detection on yet. That's the obvious next thing to add.
