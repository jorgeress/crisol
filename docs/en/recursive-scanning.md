# Opening the container: recursive scanning

*[Versión en español](../escaneo-recursivo.md)*

_September 7, 2026 · 69 malware samples · 58 goodware_

> **Update (September 23):** the .NET goodware this document asked for now
> exists, and it confirmed the suspicion: the +6 were false positives from
> `high_entropy_section`. See [round 3](round-3-dotnet.md).

`overlay_bulk_inflation` deliberately gives up on installers: a malicious
NSIS and a legitimate one have the same shape, and telling them apart means
looking inside. This is looking inside. **And the main result isn't the
detection it adds, but why I can't sign off on it.**

## What was built

`src/crisol/carve.py` extracts payloads from a sample and
`RuleSet.scan_recursive()` scans them:

- **Uncompressed embedded PEs**, carved by reading the section table by hand
  (not with pefile: on an arbitrary offset of a hostile file that's a lot of
  attack surface when all you want is a size).
- **ZIP members**, which covers self-extracting archives with that shape.

With caps on everything (64 payloads, 64 MB each) because every offset that
gets in there was chosen by the file under analysis, not by me.

Available in `bench/harness.py --recursive` and `crisol scan --recursive`.

## The two numbers are kept apart

*"This file fires a rule"* and *"this file contains something that fires
it"* are different claims. Adding them up inflates detection without saying
so, so the harness counts them separately and the CLI doesn't let an embedded
payload change the sample's verdict.

| Metric | Value |
|---|---|
| Direct detection | 20/69 = **28.99%** |
| Only when opened | +6 → 26/69 = **37.68%** |
| Direct FPs (58 goodware) | 0.0% |
| FPs only from what's inside | **0/58** |

## Why I don't trust that +6

The six new detections are **all ConnectWise**, and they all come from the
same rule: `high_entropy_section` firing on a 3 MB .NET assembly embedded in
the installer.

ConnectWise ScreenConnect is **legitimate remote access software**, abused by
actors who deploy it configured against their own server. The corpus samples
contain DigiCert code signing URLs: they are genuinely signed installers.
What's malicious is the **configuration** (in one of them, the IOC
`192.162.199.231`), not the binary's structure.

In other words: a legitimate ScreenConnect installer would fire exactly the
same way.

### The mechanism, which is the part that generalizes

In a .NET assembly, embedded managed resources live **inside `.text`**, which
is marked executable. `high_entropy_section` requires exactly that: an
executable section with entropy ≥7.4. Conclusion: **any .NET assembly with
large compressed resources fires that rule**, and that describes half the
industry: WPF apps, installers, ClickOnce.

On the top-level file you almost never see it, because a standalone .NET
assembly rarely carries 3 MB of resources. When scanning recursively, though,
every installer gets opened and everything inside it gets looked at, which is
exactly where those assemblies live. **Recursive scanning doesn't add
detection power: it multiplies the reach of the rules you already have, blind
spots included.**

### And I can't falsify it

Measuring it would take .NET goodware. This machine has **zero** .NET
assemblies (searched `/usr/lib/wine`, `/opt`, `/usr/lib/mono`,
`/usr/share/dotnet`) and no `dotnet` toolchain to build them with. It's the
same wall that blocked
[round 2's hypothesis 3](round-2-rules.md#hypothesis-3-blocked-no-net-goodware-to-falsify-it),
and now it blocks two things instead of one.

That's why 37.68% doesn't go into the README as a detection rate, and why
`--recursive` is optional and off by default.

## What is measured

The goodware had a silent problem: **not a single file with embedded PEs**.
Scanning recursively against it would have given 0% FP without checking
anything, which is the trap this whole project is about.

`make_goodware_go.sh` now builds a second control,
`control-bundle-pe-amd64.exe`: a legitimate stub with the Go binaries inside,
in an **uncompressed** ZIP so they can be carved. The engine extracts all four
and fires on none of them. That 0 does mean something.

## A limitation that is also a defense

Carving only finds **uncompressed** payloads. An installer that deflates its
contents is invisible here, and that cuts what gets detected, but it cuts
exactly as much what can be flagged by mistake: what comes out of the carver
are executables as they are, not decompressed blobs that could look like
anything.

The two Inno Setup ValleyRAT samples that round 2 let through **still get
through**: their payload is compressed. Those need `innoextract` or
equivalent, and that's an external dependency, not a rule.

## A gate that couldn't fail

`--max-fp-rate` only looked at the rate of direct matches. In recursive mode,
a goodware file that lights up **only** because of what it carries didn't
raise that rate: the threshold passed without checking anything. Fixed with
`false_positive_rate_recursive`, which is what the gate checks when
`--recursive` is on, plus a regression test (`tests/test_harness_gate.py`)
that builds the case (clean container, dirty payload) and checks that the
gate fails. A gate that can't fail isn't a gate.

## Next steps

1. **.NET goodware.** It blocks hypothesis 3 and it blocks validating this
   +6. It's by far the most valuable next step.
2. **Revisit `high_entropy_section`** in light of this: it should probably
   exclude .NET assemblies, or require that the high-entropy section isn't the
   `.text` of a managed binary. Not to be touched without a corpus to measure
   it against.
3. **Installer decompression** (Inno, NSIS) to reach compressed payloads,
   accepting the external dependency.
