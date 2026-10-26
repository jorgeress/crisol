# Round three: .NET goodware, and a rule that didn't detect what it seemed to

*[Versión en español](../ronda-3-dotnet.md)*

_September 23, 2026 · 69 malware samples · 64 goodware_

The two previous rounds recorded the same blocker twice: there wasn't a
single .NET binary in the goodware corpus. That made it impossible to attempt
[hypothesis 3](round-2-rules.md) (a rule for .NET droppers) and to validate
the [+6 detections from recursive scanning](recursive-scanning.md), which came
from `high_entropy_section` firing on embedded .NET assemblies.

This round builds that goodware. **Detection drops from 28.99% to 17.39%**,
and that's the correct result: eight of the hits the bench considered good
weren't detecting malware, they were detecting a trait that any .NET app with
images has.

## Result

| Metric | Before | After |
|---|:---:|:---:|
| False positives (64 goodware, 6 of them .NET) | 3.12% (2) | **0.0%** |
| Direct detection (69 samples) | 28.99% (20) | **17.39%** (12) |
| Extra detections from opening containers | +6 | **+0** |

The "before" column is the old rule measured against the new corpus. Against
the old corpus it scored 0% FP, and that 0% was exactly the one that couldn't
be trusted.

Raw metrics in [`bench/metrics-2026-09-23-ronda3.json`](../../bench/metrics-2026-09-23-ronda3.json).

## What was built

[`bench/make_goodware_dotnet.sh`](../../bench/make_goodware_dotnet.sh),
analogous to round 2's Go generator. It compiles six trivial, legitimate .NET
binaries. Each one represents a class of real software that a badly tuned
rule would flag:

| File | What it represents |
|---|---|
| `dotnet-hola-apphost.exe` + `dotnet-hola.dll` | A modern console app: the native launcher and the managed assembly. The most common thing there is. |
| `dotnet-winforms-net48.exe` | A .NET Framework 4.8 form. It has **a single import, `mscoree!_CorExeMain`**, just like 12 of the 13 .NET malware samples. |
| `dotnet-recursos-net48.exe`, `dotnet-recursos.dll` | An app with 3 MB of high-entropy resources, which is the shape of any WPF app with images. |
| `dotnet-singlefile.exe` | A self-contained single-file executable: a container with the runtime and the assemblies inside, uncompressed and therefore carvable. Like the ConnectWise installers in the corpus, it carries .NET assemblies inside. |

It's built with `make goodware` (needs `dotnet-sdk`) and CI rebuilds it on
every push.

## The finding

With the new goodware, `high_entropy_section` flags both apps with
resources. That was expected. What wasn't expected shows up when looking at
**its hits on the malware**:

| Sample | Type | `.text` entropy | Without managed resources |
|---|---|:---:|:---:|
| 5 njrat, MassLogger, RemcosRAT, Formbook | .NET, 0.7 to 1.4 MB of resources | 7.69 to 7.87 | **5.18 to 6.16** |
| CoinMiner, `unknown` | Native PE, encrypted executable section | 7.98 | (n/a) |
| The two legitimate apps | .NET, 3.15 MB of resources | 8.00 | **5.02 to 5.05** |

Of the rule's 10 hits, **8 are .NET assemblies**. In all eight, the high
entropy comes **only from the resources**: strip them and the code has the
entropy of a normal program. The two legitimate apps fire for the exact same
reason.

So the rule never detected a .NET dropper. It detected ".NET assembly with
large compressed resources", and that covers half the industry.

### Why it happens

In a native PE, an executable section with entropy close to 8 is encrypted
or compressed code: the signature of a packer, which is what the rule was
meant to catch. In a .NET assembly, managed resources (images, icons, data
files) are stored **inside `.text`**, and `.text` is marked executable. The
rule looks at the entropy of the whole section and has no way of knowing that
almost all of those bytes aren't code.

## The fix

`high_entropy_section` no longer applies to .NET assemblies: if the PE has a
CLR header, the rule doesn't look at its sections' entropy.

```yara
pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address == 0
```

It costs **8 detections** (njrat 6 → 1, MassLogger, RemcosRAT and Formbook
1 → 0), and none of the 8 was a real detection. A .NET packer that encrypts
the code itself (not just the resources) falls outside this rule, and that's
accepted: it needs its own rule, one that looks inside .NET.

It's guarded by two tests with PEs built in memory (`tests/test_rules.py`):
the rule must keep firing on an encrypted native PE and must stay quiet on
the same bytes in a .NET assembly. The second one fails with the old rule,
which is how you know it's guarding something.

### The recursive scanning +6, closed

The six ConnectWise detections that recursive scanning added disappear with
the fix, because they came from the same mechanism.
[`recursive-scanning.md`](recursive-scanning.md) already refused to sign off on
them without this corpus; now it's measured that they were false positives.

## Takeaways

This is the third time this project's lesson repeats itself: **the bench is
only as good as its goodware corpus.**

- Round 1: `dynamic_api_resolution_small_iat` was tuned looking only at
  goodware and turned out to have 0 real hits.
- Round 2: the "crypter cluster" was the Go runtime.
- Round 3: `high_entropy_section` had been in the repo from the start, with 0%
  FP, and 40% of the engine's total detection came from a trait shared by any
  .NET app with images.

This time it wasn't a new rule dropped before shipping: it was a shipped
rule, with good numbers, and the numbers were false. Nothing in the metrics
gave it away. The corpus did.

## Next steps

> **Update:** item 1 is done in [round 4](round-4-dotnet-loader.md).

1. **Hypothesis 3, now unblocked.** .NET droppers (5 njrat now blind,
   MassLogger, RemcosRAT, Formbook) are back to having no rule, but now
   there's goodware to measure one against. What's already known **not** to
   work: resource entropy (legitimate apps have it) and generic WinForms
   strings (round 2). It needs to look at something a normal app doesn't do,
   like a resource that gets loaded and turned into code (`Assembly.Load` on a
   resource stream).
2. **Unpack installers** (Inno, NSIS), to reach the two ValleyRAT samples
   that are knowingly let through.
3. **Real installer goodware**, to measure the blind spot of
   `overlay_bulk_inflation`, covered today only by synthetic controls.
