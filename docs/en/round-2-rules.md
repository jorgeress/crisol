# Round two: what survives the bench

*[Versión en español](../ronda-2-reglas.md)*

_September 7, 2026 · 69 malware samples · 57 goodware_

The [first measurement](round-1-detection.md) left three hypotheses with
their expected gain. This document runs them through the bench. **One is
refuted, one ships and one stays blocked**, and the reason for the block is
more interesting than the other two put together.

## Result

| Metric | Before | After |
|---|:---:|:---:|
| Detection (69 samples) | 21.74% (15) | **28.99%** (20) |
| False positives (57 goodware) | 0.0% | **0.0%** |

Raw metrics in [`bench/metrics-2026-09-07.json`](../../bench/metrics-2026-09-07.json).

> **Round 1's 36.84% isn't comparable to this.** That number came from 19
> samples dominated by packed families; this corpus was expanded *on
> purpose* towards the blind families (ValleyRAT 3→13, RemusStealer 2→12,
> njrat 1→11, RustyStealer 1→11, ConnectWise 1→11). Adding 50 samples chosen
> because they're the hard ones lowers the overall rate even as the rules
> improve. The only honest comparison is the one in the table: same corpus,
> same samples, before and after.

### Per family

| Family | Before | After | Total |
|---|:---:|:---:|:---:|
| njrat | 6 | 6 | 11 |
| RemusStealer | 0 | **2** | 12 |
| RustyStealer | 1 | **2** | 11 |
| ConnectWise | 0 | **1** | 11 |
| ValleyRAT | 1 | 1 | 13 |
| unknown | 1 | **2** | 3 |
| Vidar | 1 | 1 | 3 |
| ACRStealer, CoinMiner, Formbook, MassLogger, RemcosRAT | 1 | 1 | 1 each |

The two worst are still **ConnectWise (1/11)** and **ValleyRAT (1/13)**, and
neither is caught through packing, which is the only thing this engine is good
at.

## Hypothesis 1, REFUTED: it wasn't a crypter, it was the Go runtime

Round 1 found four samples with `imphash f0ea7b78...` and exactly 40 imports,
spread across Vidar, RemusStealer and `unknown`, and concluded it was "the
same crypter with different labels". It was the piece with the highest
expected yield: +3 detections.

With the expanded corpus the cluster grows to 6 samples, and a bigger group
shows up: **15 samples with 39-47 imports that import only `kernel32.dll`**
(10 RemusStealer, 3 Vidar, 2 `unknown`) and share **35 identical functions**.
Among them `CreateIoCompletionPort`, `GetQueuedCompletionStatusEx`,
`SwitchToThread`, `SetProcessPriorityBoost`, `SetWaitableTimer`... which is
not the signature of any crypter: **it's the import table of the Go
runtime**.

A grep confirms it beyond doubt: the samples that contain the string
`Go build ID` are **exactly those 15**, not one more, not one less.

The definitive proof is three lines long:

```go
package main

import "fmt"

func main() { fmt.Println("hello") }
```

Compiled with `GOOS=windows go build`, that program has **47 imports, only
kernel32**, and an IAT indistinguishable from that of the corpus stealers.

So the rule the hypothesis called for was written (the *shape* of the IAT,
not the literal hash) and measured against a goodware set that now includes
Windows Go binaries built with [`bench/make_goodware_go.sh`](../../bench/make_goodware_go.sh):

| Rule version | TP | FP | Verdict |
|---|:---:|:---:|---|
| Literal `imphash` + 40 imports | 6 | 0 | It's an **IOC**, not a rule: it only recognizes those exact builds. Zero generalization. |
| IAT shape (what the hypothesis called for) | 6 | **5 of 5** | It flags **100% of the Go goodware in the corpus**. Overall FP 8.77%. |

Five out of five. The rule doesn't detect a crypter: it detects that a
program is written in Go, and that includes docker, kubectl, terraform and
hugo.

**And here's the important part**: this rule would have scored 0% false
positives against the round 1 corpus, because that goodware was 52 Linux and
Wine binaries, not one of them built with Go. It's *exactly* the same mistake
as finding 2 of the previous round (tuning against a corpus that doesn't
contain the class that's going to hurt you), but caught before shipping the
rule instead of after. The fix wasn't touching the rule: it was **fixing the
corpus**, which is why `make_goodware_go.sh` is the real deliverable of this
hypothesis.

## Hypothesis 2, SHIPPED: an overlay that eats the file

The overlay is the bytes that come after the last section. Measured on both
corpora:

| | max overlay | max ratio |
|---|:---:|:---:|
| Goodware (57) | **0.72 MB** | 61.9% (of a 0.16 MB file) |
| Malware (69) | **88.09 MB** | 99.6% |

No legitimate binary in the corpus goes past one megabyte. Nine samples have
8.4 to 88.1 MB of overlay, making up between 61.1% and 99.6% of the file.
That's padding to get past the size threshold above which many AVs and
sandboxes discard a file without looking at it.

Two rules ship in [`rules/malware/overlay_inflation.yar`](../../rules/malware/overlay_inflation.yar):

| Rule | Condition | TP | FP |
|---|---|:---:|:---:|
| `overlay_bulk_inflation` | overlay >4 MB, >60% of the file, no known container signature | **7** | 0 |
| `overlay_null_padding` | overlay >1 MB, >50%, entropy <1.0 | **2** | 0 |

Net gain: **+5 detections** on false negatives (RemusStealer 0→2,
ConnectWise 0→1, RustyStealer 1→2, `unknown` 1→2); the other two were
already caught by another rule.

### The deliberate trade-off

A legitimate installer (NSIS, Inno Setup, a self-extracting 7z) is a small PE
with a huge compressed archive glued after it. Structurally it's
**identical** to evasion padding. That's why the rule doesn't fire if the
overlay starts with the signature of a known container (ZIP, CAB, 7z, RAR,
XZ, gzip, OLE/MSI, Inno).

That costs real, measurable detections: two ValleyRAT samples in the corpus
have 16 and 29 MB overlays starting with `7a 6c 62 1a`, i.e. `zlb\x1a`, the
Inno Setup signature. They are malicious installers, and the rule knowingly
lets them through. The alternative was flagging every installer in the world
as malicious; telling them apart requires opening the container, which is the
next **tool**, not the next rule.

So that this trade-off is measured and not just argued, the goodware now
includes a control shaped like a self-extracting archive: a legitimate Go
binary with 21 MB of ZIP after it (89% of the file). If someone loosens the
rule, that control lights up and the CI gate fails.

**Blind spot on record**: a legitimate self-extractor with a *proprietary*
container (no recognizable signature) would be a false positive. There are
none in the corpus, so today it's an unmeasured hypothesis, not a fact.

## Hypothesis 3, BLOCKED: no .NET goodware to falsify it

> **Update (September 23):** unblocked in [round 3](round-3-dotnet.md),
> which confirms that a "large, high-entropy resource" rule would flag
> legitimate .NET apps.

Thirteen samples in the corpus are .NET (10 njrat, MassLogger, Formbook,
RemcosRAT), twelve of them with a single import: `mscoree.dll!_CorExeMain`.
Five njrat samples are still undetected.

The hypothesis proposed combining that .NET pivot with RAT strings. Looking
for them, what shows up in all thirteen samples is generic WinForms
(`STAThreadAttribute`, `ResumeLayout`, `ResourceManager`, the
`requestedPrivileges` manifest) and not a single family-specific indicator:
they aren't bare njRAT, they're .NET *droppers* with the payload inside their
resources. The behavioral indicators that would discriminate
(`InvokeMember`, `GetManifestResourceStream`, `RegistryKey`) also show up in
the corpus goodware.

A rule like ".NET assembly with a huge, high-entropy resource" could be
written anyway and it would come out at 0% FP. **It would be a lie**, for the
same reason as hypothesis 1: there isn't a single .NET binary in the goodware
corpus, so that 0% wouldn't measure anything. A WPF installer with embedded
images has exactly that shape.

The rule doesn't ship. The block isn't about detection, it's about the
corpus, and it has a concrete fix: it needs a .NET toolchain (`dotnet` isn't
on this machine) to build .NET goodware the same way it was done for Go.
Until then, any .NET rule in this repo would be a rule without a bench.

## Takeaways

All three hypotheses came with an expected gain. The promised total was ~+7
detections; what was delivered is +5, from just one of the three. The other
two didn't fail because the rule was badly written:

- **#1** failed because the goodware corpus didn't contain the class of
  software the rule was going to flag.
- **#3** fails for the same reason, and that's why it doesn't ship.

The pattern repeats: **the test bench is only as good as its goodware
corpus**. Writing the rule is the easy part; building the corpus that can
prove it wrong is the work.

## Next steps

1. **.NET goodware** (`dotnet build`, analogous to `make_goodware_go.sh`).
   Without it hypothesis 3 can't even be attempted.
2. **Real installer goodware** (legitimate NSIS, Inno, 7z SFX) to properly
   measure the blind spot of `overlay_bulk_inflation`, covered today only by a
   synthetic control.
3. **Open containers**: extract the payload of an Inno/NSIS installer and scan
   it recursively. That's where the two ValleyRAT samples that are knowingly
   let through today live, and it's what turns the engine into more than a
   header viewer.
4. **Still-blind families**: ConnectWise 1/11 and ValleyRAT 1/13 are the
   worst on the bench, and neither is caught through packing.
