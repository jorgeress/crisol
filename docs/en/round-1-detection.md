# First detection measurement on real malware

*[Versión en español](../hallazgos-deteccion.md)*

_September 3, 2026 · 19 samples · 12 families_

Up to this point crisol only measured **false positives** (0% on 52
legitimate binaries). That's half the story: rules that never fire also have
a 0% FP rate. This document is the other half: what they actually detect,
what slips past them and **why**.

## Result

| Metric | Value |
|---|---|
| False positives (52 goodware) | **0.0%** |
| Detection (19 real samples) | **36.84%** (7/19) |

Raw metrics in [`bench/metrics-2026-09-03.json`](../../bench/metrics-2026-09-03.json).

### Per rule

| Rule | TP | FP |
|---|---|---|
| `high_entropy_section` | 5 | 0 |
| `packer_signature_strings` | 1 | 0 |
| `anti_debug_stacked` | 1 | 0 |
| `process_injection_apis` | **0** | 0 |
| `dynamic_api_resolution_small_iat` | **0** | 0 |
| VBA rules (`vba_*`) | 0 | 0 |

### Per family

| Family | Detected | Total |
|---|---|---|
| ACRStealer, CoinMiner, Formbook, MassLogger, RemcosRAT | 1 | 1 |
| Vidar | 1 | 3 |
| unknown | 1 | 3 |
| **ValleyRAT** | **0** | 3 |
| **RemusStealer** | **0** | 2 |
| **ConnectWise, RustyStealer, njrat** | **0** | 1 |

## Methodology

- **Corpus**: MalwareBazaar via `--recent` (a time slice of what was
  circulating that day) filtered to `exe,dll`, capped at 3 per family so an
  active campaign doesn't dominate the sample.
- **Integrity**: sha256 recomputed before saving. A mislabeled corpus produces
  lying metrics, which is the most expensive failure in this project.
- **Isolation**: all analysis ran inside `scripts/sandbox.sh`
  (see [safe sample handling](safe-sample-handling.md)).
- **Reproducibility**: [`bench/corpus_manifest.json`](../../bench/corpus_manifest.json)
  publishes the sha256 hashes and families. With it anyone can rebuild the
  same corpus and check these numbers. Samples are not redistributed.

## Findings

### 1. Today, the engine is an entropy detector
Five of the seven detections come from `high_entropy_section`, one from
packer strings and one from anti-debugging. **None are behavioral.**
Everything crisol catches, it catches because it's packed; against an
unpacked sample it's blind.

### 2. The "tiny IAT" hypothesis is refuted
`dynamic_api_resolution_small_iat` requires `pe.number_of_imported_functions < 30`.
That threshold came from tuning **against goodware**, and it worked: it
lowered FPs. Against real malware it scores **0 true positives**, because the
stealers in this corpus have IATs of 39 to 658 functions:

| Sample | Family | Imports |
|---|---|---|
| `2faf35c8` | ValleyRAT | 658 |
| `ffb3eacf` | RustyStealer | 303 |
| `52e889aa` | ValleyRAT | 146 |
| `32431111` | ConnectWise | 76 |
| `0b00260f` | RemusStealer | 39 |

It's textbook overfitting: one metric (FP) was optimized until the rule lost
all value on the other (detection). Documenting it is worth more than the
rule that did work, because it's the trap anyone tuning rules while looking
at only one side of the bench falls into.

### 3. An imphash cluster groups 4 samples (3 undetected)
Four samples share `imphash f0ea7b7844bbc5bfa9bb32efdcea957c` with exactly 40
imported functions: two labeled Vidar and two `unknown`. It's the same
crypter with different labels. Only one is caught (by packer strings).

A rule on that IAT shape turns 3 false negatives into detections. **It's the
highest-yield loose end in the corpus.**

### 4. An imphash that looks like a rule but is only a pivot
Another cluster, `f34d5f2d4577ed6d9ceec516c1f5a744` with 1 import, is
`mscoree.dll!_CorExeMain`: the signature of **any .NET executable**
(MassLogger, Formbook, njrat here). As a standalone rule it would push the FP
rate back into double digits the day the goodware includes a .NET binary. It
works as a **pivot** (an entry condition combined with other evidence), never
as a detection on its own.

### 5. Size inflation as evasion
Two samples are around 90 MB with ~87 MB of **overlay** (data after the last
section). It's deliberate padding: many AVs and sandboxes skip files above a
size threshold. The structure is very distinctive (a huge, low-entropy
overlay) and goodware almost never has it, so it promises detection with low
FP.

### 6. Small and unpacked is invisible
`njrat` is 0.0 MB, .NET, with entropy 5.57. There's nothing to unpack and no
high-entropy section to see. Against this profile the current rules can do
nothing by design: it needs a different family of rules based on .NET
strings and structure.

## Limitations (read before quoting the percentages)

- **n = 19.** Each sample is worth 5.3 points of detection. Confidence
  intervals are huge; these numbers guide the work, they don't certify
  anything.
- **Families with 1 sample don't have a rate**, they have a yes or a no.
- **`--recent` is a time slice**, not a representative sample of malware in
  general: it overrepresents the campaigns active that day.
- **The goodware is 52 Linux/Wine binaries**, so the 0% FP rate says nothing
  about signed Windows software, which is where a false positive hurts most.

## Next steps

The next three rules, in order of expected yield, each with its falsifiable
hypothesis:

1. **Crypter cluster by IAT shape** (finding 3). *Hypothesis*: the
   combination of imphash and import count identifies the crypter regardless
   of family. *Expected gain*: +3 detections (→ ~52%).
2. **Oversized overlay** (finding 5). *Hypothesis*: an overlay that is >80%
   of the file and exceeds tens of MB is evasion padding, not legitimate data.
   *Expected gain*: +1, and it generalizes to future campaigns.
3. **Unpacked .NET malware** (finding 6). *Hypothesis*: the .NET pivot from
   finding 4 plus RAT strings (`mscoree` + embedded config patterns)
   discriminates without touching .NET goodware.

**Non-negotiable acceptance criterion: the FP rate stays at 0%.** A rule that
raises detection by breaking that is a rule that gets dropped. And after
writing them, everything must be **re-measured on the expanded corpus**, not
this one: tuning against the same 19 samples would repeat the mistake of
finding 2 in the other direction.

Before writing anything, the corpus should grow to 50-60 samples using
`--signature` on the blind families (ValleyRAT, RemusStealer, njrat), so each
sample stops being worth 5 points.

---

> **Follow-up (Sep 7, 2026)**: done, with a surprise. The corpus is at 69
> samples and all three hypotheses have been through the bench: #2 ships, #3
> stays blocked and **#1, the one with the highest expected yield, is
> refuted: this document's "crypter cluster" is the Go runtime**. It's all in
> **[round 2](round-2-rules.md)**.
