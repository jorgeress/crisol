# Round four: the four-family crypter

*[Versión en español](../ronda-4-loader-dotnet.md)*

_September 23, 2026 · 69 malware samples · 315 goodware_

[Round 3](round-3-dotnet.md) left 8 .NET samples blind: `high_entropy_section`
was detecting them for the wrong reason, and once that was fixed they had no
rule. This round looks for a real rule for them. What comes out is better than
expected: four different "families" turn out to be **the same crypter**.

## Result

| Metric | Before | After |
|---|:---:|:---:|
| False positives | 0.0% (64 goodware) | **0.0%** (315 goodware) |
| Detection (69 samples) | 17.39% (12) | **33.33%** (23) |
| njrat | 1/11 | **9/11** |
| MassLogger, RemcosRAT, Formbook | 0/1 each | **1/1** each |

It beats round 2's 28.99%, and this time without any known hit for the wrong
reason. Raw metrics in
[`bench/metrics-2026-09-23-ronda4.json`](../../bench/metrics-2026-09-23-ronda4.json).

## First, a corpus that can say no

The six .NET binaries from round 3 are toy programs: they don't draw images
or use reflection. A rule looking at those APIs would score 0% FP against
them without proving anything, which is the trap this project is about.

So `make_goodware_dotnet.sh` now does two more things:

1. **Publishes a self-contained WinForms + WPF app**, the way a vendor would
   ship it. The resulting folder is 249 binaries: the app itself and
   **247 real Microsoft binaries**: the implementation of WinForms, WPF,
   System.Drawing and the runtime, with their native DLLs. It's production
   software that legitimately uses every API a loader uses.
2. **Builds two controls in the exact shape of the loader** (explained below,
   since they come out of the analysis).

Goodware goes from 64 to 315 binaries, 234 of them .NET.

## A rule that was already wrong: `anti_debug_stacked`

Before writing anything new, the existing rules against the expanded corpus.
`anti_debug_stacked` flags **`mscordbi.dll`, the .NET debugger**.

The rule classified `DebugActiveProcess` as a *strong* technique, rare in
legitimate software. And it is, except in debuggers: it's literally the API a
debugger uses to attach to a process. The same goes for profilers and crash
reporters. The corpus had none.

It's downgraded to *ubiquitous*. **It doesn't cost a single hit**: the four
samples that fire the rule also have `NtQueryInformationProcess`. A new test
(`test_anti_debug_does_not_fire_on_a_debugger`) reproduces the APIs of
`mscordbi.dll` and fails with the old rule.

## The finding: one crypter, four families

The 13 .NET samples in the corpus split into two groups without looking at a
single label:

**Group A, bare njRAT** (4 samples, 20 to 60 KB). The configuration is in
plain text: host, port, the protocol separator `|'|'|`, the commands
(`netsh firewall`, `cmd.exe /c ping 0 -n 2 & del`) and the builder's error
messages (`Execute ERROR`, `Download ERROR`).

**Group B, steganographic loader** (8 samples: 5 njrat, MassLogger,
RemcosRAT and Formbook). They're all a decoy WinForms app with made-up
project names (`VineyardFrost`, `CollieryWinder`, `PonsFuniculus`,
`RegenGarten`), with a 0.7 to 1.4 MB image in `Properties.Resources` that
takes up **between 83% and 96% of the file**, and the same APIs: `Bitmap`,
`GetPixel`, `InvokeMember`. The payload is hidden in the image's pixels,
rebuilt by reading them one by one and run via reflection.

MassLogger and RemcosRAT even share the decoy (`VineyardFrost`, with Finnish
text). What MalwareBazaar labels as four families is **the same packer** with
four different payloads. For a rule that's good news: you catch the wrapper,
and the wrapper is shared.

## Which combination survives

Each piece of group B on its own is completely ordinary. This is what each
candidate scores against the final corpus (234 legitimate .NET assemblies):

| Condition | TP | FP | What takes it down |
|---|:---:|:---:|---|
| `GetPixel` | 6 | 4 | `System.Windows.Forms.dll` and the two controls |
| `InvokeMember` | 7 | 5 | `PresentationCore.dll`, `System.Xaml.dll`... |
| Resource > 50% of the file (the original hypothesis 3) | 8 | **8** | 4 Microsoft DLLs (WPF themes like `PresentationFramework.Luna.dll`, and `System.Text.Encoding.CodePages.dll`) and 4 controls |
| Resource > 50% + `GetObject` | 8 | 0 → **2** | the two controls |
| Resource > 50% + (`InvokeMember` or `Activator`) | 8 | 0 → **1** | the `plugins` control |
| **Resource > 50% + `Bitmap` + `InvokeMember`** | **7** | **0** | nothing |

Round 2's hypothesis 3 ("huge, high-entropy resource") is refuted with data:
**four real Microsoft DLLs** have that shape, not counting the synthetic
controls.

### The two controls, and why they were needed

The rows with the arrow (`0 → 2`, `0 → 1`) scored **8 TP and 0 FP** against
the 247 Microsoft binaries. They looked like the winners. But all those
binaries are **libraries**, and what the loader imitates is an
**application**: a WinForms app that reads its background image with
`ResourceManager.GetObject` does exactly the same as the dropper, and the
corpus didn't have one.

So two were built, compiled for .NET Framework 4.8 just like the samples:

- **`dotnet-visor.exe`**: a color picker. A 1024x768 PNG in
  `Properties.Resources`, read with `GetObject`, and `GetPixel` to show the
  color where you click.
- **`dotnet-plugins.exe`**: the same viewer, which also loads plugins via
  reflection with `Activator.CreateInstance`.

They took down both candidates. Without them a rule would have shipped that
flags any app with a large background image.

### The shipped rule

[`rules/malware/dotnet_loaders.yar`](../../rules/malware/dotnet_loaders.yar):

```yara
dotnet.is_dotnet and $bitmap and $invoke and
for any i in (0..dotnet.number_of_resources - 1): (
    dotnet.resources[i].length > filesize \ 2
)
```

`$bitmap` and `$invoke` look for the names in the metadata heap delimited by
null bytes, so they don't match `BitmapData` or `InvokeMemberBinder`.

**Blind spot on record**: a legitimate app with an image taking up more than
half the file that automates COM (Excel, Word) with `InvokeMember` would
fire. There are none in the corpus, so it's an unmeasured hypothesis, not a
fact.

## The njRAT rule

`njrat_config_markers` requires 4 of 8 markers from group A (separator,
commands and error messages), in UTF-16 because that's how .NET stores its
strings. 4 TP, 0 FP.

It's a **family signature**, not a behavioral one, and that should be said
plainly: it catches njRAT builder 0.7d and nothing else. `0.7d` itself is left
out (too short), as is the `Run` registry key (any program that starts with
Windows uses it).

## What's still undetected

Two njrat samples:

- **`a9665d49`**: it's from group B (95% image, `RegenGarten` decoy), but it
  uses `Activator.CreateInstance` instead of `InvokeMember`. Catching it means
  accepting `Activator`, and the `plugins` control shows that flags
  legitimate apps. It's knowingly let through.
- **`6f201afc`**: obfuscated (namespaces like `Ⴍ`), no large resource and no
  plain-text strings. It needs a different tool, not a different rule.

## Takeaways

This round raises detection instead of lowering it, but the lesson is the
same as always, and this time it's visible in the table: **two of the
candidates scored 8 TP and 0 FP until the goodware that could take them down
was built.** Against 247 Microsoft binaries they already looked solid. What
was missing wasn't volume, it was the right class of software: an
application with the same shape as the malware.

## Next steps

1. **Unpack installers** (Inno, NSIS): the two ValleyRAT samples knowingly let
   through since round 2.
2. **Real installer goodware**, to measure the blind spot of
   `overlay_bulk_inflation`.
3. **Blind families**: ConnectWise 1/11 and ValleyRAT 1/13 are still the
   worst, and there's nothing easy left in them.
