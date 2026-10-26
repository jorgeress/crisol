# Safe sample handling

*[Versión en español](../manejo-seguro-muestras.md)*

This document explains **how real malware samples are handled** in crisol
and, above all, *why* each control is where it is. It's the part a real lab
takes for granted and almost no portfolio project documents.

## The starting point: static analysis

crisol **never executes the sample**. It extracts features (PE/ELF headers,
IAT, entropy, strings) and runs YARA rules over the bytes. That changes the
threat model completely compared to a dynamic lab: there's no need for a
disposable VM with an isolated network, because there's no malicious process
running to defend against.

What remains is a subtler risk, and that's what is addressed here.

## Threat model

| # | Risk | Likelihood | Impact | Control |
|---|------|------------|--------|---------|
| 1 | **Accidental execution**: a `chmod +x`, a glob in a script, a double click | High | Host compromise | Samples are `0400` with no extension; the name is the sha256; the exec bit is never touched |
| 2 | **Leak to the public repo**: `git add -f`, a rename, a badly edited `.gitignore` | Medium | Distributing malware; breaking abuse.ch's ToS | `.gitignore` + a `pre-commit` hook that inspects the *index*, not the ignore rules |
| 3 | **Parser exploit**: a deliberately malformed file blows up `pefile`, `oletools` or `libyara` | Low | Code execution in the analyzer process | `scripts/sandbox.sh`: bubblewrap with no network, no `$HOME`, read-only repo, `NoNewPrivs` |
| 4 | **Lateral spread**: the sample ends up in a backup, a cloud sync or gets scanned by a Windows machine on the network | Medium | Someone else's EDR alerts; corpus deleted | Corpus outside synced paths; `0700` directory; excluded from backups |
| 5 | **Mislabeled corpus**: something different from what the manifest claims gets stored | Medium | **Lying metrics** | sha256 recomputed on download; if it doesn't match, it's discarded |

Risk 5 is about integrity, not security, but it's the most expensive one for
this particular project: all of crisol's value lies in its numbers being
credible.

## Implemented controls

### 1. Storage with no sharp edges
`bench/fetch_malwarebazaar.py` stores each sample:

- with the **sha256 as its name and no extension**: no `.exe` inviting a
  double click, no extension that triggers a desktop handler;
- with **`0400`** permissions (read-only, no execute, no write), in a `0700`
  directory;
- **verifying the sha256** against the one MalwareBazaar advertises before
  writing anything.

### 2. Analyzer isolation
```bash
scripts/sandbox.sh make bench          # or: make sandbox-bench
scripts/sandbox.sh .venv/bin/python -m crisol.cli scan corpus/malware/<sha>
```

`scripts/sandbox.sh` wraps the command in [bubblewrap](https://github.com/containers/bubblewrap)
using **unprivileged user namespaces** (no root, no daemon, no image to
build):

| Property | How |
|---|---|
| No network | `--unshare-all` (includes the network namespace) |
| No real `$HOME` | only the repo is mounted; `HOME` points to a tmpfs |
| Read-only repo | `--ro-bind`; the only writable exception: `reports/` |
| No privilege escalation | `NoNewPrivs=1` |
| No terminal hijacking | `--new-session` (blocks `TIOCSTI`) |
| Dies with its parent | `--die-with-parent` |
| API key hidden | `.mb_api_key` is masked with `/dev/null` |

These properties are **verified by tests** (`tests/test_sandbox.py`), not
just documented: if someone adds an extra `--bind`, the test fails.

### 3. The corpus doesn't leave the disk
```bash
make hooks   # installs scripts/pre-commit
```
The hook blocks any commit that adds files under `corpus/` or any
`MZ`/`ELF`/`OLE` binary to the index, wherever it comes from. It looks at the
index directly, so `git add -f` doesn't get around it.

### 4. Optional host hardening
A `noexec` mount over the corpus makes it impossible to execute a sample even
if someone sets `+x` on it. It needs root once:

```bash
sudo mount --bind -o noexec,nosuid,nodev corpus/malware corpus/malware
```

And, to survive a reboot, the equivalent line in `/etc/fstab`. Also
recommended: exclude `corpus/` from any backup or synced folder (Dropbox,
Drive, Syncthing), because an automatic backup is the quietest way to spread
a sample to another machine.

## What is deliberately NOT done

- **No dynamic analysis.** Running malware requires a VM with snapshots and a
  controlled network; that's out of scope for this project, which is why the
  bubblewrap sandbox is enough. Bubblewrap is **not** a security boundary
  designed to contain hostile code being run on purpose: here it contains the
  consequences of an accident in one of my own processes, which is a
  different thing.
- **Samples are not redistributed.** abuse.ch's ToS forbids it. The sha256
  hashes and families can be published: with them anyone can rebuild the same
  corpus and reproduce the metrics.
- **The host antivirus is not disabled.** If an EDR quarantines a sample,
  that's the system working as intended; the right answer is an exclusion
  scoped to the corpus directory, not turning protection off.

## Operational checklist

Before downloading:
- [ ] `make hooks`: the anti-leak hook is installed
- [ ] `corpus/` is not inside a synced folder or a backup

While analyzing:
- [ ] `make sandbox-bench` instead of `make bench` when there are real samples
- [ ] never `chmod +x` anything in `corpus/malware/`

When publishing:
- [ ] only hashes, families and metrics, never a single byte of a sample
