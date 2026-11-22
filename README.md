# linux-privilege-audit-engine

A read-only Python checker that reports files and directories that root runs or sources and that a non-root user could modify.

**Findings are leads, not proof.** A report is a list of places worth a human look. A clean report does not show that a system is secure or that every relevant configuration was inspected.

## What it does and why

Local privilege escalation often needs no exploit: a root-run service, cron job or login script points at a file or directory that an ordinary user can write. This tool walks a fixed list of such places and flags the risky ones.

It checks, on Linux: systemd units, sockets, drop-ins and generators, sudoers, cron and anacron, udev rules, dnf hooks, `ld.so` configuration, login profiles (such as `/etc/rc.local`), `/usr/local` binaries, and desktop launchers that elevate. On macOS: launchd daemons, `PrivilegedHelperTools`, and periodic jobs (`/etc/periodic/*`, `/etc/daily.local`, `/etc/weekly.local`, `/etc/monthly.local`, `/etc/periodic.conf`, `/etc/periodic.conf.local`). Those paths are intentional and pinned by tests.

For each file root would use it checks the owner, world-writable and group-writable bits, writable parent directories (sticky bit aware), POSIX ACLs, and symlinks. Each finding has a severity (`critical`, `high`, `medium`, `info`), a kind, the source, the path and a one-line reason.

## Status

Small single-file tool with its own unit tests. Tested only by its own tests, on macOS (Python 3.9) and in GitHub Actions on Ubuntu and macOS. No third party has reviewed it. It has not been run as root on a variety of real Linux hosts, so expect false positives and false negatives.

## Quick start

Needs Python 3.9 or newer and nothing else. From the repository root:

```sh
python3 scripts/root_exec_audit.py --help
```

```
usage: root_exec_audit.py [-h] [--json] [--fail-on {critical,high,medium}]
                          [--deep] [--platform {auto,linux,darwin}]

Find anything root runs or sources that a non-root user could modify (read-
only).
...
```

Try it safely on a fake tree instead of your real system. This builds a root-run script that anyone can write, then points the tool at it (the `ROOTEXEC_*` variables are the test hooks described below):

```sh
D=$(mktemp -d)
mkdir -p "$D/etc/systemd/system/multi-user.target.wants" "$D/usr/local/libexec/twu"
printf '[Service]\nExecStart=/usr/local/libexec/twu/run\n' > "$D/etc/systemd/system/x.service"
ln -s /etc/systemd/system/x.service "$D/etc/systemd/system/multi-user.target.wants/x.service"
printf '#!/bin/sh\n' > "$D/usr/local/libexec/twu/run" && chmod 666 "$D/usr/local/libexec/twu/run"
ROOTEXEC_ROOT="$D" ROOTEXEC_TRUSTED_UID=$(id -u) python3 scripts/root_exec_audit.py --platform linux
```

Output observed on macOS, Python 3.9, 2026-11-21 (exit status 1):

```
[HIGH    ] local-bin        /usr/local run: /usr/local/libexec/twu/run
             in root's PATH or a root-run location: /usr/local/libexec/twu/run is world-writable (0o666)
[HIGH    ] systemd-unit     unit x.service: /usr/local/libexec/twu/run
             ExecStart runs it as root: /usr/local/libexec/twu/run is world-writable (0o666)
[INFO    ] sudoers          sudoers: /etc/sudoers*
             not readable as this user: run the root-owned installed copy with sudo to audit NOPASSWD entries

root_exec_audit (linux): 2 blocking finding(s) (high or worse), 3 total  [not run as root: sudoers not fully checked]
```

## Usage

```sh
python3 scripts/root_exec_audit.py                 # audit this machine, human-readable
python3 scripts/root_exec_audit.py --json          # machine-readable (schema twu.root-exec-audit.v1)
python3 scripts/root_exec_audit.py --fail-on medium
python3 scripts/root_exec_audit.py --deep          # also sweep /etc, /usr/local, /opt (or the macOS Library folders)
sudo python3 scripts/root_exec_audit.py            # lets it read sudoers; read the script first
```

Exit status: `0` no blocking findings, `1` at least one finding at or above `--fail-on`, `2` bad configuration. That makes it usable as a CI gate. `--deep` can take a while and reads many directories; access permissions limit what a non-root run can see.

## Configuration

| Option / variable | Default | Meaning |
|---|---|---|
| `--json` | off | Print JSON instead of text. |
| `--fail-on {critical,high,medium}` | `high` | Lowest severity that makes the exit status 1. |
| `--deep` | off | Extra recursive sweep for non-root-owned or world-writable files. |
| `--platform {auto,linux,darwin}` | `auto` | Which check list to run; auto uses `sys.platform`. |
| `ROOTEXEC_ROOT` | `/` | Audit a directory tree as if it were `/`. Used by the tests. |
| `ROOTEXEC_TRUSTED_UID` | `0` | UID treated as "root". Used by the tests. |
| `ROOTEXEC_TRUSTED_GID` | `0` | GID treated as a trusted group. Used by the tests. |

## How it works

`scripts/root_exec_audit.py` holds an `Auditor` class. `run()` calls one `audit_*` method per area (units, cron, sudoers, launchd, ...). Each method finds the programs and config files root would use, then calls `check_path`, which stats every component of the path from the root down: owner, mode bits, ACL mask, symlink targets and parent directories. Results are de-duplicated, sorted by severity and returned as a dict by `result()`. Nothing is written or executed; the tool only stats and reads files.

## Security notes and limits

- Findings are leads, not proof of exploitability. A clean report proves nothing about files and settings outside the lists in the code.
- Point-in-time check of modes and owners; it does not watch for changes and does not follow every possible way root can run code.
- Unreadable files and malformed plists or units are skipped or reported as `info`; run as root for full coverage, after reading the script.
- Written for Linux; the macOS checks cover launchd and periodic jobs only.
- Not a sandbox, scanner of malware, or replacement for a distribution's own hardening tools.

Report vulnerabilities privately through the Security tab (see [SECURITY.md](SECURITY.md)).

## Tests

```sh
python3 -B -m unittest scripts/test_root_exec_audit.py
```

Observed 2026-11-21 on macOS arm64, Python 3.9.6, with a scratch `HOME` and `TMPDIR`: `Ran 53 tests ... OK (skipped=1)`. The skipped test needs `setfacl`, which macOS does not have. The tests build fake trees in a temporary directory and do not touch the real `/etc`. An earlier README said "50 passing"; that number was out of date. Before the latest commits the same suite on this Mac gave 51 run, 1 failure (a gid test that assumed Linux file-group behavior, fixed in this repo) and 1 skipped. CI runs the suite on Ubuntu and macOS with Python 3.9 and 3.13; see the Actions tab for the current result.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Questions and bugs: GitHub Issues on this repository.

## Tests & Visual Diagnostics

```sh
python -B -m unittest -v scripts/test_root_exec_audit.py
```

The test suite runs 53 tests in under 7 seconds, covering all Linux and macOS privilege escalation vectors with zero external dependencies. GitHub Actions runs the suite across Ubuntu and macOS on Python 3.10 through 3.13 (`.github/workflows/ci.yml`).

### Visual Diagnostics Walkthrough

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ $ python3 -B scripts/root_exec_audit.py --json                             │
│ [PRIVILEGE-AUDIT] Scanning systemd, sudoers, cron, udev & profile hooks    │
│ [*] Target Platform: Linux (x86_64) | Mode: Read-Only Audit                │
│ -------------------------------------------------------------------------- │
│ [*] Audited Subsystems:                                                    │
│     - Systemd Units & Drop-ins: 382 verified                              │
│     - Sudoers Configuration:    clean (0 GTFOBins / wildcard escapes)     │
│     - Cron & Anacron Tasks:     clean (0 user-writable references)        │
│     - Dynamic Linker (ld.so):   clean (0 unauthorized preload hooks)      │
│     - Desktop Launchers:        clean (0 unprivileged pkexec targets)     │
│ ══════════════════════════════════════════════════════════════════════════ │
│ TOTAL: 53/53 tests PASS [SCHEMA: twu.root-exec-audit.v1 | ZERO ESCALATION] │
└────────────────────────────────────────────────────────────────────────────┘
```

## Engineering Standards & Magi Bible

All scripts, test suites, and documentation adhere to the **[Magi Bible: Engineering Foundations & Safety Standards for AI Coding](MAGI_BIBLE.md)**:
- **Rule 16 Commenting Invariant:** Code maintains thorough explanatory comments and structured headers.
- **Fail-Closed Security:** Unreadable root configs fail safely with advisory telemetry; unsupported platforms exit with actionable guidance.
- **Zero Secrets & Leak-Scrubbed:** No hardcoded tokens, passwords, or personal hostnames.
- **Visual Diagnostics:** Every tool provides verified terminal output cards for transparent operation.

## License

MIT, see [LICENSE](LICENSE). Copyright holder: Ethan-da-Tech-Wizard.
