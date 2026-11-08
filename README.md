# Linux & macOS Privilege Escalation Auditor Engine (`root_exec_audit`)

[![Audit CI](https://github.com/Ethan-da-Tech-Wizard/linux-privilege-audit-engine/actions/workflows/audit-ci.yml/badge.svg)](https://github.com/Ethan-da-Tech-Wizard/linux-privilege-audit-engine/actions/workflows/audit-ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-success.svg)](https://docs.python.org/3/library/)

> **A deterministic, zero-dependency static analysis engine and compliance auditor that detects local privilege escalation (LPE) vectors in Linux (`systemd`, `sudoers`, `udev`, `cron`, `dnf`, `polkit`, `PAM`) and macOS (`launchd`, `periodic`, `paths.d`).**

---

## 1. Executive Summary & The Zero-Escalation Invariant

In modern Unix-like operating systems, the vast majority of local privilege escalation (LPE) vulnerabilities stem not from zero-day kernel memory corruption, but from **execution-chain trust inversion**: privileged processes (running as `UID 0` / `root`) executing, sourcing, or importing files located in paths that unprivileged users can modify, replace, or create.

The **Linux Privilege Escalation Auditor Engine** enforces the **Zero-Escalation Invariant**:

$$\forall \text{ path } p \in \text{ExecChain}(\text{root}), \quad \text{WritableByNonRoot}(p) = \emptyset$$

### Core Engineering Invariants
* **Zero Dependencies:** Implemented strictly in standard library Python (`sys`, `os`, `stat`, `struct`, `shlex`, `plistlib`). Operates seamlessly in minimal container base images, isolated production bastion hosts, and air-gapped forensic environments without requiring `pip install`.
* **Zero System Modification:** 100% read-only static analysis. Does not write to `/tmp`, does not modify configurations, and spawns zero subshells or external processes.
* **Fail-Closed Security Architecture:** If permissions prevent inspecting a subsystem (e.g., an unprivileged user scanning `/etc/sudoers`), the engine emits a structured `info` finding rather than silently reporting a clean bill of health.
* **Deterministic Dual-Platform Engine:** Native support for both **Linux** (deep `systemd` drop-in inheritance, POSIX extended ACL struct parsing, `udev`, `PAM`) and **macOS** (`launchd` plist parsing, `PrivilegedHelperTools`, `paths.d`).

---

## 2. The 12 False-Negative Vulnerability Classes

Traditional security linters and naive vulnerability scanners frequently suffer from catastrophic false negatives because they only perform simple string matching or inspect the target executable file itself. The Auditor Engine was engineered to systematically intercept **12 distinct adversarial false-negative classes**:

```
                                VULNERABILITY TAXONOMY
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [1] Directory Write Delegation   ─── Parent directory permissions permit atomic swap  │
│ [2] Multi-Hop Symlink Traversal  ─── Symlink resolution hops traverse unprivileged dir │
│ [3] Phantom File Creation        ─── Missing optional hooks exploitable via creation  │
│ [4] POSIX ACL Mask Inversion     ─── Extended ACLs grant write without st_mode bits   │
│ [5] systemd Drop-In Hierarchy    ─── .d/*.conf overrides supersede base unit safely   │
│ [6] ExecStart Prefix Operators   ─── '+' and '!' elevate even under User=nobody       │
│ [7] Dynamic Linker / CWD Inject  ─── EnvironmentFile or relative PATH in root daemon  │
│ [8] Script Interpreter Traversal ─── python/bash -c or positional script file targets │
│ [9] Process Execution Wrappers   ─── env/timeout/nice unwrapping reveals payload       │
│ [10] Inline Shell Tokenization   ─── Complex pipelines (&&, ;, ||) parsed to leaf     │
│ [11] Sudoers Wildcards & GTFO    ─── NOPASSWD permits shell-escape or file-write bin   │
│ [12] Elevated User Launchers     ─── ~/.local/bin pkexec/sudo launchers hijacked      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Class 1: Parent Directory Write-Delegation (`rename()` Atomic Swap)
* **The Vulnerability:** An auditor checks `/opt/corp/bin/backup-daemon`, sees permissions `0755` and ownership `root:root`, and marks it secure. However, `/opt/corp` or `/opt/corp/bin` is owned by `developer (UID 1001)` or has permission `0777`.
* **The Exploit:** The unprivileged user cannot modify the binary directly, but POSIX directory semantics permit anyone with directory write access to unlink or rename files within it:
  ```bash
  mv /opt/corp/bin/backup-daemon /opt/corp/bin/backup-daemon.bak
  cp /tmp/evil /opt/corp/bin/backup-daemon
  ```
* **Engine Defense:** Emulates kernel pathname resolution (`walk_nodes()`), testing every ancestor directory from root down to leaf for foreign UID ownership and missing sticky bits.

### Class 2: Multi-Hop Symlink Traversal & Relative Step-Out (`..`)
* **The Vulnerability:** An executable path `/usr/local/bin/service` is a symlink pointing to `/var/opt/links/app.sh`, which in turn points to `../../home/app/start.sh`.
* **The Exploit:** Evaluating only `os.path.realpath()` masks the fact that intermediate symlinks or symlink directories reside in user-writable spaces.
* **Engine Defense:** Iteratively dereferences symlinks step-by-step using `os.readlink()`, evaluating relative path steps (`..`) against the *physical* directory stack, bounded at 40 loops (matching Linux kernel `MAXSYMLINKS` in `include/linux/namei.h`).

### Class 3: The Phantom File Creation Trap (`strict_missing`)
* **The Vulnerability:** A root service, cron job, or DNF hook specifies an optional execution target that does not currently exist on disk (e.g., `/etc/kernel/postinst.d/custom-sync` or an optional `EnvironmentFile=-/etc/sysconfig/app`).
* **The Exploit:** Naive checkers use `os.path.exists()` and ignore missing files. If the parent directory is writable by an unprivileged user, an attacker simply creates the file with payload code and waits for the trigger.
* **Engine Defense:** The `strict_missing=True` audit mode checks whether the missing file resides in a user area or a directory writable by non-root, reporting a blocking vulnerability before the file is even planted.

### Class 4: POSIX Extended ACL Mask Inversion
* **The Vulnerability:** Standard `ls -l` and `stat.st_mode` show permissions `rwxr-xr-x` (`0755`). However, an extended ACL was set via `setfacl -m u:alice:rwx /usr/local/bin/deploy`.
* **The Exploit:** User `alice` can overwrite the root-executed binary, yet standard octal mode checks report safe permissions.
* **Engine Defense:** Unpacks the kernel's binary `system.posix_acl_access` extended attribute directly via `struct.unpack("<HHI")`, calculating the effective permission mask (`p & mask & 2`) for named UIDs and GIDs.

### Class 5: Systemd Drop-In Hierarchy & Precedence Inversion
* **The Vulnerability:** A root service `/usr/lib/systemd/system/myapp.service` is locked down. However, an unprivileged user has write access to `/etc/systemd/system/myapp.service.d/override.conf` or a template drop-in `/etc/systemd/system/myapp@.service.d/`.
* **The Exploit:** Drop-in snippets override vendor unit definitions, silently altering `ExecStart`, `Environment`, or `User`.
* **Engine Defense:** Implements full systemd precedence modeling across vendor (`/usr/lib`), package (`/usr/local/lib`), runtime (`/run`), administrator (`/etc`), and transient control (`system.control`) directories, merging exact-name, template-name, and hyphen-delimited prefix drop-in directories.

### Class 6: Systemd `ExecStart` Empty-Assignment Resets & Dangerous Prefixes (`+`, `!`)
* **The Vulnerability:** Systemd service units support execution modifier prefixes:
  * `-` : Ignore non-zero exit codes.
  * `@` : Set custom `argv[0]`.
  * `+` : **Execute command with full root privileges even if `User=` specifies an unprivileged user!**
  * `!` : Execute command with elevated capabilities.
* **The Exploit:** An unprivileged service (`User=www-data`) includes `ExecStartPre=+/usr/local/bin/setup`. A naive auditor sees `User=www-data` and ignores the service as non-root, missing the root execution trap. Additionally, systemd allows `ExecStart=` (empty value) to wipe all previous commands.
* **Engine Defense:** Parses and strips execution modifier prefixes, detects `+` and `!` overrides under unprivileged service contexts, and honors empty-assignment reset semantics.

### Class 7: Dynamic Linker & Runtime Path Poisoning
* **The Vulnerability:** A root daemon or startup script defines `Environment="PATH=bin:/usr/bin"` or sets `WorkingDirectory=/home/app`.
* **The Exploit:** When a relative path exists in `PATH` or when a daemon executes relative commands from an untrusted working directory, the dynamic linker or interpreter searches the current directory first, allowing local binary planting.
* **Engine Defense:** Scans `PATH`, `PYTHONPATH`, `LD_LIBRARY_PATH`, and `NODE_PATH` for relative directory entries, and audits `WorkingDirectory` settings against untrusted user locations.

### Class 8: Script Interpreter Positional Traversal
* **The Vulnerability:** A root cron job executes `/usr/bin/python3 /home/deploy/process.py`.
* **The Exploit:** Auditing only `argv[0]` verifies that `/usr/bin/python3` is root-owned, completely ignoring the unprivileged Python script target.
* **Engine Defense:** Classifies runtimes (`SCRIPTERS`: Python, Perl, Ruby, Node, PHP, Lua, Awk) and shells (`SHELLS`: Bash, Sh, Dash, Zsh), parsing CLI flags (`-c`, `-e`, `-f`) to locate and audit the actual script payload.

### Class 9: Process Execution Wrappers
* **The Vulnerability:** Root services frequently execute commands via wrappers:
  ```ini
  ExecStart=/usr/bin/env timeout -k 5s 60s /usr/bin/nice -n 10 /home/user/script.sh
  ```
* **The Exploit:** Simple parsers fail to inspect past `/usr/bin/env` or flags like `-n 10`.
* **Engine Defense:** Maintains a catalog of 25+ process wrappers (`WRAP`), unwrapping option flags, timeouts, and hexadecimal affinity masks until the true target executable is exposed.

### Class 10: Inline Shell Tokenization & Compound Pipelines
* **The Vulnerability:** Commands executing inline shell expressions:
  ```ini
  ExecStart=/bin/sh -c "cd /tmp && ./fetch.sh || /home/u/rescue"
  ```
* **The Exploit:** Sub-commands hidden behind logical operators (`&&`, `||`, `;`, `|`), subshells `()`, and leading variable assignments (`VAR=val`) evade simplistic keyword scans.
* **Engine Defense:** Performs recursive shell tokenization (`string_commands()`), stripping I/O redirections and shell control keywords to audit every executable invoked in the pipeline.

### Class 11: Sudoers Wildcards & GTFOBins Exploitation
* **The Vulnerability:** Sudoers file authorizes:
  ```sudoers
  alice ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find /var/log/*
  ```
* **The Exploit:** `vim` contains built-in shell escape commands (`:!/bin/sh`). Wildcards like `/var/log/*` allow passing option flags or path traversal arguments (`/var/log/../../bin/sh`).
* **Engine Defense:** Audits `NOPASSWD` rules against a built-in catalog of 60+ GTFOBins (`vim`, `find`, `less`, `awk`, `python`, `tar`, `tee`, etc.), detects wildcard parameters, and checks group membership across both supplementary and primary GID databases.

### Class 12: Elevated User Launchers & Desktop Autostart
* **The Vulnerability:** Developers or desktop environments frequently configure desktop launchers (`.desktop`) or scripts in `~/.local/bin` that trigger `pkexec`, `sudo`, or `doas`.
* **The Exploit:** If an elevated launcher in `~/.local/bin/run-service` invokes a script residing in user home space, any local process running as that user can modify the script and obtain root privileges upon the next invocation.
* **Engine Defense:** Scans user autostart directories, desktop launchers, and local bin directories (`audit_user_launchers()`), intercepting privilege-escalating wrappers.

---

## 3. Subsystem Deep Dives & Low-Level Mechanics

### A. Bitwise File Mode Operations & POSIX ACL Parsing

The engine performs bitwise masking on the 16-bit `st_mode` integer returned by `os.lstat()`:

```
 15 14 13 12 │ 11 10 09 │ 08 07 06 │ 05 04 03 │ 02 01 00  <-- Bit Position
┌────────────┼──────────┼──────────┼──────────┼──────────┐
│ File Type  │ Special  │   User   │  Group   │  Others  │
│ (4 bits)   │ (3 bits) │  (r w x) │  (r w x) │  (r w x) │
└────────────┴──────────┴──────────┴──────────┴──────────┘
```

#### World-Writable Bitmask Evaluation:
```python
is_world_writable = bool(m & 0o002)
is_sticky_directory = bool(stat.S_ISDIR(m) and (m & 0o1000))

if is_world_writable and not is_sticky_directory:
    # High Severity Finding: Any local user can overwrite or delete this file!
```
* `0o002` (`S_IWOTH`): Tests write permission bit for "others".
* `0o1000` (`S_ISVTX`): Tests the sticky bit. On directories like `/tmp`, the sticky bit prevents unprivileged users from unlinking files owned by other users. If a directory has `0o002` set *without* `0o1000`, any user can rename or replace files within it.

#### Binary POSIX ACL Byte Unpacking:
When extended ACLs are configured on Linux ext4/xfs filesystems, `st_mode & 0o070` represents the ACL *mask*, not the group permissions. The engine reads extended attributes directly:
```python
raw = os.getxattr(real_path, "system.posix_acl_access", follow_symlinks=False)
# Unpack header (4 bytes) + 8-byte entries (uint16 tag, uint16 perm, uint32 id)
ents = [struct.unpack("<HHI", raw[i:i + 8]) for i in range(4, len(raw) - 7, 8)]

mask = next((p for t, p, _ in ents if t == 0x10), 7)  # Tag 0x10 = ACL_MASK
for tag, perm, uid_gid in ents:
    # Tag 2 = ACL_USER (named user), Tag 8 = ACL_GROUP (named group)
    if tag in (2, 8) and (perm & mask & 2):  # Bitwise test for effective write (0x02)
        flag_acl_writer(tag, uid_gid)
```

---

### B. Sudoers Grammar Lexing & GTFOBins Resolution

The `audit_sudoers()` engine implements a fail-closed lexer modeling `/etc/sudoers`:
1. **Drop-in Inclusion:** Resolves `#include` and `@includedir` directives. Mirroring sudo's internal parser, it skips files containing `.` (such as `.rpmnew` or `.dpkg-dist`) and editor backups ending with `~`.
2. **`secure_path` Validation:** Audits directory permissions for every entry in `Defaults secure_path=...`.
3. **NOPASSWD ALL Authorization:**
   ```sudoers
   %wheel ALL=(ALL) NOPASSWD: ALL
   ```
   Queries both `/etc/group` (`grp.getgrnam`) and `/etc/passwd` (`pwd.getpwall`) to identify all human users (UID $\ge$ 1000) who can escalate to root without authentication.
4. **GTFOBins Catalog Matching:** Compares command binaries against an authoritative catalog of binaries that support shell spawning, arbitrary memory reading, or file overwrites.

---

### C. Systemd Unit Precedence & Drop-in Synthesis

The engine calculates unit precedence according to systemd's canonical search order:

| Precedence | Search Directory | Description |
| :---: | :--- | :--- |
| **6** | `/etc/systemd/system.control/` | Persisted control units |
| **5** | `/run/systemd/system.control/` | Transient control units (`systemd-run`) |
| **4** | `/etc/systemd/system/` | System administrator units and drop-ins |
| **3** | `/run/systemd/system/` | Runtime units generated during boot |
| **2** | `/usr/local/lib/systemd/system/` | Locally installed software units |
| **1** | `/usr/lib/systemd/system/` | Vendor and distribution packaged units |

Drop-in directories (`.d/*.conf`) are synthesized in order:
$$\text{Unit Drop-ins} = \text{unit.service.d} \cup \text{template@.service.d} \cup \text{prefix-.service.d} \cup \text{service.d}$$

---

## 4. Least-Privilege Hardening Playbook

To achieve a clean audit (`0 blocking findings`), implement the following DevSecOps hardening controls:

```
                                HARDENING BLUEPRINT
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. Immutable Root Execution Directory:                                                │
│    Migrate root-run scripts to /usr/local/libexec/twu/ owned root:root (0755).         │
│    Apply immutable filesystem flags: chattr +i /usr/local/libexec/twu/*.py             │
│                                                                                        │
│ 2. Remediate World-Writable Files:                                                     │
│    chmod o-w /path/to/vulnerable/file                                                 │
│                                                                                        │
│ 3. Restrict Sudoers Privilege Specifications:                                          │
│    Avoid NOPASSWD: ALL. Specify absolute binary paths and disallow GTFOBins.          │
│    Enforce secure_path="/usr/sbin:/usr/bin:/sbin:/bin"                                │
│                                                                                        │
│ 4. Systemd Unit Isolation:                                                            │
│    Always pair non-root User= with ProtectSystem=strict, ProtectHome=read-only,      │
│    and NoNewPrivileges=yes. Avoid '+' and '!' prefixes on ExecStart directives.        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Usage & CLI Specification

### Basic Execution
```bash
# Run local host audit (default: exits 1 if high or critical findings exist)
python3 scripts/root_exec_audit.py

# Output formatted JSON report
python3 scripts/root_exec_audit.py --json

# Perform deep sweep of /etc, /usr/local, and /opt
python3 scripts/root_exec_audit.py --deep

# Set failure threshold (critical, high, medium)
python3 scripts/root_exec_audit.py --fail-on critical
```

### JSON Report Schema
```json
{
  "schema": "twu.root-exec-audit.v1",
  "platform": "linux",
  "fail_on": "high",
  "findings": [
    {
      "severity": "critical",
      "kind": "systemd-unit",
      "source": "unit backup.service",
      "path": "/home/developer/scripts/backup.sh",
      "why": "ExecStart runs it as root: /home/developer/scripts/backup.sh lives in a user/temporary area"
    }
  ],
  "blocking": 1,
  "total": 1,
  "checked_as_root": true,
  "sudoers_readable": true
}
```

### Exit Codes
* **`0`**: Success. Zero findings discovered at or above `--fail-on` threshold.
* **`1`**: Security Finding. At least one blocking privilege escalation finding identified.
* **`2`**: Usage Error. Invalid CLI arguments, unsupported operating system, or malformed overrides.

---

## 6. Verification & Automated CI

The test suite includes **51 adversarial unit test cases** covering every false-negative class:
```bash
# Execute unit tests across all 51 test scenarios
python3 -B -m unittest -v scripts/test_root_exec_audit.py
```

### Test Suite Coverage Highlights
* Symlink loop detection and 40-step kernel limit exhaustion.
* Masked systemd units (`/dev/null`) ignored cleanly.
* Drop-in reset semantics (`ExecStart=`) clearing previous findings.
* POSIX extended ACL struct unpacking and mask bitwise evaluation.
* Sudoers NOPASSWD GTFOBins detection and group membership resolution.
* Semicolon-delimited command chaining and inline shell tokenization.
* macOS launchd plist parsing and binary plist validation.

---

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.  
Maintained by **Ethan Kilmer** (`ethan@twu.software`).
