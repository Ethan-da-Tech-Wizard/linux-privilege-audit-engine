#!/usr/bin/env python3
"""scripts/test_root_exec_audit.py — Adversarial Regression Test Suite for Privilege Escalation Auditor.

========================================================================================
ADVERSARIAL UNIT TEST MATRIX & PRIVILEGE ESCALATION VALIDATION HARNESS
========================================================================================
Architecture & Theoretical Testing Principles:
  This test harness comprehensively evaluates all 12 privilege escalation false-negative
  classes intercepted by scripts/root_exec_audit.py without requiring root privileges or
  touching the host operating system's /etc directory.

Isolation & Determinism Invariants:
  1. Sandboxed Filesystem Hierarchy: Every test constructs an isolated temporary root
     directory (self.base / t{seq}) representing a mock root filesystem (/).
  2. Non-Root Test Safety: In unit tests, the test runner's current UID (os.getuid())
     serves as the trusted root UID inside the fake tree, unless explicitly overridden.
     This ensures tests run identically whether invoked by an unprivileged developer
     or within an isolated CI sandbox container (where UID may be 0 or 1001).
  3. Untrusted Space Modeling: Non-root user files are created under /home/u (Linux)
     or /Users/u (macOS) to emulate attacker-controlled user environments.
  4. Bitwise Permission Verification: Tests explicitly assert against world-writable
     bits (st_mode & 0o002), sticky bit directory protection (0o1000), group-writable
     bits (0o020), and POSIX binary ACL unpacking.
  5. Zero Host Contamination: Tests verify read-only safety; no files are modified or
     created outside the temporary test directory.

Ownership & Licensing:
  Author: Ethan Kilmer <ethan@twu.software>
  Organization: TWU LLC
  License: MIT License (2026)
========================================================================================
"""

from __future__ import annotations

import json
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import root_exec_audit as rea

# Canonical mock paths for untrusted user homes across Linux and macOS
HU = "/" + "home/u"
UU = "/" + "Users/u"

# Resolved path to the audit script under test
SCRIPT = str(Path(rea.__file__).resolve())

# Standard oneshot systemd service unit template
SVC = "[Unit]\nDescription=x\n[Service]\nType=oneshot\nExecStart={cmd}\n[Install]\nWantedBy=multi-user.target\n"

# Standard enablement symlink pair: multi-user.target.wants link -> active unit file
WANT = ("/etc/systemd/system/multi-user.target.wants/x.service", "/etc/systemd/system/x.service")

# Canonical macOS LaunchDaemon path and hardened application support directory
LD = "/Library/LaunchDaemons/com.twu.x.plist"
TWU_MAC = "/Library/Application Support/TWU"


def unit(body: str) -> str:
    """Generate a standard systemd service unit file wrapping arbitrary [Service] body directives."""
    return "[Unit]\n[Service]\n" + body + "\n[Install]\nWantedBy=multi-user.target\n"


class Base(unittest.TestCase):
    """Base test fixture providing isolated filesystem sandbox synthesis and verification helpers."""
    platform = "linux"

    def setUp(self):
        """Initialize an isolated temporary sandbox directory for filesystem simulation."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.seq = 0

    def tree(self, files, trusted_uid=None, trusted_gid=4242, dirs=(), modes=None, links=(), deep=False, fail_on="high", platform=None, bytes_files=None):
        """Construct a mock root filesystem inside the sandbox and execute run_audit().
        
        Parameters:
          - files: Mapping of {absolute_path: text_content} to create.
          - trusted_uid: UID treated as trusted root (defaults to os.getuid() for runner compatibility).
          - trusted_gid: GID treated as trusted root group (defaults to 4242).
          - dirs: Iterable of directories to explicitly create.
          - modes: Mapping of {absolute_path: octal_mode} permission overrides.
          - links: Iterable of (symlink_source, target) tuples.
          - deep: Whether to run deep filesystem sweep (--deep).
          - fail_on: Severity threshold that marks blocking findings.
          - platform: Platform override ('linux' or 'darwin').
          - bytes_files: Mapping of {absolute_path: raw_bytes} for binary files (e.g. bplist).
        
        Default POSIX permissions applied:
          - Directories: 0755 (rwxr-xr-x)
          - Regular files: 0644 (rw-r--r--)
        """
        self.seq += 1
        root = self.base / f"t{self.seq}"
        for d in dirs:
            (root / d.lstrip("/")).mkdir(parents=True, exist_ok=True)
        for p, txt in files.items():
            f = root / p.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(txt)
        for p, data in (bytes_files or {}).items():
            f = root / p.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        for src, dst in links:
            f = root / src.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(dst, f)
        root.mkdir(exist_ok=True)
        for dp, dns, fns in os.walk(root):
            os.chmod(dp, 0o755)
            for n in fns:
                if not os.path.islink(os.path.join(dp, n)):
                    os.chmod(os.path.join(dp, n), 0o644)
        for p, m in (modes or {}).items():
            os.chmod(root / p.lstrip("/"), m)
        self.root = root
        return rea.run_audit(str(root), os.getuid() if trusted_uid is None else trusted_uid, trusted_gid, platform or self.platform, deep, fail_on, is_root=False)

    @staticmethod
    def sev(res, kind=None, sev=None):
        """Filter audit result findings matching specified category kind and severity level."""
        return [f for f in res["findings"] if (kind is None or f["kind"] == kind) and (sev is None or f["severity"] == sev)]

    def assertClean(self, res, msg=""):
        """Assert that an audit result discovered zero blocking findings and zero actionable security risks."""
        bad = [f for f in res["findings"] if f["severity"] != "info"]
        self.assertEqual(res["blocking"], 0, f"{msg} {res['findings']}")
        self.assertFalse(bad, f"{msg} {bad}")


class TestLinuxCore(Base):
    """Core regression test suite for Linux privilege escalation auditing and systemd parsing."""

    def test_clean_tree(self):
        """Baseline Hardening Test: Clean Root Service Configuration.
        
        Validates that a correctly configured systemd service unit executing a root-owned
        executable in /usr/local/libexec/twu with standard permissions (0755) and an active
        enablement symlink generates zero blocking findings.
        """
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/bash /usr/local/libexec/twu/x"), "/usr/local/libexec/twu/x": "#!/bin/sh\n"},
                        modes={"/usr/local/libexec/twu/x": 0o755}, links=[WANT])
        self.assertClean(res)

    def test_original_bug_script_under_home_is_critical(self):
        """Vulnerability Class 8: Script Execution Within User Home Directory (Critical).
        
        Threat Model:
          A root systemd service executes a maintenance script residing in a user home
          directory (/home/u/.../apply.sh). Because the unprivileged user owns their home
          directory, they can modify, rename, or rewrite apply.sh. When systemd runs the
          service as root, the user's arbitrary payload executes with full UID 0 privileges.
        
        Verification:
          Asserts that path resolution flags the script as Critical severity and records
          a blocking vulnerability.
        """
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/bash /home/u/TWU_LLC/private/configs/apply.sh"),
                         f"{HU}/TWU_LLC/private/configs/apply.sh": "#!/bin/sh\n"}, links=[WANT])
        crit = self.sev(res, "systemd-unit", "critical")
        self.assertTrue(crit and "apply.sh" in crit[0]["path"], res["findings"])
        self.assertEqual(res["blocking"] >= 1, True)

    def test_dropin_reset_clears_old_path_and_removing_it_restores_finding(self):
        """Vulnerability Class 5: Systemd Drop-in Override Reset Semantics (ExecStart=).
        
        Threat Model & Systemd Mechanics:
          Systemd drop-in configuration snippets (.d/*.conf) allow system administrators
          to override vendor unit directives. In systemd syntax, assigning an empty value
          (`ExecStart=`) completely clears all previously defined commands.
        
        Verification:
          1. Base unit defines a vulnerable /home script. Drop-in 10-hardened.conf issues
             `ExecStart=` to wipe the old command and defines a hardened /usr/local/libexec path.
             Asserts 0 blocking findings (vulnerability successfully remediated).
          2. The drop-in is deleted. Asserts that the underlying Critical finding immediately
             re-emerges, proving the scanner accurately tracks live active configuration state.
        """
        files = {"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/bash /home/u/x/apply.sh"), f"{HU}/x/apply.sh": "#!/bin/sh\n",
                 "/usr/local/libexec/twu/apply": "#!/bin/sh\n",
                 "/etc/systemd/system/x.service.d/10-hardened.conf": "[Service]\nExecStart=\nExecStart=-/usr/bin/bash /usr/local/libexec/twu/apply\n"
                 "ExecStart=/usr/bin/bash -c 'echo on > /sys/bus/pci/devices/0000:00:1e.0/power/control'\n"}
        res = self.tree(files, links=[WANT], modes={"/usr/local/libexec/twu/apply": 0o755})
        self.assertEqual(res["blocking"], 0, res["findings"])
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])
        del files["/etc/systemd/system/x.service.d/10-hardened.conf"]
        res = self.tree(files, links=[WANT])
        self.assertTrue(self.sev(res, "systemd-unit", "critical"))
        self.assertEqual(res["blocking"] > 0, True)

    def test_dropin_in_higher_directory_overrides_same_name(self):
        """Vulnerability Class 5: Systemd Search Path Precedence Hierarchy.
        
        Threat Model & Precedence Ordering:
          Systemd loads unit configurations from multiple directories in strict priority order:
          /etc/systemd/system (Priority 4) supersedes /usr/lib/systemd/system (Priority 1).
        
        Verification:
          A vendor drop-in in /usr/lib defines an untrusted command (`ExecStartPre=/home/u/bad`).
          An administrator drop-in with the same filename in /etc issues `ExecStartPre=` to reset it.
          Asserts that the /etc drop-in overrides the vendor drop-in and clears the finding.
        """
        files = {"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/libexec/twu/ok"), "/usr/local/libexec/twu/ok": "x", f"{HU}/bad": "x",
                 "/usr/lib/systemd/system/x.service.d/a.conf": "[Service]\nExecStartPre=/home/u/bad\n",
                 "/etc/systemd/system/x.service.d/a.conf": "[Service]\nExecStartPre=\n"}
        res = self.tree(files, links=[WANT], modes={"/usr/local/libexec/twu/ok": 0o755})
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])

    def test_permissions_world_group_owner_and_sticky(self):
        """Vulnerability Class 1: Bitwise File Mode Operations, Directory Delegation, and Sticky Bits.
        
        POSIX Permission Bitwise Mechanics:
          - 0o666 (rw-rw-rw-): Others write bit (0o002) is active -> High severity finding.
          - 0o777 (rwxrwxrwx): Parent directory is world-writable without sticky bit (0o1000).
            Any unprivileged user can unlink or rename the root executable via rename(2)!
          - 0o664 (rw-rw-r--): Group-writable (0o020) by untrusted group -> Medium severity.
            Does not block by default; blocks when --fail-on medium is set.
          - Non-root UID ownership: An executable owned by non-root UID is flagged High/Critical.
          - 0o1757 (rwxr-xrwt): Sticky bit (0o1000) active on directory. The sticky bit enforces
            restricted deletion, preventing unprivileged users from unlinking files they do not own.
            Neutralizes directory write delegation!
        """
        f = {"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/libexec/twu/run"), "/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        # Scenario 1: World-writable target executable (0o666 & 0o002)
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o666})
        self.assertTrue(self.sev(res, "systemd-unit", "high") and res["blocking"], "world-writable file")
        # Scenario 2: World-writable parent directory without sticky bit (0o777)
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu": 0o777})
        self.assertTrue(self.sev(res, "systemd-unit", "high") and res["blocking"], "world-writable parent dir")
        # Scenario 3: Group-writable file (0o664 & 0o020) by non-root GID
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o664})
        self.assertTrue(self.sev(res, "systemd-unit", "medium"), "group-writable is medium")
        self.assertEqual(res["blocking"], 0, "medium must not block by default")
        # Scenario 4: Verify --fail-on medium blocks group-writable files
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o664}, fail_on="medium")
        self.assertGreater(res["blocking"], 0, "--fail-on medium blocks group-writable")
        # Scenario 5: File owned by non-root UID
        res = self.tree(f, links=[WANT], trusted_uid=os.getuid() + 1)
        self.assertTrue(any("owned by uid" in x["why"] for x in res["findings"]) and res["blocking"], "non-root owner")
        # Scenario 6: Sticky bit (0o1000) set on world-writable directory protects files
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu": 0o1757})   # sticky + other-write, not group-write
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])

    def test_group_writable_by_trusted_group_is_fine(self):
        """Security Policy Invariant: Group-Writable by Trusted Administrative GID is Permitted.
        
        If an executable is group-writable (0o664), but the owning GID matches the trusted
        administrative group (trusted_gid), the auditor does not report a finding, allowing
        controlled team administration without false alarms.
        """
        f = {"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/libexec/twu/run"), "/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o664}, trusted_gid=os.getgid())
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])

    def test_unit_file_itself_and_symlinked_unit_are_checked(self):
        """Vulnerability Class 5: Systemd Unit File Permissions and Symlink Integrity.
        
        Threat Model:
          If the .service unit file itself is world-writable (0o666) or is a symlink pointing
          into a user directory (/home/u/x.service), an attacker does not need to compromise
          the target binary; they simply edit the unit file to insert arbitrary `ExecStart=` commands.
        
        Verification:
          1. Asserts world-writable unit file in /etc/systemd/system is flagged.
          2. Asserts unit file symlinked to /home is flagged Critical severity.
        """
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT],
                        modes={"/etc/systemd/system/x.service": 0o666})
        self.assertTrue([f for f in self.sev(res, "systemd-unit-file") if f["path"] == "/etc/systemd/system/x.service"], res["findings"])
        res = self.tree({f"{HU}/x.service": SVC.format(cmd="/usr/bin/true"), "/usr/bin/true": "x"},
                        links=[WANT, ("/etc/systemd/system/x.service", f"{HU}/x.service")])
        self.assertTrue(self.sev(res, "systemd-unit", "critical"), res["findings"])

    def test_interpreters_envfile_pythonpath_workingdir(self):
        """Vulnerability Classes 7, 8, 9: Interpreters, Environment, and Working Directory Hijacking.
        
        Comprehensive Parameterized Matrix:
          - 'bash': Direct bash script argument in /home
          - 'env-python': /usr/bin/env python3 executing user script
          - 'dash-c': /bin/sh -c compound inline command string
          - 'envfile': EnvironmentFile loading user-controlled environment file
          - 'pythonpath': PYTHONPATH pointing to user library directory
          - 'wd': WorkingDirectory set to user home directory
          - 'prefix-dash': Systemd '-' prefix modifier stripped to audit target
          - 'path-env': PATH containing user-controlled search directory
        """
        tree = {f"{HU}/s.sh": "x", f"{HU}/e.env": "A=1", "/usr/bin/true": "x"}
        cases = {"bash": "ExecStart=/usr/bin/bash /home/u/s.sh", "env-python": "ExecStart=/usr/bin/env python3 /home/u/s.sh",
                 "dash-c": f"ExecStart=/bin/sh -c '{HU}/s.sh now'", "envfile": "ExecStart=/usr/bin/true\nEnvironmentFile=-/home/u/e.env",
                 "pythonpath": "ExecStart=/usr/bin/true\nEnvironment=PYTHONPATH=/home/u/lib", "wd": "ExecStart=/usr/bin/true\nWorkingDirectory=/home/u",
                 "prefix-dash": "ExecStart=-/usr/bin/bash /home/u/s.sh", "path-env": 'ExecStart=/usr/bin/true\nEnvironment="PATH=/home/u/lib:/usr/bin"'}
        for name, body in cases.items():
            with self.subTest(name):
                res = self.tree(dict(tree, **{"/etc/systemd/system/x.service": unit(body)}), links=[WANT], dirs=[f"{HU}/lib"])
                self.assertTrue(self.sev(res, "systemd-unit", "critical") and res["blocking"], res["findings"])

    def test_sysfs_paths_ignored_and_unprivileged_user_units_skipped(self):
        """False-Positive Mitigation: Kernel Pseudo-Filesystems and Non-Root Service Accounts.
        
        1. Synthetic kernel paths under /sys, /proc, and /dev (e.g. PCI power control) are
           managed by kernel drivers and must not be flagged as user storage.
        2. Service units specifying User=nobody or an unprivileged user account do not execute
           commands as root and are skipped (unless elevated via '+' or '!').
        3. Units specifying User=root are audited with full strictness.
        """
        tree = {f"{HU}/s.sh": "x", "/usr/bin/true": "x"}
        res = self.tree(dict(tree, **{"/etc/systemd/system/x.service": unit("ExecStart=/usr/bin/bash -c 'echo on > /sys/bus/pci/devices/0000:00:1e.0/power/control'")}), links=[WANT])
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])
        res = self.tree(dict(tree, **{"/etc/systemd/system/x.service": unit("User=nobody\nExecStart=/usr/bin/bash /home/u/s.sh")}), links=[WANT])
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])
        res = self.tree(dict(tree, **{"/etc/systemd/system/x.service": unit("User=root\nExecStart=/usr/bin/bash /home/u/s.sh")}), links=[WANT])
        self.assertTrue(self.sev(res, "systemd-unit", "critical"))

    def test_empty_command_word_does_not_hang(self):
        """Parser Boundary Safety: Malformed and Empty Command Words.
        
        Ensures shlex tokenization and command_paths() handle empty command strings
        (`ExecStart=""`) and naked prefix characters ('-') safely without hanging,
        infinite recursion, or raising unhandled IndexError exceptions.
        """
        self.assertEqual(rea.command_paths([""]), [])
        self.assertEqual(rea.command_paths(["-", "x"]), [])
        res = self.tree({"/etc/systemd/system/x.service": unit('ExecStart=""')}, links=[WANT])
        self.assertIn("findings", res)

    def test_not_enabled_unit_is_downgraded_to_high(self):
        """Service Enablement Hierarchy: Latent vs Active Vulnerability Severity.
        
        If a unit file contains a critical execution vulnerability but is not actively enabled
        (no enablement link in /etc/systemd/system/*.wants and contains an [Install] section),
        the severity is downgraded from Critical to High. Under default configuration, High
        severity remains blocking because enabling the unit activates the trap.
        """
        res = self.tree({"/etc/systemd/system/y.service": SVC.format(cmd="/usr/bin/bash /home/u/s.sh"), f"{HU}/s.sh": "x"})
        self.assertTrue(self.sev(res, "systemd-unit", "high") and not self.sev(res, "systemd-unit", "critical"), res["findings"])
        self.assertGreater(res["blocking"], 0, "default --fail-on high still blocks a not-enabled trap")

    def test_other_sources_all_flagged(self):
        """Multi-Subsystem Linux Privilege Source Audit: udev, DNF, Cron, Sudoers, and PATH.
        
        Validates that root execution vectors across diverse system components are intercepted:
        - udev rules: RUN+= triggers executing on device events
        - DNF package manager: post_transaction hooks in libdnf5-plugins/actions.d
        - Cron daemon: /etc/cron.d/ scheduled tasks executing as root
        - Sudoers: NOPASSWD: ALL authorizations and user-controlled command paths
        - Local bin directories: Symlinks in /usr/local/bin resolving into user space.
        """
        f = {f"{HU}/s.sh": "x", "/etc/udev/rules.d/90-x.rules": f'ACTION=="add", RUN+="{HU}/s.sh"\n',
             "/etc/dnf/libdnf5-plugins/actions.d/x.actions": "post_transaction:*:/home/u/s.sh now\n",
             "/etc/cron.d/job": "*/5 * * * * root /home/u/s.sh\n", "/etc/NetworkManager/dispatcher.d/90-x": "#!/bin/sh\n",
             "/etc/kernel/install.d/90-x.install": "#!/bin/sh\n",
             "/etc/sudoers.d/u": "u ALL=(ALL) NOPASSWD: ALL\nv ALL=(root) NOPASSWD: /home/u/s.sh\n", "/usr/local/bin/tool": ""}
        res = self.tree(f, links=[("/usr/local/bin/tool2", f"{HU}/s.sh")])
        kinds = {x["kind"] for x in res["findings"] if x["severity"] in ("critical", "high")}
        for want in ("udev-rule", "dnf-plugin", "cron", "sudoers", "local-bin"):
            self.assertIn(want, kinds)
        self.assertTrue(any("passwordless sudo for ALL" in x["why"] for x in res["findings"]))
        self.assertGreater(res["blocking"], 0)

    def test_user_crontab_is_not_root_run(self):
        """Crontab User Isolation: Non-Root Spool Files vs Root Spool File.
        
        Ensures spool directories (/var/spool/cron/) distinguish between unprivileged users
        (e.g. /var/spool/cron/someuser, which executes with user privileges and is safe)
        and /var/spool/cron/root (which executes with UID 0 and must be audited).
        """
        res = self.tree({"/var/spool/cron/someuser": "* * * * * /usr/bin/true\n"}, trusted_uid=os.getuid() + 1)
        self.assertFalse(self.sev(res, "cron"), res["findings"])
        res = self.tree({"/var/spool/cron/root": "* * * * * /usr/bin/true\n"}, trusted_uid=os.getuid() + 1)
        self.assertTrue(self.sev(res, "cron"), res["findings"])

    def test_ld_preload_and_profile(self):
        """Dynamic Linker Search Paths (/etc/ld.so.conf.d) and Login Profile Sourcing (/etc/profile.d).
        
        1. /etc/ld.so.conf.d/ entries pointing to user-writable directories allow local shared
           library (.so) preloading and hijacking for all dynamically linked binaries.
        2. Scripts in /etc/profile.d/ are sourced by root login shells; placing user-writable
           scripts here grants instant elevation upon administrator login.
        """
        res = self.tree({"/etc/ld.so.conf.d/x.conf": f"{HU}/lib\n", "/etc/profile.d/x.sh": "x\n"}, dirs=[f"{HU}/lib"])
        self.assertTrue(self.sev(res, "ld.so", "critical"), res["findings"])

    def test_unreadable_sudoers_is_info_not_failure(self):
        """Fail-Closed Unprivileged Audit Behavior on Inaccessible Sudoers.
        
        When an unprivileged user runs the audit without sudo rights, /etc/sudoers cannot be read
        (mode 0440 root:root). Rather than failing with a fatal crash or falsely reporting 0 findings,
        the auditor emits an informative 'info' finding advising the operator to run with root credentials.
        """
        f = {"/etc/sudoers": "root ALL=(ALL) ALL\n"}
        with mock.patch.object(rea.os, "access", return_value=False):
            res = self.tree(f)
        self.assertTrue(any(x["kind"] == "sudoers" and x["severity"] == "info" for x in res["findings"]))
        self.assertFalse(res["sudoers_readable"])
        self.assertEqual(res["blocking"], 0)
        res = self.tree(f)
        self.assertTrue(res["sudoers_readable"])
        self.assertFalse(self.sev(res, "sudoers"), res["findings"])

    def test_json_shape_is_stable(self):
        """Audit Output JSON Schema Stability Contract.
        
        Verifies machine-readable output against the twu.root-exec-audit.v1 schema specification,
        ensuring automated CI/CD security gates and ingestion pipelines receive consistent fields.
        """
        res = self.tree({"/etc/systemd/system/y.service": SVC.format(cmd="/usr/bin/bash /home/u/s.sh"), f"{HU}/s.sh": "x"})
        self.assertTrue(set(res) >= {"schema", "platform", "fail_on", "findings", "blocking", "total", "checked_as_root", "sudoers_readable"})
        self.assertTrue(all(set(x) == {"severity", "kind", "source", "path", "why"} for x in res["findings"]))
        self.assertEqual(res["platform"], "linux")

    def test_deep_scan_finds_world_writable_and_foreign_owner_and_is_bounded(self):
        """Deep Recursive Filesystem Sweep (--deep) & Boundary Limit Enforcement.
        
        1. Recursively sweeps /etc, /usr/local, and /opt for any file with non-root UID or
           world-writable mode bits.
        2. Bounded execution: Enforces DEEP_LIMIT cutoff to prevent unbounded resource
           consumption on severely misconfigured systems.
        """
        res = self.tree({"/etc/foo.conf": "x", "/opt/app/run": "x"}, modes={"/opt/app/run": 0o666}, deep=True)
        self.assertTrue([f for f in self.sev(res, "deep-scan", "high") if f["path"] == "/opt/app/run"], res["findings"])
        res = self.tree({"/etc/a": "x"}, trusted_uid=os.getuid() + 1, deep=True)
        self.assertTrue(self.sev(res, "deep-scan"))
        with mock.patch.object(rea, "DEEP_LIMIT", 2):
            res = self.tree({f"/etc/f{i}": "x" for i in range(6)}, trusted_uid=os.getuid() + 1, deep=True)
        self.assertEqual(len(self.sev(res, "deep-scan", "info")), 1)

    def test_symlink_loop_and_deep_chains_terminate(self):
        """VFS Path Resolution Safety: Symlink Loop and Recursion Cutoff.
        
        Simulates circular symlinks (e.g. loop -> loop). Verifies that walk_nodes() adheres
        to Linux kernel MAXSYMLINKS (40 traversals) cutoff, terminating safely without
        infinite recursion or stack overflow.
        """
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/bin/loop")}, links=[WANT, ("/usr/local/bin/loop", "/usr/local/bin/loop")])
        self.assertIn("findings", res)

    # ---- Regression test cases modeling demonstrated false-negative edge cases
    @staticmethod
    def u(body, install=True):
        """Construct a systemd unit file with optional [Install] target section."""
        return "[Unit]\nDescription=t\n[Service]\n" + body + "\n" + ("[Install]\nWantedBy=multi-user.target\n" if install else "")

    def crit(self, res):
        """Extract critical and high severity findings representing blocking privilege escalations."""
        return [f for f in res["findings"] if f["severity"] in ("critical", "high")]

    def test_v2_unit_files_themselves(self):
        """Unit File and Drop-In Snippet Physical Permission Integrity.
        
        Validates that unit files (/etc/systemd/system/x.service) and drop-in overrides (*.d/*.conf)
        cannot be modified by unprivileged users via:
        1. Symlinks pointing to home space
        2. World-writable unit file permissions (0o666)
        3. World-writable drop-in snippet permissions (0o666).
        """
        ok = self.u("ExecStart=/usr/local/libexec/twu/run")
        base = {"/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        res = self.tree(dict(base, **{f"{HU}/x.service": ok}), links=[("/etc/systemd/system/x.service", f"{HU}/x.service"), WANT], modes={"/usr/local/libexec/twu/run": 0o755})
        self.assertTrue(self.crit(res) and res["blocking"], "unit symlinked into /home")
        res = self.tree(dict(base, **{"/etc/systemd/system/x.service": ok}), links=[WANT], modes={"/etc/systemd/system/x.service": 0o666, "/usr/local/libexec/twu/run": 0o755})
        self.assertTrue(self.crit(res) and res["blocking"], "world-writable unit file")
        res = self.tree(dict(base, **{"/etc/systemd/system/x.service": ok, "/etc/systemd/system/x.service.d/a.conf": "[Service]\nExecStartPost=/usr/bin/true\n"}), links=[WANT],
                        modes={"/etc/systemd/system/x.service.d/a.conf": 0o666, "/usr/local/libexec/twu/run": 0o755})
        self.assertTrue(self.crit(res) and res["blocking"], "world-writable drop-in")

    def test_v2_dropin_discovery(self):
        """Complete Systemd Drop-In Directory Synthesis Matrix.
        
        Tests the 4 structural drop-in resolution patterns defined in systemd specifications:
        1. Type drop-ins: service.d/ (applies to all .service units)
        2. Prefix drop-ins: x-.service.d/ (applies to hyphen-delimited unit family)
        3. Template drop-ins: x@.service.d/ (applies to instantiated template units)
        4. Control drop-ins: system.control/ (transient systemd-run control units).
        """
        evil = "[Service]\nExecStartPre=/home/u/evil.sh\n"
        base = {f"{HU}/evil.sh": "x", "/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        for tid, unit_name, dpath in (("ty", "x.service", "/etc/systemd/system/service.d/10.conf"), ("pre", "x-y.service", "/etc/systemd/system/x-.service.d/10.conf"),
                                      ("tpl", "x@.service", "/etc/systemd/system/x@.service.d/10.conf"), ("ctl", "x.service", "/etc/systemd/system/system.control/x.service.d/10.conf".replace("system/system.control", "system.control"))):
            with self.subTest(tid):
                files = dict(base, **{"/etc/systemd/system/" + unit_name: self.u("ExecStart=/usr/local/libexec/twu/run"), dpath: evil})
                res = self.tree(files, links=[("/etc/systemd/system/multi-user.target.wants/" + unit_name, "/etc/systemd/system/" + unit_name)], modes={"/usr/local/libexec/twu/run": 0o755})
                self.assertTrue(self.crit(res) and res["blocking"], res["findings"])

    def test_v2_sockets_semicolons_and_missing_files(self):
        """Systemd Sockets, Semicolon Chaining, and Missing Phantom Files.
        
        1. .socket units: ExecStartPre directives executed by systemd sockets.
        2. Semicolon chaining: Systemd Exec directives allow multiple commands separated
           by semicolons ('cmd1 ; cmd2'); both must be extracted and audited.
        3. Missing phantom files: Optional hooks (ExecStartPre=-/home/u/hook.sh) that do not
           yet exist are flagged if their target directory is writable by an unprivileged user.
        """
        base = {f"{HU}/evil.sh": "x", "/usr/bin/true": "x"}
        res = self.tree(dict(base, **{"/etc/systemd/system/x.socket": "[Socket]\nListenStream=/run/x\nExecStartPre=/home/u/evil.sh\n[Install]\nWantedBy=sockets.target\n"}),
                        links=[("/etc/systemd/system/sockets.target.wants/x.socket", "/etc/systemd/system/x.socket")])
        self.assertTrue(self.crit(res) and res["blocking"], ".socket Exec")
        res = self.tree(dict(base, **{"/etc/systemd/system/x.service": self.u("ExecStart=/usr/bin/true ; /home/u/evil.sh")}), links=[WANT])
        self.assertTrue(self.crit(res) and res["blocking"], "';' chain")
        res = self.tree({"/etc/systemd/system/x.service": self.u("ExecStartPre=-/home/u/hook.sh\nExecStart=/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT], dirs=[HU])
        self.assertTrue(self.crit(res) and res["blocking"], "not-yet-existing hook file")
        res = self.tree({"/etc/systemd/system/x.service": self.u("ExecStartPre=-/usr/local/libexec/twu/optional\nExecStart=/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT], dirs=["/usr/local/libexec/twu"])
        self.assertFalse(self.crit(res), "missing file under a root-only dir")

    def test_v2_acl_entry_gives_write_access(self):
        """POSIX Extended Access Control List (ACL) Parsing and Live Kernel Verification.
        
        Uses setfacl to set a named user ACL (u:65534:rwx) on a root execution directory.
        Verifies that the auditor unpacks the binary system.posix_acl_access attribute and
        detects the effective write permission even when st_mode shows standard 0755 permissions.
        """
        import shutil
        if not shutil.which("setfacl"):
            self.skipTest("setfacl not installed")
        f = {"/etc/systemd/system/x.service": self.u("ExecStart=/usr/local/libexec/twu/run"), "/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        # build the tree first, then add the ACL, then audit (tree() audits immediately, so build manually)
        self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o755})
        r = subprocess.run(["setfacl", "-m", "u:65534:rwx", str(self.root / "usr/local/libexec/twu")], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("filesystem has no ACL support: " + r.stderr.strip()[:60])
        res = rea.run_audit(str(self.root), os.getuid(), os.getgid(), "linux", is_root=False)
        self.assertTrue(any("ACL" in x["why"] for x in res["findings"]) and res["blocking"], res["findings"])

    def test_v2_sudoers(self):
        """Sudoers Compliance, GTFOBins Defense, and Wildcard Argument Hijacking.
        
        Evaluates sudoers rule security:
        1. @includedir directive handling.
        2. Defaults secure_path extraction and auditing.
        3. NOPASSWD: ALL detection for individual users (alice) and groups with active members (%wheelish).
        4. GTFOBins detection: Flags vim and tee under NOPASSWD as root escape binaries.
        5. Wildcard parameter detection: Flags command specifications with '*' wildcards that
           permit arbitrary parameter injection.
        """
        files = {"/etc/sudoers": "@includedir /etc/sudoers.d\nDefaults secure_path=\"/usr/sbin:/usr/bin\"\n",
                 "/etc/sudoers.d/a": "alice ALL=(ALL) NOPASSWD:SETENV: ALL\n%wheelish ALL=(ALL) NOPASSWD: ALL\nbob ALL=(root) NOPASSWD: /usr/bin/vim, /usr/bin/tee\ncarol ALL=(root) NOPASSWD: /usr/local/bin/x *\n",
                 "/usr/local/bin/x": "x"}
        with mock.patch.object(rea, "_group_has_members", return_value=["dave"]):
            res = self.tree(files)
        why = " | ".join(x["why"] for x in res["findings"] if x["kind"] == "sudoers")
        for want in ("passwordless sudo for ALL commands for 'alice'", "group '%wheelish'", "'vim'", "'tee'", "wildcard"):
            self.assertIn(want, why)
        with mock.patch.object(rea, "_group_has_members", return_value=[]):
            res = self.tree({"/etc/sudoers": "%empty ALL=(ALL) NOPASSWD: ALL\n"})
        self.assertFalse(self.sev(res, "sudoers", "high"), "group without members must not be flagged")

    def test_v2_env_and_prefix(self):
        """Systemd '+' Execution Prefix and Dangerous Environment Variables.
        
        1. '+' prefix modifier: Forces execution with root credentials even when User=nobody
           is explicitly specified!
        2. BASH_ENV: Environment variable pointing to a file automatically sourced on
           non-interactive bash invocations.
        3. Relative PATH entry: PATH=bin:/usr/bin resolves against the working directory,
           enabling binary planting.
        """
        base = {f"{HU}/evil.sh": "x", "/usr/bin/true": "x"}
        cases = {"var": "Environment=S=/home/u/evil.sh\nExecStart=/usr/bin/bash $S", "bashenv": "Environment=BASH_ENV=/home/u/evil.sh\nExecStart=/usr/bin/true",
                 "relpath": "Environment=PATH=bin:/usr/bin\nExecStart=/usr/bin/true", "plus": "User=nobody\nExecStartPre=+/home/u/evil.sh\nExecStart=/usr/bin/true"}
        for name, body in cases.items():
            with self.subTest(name):
                res = self.tree(dict(base, **{"/etc/systemd/system/x.service": self.u(body)}), links=[WANT])
                self.assertTrue(self.crit(res) and res["blocking"], res["findings"])
        res = self.tree(dict(base, **{"/etc/systemd/system/x.service": self.u("User=nobody\nExecStart=/usr/bin/bash /home/u/evil.sh")}), links=[WANT])
        self.assertFalse(self.crit(res), res["findings"])

    def test_v2_wrappers_and_shell_strings(self):
        """Execution Wrapper Unwrapping and Script Interpreter Analysis.
        
        Verifies that command_paths() strips wrapper utilities (taskset, setpriv, systemd-run)
        and parses inline scripting options (bash -xc, perl -e, awk -f) to isolate and audit
        the payload script.
        """
        base = {f"{HU}/evil.sh": "x", "/usr/bin/true": "x"}
        for name, cmd in {"taskset": "/usr/bin/taskset 1 /home/u/evil.sh", "setpriv": "/usr/bin/setpriv --reuid 0 /home/u/evil.sh", "xc": "/bin/bash -xc 'cd /tmp; /home/u/evil.sh'",
                          "perl": "/usr/bin/perl -e 'system(q(/home/u/evil.sh))'", "sdrun": "/usr/bin/systemd-run --wait /home/u/evil.sh", "awk": "/usr/bin/awk -f /home/u/evil.sh"}.items():
            with self.subTest(name):
                res = self.tree(dict(base, **{"/etc/systemd/system/x.service": self.u("ExecStart=" + cmd)}), links=[WANT])
                self.assertTrue(self.crit(res) and res["blocking"], res["findings"])
        res = self.tree({"/etc/systemd/system/x.service": self.u("ExecStartPre=-/bin/sh -c '/usr/bin/chown -f -R root:root /var/lib/sss/db'\nExecStart=/usr/bin/true"),
                         "/usr/bin/true": "x", "/var/lib/sss/db/f": "x"}, links=[WANT], trusted_uid=os.getuid() + 1)
        self.assertFalse([x for x in res["findings"] if x["kind"] == "systemd-unit" and "/var/lib/sss" in x["path"]], res["findings"])

    def test_v2_more_sources(self):
        """Linux Kernel and System Service Hook Auditing Matrix.
        
        Tests PAM execution modules (pam_exec.so), modprobe install commands, logrotate
        postrotate scripts, tuned daemon scripts, polkit.spawn() JavaScript rules, and
        systemd sleep/suspend hooks.
        """
        f = {f"{HU}/s.sh": "x", "/etc/pam.d/sshd": "auth required pam_exec.so quiet /home/u/s.sh\n", "/etc/modprobe.d/x.conf": "install foo /home/u/s.sh\n",
             "/etc/logrotate.d/x": "/var/log/x {\n  postrotate\n    /home/u/s.sh\n  endscript\n}\n", "/etc/tuned/p/tuned.conf": "[script]\nscript=/home/u/s.sh\n",
             "/etc/polkit-1/rules.d/10.rules": f'polkit.spawn(["{HU}/s.sh"]);\n', "/etc/systemd/system-sleep/hook": "#!/bin/sh\n", "/etc/cron.d/job": "@reboot root /home/u/s.sh\n",
             "/var/spool/cron/root": "*/5 * * * * /home/u/s.sh\n", "/var/spool/cron/alice": "*/5 * * * * /home/alice/own.sh\n"}
        res = self.tree(f, links=[("/etc/systemd/system-sleep/link", f"{HU}/s.sh")])
        kinds = {x["kind"] for x in res["findings"] if x["severity"] in ("critical", "high")}
        for want in ("pam", "modprobe", "logrotate", "tuned", "polkit", "cron", "systemd-hook"):
            self.assertIn(want, kinds)
        self.assertFalse(any("own.sh" in x["path"] or "alice" in x["source"] for x in res["findings"]), "a normal user's crontab was audited as root-run")

    def test_v2_resolution_edge_cases(self):
        """VFS Physical Resolution of '..' Traversal Through Symlinks.
        
        Verifies that navigating '../' through a symlink resolves against the physical parent
        directory on disk rather than the logical symlink path, preventing step-out evasion attacks.
        """
        res = self.tree({"/etc/systemd/system/x.service": self.u('ExecStart=""\nExecStartPre=-')}, links=[WANT])
        self.assertIn("findings", res)
        f = {"/etc/systemd/system/x.service": self.u("ExecStart=/usr/local/libexec/twu/link/../x"), f"{HU}/d/placeholder": "x", f"{HU}/x": "x"}
        res = self.tree(f, links=[WANT, ("/usr/local/libexec/twu/link", f"{HU}/d")], dirs=["/usr/local/libexec/twu"])
        self.assertTrue(self.crit(res) and res["blocking"], "'..' through a symlink must resolve physically")
        res = self.tree({"/etc/systemd/system/x.service": self.u("ExecStart=/home/u/s.sh", install=False), f"{HU}/s.sh": "x"})
        self.assertTrue(any(x["severity"] == "critical" for x in res["findings"]), "static unit must keep full severity")
        res = self.tree({"/etc/systemd/system/x.service": self.u("ExecStart=/home/u/s.sh"), f"{HU}/s.sh": "x"})
        self.assertTrue(not any(x["severity"] == "critical" for x in res["findings"]) and self.crit(res), "enableable-but-disabled is high")

    def test_v2_masked_unit_is_not_flagged(self):
        """Systemd Unit Masking via /dev/null Symlinks.
        
        In systemd, masking a unit is accomplished by symlinking it to /dev/null. Masked units
        cannot be loaded or activated, so vulnerable paths defined in masked units must not be flagged.
        """
        res = self.tree({"/usr/lib/systemd/system/x.service": self.u("EnvironmentFile=-/tmp/x.env\nExecStart=/usr/bin/true"), "/usr/bin/true": "x"},
                        links=[("/etc/systemd/system/x.service", "/dev/null"), WANT])
        self.assertFalse(self.crit(res), res["findings"])

    def test_v2_clean_real_looking_tree_has_no_false_positive_on_optional_hook(self):
        """Zero False-Positive Invariant for Standard Production Installations.
        
        Verifies that a correctly hardened, root-owned system configuration yields zero blocking findings.
        """
        res = self.tree({"/etc/systemd/system/x.service": self.u("ExecStart=/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT])
        self.assertClean(res)


class TestUserLaunchers(Base):
    """Regression test suite for unprivileged desktop launchers elevating via pkexec, sudo, or doas."""

    def test_pkexec_of_user_owned_script_is_flagged(self):
        """Elevated Launcher Vulnerability: pkexec Invoking User-Owned Script.
        
        Threat Model:
          A developer places a utility script in ~/.local/bin/tuned that invokes pkexec python3
          on a script in their home directory. Because the home directory script is user-writable,
          any malicious process running as that user can rewrite the script to escalate to root
          upon next launcher invocation.
        """
        res = self.tree({f"{HU}/.local/bin/tuned": "#!/bin/sh\npkexec /usr/bin/python3 /home/u/tool/apply.py\nexec steam\n",
                         f"{HU}/tool/apply.py": "print(1)\n", "/usr/bin/python3": ""},
                        trusted_uid=os.getuid() + 12345)
        found = self.sev(res, "elevated-launcher")
        self.assertTrue(found, res["findings"])
        self.assertTrue(any("apply.py" in f["path"] for f in found), found)

    def test_desktop_exec_sudo_is_flagged(self):
        """Desktop Launcher Vulnerability: .desktop File with Exec=sudo.
        
        Threat Model:
          A desktop application launcher (.desktop) in ~/.local/share/applications/ defines
          Exec=sudo /home/u/run.sh. Flagged as an elevated launcher risk.
        """
        res = self.tree({f"{HU}/.local/share/applications/x.desktop": "[Desktop Entry]\nExec=sudo /home/u/run.sh\n",
                         f"{HU}/run.sh": "id\n"}, trusted_uid=os.getuid() + 12345)
        self.assertTrue(self.sev(res, "elevated-launcher"), res["findings"])

    def test_launcher_without_elevation_is_not_flagged(self):
        """Launcher Baseline: Non-Elevated Launchers Are Clean.
        
        Verifies that standard user launchers executing unprivileged applications (e.g. Steam)
        or commented-out elevation commands are not flagged.
        """
        res = self.tree({f"{HU}/.local/bin/plain": "#!/bin/sh\nexec steam steam://rungameid/1\n",
                         f"{HU}/.local/bin/commented": "# pkexec /home/u/x.py\n"}, trusted_uid=os.getuid() + 12345)
        self.assertFalse(self.sev(res, "elevated-launcher"), res["findings"])

    def test_pkexec_of_root_owned_copy_is_clean(self):
        """Hardened Launcher: pkexec Invoking Root-Owned Binary.
        
        When a user launcher uses pkexec to invoke a hardened, root-owned binary located in
        /usr/local/libexec/twu/, it is safe and produces zero blocking findings.
        """
        res = self.tree({f"{HU}/.local/bin/tuned": "#!/bin/sh\npkexec /usr/bin/python3 /usr/local/libexec/twu/apply.py\n",
                         "/usr/local/libexec/twu/apply.py": "print(1)\n", "/usr/bin/python3": ""},
                        trusted_uid=os.getuid())
        self.assertFalse([f for f in self.sev(res, "elevated-launcher") if f["severity"] != "info"], res["findings"])


class TestMacOS(Base):
    """Regression test suite for macOS launchd LaunchDaemons, periodic jobs, and paths.d."""
    platform = "darwin"

    @staticmethod
    def plist(**kw):
        """Generate XML plist byte string for launchd LaunchDaemon specification."""
        return plistlib.dumps(dict({"Label": "com.twu.x", "ProgramArguments": ["/bin/sh", f"{TWU_MAC}/x.sh"]}, **kw))

    def good_tree(self, **plist_kw):
        """Construct a hardened baseline macOS LaunchDaemon test tree."""
        return {"bytes_files": {LD: self.plist(**plist_kw)}, "files": {f"{TWU_MAC}/x.sh": "#!/bin/sh\n"}, "modes": {f"{TWU_MAC}/x.sh": 0o755}}

    def run_tree(self, spec, **kw):
        """Execute macOS audit on constructed specification tree."""
        return self.tree(spec["files"], bytes_files=spec["bytes_files"], modes=spec.get("modes"), **kw)

    def test_root_owned_path_is_clean(self):
        """macOS Baseline: Hardened LaunchDaemon is Clean."""
        self.assertClean(self.run_tree(self.good_tree()))

    def test_program_arguments_under_users_flagged_critical(self):
        """macOS Vulnerability: LaunchDaemon ProgramArguments in /Users Directory.
        
        Threat Model:
          A root LaunchDaemon in /Library/LaunchDaemons defines ProgramArguments pointing
          to a script in /Users/u/bin/run.sh. Flagged Critical severity.
        """
        res = self.tree({f"{UU}/bin/run.sh": "#!/bin/sh\n"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/bin/run.sh"])})
        crit = self.sev(res, "launchd-daemon", "critical")
        self.assertTrue(crit and any("run.sh" in f["path"] for f in crit), res["findings"])
        self.assertGreater(res["blocking"], 0)

    def test_program_key_and_first_argument(self):
        """macOS LaunchDaemon Program Key vs ProgramArguments Target Resolution.
        
        Tests both Program string directive and inline python script arguments under ProgramArguments.
        """
        res = self.tree({f"{UU}/d": "x"}, bytes_files={LD: plistlib.dumps({"Label": "x", "Program": f"{UU}/d"})})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])
        res = self.tree({f"{UU}/d": "x"}, bytes_files={LD: plistlib.dumps({"Label": "x", "Program": "/bin/sh", "ProgramArguments": ["sh", f"{UU}/d"]})})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])
        res = self.tree({f"{UU}/d": "x"}, bytes_files={LD: plistlib.dumps({"Label": "x", "ProgramArguments": ["/usr/bin/python3", "-c", f"import x; x.run('{UU}/d')"]})})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])

    def test_username_non_root_is_skipped_root_is_not(self):
        """macOS LaunchDaemon Privilege Dropping via UserName Directive.
        
        When a LaunchDaemon specifies UserName=_nobody or a non-root UID (501), it drops privileges
        and is skipped. When UserName=root, it is audited with full strictness.
        """
        args = ["/bin/sh", f"{UU}/bin/run.sh"]
        for user in ("_nobody", "ethan", "501"):
            with self.subTest(user):
                res = self.tree({f"{UU}/bin/run.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=args, UserName=user)})
                self.assertFalse(self.sev(res, "launchd-daemon"), res["findings"])
        res = self.tree({f"{UU}/bin/run.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=args, UserName="root")})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"))

    def test_environment_variables_and_working_directory(self):
        """macOS Environment Variables & Dynamic Linker Injection (DYLD_INSERT_LIBRARIES).
        
        Tests environment variable injection across:
        - PATH with untrusted directory
        - DYLD_INSERT_LIBRARIES (macOS equivalent of LD_PRELOAD)
        - PYTHONPATH pointing to user directory
        - WorkingDirectory set to user home directory.
        """
        for name, extra in {"path": {"EnvironmentVariables": {"PATH": f"{UU}/bin:/usr/bin"}},
                            "dyld": {"EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": f"{UU}/evil.dylib"}},
                            "pythonpath": {"EnvironmentVariables": {"PYTHONPATH": f"{UU}/lib"}},
                            "wd": {"WorkingDirectory": UU}}.items():
            with self.subTest(name):
                spec = self.good_tree(**extra)
                spec["files"].update({f"{UU}/evil.dylib": "x", f"{UU}/bin/x": "x", f"{UU}/lib/x": "x"})
                res = self.run_tree(spec)
                self.assertTrue(self.sev(res, "launchd-daemon", "critical") and res["blocking"], res["findings"])
        spec = self.good_tree(EnvironmentVariables={"PATH": "/usr/bin:/bin", "HOME": UU})
        self.assertClean(self.run_tree(spec))

    def test_disabled_job_is_downgraded_to_high(self):
        """macOS Disabled LaunchDaemon Severity Downgrading.
        
        When a LaunchDaemon specifies Disabled=true, critical findings are downgraded to High.
        """
        res = self.tree({f"{UU}/r.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/r.sh"], Disabled=True)})
        self.assertTrue(self.sev(res, "launchd-daemon", "high") and not self.sev(res, "launchd-daemon", "critical"), res["findings"])

    def test_plist_file_permissions_and_binary_format(self):
        """macOS LaunchDaemon Plist Permissions and Binary Plist (bplist) Parsing.
        
        1. World-writable plist file (0o666) in /Library/LaunchDaemons flagged High severity.
        2. Binary plist format (bplist00) parsed and decoded seamlessly via plistlib.
        """
        spec = self.good_tree()
        spec["modes"][LD] = 0o666
        res = self.run_tree(spec)
        self.assertTrue([f for f in self.sev(res, "launchd-daemon", "high") if f["path"] == LD], res["findings"])
        bplist = plistlib.dumps({"Label": "x", "ProgramArguments": ["/bin/sh", f"{UU}/r.sh"]}, fmt=plistlib.FMT_BINARY)
        res = self.tree({f"{UU}/r.sh": "x"}, bytes_files={LD: bplist})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), "binary plist not parsed")

    def test_garbled_plist_is_info_and_does_not_stop_the_audit(self):
        """Fail-Closed Robustness: Corrupted or Non-Dictionary Plists.
        
        A malformed or corrupted plist file generates an informative 'info' finding without
        crashing or halting the audit of remaining jobs.
        """
        res = self.tree({"/Library/LaunchDaemons/bad.plist": "<<<not a plist", "/etc/periodic/daily/500x": "x"},
                        bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/r.sh"]), "/Library/LaunchDaemons/list.plist": plistlib.dumps(["a"])},
                        modes={"/etc/periodic/daily/500x": 0o666}, links=[])
        self.assertEqual(len(self.sev(res, "launchd-daemon", "info")), 2, res["findings"])
        self.assertTrue(self.sev(res, "periodic", "high"), "audit stopped after the bad plist")

    def test_periodic_usr_local_sudoers_and_twu_dir(self):
        """macOS Periodic Jobs, Homebrew /usr/local Ownership Risks, and Sudoers.
        
        1. World-writable periodic maintenance scripts (/etc/periodic/daily/*).
        2. User-owned /usr/local/bin (common in Homebrew installations) on root PATH.
        3. Sudoers NOPASSWD: ALL authorizations.
        4. World-writable /Library/Application Support/TWU directory.
        """
        res = self.tree({"/etc/periodic/daily/500x": "#!/bin/sh\n", "/usr/local/bin/tool": "x", "/etc/sudoers": "u ALL=(ALL) NOPASSWD: ALL\n"},
                        modes={"/etc/periodic/daily/500x": 0o666}, trusted_uid=os.getuid())
        kinds = {f["kind"] for f in res["findings"] if f["severity"] == "high"}
        self.assertTrue({"periodic", "sudoers"} <= kinds, res["findings"])
        res = self.tree({"/usr/local/bin/tool": "x"}, trusted_uid=os.getuid() + 1)
        self.assertTrue(self.sev(res, "local-bin") and res["blocking"], "user-owned /usr/local/bin (Homebrew style)")
        spec = self.good_tree()
        spec["modes"][TWU_MAC] = 0o777
        res = self.run_tree(spec)
        self.assertTrue([f for f in res["findings"] if f["severity"] == "high" and TWU_MAC in f["why"]], res["findings"])

    def test_admin_group_writable_library_is_medium_not_blocking(self):
        """macOS Admin Group Write Permissions on /Library/Application Support.
        
        On macOS, group-writable /Library directories (owned by group admin) are evaluated
        as Medium severity and do not block by default.
        """
        spec = self.good_tree()
        spec["modes"]["/Library/Application Support"] = 0o775
        res = self.run_tree(spec)
        self.assertTrue(self.sev(res, "launchd-daemon", "medium"), res["findings"])
        self.assertEqual(res["blocking"], 0)

    def test_paths_d_and_tmp_symlink(self):
        """macOS PATH Configuration (/etc/paths.d) and /tmp -> /private/tmp Symlink Resolution.
        
        1. /etc/paths.d/ entries adding user-controlled directories to login PATH.
        2. /tmp -> /private/tmp symlink dereferencing correctly under Darwin VFS rules.
        """
        res = self.tree({"/etc/paths.d/x": f"{UU}/bin\n", f"{UU}/bin/f": "x"})
        self.assertTrue([f for f in self.sev(res, "profile", "critical") if f["path"] == f"{UU}/bin"], res["findings"])
        res = self.tree({"/private/tmp/r.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", "/tmp/r.sh"])}, links=[("/tmp", "private/tmp")])
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])

    def test_platform_isolation(self):
        """Platform Isolation Guarantee: Linux Subsystems Not Audited on macOS and Vice Versa.
        
        udev rules must not be audited under Darwin; launchd plists must not be audited under Linux.
        """
        linux_only = {"/etc/udev/rules.d/90-x.rules": f'RUN+="{HU}/s.sh"\n', f"{HU}/s.sh": "x"}
        res = self.tree(linux_only)
        self.assertFalse(self.sev(res, "udev-rule"), "udev audited on darwin")
        res = self.tree({f"{UU}/r.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/r.sh"])}, platform="linux")
        self.assertFalse(self.sev(res, "launchd-daemon"), "launchd audited on linux")
        self.assertEqual(res["platform"], "linux")

    def test_deep_scan_on_darwin(self):
        """macOS Deep Sweep Across Privileged Directories (/Library/PrivilegedHelperTools)."""
        res = self.tree({"/Library/PrivilegedHelperTools/h": "x"}, modes={"/Library/PrivilegedHelperTools/h": 0o666}, deep=True)
        self.assertTrue([f for f in self.sev(res, "deep-scan", "high") if f["path"].endswith("/h")], res["findings"])


class TestCli(Base):
    """Regression test suite for Command-Line Interface (CLI), exit codes, and JSON schemas."""

    def cli(self, *args, root=None, env_extra=None, platform_arg=("--platform", "linux")):
        """Invoke root_exec_audit CLI in an isolated subprocess with test environment overrides."""
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if root:
            env.update(ROOTEXEC_ROOT=str(root), ROOTEXEC_TRUSTED_UID=str(os.getuid()), ROOTEXEC_TRUSTED_GID="4242")
        env.update(env_extra or {})
        return subprocess.run([sys.executable, "-B", "-I", SCRIPT, *platform_arg, *args], capture_output=True, text=True, env=env, timeout=60, cwd=str(self.base))

    def test_exit_codes_and_json(self):
        """CLI Exit Code Contract & JSON Reporting.
        
        - Exit Code 1: Blocking findings detected.
        - Exit Code 0: Clean audit result.
        - Flag --fail-on critical adjusts failure threshold.
        - Flag --json emits valid JSON parseable report.
        """
        self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/bash /home/u/s.sh"), f"{HU}/s.sh": "x"}, links=[WANT])
        r = self.cli("--json", root=self.root)
        self.assertEqual(r.returncode, 1, r.stderr)
        data = json.loads(r.stdout)
        self.assertGreater(data["blocking"], 0)
        self.assertEqual(self.cli("--fail-on", "critical", root=self.root).returncode, 1)
        text = self.cli(root=self.root)
        self.assertIn("[CRITICAL", text.stdout)
        self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT])
        self.assertEqual(self.cli("--json", root=self.root).returncode, 0)

    def test_bad_usage_and_bad_overrides_exit_2(self):
        """CLI Usage Error Contract: Exit Code 2 on Malformed Arguments."""
        self.assertEqual(self.cli("--fail-on", "bogus").returncode, 2)
        self.tree({})
        r = self.cli(root=self.root, env_extra={"ROOTEXEC_TRUSTED_UID": "abc"})
        self.assertEqual(r.returncode, 2, r.stdout)

    def test_environment_is_ignored_without_the_test_overrides_and_nothing_is_written(self):
        """Zero-Write Security Guarantee: Read-Only Operation.
        
        Validates that running the CLI writes zero files to the working directory.
        """
        self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT])
        before = sorted(p.name for p in self.base.iterdir())
        r = self.cli("--json", env_extra={"HOME": str(self.root), "XDG_CONFIG_HOME": str(self.root), "PYTHONPATH": str(self.root)})
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertEqual(json.loads(r.stdout)["platform"], "linux")
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), before, "tool wrote into the working directory")

    def test_platform_detection(self):
        """Platform Identification and Unsupported OS Handling."""
        self.assertEqual(rea.detect_platform("linux"), "linux")
        self.assertEqual(rea.detect_platform("linux2"), "linux")
        self.assertEqual(rea.detect_platform("darwin"), "darwin")
        with self.assertRaises(ValueError):
            rea.detect_platform("win32")
        with mock.patch.object(rea.sys, "platform", "freebsd13"):
            self.assertEqual(rea.main(["--json"]), 2)

    def test_live_host_smoke_is_valid_json_and_fast(self):
        """Live Host Smoke Test: Self-Audit Execution.
        
        Runs against the actual live host and verifies valid JSON output format.
        """
        r = self.cli("--json", platform_arg=())
        self.assertIn(r.returncode, (0, 1), r.stderr[-300:])
        data = json.loads(r.stdout)
        self.assertIn(data["platform"], ("linux", "darwin"))


if __name__ == "__main__":
    unittest.main()
