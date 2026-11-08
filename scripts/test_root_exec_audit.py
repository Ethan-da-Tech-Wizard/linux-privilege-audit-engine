#!/usr/bin/env python3
"""Tests for scripts/root_exec_audit.py — the detector for "root runs something a normal user can write".

Every case builds a fake filesystem in a temporary directory and audits it through the module (or the CLI for exit codes);
nothing reads the real /etc. The user running the tests counts as root inside the fake tree (trusted_uid = our uid) unless a
case says otherwise, so the suite behaves the same as a normal user and inside the capped sandbox (where we are uid 0).
Fake users live under /home/u and /Users/u.
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

HU = "/" + "home/u"
UU = "/" + "Users/u"
SCRIPT = str(Path(rea.__file__).resolve())
SVC = "[Unit]\nDescription=x\n[Service]\nType=oneshot\nExecStart={cmd}\n[Install]\nWantedBy=multi-user.target\n"
WANT = ("/etc/systemd/system/multi-user.target.wants/x.service", "/etc/systemd/system/x.service")
LD = "/Library/LaunchDaemons/com.twu.x.plist"
TWU_MAC = "/Library/Application Support/TWU"


def unit(body: str) -> str:
    return "[Unit]\n[Service]\n" + body + "\n[Install]\nWantedBy=multi-user.target\n"


class Base(unittest.TestCase):
    platform = "linux"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.seq = 0

    def tree(self, files, trusted_uid=None, trusted_gid=4242, dirs=(), modes=None, links=(), deep=False, fail_on="high", platform=None, bytes_files=None):
        """files: {abs path: text}. Default modes: dirs 755, files 644; `modes` then overrides. Returns the audit result dict."""
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
        return [f for f in res["findings"] if (kind is None or f["kind"] == kind) and (sev is None or f["severity"] == sev)]

    def assertClean(self, res, msg=""):
        bad = [f for f in res["findings"] if f["severity"] != "info"]
        self.assertEqual(res["blocking"], 0, f"{msg} {res['findings']}")
        self.assertFalse(bad, f"{msg} {bad}")


class TestLinuxCore(Base):
    def test_clean_tree(self):
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/bash /usr/local/libexec/twu/x"), "/usr/local/libexec/twu/x": "#!/bin/sh\n"},
                        modes={"/usr/local/libexec/twu/x": 0o755}, links=[WANT])
        self.assertClean(res)

    def test_original_bug_script_under_home_is_critical(self):
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/bash /home/u/TWU_LLC/private/configs/apply.sh"),
                         f"{HU}/TWU_LLC/private/configs/apply.sh": "#!/bin/sh\n"}, links=[WANT])
        crit = self.sev(res, "systemd-unit", "critical")
        self.assertTrue(crit and "apply.sh" in crit[0]["path"], res["findings"])
        self.assertEqual(res["blocking"] >= 1, True)

    def test_dropin_reset_clears_old_path_and_removing_it_restores_finding(self):
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
        files = {"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/libexec/twu/ok"), "/usr/local/libexec/twu/ok": "x", f"{HU}/bad": "x",
                 "/usr/lib/systemd/system/x.service.d/a.conf": "[Service]\nExecStartPre=/home/u/bad\n",
                 "/etc/systemd/system/x.service.d/a.conf": "[Service]\nExecStartPre=\n"}
        res = self.tree(files, links=[WANT], modes={"/usr/local/libexec/twu/ok": 0o755})
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])

    def test_permissions_world_group_owner_and_sticky(self):
        f = {"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/libexec/twu/run"), "/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o666})
        self.assertTrue(self.sev(res, "systemd-unit", "high") and res["blocking"], "world-writable file")
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu": 0o777})
        self.assertTrue(self.sev(res, "systemd-unit", "high") and res["blocking"], "world-writable parent dir")
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o664})
        self.assertTrue(self.sev(res, "systemd-unit", "medium"), "group-writable is medium")
        self.assertEqual(res["blocking"], 0, "medium must not block by default")
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o664}, fail_on="medium")
        self.assertGreater(res["blocking"], 0, "--fail-on medium blocks group-writable")
        res = self.tree(f, links=[WANT], trusted_uid=os.getuid() + 1)
        self.assertTrue(any("owned by uid" in x["why"] for x in res["findings"]) and res["blocking"], "non-root owner")
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu": 0o1757})   # sticky + other-write, not group-write
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])

    def test_group_writable_by_trusted_group_is_fine(self):
        f = {"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/libexec/twu/run"), "/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        res = self.tree(f, links=[WANT], modes={"/usr/local/libexec/twu/run": 0o664}, trusted_gid=os.getgid())
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])

    def test_unit_file_itself_and_symlinked_unit_are_checked(self):
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT],
                        modes={"/etc/systemd/system/x.service": 0o666})
        self.assertTrue([f for f in self.sev(res, "systemd-unit-file") if f["path"] == "/etc/systemd/system/x.service"], res["findings"])
        res = self.tree({f"{HU}/x.service": SVC.format(cmd="/usr/bin/true"), "/usr/bin/true": "x"},
                        links=[WANT, ("/etc/systemd/system/x.service", f"{HU}/x.service")])
        self.assertTrue(self.sev(res, "systemd-unit", "critical"), res["findings"])

    def test_interpreters_envfile_pythonpath_workingdir(self):
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
        tree = {f"{HU}/s.sh": "x", "/usr/bin/true": "x"}
        res = self.tree(dict(tree, **{"/etc/systemd/system/x.service": unit("ExecStart=/usr/bin/bash -c 'echo on > /sys/bus/pci/devices/0000:00:1e.0/power/control'")}), links=[WANT])
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])
        res = self.tree(dict(tree, **{"/etc/systemd/system/x.service": unit("User=nobody\nExecStart=/usr/bin/bash /home/u/s.sh")}), links=[WANT])
        self.assertFalse(self.sev(res, "systemd-unit"), res["findings"])
        res = self.tree(dict(tree, **{"/etc/systemd/system/x.service": unit("User=root\nExecStart=/usr/bin/bash /home/u/s.sh")}), links=[WANT])
        self.assertTrue(self.sev(res, "systemd-unit", "critical"))

    def test_empty_command_word_does_not_hang(self):
        self.assertEqual(rea.command_paths([""]), [])
        self.assertEqual(rea.command_paths(["-", "x"]), [])
        res = self.tree({"/etc/systemd/system/x.service": unit('ExecStart=""')}, links=[WANT])
        self.assertIn("findings", res)

    def test_not_enabled_unit_is_downgraded_to_high(self):
        res = self.tree({"/etc/systemd/system/y.service": SVC.format(cmd="/usr/bin/bash /home/u/s.sh"), f"{HU}/s.sh": "x"})
        self.assertTrue(self.sev(res, "systemd-unit", "high") and not self.sev(res, "systemd-unit", "critical"), res["findings"])
        self.assertGreater(res["blocking"], 0, "default --fail-on high still blocks a not-enabled trap")

    def test_other_sources_all_flagged(self):
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
        res = self.tree({"/var/spool/cron/someuser": "* * * * * /usr/bin/true\n"}, trusted_uid=os.getuid() + 1)
        self.assertFalse(self.sev(res, "cron"), res["findings"])
        res = self.tree({"/var/spool/cron/root": "* * * * * /usr/bin/true\n"}, trusted_uid=os.getuid() + 1)
        self.assertTrue(self.sev(res, "cron"), res["findings"])

    def test_ld_preload_and_profile(self):
        res = self.tree({"/etc/ld.so.conf.d/x.conf": f"{HU}/lib\n", "/etc/profile.d/x.sh": "x\n"}, dirs=[f"{HU}/lib"])
        self.assertTrue(self.sev(res, "ld.so", "critical"), res["findings"])

    def test_unreadable_sudoers_is_info_not_failure(self):
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
        res = self.tree({"/etc/systemd/system/y.service": SVC.format(cmd="/usr/bin/bash /home/u/s.sh"), f"{HU}/s.sh": "x"})
        self.assertTrue(set(res) >= {"schema", "platform", "fail_on", "findings", "blocking", "total", "checked_as_root", "sudoers_readable"})
        self.assertTrue(all(set(x) == {"severity", "kind", "source", "path", "why"} for x in res["findings"]))
        self.assertEqual(res["platform"], "linux")

    def test_deep_scan_finds_world_writable_and_foreign_owner_and_is_bounded(self):
        res = self.tree({"/etc/foo.conf": "x", "/opt/app/run": "x"}, modes={"/opt/app/run": 0o666}, deep=True)
        self.assertTrue([f for f in self.sev(res, "deep-scan", "high") if f["path"] == "/opt/app/run"], res["findings"])
        res = self.tree({"/etc/a": "x"}, trusted_uid=os.getuid() + 1, deep=True)
        self.assertTrue(self.sev(res, "deep-scan"))
        with mock.patch.object(rea, "DEEP_LIMIT", 2):
            res = self.tree({f"/etc/f{i}": "x" for i in range(6)}, trusted_uid=os.getuid() + 1, deep=True)
        self.assertEqual(len(self.sev(res, "deep-scan", "info")), 1)

    def test_symlink_loop_and_deep_chains_terminate(self):
        res = self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/local/bin/loop")}, links=[WANT, ("/usr/local/bin/loop", "/usr/local/bin/loop")])
        self.assertIn("findings", res)


    # ---- ports of the Fedora review regressions (each was a demonstrated false negative)
    @staticmethod
    def u(body, install=True):
        return "[Unit]\nDescription=t\n[Service]\n" + body + "\n" + ("[Install]\nWantedBy=multi-user.target\n" if install else "")

    def crit(self, res):
        return [f for f in res["findings"] if f["severity"] in ("critical", "high")]

    def test_v2_unit_files_themselves(self):
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
        evil = "[Service]\nExecStartPre=/home/u/evil.sh\n"
        base = {f"{HU}/evil.sh": "x", "/usr/local/libexec/twu/run": "#!/bin/sh\n"}
        for tid, unit_name, dpath in (("ty", "x.service", "/etc/systemd/system/service.d/10.conf"), ("pre", "x-y.service", "/etc/systemd/system/x-.service.d/10.conf"),
                                      ("tpl", "x@.service", "/etc/systemd/system/x@.service.d/10.conf"), ("ctl", "x.service", "/etc/systemd/system/system.control/x.service.d/10.conf".replace("system/system.control", "system.control"))):
            with self.subTest(tid):
                files = dict(base, **{"/etc/systemd/system/" + unit_name: self.u("ExecStart=/usr/local/libexec/twu/run"), dpath: evil})
                res = self.tree(files, links=[("/etc/systemd/system/multi-user.target.wants/" + unit_name, "/etc/systemd/system/" + unit_name)], modes={"/usr/local/libexec/twu/run": 0o755})
                self.assertTrue(self.crit(res) and res["blocking"], res["findings"])

    def test_v2_sockets_semicolons_and_missing_files(self):
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
        res = self.tree({"/usr/lib/systemd/system/x.service": self.u("EnvironmentFile=-/tmp/x.env\nExecStart=/usr/bin/true"), "/usr/bin/true": "x"},
                        links=[("/etc/systemd/system/x.service", "/dev/null"), WANT])
        self.assertFalse(self.crit(res), res["findings"])

    def test_v2_clean_real_looking_tree_has_no_false_positive_on_optional_hook(self):
        res = self.tree({"/etc/systemd/system/x.service": self.u("ExecStart=/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT])
        self.assertClean(res)


class TestUserLaunchers(Base):
    def test_pkexec_of_user_owned_script_is_flagged(self):
        res = self.tree({f"{HU}/.local/bin/tuned": "#!/bin/sh\npkexec /usr/bin/python3 /home/u/tool/apply.py\nexec steam\n",
                         f"{HU}/tool/apply.py": "print(1)\n", "/usr/bin/python3": ""},
                        trusted_uid=os.getuid() + 12345)
        found = self.sev(res, "elevated-launcher")
        self.assertTrue(found, res["findings"])
        self.assertTrue(any("apply.py" in f["path"] for f in found), found)

    def test_desktop_exec_sudo_is_flagged(self):
        res = self.tree({f"{HU}/.local/share/applications/x.desktop": "[Desktop Entry]\nExec=sudo /home/u/run.sh\n",
                         f"{HU}/run.sh": "id\n"}, trusted_uid=os.getuid() + 12345)
        self.assertTrue(self.sev(res, "elevated-launcher"), res["findings"])

    def test_launcher_without_elevation_is_not_flagged(self):
        res = self.tree({f"{HU}/.local/bin/plain": "#!/bin/sh\nexec steam steam://rungameid/1\n",
                         f"{HU}/.local/bin/commented": "# pkexec /home/u/x.py\n"}, trusted_uid=os.getuid() + 12345)
        self.assertFalse(self.sev(res, "elevated-launcher"), res["findings"])

    def test_pkexec_of_root_owned_copy_is_clean(self):
        res = self.tree({f"{HU}/.local/bin/tuned": "#!/bin/sh\npkexec /usr/bin/python3 /usr/local/libexec/twu/apply.py\n",
                         "/usr/local/libexec/twu/apply.py": "print(1)\n", "/usr/bin/python3": ""},
                        trusted_uid=os.getuid())
        self.assertFalse([f for f in self.sev(res, "elevated-launcher") if f["severity"] != "info"], res["findings"])


class TestMacOS(Base):
    platform = "darwin"

    @staticmethod
    def plist(**kw):
        return plistlib.dumps(dict({"Label": "com.twu.x", "ProgramArguments": ["/bin/sh", f"{TWU_MAC}/x.sh"]}, **kw))

    def good_tree(self, **plist_kw):
        return {"bytes_files": {LD: self.plist(**plist_kw)}, "files": {f"{TWU_MAC}/x.sh": "#!/bin/sh\n"}, "modes": {f"{TWU_MAC}/x.sh": 0o755}}

    def run_tree(self, spec, **kw):
        return self.tree(spec["files"], bytes_files=spec["bytes_files"], modes=spec.get("modes"), **kw)

    def test_root_owned_path_is_clean(self):
        self.assertClean(self.run_tree(self.good_tree()))

    def test_program_arguments_under_users_flagged_critical(self):
        res = self.tree({f"{UU}/bin/run.sh": "#!/bin/sh\n"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/bin/run.sh"])})
        crit = self.sev(res, "launchd-daemon", "critical")
        self.assertTrue(crit and any("run.sh" in f["path"] for f in crit), res["findings"])
        self.assertGreater(res["blocking"], 0)

    def test_program_key_and_first_argument(self):
        res = self.tree({f"{UU}/d": "x"}, bytes_files={LD: plistlib.dumps({"Label": "x", "Program": f"{UU}/d"})})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])
        res = self.tree({f"{UU}/d": "x"}, bytes_files={LD: plistlib.dumps({"Label": "x", "Program": "/bin/sh", "ProgramArguments": ["sh", f"{UU}/d"]})})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])
        res = self.tree({f"{UU}/d": "x"}, bytes_files={LD: plistlib.dumps({"Label": "x", "ProgramArguments": ["/usr/bin/python3", "-c", f"import x; x.run('{UU}/d')"]})})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])

    def test_username_non_root_is_skipped_root_is_not(self):
        args = ["/bin/sh", f"{UU}/bin/run.sh"]
        for user in ("_nobody", "ethan", "501"):
            with self.subTest(user):
                res = self.tree({f"{UU}/bin/run.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=args, UserName=user)})
                self.assertFalse(self.sev(res, "launchd-daemon"), res["findings"])
        res = self.tree({f"{UU}/bin/run.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=args, UserName="root")})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"))

    def test_environment_variables_and_working_directory(self):
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
        res = self.tree({f"{UU}/r.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/r.sh"], Disabled=True)})
        self.assertTrue(self.sev(res, "launchd-daemon", "high") and not self.sev(res, "launchd-daemon", "critical"), res["findings"])

    def test_plist_file_permissions_and_binary_format(self):
        spec = self.good_tree()
        spec["modes"][LD] = 0o666
        res = self.run_tree(spec)
        self.assertTrue([f for f in self.sev(res, "launchd-daemon", "high") if f["path"] == LD], res["findings"])
        bplist = plistlib.dumps({"Label": "x", "ProgramArguments": ["/bin/sh", f"{UU}/r.sh"]}, fmt=plistlib.FMT_BINARY)
        res = self.tree({f"{UU}/r.sh": "x"}, bytes_files={LD: bplist})
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), "binary plist not parsed")

    def test_garbled_plist_is_info_and_does_not_stop_the_audit(self):
        res = self.tree({"/Library/LaunchDaemons/bad.plist": "<<<not a plist", "/etc/periodic/daily/500x": "x"},
                        bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/r.sh"]), "/Library/LaunchDaemons/list.plist": plistlib.dumps(["a"])},
                        modes={"/etc/periodic/daily/500x": 0o666}, links=[])
        self.assertEqual(len(self.sev(res, "launchd-daemon", "info")), 2, res["findings"])
        self.assertTrue(self.sev(res, "periodic", "high"), "audit stopped after the bad plist")

    def test_periodic_usr_local_sudoers_and_twu_dir(self):
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
        spec = self.good_tree()
        spec["modes"]["/Library/Application Support"] = 0o775
        res = self.run_tree(spec)
        self.assertTrue(self.sev(res, "launchd-daemon", "medium"), res["findings"])
        self.assertEqual(res["blocking"], 0)

    def test_paths_d_and_tmp_symlink(self):
        res = self.tree({"/etc/paths.d/x": f"{UU}/bin\n", f"{UU}/bin/f": "x"})
        self.assertTrue([f for f in self.sev(res, "profile", "critical") if f["path"] == f"{UU}/bin"], res["findings"])
        res = self.tree({"/private/tmp/r.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", "/tmp/r.sh"])}, links=[("/tmp", "private/tmp")])
        self.assertTrue(self.sev(res, "launchd-daemon", "critical"), res["findings"])

    def test_platform_isolation(self):
        linux_only = {"/etc/udev/rules.d/90-x.rules": f'RUN+="{HU}/s.sh"\n', f"{HU}/s.sh": "x"}
        res = self.tree(linux_only)
        self.assertFalse(self.sev(res, "udev-rule"), "udev audited on darwin")
        res = self.tree({f"{UU}/r.sh": "x"}, bytes_files={LD: self.plist(ProgramArguments=["/bin/sh", f"{UU}/r.sh"])}, platform="linux")
        self.assertFalse(self.sev(res, "launchd-daemon"), "launchd audited on linux")
        self.assertEqual(res["platform"], "linux")

    def test_deep_scan_on_darwin(self):
        res = self.tree({"/Library/PrivilegedHelperTools/h": "x"}, modes={"/Library/PrivilegedHelperTools/h": 0o666}, deep=True)
        self.assertTrue([f for f in self.sev(res, "deep-scan", "high") if f["path"].endswith("/h")], res["findings"])


class TestCli(Base):
    def cli(self, *args, root=None, env_extra=None, platform_arg=("--platform", "linux")):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if root:
            env.update(ROOTEXEC_ROOT=str(root), ROOTEXEC_TRUSTED_UID=str(os.getuid()), ROOTEXEC_TRUSTED_GID="4242")
        env.update(env_extra or {})
        return subprocess.run([sys.executable, "-B", "-I", SCRIPT, *platform_arg, *args], capture_output=True, text=True, env=env, timeout=60, cwd=str(self.base))

    def test_exit_codes_and_json(self):
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
        self.assertEqual(self.cli("--fail-on", "bogus").returncode, 2)
        self.tree({})
        r = self.cli(root=self.root, env_extra={"ROOTEXEC_TRUSTED_UID": "abc"})
        self.assertEqual(r.returncode, 2, r.stdout)

    def test_environment_is_ignored_without_the_test_overrides_and_nothing_is_written(self):
        self.tree({"/etc/systemd/system/x.service": SVC.format(cmd="/usr/bin/true"), "/usr/bin/true": "x"}, links=[WANT])
        before = sorted(p.name for p in self.base.iterdir())
        r = self.cli("--json", env_extra={"HOME": str(self.root), "XDG_CONFIG_HOME": str(self.root), "PYTHONPATH": str(self.root)})
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertEqual(json.loads(r.stdout)["platform"], "linux")
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), before, "tool wrote into the working directory")

    def test_platform_detection(self):
        self.assertEqual(rea.detect_platform("linux"), "linux")
        self.assertEqual(rea.detect_platform("linux2"), "linux")
        self.assertEqual(rea.detect_platform("darwin"), "darwin")
        with self.assertRaises(ValueError):
            rea.detect_platform("win32")
        with mock.patch.object(rea.sys, "platform", "freebsd13"):
            self.assertEqual(rea.main(["--json"]), 2)

    def test_live_host_smoke_is_valid_json_and_fast(self):
        r = self.cli("--json", platform_arg=())
        self.assertIn(r.returncode, (0, 1), r.stderr[-300:])
        data = json.loads(r.stdout)
        self.assertIn(data["platform"], ("linux", "darwin"))


if __name__ == "__main__":
    unittest.main()
