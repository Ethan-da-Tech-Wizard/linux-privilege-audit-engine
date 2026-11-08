#!/usr/bin/env python3
"""scripts/root_exec_audit.py — Linux & macOS Root Execution Privilege Escalation Auditor.

========================================================================================
LINUX & MACOS ROOT EXECUTION PRIVILEGE ESCALATION AUDITOR & LEAST-PRIVILEGE SCANNER
========================================================================================
Architecture & Theoretical Principle:
  In modern UNIX and Linux systems, local privilege escalation (LPE) vulnerabilities
  frequently occur not through memory corruption or kernel exploits, but through subtle
  misconfigurations in execution chains executed by UID 0 (root).

  Core Axiom: "Nothing executed or sourced by root may reside in, traverse through,
  or depend upon a filesystem path that an unprivileged user can modify, replace,
  or create."

  This tool implements deterministic static analysis and filesystem auditing across:
  - systemd service units, sockets, drop-in overrides (.d/*.conf), generators, hooks
  - Sudoers privilege specifications, NOPASSWD authorizations, secure_path, and GTFOBins
  - POSIX file mode permissions, sticky bits, directory write delegation, and ACL masks
  - Dynamic linkers (/etc/ld.so.preload, /etc/ld.so.conf.d) and environment variables
  - Cron tab spool files, anacron, udev rules, DNF package hooks, and polkit policies
  - User desktop launchers (.desktop) and scripts elevating via pkexec, sudo, or doas
  - macOS launchd LaunchDaemons, PrivilegedHelperTools, periodic jobs, and paths.d

Zero-Dependency & Fail-Closed Design:
  - 100% Python Standard Library (no third-party pip dependencies).
  - Pure read-only operation: performs zero filesystem writes or modifications.
  - Fail-closed security architecture: missing permissions or malformed entries are
    flagged or downgraded safely without crashing the audit process.

Author: Ethan Kilmer <ethan@twu.software>
License: MIT
========================================================================================
"""

from __future__ import annotations

import argparse
import glob
import grp
import json
import os
import plistlib
import pwd
import re
import shlex
import stat
import struct
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Severity mappings: lower numerical values represent higher severity.
SEV = {"critical": 0, "high": 1, "medium": 2, "info": 3}

# Environment variable keys used strictly for test harness sandboxing and isolation.
ENV_ROOT, ENV_UID, ENV_GID = "ROOTEXEC_ROOT", "ROOTEXEC_TRUSTED_UID", "ROOTEXEC_TRUSTED_GID"

# Directories categorized as untrusted user or temporary storage areas on Linux.
# Files or ancestor directories within these boundaries are considered untrusted.
AREAS_LINUX = ("/home/", "/tmp/", "/var/tmp/", "/run/user/", "/dev/shm/")
AREA_ROOTS_LINUX = ("/home", "/tmp", "/var/tmp", "/run/user", "/dev/shm")

# Untrusted user or temporary storage boundaries on macOS (Darwin).
AREAS_DARWIN = ("/Users/", "/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/", "/private/var/folders/", "/Volumes/")
AREA_ROOTS_DARWIN = ("/Users", "/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/private/var/folders", "/Volumes")

# Virtual, pseudo-filesystem, and device paths skipped during traversal.
# These synthetic filesystems (/proc, /sys, /dev) are managed directly by kernel drivers.
SKIP_PREFIX = ("/proc", "/sys", "/dev", "/run/systemd", "/run/udev")

# Common command shells capable of command execution via -c flags.
SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh", "fish", "ash", "csh", "tcsh"})

# Scripting language runtimes whose script file arguments require traversal and auditing.
SCRIPTERS = frozenset({"python", "python3", "perl", "ruby", "node", "php", "awk", "gawk", "lua", "tclsh", "expect", "Rscript", "pwsh", "osascript"})

# Execution wrapper utilities that prepend options before invoking the real target binary.
WRAP = frozenset({
    "env", "flock", "nice", "ionice", "timeout", "nohup", "stdbuf", "xargs", "taskset",
    "setpriv", "chrt", "unshare", "nsenter", "runuser", "su", "systemd-run", "strace",
    "ltrace", "time", "setsid", "sg", "chroot", "numactl", "cpulimit", "caffeinate", "arch"
})

# GTFOBins catalog: Unix binaries that allow arbitrary file write, read, or shell execution.
# Granting passwordless sudo access (NOPASSWD) to any of these binaries allows immediate root escape.
GTFO = frozenset({
    "vim", "vi", "view", "nano", "less", "more", "man", "find", "awk", "gawk", "perl",
    "python", "python3", "ruby", "node", "php", "bash", "sh", "dash", "zsh", "env", "tee",
    "cp", "mv", "dd", "tar", "zip", "unzip", "rsync", "ssh", "scp", "git", "tcpdump",
    "systemctl", "journalctl", "mount", "umount", "chmod", "chown", "sed", "nmap", "docker",
    "podman", "ftp", "gdb", "ed", "emacs", "make", "nice", "timeout", "xargs", "tclsh",
    "lua", "wget", "curl", "busybox", "install", "ln", "cat", "head", "tail", "osascript"
})

# Environment variables that specify colon-delimited search paths for executables or libraries.
ENV_PATHLISTS = frozenset({
    "PATH", "PYTHONPATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "PYTHONHOME",
    "PERL5LIB", "RUBYLIB", "NODE_PATH", "PYTHONUSERBASE", "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH"
})

# Environment variables where a relative directory entry creates cwd-hijacking vulnerabilities.
ENV_RELATIVE_BAD = frozenset({
    "PATH", "PYTHONPATH", "LD_LIBRARY_PATH", "NODE_PATH", "PERL5LIB", "RUBYLIB",
    "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"
})

# Environment variables pointing to executable or sourced configuration scripts.
ENV_FILES = frozenset({"BASH_ENV", "ENV", "PYTHONSTARTUP"})

# Environment variables containing options or flags where script paths may be embedded.
ENV_SCAN = frozenset({"PERL5OPT", "NODE_OPTIONS", "RUBYOPT", "JAVA_TOOL_OPTIONS", "GCONV_PATH"})

# Systemd unit file load order and priority hierarchy (lowest to highest precedence).
# Systemd looks in vendor/distribution paths first, overridden by runtime, and lastly /etc.
UNIT_PRIO = [
    ("/usr/lib/systemd/system", 1),         # Vendor-supplied packaged unit files
    ("/lib/systemd/system", 1),              # Legacy vendor unit files
    ("/usr/local/lib/systemd/system", 2),    # Locally installed software packages
    ("/run/systemd/system", 3),              # Transient / volatile runtime units
    ("/etc/systemd/system", 4),              # System administrator custom units and overrides
    ("/run/systemd/system.control", 5),      # Dynamic transient control units (systemd-run)
    ("/etc/systemd/system.control", 6),      # Persisted control unit modifications
]

# Safety bound for deep filesystem traversal to prevent resource exhaustion.
DEEP_LIMIT = 2000

# Regular expression matching absolute file paths residing inside untrusted user or temporary areas.
USER_AREA_SCRIPT = r"(?<![\w.])(/(?:home|Users|tmp|var/tmp|private/tmp|run/user|dev/shm)/[A-Za-z0-9_.+/-]+)"


def detect_platform(name: Optional[str] = None) -> str:
    """Identify host operating system platform.
    
    Returns 'linux' or 'darwin' based on sys.platform or user override.
    Raises ValueError for unsupported platforms (e.g. Windows or BSD).
    """
    name = name or sys.platform
    if name.startswith("linux"):
        return "linux"
    if name == "darwin":
        return "darwin"
    raise ValueError(f"unsupported platform {name!r}: this audit knows Linux and macOS")


# ------------------------------------------------------------------ Pure Helpers
def split_command(line: str) -> List[str]:
    """Parse a command line string into arguments respecting quotes and whitespace.
    
    Uses POSIX shell lexing (shlex.split). Falls back to standard str.split() if the
    command string contains unclosed quotes or syntax errors, ensuring the scanner
    never crashes on hostile or malformed command specifications.
    """
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def expand(tok: str, env: Dict[str, str]) -> str:
    """Expand environment variable references (${VAR} or $VAR) using provided mapping.
    
    If the variable is not defined in the environment dictionary, preserves the token
    intact rather than replacing it with an empty string, avoiding accidental masking.
    """
    return re.sub(r"\$\{?(\w+)\}?", lambda m: env.get(m.group(1), m.group(0)), tok)


def string_commands(text: str, depth: int = 0, env: Optional[Dict[str, str]] = None) -> List[Tuple[str, bool]]:
    """Extract and parse executable commands embedded within shell execution strings (e.g. sh -c '...').
    
    Splits compound shell expressions across pipeline and conditional operators (&&, ||, ;, |, &).
    Strips shell control flow keywords (if, then, exec, while) and leading environment variable
    assignments (KEY=val) to isolate the true executable command word.
    """
    out: List[Tuple[str, bool]] = []
    # Tokenize command string by control flow and pipeline delimiters
    for part in re.split(r"&&|\|\||[;|&\n]", text):
        part = part.strip().strip("(){}")
        if not part:
            continue
        # Drop shell I/O redirections (e.g. >/dev/null, 2>&1, <input)
        toks = [t for t in split_command(part) if not re.match(r"^\d*[<>]", t)]
        # Consume leading variable assignments (FOO=bar) and shell keywords
        while toks and (re.match(r"^[A-Za-z_]\w*=", toks[0]) or toks[0] in ("if", "then", "else", "elif", "do", "while", "until", "exec", "!", "time", "command")):
            toks = toks[1:]
        out += command_paths(toks, depth + 1, env)
    return out


def command_paths(argv: List[str], depth: int = 0, env: Optional[Dict[str, str]] = None) -> List[Tuple[str, bool]]:
    """Traverse an argv command array and extract all executable paths and referenced scripts.
    
    ====================================================================================
    SYSTEMD EXECSTART & WRAPPER PARSING ALGORITHM
    ====================================================================================
    Line-by-line breakdown of command resolution:
    1. Depth Guard: Recursion depth is capped at 6 to prevent infinite recursion on
       nested wrapper chains (e.g. env -> timeout -> nice -> bash -> python).
    2. Systemd Prefix Stripping: Systemd ExecStart command strings permit specific execution
       modifier prefixes in the first argument:
         '-' : Ignore exit code (failure does not cause unit failure).
         '@' : Passed argument serves as argv[0] to the process.
         '+' : Run with full root privileges even if User= is specified!
         '!' : Run with elevated credentials / ambient capabilities.
         ':' : Disable environment variable substitution.
       These prefix characters are stripped to expose the actual filesystem path.
    3. Variable Expansion: If an environment dictionary is provided, variable tokens
       like $BINDIR or ${APP_PATH} are expanded.
    4. Interpreter & Shell Analysis:
       - If the command invokes a shell (bash, sh, etc.) with -c, recursively parses
         the inline command string via string_commands().
       - If the command invokes a script interpreter (python, perl, node, etc.), inspects
         the arguments for script file paths or inline script references (-c, -e).
       - If the command is a wrapper tool (env, timeout, chroot, etc.), skips flags and
         unwraps the nested target executable.
    ====================================================================================
    Returns: List of tuples [(path, strict)]:
      - path: Absolute or relative executable path.
      - strict: Boolean indicating whether missing file creation should be flagged.
    """
    out: List[Tuple[str, bool]] = []
    if not argv or depth > 6:
        return out
    argv = list(argv)

    # Step 2: Strip systemd execution modifier prefixes (-@+!:) from argv[0]
    while argv and argv[0] and argv[0][:1] in "-@+!:":
        argv[0] = argv[0][1:]
    if not argv or not argv[0]:
        return out

    # Step 3: Expand environment variables in argument list
    if env:
        argv = [expand(a, env) for a in argv]
    exe = argv[0]
    base = os.path.basename(exe)

    # If the executable specifies an absolute or relative directory path, register it
    if exe.startswith("/") or "/" in exe:
        out.append((exe, True))

    # Step 4a: Handle shell execution (e.g. /bin/bash -c "cmd")
    if base in SHELLS:
        i = 1
        while i < len(argv):
            a = argv[i]
            # Match shell -c or combined option flags like -ec or -xce
            if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a):
                if i + 1 < len(argv):
                    out += string_commands(argv[i + 1], depth, env)
                break
            if a.startswith("-"):
                i += 1
                continue
            # Shell script path passed as positional argument (e.g. bash /path/to/script.sh)
            if "/" in a:
                out.append((a, True))
            break

    # Step 4b: Handle script interpreters (python, perl, ruby, node, etc.)
    elif base in SCRIPTERS:
        i = 1
        while i < len(argv):
            a = argv[i]
            # Check for inline evaluation flags (-c, -e, -E, -r, -f)
            if a in ("-c", "-e", "-E", "-r", "-f"):
                if a == "-f" and i + 1 < len(argv):
                    out.append((argv[i + 1], True))
                    break
                # Extract any file paths referenced inside inline script strings
                for pth in re.findall(USER_AREA_SCRIPT, " ".join(argv[i + 1:])):
                    out.append((pth, False))  # Flag inline references if in user/temp areas
                break
            if a.startswith("-"):
                i += 1
                continue
            # Position argument is the script file path (e.g. python3 /app/main.py)
            if "/" in a:
                out.append((a, True))
            break

    # Step 4c: Handle execution wrapper utilities (env, timeout, nice, flock, etc.)
    elif base in WRAP:
        i = 1
        while i < len(argv):
            a = argv[i]
            # Skip wrapper flags, hexadecimal masks, and environment assignments (KEY=VAL)
            if a.startswith("-") or re.fullmatch(r"(0x)?[0-9a-fA-F,.:-]+", a) or ("=" in a and not a.startswith("/")):
                # Options taking mandatory arguments (e.g. timeout -k 5s, nice -n 10)
                if a in ("-n", "-p", "-u", "-g", "-c", "-t", "-s", "-k", "-d") and i + 1 < len(argv) and not argv[i + 1].startswith("/"):
                    i += 2
                else:
                    i += 1
                continue
            # Unwrapped target command reached: recurse with incremented depth
            out += command_paths(argv[i:], depth + 1, env)
            break
    return out


def dropin_dir_names(name: str) -> List[str]:
    """Calculate all valid drop-in override directory names for a systemd unit name.
    
    Systemd drop-in override semantics support multiple levels of configuration layering:
    1. Exact unit drop-in: <name>.d (e.g. sshd.service.d)
    2. Template instance drop-in: If the unit is an instantiation (e.g. user@1000.service),
       the base template drop-in user@.service.d is also loaded.
    3. Hierarchical prefix drop-in: Hyphen-separated prefixes define inheritance
       (e.g. system-myservice.service loads system-.service.d).
    4. Type-wide drop-in: Applies to all units of that type (e.g. service.d).
    """
    names = [name + ".d"]
    stem, _dot, typ = name.rpartition(".")
    if "@" in stem:
        names.append(stem.split("@")[0] + "@." + typ + ".d")
    parts = stem.split("-")
    for i in range(1, len(parts)):
        names.append("-".join(parts[:i]) + "-." + typ + ".d")
    names.append(typ + ".d")
    return names


def parse_unit(texts: List[str]) -> Dict[str, List[str]]:
    """Parse systemd unit file contents into structured key-value directive lists.
    
    ====================================================================================
    SYSTEMD CONFIGURATION DIRECTIVE PARSING & RESET SEMANTICS
    ====================================================================================
    Line-by-line parsing behavior:
    1. Line Continuation Unfolding: Systemd supports backslash line continuation (`\\\n`).
       These are replaced with whitespace to reconstruct single logical directives.
    2. Comments and Section Filtering: Lines beginning with '#' or ';' are comment lines.
       Section headers ('[Service]', '[Unit]') are skipped.
    3. Empty Assignment Reset Semantics (Crucial Security Invariant):
       In systemd configuration syntax, assigning an empty value to an accumulation list
       directive (e.g. `ExecStart=`) completely clears all previously parsed values!
       Example:
         Vendor unit has: `ExecStart=/usr/bin/daemon`
         Admin drop-in has:
           `ExecStart=`                 <-- Resets the command list to empty!
           `ExecStart=/opt/bin/daemon`   <-- Defines the new active command.
       Failing to model this reset semantics results in false-positive alerts on overridden
       vendor paths, or worse, false negatives if the replacement command is untrusted.
    ====================================================================================
    """
    d: Dict[str, List[str]] = {}
    for txt in texts:
        # Step 1: Unfold backslash-continued lines into single logical lines
        for ln in txt.replace("\\\n", " ").splitlines():
            ln = ln.strip()
            # Step 2: Skip empty lines, comment lines, section brackets, and non-assignments
            if not ln or ln[0] in "#;[" or "=" not in ln:
                continue
            k, v = (x.strip() for x in ln.split("=", 1))
            # Track execution directives, environment settings, and working directory
            if k.startswith("Exec") or k in ("EnvironmentFile", "WorkingDirectory", "Environment", "User", "RootDirectory", "RootImage"):
                # Step 3: Implement empty assignment reset semantics
                if v == "":
                    d[k] = []  # Clear previous directives for this key
                else:
                    d.setdefault(k, []).append(v)
    return d


def _group_has_members(name: str) -> Optional[List[str]]:
    """Determine all non-root user accounts that are members of a given group.
    
    Queries both:
    1. Secondary / supplementary group members via grp.getgrnam().gr_mem.
    2. Primary group members via pwd.getpwall() where pw_gid matches gr_gid.
    Excludes root and system service accounts (UID < 500) to isolate human users.
    """
    try:
        g = grp.getgrnam(name)
    except KeyError:
        return None
    members = {m for m in g.gr_mem if m != "root"}
    members |= {u.pw_name for u in pwd.getpwall() if u.pw_gid == g.gr_gid and u.pw_name != "root" and u.pw_uid >= 500}
    return sorted(members)


# ------------------------------------------------------------------ The Auditor
class Auditor:
    """Privilege escalation and file permission security auditor.
    
    Performs deterministic inspection of filesystem permissions, systemd service units,
    sudoers privilege rules, dynamic linker configurations, and execution launchers.
    """

    def __init__(self, root: str = "/", trusted_uid: int = 0, trusted_gid: int = 0, platform: Optional[str] = None, is_root: Optional[bool] = None):
        self.root = (root or "/").rstrip("/") or "/"
        self.tuid, self.tgid = int(trusted_uid), int(trusted_gid)
        self.platform = detect_platform(platform)
        mac = self.platform == "darwin"
        self.areas = AREAS_DARWIN if mac else AREAS_LINUX
        self.area_roots = AREA_ROOTS_DARWIN if mac else AREA_ROOTS_LINUX
        self.first_user_uid = 500 if mac else 1000
        self.is_root = (os.geteuid() == 0) if is_root is None else is_root
        self.findings: List[Dict[str, str]] = []
        self.sudoers_readable = False
        self._cache: Dict[str, List[Tuple[str, str]]] = {}

    # -------------------------------------------------------------- Path Plumbing
    def P(self, p: str) -> str:
        """Map a system absolute path into the audit root (supports fake test filesystems)."""
        return os.path.join(self.root, p.lstrip("/")) if self.root != "/" else p

    def unP(self, real: str) -> str:
        """Inverse mapping: strip the fake root prefix to restore true system path names."""
        if self.root != "/" and real.startswith(self.root):
            return real[len(self.root):] or "/"
        return real

    def add(self, sev: str, kind: str, source: str, path: str, why: str) -> None:
        """Record an audit finding with severity, category, source entity, and explanation."""
        self.findings.append({"severity": sev, "kind": kind, "source": source, "path": path, "why": why})

    def exists(self, p: str) -> bool:
        """Check if path exists using lexists (does not follow broken terminal symlinks)."""
        return os.path.lexists(self.P(p))

    def read(self, p: str) -> str:
        """Read text content of an absolute file path; returns empty string on any OS error."""
        try:
            with open(self.P(p), errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""

    def glob(self, pattern: str) -> List[str]:
        """Return sorted absolute root-relative matching paths for a glob pattern."""
        return sorted(self.unP(m) for m in glob.glob(self.P(pattern)))

    # -------------------------------------------------------------- Path Risk & Permissions
    def acl_writers(self, real_path: str) -> List[str]:
        """Extract user or group IDs with effective write permissions via POSIX Extended ACLs.
        
        ====================================================================================
        POSIX ACL EXTENDED ATTRIBUTE PARSING & BITWISE MASKING
        ====================================================================================
        Line-by-line operation:
        1. Retrieval: Reads extended attribute 'system.posix_acl_access' without following
           symlinks via os.getxattr(..., follow_symlinks=False).
        2. Binary Struct Unpacking: The Linux kernel encodes ACL entries as a binary stream:
           Header: 4-byte version (0x0002).
           Entries: 8-byte structures unpacked with format '<HHI' (little-endian):
             - tag (uint16): ACL entry type:
                 0x01 = ACL_USER_OBJ  (owning user)
                 0x02 = ACL_USER      (named individual user)
                 0x04 = ACL_GROUP_OBJ (owning group)
                 0x08 = ACL_GROUP     (named group)
                 0x10 = ACL_MASK      (effective permissions mask for named users/groups)
                 0x20 = ACL_OTHER     (other/world permissions)
             - perm (uint16): Permission bits:
                 0x04 = Read (r)
                 0x02 = Write (w)
                 0x01 = Execute (x)
             - idv (uint32): User ID (UID) or Group ID (GID) associated with the entry.
        3. Effective Rights Mask Calculation:
           If an ACL_MASK entry (tag 0x10) is present, its perm bits restrict the maximum
           effective permissions for all named users and groups.
           Defaults to 7 (rwx = 0b111) if no mask entry is defined.
        4. Effective Write Permission Evaluation:
           Evaluates: (p & mask & 2) != 0
             - 'p & mask': Bitwise AND of entry permissions with ACL mask calculates effective perms.
             - '& 2': Bitwise AND with 0x02 (write bit). If non-zero, effective write is granted!
           Checks if the granted UID or GID does not equal the trusted root UID/GID.
        ====================================================================================
        """
        try:
            raw = os.getxattr(real_path, "system.posix_acl_access", follow_symlinks=False)  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            return []
        # Unpack 8-byte ACL entries starting after the 4-byte version header
        ents = [struct.unpack("<HHI", raw[i:i + 8]) for i in range(4, len(raw) - 7, 8)]
        # Locate ACL_MASK entry (tag 0x10) to determine effective permission mask
        mask = next((p for t, p, _ in ents if t == 0x10), 7)
        out = []
        for t, p, idv in ents:
            # Tag 2 = ACL_USER (named user). Check if (perm & mask & 2) grants effective write access
            if t == 2 and (p & mask & 2) and idv != self.tuid:
                out.append(f"user {idv}")
            # Tag 8 = ACL_GROUP (named group). Check if (perm & mask & 2) grants effective write access
            elif t == 8 and (p & mask & 2) and idv != self.tgid:
                out.append(f"group {idv}")
        return out

    def walk_nodes(self, path: str) -> Tuple[List[Tuple[str, Optional[os.stat_result]]], str]:
        """Emulate Linux kernel VFS pathname resolution across symlinks and parent directory links.
        
        Security Significance:
          Standard os.path.realpath() resolves symlinks but does NOT audit the intermediate
          symlinks or parent directories themselves. If /usr/local/bin/tool is root-owned,
          but /usr/local/bin is world-writable, an attacker simply renames 'tool' and places
          a malicious binary at that path.
        
        Algorithm:
          - Iterates path components sequentially from root.
          - Tracks physical parent directory hierarchy via stack ('..' pops stack).
          - Dereferences symlinks using os.readlink() without executing outside Python.
          - Bounds symlink recursion at 40 traversals (matching Linux kernel MAXSYMLINKS).
          - Returns tuple of (inspected_nodes, resolved_final_path).
        """
        nodes: List[Tuple[str, Optional[os.stat_result]]] = []
        stack: List[str] = []
        loops = 0
        queue = [c for c in path.split("/") if c]
        while queue:
            comp = queue.pop(0)
            if comp == ".":
                continue
            if comp == "..":
                if stack:
                    stack.pop()
                continue
            cur = "/" + "/".join(stack + [comp])
            try:
                st = os.lstat(self.P(cur))
            except OSError:
                # Path node does not exist: record missing node and remaining path components
                nodes.append((cur, None))
                for c in queue:
                    nodes.append(("/" + "/".join(stack + [comp, c]), None))
                break
            nodes.append((cur, st))
            # If the current node is a symlink, dereference and prepend target components
            if stat.S_ISLNK(st.st_mode):
                loops += 1
                if loops > 40:  # Kernel MAXSYMLINKS loop cutoff
                    break
                try:
                    tgt = os.readlink(self.P(cur))
                except OSError:
                    break
                # If target is absolute, reset stack to root; otherwise resolve relative to parent
                if tgt.startswith("/"):
                    stack = []
                queue = [c for c in tgt.split("/") if c] + queue
            else:
                stack.append(comp)
        return nodes, "/" + "/".join(stack)

    def risk(self, path: str) -> List[Tuple[str, str]]:
        """Evaluate privilege escalation risks across a filesystem path and all its ancestors.
        
        ====================================================================================
        FILE MODE BITWISE OPERATIONS & PERMISSION VULNERABILITY AUDITING
        ====================================================================================
        Line-by-line inspection of stat mode bits (st.st_mode):
        1. User/Temporary Area Location:
           Checks if any ancestor node resides within /home, /tmp, /var/tmp, or /run/user.
           Execution from user or temporary space is inherently Critical severity.
        2. UID Ownership Verification:
           `st.st_uid != self.tuid`:
           Checks whether the file or directory is owned by non-root UID. If UID >= 1000
           (or >= 500 on macOS), it belongs to an unprivileged human user (Critical).
           If UID < 1000, it belongs to an unprivileged system daemon service account (High).
        3. Bitwise Mode Masking on Regular Files & Directories (stat.S_ISLNK is skipped):
           Symlink mode bits on Linux are always 0777 (lrwxrwxrwx) and ignored by the kernel;
           permissions are enforced on the target file and containing directory.
           - World-Writable Bitwise Test:
             `m & 0o002 and not (stat.S_ISDIR(m) and m & 0o1000)`:
             - `0o002` (stat.S_IWOTH): Tests the "others write" permission bit.
             - `stat.S_ISDIR(m)`: Bitwise check `(m & 0o170000) == 0o040000` for directory type.
             - `0o1000` (stat.S_ISVTX): Tests the "sticky bit" (restricted deletion flag).
             Why this is a critical security distinction:
               On a directory, the sticky bit prevents unprivileged users from deleting or
               renaming files they do not own (e.g. /tmp). If a directory is world-writable
               (`m & 0o002`) WITHOUT the sticky bit, ANY user can delete, rename, or swap
               root-owned files located inside it!
           - Group-Writable Bitwise Test:
             `m & 0o020 and st.st_gid != self.tgid`:
             - `0o020` (stat.S_IWGRP): Tests the "group write" permission bit.
             - If group write is enabled and the owning GID is not the trusted root GID,
               any user belonging to that secondary group can overwrite the executable.
           - Extended Access Control List (ACL) Test:
             `if m & 0o070: ... acl_writers(...)`:
             - `0o070` (stat.S_IRWXG): Group permission mask (read, write, execute).
               Under Linux POSIX ACLs, when an extended ACL is present, the st_mode group bits
               store the ACL mask rather than the owning group permissions! If group permissions
               are non-zero, queries acl_writers() to unpack binary ACLs and verify if named
               users or groups have write privileges.
        ====================================================================================
        """
        if path in self._cache:
            return self._cache[path]
        reasons: List[Tuple[str, str]] = []
        nodes, final = self.walk_nodes(os.path.normpath(path) if ".." not in path.split("/") else path)
        for node, st in nodes:
            # Skip pseudo-filesystems managed by kernel drivers (/proc, /sys, /dev/null)
            if node.startswith(SKIP_PREFIX):
                continue
            # Check if path node resides in user or temporary storage areas
            if (node + "/").startswith(self.areas) and node not in self.area_roots:
                reasons.append(("critical", f"{node} lives in a user/temporary area"))
            if st is None:
                continue
            m = st.st_mode

            # Step 2: Ownership verification (UID comparison)
            if st.st_uid != self.tuid:
                reasons.append(("critical" if st.st_uid >= self.first_user_uid else "high", f"{node} is owned by uid {st.st_uid} (not root)"))

            # Step 3: Bitwise permission analysis (ignoring symlink mode bits)
            if not stat.S_ISLNK(m):
                # Check for world-writable permissions without sticky bit protection
                if m & 0o002 and not (stat.S_ISDIR(m) and m & 0o1000):
                    reasons.append(("high", f"{node} is world-writable ({oct(m & 0o7777)})"))
                # Check for group-writable permissions by untrusted GID
                if m & 0o020 and st.st_gid != self.tgid:
                    reasons.append(("medium", f"{node} is group-writable by gid {st.st_gid}"))
                # Check for POSIX ACL write permissions when group bits indicate mask presence
                if m & 0o070:
                    for who in self.acl_writers(self.P(node)):
                        reasons.append(("high", f"{node} has an ACL entry giving {who} write access"))

        # Check if the final dereferenced target path lands in a user/temp directory
        if final.startswith(self.areas) and final not in self.area_roots:
            reasons.append(("critical", f"{final} (resolved) lives in a user/temporary area"))

        # Deduplicate findings while preserving priority order
        out: List[Tuple[str, str]] = []
        keys: set = set()
        for sev, why in reasons:
            if why not in keys:
                keys.add(why)
                out.append((sev, why))
        self._cache[path] = out
        return out

    def check_path(self, kind: str, source: str, path: str, why_used: str, strict_missing: bool = True) -> None:
        """Audit a single target filesystem path against all privilege escalation risks.
        
        Parameters:
          - strict_missing: If True, flags non-existent paths located in user-writable directories.
            This prevents 'phantom file' attacks where root executes an optional hook that
            an unprivileged user can create on demand.
        """
        if not path or not path.startswith("/") or path.startswith(SKIP_PREFIX) or "%" in path or "$" in path:
            return
        existing = self.exists(path)
        if not existing and not strict_missing:
            return
        for sev, why in sorted(self.risk(path), key=lambda r: SEV[r[0]]):
            self.add(sev, kind, source, path, f"{why_used}: {why}" + ("" if existing else " (does not exist yet: a user could create it)"))

    def check_files(self, kind: str, label: str, patterns: Iterable[str], why: str) -> None:
        """Audit existing filesystem files and their parent directories across glob patterns."""
        for pat in patterns:
            for f in self.glob(pat):
                if os.path.isdir(self.P(f)) and not os.path.islink(self.P(f)):
                    continue
                self.check_path(kind, f"{label} {os.path.basename(f)}", f, why, strict_missing=False)

    def check_command(self, kind: str, source: str, argv: List[str], why: str, env: Optional[Dict[str, str]] = None) -> None:
        """Audit command arguments by extracting executables, scripts, and unwrapped binaries."""
        for pth, strict in command_paths(argv, env=env):
            self.check_path(kind, source, pth, why, strict_missing=strict)

    def check_env(self, kind: str, src: str, env: Dict[str, str], who: str) -> None:
        """Audit environment variable definitions for path injection or relative directory risks."""
        for k, v in env.items():
            if k in ENV_PATHLISTS:
                for pth in re.split(r"[:\s]+", v):
                    if not pth:
                        continue
                    if not pth.startswith("/"):
                        if k in ENV_RELATIVE_BAD:
                            self.add("high", kind, src, pth, f"{k} has a relative entry: it resolves against the working directory")
                        continue
                    self.check_path(kind, src, pth, f"{k} entry for a root {who}")
            elif k in ENV_FILES:
                self.check_path(kind, src, v, f"{k} is sourced/run by a root {who}")
            elif k in ENV_SCAN:
                for pth in re.findall(r"(/[A-Za-z0-9_.+/-]+)", v):
                    self.check_path(kind, src, pth, f"{k} loads it in a root {who}", strict_missing=False)

    # -------------------------------------------------------------- Systemd Auditing
    def units(self) -> Dict[str, Tuple[str, List[str]]]:
        """Discover and resolve all systemd services and sockets across priority search paths.
        
        Merges base unit files and all corresponding drop-in configuration snippets (.conf).
        Resolves unit naming collisions using systemd precedence hierarchy (UNIT_PRIO).
        """
        names: Dict[str, List[Tuple[int, str]]] = {}
        for base, pr in UNIT_PRIO:
            for typ in ("service", "socket"):
                for f in self.glob(f"{base}/*.{typ}"):
                    names.setdefault(os.path.basename(f), []).append((pr, f))
        out: Dict[str, Tuple[str, List[str]]] = {}
        for name, files in sorted(names.items()):
            main = max(files)[1]  # Select unit file from highest-priority directory
            drops: Dict[str, str] = {}
            for dn in dropin_dir_names(name):
                for base, _pr in sorted(UNIT_PRIO, key=lambda x: x[1]):
                    for f in self.glob(f"{base}/{dn}/*.conf"):
                        drops[os.path.basename(f)] = f
            out[name] = (main, [drops[k] for k in sorted(drops)])
        # Instance-specific drop-ins of template units (e.g. user@1000.service.d)
        for base, _pr in UNIT_PRIO:
            for d in self.glob(f"{base}/*@*.d"):
                dn = os.path.basename(d)
                m = re.match(r"^(.+)@([^.]+)\.(service|socket)\.d$", dn)
                if m and m.group(2) and f"{m.group(1)}@.{m.group(3)}" in out:
                    out[f"{m.group(1)}@.{m.group(3)}"][1].extend(self.glob(f"{d}/*.conf"))
        return out

    def audit_units(self) -> None:
        """Comprehensive audit of systemd service and socket units.
        
        Audits:
        1. Enablement symlinks (/etc/systemd/system/*.wants/* and *.requires/*).
        2. Unit file and drop-in file permissions (read by systemd as UID 0).
        3. ExecStart, ExecStartPre, ExecStartPost, ExecStop commands and prefix operators.
        4. EnvironmentFile configuration paths.
        5. WorkingDirectory configuration (relative path hijacking).
        6. Environment variables (PATH, PYTHONPATH, LD_PRELOAD).
        """
        wants = set()
        for lnk in self.glob("/etc/systemd/system/*.wants/*") + self.glob("/etc/systemd/system/*.requires/*"):
            wants.add(os.path.basename(lnk))
            self.check_path("systemd-unit", f"enablement link {os.path.basename(lnk)}", lnk, "an enablement link in /etc/systemd/system", strict_missing=False)
        for name, (main, drops) in self.units().items():
            has_install = "[Install]" in self.read(main)
            # Units with no [Install] section are static and activated by sockets or dependencies
            enabled = name in wants or name.replace(".socket", ".service") in wants or not has_install
            src = f"unit {name}" + ("" if enabled else " (installed, not enabled)")
            before = len(self.findings)
            # Audit permissions of the unit file and drop-in configuration snippets
            for f in [main] + drops:
                self.check_path("systemd-unit-file", src, f, "systemd reads this unit file/drop-in as root", strict_missing=False)
            d = parse_unit([self.read(f) for f in [main] + drops])
            user = (d.get("User") or [""])[-1]
            unpriv = bool(user) and user not in ("root", "0") and not user.startswith("%")
            env: Dict[str, str] = {}
            for e in d.get("Environment", []):
                for kv in split_command(e):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        env[k] = v
            # Audit all Exec* execution directives
            for key in [k for k in d if k.startswith("Exec")]:
                for line in d[key]:
                    cmds: List[List[str]] = []
                    cur: List[str] = []
                    # Semicolons separate multiple commands in systemd Exec directives
                    for w in split_command(line):
                        if w == ";":
                            cmds.append(cur)
                            cur = []
                        else:
                            cur.append(w)
                    cmds.append(cur)
                    for argv in cmds:
                        if not argv:
                            continue
                        prefixes = set(re.match(r"^[-@+!:]*", argv[0]).group(0))  # type: ignore[union-attr]
                        # If User= is non-root, commands run unprivileged UNLESS prefixed with '+' or '!'
                        if unpriv and not ({"+", "!"} & prefixes):
                            continue
                        self.check_command("systemd-unit", src, argv, f"{key} runs it as root", env=env)
            # Audit EnvironmentFile paths
            for ef in d.get("EnvironmentFile", []):
                for tok in split_command(ef):
                    tok = tok.lstrip("-")
                    for g in (self.glob(tok) if "*" in tok else [tok]):
                        self.check_path("systemd-unit", src, g, "EnvironmentFile is read by root")
            # Audit WorkingDirectory paths
            for wd in d.get("WorkingDirectory", []):
                if wd.startswith("/"):
                    self.check_path("systemd-unit", src, wd.lstrip("-"), "WorkingDirectory of a root service (relative imports/scripts)")
            # Audit service environment variables
            self.check_env("systemd-unit", src, env, "service")
            # Downgrade critical findings to high if the unit is not enabled (less urgent trap)
            if not enabled:
                for f in self.findings[before:]:
                    if f["severity"] == "critical":
                        f["severity"] = "high"

    def audit_generators(self) -> None:
        """Audit systemd generator binaries, power management sleep hooks, and shutdown hooks."""
        for d in ("/etc/systemd/system-generators", "/usr/local/lib/systemd/system-generators", "/run/systemd/system-generators", "/usr/lib/systemd/system-generators",
                  "/etc/systemd/system-sleep", "/usr/lib/systemd/system-sleep", "/usr/local/lib/systemd/system-sleep", "/etc/systemd/system-shutdown",
                  "/usr/lib/systemd/system-shutdown", "/usr/local/lib/systemd/system-shutdown"):
            for f in self.glob(d + "/*"):
                self.check_path("systemd-hook", f"{os.path.basename(d)} {os.path.basename(f)}", f, "run by systemd as root (generator / sleep / shutdown hook)", strict_missing=False)

    # -------------------------------------------------------------- Linux Privilege Sources
    def audit_udev(self) -> None:
        """Audit udev hardware event rules for root RUN/PROGRAM executable triggers."""
        for d in ("/etc/udev/rules.d", "/usr/lib/udev/rules.d", "/usr/local/lib/udev/rules.d", "/run/udev/rules.d"):
            for f in self.glob(d + "/*.rules"):
                src = f"udev {os.path.basename(f)}"
                self.check_path("udev-rule", src, f, "udev rules files are read by root", strict_missing=False)
                for m in re.finditer(r'(?:RUN(?:\{program\})?\s*\+?=|PROGRAM\s*=|IMPORT\{program\}\s*=)\s*"([^"]+)"', self.read(f)):
                    self.check_command("udev-rule", src, split_command(m.group(1)), "RUN/PROGRAM executes it as root on device events")

    def audit_dnf(self) -> None:
        """Audit DNF / libdnf5 package manager plugins and post-transaction action hooks."""
        for f in self.glob("/etc/dnf/libdnf5-plugins/*/*") + self.glob("/etc/dnf/plugins/*"):
            if os.path.isdir(self.P(f)):
                continue
            self.check_path("dnf-plugin", f"dnf {os.path.basename(f)}", f, "dnf plugin configuration is read by root", strict_missing=False)
            if f.endswith(".actions"):
                for ln in self.read(f).splitlines():
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    cmd = ln.split(":", 3)[-1]
                    found = command_paths(split_command(cmd)) or [(p, False) for p in re.findall(r"(/[A-Za-z0-9_.+/-]+)", cmd)]
                    for pth, strict in found:
                        self.check_path("dnf-plugin", f"dnf actions {os.path.basename(f)}", pth, "runs as root during package transactions", strict_missing=strict)

    def audit_cron(self) -> None:
        """Audit system crontab, cron spools, cron.d drop-ins, and anacrontab."""
        if self.platform == "darwin":
            spools = ["/usr/lib/cron/tabs/root", "/var/at/tabs/root"]
            system = ["/etc/crontab"]
            patterns = ["/etc/crontab"] + spools
        else:
            spools = ["/var/spool/cron/root"]
            system = ["/etc/crontab"] + self.glob("/etc/cron.d/*")
            patterns = ["/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*", "/etc/anacrontab"] + spools
        self.check_files("cron", "cron", patterns, "executed by cron as root")
        for f in system + spools:
            is_spool = f in spools
            for ln in self.read(f).splitlines():
                s = ln.strip()
                if not s or s.startswith("#") or "=" in s.split()[0]:
                    continue
                w = s.split(None, 6)
                if w[0].startswith("@"):
                    cmd = " ".join(w[2:]) if not is_spool and len(w) > 2 and w[1] == "root" else " ".join(w[1:])
                    user_ok = is_spool or (len(w) > 2 and w[1] == "root")
                elif is_spool:
                    parts = s.split(None, 5)
                    cmd = parts[5] if len(parts) > 5 else ""
                    user_ok = True
                else:
                    if len(w) < 7:
                        continue
                    cmd, user_ok = w[6], w[5] == "root"
                if user_ok:
                    self.check_command("cron", f"cron {os.path.basename(f)}", split_command(cmd), "cron job runs it as root")
        for ln in self.read("/etc/anacrontab").splitlines():
            w = ln.split(None, 3)
            if len(w) == 4 and not ln.lstrip().startswith("#") and "=" not in w[0]:
                self.check_command("cron", "anacron", split_command(w[3]), "anacron job runs it as root")

    def audit_sudoers(self) -> None:
        """Comprehensive security audit of /etc/sudoers and /etc/sudoers.d/* drop-in files.
        
        ====================================================================================
        SUDOERS LEXING, PRIVILEGE SPECIFICATION & GTFOBINS DETECTION
        ====================================================================================
        Line-by-line breakdown of sudoers parsing:
        1. Readability & Permission Check:
           If /etc/sudoers cannot be read (unprivileged user without sudo rights), records
           an informative 'info' finding rather than failing silently or assuming clean.
        2. Recursive Include Queue:
           Supports both `#include` and modern `@include` directives, as well as directory
           inclusions (`#includedir` / `@includedir`).
           In drop-in directories, ignores files containing '.' (e.g. .rpmnew, .bak) or ending
           with '~' (editor swap files), precisely mirroring sudo's internal include rules.
        3. Alias and Defaults Filtering:
           Skips Alias definitions (User_Alias, Host_Alias, Cmnd_Alias) while extracting
           secure_path configurations from `Defaults` lines.
           If secure_path includes user-writable directories, commands executed under sudo
           can be hijacked by placing malicious executables in those directories.
        4. User Privilege Specification & NOPASSWD Detection:
           Splits specification lines: `who = s.split()[0]`, `rhs = s.split("=", 1)[-1]`.
           - Unrestricted Sudo Access: Matches `NOPASSWD: ALL` for any user other than root.
             If granted to a group (`%group`), resolves group members via _group_has_members()
             and flags as High severity privilege escalation vulnerability.
           - GTFOBins Privilege Escalation:
             Inspects binaries permitted under NOPASSWD against the GTFO catalog.
             Binaries like vi, find, python, awk, less, and tar allow immediate escape to
             an interactive root shell or arbitrary file modification.
           - Wildcard Argument Traversal:
             Matches `*` wildcards in NOPASSWD command specifications (Medium severity).
             Command line wildcards allow attackers to append arbitrary flags or path parameters
             (e.g. sudo /usr/bin/cat /var/log/* can be called as cat /var/log/../../etc/shadow).
           - Executable Path Integrity:
             Extracts all absolute filesystem paths from rhs and verifies their ownership,
             symlinks, parent directories, and ACL permissions.
        ====================================================================================
        """
        files = [f for f in ["/etc/sudoers"] + self.glob("/etc/sudoers.d/*") if os.path.isfile(self.P(f)) and os.access(self.P(f), os.R_OK)]
        self.sudoers_readable = bool(files)
        # Step 1: Handle unreadable sudoers files gracefully with informative finding
        if not files:
            self.add("info", "sudoers", "sudoers", "/etc/sudoers*", "not readable as this user: run the root-owned installed copy with sudo to audit NOPASSWD entries")
            return

        # Step 2: Initialize include resolution queue
        queue = list(files)
        seen: set = set()
        while queue:
            f = queue.pop(0)
            if f in seen:
                continue
            seen.add(f)
            label = f"sudoers {os.path.basename(f)}"
            self.check_path("sudoers", label, f, "sudo reads the sudoers file as root", strict_missing=False)
            for ln in self.read(f).splitlines():
                s = ln.strip()
                if not s:
                    continue
                # Handle #include and @includedir directives
                m = re.match(r"^[@#]include(dir)?\s+(\S+)", s)
                if m:
                    tgt = m.group(2)
                    if m.group(1):
                        # Filter drop-ins: skip dotfiles and backup files ending with ~
                        queue += [x for x in self.glob(tgt + "/*") if os.path.isfile(self.P(x)) and "." not in os.path.basename(x) and not x.endswith("~")]
                    elif os.path.isfile(self.P(tgt)):
                        queue.append(tgt)
                    continue

                # Step 3: Handle Defaults directives and extract secure_path
                if s.startswith("#") or s.startswith(("Defaults", "Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias")):
                    if s.startswith("Defaults") and re.search(r"\bsecure_path\s*=", s):
                        for pth in re.findall(r"(/[A-Za-z0-9_.+/-]+)", s):
                            self.check_path("sudoers", label, pth, "secure_path entry for sudo")
                    continue

                # Step 4: Parse privilege specifications (User Host = (RunAs) NOPASSWD: Commands)
                who = s.split()[0]
                rhs = s.split("=", 1)[-1]

                # Check for passwordless sudo for ALL commands (unrestricted privilege elevation)
                if re.search(r"NOPASSWD\s*:(?:\s*[A-Z_]+\s*:)*\s*ALL\b", rhs) and who != "root":
                    if who.startswith("%"):
                        mem = _group_has_members(who[1:])
                        if mem:
                            self.add("high", "sudoers", label, f, f"passwordless sudo for ALL commands for group '{who}' (members: {', '.join(mem)}): any process running as them gets root without a password")
                    else:
                        self.add("high", "sudoers", label, f, f"passwordless sudo for ALL commands for '{who}': any process running as that user gets root without a password")

                # Check for GTFOBins and wildcard vulnerabilities in NOPASSWD authorizations
                if "NOPASSWD" in rhs:
                    for cmdpath in re.findall(r"(/[A-Za-z0-9_.+/-]+)", rhs):
                        b = os.path.basename(cmdpath)
                        if b in GTFO:
                            self.add("high", "sudoers", label, cmdpath, f"passwordless sudo for '{b}' is equivalent to root (it can run commands, read or write any file)")
                    if re.search(r"\s\*|\*\s|[A-Za-z0-9_/.-]\*", rhs):
                        self.add("medium", "sudoers", label, f, "a wildcard in a passwordless sudo command line lets the caller add arguments")

                # Audit filesystem permissions of all command paths referenced in sudoers
                for pth in re.findall(r"(/[A-Za-z0-9_.+/-]+)", rhs):
                    self.check_path("sudoers", label, pth, "a sudoers rule lets this run as root")

    def audit_local_bins(self) -> None:
        """Audit /usr/local binary and library directories placed on root PATH."""
        patterns = ["/usr/local/bin/*", "/usr/local/sbin/*", "/usr/local/libexec/*/*", "/usr/local/libexec/*"]
        dirs = ["/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/local/libexec", "/usr/local/libexec/twu"]
        if self.platform == "darwin":
            patterns += ["/Library/Application Support/TWU/*", "/Library/Application Support/TWU/*/*", "/Library/PrivilegedHelperTools/*"]
            dirs += ["/Library", "/Library/Application Support", "/Library/Application Support/TWU", "/Library/PrivilegedHelperTools"]
        self.check_files("local-bin", "/usr/local", patterns, "in root's PATH or a root-run location")
        for d in dirs:
            if self.exists(d):
                self.check_path("local-bin", d, d, "directory that holds root-run programs")

    ELEVATORS = ("pkexec", "sudo", "doas")

    def audit_user_launchers(self) -> None:
        """Audit unprivileged user desktop launchers, autostart entries, and local scripts.
        
        Detects launchers in ~/.local/bin, ~/bin, ~/.local/share/applications, or ~/.config/autostart
        that elevate privileges via pkexec, sudo, or doas and execute a user-writable script.
        """
        homes = [os.path.join("/Users", "*")] if self.platform == "darwin" else [os.path.join("/home", "*"), "/root"]
        pats = []
        for h in homes:
            pats += [f"{h}/.local/bin/*", f"{h}/bin/*", f"{h}/.local/share/applications/*.desktop", f"{h}/.config/autostart/*.desktop"]
        for f in self.glob_any(pats):
            if os.path.isdir(self.P(f)):
                continue
            try:
                if os.path.getsize(self.P(f)) > 65536:  # Skip large compiled binaries
                    continue
                text = self.read(f)
            except Exception:
                continue
            if "\0" in text:
                continue
            for line in text.splitlines():
                body = line.strip()
                if body.startswith("#"):
                    continue
                if body.startswith("Exec="):
                    body = body[5:]
                try:
                    toks = split_command(body)
                except Exception:
                    continue
                for i, tok in enumerate(toks):
                    if os.path.basename(tok) not in self.ELEVATORS:
                        continue
                    rest = [t for t in toks[i + 1:]]
                    while rest and rest[0].startswith("-"):
                        rest = rest[1:]
                    if rest:
                        self.check_command("elevated-launcher", f"{f} ({os.path.basename(tok)})", rest,
                                           "a user launcher elevates to root and runs this file")

    def glob_any(self, patterns: Iterable[str]) -> List[str]:
        """Aggregate unique matches across multiple glob patterns."""
        seen: List[str] = []
        for pat in patterns:
            for f in self.glob(pat):
                if f not in seen:
                    seen.append(f)
        return seen

    def audit_ld(self) -> None:
        """Audit dynamic linker preload configurations (/etc/ld.so.preload, ld.so.conf.d)."""
        self.check_files("ld.so", "ld.so", ["/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d/*"], "dynamic-linker configuration read by every program")
        for f in ["/etc/ld.so.preload"] + self.glob("/etc/ld.so.conf.d/*"):
            for ln in self.read(f).splitlines():
                if ln.strip().startswith("/"):
                    self.check_path("ld.so", f"ld.so {os.path.basename(f)}", ln.strip(), "library search path / preload entry")

    def audit_misc_linux(self) -> None:
        """Audit Linux shell profile scripts, PAM modules, NetworkManager hooks, polkit, and tuned."""
        self.check_files("profile", "login", ["/etc/profile", "/etc/profile.d/*", "/etc/bashrc", "/etc/environment", "/etc/rc.local"], "sourced by root login shells")
        self.check_files("nm-dispatcher", "NetworkManager", ["/etc/NetworkManager/dispatcher.d/*", "/etc/NetworkManager/dispatcher.d/*/*"], "run as root on network events")
        self.check_files("kernel-hook", "kernel hook", ["/etc/kernel/postinst.d/*", "/etc/kernel/install.d/*", "/usr/local/lib/kernel/install.d/*",
                                                         "/usr/lib/kernel/install.d/*", "/etc/kernel/install.conf"], "run as root when kernels are installed")
        self.check_files("polkit", "polkit", ["/etc/polkit-1/rules.d/*", "/usr/share/polkit-1/rules.d/*"], "polkit rules are evaluated by a root daemon")
        for f in self.glob("/etc/polkit-1/rules.d/*.rules") + self.glob("/usr/share/polkit-1/rules.d/*.rules"):
            for m in re.finditer(r'polkit\.spawn\(\s*\[\s*"([^"]+)"', self.read(f)):
                self.check_path("polkit", f"polkit {os.path.basename(f)}", m.group(1), "polkit.spawn runs it as root")
        for f in self.glob("/usr/share/polkit-1/actions/*.policy"):
            for m in re.finditer(r'exec\.path">([^<]+)<', self.read(f)):
                self.check_path("polkit", f"polkit {os.path.basename(f)}", m.group(1).strip(), "pkexec runs it as root")
        self.check_files("pam", "pam", ["/etc/pam.d/*", "/etc/security/*.conf"], "authentication configuration read by root")
        for f in self.glob("/etc/pam.d/*"):
            for ln in self.read(f).splitlines():
                if "pam_exec.so" in ln and not ln.lstrip().startswith("#"):
                    for pth in [t for t in ln.split() if t.startswith("/")]:
                        self.check_path("pam", f"pam {os.path.basename(f)}", pth, "pam_exec runs it as root")
        for f in self.glob("/etc/modprobe.d/*.conf") + self.glob("/usr/lib/modprobe.d/*.conf") + self.glob("/usr/local/lib/modprobe.d/*.conf"):
            for ln in self.read(f).splitlines():
                m = re.match(r"^\s*(install|remove)\s+\S+\s+(.+)$", ln)
                if m:
                    self.check_command("modprobe", f"modprobe {os.path.basename(f)}", split_command(m.group(2)), f"modprobe '{m.group(1)}' command runs as root")
        for f in self.glob("/etc/logrotate.d/*") + ["/etc/logrotate.conf"]:
            for blk in re.findall(r"(?:prerotate|postrotate|firstaction|lastaction|preremove)\n(.*?)\n\s*endscript", self.read(f), re.S):
                for pth in re.findall(r"(/[A-Za-z0-9_.+/-]+)", blk):
                    self.check_path("logrotate", f"logrotate {os.path.basename(f)}", pth, "logrotate runs this script as root", strict_missing=False)
        self.check_files("tuned", "tuned", ["/etc/tuned/*/*.sh", "/etc/tuned/*.sh", "/usr/lib/tuned/*/*.sh"], "tuned profile scripts run as root")
        for f in self.glob("/etc/tuned/*/tuned.conf") + self.glob("/usr/lib/tuned/*/tuned.conf"):
            for m in re.finditer(r"^\s*script\s*=\s*(\S+)", self.read(f), re.M):
                pth = m.group(1).replace("${i:PROFILE_DIR}", os.path.dirname(f))
                self.check_path("tuned", f"tuned {os.path.basename(os.path.dirname(f))}", pth, "tuned runs this script as root")

    # -------------------------------------------------------------- macOS Launchd Auditing
    def audit_launchd(self) -> None:
        """Audit macOS LaunchDaemons (/Library/LaunchDaemons/*.plist) for root privilege risks."""
        for f in self.glob("/Library/LaunchDaemons/*.plist"):
            src = f"launchd {os.path.basename(f)}"
            try:
                with open(self.P(f), "rb") as fh:
                    job = plistlib.load(fh)
            except Exception as exc:  # Hostile or garbled plist must not crash the audit
                self.add("info", "launchd-daemon", src, f, f"plist could not be parsed ({type(exc).__name__}); launchd would not load it, but check it by hand")
                continue
            if not isinstance(job, dict):
                self.add("info", "launchd-daemon", src, f, "plist is not a dictionary; launchd would not load it")
                continue
            user = str(job.get("UserName", "") or "")
            if user and user not in ("root", "0"):
                continue  # Job drops privileges to non-root account
            start = len(self.findings)
            self.check_path("launchd-daemon", src, f, "launchd reads the job definition as root", strict_missing=False)
            program = job.get("Program") if isinstance(job.get("Program"), str) else ""
            raw_args = job.get("ProgramArguments")
            args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []
            if program:
                self.check_path("launchd-daemon", src, program, "Program runs as root")
            self.check_command("launchd-daemon", src, args or ([program] if program else []), "ProgramArguments run as root")
            wd = job.get("WorkingDirectory")
            if isinstance(wd, str) and wd.startswith("/"):
                self.check_path("launchd-daemon", src, wd, "WorkingDirectory of a root daemon (relative imports/scripts)")
            envs = job.get("EnvironmentVariables")
            if isinstance(envs, dict):
                self.check_env("launchd-daemon", src, {k: v for k, v in envs.items() if isinstance(k, str) and isinstance(v, str)}, "daemon")
            if job.get("Disabled") is True:
                for fd in self.findings[start:]:
                    if fd["severity"] == "critical":
                        fd["severity"] = "high"
                    fd["source"] = src + " (Disabled=true)"

    def audit_misc_darwin(self) -> None:
        """Audit macOS periodic jobs, system paths (/etc/paths, /etc/paths.d), and login profiles."""
        self.check_files("periodic", "periodic", ["/etc/periodic/*/*", "/usr/local/etc/periodic/*/*", "/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local",
                                                  "/etc/periodic.conf", "/etc/periodic.conf.local"], "run as root by the daily/weekly/monthly periodic jobs")
        self.check_files("profile", "login", ["/etc/profile", "/etc/zshenv", "/etc/zprofile", "/etc/zshrc", "/etc/bashrc", "/etc/paths", "/etc/paths.d/*"],
                         "sourced or read by root login shells")
        for f in ["/etc/paths"] + self.glob("/etc/paths.d/*"):
            for ln in self.read(f).splitlines():
                if ln.strip().startswith("/"):
                    self.check_path("profile", f"paths {os.path.basename(f)}", ln.strip(), "directory placed on root's login PATH")

    # -------------------------------------------------------------- Deep Filesystem Sweep
    def deep_scan(self) -> None:
        """Perform recursive sweep across /etc, /usr/local, and /opt for non-root ownership or world-writable files."""
        tops = ["/etc", "/usr/local", "/opt"]
        if self.platform == "darwin":
            tops = ["/etc", "/usr/local", "/Library/LaunchDaemons", "/Library/PrivilegedHelperTools", "/Library/Application Support/TWU"]
        count = 0
        for top in tops:
            if not self.exists(top):
                continue
            for dp, dns, fns in os.walk(self.P(top), followlinks=False):
                for n in dns + fns:
                    full = os.path.join(dp, n)
                    try:
                        st = os.lstat(full)
                    except OSError:
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    why = None
                    if st.st_uid != self.tuid:
                        why = ("high" if st.st_uid < self.first_user_uid else "critical", f"owned by uid {st.st_uid} (not root)")
                    elif st.st_mode & 0o002 and not (stat.S_ISDIR(st.st_mode) and st.st_mode & 0o1000):
                        why = ("high", f"world-writable ({oct(st.st_mode & 0o7777)})")
                    if why:
                        count += 1
                        if count > DEEP_LIMIT:
                            self.add("info", "deep-scan", "sweep", top, f"stopped after {DEEP_LIMIT} findings; fix these first and rerun")
                            return
                        self.add(why[0], "deep-scan", f"{top} sweep", self.unP(full), why[1])

    # -------------------------------------------------------------- Audit Driver
    def run(self, deep: bool = False) -> None:
        """Execute full platform privilege audit suite."""
        if self.platform == "linux":
            self.audit_units()
            self.audit_generators()
            self.audit_udev()
            self.audit_dnf()
            self.audit_cron()
            self.audit_sudoers()
            self.audit_local_bins()
            self.audit_ld()
            self.audit_misc_linux()
            self.audit_user_launchers()
        else:
            self.audit_launchd()
            self.audit_sudoers()
            self.audit_cron()
            self.audit_local_bins()
            self.audit_misc_darwin()
            self.audit_user_launchers()
        if deep:
            self.deep_scan()

    def result(self, fail_on: str = "high") -> Dict[str, Any]:
        """Aggregate, deduplicate, and format audit results into structured JSON report."""
        seen: set = set()
        out: List[Dict[str, str]] = []
        for f in self.findings:
            key = (f["severity"], f["kind"], f["source"], f["path"], f["why"])
            if key not in seen:
                seen.add(key)
                out.append(f)
        out.sort(key=lambda f: (SEV[f["severity"]], f["kind"], f["path"]))
        blocking = [f for f in out if SEV[f["severity"]] <= SEV[fail_on]]
        return {
            "schema": "twu.root-exec-audit.v1",
            "platform": self.platform,
            "fail_on": fail_on,
            "findings": out,
            "blocking": len(blocking),
            "total": len(out),
            "checked_as_root": self.is_root,
            "sudoers_readable": self.sudoers_readable
        }


def run_audit(root: str = "/", trusted_uid: int = 0, trusted_gid: int = 0, platform: Optional[str] = None,
              deep: bool = False, fail_on: str = "high", is_root: Optional[bool] = None) -> Dict[str, Any]:
    """Execute privilege audit on specified root directory and return structured result dictionary."""
    auditor = Auditor(root, trusted_uid, trusted_gid, platform, is_root)
    auditor.run(deep)
    return auditor.result(fail_on)


def _overrides(environ: Dict[str, str]) -> Tuple[str, int, int]:
    """Extract test overrides from environment variables (used exclusively in automated unit tests)."""
    try:
        return environ.get(ENV_ROOT, "/"), int(environ.get(ENV_UID, "0")), int(environ.get(ENV_GID, "0"))
    except ValueError as exc:
        raise ValueError(f"{ENV_UID}/{ENV_GID} must be integers ({exc})") from exc


def render(res: Dict[str, Any]) -> str:
    """Format audit results as human-readable terminal output."""
    lines = [f"[{f['severity'].upper():8}] {f['kind']:16} {f['source']}: {f['path']}\n             {f['why']}" for f in res["findings"]]
    tail = "" if res["checked_as_root"] else "  [not run as root: sudoers not fully checked]"
    lines.append(f"\nroot_exec_audit ({res['platform']}): {res['blocking']} blocking finding(s) ({res['fail_on']} or worse), {res['total']} total" + tail)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line interface entry point."""
    ap = argparse.ArgumentParser(description="Find anything root runs or sources that a non-root user could modify (read-only).")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--fail-on", default="high", choices=("critical", "high", "medium"), help="lowest severity that makes the exit code 1 (default high)")
    ap.add_argument("--deep", action="store_true", help="also sweep /etc, /usr/local and the root-run Library folders for non-root-owned or world-writable files")
    ap.add_argument("--platform", default="auto", choices=("auto", "linux", "darwin"), help="default: detected from sys.platform")
    a = ap.parse_args(argv)
    try:
        root, tuid, tgid = _overrides(dict(os.environ))
        res = run_audit(root, tuid, tgid, None if a.platform == "auto" else a.platform, a.deep, a.fail_on)
    except ValueError as exc:
        print(f"root_exec_audit: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=1) if a.json else render(res))
    return 1 if res["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
