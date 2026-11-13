# Linux Privilege Audit Engine

A Python audit tool that looks for potentially unsafe paths and configurations associated with privileged execution. The code includes checks for Linux systemd units, udev, cron and sudoers, along with macOS launchd checks.

## What's included

- [Audit implementation](scripts/root_exec_audit.py)
- [Audit tests](scripts/test_root_exec_audit.py)
- Text and JSON output, severity-based exit status, and an optional deeper scan

## Explore

From the repository root:

```sh
python3 scripts/root_exec_audit.py --help
```

For machine-readable output, the CLI supports `--json`. The `--deep` option extends the filesystem sweep; inspect the help and source to understand its scope before using it. Access permissions affect what the tool can inspect.

## Limitations

Findings are prompts for investigation, not proof of exploitability. A clean report does not establish that a system is secure or that every relevant configuration was inspected. Review the tool and test it in your environment before relying on its output.

See the [license](LICENSE).
