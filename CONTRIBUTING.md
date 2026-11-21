# Contributing

Small, one-maintainer project; the process is light.

## Useful contributions

1. Bug reports with a reproduction: command, Python version, OS, and the raw output.
2. False positives and false negatives, with a minimal fake tree that shows them.
3. Corrections to a README or comment that the code or tests do not support.
4. Small pull requests that change one thing and add or change a test.

Vulnerabilities do not go in public issues; see [SECURITY.md](SECURITY.md).

## Ground rules

- Standard library only. No third-party dependencies, no network access.
- Python 3.9 and newer (CI runs 3.9 and 3.13).
- Run the tests before opening a PR: `python3 -B -m unittest scripts/test_root_exec_audit.py`.
- Tests build fake trees under a temporary directory. They must not touch the real `/etc` or `/Library`.
- The audited path lists (for example `/etc/rc.local`, `/etc/daily.local`, `/etc/periodic.conf.local`) are intentional and pinned by tests. Add paths if you can justify them; do not remove or rename them without changing the pinning tests and saying why.
- Use fake values in tests (`/home/u`, `/Users/u`); no real hostnames, usernames, or addresses.
- Numbers in docs must come from a real run. Say whether an AI agent helped write your change.

By contributing you agree your contribution is licensed under the MIT license in [LICENSE](LICENSE). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
