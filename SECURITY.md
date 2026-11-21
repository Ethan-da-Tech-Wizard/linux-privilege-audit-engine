# Security policy

## What this tool is, and is not

`root_exec_audit.py` is a read-only checker. It looks at file modes, owners and a fixed list of paths that root runs or sources (systemd units, sudoers, cron, udev, login profiles, macOS launchd and periodic jobs) and reports ones that a non-root user could modify.

- It is not a vulnerability scanner or an exploit detector. A finding is a lead to investigate, not proof.
- A clean report does not mean the system is safe. Only the listed paths are checked, at one moment in time, and only as the user who ran it (run it as root to read sudoers).
- It never changes files, but it reads sensitive system configuration. Do not paste a full report into a public issue if it names paths or users you consider private.
- It has been tested only by its own tests, on macOS and in CI on Ubuntu and macOS. No third party has reviewed it.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting**: open this repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue for a vulnerability. This is a one-person project with no service-level promise.

Wrong claims in the README or comments count as bugs too; open a normal issue.

## Supported versions

Only the latest commit on the default branch. There are no releases.
