# Security policy

Handoff Witness is experimental research software. There is no supported
production release or guaranteed response time. Security fixes target the latest
development version; older snapshots are preserved for research reproducibility.

## Reporting a vulnerability

If the repository's Security tab offers **Report a vulnerability**, use that
private channel. Availability depends on the maintainer enabling private
vulnerability reporting. Otherwise, open a minimal issue requesting a private
contact channel, without exploit details or sensitive data. Do not post secrets,
private keys, session data, or personal browsing evidence publicly.

In the private report, include the affected commit, the violated trust boundary,
reproduction steps using local fixtures, expected and actual behavior, and a
proposed mitigation if available.

## Scope and assumptions

Read the [threat model](docs/THREAT_MODEL.md) and
[execution boundary](docs/EXECUTION.md) before interpreting the guarantees.
The gate applies to a dedicated controlled browser context. It does not provide
OS-wide network isolation or resist a compromised trusted controller. Signed
records authenticate recorder statements under trusted keys; they do not prove
physical human input, intent, or legal responsibility. Independently retained
keys and checkpoints are necessary for meaningful adversarial verification.

Use controlled local fixtures for testing. Do not use personal browsing sessions
or access restricted websites to demonstrate a finding.
