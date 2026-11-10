# Contributing to Handoff Witness

Contributions that improve reproducibility, clarify evidence boundaries, or
demonstrate a concrete failure case are welcome. This is an experimental research
prototype; changes should preserve the distinction between recorded initiation,
approval, observed execution, and human intent.

## Development

Use Python 3.11 or newer, from the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

For browser changes, follow the relevant integration commands in
[README.md](README.md) and [the execution documentation](docs/EXECUTION.md).
Use loopback fixtures and fresh output directories. The browser experiments
require Playwright and Chromium; the unit suite does not require model weights.

## Issues and pull requests

- Describe the behavior, expected result, and smallest reproducible example.
- Include Python/browser versions and the exact command used.
- Add a regression test for a behavior change when it can demonstrate the bug.
- Explain changes to trust assumptions, event schemas, or evidence interpretation.
- Report the checks actually run and any checks that were unavailable.

Keep credentials, private keys, browser profiles, personal browsing history, and
unredacted personal URLs out of issues and commits. For security findings, follow
[SECURITY.md](SECURITY.md).

## Research artifacts

Keep raw observations separate from analysis and avoid editing measurements to
fit expected results. Document seeds, dependencies, exclusions, and limitations.
The [paper guide](paper/README.md) describes reproduction and package validation.
Do not claim that synthetic labels or virtual approvals establish human identity,
intent, legal responsibility, or general security guarantees.

Code contributions are provided under the repository's MIT license. Manuscript
contributions are provided under its CC BY 4.0 license. Preserve attribution and
identify any third-party material and its license.
