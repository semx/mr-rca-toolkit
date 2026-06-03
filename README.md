# Merge Review & RCA Toolkit

[![tests](https://github.com/semx/mr-rca-toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/semx/mr-rca-toolkit/actions/workflows/tests.yml)

Infrastructure review and incident triage utilities for GitLab-centric
platform teams.

The toolkit reviews merge request payloads for risky Terraform, Helm, and
Ansible changes before human approval. It also turns incident telemetry into a
first-pass RCA draft by correlating deploys, log events, trace symptoms, and
service ownership data.

## Features

- Merge request manifest parser for changed files and diff snippets.
- Policy checks for Terraform, Helm, and Ansible repositories.
- Risk scoring with severity, evidence, and remediation hints.
- Drift comparison against captured environment state.
- RCA draft builder for on-call handoff.
- CLI output suitable for CI logs or saved JSON artifacts.

## Quick start

```bash
python3 -m unittest discover -s tests
python3 -m toolkit.cli review examples/merge-request.json --pretty
python3 -m toolkit.cli rca examples/incident.json --pretty
```

## CI usage

```yaml
review:
  image: python:3.12-slim
  script:
    - python -m toolkit.cli review "$MR_MANIFEST" --fail-on high
```

The project is self-contained and does not require access to GitLab or
observability systems for local testing. Production integrations can generate
the same JSON envelopes consumed by the CLI.
