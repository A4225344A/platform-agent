# platform-agent

Independent remediation agent for the platform control plane.

This repository owns the agent code that receives monitoring signals, enriches
diagnostics, calls LLM tooling, and eventually performs or recommends
remediation actions.

The original runbook mentions `~/agent-src/` as an execution location. Treat
that as a deployment target only. Source code should live here and be deployed
from version control.

## Layout

```text
Dockerfile
requirements.in
requirements.lock
src/
  agent.py
  genai_semconv.py
```

`requirements.lock` is generated from `requirements.in` with hash pinning in a
Python 3.11 environment that matches the Docker image.

## Current Scope

- `agent.py` receives Alertmanager webhooks and processes queued alerts.
- `genai_semconv.py` isolates unstable OpenTelemetry GenAI attribute names.
- `Dockerfile` builds the deployable agent image from `src/`.

## Safety Controls

- `/alert` requires `Authorization: Bearer $ALERT_WEBHOOK_TOKEN`.
- `REQUIRE_HUMAN_APPROVAL` defaults to `true`, so model-selected remediation is
  downgraded to notification unless an explicit approval path is added.
- Kubernetes resource names are protected during sanitization so Pod,
  Deployment, and Service names are not masked as PII.

## Generate Lock File

```bash
python -m pip install --upgrade pip-tools==7.6.1 pip-audit==2.10.1
pip-compile --generate-hashes --output-file requirements.lock requirements.in
python -m pip install --require-hashes -r requirements.lock
python -m pip check
pip-audit -r requirements.lock
```

## Run Locally

The agent expects Kubernetes, Postgres, Prometheus, Presidio, LiteLLM, and OTel
endpoints through environment variables. In normal use it should run in the
cluster with the GitOps manifest from the runbook.

For a local syntax check:

```bash
python -m py_compile src/agent.py src/genai_semconv.py
```
