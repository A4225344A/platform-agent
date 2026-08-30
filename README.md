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
src/
  genai_semconv.py
```

Future agent runtime files from the runbook, including `agent.py`,
`requirements.in`, and `requirements.lock`, should be added here in the same
deployment-oriented shape unless the service is later converted into a reusable
Python package.

## Current scope

- `genai_semconv.py` isolates OpenTelemetry GenAI semantic convention strings.
- The mapping layer keeps unstable `gen_ai.*` names in one place so future
  convention changes do not spread across agent logic.
