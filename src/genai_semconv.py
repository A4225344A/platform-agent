"""OpenTelemetry GenAI semantic convention attribute mapping.

The GenAI semantic conventions are still evolving, so agent code should import
these constants instead of spelling `gen_ai.*` attribute names inline. If a
future semantic-conventions release renames an attribute, update this file and
keep the rest of the agent stable.
"""

# Span naming convention: "{operation} {model}", for example "chat judge".
OP_CHAT = "chat"
OP_EMBEDDINGS = "embeddings"
OP_INVOKE_AGENT = "invoke_agent"

# Request attributes.
ATTR_OPERATION = "gen_ai.operation.name"
ATTR_PROVIDER = "gen_ai.provider.name"
ATTR_REQ_MODEL = "gen_ai.request.model"

# Usage attributes.
ATTR_IN_TOKENS = "gen_ai.usage.input_tokens"
ATTR_OUT_TOKENS = "gen_ai.usage.output_tokens"

# Response attributes.
ATTR_RESP_MODEL = "gen_ai.response.model"
ATTR_FINISH = "gen_ai.response.finish_reasons"

# Project-specific attributes. The w3. prefix avoids collisions with OTel names.
ATTR_ALERTNAME = "w3.alert.name"
ATTR_SERVICE = "w3.target.service"
ATTR_ACTION = "w3.remediation.action"
ATTR_VERIFIED = "w3.remediation.verified"
