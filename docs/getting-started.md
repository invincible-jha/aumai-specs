# Getting Started with aumai-specs

## Overview

`aumai-specs` provides four canonical schemas and their Python bindings
for the AumAI platform. This guide walks through installation, the key
APIs, and common usage patterns.

---

## Installation

### From PyPI

```bash
pip install aumai-specs
```

### From source (development)

```bash
git clone https://github.com/muveraai/aumai-specs.git
cd aumai-specs
pip install -e ".[dev]"
```

---

## The Loader API

`aumai_specs.loader` is the primary entry point for working with raw schemas.

### Loading schemas

```python
from aumai_specs.loader import load_schema, list_schemas

# List all available schemas
print(list_schemas())
# ['agent_capability_v1', 'agent_error_taxonomy_v1', 'capsule_format_v1', 'tool_canonical_ir_v1']

# Load a schema as a plain dict
schema = load_schema("tool_canonical_ir_v1")
print(schema["title"])      # AumAI Tool Canonical IR
print(schema["$id"])        # https://specs.aumai.dev/tool-canonical-ir/v1
```

Schemas are loaded once and cached in-process (`functools.lru_cache`).

### Validating data

```python
from aumai_specs.loader import validate, validate_quietly, SchemaValidationError

# Raises SchemaValidationError on failure
try:
    validate(my_tool_dict, "tool_canonical_ir_v1")
except SchemaValidationError as exc:
    print(exc.validation_error.message)  # jsonschema error message
    print(exc.validation_error.path)     # JSON path to the offending field

# Never raises — returns (bool, message) tuple
is_valid, message = validate_quietly(my_tool_dict, "tool_canonical_ir_v1")
if not is_valid:
    print(f"Validation failed: {message}")
```

### Getting schema file paths

```python
from aumai_specs.loader import get_schema_path

path = get_schema_path("agent_capability_v1")
print(path)  # /path/to/aumai_specs/schemas/agent_capability_v1.yaml
```

---

## Working with Pydantic Models

`aumai_specs.models` provides typed Pydantic v2 models for all schemas.
Models validate on construction and support serialization via `model_dump()`.

### Tool Canonical IR

```python
from aumai_specs.models import (
    ToolCanonicalIR,
    ToolCapability,
    ToolSecurity,
    ToolSourceFormats,
    DataClassification,
    PiiHandling,
    SideEffect,
    CostEstimate,
)

tool = ToolCanonicalIR(
    name="send_email",
    version="2.1.0",
    description="Send an email via SMTP or a transactional email provider.",
    capabilities=[
        ToolCapability(
            action="send",
            domain="email",
            side_effects=[SideEffect.NETWORK_EGRESS, SideEffect.EMAIL_SEND],
            idempotent=False,
            cost_estimate=CostEstimate.LOW,
        )
    ],
    inputs={
        "type": "object",
        "required": ["to", "subject", "body"],
        "properties": {
            "to": {"type": "string", "format": "email"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
    },
    outputs={
        "type": "object",
        "properties": {"message_id": {"type": "string"}},
    },
    security=ToolSecurity(
        required_permissions=["email:send"],
        data_classification=DataClassification.CONFIDENTIAL,
        pii_handling=PiiHandling.WRITE,
        audit_required=True,
    ),
    source_formats=ToolSourceFormats(
        openai={
            "type": "function",
            "function": {"name": "send_email", "description": "Send an email"},
        }
    ),
)
```

### Agent Error Taxonomy

```python
from aumai_specs.models import (
    AgentError,
    ErrorCategory,
    SeverityLevel,
)
from datetime import datetime, timezone

error = AgentError(
    code=502,                              # 5xx = Resource
    category=ErrorCategory.RESOURCE,
    message="Run exceeded $1.00 cost cap. Aborted at step 47.",
    severity=SeverityLevel.CRITICAL,
    recoverable=False,
    agent_id="research-agent-v1",
    run_id="run_abc123",
    step_index=47,
    timestamp=datetime.now(tz=timezone.utc),
    context={"cost_usd": "1.043", "cap_usd": "1.00"},
)
```

The `category` must match the hundreds digit of `code` — validation enforces this:

```python
# Raises ValidationError: code 502 belongs to category 'resource',
# but category 'planning' was provided.
AgentError(code=502, category=ErrorCategory.PLANNING, ...)
```

### Run Capsule

```python
from aumai_specs.models import (
    RunCapsule,
    CapsuleAgent,
    CapsuleRun,
    CapsuleStep,
    CapsuleEnvironment,
    CapsuleOutcome,
    ModelInfo,
    ModelProvider,
    RunStatus,
    StepType,
    TokenUsage,
    SandboxTier,
)
from datetime import datetime, timezone

now = datetime.now(tz=timezone.utc)

capsule = RunCapsule(
    capsule_id="capsule_01HZABCDEFGHIJKLMNOPQRSTUV",
    schema_version="1.0.0",
    created_at=now,
    agent=CapsuleAgent(
        agent_id="research-agent-v1",
        agent_name="Research Agent",
        agent_version="1.2.0",
        model=ModelInfo(
            provider=ModelProvider.ANTHROPIC,
            model_id="claude-opus-4-6",
            parameters={"temperature": 0.5},
        ),
    ),
    run=CapsuleRun(
        run_id="run_xyz789",
        started_at=now,
        ended_at=now,
        status=RunStatus.SUCCESS,
        goal="Summarize the quarterly earnings report.",
    ),
    execution_trace=[
        CapsuleStep(
            step_index=0,
            step_type=StepType.LLM_INFERENCE,
            started_at=now,
            ended_at=now,
            tokens=TokenUsage(input_tokens=2048, output_tokens=512, total_tokens=2560),
        )
    ],
    environment=CapsuleEnvironment(
        aumai_runtime_version="0.1.0",
        python_version="3.12.0",
        sandbox_tier=SandboxTier.E2B_MICRO,
    ),
    outcome=CapsuleOutcome(
        final_answer="Q4 revenue was $42M, up 18% YoY...",
        total_cost_usd=0.0078,
        total_steps=1,
        goal_achieved=True,
        confidence_score=0.93,
    ),
)
```

### Agent Capability Declaration

```python
from aumai_specs.models import (
    AgentCapability,
    SandboxConfig,
    NetworkConfig,
    NetworkEgressRule,
    NetworkProtocol,
    FilesystemConfig,
    ResourceLimits,
    PermissionsConfig,
    ToolDeclaration,
    CapabilityMetadata,
    SandboxTier,
    EgressMode,
    FilesystemMode,
    DataClassification,
    Environment,
)

capability = AgentCapability(
    capability_version="1.0.0",
    agent_id="email-agent-v1",
    agent_name="Email Agent",
    agent_version="1.0.0",
    sandbox=SandboxConfig(tier=SandboxTier.E2B_STANDARD),
    network=NetworkConfig(
        egress_mode=EgressMode.ALLOWLIST_ONLY,
        egress_rules=[
            NetworkEgressRule(
                host="api.resend.com",
                ports=[443],
                protocol=NetworkProtocol.HTTPS,
                description="Resend transactional email API",
            )
        ],
    ),
    filesystem=FilesystemConfig(
        mode=FilesystemMode.READ_ONLY,
        allowed_paths=["/templates/"],
    ),
    resources=ResourceLimits(
        max_cpu_cores=0.5,
        max_memory_mb=256,
        max_run_duration_seconds=60,
        max_cost_usd_per_run=0.10,
    ),
    permissions=PermissionsConfig(
        scopes=["email:send", "tools:read"],
        data_classifications=[DataClassification.CONFIDENTIAL],
        pii_access=True,   # requires confidential or restricted classification
        audit_all_runs=True,
    ),
    tools=[ToolDeclaration(tool_name="send_email", tool_version="2.1.0")],
    metadata=CapabilityMetadata(environment=Environment.PRODUCTION),
)
```

---

## Error Handling

All public functions raise typed exceptions that inherit from standard Python
exceptions:

| Exception | Parent | When raised |
|-----------|--------|------------|
| `SchemaNotFoundError` | `FileNotFoundError` | Requested schema name has no file |
| `SchemaParseError` | `ValueError` | Schema file cannot be parsed |
| `SchemaValidationError` | `ValueError` | Data fails validation against a schema |

```python
from aumai_specs.loader import (
    SchemaNotFoundError,
    SchemaParseError,
    SchemaValidationError,
    load_schema,
    validate,
)

try:
    schema = load_schema("nonexistent_v99")
except SchemaNotFoundError as exc:
    print(exc.schema_name)   # "nonexistent_v99"

try:
    validate(bad_data, "tool_canonical_ir_v1")
except SchemaValidationError as exc:
    # Full jsonschema.ValidationError is available for detailed inspection
    print(exc.validation_error.absolute_path)
    print(exc.validation_error.message)
```

---

## Round-Trip Validation Pattern

A common pattern is to construct a Pydantic model (which validates field
types and business rules), then validate the serialized output against the
JSON Schema (which validates structural constraints):

```python
from aumai_specs.loader import validate
from aumai_specs.models import ToolCanonicalIR, ToolCapability

tool = ToolCanonicalIR(
    name="my_tool",
    version="1.0.0",
    capabilities=[ToolCapability(action="do_thing", domain="example")],
    inputs={"type": "object"},
    outputs={"type": "object"},
)

# Pydantic model_dump() produces JSON-serializable dicts by default for
# primitive types; use mode="json" to ensure datetime → ISO string etc.
validate(tool.model_dump(mode="json"), "tool_canonical_ir_v1")
```

This gives you both layers of validation: Pydantic's Python-level type
checking plus jsonschema's structural validation.
