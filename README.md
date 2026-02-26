# aumai-specs

Canonical schema definitions and Pydantic v2 models for the AumAI platform.

This is the **foundational repository** that all 86+ AumAI projects depend on.
It contains four immutable canonical schemas and their Python bindings.

---

## Schemas

| Schema | File | Purpose |
|--------|------|---------|
| Tool Canonical IR v1 | `tool_canonical_ir_v1.json` | Universal intermediate representation for agent tool definitions across all provider formats (OpenAI, Anthropic, MCP, LangChain) |
| Agent Error Taxonomy v1 | `agent_error_taxonomy_v1.json` | Structured error codes (1xx–6xx) for consistent error handling and observability |
| Run Capsule Format v1 | `capsule_format_v1.json` | Immutable execution records for deterministic replay, auditing, and cost attribution |
| Agent Capability Declaration v1 | `agent_capability_v1.yaml` | Sandbox, network, filesystem, and resource governance manifests for every deployed agent |

---

## Installation

```bash
pip install aumai-specs
```

Requires Python 3.11+.

---

## Quick Start

```python
from aumai_specs.loader import load_schema, validate
from aumai_specs.models import (
    ToolCanonicalIR,
    ToolCapability,
    ToolSecurity,
    DataClassification,
    SideEffect,
    CostEstimate,
)

# Load a raw schema dict
schema = load_schema("tool_canonical_ir_v1")
print(schema["title"])  # AumAI Tool Canonical IR

# Create a typed model
tool = ToolCanonicalIR(
    name="web_search",
    version="1.0.0",
    capabilities=[
        ToolCapability(
            action="search",
            domain="web",
            side_effects=[SideEffect.NETWORK_EGRESS],
            cost_estimate=CostEstimate.LOW,
        )
    ],
    inputs={"type": "object", "required": ["query"]},
    outputs={"type": "object"},
    security=ToolSecurity(data_classification=DataClassification.PUBLIC),
)

# Validate arbitrary data against a schema
is_valid = validate(tool.model_dump(mode="json"), "tool_canonical_ir_v1")
```

See `examples/quickstart.py` for a full walkthrough.

---

## Schema Reference

### Tool Canonical IR (`tool_canonical_ir_v1`)

The universal IR for agent tool definitions. Enables tools to be defined
once and used across any LLM provider.

Key fields:
- `name` — Unique tool identifier (must start with a letter)
- `version` — Semantic version (`X.Y.Z`)
- `capabilities` — Array of `{action, domain}` pairs
- `inputs` / `outputs` — JSON Schema for parameters and return values
- `security` — Permissions, data classification, PII handling
- `source_formats` — Original provider-specific definitions

### Agent Error Taxonomy (`agent_error_taxonomy_v1`)

Three-digit error codes grouped by hundreds digit:

| Range | Category |
|-------|----------|
| 1xx | Planning |
| 2xx | Tool Execution |
| 3xx | Context |
| 4xx | Security |
| 5xx | Resource |
| 6xx | Orchestration |

Each error entry includes: `code`, `name` (SCREAMING_SNAKE_CASE), `description`,
`severity`, `recoverable`, `retry_strategy`.

### Run Capsule Format (`capsule_format_v1`)

Immutable record of a complete agent execution. Captures:
- Agent identity and model configuration
- Run metadata and goal
- Full execution trace (every LLM call, tool call, cost, and token usage)
- Runtime environment snapshot
- Final outcome with confidence score
- Cryptographic integrity hash

### Agent Capability Declaration (`agent_capability_v1`)

Governance manifest evaluated at agent registration:
- `sandbox` — Tier (`e2b_micro`, `e2b_standard`, `modal_ephemeral`, etc.)
- `network` — Egress mode (`isolated`, `allowlist_only`, `full_access`) with explicit rules
- `filesystem` — Access mode and path allowlist
- `resources` — CPU, memory, duration, token, and cost limits
- `permissions` — Required scopes and data classification levels

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
make test

# Run tests with coverage
make test-cov

# Type check
make typecheck

# Lint and format
make fmt

# Run all checks
make check

# Run quickstart example
make quickstart
```

---

## Contributing

See `CONTRIBUTING.md`.

Schema changes follow the RFC process described in `GOVERNANCE.md`.

---

## License

Apache 2.0. See `LICENSE`.
