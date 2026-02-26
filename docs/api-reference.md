# API Reference

## `aumai_specs.loader`

### Functions

---

#### `list_schemas() -> list[str]`

Return the names of all bundled canonical schemas, sorted alphabetically.

Returns base names without file extensions.

```python
>>> list_schemas()
['agent_capability_v1', 'agent_error_taxonomy_v1', 'capsule_format_v1', 'tool_canonical_ir_v1']
```

---

#### `load_schema(schema_name: str) -> dict[str, Any]`

Load and parse a canonical schema by base name.

Results are cached in-process. Subsequent calls for the same name are O(1).

**Parameters:**
- `schema_name` — Base name without extension (e.g. `"tool_canonical_ir_v1"`)

**Returns:** Parsed schema as a nested dictionary.

**Raises:**
- `SchemaNotFoundError` — No file exists for the given name
- `SchemaParseError` — The file cannot be parsed as JSON or YAML

---

#### `validate(data: dict[str, Any], schema_name: str) -> bool`

Validate `data` against the named schema using JSON Schema Draft 2020-12.

**Parameters:**
- `data` — Dictionary to validate
- `schema_name` — Name of the schema to validate against

**Returns:** `True` if validation passes.

**Raises:**
- `SchemaNotFoundError` — Schema not found
- `SchemaValidationError` — Data fails validation (wraps jsonschema.ValidationError)

---

#### `validate_quietly(data: dict[str, Any], schema_name: str) -> tuple[bool, str]`

Like `validate()` but never raises. Returns `(is_valid, message)`.

Useful for bulk validation where you want all failures collected rather
than short-circuiting on the first.

---

#### `get_schema_path(schema_name: str) -> Path`

Return the absolute filesystem path to a schema file.

**Raises:** `SchemaNotFoundError` — Schema file not found.

---

### Exceptions

#### `SchemaNotFoundError(FileNotFoundError)`

Attributes:
- `schema_name: str` — The requested schema name

#### `SchemaParseError(ValueError)`

Attributes:
- `path: Path` — Path to the file that failed to parse
- `cause: Exception` — Underlying parse exception

#### `SchemaValidationError(ValueError)`

Attributes:
- `validation_error: jsonschema.exceptions.ValidationError` — Full jsonschema error

---

## `aumai_specs.models`

### Enumerations

| Enum | Values |
|------|--------|
| `CostEstimate` | `free`, `low`, `medium`, `high` |
| `DataClassification` | `public`, `internal`, `confidential`, `restricted` |
| `PiiHandling` | `none`, `read`, `write`, `both` |
| `SeverityLevel` | `debug`, `info`, `warning`, `error`, `critical` |
| `RetryStrategy` | `none`, `immediate`, `exponential_backoff`, `human_escalation` |
| `ErrorCategory` | `planning`, `tool_execution`, `context`, `security`, `resource`, `orchestration` |
| `SandboxTier` | `e2b_micro`, `e2b_standard`, `modal_ephemeral`, `docker_local`, `none` |
| `EgressMode` | `isolated`, `allowlist_only`, `full_access` |
| `FilesystemMode` | `none`, `read_only`, `read_write_ephemeral`, `read_write_persistent` |
| `ModelProvider` | `anthropic`, `openai`, `google`, `mistral`, `cohere`, `local` |
| `RunStatus` | `success`, `failure`, `partial`, `cancelled`, `timeout` |
| `RunTrigger` | `human`, `scheduler`, `webhook`, `agent`, `test` |
| `StepType` | `llm_inference`, `tool_call`, `tool_result`, `planning`, `reflection`, `memory_read`, `memory_write`, `human_handoff`, `sub_agent_spawn`, `sub_agent_result`, `error` |
| `SideEffect` | `network_egress`, `filesystem_write`, `filesystem_read`, `database_write`, `database_read`, `memory_mutation`, `external_api_call`, `email_send`, `process_spawn`, `environment_mutation` |
| `NetworkProtocol` | `tcp`, `udp`, `https`, `http` |
| `Environment` | `development`, `staging`, `production` |

---

### Tool Canonical IR Models

#### `ToolCapability`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `action` | `str` | Yes | 1–128 chars |
| `domain` | `str` | Yes | 1–128 chars |
| `description` | `str \| None` | No | max 256 chars |
| `side_effects` | `list[SideEffect]` | No | |
| `idempotent` | `bool \| None` | No | |
| `cost_estimate` | `CostEstimate \| None` | No | |
| `timeout_seconds` | `int \| None` | No | 1–3600 |

#### `ToolSecurity`

| Field | Type | Default |
|-------|------|---------|
| `required_permissions` | `list[str]` | `[]` |
| `data_classification` | `DataClassification \| None` | `None` |
| `pii_handling` | `PiiHandling` | `PiiHandling.NONE` |
| `audit_required` | `bool` | `False` |
| `rate_limit` | `RateLimit \| None` | `None` |

#### `ToolCanonicalIR`

| Field | Type | Required | Validators |
|-------|------|----------|-----------|
| `name` | `str` | Yes | Pattern: `^[a-zA-Z][a-zA-Z0-9_\-\.]*$` |
| `version` | `str` | Yes | Semantic version `X.Y.Z` |
| `description` | `str \| None` | No | max 500 chars |
| `tags` | `list[str]` | No | |
| `capabilities` | `list[ToolCapability]` | Yes | min 1 item |
| `inputs` | `dict[str, Any]` | Yes | JSON Schema dict |
| `outputs` | `dict[str, Any]` | Yes | JSON Schema dict |
| `security` | `ToolSecurity` | No | default: `ToolSecurity()` |
| `source_formats` | `ToolSourceFormats` | No | |
| `metadata` | `ToolMetadata` | No | |

**Cross-field validation:** `deprecation_message` requires `deprecated=True`.

---

### Agent Error Taxonomy Models

#### `AgentError`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `code` | `int` | Yes | 100–699 |
| `category` | `ErrorCategory` | Yes | Must match hundreds digit of `code` |
| `message` | `str` | Yes | 1–1024 chars |
| `severity` | `SeverityLevel` | Yes | |
| `recoverable` | `bool` | No | default: `True` |
| `agent_id` | `str \| None` | No | |
| `run_id` | `str \| None` | No | |
| `step_index` | `int \| None` | No | ≥ 0 |
| `timestamp` | `datetime \| None` | No | |
| `context` | `dict[str, str]` | No | |
| `cause` | `str \| None` | No | max 2048 chars |
| `retry_after_seconds` | `int \| None` | No | ≥ 0 |

**Cross-field validation:** `category` must match `code // 100`:
- 1xx → `planning`, 2xx → `tool_execution`, 3xx → `context`,
  4xx → `security`, 5xx → `resource`, 6xx → `orchestration`

---

### Run Capsule Models

#### `CapsuleStep`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `step_index` | `int` | Yes | ≥ 0, must be contiguous in trace |
| `step_type` | `StepType` | Yes | |
| `started_at` | `datetime` | Yes | |
| `ended_at` | `datetime` | Yes | must be ≥ `started_at` |
| `duration_ms` | `int \| None` | No | ≥ 0 |
| `tokens` | `TokenUsage \| None` | No | |
| `cost` | `StepCost \| None` | No | |
| `tool_name` | `str \| None` | No | Only valid for `tool_call`/`tool_result` |
| `tool_call_id` | `str \| None` | No | Correlates tool_call with tool_result |
| `error_code` | `int \| None` | No | 100–699 |

#### `RunCapsule`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `capsule_id` | `str` | Yes | Pattern: `capsule_<26 alphanumeric>` |
| `schema_version` | `str` | Yes | Must be `"1.0.0"` |
| `created_at` | `datetime` | Yes | |
| `agent` | `CapsuleAgent` | Yes | |
| `run` | `CapsuleRun` | Yes | |
| `execution_trace` | `list[CapsuleStep]` | No | Indices must be 0-based, contiguous |
| `environment` | `CapsuleEnvironment` | Yes | |
| `outcome` | `CapsuleOutcome` | Yes | |
| `integrity` | `CapsuleIntegrity` | No | |

---

### Agent Capability Models

#### `AgentCapability`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `capability_version` | `str` | Yes | Semantic version |
| `agent_id` | `str` | Yes | 1–128 chars |
| `agent_name` | `str` | Yes | 1–128 chars |
| `sandbox` | `SandboxConfig` | Yes | |
| `network` | `NetworkConfig` | Yes | |
| `filesystem` | `FilesystemConfig` | Yes | |
| `resources` | `ResourceLimits` | Yes | |
| `permissions` | `PermissionsConfig` | Yes | |
| `tools` | `list[ToolDeclaration]` | No | |
| `metadata` | `CapabilityMetadata` | No | |

**Cross-field validations:**
- Production agents (`metadata.environment == "production"`) must not use `sandbox.tier == "none"`.
- Agents with `permissions.pii_access == True` must declare `confidential` or `restricted` in `permissions.data_classifications`.

#### `NetworkConfig`

**Cross-field validation:** `egress_mode == "allowlist_only"` requires at least one `egress_rule`.

#### `SandboxConfig`

**Cross-field validation:** `image` is only valid when `tier == "docker_local"`.
