"""AumAI Specs — Quickstart example.

Demonstrates the three core workflows:
  1. Loading raw schemas
  2. Creating typed Pydantic models
  3. Validating arbitrary data against schemas

Run from the repo root:
    python examples/quickstart.py
"""

from __future__ import annotations

from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 1. Load raw schemas
# ---------------------------------------------------------------------------

from aumai_specs.loader import (
    SchemaValidationError,
    list_schemas,
    load_schema,
    validate,
    validate_quietly,
)

print("=" * 60)
print("aumai-specs quickstart")
print("=" * 60)

print("\n--- Available schemas ---")
for name in list_schemas():
    schema = load_schema(name)
    print(f"  {name:40s}  {schema['title']}")

# Load a schema to inspect it
tool_schema = load_schema("tool_canonical_ir_v1")
print(f"\nTool IR schema $id : {tool_schema['$id']}")
print(f"Required fields    : {tool_schema['required']}")

# ---------------------------------------------------------------------------
# 2. Create Pydantic models
# ---------------------------------------------------------------------------

from aumai_specs.models import (
    AgentCapability,
    AgentError,
    CapsuleAgent,
    CapsuleEnvironment,
    CapsuleOutcome,
    CapsuleRun,
    CapsuleStep,
    DataClassification,
    EgressMode,
    ErrorCategory,
    FilesystemConfig,
    FilesystemMode,
    ModelInfo,
    ModelProvider,
    NetworkConfig,
    NetworkEgressRule,
    NetworkProtocol,
    PermissionsConfig,
    ResourceLimits,
    RunCapsule,
    RunStatus,
    RunTrigger,
    SandboxConfig,
    SandboxTier,
    SeverityLevel,
    StepType,
    TokenUsage,
    ToolCanonicalIR,
    ToolCapability,
    ToolDeclaration,
    ToolSecurity,
    SideEffect,
    CostEstimate,
)

print("\n--- Create a ToolCanonicalIR model ---")
tool = ToolCanonicalIR(
    name="web_search",
    version="1.0.0",
    description="Search the web and return ranked results.",
    capabilities=[
        ToolCapability(
            action="search",
            domain="web",
            description="Perform a web search",
            side_effects=[SideEffect.NETWORK_EGRESS, SideEffect.EXTERNAL_API_CALL],
            idempotent=True,
            cost_estimate=CostEstimate.LOW,
            timeout_seconds=30,
        )
    ],
    inputs={
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "max_results": {"type": "integer", "default": 10},
        },
    },
    outputs={
        "type": "object",
        "properties": {
            "results": {"type": "array"},
            "total": {"type": "integer"},
        },
    },
    security=ToolSecurity(
        required_permissions=["tools:read"],
        data_classification=DataClassification.PUBLIC,
    ),
)
print(f"  Tool name    : {tool.name}")
print(f"  Version      : {tool.version}")
print(f"  Capabilities : {[c.action for c in tool.capabilities]}")
print(f"  Security PII : {tool.security.pii_handling.value}")

print("\n--- Create an AgentError model ---")
error = AgentError(
    code=201,
    category=ErrorCategory.TOOL_EXECUTION,
    message="Tool 'web_search' timed out after 30 seconds",
    severity=SeverityLevel.ERROR,
    recoverable=True,
    agent_id="research-agent-v1",
    run_id="run_abc123",
    step_index=3,
    timestamp=datetime.now(tz=timezone.utc),
    context={"tool": "web_search", "timeout_seconds": "30"},
    retry_after_seconds=5,
)
print(f"  Error code   : {error.code}")
print(f"  Category     : {error.category.value}")
print(f"  Severity     : {error.severity.value}")
print(f"  Recoverable  : {error.recoverable}")

print("\n--- Create a RunCapsule model ---")
now = datetime.now(tz=timezone.utc)
capsule = RunCapsule(
    capsule_id="capsule_01HZABCDEFGHIJKLMNOPQRSTUV",
    schema_version="1.0.0",
    created_at=now,
    agent=CapsuleAgent(
        agent_id="research-agent-v1",
        agent_name="Research Agent",
        agent_version="1.0.0",
        model=ModelInfo(
            provider=ModelProvider.ANTHROPIC,
            model_id="claude-opus-4-6",
            parameters={"temperature": 0.7, "max_tokens": 4096},
        ),
        tools_loaded=[],
    ),
    run=CapsuleRun(
        run_id="run_abc123",
        started_at=now,
        ended_at=now,
        status=RunStatus.SUCCESS,
        triggered_by=RunTrigger.HUMAN,
        goal="Research the latest advances in quantum computing.",
    ),
    execution_trace=[
        CapsuleStep(
            step_index=0,
            step_type=StepType.LLM_INFERENCE,
            started_at=now,
            ended_at=now,
            duration_ms=1200,
            tokens=TokenUsage(input_tokens=512, output_tokens=256, total_tokens=768),
        )
    ],
    environment=CapsuleEnvironment(
        aumai_runtime_version="0.1.0",
        python_version="3.12.0",
        os="linux/amd64",
        sandbox_tier=SandboxTier.E2B_MICRO,
    ),
    outcome=CapsuleOutcome(
        final_answer="Quantum computing advances include...",
        total_cost_usd=0.004,
        total_steps=1,
        goal_achieved=True,
        confidence_score=0.85,
    ),
)
print(f"  Capsule ID   : {capsule.capsule_id}")
print(f"  Run status   : {capsule.run.status.value}")
print(f"  Steps        : {len(capsule.execution_trace)}")
print(f"  Goal achieved: {capsule.outcome.goal_achieved}")

print("\n--- Create an AgentCapability model ---")
capability = AgentCapability(
    capability_version="1.0.0",
    agent_id="research-agent-v1",
    agent_name="Research Agent",
    agent_version="1.0.0",
    description="A research agent that searches the web and synthesizes information.",
    sandbox=SandboxConfig(
        tier=SandboxTier.E2B_MICRO,
        startup_timeout_seconds=30,
    ),
    network=NetworkConfig(
        egress_mode=EgressMode.ALLOWLIST_ONLY,
        egress_rules=[
            NetworkEgressRule(
                host="api.anthropic.com",
                ports=[443],
                protocol=NetworkProtocol.HTTPS,
                description="Anthropic API for LLM inference",
            ),
            NetworkEgressRule(
                host="serpapi.com",
                ports=[443],
                protocol=NetworkProtocol.HTTPS,
                description="Web search API",
            ),
        ],
    ),
    filesystem=FilesystemConfig(
        mode=FilesystemMode.READ_WRITE_EPHEMERAL,
        allowed_paths=["/workspace/", "/tmp/"],
        max_file_size_mb=50,
    ),
    resources=ResourceLimits(
        max_cpu_cores=1.0,
        max_memory_mb=512,
        max_run_duration_seconds=300,
        max_llm_calls_per_run=50,
        max_cost_usd_per_run=1.0,
    ),
    permissions=PermissionsConfig(
        scopes=["tools:read", "memory:read", "memory:write"],
        data_classifications=[DataClassification.PUBLIC, DataClassification.INTERNAL],
    ),
    tools=[
        ToolDeclaration(tool_name="web_search", tool_version="1.0.0"),
    ],
)
print(f"  Agent        : {capability.agent_name}")
print(f"  Sandbox tier : {capability.sandbox.tier.value}")
print(f"  Egress mode  : {capability.network.egress_mode.value}")
print(f"  Egress rules : {len(capability.network.egress_rules)}")
print(f"  Max CPU      : {capability.resources.max_cpu_cores}")
print(f"  Tools        : {[t.tool_name for t in capability.tools]}")

# ---------------------------------------------------------------------------
# 3. Validate data against schemas
# ---------------------------------------------------------------------------

print("\n--- Validate Pydantic model against JSON schema ---")

# Serialize the Pydantic model and validate against the JSON schema.
# exclude_none=True removes fields that are None so optional JSON Schema
# fields are not included with a null value (which would fail type checks).
tool_dict = tool.model_dump(mode="json", exclude_none=True)
result = validate(tool_dict, "tool_canonical_ir_v1")
print(f"  ToolCanonicalIR validates against schema: {result}")

# validate_quietly never raises — useful for batch validation
is_valid, message = validate_quietly(tool_dict, "tool_canonical_ir_v1")
print(f"  validate_quietly result: ({is_valid}, '{message}')")

print("\n--- Demonstrate validation failure ---")
bad_data = {"name": "123_invalid_name", "version": "not-semver"}
is_valid, message = validate_quietly(bad_data, "tool_canonical_ir_v1")
print(f"  Bad data validates: {is_valid}")
print(f"  Error message     : {message[:80]}...")

print("\n--- Demonstrate SchemaValidationError ---")
try:
    validate({"completely": "wrong"}, "tool_canonical_ir_v1")
except SchemaValidationError as exc:
    print(f"  Caught SchemaValidationError: {str(exc)[:80]}...")

print("\nDone. All examples completed successfully.")
