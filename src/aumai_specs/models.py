"""Pydantic v2 models for all AumAI canonical schemas.

Each model corresponds to a top-level schema document or a significant
nested structure within it. All models use strict Pydantic v2 patterns:

- ``model_config = ConfigDict(strict=False, ...)`` with explicit validators
- No use of the deprecated v1 ``@validator`` decorator — only ``@field_validator``
  and ``@model_validator``
- Optional fields carry explicit ``None`` defaults, never bare ``...`` for
  anything that is not truly required
- All collection fields default to empty collections, not ``None``

The models are intentionally kept independent of the loader module so that
downstream packages may use them without pulling in jsonschema if they only
need Pydantic-level validation.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

# ---------------------------------------------------------------------------
# Shared enumerations
# ---------------------------------------------------------------------------


class CostEstimate(str, Enum):
    FREE = "free"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PiiHandling(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    BOTH = "both"


class SeverityLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RetryStrategy(str, Enum):
    NONE = "none"
    IMMEDIATE = "immediate"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    HUMAN_ESCALATION = "human_escalation"


class ErrorCategory(str, Enum):
    PLANNING = "planning"
    TOOL_EXECUTION = "tool_execution"
    CONTEXT = "context"
    SECURITY = "security"
    RESOURCE = "resource"
    ORCHESTRATION = "orchestration"


class SandboxTier(str, Enum):
    E2B_MICRO = "e2b_micro"
    E2B_STANDARD = "e2b_standard"
    MODAL_EPHEMERAL = "modal_ephemeral"
    DOCKER_LOCAL = "docker_local"
    NONE = "none"


class EgressMode(str, Enum):
    ISOLATED = "isolated"
    ALLOWLIST_ONLY = "allowlist_only"
    FULL_ACCESS = "full_access"


class FilesystemMode(str, Enum):
    NONE = "none"
    READ_ONLY = "read_only"
    READ_WRITE_EPHEMERAL = "read_write_ephemeral"
    READ_WRITE_PERSISTENT = "read_write_persistent"


class ModelProvider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    MISTRAL = "mistral"
    COHERE = "cohere"
    LOCAL = "local"


class RunStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class RunTrigger(str, Enum):
    HUMAN = "human"
    SCHEDULER = "scheduler"
    WEBHOOK = "webhook"
    AGENT = "agent"
    TEST = "test"


class StepType(str, Enum):
    LLM_INFERENCE = "llm_inference"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    PLANNING = "planning"
    REFLECTION = "reflection"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    HUMAN_HANDOFF = "human_handoff"
    SUB_AGENT_SPAWN = "sub_agent_spawn"
    SUB_AGENT_RESULT = "sub_agent_result"
    ERROR = "error"


class SideEffect(str, Enum):
    NETWORK_EGRESS = "network_egress"
    FILESYSTEM_WRITE = "filesystem_write"
    FILESYSTEM_READ = "filesystem_read"
    DATABASE_WRITE = "database_write"
    DATABASE_READ = "database_read"
    MEMORY_MUTATION = "memory_mutation"
    EXTERNAL_API_CALL = "external_api_call"
    EMAIL_SEND = "email_send"
    PROCESS_SPAWN = "process_spawn"
    ENVIRONMENT_MUTATION = "environment_mutation"


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    HTTPS = "https"
    HTTP = "http"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------

_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_TOOL_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-\.]*$")
_CAPSULE_ID_PATTERN = re.compile(r"^capsule_[a-zA-Z0-9]{26}$")
_SCREAMING_SNAKE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]+$")


def _validate_semver(value: str) -> str:
    if not _SEMVER_PATTERN.match(value):
        raise ValueError(f"'{value}' is not a valid semantic version (expected X.Y.Z)")
    return value


def _validate_sha256(value: str) -> str:
    if not _SHA256_PATTERN.match(value):
        raise ValueError(
            f"'{value}' is not a valid SHA-256 hash (expected 'sha256:<64 hex chars>')"
        )
    return value


# ---------------------------------------------------------------------------
# Tool Canonical IR models
# ---------------------------------------------------------------------------


class RateLimit(BaseModel):
    """Per-agent rate limits for a tool."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    requests_per_minute: int | None = Field(
        default=None, ge=1, description="Maximum requests per minute."
    )
    requests_per_day: int | None = Field(
        default=None, ge=1, description="Maximum requests per day."
    )


class ToolSecurity(BaseModel):
    """Security metadata for a tool definition."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    required_permissions: list[str] = Field(
        default_factory=list,
        description="Permission scopes required to invoke this tool.",
    )
    data_classification: DataClassification | None = Field(
        default=None,
        description="Highest data classification this tool may access.",
    )
    pii_handling: PiiHandling = Field(
        default=PiiHandling.NONE,
        description="Whether this tool reads or writes PII.",
    )
    audit_required: bool = Field(
        default=False,
        description="Whether every invocation must be audit-logged.",
    )
    rate_limit: RateLimit | None = Field(
        default=None,
        description="Per-agent rate limits.",
    )


class ToolCapability(BaseModel):
    """A single discrete action a tool can perform."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    action: str = Field(
        min_length=1,
        max_length=128,
        description="Verb-noun action (e.g. 'read_file', 'send_email').",
    )
    domain: str = Field(
        min_length=1,
        max_length=128,
        description="Problem domain (e.g. 'filesystem', 'email').",
    )
    description: str | None = Field(default=None, max_length=256)
    side_effects: list[SideEffect] = Field(default_factory=list)
    idempotent: bool | None = Field(default=None)
    cost_estimate: CostEstimate | None = Field(default=None)
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)


class ToolSourceFormats(BaseModel):
    """Original provider-specific definitions before canonicalization."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    openai: dict[str, Any] | None = Field(default=None)
    anthropic: dict[str, Any] | None = Field(default=None)
    mcp: dict[str, Any] | None = Field(default=None)
    langchain: dict[str, Any] | None = Field(default=None)


class ToolMetadata(BaseModel):
    """Registry and lifecycle metadata for a tool."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    author: str | None = Field(default=None, max_length=256)
    created_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)
    deprecated: bool = Field(default=False)
    deprecation_message: str | None = Field(default=None, max_length=512)
    successor_tool: str | None = Field(default=None)
    registry_url: AnyUrl | None = Field(default=None)


class ToolCanonicalIR(BaseModel):
    """Universal intermediate representation for an agent tool definition.

    Example::

        tool = ToolCanonicalIR(
            name="web_search",
            version="1.0.0",
            capabilities=[ToolCapability(action="search", domain="web")],
            inputs={"type": "object", "properties": {"query": {"type": "string"}}},
            outputs={"type": "object"},
        )
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    name: str = Field(
        min_length=1,
        max_length=128,
        description="Unique tool identifier.",
    )
    version: str = Field(description="Semantic version of this tool definition.")
    description: str | None = Field(default=None, max_length=500)
    tags: list[str] = Field(default_factory=list)
    capabilities: list[ToolCapability] = Field(
        min_length=1,
        description="At least one capability must be declared.",
    )
    inputs: dict[str, Any] = Field(
        description="JSON Schema for the tool's input parameters."
    )
    outputs: dict[str, Any] = Field(
        description="JSON Schema for the tool's output structure."
    )
    security: ToolSecurity = Field(default_factory=ToolSecurity)
    source_formats: ToolSourceFormats = Field(default_factory=ToolSourceFormats)
    metadata: ToolMetadata = Field(default_factory=ToolMetadata)

    @field_validator("name")
    @classmethod
    def validate_name_pattern(cls, value: str) -> str:
        if not _TOOL_NAME_PATTERN.match(value):
            raise ValueError(
                f"Tool name '{value}' must start with a letter and contain only "
                "alphanumerics, underscores, hyphens, and dots."
            )
        return value

    @field_validator("version")
    @classmethod
    def validate_version_semver(cls, value: str) -> str:
        return _validate_semver(value)

    @model_validator(mode="after")
    def validate_deprecation_coherence(self) -> "ToolCanonicalIR":
        if self.metadata.deprecation_message and not self.metadata.deprecated:
            raise ValueError(
                "deprecation_message is set but deprecated is False. "
                "Set deprecated=True if providing a deprecation_message."
            )
        return self


# ---------------------------------------------------------------------------
# Agent Error Taxonomy models
# ---------------------------------------------------------------------------


class AgentError(BaseModel):
    """A single structured error instance emitted by an agent at runtime.

    Example::

        error = AgentError(
            code=201,
            category=ErrorCategory.TOOL_EXECUTION,
            message="Tool 'web_search' timed out after 30s",
            severity=SeverityLevel.ERROR,
        )
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    code: int = Field(ge=100, le=699, description="Numeric error code.")
    category: ErrorCategory = Field(description="High-level error category.")
    message: str = Field(min_length=1, max_length=1024)
    severity: SeverityLevel
    recoverable: bool = Field(default=True)
    agent_id: str | None = Field(default=None)
    run_id: str | None = Field(default=None)
    step_index: int | None = Field(default=None, ge=0)
    timestamp: datetime | None = Field(default=None)
    context: dict[str, str] = Field(default_factory=dict)
    cause: str | None = Field(default=None, max_length=2048)
    retry_after_seconds: int | None = Field(default=None, ge=0)

    @field_validator("code")
    @classmethod
    def validate_code_category_alignment(cls, value: int) -> int:
        # Codes must be in [100, 699] — already enforced by ge/le.
        # Additionally validate the hundreds digit is in [1, 6].
        prefix = value // 100
        if prefix < 1 or prefix > 6:
            raise ValueError(
                f"Error code {value} has hundreds prefix {prefix}. "
                "Valid range is 1xx-6xx."
            )
        return value

    @model_validator(mode="after")
    def validate_category_matches_code_prefix(self) -> "AgentError":
        """Ensure the category enum aligns with the code's hundreds digit."""
        prefix_to_category: dict[int, ErrorCategory] = {
            1: ErrorCategory.PLANNING,
            2: ErrorCategory.TOOL_EXECUTION,
            3: ErrorCategory.CONTEXT,
            4: ErrorCategory.SECURITY,
            5: ErrorCategory.RESOURCE,
            6: ErrorCategory.ORCHESTRATION,
        }
        expected = prefix_to_category[self.code // 100]
        if self.category != expected:
            raise ValueError(
                f"Code {self.code} belongs to category '{expected.value}' "
                f"but category '{self.category.value}' was provided."
            )
        return self


class TaxonomyErrorEntry(BaseModel):
    """A single error entry in the taxonomy definition document."""

    model_config = ConfigDict(str_strip_whitespace=True)

    code: int = Field(ge=100, le=699)
    name: str = Field(description="SCREAMING_SNAKE_CASE symbolic name.")
    description: str = Field(min_length=1, max_length=512)
    severity: SeverityLevel
    recoverable: bool
    retry_strategy: RetryStrategy = Field(default=RetryStrategy.NONE)
    example_message: str | None = Field(default=None, max_length=256)

    @field_validator("name")
    @classmethod
    def validate_screaming_snake(cls, value: str) -> str:
        if not _SCREAMING_SNAKE_PATTERN.match(value):
            raise ValueError(
                f"Error name '{value}' must be SCREAMING_SNAKE_CASE "
                "(uppercase letters, digits, underscores only)."
            )
        return value


class TaxonomyCategory(BaseModel):
    """A category grouping in the error taxonomy definition document."""

    model_config = ConfigDict(str_strip_whitespace=True)

    category_name: str = Field(min_length=1)
    code_prefix: int = Field(ge=1, le=6)
    description: str = Field(min_length=1)
    errors: list[TaxonomyErrorEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_error_codes_match_prefix(self) -> "TaxonomyCategory":
        for entry in self.errors:
            if entry.code // 100 != self.code_prefix:
                raise ValueError(
                    f"Error code {entry.code} does not match category prefix "
                    f"{self.code_prefix}xx."
                )
        return self


class AgentErrorTaxonomy(BaseModel):
    """Top-level taxonomy document listing all defined error codes."""

    model_config = ConfigDict(str_strip_whitespace=True)

    taxonomy_version: str
    categories: list[TaxonomyCategory] = Field(min_length=1)

    @field_validator("taxonomy_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        return _validate_semver(value)

    @model_validator(mode="after")
    def validate_no_duplicate_codes(self) -> "AgentErrorTaxonomy":
        seen_codes: set[int] = set()
        for category in self.categories:
            for entry in category.errors:
                if entry.code in seen_codes:
                    raise ValueError(
                        f"Duplicate error code {entry.code} found in taxonomy."
                    )
                seen_codes.add(entry.code)
        return self


# ---------------------------------------------------------------------------
# Capsule Format models
# ---------------------------------------------------------------------------


class TokenUsage(BaseModel):
    """Token usage for an LLM inference step."""

    model_config = ConfigDict(validate_assignment=True)

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_total_coherence(self) -> "TokenUsage":
        """If total_tokens is non-zero, verify it is consistent with parts."""
        computed = self.input_tokens + self.output_tokens
        if self.total_tokens != 0 and self.total_tokens < computed:
            raise ValueError(
                f"total_tokens ({self.total_tokens}) is less than "
                f"input_tokens + output_tokens ({computed})."
            )
        return self


class StepCost(BaseModel):
    """Cost attribution for a single execution step."""

    model_config = ConfigDict(validate_assignment=True)

    input_cost_usd: float = Field(default=0.0, ge=0.0)
    output_cost_usd: float = Field(default=0.0, ge=0.0)
    tool_cost_usd: float = Field(default=0.0, ge=0.0)
    total_cost_usd: float = Field(default=0.0, ge=0.0)


class CapsuleStep(BaseModel):
    """A single step in the agent's execution trace.

    Example::

        step = CapsuleStep(
            step_index=0,
            step_type=StepType.LLM_INFERENCE,
            started_at=datetime.utcnow(),
            ended_at=datetime.utcnow(),
            tokens=TokenUsage(input_tokens=512, output_tokens=128),
        )
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    step_index: int = Field(ge=0)
    step_type: StepType
    started_at: datetime
    ended_at: datetime
    duration_ms: int | None = Field(default=None, ge=0)
    input: dict[str, Any] | str | None = Field(default=None)
    output: dict[str, Any] | str | None = Field(default=None)
    tokens: TokenUsage | None = Field(default=None)
    cost: StepCost | None = Field(default=None)
    tool_name: str | None = Field(default=None)
    tool_call_id: str | None = Field(default=None)
    error_code: int | None = Field(default=None, ge=100, le=699)
    error_message: str | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_timing_order(self) -> "CapsuleStep":
        if self.ended_at < self.started_at:
            raise ValueError(
                f"ended_at ({self.ended_at}) must not be before "
                f"started_at ({self.started_at}) for step {self.step_index}."
            )
        return self

    @model_validator(mode="after")
    def validate_tool_fields_coherence(self) -> "CapsuleStep":
        """tool_name should only be present for tool_call/tool_result steps."""
        tool_step_types = {StepType.TOOL_CALL, StepType.TOOL_RESULT}
        if self.tool_name and self.step_type not in tool_step_types:
            raise ValueError(
                f"tool_name is only valid for {tool_step_types} steps, "
                f"not '{self.step_type}'."
            )
        return self


class ModelInfo(BaseModel):
    """Model identity and inference parameters."""

    model_config = ConfigDict(str_strip_whitespace=True)

    provider: ModelProvider
    model_id: str = Field(min_length=1)
    model_version: str | None = Field(default=None)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ToolBinding(BaseModel):
    """A tool loaded by the agent at run time."""

    model_config = ConfigDict(str_strip_whitespace=True)

    tool_name: str = Field(min_length=1)
    tool_version: str
    tool_ir_hash: str | None = Field(default=None)

    @field_validator("tool_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        return _validate_semver(value)

    @field_validator("tool_ir_hash")
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_sha256(value)
        return value


class CapsuleAgent(BaseModel):
    """Agent identity and configuration recorded in a capsule."""

    model_config = ConfigDict(str_strip_whitespace=True)

    agent_id: str = Field(min_length=1)
    agent_name: str = Field(min_length=1)
    agent_version: str
    model: ModelInfo
    system_prompt_hash: str | None = Field(default=None)
    tools_loaded: list[ToolBinding] = Field(default_factory=list)

    @field_validator("agent_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        return _validate_semver(value)

    @field_validator("system_prompt_hash")
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_sha256(value)
        return value


class CapsuleRun(BaseModel):
    """Run-level metadata recorded in a capsule."""

    model_config = ConfigDict(str_strip_whitespace=True)

    run_id: str = Field(min_length=1)
    started_at: datetime
    ended_at: datetime
    status: RunStatus
    triggered_by: RunTrigger | None = Field(default=None)
    parent_run_id: str | None = Field(default=None)
    goal: str | None = Field(default=None, max_length=2048)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_run_timing(self) -> "CapsuleRun":
        if self.ended_at < self.started_at:
            raise ValueError("ended_at must not be before started_at.")
        return self


class CapsuleEnvironment(BaseModel):
    """Runtime environment snapshot."""

    model_config = ConfigDict(str_strip_whitespace=True)

    aumai_runtime_version: str
    python_version: str
    os: str | None = Field(default=None)
    container_image: str | None = Field(default=None)
    sandbox_tier: SandboxTier | None = Field(default=None)
    network_policy: EgressMode | None = Field(default=None)
    extra: dict[str, str] = Field(default_factory=dict)

    @field_validator("aumai_runtime_version", "python_version")
    @classmethod
    def validate_semver(cls, value: str) -> str:
        return _validate_semver(value)


class CapsuleOutcome(BaseModel):
    """Final result and aggregate statistics for a run."""

    model_config = ConfigDict(validate_assignment=True)

    final_answer: str | dict[str, Any] | None = Field(
        description="The agent's final response or output artifact."
    )
    structured_output: dict[str, Any] | None = Field(default=None)
    total_tokens: TokenUsage | None = Field(default=None)
    total_cost_usd: float | None = Field(default=None, ge=0.0)
    total_steps: int | None = Field(default=None, ge=0)
    total_tool_calls: int | None = Field(default=None, ge=0)
    errors_encountered: list[int] = Field(default_factory=list)
    goal_achieved: bool | None = Field(default=None)
    confidence_score: float | None = Field(default=None, ge=0.0, le=1.0)


class CapsuleIntegrity(BaseModel):
    """Cryptographic integrity metadata."""

    model_config = ConfigDict(str_strip_whitespace=True)

    capsule_hash: str | None = Field(default=None)
    signature: str | None = Field(default=None)
    signing_key_id: str | None = Field(default=None)

    @field_validator("capsule_hash")
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_sha256(value)
        return value


class RunCapsule(BaseModel):
    """Immutable record of a complete agent execution.

    Example::

        capsule = RunCapsule(
            capsule_id="capsule_01HZABCDEFGHIJKLMNOPQRSTUV",
            schema_version="1.0.0",
            created_at=datetime.utcnow(),
            agent=CapsuleAgent(...),
            run=CapsuleRun(...),
            execution_trace=[CapsuleStep(...)],
            environment=CapsuleEnvironment(...),
            outcome=CapsuleOutcome(final_answer="Done."),
        )
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    capsule_id: str = Field(description="Globally unique capsule identifier.")
    schema_version: str = Field(description="Must be '1.0.0' for v1 capsules.")
    created_at: datetime
    agent: CapsuleAgent
    run: CapsuleRun
    execution_trace: list[CapsuleStep] = Field(default_factory=list)
    environment: CapsuleEnvironment
    outcome: CapsuleOutcome
    integrity: CapsuleIntegrity = Field(default_factory=CapsuleIntegrity)

    @field_validator("capsule_id")
    @classmethod
    def validate_capsule_id_format(cls, value: str) -> str:
        if not _CAPSULE_ID_PATTERN.match(value):
            raise ValueError(
                f"capsule_id '{value}' must match pattern 'capsule_<26 alphanumeric chars>'."
            )
        return value

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if value != "1.0.0":
            raise ValueError(
                f"schema_version must be '1.0.0' for v1 capsules, got '{value}'."
            )
        return value

    @model_validator(mode="after")
    def validate_trace_indices_contiguous(self) -> "RunCapsule":
        """Execution trace step indices must be 0-based and contiguous."""
        for expected_idx, step in enumerate(self.execution_trace):
            if step.step_index != expected_idx:
                raise ValueError(
                    f"Execution trace step at position {expected_idx} has "
                    f"step_index={step.step_index}. Indices must be contiguous "
                    f"and zero-based."
                )
        return self


# ---------------------------------------------------------------------------
# Agent Capability Declaration models
# ---------------------------------------------------------------------------


class SecretBinding(BaseModel):
    """A secret reference injected as an environment variable."""

    model_config = ConfigDict(str_strip_whitespace=True)

    secret_name: str = Field(min_length=1)
    env_var: str = Field(min_length=1)


class SandboxConfig(BaseModel):
    """Sandbox environment configuration."""

    model_config = ConfigDict(str_strip_whitespace=True)

    tier: SandboxTier
    image: str | None = Field(default=None)
    startup_timeout_seconds: int = Field(default=30, ge=1, le=300)
    environment_variables: dict[str, str] = Field(default_factory=dict)
    secrets: list[SecretBinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_image_only_for_docker(self) -> "SandboxConfig":
        if self.image and self.tier != SandboxTier.DOCKER_LOCAL:
            raise ValueError(
                "image is only applicable when tier is 'docker_local'."
            )
        return self


class NetworkEgressRule(BaseModel):
    """A single network egress allowlist rule.

    Example::

        rule = NetworkEgressRule(
            host="api.anthropic.com",
            ports=[443],
            protocol=NetworkProtocol.HTTPS,
            description="Anthropic API access",
        )
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    host: str = Field(min_length=1, description="Hostname or CIDR range.")
    ports: list[int] = Field(min_length=1)
    protocol: NetworkProtocol
    description: str | None = Field(default=None, max_length=256)
    rate_limit_rps: int | None = Field(default=None, ge=1)

    @field_validator("ports")
    @classmethod
    def validate_port_range(cls, value: list[int]) -> list[int]:
        for port in value:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is out of range [1, 65535].")
        return value


class NetworkConfig(BaseModel):
    """Network egress policy configuration."""

    model_config = ConfigDict(str_strip_whitespace=True)

    egress_mode: EgressMode
    egress_rules: list[NetworkEgressRule] = Field(default_factory=list)
    dns_policy: str = Field(default="default")

    @model_validator(mode="after")
    def validate_allowlist_has_rules(self) -> "NetworkConfig":
        if self.egress_mode == EgressMode.ALLOWLIST_ONLY and not self.egress_rules:
            raise ValueError(
                "egress_rules must be non-empty when egress_mode is 'allowlist_only'."
            )
        return self


class FilesystemConfig(BaseModel):
    """Filesystem access configuration."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mode: FilesystemMode
    allowed_paths: list[str] = Field(default_factory=list)
    max_file_size_mb: int = Field(default=100, ge=1, le=10240)
    max_total_storage_mb: int = Field(default=1024, ge=1, le=102400)


class ResourceLimits(BaseModel):
    """Compute resource limits for an agent."""

    model_config = ConfigDict(validate_assignment=True)

    max_cpu_cores: float = Field(ge=0.1, le=64.0)
    max_memory_mb: int = Field(ge=64, le=131072)
    max_run_duration_seconds: int = Field(ge=1, le=86400)
    max_concurrent_tool_calls: int = Field(default=5, ge=1, le=100)
    max_llm_calls_per_run: int = Field(default=100, ge=1, le=10000)
    max_tokens_per_run: int | None = Field(default=None, ge=1000)
    max_cost_usd_per_run: float | None = Field(default=None, ge=0.001)
    gpu_required: bool = Field(default=False)


class PermissionsConfig(BaseModel):
    """Declared permission scopes for an agent."""

    model_config = ConfigDict(str_strip_whitespace=True)

    scopes: list[str] = Field(default_factory=list)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    pii_access: bool = Field(default=False)
    audit_all_runs: bool = Field(default=True)


class ToolDeclaration(BaseModel):
    """A tool binding in a capability declaration."""

    model_config = ConfigDict(str_strip_whitespace=True)

    tool_name: str = Field(min_length=1)
    tool_version: str
    capability_subset: list[str] = Field(default_factory=list)
    optional: bool = Field(default=False)

    @field_validator("tool_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        return _validate_semver(value)


class CapabilityMetadata(BaseModel):
    """Lifecycle and ownership metadata for a capability manifest."""

    model_config = ConfigDict(str_strip_whitespace=True)

    owner_team: str | None = Field(default=None)
    approved_by: str | None = Field(default=None)
    approved_at: datetime | None = Field(default=None)
    review_required_at: datetime | None = Field(default=None)
    environment: Environment | None = Field(default=None)
    labels: dict[str, str] = Field(default_factory=dict)


class AgentCapability(BaseModel):
    """Full capability declaration for an AumAI agent.

    Example::

        capability = AgentCapability(
            capability_version="1.0.0",
            agent_id="research-agent-v1",
            agent_name="Research Agent",
            sandbox=SandboxConfig(tier=SandboxTier.E2B_MICRO),
            network=NetworkConfig(egress_mode=EgressMode.ISOLATED),
            filesystem=FilesystemConfig(mode=FilesystemMode.READ_WRITE_EPHEMERAL),
            resources=ResourceLimits(
                max_cpu_cores=1.0,
                max_memory_mb=512,
                max_run_duration_seconds=300,
            ),
            permissions=PermissionsConfig(scopes=["tools:read"]),
        )
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    capability_version: str
    agent_id: str = Field(min_length=1, max_length=128)
    agent_name: str = Field(min_length=1, max_length=128)
    agent_version: str | None = Field(default=None)
    description: str | None = Field(default=None, max_length=1024)
    sandbox: SandboxConfig
    network: NetworkConfig
    filesystem: FilesystemConfig
    resources: ResourceLimits
    permissions: PermissionsConfig
    tools: list[ToolDeclaration] = Field(default_factory=list)
    metadata: CapabilityMetadata = Field(default_factory=CapabilityMetadata)

    @field_validator("capability_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        return _validate_semver(value)

    @field_validator("agent_version")
    @classmethod
    def validate_agent_version(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_semver(value)
        return value

    @model_validator(mode="after")
    def validate_production_sandbox_requirements(self) -> "AgentCapability":
        """Production agents must not use sandbox tier 'none'."""
        if (
            self.metadata.environment == Environment.PRODUCTION
            and self.sandbox.tier == SandboxTier.NONE
        ):
            raise ValueError(
                "Production agents must not use sandbox tier 'none'. "
                "Use e2b_micro or higher."
            )
        return self

    @model_validator(mode="after")
    def validate_pii_requires_confidential_classification(
        self,
    ) -> "AgentCapability":
        """Agents handling PII must declare at minimum 'confidential' classification."""
        if self.permissions.pii_access:
            elevated = {DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED}
            if not any(dc in elevated for dc in self.permissions.data_classifications):
                raise ValueError(
                    "Agents with pii_access=True must declare at least "
                    "'confidential' in data_classifications."
                )
        return self
