"""Tests for aumai_specs.models — Pydantic model validation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from aumai_specs.models import (
    AgentCapability,
    AgentError,
    AgentErrorTaxonomy,
    CapsuleAgent,
    CapsuleEnvironment,
    CapsuleOutcome,
    CapsuleRun,
    CapsuleStep,
    CapabilityMetadata,
    DataClassification,
    EgressMode,
    Environment,
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
    RetryStrategy,
    RunCapsule,
    RunStatus,
    RunTrigger,
    SandboxConfig,
    SandboxTier,
    SecretBinding,
    SeverityLevel,
    SideEffect,
    StepCost,
    StepType,
    TaxonomyCategory,
    TaxonomyErrorEntry,
    TokenUsage,
    ToolBinding,
    ToolCanonicalIR,
    ToolCapability,
    ToolDeclaration,
    ToolMetadata,
    ToolSecurity,
    ToolSourceFormats,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UTC = timezone.utc
_NOW = datetime(2026, 2, 26, 12, 0, 0, tzinfo=_UTC)
_VALID_SHA256 = "sha256:" + "a" * 64


def _make_minimal_tool(**overrides: Any) -> ToolCanonicalIR:
    defaults: dict[str, Any] = {
        "name": "web_search",
        "version": "1.0.0",
        "capabilities": [ToolCapability(action="search", domain="web")],
        "inputs": {"type": "object"},
        "outputs": {"type": "object"},
    }
    defaults.update(overrides)
    return ToolCanonicalIR(**defaults)


def _make_minimal_agent_error(**overrides: Any) -> AgentError:
    defaults: dict[str, Any] = {
        "code": 101,
        "category": ErrorCategory.PLANNING,
        "message": "Goal decomposition failed",
        "severity": SeverityLevel.ERROR,
    }
    defaults.update(overrides)
    return AgentError(**defaults)


def _make_minimal_capsule(**overrides: Any) -> RunCapsule:
    defaults: dict[str, Any] = {
        "capsule_id": "capsule_01HZABCDEFGHIJKLMNOPQRSTUV",
        "schema_version": "1.0.0",
        "created_at": _NOW,
        "agent": CapsuleAgent(
            agent_id="agent-1",
            agent_name="Test Agent",
            agent_version="1.0.0",
            model=ModelInfo(provider=ModelProvider.ANTHROPIC, model_id="claude-opus-4-6"),
        ),
        "run": CapsuleRun(
            run_id="run-1",
            started_at=_NOW,
            ended_at=_NOW,
            status=RunStatus.SUCCESS,
        ),
        "execution_trace": [],
        "environment": CapsuleEnvironment(
            aumai_runtime_version="0.1.0", python_version="3.12.0"
        ),
        "outcome": CapsuleOutcome(final_answer="Done."),
    }
    defaults.update(overrides)
    return RunCapsule(**defaults)


def _make_minimal_capability(**overrides: Any) -> AgentCapability:
    defaults: dict[str, Any] = {
        "capability_version": "1.0.0",
        "agent_id": "agent-1",
        "agent_name": "Test Agent",
        "sandbox": SandboxConfig(tier=SandboxTier.E2B_MICRO),
        "network": NetworkConfig(egress_mode=EgressMode.ISOLATED),
        "filesystem": FilesystemConfig(mode=FilesystemMode.READ_WRITE_EPHEMERAL),
        "resources": ResourceLimits(
            max_cpu_cores=1.0,
            max_memory_mb=512,
            max_run_duration_seconds=300,
        ),
        "permissions": PermissionsConfig(scopes=["tools:read"]),
    }
    defaults.update(overrides)
    return AgentCapability(**defaults)


# ---------------------------------------------------------------------------
# ToolCapability
# ---------------------------------------------------------------------------


class TestToolCapability:
    def test_minimal_valid(self) -> None:
        cap = ToolCapability(action="search", domain="web")
        assert cap.action == "search"
        assert cap.domain == "web"

    def test_full_valid(self) -> None:
        cap = ToolCapability(
            action="read_file",
            domain="filesystem",
            description="Read a file",
            side_effects=[SideEffect.FILESYSTEM_READ],
            idempotent=True,
            cost_estimate="free",
            timeout_seconds=30,
        )
        assert cap.idempotent is True
        assert cap.timeout_seconds == 30

    def test_action_required(self) -> None:
        with pytest.raises(ValidationError):
            ToolCapability(domain="web")  # type: ignore[call-arg]

    def test_domain_required(self) -> None:
        with pytest.raises(ValidationError):
            ToolCapability(action="search")  # type: ignore[call-arg]

    def test_timeout_below_minimum_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolCapability(action="search", domain="web", timeout_seconds=0)

    def test_timeout_above_maximum_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolCapability(action="search", domain="web", timeout_seconds=9999)

    def test_invalid_cost_estimate_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolCapability(action="search", domain="web", cost_estimate="astronomical")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ToolSecurity
# ---------------------------------------------------------------------------


class TestToolSecurity:
    def test_defaults_are_safe(self) -> None:
        sec = ToolSecurity()
        assert sec.pii_handling.value == "none"
        assert sec.audit_required is False
        assert sec.required_permissions == []

    def test_full_valid(self) -> None:
        sec = ToolSecurity(
            required_permissions=["tools:read", "data:confidential"],
            data_classification=DataClassification.CONFIDENTIAL,
            pii_handling="both",  # type: ignore[arg-type]
            audit_required=True,
        )
        assert sec.data_classification == DataClassification.CONFIDENTIAL

    def test_invalid_data_classification_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolSecurity(data_classification="ultra_secret")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ToolCanonicalIR
# ---------------------------------------------------------------------------


class TestToolCanonicalIR:
    def test_minimal_valid(self) -> None:
        tool = _make_minimal_tool()
        assert tool.name == "web_search"
        assert tool.version == "1.0.0"

    def test_name_starting_with_digit_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_tool(name="123tool")

    def test_name_with_spaces_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_tool(name="my tool")

    def test_valid_name_with_dots_and_hyphens(self) -> None:
        tool = _make_minimal_tool(name="com.example.my-tool_v2")
        assert tool.name == "com.example.my-tool_v2"

    def test_invalid_semver_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_tool(version="1.0")

    def test_invalid_semver_with_prefix_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_tool(version="v1.0.0")

    def test_empty_capabilities_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_tool(capabilities=[])

    def test_deprecation_message_without_deprecated_flag_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_tool(
                metadata=ToolMetadata(
                    deprecated=False,
                    deprecation_message="This tool is going away",
                )
            )

    def test_deprecation_message_with_deprecated_flag_passes(self) -> None:
        tool = _make_minimal_tool(
            metadata=ToolMetadata(
                deprecated=True,
                deprecation_message="Use new_tool instead",
                successor_tool="new_tool",
            )
        )
        assert tool.metadata.deprecated is True

    def test_source_formats_optional(self) -> None:
        tool = _make_minimal_tool()
        assert tool.source_formats.openai is None
        assert tool.source_formats.anthropic is None

    def test_with_source_formats(self) -> None:
        tool = _make_minimal_tool(
            source_formats=ToolSourceFormats(
                openai={"type": "function", "function": {"name": "web_search"}},
            )
        )
        assert tool.source_formats.openai is not None

    def test_model_dump_roundtrip(self) -> None:
        tool = _make_minimal_tool()
        dumped = tool.model_dump()
        assert dumped["name"] == "web_search"
        assert dumped["version"] == "1.0.0"


# ---------------------------------------------------------------------------
# AgentError
# ---------------------------------------------------------------------------


class TestAgentError:
    def test_minimal_valid(self) -> None:
        error = _make_minimal_agent_error()
        assert error.code == 101
        assert error.category == ErrorCategory.PLANNING

    def test_all_category_code_mappings(self) -> None:
        mappings = [
            (101, ErrorCategory.PLANNING),
            (201, ErrorCategory.TOOL_EXECUTION),
            (301, ErrorCategory.CONTEXT),
            (401, ErrorCategory.SECURITY),
            (501, ErrorCategory.RESOURCE),
            (601, ErrorCategory.ORCHESTRATION),
        ]
        for code, category in mappings:
            error = AgentError(
                code=code,
                category=category,
                message="test",
                severity=SeverityLevel.ERROR,
            )
            assert error.code == code

    def test_mismatched_category_raises(self) -> None:
        with pytest.raises(ValidationError):
            AgentError(
                code=101,  # planning (1xx)
                category=ErrorCategory.TOOL_EXECUTION,  # wrong category
                message="test",
                severity=SeverityLevel.ERROR,
            )

    def test_code_below_100_raises(self) -> None:
        with pytest.raises(ValidationError):
            AgentError(
                code=99,
                category=ErrorCategory.PLANNING,
                message="test",
                severity=SeverityLevel.ERROR,
            )

    def test_code_above_699_raises(self) -> None:
        with pytest.raises(ValidationError):
            AgentError(
                code=700,
                category=ErrorCategory.PLANNING,
                message="test",
                severity=SeverityLevel.ERROR,
            )

    def test_optional_fields_default_to_none(self) -> None:
        error = _make_minimal_agent_error()
        assert error.agent_id is None
        assert error.run_id is None
        assert error.timestamp is None

    def test_with_context_dict(self) -> None:
        error = _make_minimal_agent_error(
            context={"tool": "web_search", "timeout": "30s"}
        )
        assert error.context["tool"] == "web_search"

    def test_empty_message_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_agent_error(message="")


# ---------------------------------------------------------------------------
# TaxonomyCategory and AgentErrorTaxonomy
# ---------------------------------------------------------------------------


class TestAgentErrorTaxonomy:
    def test_valid_taxonomy(
        self, valid_error_taxonomy_dict: dict[str, Any]
    ) -> None:
        taxonomy = AgentErrorTaxonomy(**valid_error_taxonomy_dict)
        assert taxonomy.taxonomy_version == "1.0.0"
        assert len(taxonomy.categories) == 6

    def test_invalid_semver_raises(
        self, valid_error_taxonomy_dict: dict[str, Any]
    ) -> None:
        valid_error_taxonomy_dict["taxonomy_version"] = "bad"
        with pytest.raises(ValidationError):
            AgentErrorTaxonomy(**valid_error_taxonomy_dict)

    def test_duplicate_error_codes_across_categories_raises(
        self, valid_error_taxonomy_dict: dict[str, Any]
    ) -> None:
        # Duplicate code 101 in second category (tool_execution)
        valid_error_taxonomy_dict["categories"][1]["errors"][0]["code"] = 101
        with pytest.raises(ValidationError):
            AgentErrorTaxonomy(**valid_error_taxonomy_dict)

    def test_error_code_outside_category_prefix_raises(self) -> None:
        with pytest.raises(ValidationError):
            TaxonomyCategory(
                category_name="planning",
                code_prefix=1,
                description="Planning errors",
                errors=[
                    TaxonomyErrorEntry(
                        code=201,  # 2xx doesn't match prefix 1
                        name="WRONG_PREFIX",
                        description="Test",
                        severity=SeverityLevel.ERROR,
                        recoverable=True,
                    )
                ],
            )

    def test_screaming_snake_validation(self) -> None:
        with pytest.raises(ValidationError):
            TaxonomyErrorEntry(
                code=101,
                name="not_screaming_snake",  # must be uppercase
                description="Test",
                severity=SeverityLevel.ERROR,
                recoverable=True,
            )

    def test_valid_screaming_snake_names(self) -> None:
        entry = TaxonomyErrorEntry(
            code=101,
            name="VALID_NAME_123",
            description="Test",
            severity=SeverityLevel.ERROR,
            recoverable=True,
        )
        assert entry.name == "VALID_NAME_123"


# ---------------------------------------------------------------------------
# CapsuleStep
# ---------------------------------------------------------------------------


class TestCapsuleStep:
    def test_minimal_valid(self) -> None:
        step = CapsuleStep(
            step_index=0,
            step_type=StepType.LLM_INFERENCE,
            started_at=_NOW,
            ended_at=_NOW,
        )
        assert step.step_index == 0

    def test_ended_before_started_raises(self) -> None:
        before = datetime(2026, 1, 1, tzinfo=_UTC)
        after = datetime(2026, 2, 1, tzinfo=_UTC)
        with pytest.raises(ValidationError):
            CapsuleStep(
                step_index=0,
                step_type=StepType.LLM_INFERENCE,
                started_at=after,
                ended_at=before,  # before started_at
            )

    def test_tool_name_in_non_tool_step_raises(self) -> None:
        with pytest.raises(ValidationError):
            CapsuleStep(
                step_index=0,
                step_type=StepType.LLM_INFERENCE,  # not a tool step
                started_at=_NOW,
                ended_at=_NOW,
                tool_name="web_search",  # invalid for this step type
            )

    def test_tool_name_valid_for_tool_call(self) -> None:
        step = CapsuleStep(
            step_index=0,
            step_type=StepType.TOOL_CALL,
            started_at=_NOW,
            ended_at=_NOW,
            tool_name="web_search",
            tool_call_id="call_abc123",
        )
        assert step.tool_name == "web_search"

    def test_token_usage_coherence(self) -> None:
        tokens = TokenUsage(
            input_tokens=100,
            output_tokens=50,
            total_tokens=150,
        )
        assert tokens.total_tokens == 150

    def test_token_total_less_than_parts_raises(self) -> None:
        with pytest.raises(ValidationError):
            TokenUsage(
                input_tokens=100,
                output_tokens=50,
                total_tokens=10,  # less than 100+50
            )

    def test_error_code_in_valid_range(self) -> None:
        step = CapsuleStep(
            step_index=0,
            step_type=StepType.ERROR,
            started_at=_NOW,
            ended_at=_NOW,
            error_code=201,
            error_message="Tool timed out",
        )
        assert step.error_code == 201


# ---------------------------------------------------------------------------
# RunCapsule
# ---------------------------------------------------------------------------


class TestRunCapsule:
    def test_minimal_valid(self) -> None:
        capsule = _make_minimal_capsule()
        assert capsule.capsule_id == "capsule_01HZABCDEFGHIJKLMNOPQRSTUV"
        assert capsule.schema_version == "1.0.0"

    def test_invalid_capsule_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_capsule(capsule_id="bad_id")

    def test_wrong_schema_version_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_capsule(schema_version="2.0.0")

    def test_non_contiguous_trace_indices_raises(self) -> None:
        steps = [
            CapsuleStep(
                step_index=0,
                step_type=StepType.LLM_INFERENCE,
                started_at=_NOW,
                ended_at=_NOW,
            ),
            CapsuleStep(
                step_index=5,  # gap — should be 1
                step_type=StepType.LLM_INFERENCE,
                started_at=_NOW,
                ended_at=_NOW,
            ),
        ]
        with pytest.raises(ValidationError):
            _make_minimal_capsule(execution_trace=steps)

    def test_contiguous_trace_passes(self) -> None:
        steps = [
            CapsuleStep(
                step_index=i,
                step_type=StepType.LLM_INFERENCE,
                started_at=_NOW,
                ended_at=_NOW,
            )
            for i in range(3)
        ]
        capsule = _make_minimal_capsule(execution_trace=steps)
        assert len(capsule.execution_trace) == 3

    def test_agent_version_semver_validated(self) -> None:
        with pytest.raises(ValidationError):
            CapsuleAgent(
                agent_id="a",
                agent_name="A",
                agent_version="bad-version",
                model=ModelInfo(
                    provider=ModelProvider.ANTHROPIC,
                    model_id="claude-opus-4-6",
                ),
            )

    def test_agent_system_prompt_hash_format_validated(self) -> None:
        with pytest.raises(ValidationError):
            CapsuleAgent(
                agent_id="a",
                agent_name="A",
                agent_version="1.0.0",
                model=ModelInfo(
                    provider=ModelProvider.ANTHROPIC,
                    model_id="claude-opus-4-6",
                ),
                system_prompt_hash="not-a-sha256",
            )

    def test_valid_sha256_hash_accepted(self) -> None:
        agent = CapsuleAgent(
            agent_id="a",
            agent_name="A",
            agent_version="1.0.0",
            model=ModelInfo(
                provider=ModelProvider.ANTHROPIC, model_id="claude-opus-4-6"
            ),
            system_prompt_hash=_VALID_SHA256,
        )
        assert agent.system_prompt_hash == _VALID_SHA256

    def test_run_ended_before_started_raises(self) -> None:
        before = datetime(2026, 1, 1, tzinfo=_UTC)
        after = datetime(2026, 2, 1, tzinfo=_UTC)
        with pytest.raises(ValidationError):
            CapsuleRun(
                run_id="r",
                started_at=after,
                ended_at=before,
                status=RunStatus.SUCCESS,
            )

    def test_capsule_environment_semver_validated(self) -> None:
        with pytest.raises(ValidationError):
            CapsuleEnvironment(
                aumai_runtime_version="bad",
                python_version="3.12.0",
            )

    def test_confidence_score_out_of_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            CapsuleOutcome(final_answer="done", confidence_score=1.5)

    def test_model_dump_produces_serializable_dict(self) -> None:
        capsule = _make_minimal_capsule()
        dumped = capsule.model_dump()
        assert isinstance(dumped, dict)
        assert dumped["capsule_id"] == "capsule_01HZABCDEFGHIJKLMNOPQRSTUV"


# ---------------------------------------------------------------------------
# NetworkEgressRule
# ---------------------------------------------------------------------------


class TestNetworkEgressRule:
    def test_valid_https_rule(self) -> None:
        rule = NetworkEgressRule(
            host="api.anthropic.com",
            ports=[443],
            protocol=NetworkProtocol.HTTPS,
        )
        assert rule.host == "api.anthropic.com"

    def test_port_below_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(host="example.com", ports=[0], protocol=NetworkProtocol.TCP)

    def test_port_above_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(
                host="example.com", ports=[65536], protocol=NetworkProtocol.TCP
            )

    def test_multiple_ports_valid(self) -> None:
        rule = NetworkEgressRule(
            host="example.com",
            ports=[80, 443, 8080],
            protocol=NetworkProtocol.TCP,
        )
        assert 443 in rule.ports

    def test_empty_ports_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(host="example.com", ports=[], protocol=NetworkProtocol.TCP)

    def test_wildcard_host_accepted(self) -> None:
        rule = NetworkEgressRule(
            host="*.anthropic.com",
            ports=[443],
            protocol=NetworkProtocol.HTTPS,
        )
        assert rule.host == "*.anthropic.com"


# ---------------------------------------------------------------------------
# NetworkConfig
# ---------------------------------------------------------------------------


class TestNetworkConfig:
    def test_isolated_mode_no_rules_required(self) -> None:
        config = NetworkConfig(egress_mode=EgressMode.ISOLATED)
        assert config.egress_rules == []

    def test_allowlist_mode_requires_rules(self) -> None:
        with pytest.raises(ValidationError):
            NetworkConfig(egress_mode=EgressMode.ALLOWLIST_ONLY, egress_rules=[])

    def test_allowlist_mode_with_rules_passes(self) -> None:
        config = NetworkConfig(
            egress_mode=EgressMode.ALLOWLIST_ONLY,
            egress_rules=[
                NetworkEgressRule(
                    host="api.example.com",
                    ports=[443],
                    protocol=NetworkProtocol.HTTPS,
                )
            ],
        )
        assert len(config.egress_rules) == 1

    def test_full_access_mode_no_rules_required(self) -> None:
        config = NetworkConfig(egress_mode=EgressMode.FULL_ACCESS)
        assert config.egress_mode == EgressMode.FULL_ACCESS


# ---------------------------------------------------------------------------
# AgentCapability
# ---------------------------------------------------------------------------


class TestAgentCapability:
    def test_minimal_valid(self) -> None:
        cap = _make_minimal_capability()
        assert cap.capability_version == "1.0.0"
        assert cap.agent_id == "agent-1"

    def test_invalid_semver_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_capability(capability_version="1.0")

    def test_production_sandbox_none_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_capability(
                sandbox=SandboxConfig(tier=SandboxTier.NONE),
                metadata=CapabilityMetadata(environment=Environment.PRODUCTION),
            )

    def test_production_non_none_sandbox_passes(self) -> None:
        cap = _make_minimal_capability(
            sandbox=SandboxConfig(tier=SandboxTier.E2B_MICRO),
            metadata=CapabilityMetadata(environment=Environment.PRODUCTION),
        )
        assert cap.sandbox.tier == SandboxTier.E2B_MICRO

    def test_pii_access_without_confidential_classification_raises(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_capability(
                permissions=PermissionsConfig(
                    scopes=["tools:read"],
                    pii_access=True,
                    data_classifications=[DataClassification.PUBLIC],  # too low
                )
            )

    def test_pii_access_with_confidential_classification_passes(self) -> None:
        cap = _make_minimal_capability(
            permissions=PermissionsConfig(
                scopes=["tools:read", "data:confidential"],
                pii_access=True,
                data_classifications=[DataClassification.CONFIDENTIAL],
            )
        )
        assert cap.permissions.pii_access is True

    def test_pii_access_with_restricted_classification_passes(self) -> None:
        cap = _make_minimal_capability(
            permissions=PermissionsConfig(
                scopes=["tools:read"],
                pii_access=True,
                data_classifications=[DataClassification.RESTRICTED],
            )
        )
        assert cap.permissions.pii_access is True

    def test_docker_image_only_for_docker_tier(self) -> None:
        with pytest.raises(ValidationError):
            _make_minimal_capability(
                sandbox=SandboxConfig(
                    tier=SandboxTier.E2B_MICRO,
                    image="python:3.12-slim",  # image not valid for e2b_micro
                )
            )

    def test_docker_tier_with_image_passes(self) -> None:
        cap = _make_minimal_capability(
            sandbox=SandboxConfig(
                tier=SandboxTier.DOCKER_LOCAL,
                image="python:3.12-slim@sha256:" + "a" * 64,
            )
        )
        assert cap.sandbox.image is not None

    def test_resource_limits_cpu_below_minimum_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(
                max_cpu_cores=0.0,  # below minimum 0.1
                max_memory_mb=512,
                max_run_duration_seconds=300,
            )

    def test_resource_limits_duration_above_maximum_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(
                max_cpu_cores=1.0,
                max_memory_mb=512,
                max_run_duration_seconds=86401,  # above max 86400
            )

    def test_tool_declaration_semver_validated(self) -> None:
        with pytest.raises(ValidationError):
            ToolDeclaration(tool_name="web_search", tool_version="not-semver")

    def test_tool_declaration_valid(self) -> None:
        decl = ToolDeclaration(tool_name="web_search", tool_version="1.2.3")
        assert decl.tool_version == "1.2.3"

    def test_secret_binding_structure(self) -> None:
        binding = SecretBinding(secret_name="OPENAI_API_KEY", env_var="OPENAI_KEY")
        assert binding.secret_name == "OPENAI_API_KEY"
        assert binding.env_var == "OPENAI_KEY"

    def test_model_dump_roundtrip(self) -> None:
        cap = _make_minimal_capability()
        dumped = cap.model_dump()
        assert dumped["agent_id"] == "agent-1"


# ---------------------------------------------------------------------------
# Enum coverage
# ---------------------------------------------------------------------------


class TestEnumCoverage:
    """Ensure all enum members can be constructed from their string values."""

    def test_all_severity_levels(self) -> None:
        for value in ["debug", "info", "warning", "error", "critical"]:
            assert SeverityLevel(value).value == value

    def test_all_run_statuses(self) -> None:
        for value in ["success", "failure", "partial", "cancelled", "timeout"]:
            assert RunStatus(value).value == value

    def test_all_step_types(self) -> None:
        for value in [
            "llm_inference",
            "tool_call",
            "tool_result",
            "planning",
            "reflection",
            "memory_read",
            "memory_write",
            "human_handoff",
            "sub_agent_spawn",
            "sub_agent_result",
            "error",
        ]:
            assert StepType(value).value == value

    def test_all_sandbox_tiers(self) -> None:
        for value in ["e2b_micro", "e2b_standard", "modal_ephemeral", "docker_local", "none"]:
            assert SandboxTier(value).value == value

    def test_all_filesystem_modes(self) -> None:
        for value in ["none", "read_only", "read_write_ephemeral", "read_write_persistent"]:
            assert FilesystemMode(value).value == value

    def test_all_side_effects(self) -> None:
        for value in [
            "network_egress",
            "filesystem_write",
            "filesystem_read",
            "database_write",
            "database_read",
            "memory_mutation",
            "external_api_call",
            "email_send",
            "process_spawn",
            "environment_mutation",
        ]:
            assert SideEffect(value).value == value
