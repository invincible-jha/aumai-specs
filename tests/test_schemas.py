"""Tests for the raw JSON/YAML schema files themselves.

These tests verify that each schema file:
  1. Exists and is readable
  2. Is parseable (valid JSON / valid YAML)
  3. Is itself a valid JSON Schema document (meta-validation)
  4. Contains the expected structural elements

This is intentionally a schema-level contract test, not a model test.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jsonschema
import jsonschema.validators
import pytest
import yaml

from aumai_specs.loader import get_schema_path, load_schema


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ALL_SCHEMA_NAMES = [
    "tool_canonical_ir_v1",
    "agent_error_taxonomy_v1",
    "capsule_format_v1",
    "agent_capability_v1",
]


def _get_validator_for(schema: dict[str, Any]) -> type:
    """Return the jsonschema validator class appropriate for the schema."""
    return jsonschema.validators.validator_for(schema)


# ---------------------------------------------------------------------------
# File existence and parsability
# ---------------------------------------------------------------------------


class TestSchemaFiles:
    @pytest.mark.parametrize("schema_name", ALL_SCHEMA_NAMES)
    def test_schema_file_exists(self, schema_name: str) -> None:
        path = get_schema_path(schema_name)
        assert path.exists(), f"Schema file for '{schema_name}' does not exist."

    @pytest.mark.parametrize("schema_name", ALL_SCHEMA_NAMES)
    def test_schema_file_is_not_empty(self, schema_name: str) -> None:
        path = get_schema_path(schema_name)
        assert path.stat().st_size > 0, f"Schema file '{schema_name}' is empty."

    @pytest.mark.parametrize("schema_name", ALL_SCHEMA_NAMES)
    def test_schema_loads_as_dict(self, schema_name: str) -> None:
        schema = load_schema(schema_name)
        assert isinstance(schema, dict), f"Schema '{schema_name}' did not load as dict."

    def test_json_schemas_are_valid_json_files(self) -> None:
        """Ensure .json schemas are valid JSON (not just parseable YAML)."""
        import json

        for name in ["tool_canonical_ir_v1", "agent_error_taxonomy_v1", "capsule_format_v1"]:
            path = get_schema_path(name)
            content = path.read_text(encoding="utf-8")
            parsed = json.loads(content)
            assert isinstance(parsed, dict)

    def test_yaml_schema_is_valid_yaml(self) -> None:
        path = get_schema_path("agent_capability_v1")
        content = path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Meta-validation: each schema must itself be a valid JSON Schema
# ---------------------------------------------------------------------------


class TestMetaValidation:
    @pytest.mark.parametrize("schema_name", ALL_SCHEMA_NAMES)
    def test_schema_is_valid_json_schema(self, schema_name: str) -> None:
        """Each schema must pass jsonschema's own meta-schema validation."""
        schema = load_schema(schema_name)
        validator_cls = _get_validator_for(schema)
        # check_schema raises jsonschema.SchemaError if the schema is invalid
        validator_cls.check_schema(schema)


# ---------------------------------------------------------------------------
# Structural expectations per schema
# ---------------------------------------------------------------------------


class TestToolCanonicalIRSchema:
    def setup_method(self) -> None:
        self.schema = load_schema("tool_canonical_ir_v1")

    def test_has_schema_meta_key(self) -> None:
        assert "$schema" in self.schema

    def test_has_id_key(self) -> None:
        assert "$id" in self.schema

    def test_id_points_to_correct_url(self) -> None:
        assert "tool-canonical-ir" in self.schema["$id"]
        assert "v1" in self.schema["$id"]

    def test_title_is_correct(self) -> None:
        assert self.schema["title"] == "AumAI Tool Canonical IR"

    def test_type_is_object(self) -> None:
        assert self.schema["type"] == "object"

    def test_required_contains_essential_fields(self) -> None:
        required = self.schema["required"]
        for field in ["name", "version", "capabilities", "inputs", "outputs"]:
            assert field in required, f"Required field '{field}' missing from schema."

    def test_properties_section_exists(self) -> None:
        assert "properties" in self.schema

    def test_name_has_pattern_constraint(self) -> None:
        assert "pattern" in self.schema["properties"]["name"]

    def test_version_has_semver_pattern(self) -> None:
        assert "pattern" in self.schema["properties"]["version"]

    def test_capabilities_is_array_with_minItems(self) -> None:
        caps = self.schema["properties"]["capabilities"]
        assert caps["type"] == "array"
        assert caps["minItems"] >= 1

    def test_security_has_data_classification_enum(self) -> None:
        sec_props = self.schema["properties"]["security"]["properties"]
        assert "data_classification" in sec_props
        assert "enum" in sec_props["data_classification"]

    def test_cost_estimate_enum_values(self) -> None:
        cap_props = (
            self.schema["properties"]["capabilities"]["items"]["properties"]
        )
        enum_values = cap_props["cost_estimate"]["enum"]
        assert set(enum_values) == {"free", "low", "medium", "high"}

    def test_side_effects_uses_known_enum_values(self) -> None:
        cap_items = self.schema["properties"]["capabilities"]["items"]
        side_effects_items = cap_items["properties"]["side_effects"]["items"]
        assert "enum" in side_effects_items
        assert "network_egress" in side_effects_items["enum"]

    def test_source_formats_has_four_providers(self) -> None:
        sf_props = self.schema["properties"]["source_formats"]["properties"]
        for provider in ["openai", "anthropic", "mcp", "langchain"]:
            assert provider in sf_props


class TestAgentErrorTaxonomySchema:
    def setup_method(self) -> None:
        self.schema = load_schema("agent_error_taxonomy_v1")

    def test_has_id_pointing_to_correct_url(self) -> None:
        assert "agent-error-taxonomy" in self.schema["$id"]

    def test_title_is_correct(self) -> None:
        assert self.schema["title"] == "AumAI Agent Error Taxonomy"

    def test_required_contains_taxonomy_version_and_categories(self) -> None:
        assert "taxonomy_version" in self.schema["required"]
        assert "categories" in self.schema["required"]

    def test_categories_is_array(self) -> None:
        cats = self.schema["properties"]["categories"]
        assert cats["type"] == "array"

    def test_error_instance_def_exists(self) -> None:
        assert "error_instance" in self.schema.get("$defs", {})

    def test_error_instance_has_code_with_range(self) -> None:
        instance_props = self.schema["$defs"]["error_instance"]["properties"]
        assert "code" in instance_props
        assert instance_props["code"]["minimum"] == 100
        assert instance_props["code"]["maximum"] == 699

    def test_error_instance_severity_has_enum(self) -> None:
        instance_props = self.schema["$defs"]["error_instance"]["properties"]
        assert "enum" in instance_props["severity"]

    def test_error_instance_category_has_all_six_values(self) -> None:
        instance_props = self.schema["$defs"]["error_instance"]["properties"]
        categories = instance_props["category"]["enum"]
        expected = {
            "planning",
            "tool_execution",
            "context",
            "security",
            "resource",
            "orchestration",
        }
        assert set(categories) == expected

    def test_taxonomy_version_has_semver_pattern(self) -> None:
        assert "pattern" in self.schema["properties"]["taxonomy_version"]


class TestCapsuleFormatSchema:
    def setup_method(self) -> None:
        self.schema = load_schema("capsule_format_v1")

    def test_title_is_correct(self) -> None:
        assert "Capsule" in self.schema["title"]

    def test_capsule_id_has_pattern(self) -> None:
        assert "pattern" in self.schema["properties"]["capsule_id"]

    def test_schema_version_is_const_1_0_0(self) -> None:
        assert self.schema["properties"]["schema_version"]["const"] == "1.0.0"

    def test_required_contains_all_top_level_fields(self) -> None:
        required = self.schema["required"]
        for field in [
            "capsule_id",
            "schema_version",
            "created_at",
            "agent",
            "run",
            "execution_trace",
            "environment",
            "outcome",
        ]:
            assert field in required

    def test_execution_trace_is_array(self) -> None:
        trace = self.schema["properties"]["execution_trace"]
        assert trace["type"] == "array"

    def test_step_type_enum_contains_all_types(self) -> None:
        step_props = self.schema["properties"]["execution_trace"]["items"]["properties"]
        step_types = step_props["step_type"]["enum"]
        for expected in [
            "llm_inference",
            "tool_call",
            "tool_result",
            "planning",
            "error",
        ]:
            assert expected in step_types

    def test_tokens_has_input_and_output(self) -> None:
        step_props = self.schema["properties"]["execution_trace"]["items"]["properties"]
        token_props = step_props["tokens"]["properties"]
        assert "input_tokens" in token_props
        assert "output_tokens" in token_props

    def test_model_provider_enum_values(self) -> None:
        model_props = (
            self.schema["properties"]["agent"]["properties"]["model"]["properties"]
        )
        providers = model_props["provider"]["enum"]
        assert "anthropic" in providers
        assert "openai" in providers

    def test_run_status_enum_values(self) -> None:
        run_props = self.schema["properties"]["run"]["properties"]
        statuses = run_props["status"]["enum"]
        for status in ["success", "failure", "partial", "cancelled", "timeout"]:
            assert status in statuses

    def test_integrity_field_exists(self) -> None:
        assert "integrity" in self.schema["properties"]

    def test_environment_requires_runtime_and_python_version(self) -> None:
        env_required = self.schema["properties"]["environment"]["required"]
        assert "aumai_runtime_version" in env_required
        assert "python_version" in env_required


class TestAgentCapabilitySchema:
    def setup_method(self) -> None:
        self.schema = load_schema("agent_capability_v1")

    def test_title_is_correct(self) -> None:
        assert "Capability" in self.schema["title"]

    def test_required_contains_all_core_sections(self) -> None:
        required = self.schema["required"]
        for field in [
            "capability_version",
            "agent_id",
            "agent_name",
            "sandbox",
            "network",
            "filesystem",
            "resources",
            "permissions",
        ]:
            assert field in required

    def test_sandbox_tier_enum_contains_expected_values(self) -> None:
        sandbox_props = self.schema["properties"]["sandbox"]["properties"]
        tiers = sandbox_props["tier"]["enum"]
        for tier in ["e2b_micro", "e2b_standard", "modal_ephemeral", "docker_local", "none"]:
            assert tier in tiers

    def test_network_egress_mode_has_three_options(self) -> None:
        net_props = self.schema["properties"]["network"]["properties"]
        modes = net_props["egress_mode"]["enum"]
        assert set(modes) == {"isolated", "allowlist_only", "full_access"}

    def test_filesystem_mode_has_four_options(self) -> None:
        fs_props = self.schema["properties"]["filesystem"]["properties"]
        modes = fs_props["mode"]["enum"]
        assert set(modes) == {
            "none",
            "read_only",
            "read_write_ephemeral",
            "read_write_persistent",
        }

    def test_resources_has_required_fields(self) -> None:
        res_required = self.schema["properties"]["resources"]["required"]
        for field in ["max_cpu_cores", "max_memory_mb", "max_run_duration_seconds"]:
            assert field in res_required

    def test_egress_rule_ports_have_range_constraints(self) -> None:
        rule_props = (
            self.schema["properties"]["network"]["properties"]["egress_rules"]["items"]["properties"]
        )
        assert "ports" in rule_props

    def test_permissions_has_scopes_array(self) -> None:
        perm_props = self.schema["properties"]["permissions"]["properties"]
        assert "scopes" in perm_props
        assert perm_props["scopes"]["type"] == "array"

    def test_metadata_section_exists(self) -> None:
        assert "metadata" in self.schema["properties"]

    def test_metadata_environment_enum_values(self) -> None:
        meta_props = self.schema["properties"]["metadata"]["properties"]
        envs = meta_props["environment"]["enum"]
        assert set(envs) == {"development", "staging", "production"}
