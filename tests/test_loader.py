"""Tests for aumai_specs.loader — schema loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from aumai_specs.loader import (
    SchemaNotFoundError,
    SchemaParseError,
    SchemaValidationError,
    get_schema_path,
    list_schemas,
    load_schema,
    validate,
    validate_quietly,
)


# ---------------------------------------------------------------------------
# list_schemas
# ---------------------------------------------------------------------------


class TestListSchemas:
    def test_returns_all_four_canonical_schemas(self) -> None:
        names = list_schemas()
        assert "tool_canonical_ir_v1" in names
        assert "agent_error_taxonomy_v1" in names
        assert "capsule_format_v1" in names
        assert "agent_capability_v1" in names

    def test_returns_sorted_list(self) -> None:
        names = list_schemas()
        assert names == sorted(names)

    def test_returns_list_type(self) -> None:
        assert isinstance(list_schemas(), list)

    def test_no_duplicates(self) -> None:
        names = list_schemas()
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# get_schema_path
# ---------------------------------------------------------------------------


class TestGetSchemaPath:
    @pytest.mark.parametrize(
        "schema_name",
        [
            "tool_canonical_ir_v1",
            "agent_error_taxonomy_v1",
            "capsule_format_v1",
            "agent_capability_v1",
        ],
    )
    def test_returns_existing_path(self, schema_name: str) -> None:
        path = get_schema_path(schema_name)
        assert isinstance(path, Path)
        assert path.exists()

    def test_raises_for_nonexistent_schema(self) -> None:
        with pytest.raises(SchemaNotFoundError) as exc_info:
            get_schema_path("nonexistent_schema_v99")
        assert "nonexistent_schema_v99" in str(exc_info.value)

    def test_error_message_lists_available_schemas(self) -> None:
        with pytest.raises(SchemaNotFoundError) as exc_info:
            get_schema_path("bogus")
        message = str(exc_info.value)
        assert "tool_canonical_ir_v1" in message

    def test_schema_not_found_error_has_schema_name_attribute(self) -> None:
        with pytest.raises(SchemaNotFoundError) as exc_info:
            get_schema_path("missing")
        assert exc_info.value.schema_name == "missing"


# ---------------------------------------------------------------------------
# load_schema
# ---------------------------------------------------------------------------


class TestLoadSchema:
    @pytest.mark.parametrize(
        "schema_name,expected_title",
        [
            ("tool_canonical_ir_v1", "AumAI Tool Canonical IR"),
            ("agent_error_taxonomy_v1", "AumAI Agent Error Taxonomy"),  # top-level title field
            ("capsule_format_v1", "AumAI Deterministic Run Capsule"),
            ("agent_capability_v1", "AumAI Agent Capability Declaration"),
        ],
    )
    def test_loads_schema_with_correct_title(
        self, schema_name: str, expected_title: str
    ) -> None:
        schema = load_schema(schema_name)
        assert schema["title"] == expected_title

    def test_returns_dict(self) -> None:
        schema = load_schema("tool_canonical_ir_v1")
        assert isinstance(schema, dict)

    def test_raises_schema_not_found_error(self) -> None:
        with pytest.raises(SchemaNotFoundError):
            load_schema("does_not_exist_v0")

    def test_caching_returns_same_object(self) -> None:
        schema_a = load_schema("tool_canonical_ir_v1")
        schema_b = load_schema("tool_canonical_ir_v1")
        assert schema_a is schema_b  # lru_cache should return same instance

    def test_different_schemas_return_different_objects(self) -> None:
        schema_a = load_schema("tool_canonical_ir_v1")
        schema_b = load_schema("agent_error_taxonomy_v1")
        assert schema_a is not schema_b

    def test_json_schema_contains_schema_meta_key(self) -> None:
        schema = load_schema("tool_canonical_ir_v1")
        assert "$schema" in schema

    def test_json_schema_contains_id_key(self) -> None:
        schema = load_schema("tool_canonical_ir_v1")
        assert "$id" in schema

    def test_yaml_schema_loads_as_dict(self) -> None:
        schema = load_schema("agent_capability_v1")
        assert isinstance(schema, dict)
        assert "properties" in schema

    def test_schema_parse_error_raised_on_corrupt_file(self, tmp_path: Path) -> None:
        """SchemaParseError is raised when a schema file contains invalid JSON."""
        from aumai_specs.schemas import SCHEMAS_DIR

        corrupt_content = "{this is not valid json ]]}"
        # Temporarily patch _resolve_schema_path to return our corrupt file
        corrupt_file = tmp_path / "corrupt_v1.json"
        corrupt_file.write_text(corrupt_content, encoding="utf-8")

        with patch("aumai_specs.loader._resolve_schema_path", return_value=corrupt_file):
            # Clear the lru_cache to force re-loading
            load_schema.cache_clear()
            with pytest.raises(SchemaParseError) as exc_info:
                load_schema("corrupt_v1")
            assert exc_info.value.path == corrupt_file
        load_schema.cache_clear()


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


class TestValidate:
    def test_valid_tool_ir_passes(self, valid_tool_ir_dict: dict[str, Any]) -> None:
        result = validate(valid_tool_ir_dict, "tool_canonical_ir_v1")
        assert result is True

    def test_valid_error_taxonomy_passes(
        self, valid_error_taxonomy_dict: dict[str, Any]
    ) -> None:
        result = validate(valid_error_taxonomy_dict, "agent_error_taxonomy_v1")
        assert result is True

    def test_valid_capsule_passes(self, valid_capsule_dict: dict[str, Any]) -> None:
        result = validate(valid_capsule_dict, "capsule_format_v1")
        assert result is True

    def test_valid_capability_passes(
        self, valid_capability_dict: dict[str, Any]
    ) -> None:
        result = validate(valid_capability_dict, "agent_capability_v1")
        assert result is True

    def test_missing_required_field_raises_validation_error(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        del valid_tool_ir_dict["name"]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate(valid_tool_ir_dict, "tool_canonical_ir_v1")
        assert "name" in str(exc_info.value).lower() or "required" in str(exc_info.value).lower()

    def test_wrong_type_raises_validation_error(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        valid_tool_ir_dict["name"] = 12345  # must be string
        with pytest.raises(SchemaValidationError):
            validate(valid_tool_ir_dict, "tool_canonical_ir_v1")

    def test_invalid_semver_raises_validation_error(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        valid_tool_ir_dict["version"] = "not-a-version"
        with pytest.raises(SchemaValidationError):
            validate(valid_tool_ir_dict, "tool_canonical_ir_v1")

    def test_invalid_enum_value_raises_validation_error(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        valid_tool_ir_dict["security"]["data_classification"] = "ultra_secret"
        with pytest.raises(SchemaValidationError):
            validate(valid_tool_ir_dict, "tool_canonical_ir_v1")

    def test_empty_capabilities_raises_validation_error(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        valid_tool_ir_dict["capabilities"] = []
        with pytest.raises(SchemaValidationError):
            validate(valid_tool_ir_dict, "tool_canonical_ir_v1")

    def test_schema_validation_error_exposes_validation_error_attribute(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        del valid_tool_ir_dict["version"]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate(valid_tool_ir_dict, "tool_canonical_ir_v1")
        import jsonschema.exceptions

        assert isinstance(
            exc_info.value.validation_error,
            jsonschema.exceptions.ValidationError,
        )

    def test_nonexistent_schema_raises_not_found(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        with pytest.raises(SchemaNotFoundError):
            validate(valid_tool_ir_dict, "nonexistent_schema_v99")

    def test_invalid_tool_name_pattern_raises(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        valid_tool_ir_dict["name"] = "123_starts_with_digit"
        with pytest.raises(SchemaValidationError):
            validate(valid_tool_ir_dict, "tool_canonical_ir_v1")

    def test_capsule_missing_agent_raises(
        self, valid_capsule_dict: dict[str, Any]
    ) -> None:
        del valid_capsule_dict["agent"]
        with pytest.raises(SchemaValidationError):
            validate(valid_capsule_dict, "capsule_format_v1")

    def test_capsule_invalid_schema_version_raises(
        self, valid_capsule_dict: dict[str, Any]
    ) -> None:
        valid_capsule_dict["schema_version"] = "2.0.0"
        with pytest.raises(SchemaValidationError):
            validate(valid_capsule_dict, "capsule_format_v1")

    def test_capability_missing_sandbox_raises(
        self, valid_capability_dict: dict[str, Any]
    ) -> None:
        del valid_capability_dict["sandbox"]
        with pytest.raises(SchemaValidationError):
            validate(valid_capability_dict, "agent_capability_v1")

    def test_capability_invalid_egress_mode_raises(
        self, valid_capability_dict: dict[str, Any]
    ) -> None:
        valid_capability_dict["network"]["egress_mode"] = "unrestricted"
        with pytest.raises(SchemaValidationError):
            validate(valid_capability_dict, "agent_capability_v1")

    def test_taxonomy_error_code_below_minimum_raises(
        self, valid_error_taxonomy_dict: dict[str, Any]
    ) -> None:
        # Code below 100 violates the JSON Schema minimum constraint
        valid_error_taxonomy_dict["categories"][0]["errors"][0]["code"] = 99
        with pytest.raises(SchemaValidationError):
            validate(valid_error_taxonomy_dict, "agent_error_taxonomy_v1")

    def test_taxonomy_error_code_above_maximum_raises(
        self, valid_error_taxonomy_dict: dict[str, Any]
    ) -> None:
        # Code above 699 violates the JSON Schema maximum constraint
        valid_error_taxonomy_dict["categories"][0]["errors"][0]["code"] = 700
        with pytest.raises(SchemaValidationError):
            validate(valid_error_taxonomy_dict, "agent_error_taxonomy_v1")


# ---------------------------------------------------------------------------
# validate_quietly
# ---------------------------------------------------------------------------


class TestValidateQuietly:
    def test_returns_true_and_empty_message_on_success(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        is_valid, message = validate_quietly(valid_tool_ir_dict, "tool_canonical_ir_v1")
        assert is_valid is True
        assert message == ""

    def test_returns_false_and_message_on_failure(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        del valid_tool_ir_dict["name"]
        is_valid, message = validate_quietly(valid_tool_ir_dict, "tool_canonical_ir_v1")
        assert is_valid is False
        assert len(message) > 0

    def test_returns_false_on_schema_not_found(
        self, valid_tool_ir_dict: dict[str, Any]
    ) -> None:
        is_valid, message = validate_quietly(valid_tool_ir_dict, "nonexistent_v99")
        assert is_valid is False
        assert "nonexistent_v99" in message

    def test_never_raises(self, valid_tool_ir_dict: dict[str, Any]) -> None:
        """validate_quietly must never raise regardless of input."""
        del valid_tool_ir_dict["name"]
        del valid_tool_ir_dict["version"]
        # Should not raise
        validate_quietly(valid_tool_ir_dict, "tool_canonical_ir_v1")
        validate_quietly({}, "completely_missing_schema")
