"""Schema loader and validator for the AumAI canonical specs.

This module is the primary entry point for working with AumAI schemas.
It handles loading JSON and YAML schemas from the package's bundled
schema files, caching them for performance, and validating arbitrary
data against those schemas using jsonschema.

Usage::

    from aumai_specs.loader import load_schema, validate

    schema = load_schema("tool_canonical_ir_v1")
    is_valid = validate(my_tool_dict, "tool_canonical_ir_v1")

Schema names are the file basenames without extension:
    - tool_canonical_ir_v1
    - agent_error_taxonomy_v1
    - capsule_format_v1
    - agent_capability_v1
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema
import jsonschema.exceptions
import yaml

from aumai_specs.schemas import SCHEMAS_DIR

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

SchemaDict = dict[str, Any]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_JSON_SUFFIX = ".json"
_YAML_SUFFIX = ".yaml"
_SUPPORTED_SCHEMAS = frozenset(
    {
        "tool_canonical_ir_v1",
        "agent_error_taxonomy_v1",
        "capsule_format_v1",
        "agent_capability_v1",
    }
)


class SchemaNotFoundError(FileNotFoundError):
    """Raised when a requested schema name has no corresponding file."""

    def __init__(self, schema_name: str) -> None:
        super().__init__(
            f"Schema '{schema_name}' not found. "
            f"Available schemas: {sorted(_SUPPORTED_SCHEMAS)}"
        )
        self.schema_name = schema_name


class SchemaValidationError(ValueError):
    """Raised when data fails validation against a schema.

    Wraps :class:`jsonschema.exceptions.ValidationError` and exposes the
    full validation error tree via the :attr:`validation_error` attribute.
    """

    def __init__(
        self,
        message: str,
        validation_error: jsonschema.exceptions.ValidationError,
    ) -> None:
        super().__init__(message)
        self.validation_error = validation_error


class SchemaParseError(ValueError):
    """Raised when a schema file cannot be parsed as JSON or YAML."""

    def __init__(self, path: Path, cause: Exception) -> None:
        super().__init__(
            f"Failed to parse schema file '{path}': {cause}"
        )
        self.path = path
        self.cause = cause


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------


def _resolve_schema_path(schema_name: str) -> Path:
    """Return the filesystem path for a named schema.

    Searches for ``<schema_name>.json`` first, then ``<schema_name>.yaml``.

    Args:
        schema_name: Basename without extension (e.g. ``"tool_canonical_ir_v1"``).

    Returns:
        :class:`pathlib.Path` pointing to the schema file.

    Raises:
        :class:`SchemaNotFoundError`: If neither JSON nor YAML file exists.
    """
    for suffix in (_JSON_SUFFIX, _YAML_SUFFIX):
        candidate = SCHEMAS_DIR / f"{schema_name}{suffix}"
        if candidate.is_file():
            return candidate
    raise SchemaNotFoundError(schema_name)


@lru_cache(maxsize=32)
def load_schema(schema_name: str) -> SchemaDict:
    """Load and parse a canonical AumAI schema by name.

    Results are cached in-process so subsequent calls for the same schema
    name are O(1) dictionary lookups. The cache is keyed by schema name,
    so different names always return different objects.

    Args:
        schema_name: Basename without extension.
            One of: ``tool_canonical_ir_v1``, ``agent_error_taxonomy_v1``,
            ``capsule_format_v1``, ``agent_capability_v1``.

    Returns:
        Parsed schema as a nested dictionary.

    Raises:
        :class:`SchemaNotFoundError`: If the schema file does not exist.
        :class:`SchemaParseError`: If the file cannot be parsed.

    Example::

        >>> schema = load_schema("tool_canonical_ir_v1")
        >>> schema["title"]
        'AumAI Tool Canonical IR'
    """
    path = _resolve_schema_path(schema_name)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchemaNotFoundError(schema_name) from exc

    try:
        if path.suffix == _JSON_SUFFIX:
            return json.loads(raw_text)  # type: ignore[return-value]
        return yaml.safe_load(raw_text)  # type: ignore[return-value]
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SchemaParseError(path, exc) from exc


def validate(data: dict[str, Any], schema_name: str) -> bool:
    """Validate *data* against the named canonical schema.

    Uses ``jsonschema`` with the JSON Schema Draft 2020-12 validator.
    Both JSON and YAML schemas are supported (YAML is loaded into a dict
    before validation).

    Args:
        data: The dictionary to validate.
        schema_name: Name of the schema to validate against.

    Returns:
        ``True`` if validation passes.

    Raises:
        :class:`SchemaNotFoundError`: If the schema cannot be found.
        :class:`SchemaValidationError`: If *data* fails validation.

    Example::

        >>> validate({"name": "my_tool", ...}, "tool_canonical_ir_v1")
        True
    """
    schema = load_schema(schema_name)
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)

    try:
        validator.validate(data)
    except jsonschema.exceptions.ValidationError as exc:
        raise SchemaValidationError(
            f"Data failed validation against '{schema_name}': {exc.message}",
            exc,
        ) from exc
    return True


def validate_quietly(data: dict[str, Any], schema_name: str) -> tuple[bool, str]:
    """Validate *data* against a schema without raising exceptions.

    A convenience wrapper around :func:`validate` that returns a ``(bool,
    message)`` tuple instead of raising. Useful for bulk validation where
    you want to collect all failures rather than short-circuit on the first.

    Args:
        data: The dictionary to validate.
        schema_name: Name of the schema to validate against.

    Returns:
        A ``(is_valid, message)`` tuple. ``message`` is an empty string on
        success, or the first validation error message on failure.
    """
    try:
        validate(data, schema_name)
        return True, ""
    except (SchemaValidationError, SchemaNotFoundError, SchemaParseError) as exc:
        return False, str(exc)


def list_schemas() -> list[str]:
    """Return the names of all bundled canonical schemas.

    Returns:
        Sorted list of schema base names (without file extension).

    Example::

        >>> list_schemas()
        ['agent_capability_v1', 'agent_error_taxonomy_v1', 'capsule_format_v1', 'tool_canonical_ir_v1']
    """
    names: list[str] = []
    for path in SCHEMAS_DIR.iterdir():
        if path.suffix in (_JSON_SUFFIX, _YAML_SUFFIX) and path.stem != "__init__":
            names.append(path.stem)
    return sorted(names)


def get_schema_path(schema_name: str) -> Path:
    """Return the absolute filesystem path to a schema file.

    Useful for tooling that needs to reference the raw file (e.g. editors,
    linters, or documentation generators).

    Args:
        schema_name: Schema base name without extension.

    Returns:
        :class:`pathlib.Path` to the schema file.

    Raises:
        :class:`SchemaNotFoundError`: If the schema file does not exist.
    """
    return _resolve_schema_path(schema_name)
