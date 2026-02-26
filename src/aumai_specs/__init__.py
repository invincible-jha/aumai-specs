"""aumai_specs — Canonical schema definitions and Pydantic models for all AumAI projects.

This package is the single source of truth for:

- **Tool Canonical IR** (``tool_canonical_ir_v1``): Universal intermediate
  representation for agent tool definitions across all provider formats
  (OpenAI, Anthropic, MCP, LangChain).

- **Agent Error Taxonomy** (``agent_error_taxonomy_v1``): Structured error
  codes (1xx-6xx) enabling consistent error handling and observability.

- **Run Capsule Format** (``capsule_format_v1``): Immutable execution records
  for deterministic replay, auditing, and cost attribution.

- **Agent Capability Declaration** (``agent_capability_v1``): Sandbox,
  network, filesystem, and resource governance manifests for every deployed
  agent.

Quick start::

    from aumai_specs.loader import load_schema, validate
    from aumai_specs.models import ToolCanonicalIR, ToolCapability

    # Load a raw schema dict
    schema = load_schema("tool_canonical_ir_v1")

    # Create a typed model
    tool = ToolCanonicalIR(
        name="web_search",
        version="1.0.0",
        capabilities=[ToolCapability(action="search", domain="web")],
        inputs={"type": "object"},
        outputs={"type": "object"},
    )

    # Validate arbitrary data against a schema
    validate(tool.model_dump(), "tool_canonical_ir_v1")
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__: str = _pkg_version("aumai-specs")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

__all__ = ["__version__"]
