"""Shared pytest fixtures for the aumai-specs test suite.

Fixtures are grouped by the schema/model they support. All fixtures
return minimal but valid instances so tests can selectively override
only the fields they care about.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Raw dictionary fixtures (for loader / JSON Schema tests)
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_tool_ir_dict() -> dict[str, Any]:
    """Minimal valid ToolCanonicalIR document conforming to the JSON schema."""
    return {
        "name": "web_search",
        "version": "1.0.0",
        "description": "Search the web and return ranked results.",
        "capabilities": [
            {
                "action": "search",
                "domain": "web",
                "side_effects": ["network_egress", "external_api_call"],
                "idempotent": True,
                "cost_estimate": "low",
            }
        ],
        "inputs": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"type": "string"},
                "max_results": {"type": "integer"},
            },
        },
        "outputs": {
            "type": "object",
            "properties": {
                "results": {"type": "array"},
                "total": {"type": "integer"},
            },
        },
        "security": {
            "required_permissions": ["tools:read"],
            "data_classification": "public",
            "pii_handling": "none",
        },
    }


@pytest.fixture
def valid_error_taxonomy_dict() -> dict[str, Any]:
    """Minimal valid AgentErrorTaxonomy document conforming to the JSON schema."""
    return {
        "taxonomy_version": "1.0.0",
        "categories": [
            {
                "category_name": "planning",
                "code_prefix": 1,
                "description": "Errors occurring during agent planning.",
                "errors": [
                    {
                        "code": 101,
                        "name": "GOAL_DECOMPOSITION_FAILED",
                        "description": "Failed to decompose goal into sub-tasks.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                        "example_message": "Could not decompose goal after 3 attempts",
                    },
                    {
                        "code": 102,
                        "name": "TASK_GRAPH_CYCLE_DETECTED",
                        "description": "Circular dependency detected in task graph.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "human_escalation",
                    },
                    {
                        "code": 103,
                        "name": "PLAN_VALIDATION_FAILED",
                        "description": "Generated plan failed structural validation.",
                        "severity": "warning",
                        "recoverable": True,
                        "retry_strategy": "immediate",
                    },
                    {
                        "code": 104,
                        "name": "AMBIGUOUS_GOAL_RECEIVED",
                        "description": "Goal is too ambiguous to plan against.",
                        "severity": "warning",
                        "recoverable": True,
                        "retry_strategy": "human_escalation",
                    },
                    {
                        "code": 105,
                        "name": "MAX_PLANNING_RETRIES_EXCEEDED",
                        "description": "Exceeded maximum allowed planning retries.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "human_escalation",
                    },
                ],
            },
            {
                "category_name": "tool_execution",
                "code_prefix": 2,
                "description": "Errors occurring during tool invocation.",
                "errors": [
                    {
                        "code": 201,
                        "name": "TOOL_NOT_FOUND",
                        "description": "Requested tool is not registered.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "none",
                    },
                    {
                        "code": 202,
                        "name": "TOOL_TIMEOUT",
                        "description": "Tool invocation exceeded timeout.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                    },
                    {
                        "code": 203,
                        "name": "TOOL_INPUT_SCHEMA_INVALID",
                        "description": "Tool inputs failed schema validation.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "immediate",
                    },
                    {
                        "code": 204,
                        "name": "TOOL_OUTPUT_SCHEMA_INVALID",
                        "description": "Tool output failed schema validation.",
                        "severity": "warning",
                        "recoverable": True,
                        "retry_strategy": "immediate",
                    },
                    {
                        "code": 205,
                        "name": "TOOL_RATE_LIMIT_EXCEEDED",
                        "description": "Tool rate limit was hit.",
                        "severity": "warning",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                    },
                ],
            },
            {
                "category_name": "context",
                "code_prefix": 3,
                "description": "Errors related to context window and memory.",
                "errors": [
                    {
                        "code": 301,
                        "name": "CONTEXT_WINDOW_EXCEEDED",
                        "description": "Input exceeds the model context window.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "immediate",
                    },
                    {
                        "code": 302,
                        "name": "MEMORY_READ_FAILED",
                        "description": "Could not read from agent memory store.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                    },
                    {
                        "code": 303,
                        "name": "MEMORY_WRITE_FAILED",
                        "description": "Could not write to agent memory store.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                    },
                    {
                        "code": 304,
                        "name": "CONTEXT_TRUNCATION_OCCURRED",
                        "description": "Context was truncated due to length.",
                        "severity": "warning",
                        "recoverable": True,
                        "retry_strategy": "none",
                    },
                    {
                        "code": 305,
                        "name": "EMBEDDING_GENERATION_FAILED",
                        "description": "Failed to generate embedding for context retrieval.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                    },
                ],
            },
            {
                "category_name": "security",
                "code_prefix": 4,
                "description": "Security and authorization errors.",
                "errors": [
                    {
                        "code": 401,
                        "name": "PERMISSION_DENIED",
                        "description": "Agent lacks required permission for action.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "human_escalation",
                    },
                    {
                        "code": 402,
                        "name": "PII_POLICY_VIOLATION",
                        "description": "Action would violate PII handling policy.",
                        "severity": "critical",
                        "recoverable": False,
                        "retry_strategy": "human_escalation",
                    },
                    {
                        "code": 403,
                        "name": "DATA_CLASSIFICATION_BREACH",
                        "description": "Action would expose data above authorized classification.",
                        "severity": "critical",
                        "recoverable": False,
                        "retry_strategy": "human_escalation",
                    },
                    {
                        "code": 404,
                        "name": "AUTHENTICATION_FAILED",
                        "description": "Authentication with external service failed.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "human_escalation",
                    },
                    {
                        "code": 405,
                        "name": "AUDIT_LOG_WRITE_FAILED",
                        "description": "Could not write required audit log entry.",
                        "severity": "critical",
                        "recoverable": False,
                        "retry_strategy": "human_escalation",
                    },
                ],
            },
            {
                "category_name": "resource",
                "code_prefix": 5,
                "description": "Resource exhaustion and quota errors.",
                "errors": [
                    {
                        "code": 501,
                        "name": "TOKEN_BUDGET_EXCEEDED",
                        "description": "Run exceeded the configured token budget.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "none",
                    },
                    {
                        "code": 502,
                        "name": "COST_CAP_EXCEEDED",
                        "description": "Run exceeded the configured USD cost cap.",
                        "severity": "critical",
                        "recoverable": False,
                        "retry_strategy": "none",
                    },
                    {
                        "code": 503,
                        "name": "MEMORY_LIMIT_EXCEEDED",
                        "description": "Agent process exceeded memory limit.",
                        "severity": "critical",
                        "recoverable": False,
                        "retry_strategy": "none",
                    },
                    {
                        "code": 504,
                        "name": "RUN_DURATION_TIMEOUT",
                        "description": "Run exceeded the maximum wall-clock duration.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "none",
                    },
                    {
                        "code": 505,
                        "name": "SANDBOX_STARTUP_TIMEOUT",
                        "description": "Sandbox environment did not start within allotted time.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                    },
                ],
            },
            {
                "category_name": "orchestration",
                "code_prefix": 6,
                "description": "Multi-agent coordination and orchestration errors.",
                "errors": [
                    {
                        "code": 601,
                        "name": "SUB_AGENT_SPAWN_FAILED",
                        "description": "Failed to spawn a required sub-agent.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "exponential_backoff",
                    },
                    {
                        "code": 602,
                        "name": "SUB_AGENT_RESULT_INVALID",
                        "description": "Sub-agent returned an invalid or malformed result.",
                        "severity": "error",
                        "recoverable": True,
                        "retry_strategy": "immediate",
                    },
                    {
                        "code": 603,
                        "name": "ORCHESTRATION_DEADLOCK",
                        "description": "Circular wait detected between agents.",
                        "severity": "critical",
                        "recoverable": False,
                        "retry_strategy": "human_escalation",
                    },
                    {
                        "code": 604,
                        "name": "HANDOFF_PROTOCOL_MISMATCH",
                        "description": "Agent handoff protocol version mismatch.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "none",
                    },
                    {
                        "code": 605,
                        "name": "MAX_AGENT_DEPTH_EXCEEDED",
                        "description": "Recursive sub-agent nesting exceeded maximum depth.",
                        "severity": "error",
                        "recoverable": False,
                        "retry_strategy": "none",
                    },
                ],
            },
        ],
    }


@pytest.fixture
def valid_capsule_dict() -> dict[str, Any]:
    """Minimal valid RunCapsule document conforming to the JSON schema."""
    now = "2026-02-26T12:00:00Z"
    return {
        "capsule_id": "capsule_01HZABCDEFGHIJKLMNOPQRSTUV",
        "schema_version": "1.0.0",
        "created_at": now,
        "agent": {
            "agent_id": "research-agent-v1",
            "agent_name": "Research Agent",
            "agent_version": "1.0.0",
            "model": {
                "provider": "anthropic",
                "model_id": "claude-opus-4-6",
                "parameters": {"temperature": 0.7, "max_tokens": 4096},
            },
            "system_prompt_hash": "sha256:" + "a" * 64,
            "tools_loaded": [
                {
                    "tool_name": "web_search",
                    "tool_version": "1.0.0",
                }
            ],
        },
        "run": {
            "run_id": "run_abc123",
            "started_at": now,
            "ended_at": now,
            "status": "success",
            "triggered_by": "human",
            "goal": "Research the latest advances in quantum computing.",
        },
        "execution_trace": [
            {
                "step_index": 0,
                "step_type": "llm_inference",
                "started_at": now,
                "ended_at": now,
                "duration_ms": 1200,
                "tokens": {
                    "input_tokens": 512,
                    "output_tokens": 256,
                    "total_tokens": 768,
                },
                "cost": {
                    "input_cost_usd": 0.0015,
                    "output_cost_usd": 0.0025,
                    "total_cost_usd": 0.004,
                },
            }
        ],
        "environment": {
            "aumai_runtime_version": "0.1.0",
            "python_version": "3.12.0",
            "os": "linux/amd64",
            "sandbox_tier": "e2b_micro",
            "network_policy": "allowlist_only",
        },
        "outcome": {
            "final_answer": "Quantum computing advances include...",
            "total_cost_usd": 0.004,
            "total_steps": 1,
            "total_tool_calls": 0,
            "goal_achieved": True,
            "confidence_score": 0.85,
        },
    }


@pytest.fixture
def valid_capability_dict() -> dict[str, Any]:
    """Minimal valid AgentCapability document conforming to the YAML schema."""
    return {
        "capability_version": "1.0.0",
        "agent_id": "research-agent-v1",
        "agent_name": "Research Agent",
        "agent_version": "1.0.0",
        "sandbox": {
            "tier": "e2b_micro",
            "startup_timeout_seconds": 30,
        },
        "network": {
            "egress_mode": "allowlist_only",
            "egress_rules": [
                {
                    "host": "api.anthropic.com",
                    "ports": [443],
                    "protocol": "https",
                    "description": "Anthropic API",
                }
            ],
        },
        "filesystem": {
            "mode": "read_write_ephemeral",
            "allowed_paths": ["/workspace/", "/tmp/"],
        },
        "resources": {
            "max_cpu_cores": 1.0,
            "max_memory_mb": 512,
            "max_run_duration_seconds": 300,
        },
        "permissions": {
            "scopes": ["tools:read", "memory:read"],
        },
    }


# ---------------------------------------------------------------------------
# Datetime helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def utc_now() -> datetime:
    """Return the current UTC datetime with timezone info."""
    return datetime.now(tz=timezone.utc)
