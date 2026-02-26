# AGENTS.md — AI Agent Guidelines for aumai-specs

This file provides instructions for AI coding agents (Claude Code, Cursor,
Copilot, etc.) working in this repository.

---

## Repository Role

`aumai-specs` is the **single source of truth** for four canonical schemas
used by all AumAI projects. Changes here have wide blast radius. Treat
every modification as a potential breaking change for 86+ downstream repos.

---

## What Agents Should Do

### When asked to add a new field to a schema

1. Check `GOVERNANCE.md` first. Any new required field is a Major change
   and requires an RFC.
2. New optional fields are Minor changes — still require a lightweight RFC.
3. Never modify an existing schema file's `$id` — that is a breaking change.
4. After changing a schema, update the corresponding Pydantic models in
   `models.py` and add tests.

### When asked to fix a bug in `loader.py` or `models.py`

1. Read the test file for the module first.
2. Write a failing test that reproduces the bug before fixing it.
3. Verify the fix passes `make check` (lint + typecheck + tests).
4. Do not change public function signatures without updating all callers and
   the API reference docs.

### When asked to add tests

1. Follow the existing test structure: class per model/function, methods
   grouped by test scenario.
2. Use the fixtures in `tests/conftest.py` rather than constructing raw
   dicts inline.
3. Use `pytest.raises` with explicit exception types, not bare `Exception`.
4. Every Pydantic model must have: a valid minimal construction test, at
   least 3 invalid construction tests, and a model_dump roundtrip test.

---

## What Agents Must Not Do

- Never delete or rename a schema file. Schemas are versioned contracts.
- Never change the `const` value of `schema_version` in capsule_format_v1.
- Never add enum values to existing enums in the JSON schemas — this is a
  breaking change that must go through the RFC process.
- Never commit secrets, API keys, or connection strings.
- Never change `pyproject.toml` version without a corresponding git tag.
- Never use `# type: ignore` without a comment explaining why.
- Never skip `pre-commit` hooks.

---

## Key Invariants to Preserve

1. **`load_schema()` is cached.** Do not add side effects to `load_schema()`
   that would make caching incorrect (e.g. mutating the returned dict).

2. **`validate()` is pure.** It must never modify `data` or the schema.

3. **All four schemas must pass their own meta-validation** (a schema must
   be a valid JSON Schema document itself). The `test_schemas.py` tests
   verify this.

4. **Error code 1xx–6xx alignment** is a core invariant. The `AgentError`
   model enforces that `category` matches `code // 100`. Never weaken this.

5. **Capsule IDs are immutable once sealed.** The format `capsule_<26 chars>`
   must not change in v1.

---

## Running Checks

```bash
make check        # lint + typecheck + tests (required before any PR)
make test-cov     # tests with coverage report (must stay ≥ 90%)
make quickstart   # verify the example still works
```

---

## File Map

| File | Purpose |
|------|---------|
| `src/aumai_specs/loader.py` | Schema loading, caching, validation |
| `src/aumai_specs/models.py` | Pydantic v2 models |
| `src/aumai_specs/schemas/` | The four canonical schema files |
| `tests/test_loader.py` | Tests for loader.py |
| `tests/test_models.py` | Tests for models.py |
| `tests/test_schemas.py` | Tests for schema files themselves |
| `tests/conftest.py` | Shared fixtures |
| `GOVERNANCE.md` | RFC process for schema evolution |
