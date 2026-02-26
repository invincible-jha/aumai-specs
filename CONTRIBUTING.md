# Contributing to aumai-specs

Thank you for contributing to the foundational schema layer of the AumAI
platform. Because all 86+ projects depend on this repository, contributions
are held to a high standard.

---

## Setup

```bash
git clone https://github.com/muveraai/aumai-specs.git
cd aumai-specs
pip install -e ".[dev]"
pre-commit install
```

---

## Making a Change

### For code changes (loader, models, tests, examples)

1. Fork the repo and create a branch from `main`:
   ```bash
   git checkout -b feature/my-change
   ```

2. Make your changes.

3. Ensure the full quality gate passes:
   ```bash
   make check   # lint + typecheck + tests
   ```

4. Coverage must remain ≥ 90%:
   ```bash
   make test-cov
   ```

5. Commit using Conventional Commits:
   ```
   feat: add validate_batch() helper to loader
   fix: correct capsule_id pattern to require 26 alphanumeric chars
   refactor: extract _validate_semver into shared helper
   docs: add network egress example to getting-started
   test: add edge cases for AgentError code/category mismatch
   ```

6. Open a PR against `main`. The PR description must explain **why** the
   change is needed, not just what it does.

### For schema changes

Schema changes follow the RFC process documented in `GOVERNANCE.md`.
Do not open a PR for a schema change without a corresponding accepted RFC.

---

## Code Standards

- **Type hints on all function signatures** — no exceptions.
- **Pydantic v2 patterns only** — no v1 `@validator`, use `@field_validator`
  and `@model_validator`.
- **No `any` types** — use `dict[str, Any]` from `typing` where truly needed.
- **ruff passes without errors** before opening a PR.
- **mypy strict passes** before opening a PR.
- **Tests for every code path** — 90% coverage is the floor, not the target.

---

## Commit Message Format

```
<type>(<scope>): <short description>

[optional body — explain WHY, not WHAT]

[optional footer: Refs #123, Closes #456]
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`

Scopes: `loader`, `models`, `schemas`, `tests`, `ci`, `docs`

---

## PR Checklist

- [ ] `make check` passes (lint + typecheck + tests)
- [ ] Coverage ≥ 90%
- [ ] New/changed public APIs have docstrings
- [ ] `CHANGELOG.md` updated for user-visible changes
- [ ] Schema changes have a corresponding accepted RFC in the issue tracker

---

## Questions?

Open a GitHub Discussion or reach out in `#platform-specs` on Slack.
