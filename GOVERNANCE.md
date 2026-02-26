# AumAI Specs Governance

## Purpose

This document defines the RFC (Request for Comments) process that governs
how schemas in `aumai-specs` evolve. Because all 86+ AumAI projects depend
on these schemas, any change carries breaking-change risk. This process
exists to surface that risk early, gather feedback, and reach an explicit
decision before merging.

---

## Principles

1. **Stability over convenience.** Schemas are versioned contracts. A
   breaking change in `aumai-specs` requires a coordinated migration across
   every dependent project. Prefer additive changes.

2. **Explicit > implicit.** Every schema change must be justified in
   writing. "We needed it" is not sufficient; the RFC must describe the
   problem, alternatives considered, and why this solution is preferred.

3. **The four canonical schemas are the floor, not the ceiling.** Projects
   may extend schemas with custom fields in their own namespaces. If a
   custom extension proves broadly useful, it can be proposed as an RFC to
   be promoted to the canonical spec.

4. **Version everything.** No in-place mutations to a released schema.
   Breaking changes produce a new schema file (`v2`, `v3`, …).

---

## Change Classification

| Class | Definition | RFC Required | Approvals Needed |
|-------|-----------|--------------|-----------------|
| **Patch** | Clarify description text, fix typos, improve examples. No schema logic change. | No | 1 maintainer |
| **Minor** | Add a new optional field. All existing valid documents remain valid. | Yes (lightweight) | 2 maintainers |
| **Major** | Remove a field, rename a field, tighten a constraint, change a type, add a required field, or add an enum value that causes previously invalid documents to become valid. | Yes (full) | 3 maintainers + 5-day comment period |
| **New schema** | Add a fifth canonical schema. | Yes (full) | All maintainers + 7-day comment period |

---

## RFC Process

### Step 1 — Draft

Open a GitHub issue using the **Schema RFC** template (`.github/ISSUE_TEMPLATE/schema_rfc.md`).
The issue title must follow the format:

```
RFC-NNNN: [schema_name] <short description of change>
```

The RFC body must answer:

- **Problem statement**: What cannot be expressed or done today?
- **Proposed change**: What exactly changes (with a diff of the schema file)?
- **Backwards compatibility**: Is this a breaking change? If so, which class (Minor/Major)?
- **Migration path**: For breaking changes, how do dependent projects migrate?
- **Alternatives considered**: What other approaches were explored?
- **Test plan**: What new tests will be added?

### Step 2 — Discussion Period

| Class | Minimum discussion period |
|-------|--------------------------|
| Minor | 3 business days |
| Major | 5 business days |
| New schema | 7 business days |

All AumAI project maintainers are notified automatically via GitHub Teams
(`@muveraai/platform-team`). Comments and objections must be addressed in
the RFC issue before the RFC can advance.

### Step 3 — Voting

Voting is done via GitHub issue reactions on the RFC issue:

- **+1 (thumbs up)**: Approve
- **-1 (thumbs down)**: Reject (must be accompanied by a written objection)
- **0 (eyes)**: Abstain / need more information

A vote passes when:
- Minor RFC: 2 maintainer approvals, 0 unresolved objections
- Major RFC / New schema: 3 maintainer approvals (or all maintainers if
  fewer than 3), 0 unresolved objections

### Step 4 — Implementation

Once a vote passes:

1. The RFC author (or an assigned maintainer) opens a PR that:
   - Implements the schema change
   - Updates the Pydantic models in `models.py`
   - Updates or adds tests to maintain ≥90% coverage
   - Updates `CHANGELOG.md` with a clear description of the change
   - For Major changes: creates the new schema version file (e.g.
     `tool_canonical_ir_v2.json`) rather than modifying the existing v1

2. The PR must reference the RFC issue number in its description.

3. The PR requires the same number of approvals as defined in the vote step.

### Step 5 — Merge and Announce

After the PR merges:

1. Close the RFC issue with a link to the merged PR.
2. Create a new GitHub Release following [semver](https://semver.org/):
   - Patch change → bump patch version
   - Minor change → bump minor version
   - Major change → bump major version (and create `v2` schema file)
3. Notify the `#platform-specs` Slack channel with a summary of the change
   and the migration guide (for Major changes).

---

## Emergency Changes

Security vulnerabilities in a schema (e.g. a constraint that enables SSRF
or PII leakage) bypass the normal RFC discussion period. The process is:

1. File a GitHub Security Advisory (private)
2. Two maintainers approve the fix in private
3. A patch is merged and released within 24 hours
4. A public post-mortem RFC is filed within 5 business days

---

## Maintainers

Current schema maintainers are listed in `CODEOWNERS`. To become a
maintainer, contribute 3+ accepted RFCs and be approved by 2 existing
maintainers.

---

## Schema Versioning Policy

| Scenario | Action |
|----------|--------|
| New optional field | Bump minor version in `taxonomy_version` / `capability_version` field within the existing schema file |
| Any breaking change | Create a new schema file (`*_v2.json`) and deprecate the v1 file with a `x-deprecated` annotation |
| v1 sunset | v1 is removed no sooner than 12 months after v2 ships, with 3 months notice |

---

## FAQ

**Q: Can I add a field to my project's schema that mirrors an aumai-specs field with a different type?**

No. If your field name collides with a canonical field name, you must use a
namespaced key (e.g. `x_myproject_field`). Field name collisions between
canonical schemas and project schemas are a source of subtle bugs.

**Q: What if my RFC is rejected?**

Re-examine the objections. You may re-submit the RFC in modified form at any
time. There is no cooling-off period.

**Q: Who breaks the tie if the vote is split?**

The most senior maintainer (by tenure) casts the deciding vote. If they
abstained, the RFC is deferred for 5 additional business days to allow
further discussion.
