# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via GitHub's private Security Advisory feature:

1. Go to https://github.com/muveraai/aumai-specs/security/advisories
2. Click "New draft security advisory"
3. Fill in the details: affected version, description, reproduction steps, and
   impact assessment.

You will receive an acknowledgment within 48 hours.

## Response Timeline

| Step | Target SLA |
|------|-----------|
| Acknowledgment | 48 hours |
| Triage and severity assignment | 5 business days |
| Fix developed and tested | 10 business days (critical: 3) |
| Patch released | 14 business days (critical: 5) |
| Public disclosure | 90 days after report (earlier if fix is released) |

## Scope

Security issues in this repository include, but are not limited to:

- JSON Schema constraints that allow SSRF vectors (e.g. URL fields without
  adequate host restrictions in capability schemas)
- Schema constraints that permit PII leakage through data classification
  misconfiguration
- `loader.py` path-traversal vulnerabilities when resolving schema files
- Pydantic model validators that can be bypassed to accept data that should
  be rejected for security reasons
- Any schema that allows an agent to declare permissions or egress rules
  that circumvent governance controls

## Out of Scope

- Vulnerabilities in dependencies (`jsonschema`, `pydantic`, `pyyaml`) — report
  those to the respective upstream projects.
- Issues that require physical access to the server.

## Acknowledgments

We will acknowledge all valid security reports in the release notes of the
patched version, unless the reporter requests anonymity.
