# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | ✅        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly:

1. **Do not** open a public GitHub issue.
2. Email: <security contact email>
3. Include: description, reproduction steps, and impact assessment.
4. Expected response time: 72 hours.

## Security Measures

- CI pipeline runs on every push: tests, linting, dependency auditing (pip-audit), SAST (bandit)
- Pre-commit hooks prevent accidental secret commits (detect-secrets)
- Dependabot monitors dependencies for known CVEs
- All API credentials are loaded from environment variables, never hardcoded
- OpenSearch queries use authenticated HTTPS connections
