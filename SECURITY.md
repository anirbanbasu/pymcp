# Security Policy

The PyMCP project and its maintainers take security vulnerabilities seriously.

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

**Note:** Intentional design decisions, feature requests, or suggestions for security improvements that do not involve an actual exploitable flaw are not considered vulnerabilities. If you have suggestions for security enhancements, please open a feature request instead.

### What constitutes a Security Vulnerability

A security vulnerability is a weakness in the software that compromises data confidentiality, integrity, or availability. This may happen by enabling:

- **Remote code execution**: Allowing an attacker to run arbitrary code on the system.
- **Elevated permissions or privilege escalation**: Gaining unauthorized access to higher privilege levels.
- **Unintended access to data or systems**: Accessing data or functionality that should be restricted.
- **Denial of service attacks**: Making the system unavailable to legitimate users.
- **Bypass of security controls**: Circumventing authentication, authorization, or other security mechanisms.

What separates a security vulnerability from other unwanted behavior (a non-security bug) is a compromise in one or more of the areas above: confidentiality, integrity, or availability.

### How to Report a Security Vulnerability

If you think you have identified a security issue with the PyMCP project, _do not open a public issue_. To responsibly report a security issue, please navigate to the "Security" tab for the repository, and click "Report a vulnerability".

Be sure to include as much detail as necessary in your report. As with reporting normal issues, a minimal reproducible example will help the maintainers address the issue faster.

## Out of Scope

The following are generally **not** considered security vulnerabilities:

- Issues in dependencies (please report these to the respective upstream projects).
- Vulnerabilities in outdated or unsupported versions.
- Social engineering attacks.
- Denial of service via resource exhaustion without amplification.
- Issues requiring physical access to a user's device.

## Security Best Practices for Users

While using PyMCP, we recommend:

- Always use the latest stable version.
- Keep all dependencies up to date.
- Follow the principle of least privilege when running MCP servers.
- Review and understand the tools and resources exposed by the server.
- Monitor security advisories in our GitHub Security tab.

## Questions?

If you have questions about our security policy or the vulnerability disclosure process, please open a discussion on this repository.
