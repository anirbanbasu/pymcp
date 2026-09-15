# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [unreleased]

## [0.3.0] - 2026-09-15

### Added

- `AGENTS.md`, with `CLAUDE.md` symlinked to it, providing guidance to coding agents working in this repository.
- `CHANGELOG.md`.
- `.python-version`, pinning the local development interpreter.
- `.github/workflows/osv-scan.yml`, running `osv-scanner` on push, pull request, and a weekly schedule, mirroring the existing `just vulnerability-scan` recipe.
- `.github/workflows/dco.yml`, enforcing Developer Certificate of Origin sign-off on pull requests via `KineticCafe/actions-dco`, closing the gap `CONTRIBUTING.md` already documented as outstanding.
- `httpx2` and `truststore` as direct dependencies, replacing the now-dropped transitive `httpx`/`certifi` dependencies that came from the previously git-pinned, pre-release FastMCP.

### Changed

- Build backend switched from `hatchling` to `uv_build`.
- `fastmcp` dependency widened from a git-pinned pre-release commit to the released `4.0` line (`>=4.0.3,<4.1`) from PyPI.

### Deprecated

- None documented yet.

### Removed

- None documented yet.

### Fixed

- None documented yet.

### Security

- None documented yet.

## [0.2.4] - 2026-05-14

### Added

- `SECURITY.md`, documenting what constitutes a security vulnerability and a link to the vulnerability reporting page ([#79](https://github.com/anirbanbasu/pymcp/pull/79), [#80](https://github.com/anirbanbasu/pymcp/pull/80)).
- GitHub Issue templates ([#77](https://github.com/anirbanbasu/pymcp/pull/77)).
- A CodeQL Advanced workflow, with its status badge added to `README.md`.

### Changed

- `LICENSE` updated to point to contributors; `CONTRIBUTING.md` added.
- GitHub Actions workflows hardened per StepSecurity recommendations ([#81](https://github.com/anirbanbasu/pymcp/pull/81)).
- Dependencies upgraded, including Dependabot bumps of `coverage` ([#82](https://github.com/anirbanbasu/pymcp/pull/82)), `ty` ([#87](https://github.com/anirbanbasu/pymcp/pull/87)), `environs` ([#88](https://github.com/anirbanbasu/pymcp/pull/88)), `pydantic-monty` ([#89](https://github.com/anirbanbasu/pymcp/pull/89)), and `cryptography` ([#83](https://github.com/anirbanbasu/pymcp/pull/83)).

### Fixed

- Vulnerabilities addressed through dependency upgrades.

## [0.2.3] - 2026-02-08

### Added

- `StripUnknownArgumentsMiddleware`, dropping tool arguments an LLM caller passed that the tool doesn't declare instead of letting FastMCP/pydantic reject the call outright ([#48](https://github.com/anirbanbasu/pymcp/pull/48)).
- `ResponseMetadataMiddleware` and other middleware, attaching package name/version and per-call timing to tool responses ([#51](https://github.com/anirbanbasu/pymcp/pull/51)).
- New tooling with 100% test coverage ([#50](https://github.com/anirbanbasu/pymcp/pull/50)).
- A GitHub Actions Scorecard workflow ([#69](https://github.com/anirbanbasu/pymcp/pull/69)).
- `run_python_code`, running arbitrary Python code in Pydantic Monty's interpreter ([#76](https://github.com/anirbanbasu/pymcp/pull/76)).

### Changed

- General cleanup of middleware and tooling code ([#58](https://github.com/anirbanbasu/pymcp/pull/58)).
- `codeql-action` upgraded to v4 ([#71](https://github.com/anirbanbasu/pymcp/pull/71)).
- Dependencies upgraded.

### Removed

- The Smithery Dockerfile, its YAML configuration, and its references from `README.md` — Smithery deployment is no longer supported by this template ([#74](https://github.com/anirbanbasu/pymcp/pull/74)).

### Fixed

- The regular expression used for the SVG header ([#75](https://github.com/anirbanbasu/pymcp/pull/75)).

### Security

- Pinned-Dependencies security issues addressed by pinning dependencies in GitHub Actions workflows.

## [0.2.0] - 2025-11-08

### Changed

- **Breaking:** every tool call now returns a FastMCP `ToolResult` instead of ad hoc return values ([#35](https://github.com/anirbanbasu/pymcp/pull/35)).
- Dependencies upgraded.

### Fixed

- Corrected FastMCP dependency specification.

## [0.1.8] - 2025-11-06

### Changed

- Dependencies and pre-commit hooks upgraded, including Dependabot bumps of `fastmcp` ([#24](https://github.com/anirbanbasu/pymcp/pull/24)), `coverage` ([#26](https://github.com/anirbanbasu/pymcp/pull/26)), and `ddgs` ([#25](https://github.com/anirbanbasu/pymcp/pull/25)).
- Test coverage improved to 100%.

## [0.1.7] - 2025-09-11

### Added

- Reading configuration from `.env` files, and validation of `MCP_SERVER_TRANSPORT` against the set of transports FastMCP actually supports.

### Changed

- `mypy` issues in `Base64EncodedBinaryDataResponse` addressed.

### Fixed

- FastMCP Cloud deployment corrected.
- A `pytest` fixture-not-found issue.

## [0.1.6] - 2025-09-01

### Added

- Documentation on deploying to FastMCP Cloud.
- `MCPMixin`, registering MCP tools/resources/prompts from declarative metadata instead of one `@mcp.tool`-style decorator per method, plus hash-value validation for the `Base64EncodedBinaryDataResponse` Pydantic model and `mypy` added to pre-commit (2025.8.31 code refactoring, [#20](https://github.com/anirbanbasu/pymcp/pull/20)).

### Changed

- `ddgs` default region changed to `uk-en`.
- Dependencies upgraded.

### Fixed

- Elicitation handling corrected.
- The Smithery Dockerfile switched to a non-root user and otherwise corrected, following the discussion in [frankfurtermcp#26](https://github.com/anirbanbasu/frankfurtermcp/issues/26) and [frankfurtermcp#35](https://github.com/anirbanbasu/frankfurtermcp/issues/35).

## [0.1.5] - 2025-08-17

### Added

- An explicit `MCP_SERVER_TRANSPORT`-driven transport type specification for the server entry point.

### Changed

- Smithery deployment updated to choose a transport explicitly.
- Dependencies upgraded, including one addressing a [Dependabot security alert](https://github.com/anirbanbasu/pymcp/security/dependabot/1).

### Fixed

- The Smithery Dockerfile's `git` installation step corrected.

### Security

- A Dependabot-flagged dependency vulnerability addressed via upgrade.

## [0.1.4] - 2025-07-20

### Added

- `text_web_search`, searching the web via [DDGS](https://github.com/deedy5/ddgs), with `README.md` documentation.

### Changed

- The `pytest` GitHub Actions workflow now triggers on any pull request.
- Dependencies upgraded, including a Dependabot bump of `pydantic-core` ([#1](https://github.com/anirbanbasu/pymcp/pull/1)).

### Fixed

- The MIME type for the `data://logo` resource corrected to `application/json`.

## [0.1.3] - 2025-07-07

### Changed

- Output schemas updated.
- The `README.md` note about a minimum FastMCP `2.10.0` requirement removed.
- Dependencies upgraded.

## [0.1.2b2] - 2025-07-01

### Added

- A helper script for upgrading `uv` dependencies.

### Fixed

- Smithery deployment: `pip` `requirements.txt` now includes the Git source needed for FastMCP; the Smithery Dockerfile no longer fails to copy `requirements.txt` and now installs the `git` package it needs.

## [0.1.2-beta.1] - 2025-07-01

### Added

- A new resource and a new prompt, with more tests and coverage reporting.
- `pirate_summary`, an experimental client LLM sampling tool, tested through `pytest` and the MCP Inspector.
- `vonmises_random`, an experimental client elicitation tool.
- `pytest` added to pre-commit, so manual dependency upgrades no longer silently break the tests.

### Changed

- FastMCP dependency upgraded to a git source.
- Package version bumped and dependencies upgraded.

### Fixed

- Tool tags corrected for `vonmises_random`.

## [0.1.1] - 2025-06-29

### Added

- A basic MCP server with `stdio` transport, and example tools.
- A logo, and a resource returning its Base64-encoded PNG data.
- `pytest` test setup, and Dependabot configuration for periodic `uv` package updates.
- A resource and a resource template.

### Changed

- Package renamed for PyPI publishing, with `README.md` updated to reflect the PyPI package badge and Glama/Smithery listings.
- Package and dependencies upgraded.

[unreleased]: https://github.com/anirbanbasu/pymcp/compare/v.0.3.0...HEAD
[0.3.0]: https://github.com/anirbanbasu/pymcp/compare/v.0.2.4...v.0.3.0
[0.2.4]: https://github.com/anirbanbasu/pymcp/compare/v.0.2.3...v.0.2.4
[0.2.3]: https://github.com/anirbanbasu/pymcp/compare/v.0.2.0...v.0.2.3
[0.2.0]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.8...v.0.2.0
[0.1.8]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.7...v.0.1.8
[0.1.7]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.6...v.0.1.7
[0.1.6]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.5...v.0.1.6
[0.1.5]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.4...v.0.1.5
[0.1.4]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.3...v.0.1.4
[0.1.3]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.2b2...v.0.1.3
[0.1.2b2]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.2-beta.1...v.0.1.2b2
[0.1.2-beta.1]: https://github.com/anirbanbasu/pymcp/compare/v.0.1.1...v.0.1.2-beta.1
[0.1.1]: https://github.com/anirbanbasu/pymcp/compare/v.0.0.1...v.0.1.1
