# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [unreleased]

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

## [0.2.4] - 2026-07-24

Baseline for this changelog. See git history for changes prior to its introduction.
