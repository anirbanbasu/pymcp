This file provides guidance to coding agents (Claude Code, Codex, and similar tools) when working with code in this repository.

## Project

pymcp: a template repository for building MCP servers with [FastMCP](http://gofastmcp.com/) in Python. It is not itself an application with a fixed domain — the `greet`, `generate_password`, `text_web_search`, `permutations`, and `run_python_code` tools exist to demonstrate patterns (tool/resource/prompt registration, middleware, caching, response metadata), not because they're the point of the project. When adapting this repository into a new MCP server, expect to delete the example tools/resources/prompts and replace them, while keeping the surrounding scaffolding (mixin registration, middleware, env var handling, test layering) intact.

## Commands

`uv` manages the Python 3.12 environment — do not use `pip` directly. Commands run either via plain `uv run` or the `justfile` (`just -l` lists every recipe).

```bash
just install                   # sync minimal (runtime-only) dependencies
just install-all               # sync all dependency groups (dev, test)
just format                    # ruff format + ruff check --fix
just type-check                # uv run ty check
just test-coverage             # pytest (via coverage) across tests/, then coverage report
just launch-inspector          # run the MCP Inspector against the server (needs nvm/node)
just vulnerability-scan        # osv-scanner over the source tree
just install-pre-commit-hooks / just pre-commit-update   # manage hooks via `prek`, not `pre-commit`
```

Run a single test:

```bash
uv run pytest tests/test_server.py::TestMCPServer::test_greet_default -v
```

`just test-coverage` enforces `fail_under = 100` (see `[tool.coverage.report]` in `pyproject.toml`); use `# pragma: no cover` for genuinely unreachable branches rather than writing tests around them. Running a single test with plain `pytest`/`uv run pytest` skips the coverage gate, which is expected during iterative development.

Ruff (line length 120, Google-style docstrings, isort, pyupgrade, complexity ≤ 15) and `ty` are also run by pre-commit hooks (`.pre-commit-config.yaml`), installed with `prek`, not the `pre-commit` CLI.

## Architecture

### Server (`server.py`)

`app()` builds a `FastMCP` instance and registers the `PyMCP` class's tools/resources/prompts via `MCPMixin.register_features()` — a declarative list-of-dicts registry (`tools`, `resources`, `prompts` class attributes) rather than one `@mcp.tool` decorator per method, so registration metadata (tags, annotations) lives next to the list instead of scattered across decorators. `ResponseCachingMiddleware` is configured with explicit per-tool opt-in (`included_tools=[...]`) rather than caching everything by default, since non-deterministic or time-sensitive tools (`generate_password`, `text_web_search`) must never be cached. `ResponseMetadataMiddleware` must be added last so it can attach metadata to whatever the preceding middleware chain produced. `main()` picks the transport from `EnvVars.MCP_SERVER_TRANSPORT` and calls `FastMCP.run()`/`http_app()` directly — there is no manual Starlette/uvicorn assembly beyond wiring CORS middleware for HTTP transports.

### Protocol compatibility

The `mcp` SDK v2 (which FastMCP 4.x is built on) negotiates the MCP protocol version per connection automatically, so every tool/resource/prompt in this template already serves both `2026-07-28`+ clients and older, handshake-era (session-based) clients with no extra code. The one exception is server-initiated back-channel requests — `ctx.sample()` (client sampling) and `ctx.elicit()` (client elicitation) — which SEP-2577 removed from the modern protocol; FastMCP still exposes them, but they only function when a client negotiates the deprecated, legacy handshake. This template used to ship `pirate_summary`/`vonmises_random` example tools exercising exactly that pattern; they were removed since none of the remaining tools need it. If you add a tool that uses `ctx.sample()`/`ctx.elicit()`, know that it is legacy-protocol-only and won't work against a client speaking the current stateless envelope.

### Mixin (`mixin.py`)

`MCPMixin.register_features()` is the generic registration engine described above; it has no FastMCP-server-construction knowledge itself, so it could be reused verbatim in a derived project as long as that project follows the same `tools`/`resources`/`prompts` dict-list convention. `get_tool_result()` is a thin `ToolResult` constructor for tools that want to return structured content plus metadata.

### Middleware (`middleware.py`)

Two middlewares: `StripUnknownArgumentsMiddleware` (drops arguments an LLM caller passed that the tool doesn't declare, rather than letting FastMCP/pydantic reject the call outright) and `ResponseMetadataMiddleware` (adds package name/version and per-call timing to `result.meta`). Both catch and log errors defensively except where propagation is intentional — see the comment in `ResponseMetadataMiddleware.on_call_tool` about *not* wrapping the timed call in try/except so real tool errors still propagate.

### Configuration (`__init__.py`)

Environment variables are declared once as class attributes on `EnvVars`, using `environs`/`marshmallow` for typed parsing and validation (`OneOf`, `Range`). Add new environment-driven config here rather than reading `os.environ` elsewhere.

### Data model (`data_model/response_models.py`)

`Base64EncodedBinaryDataResponse` pairs base64-encoded binary data with a self-verifying cryptographic hash (`model_validator` recomputes and checks the hash on construction) — a pattern worth reusing for any response that carries binary payloads over MCP's text-based content types.

### Tests (`tests/`)

Three files matching the source layout: `test_server.py` exercises tools/resources/prompts through FastMCP's in-process `Client`/`FastMCP` pair (`async with Client(mcp) as client: await client.call_tool(...)`), which actually serialises through the MCP protocol; `test_middleware.py` and `test_data_models.py` test those modules directly. Prefer reading `result.data` / `result.structured_content` in assertions over re-deriving expected values inline, matching the existing style.

## Documentation

`README.md` is the sole source of user-facing documentation — components (tools/resources/prompts), installation, environment variables, and usage all live there. There is no external documentation site. Keep the component list in README.md in sync with `PyMCP.tools`/`resources`/`prompts` in `server.py` when adapting this template.
