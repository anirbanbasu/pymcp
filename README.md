[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=3776ab&labelColor=e4e4e4)](https://www.python.org/downloads/release/python-3120/)


<p align="center">
  <img width="256" height="84" src="https://raw.githubusercontent.com/anirbanbasu/pymcp/master/resources/logo.svg" alt="pymcp logo" style="filter: invert(1)">
</p>

Primarily to be used as a template repository for developing MCP servers with [FastMCP](http://gofastmcp.com/) in Python, PyMCP is somewhat inspired by the [official everything MCP server](https://github.com/modelcontextprotocol/servers/tree/main/src/everything) in Typescript.

# Installation

The directory where you clone this repository will be referred to as the _working directory_ or _WD_ hereinafter.

Install [uv](https://docs.astral.sh/uv/getting-started/installation/). To install the project with its minimal dependencies in a virtual environment, run the following in the _WD_. To install all non-essential dependencies (_which are required for developing and testing_), replace the `--no-dev` with the `--all-groups` flag in the following command.

```bash
uv sync --no-dev
```

# Standalone usage
PyMCP can be started standalone as a MCP server with `stdio` transport by running the following. However, you are unlikely to use it this way.

```bash
uv run pymcp
```

Furthermore, being a template repository, the code deliberately does not implement `streamable-http` and `sse` transports.

# Test with the MCP Inspector

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) is an _official_ Model Context Protocol tool that can be used by developers to test and debug MCP servers. This is the most comprehensive way to explore the MCP server.

To use it, you must have Node.js installed. The best way to install and manage `node` as well as packages such as the MCP Inspector is to use the [Node Version Manager (or, `nvm`)](https://github.com/nvm-sh/nvm). Once you have `nvm` installed, you can install and use the latest Long Term Release version of `node` by executing the following.

```bash
nvm install --lts
nvm use --lts
```

Following that, run the MCP Inspector and PyMCP by executing the following in the _WD_.

```bash
npx @modelcontextprotocol/inspector uv run pymcp
```

This will create a local URL at port 6274 with an authentication token, which you can copy and browse to on your browser. Once on the MCP Inspector UI, press _Connect_ to connect to the MCP server. Thereafter, you can explore the tools available on the server.

# Use it with Claude Desktop, Visual Studio, and so on

The server entry to run with `stdio` transport that you can use with systems such as Claude Desktop, Visual Studio Code, and so on is as follows.

```json
{
    "command": "uv",
    "args": [
        "run",
        "pymcp"
    ]
}
```

Instead of having `pymcp` as the last item in the list of `args`, you may need to specify the full path to the script, e.g., _WD_`/.venv/bin/pymcp`.

# Contributing

Install [`pre-commit`](https://pre-commit.com/) for Git by using the `--all-groups` flag for `uv sync` for the installation of PyMCP.

Then enable `pre-commit` by running the following in the _WD_.

```bash
pre-commit install
```
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

# License

[MIT](https://choosealicense.com/licenses/mit/).
