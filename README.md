[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=3776ab&labelColor=e4e4e4)](https://www.python.org/downloads/release/python-3120/) [![pytest](https://github.com/anirbanbasu/pymcp/actions/workflows/uv-pytest.yml/badge.svg)](https://github.com/anirbanbasu/pymcp/actions/workflows/uv-pytest.yml) [![PyPI](https://img.shields.io/pypi/v/pymcp-template?label=pypi%20package)](https://pypi.org/project/pymcp-template/#history)  [![smithery badge](https://smithery.ai/badge/@anirbanbasu/pymcp)](https://smithery.ai/server/@anirbanbasu/pymcp)


<p align="center">
  <img width="256" height="84" src="https://raw.githubusercontent.com/anirbanbasu/pymcp/master/resources/logo.svg" alt="pymcp logo" style="filter: invert(1)">
</p>

Primarily to be used as a template repository for developing MCP servers with [FastMCP](http://gofastmcp.com/) in Python, PyMCP is somewhat inspired by the [official everything MCP server](https://github.com/modelcontextprotocol/servers/tree/main/src/everything) in Typescript.

# Components

The following components are available on this MCP server.

## Tools

1. **`greet`**
  - Greets the caller with a quintessential Hello World message.
  - Input(s)
    - `name`: _`string`_ (_optional_): The name to greet. Default value is none.
  - Output(s)
    - `TextContent` with a UTC time-stamped greeting.
2. **`generate_password`**
  - Generates a random password with specified length, optionally including special characters and conforming to the complexity requirements of at least one lowercase letter, one uppercase letter, and two digits. If special characters are included, it will also contain at least one such character.
  - Input(s)
    - `length`: _`integer`_: The length of the generated password. The value must be an integer between 8 and 64, both inclusive.
    - `use_special_chars`: _`boolean`_ (_optional_): A flag to indicate whether the password should include special characters. Default value is `False`.
  - Output(s)
    - `TextContent` with the generated password.
3. **`permutations`**
  - Calculates the number of ways to choose $k$ items from $n$ items without repetition and with order. If $k$ is not provided, it defaults to $n$.
  - Input(s)
    - `n`: _`integer`_: The number of items to choose from. This should be a non-zero, positive integer.
    - `k`: _`integer`_ (_optional_): The number of items to choose. Default value is the value of `n`.
  - Output(s)
    - `TextContent` with number of ways to choose $k$ items from $n$, essentially ${}^{n}P_{k}$.

## Resources

1. **`get_logo`**
  - Retrieves the Base64 encoded PNG logo of PyMCP along with its SHA3-512 hash.
  - URL: `data://logo`
  - Output(s)
    - `TextContent` with a `Base64EncodedBinaryDataResponse` Pydantic object with the following fields.
      - `data`: _`string`_: The Base64 encoded PNG logo of PyMCP.
      - `hash`: _`string`_: The hexadecimal encoded cryptographic hash of the raw binary data, which is represented by its Base64 encoded string equivalent in `data`. (The hex encoded hash value is expected to be _6414b58d9e44336c2629846172ec5c4008477a9c94fa572d3419c723a8b30eb4c0e2909b151fa13420aaa6a2596555b29834ac9b2baab38919c87dada7a6ef14_.)
      - `hash_algorithm`: _`string`_: The cryptographic hash algorithm used, e.g., _sha3_512_.

1. **`unicode_modulo10`**
  - Computes the modulus 10 of a given number and returns a Unicode character representing the result. The character is chosen based on whether the modulus is odd or even. For odd modulus, it uses the Unicode character starting from ❶ (U+2776). For even modulus, it uses the Unicode character starting from ① (U+2460). If the modulus is 0, it returns the circled zero character ⓪ (U+24EA).
  - URL: `data://modulo10/{number}`
  - Input(s)
    - `number`: _`integer`_: A positive integer between 1 and 1000, both inclusive.
  - Output(s)
    - `TextContent` with a string representing the correct Unicode character.

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
