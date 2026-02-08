[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=3776ab&labelColor=e4e4e4)](https://www.python.org/downloads/release/python-3120/) [![pytest](https://github.com/anirbanbasu/pymcp/actions/workflows/uv-pytest-coverage.yml/badge.svg)](https://github.com/anirbanbasu/pymcp/actions/workflows/uv-pytest-coverage.yml) [![PyPI](https://img.shields.io/pypi/v/pymcp-template?label=pypi%20package)](https://pypi.org/project/pymcp-template/#history) ![GitHub commits since latest release](https://img.shields.io/github/commits-since/anirbanbasu/pymcp/latest) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/anirbanbasu/pymcp/badge)](https://scorecard.dev/viewer/?uri=github.com/anirbanbasu/pymcp)


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
3. **`text_web_search`**
  - Searches the web with a text query using the [Dux Distributed Global Search (DDGS)](https://github.com/deedy5/ddgs).
  - Input(s)
    - `query`: _`string`_: The search query to fetch results for. It should be a non-empty string.
    - `region`: _`string`_ (_optional_): Two letter country code followed by a hyphen and then by two letter language code, e.g., `uk-en` or `us-en`. Default value is `uk-en`.
    - `max_results`: _`integer`_ (_optional_): Optional maximum number of results to be fetched. Default value is 10.
    - `pages`: _`integer`_ (_optional_): Optional number of pages to spread the results over. Default value is 1.
  - Environment variable(s)
    - `DDGS_PROXY`: _`string`_ (_optional_): Optional proxy server to use for egress web search requests.
  - Output(s)
    - `TextContent` with a list of dictionaries with search results.
4. **`permutations`**
  - Calculates the number of ways to choose $k$ items from $n$ items without repetition and with order. If $k$ is not provided, it defaults to $n$.
  - Input(s)
    - `n`: _`integer`_: The number of items to choose from. This should be a non-zero, positive integer.
    - `k`: _`integer`_ (_optional_): The number of items to choose. Default value is the value of `n`.
  - Output(s)
    - `TextContent` with number of ways to choose $k$ items from $n$, essentially ${}^{n}P_{k}$.
5. **`run_python_code`**
  - Runs arbitrary Python code in a secure and fast interpreter using [Pydantic Monty](https://github.com/pydantic/monty). Note that Pydantic Monty is experimental and Python language support is partial as of February 8, 2026.
  - Input(s)
    - `code`: _`string`_: The Python code to run.
    - `inputs`: _`dict[str, Any]`_ (_optional_): A dictionary of input values for the Python code. Default value is `None`.
    - `script_name`: _`str`_ (_optional_): The name of the script used in traceback and error messages. Default value is `main.py`.
    - `check_types`: _`bool`_ (_optional_): A flag to indicate whether to check types. Default value is `True`.
    - `type_definitions`: _`str`_ (_optional_): Type definitions to be used for type checking. Default value is `None`.
  - Output(s)
    - `TextContent` with the output, if any, of the Python code.

6. **`pirate_summary`**
  - Summarises the given text in a pirate style. _This tool uses LLM client sampling. Hence, a sampling handler must exist on the client-side._
  - Input(s)
    - `text`: _`string`_: The text to summarise.
  - Output(s)
    - `TextContent` with the summary of `text` in pirate speak.
7. **`vonmises_random`**
  - Generates a random number from the [von Mises distribution](https://reference.wolfram.com/language/ref/VonMisesDistribution.html). _This tool uses client elicitation to obtain the parameter kappa ($\kappa$). Hence, an elicitation handler must exist on the client-side._
  - Input(s)
    - `mu`: _`float`_: The parameter $\mu$ between 0 and $2\pi$.
  - Output(s)
    - `TextContent` with the a random number from the von Mises distribution.

## Resources

1. **`resource_logo`**
  - Retrieves the Base64 encoded PNG logo of PyMCP along with its SHA3-512 hash.
  - URL: `data://logo`
  - Output(s)
    - `TextContent` with a `Base64EncodedBinaryDataResponse` Pydantic object with the following fields.
      - `data`: _`string`_: The Base64 encoded PNG logo of PyMCP.
      - `hash`: _`string`_: The hexadecimal encoded cryptographic hash of the raw binary data, which is represented by its Base64 encoded string equivalent in `data`. (The hex encoded hash value is expected to be _6414b58d9e44336c2629846172ec5c4008477a9c94fa572d3419c723a8b30eb4c0e2909b151fa13420aaa6a2596555b29834ac9b2baab38919c87dada7a6ef14_.)
      - `hash_algorithm`: _`string`_: The cryptographic hash algorithm used, e.g., _sha3_512_.

2. **`resource_logo_svg`**
  - Retrieves the SVG logo of PyMCP.
  - URL: `data://logo_svg`
  - Output(s)
    - `TextContent` with a the SVG data for the PyMCP logo.

3. **`resource_unicode_modulo10`**
  - Computes the modulus 10 of a given number and returns a Unicode character representing the result. The character is chosen based on whether the modulus is odd or even. For odd modulus, it uses the Unicode characters ❶ (U+2776), ❸ (U+2778), ❺ (U+277A), ❼ (U+277C), and ❾ (U+277E). For even modulus, it uses the Unicode characters ⓪ (U+24EA), ② (U+2461), ④ (U+2463), ⑥ (U+2465), and ⑧ (U+2467).
  - URL: `data://modulo10/{number}`
  - Input(s)
    - `number`: _`integer`_: A positive integer between 1 and 1000, both inclusive.
  - Output(s)
    - `TextContent` with a string representing the correct Unicode character.

## Prompts

1. **`code_prompt`**
  - Get a prompt to write a code snippet in Python based on the specified task..
  - Input(s)
    - `task`: _`string`_: The description of the task for which a code implementation prompt will be generated.
  - Output(s)
    - `str` representing the prompt.

# Installation

The directory where you clone this repository will be referred to as the _working directory_ or _WD_ hereinafter.

Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/). Install [`just`](https://github.com/casey/just?tab=readme-ov-file#installation). To install the project with its minimal dependencies in a virtual environment, run the following in the _WD_. To install all non-essential dependencies (_which are required for developing and testing_), replace the `install` taget with the `install-all` target in the following command.

```bash
just install
```

# Environment variables

The following environment variables can be configured.

 - `PYMCP_LOG_LEVEL`: Sets the [Python log level](https://docs.python.org/3/library/logging.html#logging-levels) for the PyMCP server. Default is `INFO`.
 - `MCP_SERVER_TRANSPORT`: Sets the [FastMCP server transport](https://gofastmcp.com/deployment/running-server#transport-protocols) type of this MCP server. Default is `stdio`.
 - `RESPONSE_CACHE_TTL`: Sets the time, in seconds, for the time-to-live (TTL) cache that can be activated for caching prompt, resource and tool responses from the server. Default value is 30. Any integer value between 0 and 86400 (i.e., one day), both inclusive, is valid. Setting it to 0 effectively disables response caching.
 - `FASTMCP_HOST`: Sets the host address for the FastMCP server when using network transports (e.g., `streamable-http`, `sse`). Default is `localhost`.
 - `FASTMCP_PORT`: Sets the port number for the FastMCP server when using network transports. Default is `8000`.
 - `ASGI_CORS_ALLOWED_ORIGINS`: Sets the [CORS allowed origins](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) when the MCP server is started with a transport over HTTP. Default is `["*"]`.

# Standalone usage
PyMCP can be started standalone as a MCP server with `stdio` transport by running the following. Alternatively, it can be started using `streamable-http` or `sse` transports by specifying the transport type using the `MCP_SERVER_TRANSPORT` environment variable.

```bash
uv run pymcp
```

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

You can, alternatively, launch the MCP inspector by running `just launch-inspector`.

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

# Remotely hosted options

The currently available remotely hosted options are as follows.

 - FastMCP Cloud: https://pymcp-template.fastmcp.app/mcp
 - Glama.AI: https://glama.ai/mcp/servers/@anirbanbasu/pymcp

# Testing and coverage

To run the provided set of tests using `pytest`, execute the following in _WD_. To get a report on coverage while invoking the tests, run the following in _WD_.

```bash
just test-coverage
```

This will generate something like the following output.

```bash
Name    Stmts   Miss    Cover   Missing
---------------------------------------
TOTAL     226      0  100.00%
```

# Contributing

See the [Contributing guide](CONTRIBUTING.md).

# License

[MIT](https://choosealicense.com/licenses/mit/).
