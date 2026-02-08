import base64
import hashlib
import math
import random
import secrets
import string
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from typing import Annotated, Any
from xmlrpc.client import INTERNAL_ERROR

import pydantic_monty
import uvicorn
from ddgs import DDGS
from fastmcp import Context, FastMCP
from fastmcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from fastmcp.server.middleware.caching import (
    CallToolSettings,
    GetPromptSettings,
    ListPromptsSettings,
    ListResourcesSettings,
    ListToolsSettings,
    ReadResourceSettings,
    ResponseCachingMiddleware,
)
from fastmcp.tools.tool import ToolResult
from mcp import McpError
from mcp.types import (
    INVALID_PARAMS,
    ErrorData,
)
from pydantic import Field
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from pymcp import PACKAGE_NAME, EnvVars
from pymcp.data_model.response_models import Base64EncodedBinaryDataResponse
from pymcp.middleware import ResponseMetadataMiddleware, StripUnknownArgumentsMiddleware
from pymcp.mixin import MCPMixin

package_version = version(PACKAGE_NAME)


class PyMCP(MCPMixin):
    """A simple MCP server implementation demonstrating various features."""

    tools = [
        {
            "fn": "greet",
            "tags": ["greeting", "example"],
            "annotations": {"readOnlyHint": True},
        },
        {
            "fn": "generate_password",
            "tags": ["password-generation", "example"],
            "annotations": {"readOnlyHint": True},
        },
        {
            "fn": "text_web_search",
            "tags": ["meta-search", "text-search", "searchexample"],
        },
        {
            "fn": "permutations",
            "tags": ["math", "permutation", "example"],
            "annotations": {"readOnlyHint": True},
        },
        {
            "fn": "run_python_code",
            "tags": ["python", "monty", "secure interpreter", "example"],
        },
        {"fn": "pirate_summary", "tags": ["pirate-summary", "llm-sampling", "example"]},
        {"fn": "vonmises_random", "tags": ["experimental", "elicitation", "example"]},
    ]
    resources = [
        {
            "uri": "data://logo",
            "fn": "resource_logo",
            "mime_type": "application/json",
            "tags": ["logo", "png", "example"],
        },
        {
            "uri": "data://logo_svg",
            "fn": "resource_logo_svg",
            "mime_type": "image/svg+xml",
            "tags": ["logo", "svg", "example"],
        },
        {
            # This is a resource template, the actual URI will be like data://modulo10/42
            "uri": "data://modulo10/{number}",
            "fn": "resource_unicode_modulo10",
        },
    ]
    prompts = [
        {"fn": "code_prompt", "tags": ["example", "code-generation"]},
    ]

    async def greet(
        self,
        ctx: Context,
        name: Annotated[
            str | None,
            Field(
                default=None,
                description="The optional name to be greeted.",
                validate_default=False,
            ),
        ] = None,
    ) -> str:
        """Greet the caller with a quintessential Hello World message."""
        welcome_message = f"Welcome to the {PACKAGE_NAME} {package_version} server! The current date time in UTC is {datetime.now(UTC).isoformat()}. This response may be cached."
        response: str = ""
        if name is None or name.strip() == "":
            await ctx.warning("No name provided, using default greeting.")
            response = f"Hello World! {welcome_message}"
        else:
            await ctx.info(f"Greeting {name}.")
            response = f"Hello, {name}! {welcome_message}"
        return response

    async def generate_password(
        self,
        ctx: Context,
        length: Annotated[
            int,
            Field(
                default=12,
                ge=8,
                le=64,
                description="The length of the password to generate (between 8 and 64 characters).",
            ),
        ] = 12,
        use_special_chars: Annotated[
            bool,
            Field(
                default=False,
                description="Include special characters in the password.",
            ),
        ] = False,
    ) -> ToolResult:
        """Generate a random password with specified length, optionally including special characters."""
        """The password will meet the complexity requirements of at least one lowercase letter, one uppercase letter, and two digits.
        If special characters are included, it will also contain at least one such character.
        Until the password meets these requirements, it will keep regenerating.
        This is a simple example of a tool that can be used to generate passwords. It is not intended for production use."""
        characters = string.ascii_letters + string.digits
        if use_special_chars:
            characters += string.punctuation
        password_generation_attempts = 0
        while True:
            password = "".join(secrets.choice(characters) for _ in range(length))
            password_generation_attempts += 1
            if (
                any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 2
                and (not use_special_chars or any(c in string.punctuation for c in password))
            ):
                await ctx.info("Generated password meets complexity requirements.")
                break
            else:
                # Exclude from coverage because this may not always happen in tests
                await ctx.warning(  # pragma: no cover
                    f"Re-generating since the generated password did not meet complexity requirements: {password}"
                )
        return self.get_tool_result(
            result=password,
            metadata={
                "generate_password": {
                    "length_satisfied": len(password) == length,
                    "character_set": characters,
                    "generation_attempts": password_generation_attempts,
                }
            },
        )

    async def text_web_search(
        self,
        ctx: Context,
        query: Annotated[
            str,
            Field(
                ...,
                description="The search query to fetch results for. It should be a non-empty string.",
            ),
        ],
        region: Annotated[
            str | None,
            Field(default="uk-en", description="Optional region to search in."),
        ] = "uk-en",
        max_results: Annotated[
            int | None,
            Field(
                default=10,
                ge=1,
                le=100,
                description="The maximum number of results to return. Default is 10, maximum is 100.",
            ),
        ] = 10,
        pages: Annotated[
            int | None,
            Field(
                default=1,
                ge=1,
                le=10,
                description="The number of pages to fetch. Default is 1, maximum is 10.",
            ),
        ] = 1,
    ) -> list[dict[str, Any]]:
        """Perform a text web search using the provided query using DDGS."""
        await ctx.info(f"Performing text web search for query: {query}")
        results = DDGS().text(query=query, region=region, max_results=max_results, page=pages)
        if results:
            await ctx.info(f"Found {len(results)} results for the query.")
        return results

    async def permutations(
        self,
        ctx: Context,
        n: Annotated[
            int,
            Field(
                ge=1,
                description="The number of items to choose from.",
            ),
        ],
        k: Annotated[
            int | None,
            Field(
                default=None,
                ge=1,
                description="The optional number of items to choose.",
            ),
        ],
    ) -> int:
        """Calculate the number of ways to choose k items from n items without repetition and with order."""
        """If k is not provided, it defaults to n."""
        assert isinstance(n, int) and n >= 1, "n must be a positive integer."

        if k is None:
            k = n
        if k > n:
            raise McpError(
                error=ErrorData(
                    code=INVALID_PARAMS,
                    message=f"k ({k}) cannot be greater than n ({n}).",
                )
            )

        return math.perm(n, k)

    async def run_python_code(
        self,
        ctx: Context,
        code: str,
        inputs: dict[str, Any] | None = None,
        script_name: str = "main.py",
        check_types: bool = True,
        type_definitions: str | None = None,
    ) -> Any:
        """Run the given Python code and return the output or error message."""
        try:
            m = pydantic_monty.Monty(
                code=code,
                script_name=script_name,
                inputs=list(inputs.keys()) if inputs else None,
                type_check=check_types,
                type_check_stubs=type_definitions,
            )
            return await pydantic_monty.run_monty_async(monty_runner=m, inputs=inputs)
        except Exception as e:
            raise McpError(
                error=ErrorData(
                    code=INTERNAL_ERROR,
                    message=str(e),
                )
            ) from e

    async def pirate_summary(self, ctx: Context, text: str) -> str | None:
        """Summarise the given text in a pirate style. This is an example of a tool that can use LLM sampling to generate a summary."""
        await ctx.info("Summarising text in pirate style using client LLM sampling.")
        response = await ctx.sample(
            messages=text,
            system_prompt="Your task is to summarise a given text in a pirate style. Use a fun and engaging tone but be concise.",
            temperature=0.9,  # High creativity
            max_tokens=1024,  # Pirates can be a bit verbose!
        )
        return getattr(response, "text", None)

    async def vonmises_random(
        self,
        ctx: Context,
        mu: Annotated[
            float,
            Field(
                description="The mean angle mu (μ), expressed in radians between 0 and 2π",
                ge=0,
                le=2 * math.pi,
            ),
        ],
    ) -> float:
        """Generate a random number from the von Mises distribution. This is an example of a tool that uses elicitation to obtain the required parameter kappa (κ)."""
        await ctx.info("Requesting the user for the value of kappa for von Mises distribution.")
        response = await ctx.elicit(
            message="Please provide the value of kappa (κ) for the von Mises distribution. It should be a positive number.",
            response_type=float,
        )
        kappa: float = 1.0  # Default value
        match response:  # pragma: no cover
            case AcceptedElicitation(data=kappa):
                await ctx.warning(f"Received kappa: {kappa}")
                if kappa < 0:
                    raise McpError(
                        error=ErrorData(
                            code=INVALID_PARAMS,
                            message="kappa (κ) must be a positive number.",
                        )
                    )
            case DeclinedElicitation():
                await ctx.warning("User declined to provide kappa (κ). Using default value of 1.0.")
            case CancelledElicitation():
                await ctx.warning("User cancelled the operation. The random number will NOT be generated.")
                raise McpError(
                    error=ErrorData(
                        code=INVALID_PARAMS,
                        message="Operation cancelled by the user.",
                    )
                )
        return random.vonmisesvariate(mu, kappa)

    async def resource_logo(self, ctx: Context) -> str:
        """Get the base64 encoded PNG logo of PyMCP."""
        await ctx.info("Reading the PNG logo for PyMCP.")
        with open("resources/logo.png", "rb") as logo_file:
            logo_content = logo_file.read()
            sha3_512_hasher = hashlib.sha3_512()
            sha3_512_hasher.update(logo_content)
            hex_digest = sha3_512_hasher.hexdigest()
            await ctx.info(f"Read {len(logo_content)} bytes from the logo file. SHA3-512: {hex_digest}")
            logo_file.close()
        response = Base64EncodedBinaryDataResponse(
            data=base64.b64encode(logo_content).decode(),
            hash=hex_digest,
            hash_algorithm=sha3_512_hasher.name,
        )
        return response.model_dump_json()

    async def resource_logo_svg(self, ctx: Context) -> str:
        """Get the PyMCP logo as SVG."""
        await ctx.info("Reading the SVG logo for PyMCP.")
        with open("resources/logo.svg", "rb") as logo_file:
            logo_content = logo_file.read()
            await ctx.info(f"Read {len(logo_content)} bytes from the SVG logo file.")
            logo_file.close()
        return logo_content.decode()

    async def resource_unicode_modulo10(
        self,
        ctx: Context,
        number: Annotated[
            int,
            Field(
                ...,
                description="The number whose modulus 10 should be returned.",
                ge=1,
                le=1000,
            ),
        ],
    ) -> str:
        """Computes the modulus 10 of a given number and returns a Unicode character representing the result."""
        """
        The character is chosen based on whether the modulus is odd or even:
        - For odd modulus, it uses the Unicode character starting from ❶ (U+2776).
        - For even modulus, it uses the Unicode character starting from ① (U+2460).
        - If the modulus is 0, it returns the circled zero character ⓪ (U+24EA).
        """
        modulus = number % 10
        odd_base = 0x2776  # U+2776 is the base for odd modulus symbols. It is the symbol ❶. Remember to subtract 1.
        even_base = 0x2460  # U+2460 is the base for even modulus symbols. It is the symbol ①. Remember to subtract 1.
        circled_zero = 0x24EA  # U+24EA is the circled zero symbol (⓪).
        if modulus % 2 != 0:
            # Odd modulus, start with odd_base
            await ctx.info(
                f"{number} modulo 10 is odd, using character type {chr(int(hex(odd_base), 16))} to represent the modulus."
            )
            unicode_symbol = chr(int(hex(odd_base + modulus - 1), 16))
        else:
            await ctx.info(
                f"{number} modulo 10 is even, using character type {chr(int(hex(circled_zero), 16))} to represent the modulus."
            )
            unicode_symbol = (
                chr(int(hex(even_base + modulus - 1), 16)) if modulus != 0 else chr(int(hex(circled_zero), 16))
            )
        return unicode_symbol

    async def code_prompt(self, ctx: Context, task: str) -> str:
        """Get a prompt to write a code snippet in Python based on the specified task."""
        return f"""Write a Python code snippet to perform the following task:
        [TASK]
        {task}
        [/TASK]
        The code should be well-commented and follow best practices.
        Make sure to include necessary imports and handle any exceptions that may arise."""


def app() -> FastMCP:  # pragma: no cover
    """Create and configure the FastMCP application instance."""
    app = FastMCP(
        name=PACKAGE_NAME,
        version=package_version,
        instructions="A simple MCP server for testing purposes.",
        on_duplicate="error",
    )
    mcp_obj = PyMCP()
    app_with_features = mcp_obj.register_features(app)
    app_with_features.add_middleware(StripUnknownArgumentsMiddleware())
    app_with_features.add_middleware(
        ResponseCachingMiddleware(
            list_tools_settings=ListToolsSettings(
                ttl=EnvVars.RESPONSE_CACHE_TTL,
                enabled=EnvVars.RESPONSE_CACHE_TTL > 0,
            ),
            list_prompts_settings=ListPromptsSettings(
                ttl=EnvVars.RESPONSE_CACHE_TTL,
                enabled=EnvVars.RESPONSE_CACHE_TTL > 0,
            ),
            list_resources_settings=ListResourcesSettings(
                ttl=EnvVars.RESPONSE_CACHE_TTL,
                enabled=EnvVars.RESPONSE_CACHE_TTL > 0,
            ),
            # Only deterministic tools are included in caching.
            # Tools like 'generate_password', 'text_web_search', 'pirate_summary', and 'vonmises_random' are excluded
            # because they produce non-deterministic or time-sensitive results, and caching their
            # outputs could lead to stale or incorrect responses.
            call_tool_settings=CallToolSettings(
                included_tools=["greet", "permutations"],
                ttl=EnvVars.RESPONSE_CACHE_TTL,
                enabled=EnvVars.RESPONSE_CACHE_TTL > 0,
            ),
            get_prompt_settings=GetPromptSettings(
                ttl=EnvVars.RESPONSE_CACHE_TTL,
                enabled=EnvVars.RESPONSE_CACHE_TTL > 0,
            ),
            read_resource_settings=ReadResourceSettings(
                ttl=EnvVars.RESPONSE_CACHE_TTL,
                enabled=EnvVars.RESPONSE_CACHE_TTL > 0,
            ),
        )
    )
    # The last middleware must be the one to attach response metadata
    app_with_features.add_middleware(ResponseMetadataMiddleware())
    return app_with_features


def main():  # pragma: no cover
    """Main entry point to run the FastMCP server."""
    try:
        # Run the FastMCP server using stdio by default.
        # Other transports can be configured as needed using the MCP_SERVER_TRANSPORT environment variable.
        mcp_app = app()
        transport_type = EnvVars.MCP_SERVER_TRANSPORT
        if transport_type != "stdio":
            # Configure CORS for browser-based clients, see: https://gofastmcp.com/deployment/http#cors-for-browser-based-clients
            middleware = [
                Middleware(
                    CORSMiddleware,
                    allow_origins=EnvVars.ASGI_CORS_ALLOWED_ORIGINS,
                    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                    allow_headers=[
                        "mcp-protocol-version",
                        "mcp-session-id",
                        "Authorization",
                        "Content-Type",
                    ],
                    expose_headers=["mcp-session-id"],
                ),
            ]

            asgi_app = mcp_app.http_app(middleware=middleware, transport=transport_type)
            uvicorn.run(
                asgi_app,
                host=EnvVars.FASTMCP_HOST,
                port=EnvVars.FASTMCP_PORT,
                timeout_graceful_shutdown=5,  # seconds
            )
        else:
            mcp_app.run(transport=transport_type)
    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        # Cleanup if necessary
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
