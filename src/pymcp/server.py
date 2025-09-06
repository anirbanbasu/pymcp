import base64
import random
import sys
import string
import hashlib
import secrets
import math
from typing import Annotated, Optional
from ddgs import DDGS
from fastmcp import FastMCP, Context
from fastmcp.prompts.prompt import PromptMessage, TextContent
from mcp import McpError
from mcp.types import (
    ErrorData,
    INVALID_PARAMS,
)
from importlib.metadata import version

from pymcp import env
from marshmallow.validate import OneOf
from pydantic import Field

from datetime import datetime, timezone

from fastmcp.server.elicitation import (
    AcceptedElicitation,
    DeclinedElicitation,
    CancelledElicitation,
)

from pymcp.data_model.response_models import Base64EncodedBinaryDataResponse
from pymcp.mixin import MCPMixin


PACKAGE_NAME = "pymcp-template"
package_version = version(PACKAGE_NAME)


class PyMCP(MCPMixin):
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
            Optional[str],
            Field(
                default=None,
                description="The optional name to be greeted.",
                validate_default=False,
            ),
        ] = None,
    ) -> str:
        """Greet the caller with a quintessential Hello World message."""
        welcome_message = f"Welcome to the {PACKAGE_NAME} {package_version} server! The current date time in UTC is {datetime.now(timezone.utc).isoformat()}."
        if name is None or name.strip() == "":
            await ctx.warning("No name provided, using default greeting.")
            return f"Hello World! {welcome_message}"
        await ctx.info(f"Greeting {name}.")
        return f"Hello, {name}! {welcome_message}"

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
    ) -> str:
        """
        Generate a random password with specified length, optionally including special characters.
        The password will meet the complexity requirements of at least one lowercase letter, one uppercase letter, and two digits.
        If special characters are included, it will also contain at least one such character.
        Until the password meets these requirements, it will keep regenerating.
        This is a simple example of a tool that can be used to generate passwords. It is not intended for production use.
        """
        characters = string.ascii_letters + string.digits
        if use_special_chars:
            characters += string.punctuation
        while True:
            password = "".join(secrets.choice(characters) for _ in range(length))
            if (
                any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 2
                and (
                    not use_special_chars
                    or any(c in string.punctuation for c in password)
                )
            ):
                await ctx.info("Generated password meets complexity requirements.")
                break
            else:
                await ctx.warning(
                    f"Re-generating since the generated password did not meet complexity requirements: {password}"
                )
        return password

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
            Optional[str],
            Field(default="uk-en", description="Optional region to search in."),
        ] = "uk-en",
        max_results: Annotated[
            Optional[int],
            Field(
                default=10,
                ge=1,
                le=100,
                description="The maximum number of results to return. Default is 10, maximum is 100.",
            ),
        ] = 10,
        pages: Annotated[
            Optional[int],
            Field(
                default=1,
                ge=1,
                le=10,
                description="The number of pages to fetch. Default is 1, maximum is 10.",
            ),
        ] = 1,
    ):
        """
        Perform a text web search using the provided query using DDGS.
        """
        await ctx.info(f"Performing text web search for query: {query}")
        results = DDGS().text(
            query=query, region=region, max_results=max_results, page=pages
        )
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
            Optional[int],
            Field(
                default=None,
                ge=1,
                description="The optional number of items to choose.",
            ),
        ],
    ) -> int:
        """
        Calculate the number of ways to choose k items from n items without repetition and with order.
        If k is not provided, it defaults to n.
        """
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

    async def pirate_summary(self, ctx: Context, text: str) -> str:
        """
        Summarise the given text in a pirate style.
        This is an example of a tool that can use LLM sampling to generate a summary.
        """
        await ctx.info("Summarising text in pirate style using client LLM sampling.")
        response = await ctx.sample(
            messages=text,
            system_prompt="Your task is to summarise a given text in a pirate style. Use a fun and engaging tone but be concise.",
            temperature=0.9,  # High creativity
            max_tokens=1024,  # Pirates can be a bit verbose!
        )
        return response.text

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
        """
        Generate a random number from the von Mises distribution.
        This is an example of a tool that uses elicitation to obtain the required parameter kappa (κ).
        """
        await ctx.info(
            "Requesting the user for the value of kappa for von Mises distribution."
        )
        response = await ctx.elicit(
            message="Please provide the value of kappa (κ) for the von Mises distribution. It should be a positive number.",
            response_type=float,
        )
        kappa: float = 1.0  # Default value
        match response:
            case AcceptedElicitation(data=kappa):  # type: ignore[misc]
                await ctx.warning(f"Received kappa: {kappa}")
                if kappa < 0:
                    raise McpError(
                        error=ErrorData(
                            code=INVALID_PARAMS,
                            message="kappa (κ) must be a positive number.",
                        )
                    )
            case DeclinedElicitation():  # type: ignore[misc]
                await ctx.warning(
                    "User declined to provide kappa (κ). Using default value of 1.0."
                )
            case CancelledElicitation():  # type: ignore[misc]
                await ctx.warning(
                    "User cancelled the operation. The random number will NOT be generated."
                )
                raise McpError(
                    error=ErrorData(
                        code=INVALID_PARAMS,
                        message="Operation cancelled by the user.",
                    )
                )
        return random.vonmisesvariate(mu=mu, kappa=kappa)

    async def resource_logo(self, ctx: Context) -> Base64EncodedBinaryDataResponse:
        """
        Get the base64 encoded PNG logo of PyMCP.
        """
        await ctx.info("Reading the PNG logo for PyMCP.")
        with open("resources/logo.png", "rb") as logo_file:
            logo_content = logo_file.read()
            sha3_512_hasher = hashlib.sha3_512()
            sha3_512_hasher.update(logo_content)
            hex_digest = sha3_512_hasher.hexdigest()
            await ctx.info(
                f"Read {len(logo_content)} bytes from the logo file. SHA3-512: {hex_digest}"
            )
            logo_file.close()
        response = Base64EncodedBinaryDataResponse(
            data=base64.b64encode(logo_content).decode(),
            hash=hex_digest,
            hash_algorithm=sha3_512_hasher.name,
        )
        return response

    async def resource_logo_svg(self, ctx: Context) -> str:
        """
        Get the PyMCP logo as SVG.
        """
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
        """
        Computes the modulus 10 of a given number and returns a Unicode character representing the result.
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
                chr(int(hex(even_base + modulus - 1), 16))
                if modulus != 0
                else chr(int(hex(circled_zero), 16))
            )
        return unicode_symbol

    async def code_prompt(self, ctx: Context, task: str) -> PromptMessage:
        """
        Get a prompt to write a code snippet in Python based on the specified task.
        """
        content = f"""Write a Python code snippet to perform the following task:
        [TASK]
        {task}
        [/TASK]
        The code should be well-commented and follow best practices.
        Make sure to include necessary imports and handle any exceptions that may arise."""

        return PromptMessage(
            role="user", content=TextContent(type="text", text=content)
        )


def app() -> FastMCP:  # pragma: no cover
    app = FastMCP(
        name=PACKAGE_NAME,
        version=package_version,
        instructions="A simple MCP server for testing purposes.",
        on_duplicate_prompts="error",
        on_duplicate_resources="error",
        on_duplicate_tools="error",
    )
    mcp_obj = PyMCP()
    app_with_features = mcp_obj.register_features(app)
    return app_with_features


def main():  # pragma: no cover
    try:
        # Run the FastMCP server using stdio by default.
        # Other transports can be configured as needed using the MCP_SERVER_TRANSPORT environment variable.
        app().run(
            transport=env.str(
                name="MCP_SERVER_TRANSPORT",
                default="stdio",
                validate=OneOf(["stdio", "streamable-http", "sse"]),
            )
        )
    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        # Cleanup if necessary
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
