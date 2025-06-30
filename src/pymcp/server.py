import base64
import random
import sys
import string
import hashlib
import secrets
import math
from typing import Annotated, Optional
from fastmcp import FastMCP, Context
from fastmcp.prompts.prompt import PromptMessage, TextContent
from mcp import McpError
from mcp.types import (
    ErrorData,
    INVALID_PARAMS,
)
from importlib.metadata import metadata

from pydantic import BaseModel, Field

from datetime import datetime, timezone

from fastmcp.server.elicitation import (
    AcceptedElicitation,
    DeclinedElicitation,
    CancelledElicitation,
)


PACKAGE_NAME = "pymcp-template"
package_metadata = metadata(PACKAGE_NAME)

app = FastMCP(
    name=PACKAGE_NAME,
    version=package_metadata["Version"],
    instructions="A simple MCP server for testing purposes.",
    on_duplicate_prompts="error",
    on_duplicate_resources="error",
    on_duplicate_tools="error",
)


class Base64EncodedBinaryDataResponse(BaseModel):
    """
    A base64 encoded binary data for MCP response along with its cryptographic hash.
    """

    data: str = Field(
        ...,
        description="Base64 encoded binary data.",
    )
    hash: str = Field(
        ...,
        description="A hexadecimal encoded of a cryptographic hash of the raw binary data, typically a SHA3-512.",
    )
    hash_algorithm: str = Field(
        ...,
        description="The algorithm used to compute the hash, e.g., 'sha3_512'.",
    )


# 8<-- start of example tools -->8


@app.tool(
    tags=["greeting", "example"],
    annotations={"readOnlyHint": True},
)
async def greet(
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
    welcome_message = f"Welcome to the {PACKAGE_NAME} {package_metadata['Version']} server! The current date time in UTC is {datetime.now(timezone.utc).isoformat()}."
    if name is None or name.strip() == "":
        await ctx.warning("No name provided, using default greeting.")
        return f"Hello World! {welcome_message}"
    await ctx.info(f"Greeting {name}.")
    return f"Hello, {name}! {welcome_message}"


@app.tool(
    tags=["password-generation", "example"],
    annotations={"readOnlyHint": True},
)
async def generate_password(
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
                not use_special_chars or any(c in string.punctuation for c in password)
            )
        ):
            await ctx.info("Generated password meets complexity requirements.")
            break
        else:
            await ctx.warning(
                f"Re-generating since the generated password did not meet complexity requirements: {password}"
            )
    return password


@app.tool(
    tags=["math", "permutation", "example"],
    annotations={"readOnlyHint": True},
)
async def permutations(
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


@app.tool(
    tags=["pirate-summary", "llm-samping", "example"],
)
async def pirate_summary(ctx: Context, text: str) -> str:
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


@app.tool(
    tags=["experimental", "elicitation", "example"],
)
async def vonmises_random(
    ctx: Context,
    mu: Annotated[
        float,
        Field(
            description="The mean angle, expressed in radians between 0 and 2*pi",
            ge=0,
            le=2 * math.pi,
        ),
    ],
) -> str:
    """
    Generate a random number from the von Mises distribution.
    This is an example of a tool that uses elicitation to obtain a required parameter.
    """
    await ctx.info(
        "Requesting the user for the value of kappa for von Mises distribution."
    )
    response = await ctx.elicit(
        message="Please provide the value of kappa (κ) for the von Mises distribution. It should be a positive number.",
        response_type=float,
    )
    match response:
        case AcceptedElicitation(data=kappa):
            if kappa < 0:
                raise McpError(
                    error=ErrorData(
                        code=INVALID_PARAMS,
                        message="kappa (κ) must be a positive number.",
                    )
                )
        case DeclinedElicitation():
            await ctx.warning(
                "User declined to provide kappa (κ). Using default value of 1.0."
            )
            kappa = 1.0
        case CancelledElicitation():
            await ctx.warning(
                "User cancelled the operation. The random number will NOT be generated."
            )
            return None
    return str(random.vonmisesvariate(mu=mu, kappa=kappa))


# 8<-- end of example tools -->8

# 8<-- start of example resources -->8


@app.resource(uri="data://logo", tags=["logo", "png", "example"])
async def resource_logo(ctx: Context) -> str:
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


@app.resource(
    uri="data://logo_svg", mime_type="image/svg+xml", tags=["logo", "svg", "example"]
)
async def resource_logo_svg(ctx: Context) -> str:
    """
    Get the PyMCP logo as SVG.
    """
    await ctx.info("Reading the SVG logo for PyMCP.")
    with open("resources/logo.svg", "rb") as logo_file:
        logo_content = logo_file.read()
        await ctx.info(f"Read {len(logo_content)} bytes from the SVG logo file.")
        logo_file.close()
    return logo_content.decode()


@app.resource(uri="data://modulo10/{number}")
async def resource_unicode_modulo10(
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


# 8<-- end of example resources -->8


# 8<-- start of example prompts -->8
@app.prompt(
    tags=["example", "code-generation"],
)
async def code_prompt(ctx: Context, task: str) -> str:
    """
    Get a prompt to write a code snippet in Python based on the specified task.
    """
    content = f"""Write a Python code snippet to perform the following task:
    [TASK]
    {task}
    [/TASK]
    The code should be well-commented and follow best practices.
    Make sure to include necessary imports and handle any exceptions that may arise."""

    return PromptMessage(role="user", content=TextContent(type="text", text=content))


# 8<-- end of example prompts -->8


def main():
    try:
        # Run the FastMCP server using stdio. Other transports can be configured as needed.
        app.run()
    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        # Cleanup if necessary
        pass


if __name__ == "__main__":
    main()
