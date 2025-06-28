import base64
import signal
import sys
import string
import hashlib
import secrets
import math
from typing import Annotated, Optional
from fastmcp import FastMCP, Context
from mcp import McpError
from mcp.types import (
    ErrorData,
    INVALID_PARAMS,
)
from importlib.metadata import metadata

from pydantic import BaseModel, Field

from datetime import datetime, timezone


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
        description="A hexadecimal digest of a cryptographic hash of the data, typically a SHA3-512.",
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


# 8<-- start of example resources -->8


@app.resource(uri="data://logo")
async def get_logo(ctx: Context) -> str:
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
        data=base64.b64encode(logo_content).decode("utf-8"),
        hash=hex_digest,
        hash_algorithm=sha3_512_hasher.name,
    )
    return response


def main():
    def sigint_handler(signal, frame):
        """
        Signal handler to shut down the server gracefully.
        """
        # This is for demonstration purposes only. It may be useful with a custom middleware or ASGI.
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    # Run the FastMCP server using stdio. Other transports can be configured as needed.
    app.run()


if __name__ == "__main__":
    main()
