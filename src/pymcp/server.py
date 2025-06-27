import signal
import sys
from fastmcp import FastMCP, Context
from importlib.metadata import metadata


PACKAGE_NAME = "pymcp"
package_metadata = metadata(PACKAGE_NAME)

app = FastMCP(
    name=PACKAGE_NAME,
    instructions="A simple MCP server for testing purposes.",
)


@app.tool(
    name="greet",
    description="Greet the user with a message. This is the quintessential Hello World for MCP servers.",
    tags=["greeting", "example"],
    annotations={"readOnlyHint": True},
)
async def greet(ctx: Context, name: str = None) -> str:
    welcome_message = f"Welcome to the PyMCP {package_metadata['Version']} server!"
    if name is None or name.strip() == "":
        await ctx.warning("No name provided, using default greeting.")
        return f"Hello World! {welcome_message}"
    await ctx.info(f"Greeting {name}...")
    return f"Hello, {name}! {welcome_message}"


def main():
    def sigint_handler(signal, frame):
        """
        Signal handler to shut down the server gracefully.
        """
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    # Run the FastMCP server using stdio. Other transports can be configured as needed.
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
