from environs import Env
from marshmallow.validate import OneOf

PACKAGE_NAME = "pymcp-template"
env = Env()
env.read_env()


class EnvVars:
    """Environment variables for pymcp configuration."""

    MCP_SERVER_TRANSPORT: str = env.str(
        name="MCP_SERVER_TRANSPORT",
        default="stdio",
        validate=OneOf(["stdio", "streamable-http", "http", "sse"]),
    )

    RESPONSE_CACHE_LIST_TOOL_TTL: int = env.int(name="RESPONSE_CACHE_LIST_TOOL_TTL", default=30)  # in seconds
