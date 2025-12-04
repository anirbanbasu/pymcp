import logging

from environs import Env
from marshmallow.validate import OneOf, Range
from rich.logging import RichHandler

PACKAGE_NAME = "pymcp-template"
env = Env()
env.read_env()


class EnvVars:
    """Environment variables for pymcp configuration."""

    FASTMCP_HOST = env.str("FASTMCP_HOST", default="localhost")
    FASTMCP_PORT = env.int("FASTMCP_PORT", default=8000)

    PYMCP_LOG_LEVEL = env.str(
        "PYMCP_LOG_LEVEL",
        default="INFO",
        validate=OneOf(["NOTSET", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    ).upper()

    MCP_SERVER_TRANSPORT: str = env.str(
        name="MCP_SERVER_TRANSPORT",
        default="stdio",
        validate=OneOf(["stdio", "streamable-http", "http", "sse"]),
    )

    RESPONSE_CACHE_TTL: int = env.int(
        name="RESPONSE_CACHE_TTL",
        default=30,  # in seconds
        validate=Range(min=0, max=86400),  # 0 seconds to 1 day where 0 means caching is disabled
    )


logging.basicConfig(
    level=EnvVars.PYMCP_LOG_LEVEL,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=False, markup=True, show_path=False, show_time=False)],
)
