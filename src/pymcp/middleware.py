import logging
from importlib.metadata import PackageMetadata, metadata as importlib_metadata
from typing import ClassVar

from fastmcp.server.middleware import Middleware

from pymcp import PACKAGE_NAME

logger = logging.getLogger(__name__)


class StripUnknownArgumentsMiddleware(Middleware):
    """Middleware to strip unknown arguments from MCP feature invocations."""

    async def on_call_tool(self, context, call_next):
        """Filter out unknown arguments from tool calls."""
        try:
            # Only proceed if this is a tool call with non-zero arguments
            if context.fastmcp_context and context.message.arguments and len(context.message.arguments) > 0:
                tool = await context.fastmcp_context.fastmcp.get_tool(context.message.name)
                tool_args = tool.parameters.get("properties", None)
                expected_args_names = set(tool_args.keys()) if tool_args else set()
                filtered_args = {k: v for k, v in context.message.arguments.items() if k in expected_args_names}
                unknown_args = set(context.message.arguments.keys()).difference(expected_args_names)
                if unknown_args:
                    logger.info(f"Unknown arguments for tool '{context.message.name}': {list(unknown_args)}")
                context.message.arguments = filtered_args  # modify in place
        except Exception as e:  # pragma: no cover
            logger.error(
                f"Error in {StripUnknownArgumentsMiddleware.__name__}: {e}",
                exc_info=True,
            )
        return await call_next(context)


class ResponseMetadataMiddleware(Middleware):
    """Middleware to add metadata to MCP responses."""

    _package_metadata: ClassVar[PackageMetadata] = importlib_metadata(PACKAGE_NAME)
    PACKAGE_METADATA_KEY: ClassVar[str] = "_package_metadata"

    async def on_call_tool(self, context, call_next):
        """Add metadata to tool responses."""
        # Do not encapsulate this in a try-except; let errors propagate
        result = await call_next(context)

        if result is None:  # pragma: no cover
            # Isn't this an impossible scenario?
            return result
        if result.meta is None:
            result.meta = {}
        result.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY] = {
            "name": ResponseMetadataMiddleware._package_metadata["name"],
            "version": ResponseMetadataMiddleware._package_metadata["version"],
        }
        logger.debug(f"Added package metadata to tool response: {result.meta['_package_metadata']}")
        return result
