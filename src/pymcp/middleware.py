import logging
import time
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
    TIMING_METADATA_KEY: ClassVar[str] = "_timing_metadata"

    async def _time_operation(self, context, call_next, operation_name: str):
        """Helper method to time any operation."""
        # Based on: https://github.com/jlowin/fastmcp/blob/ee6340526216c7796000c69ef3b9001a1a6f31a3/src/fastmcp/server/middleware/timing.py#L91C5-L109C18
        start_time = time.perf_counter()
        try:
            result = await call_next(context)
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.debug(f"{operation_name} completed in {duration_ms:.2f}ms")
            return result, duration_ms
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(
                f"{operation_name} failed after {duration_ms:.2f}ms: {e}",
            )
            raise

    async def on_call_tool(self, context, call_next):
        """Add metadata to tool responses."""
        # Do not encapsulate this in a try-except; let errors propagate
        tool_name = getattr(context.message, "name", "unknown")
        result, duration_ms = await self._time_operation(context, call_next, f"Tool '{tool_name}'")

        if result is None:  # pragma: no cover
            # Isn't this an impossible scenario?
            return result
        if result.meta is None:
            result.meta = {}
        result.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY] = {
            "name": ResponseMetadataMiddleware._package_metadata["name"],
            "version": ResponseMetadataMiddleware._package_metadata["version"],
        }
        result.meta[ResponseMetadataMiddleware.TIMING_METADATA_KEY] = {
            "tool_execution_time_ms": duration_ms,
        }
        logger.debug(f"Added package metadata to tool response: {result.meta['_package_metadata']}")
        return result
